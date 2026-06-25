// Package xchain implements the SeqDEX cross-chain atomic-swap mechanism
// (Phase 5, milestone 1): a "Design A" single-secret HTLC swap between a
// Bitcoin-script leg (a Bitcoin/Elements parent chain) and a Sequentia-asset
// leg (the anchored Sequentia chain).
//
// Design A in one line: both legs are locked to the SAME hashlock H =
// sha256(secret) and the SAME secret. Redeeming either leg reveals the
// preimage on-chain, which the counterparty then uses to redeem the other —
// that single shared secret is what makes the swap atomic.
//
// The locking script is identical on both chains (it is plain Bitcoin Script,
// which elementsd evaluates unchanged in Elements mode):
//
//	OP_IF
//	    OP_SHA256 <H> OP_EQUALVERIFY <claim_pub> OP_CHECKSIG     # redeem branch
//	OP_ELSE
//	    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pub> OP_CHECKSIG  # refund
//	OP_ENDIF
//
// paid to P2SH. The redeem (IF) branch reveals the preimage; the refund (ELSE)
// branch spends back to the locker after nLockTime reaches <locktime> (CLTV).
//
// The Sequentia value-add — the whole point of this milestone — is the
// "anchor-shortened ordering" enforced by the Swap orchestrator (see
// orchestrator.go): lock the BTC leg first, then require the Sequentia leg to
// land in a Sequentia block whose anchorheight >= the BTC-leg's block height
// (paper Principle 7). Because of Bitcoin anchoring, if the BTC leg is later
// reorged the SEQ leg reorgs with it, so the SEQ leg needs only ~1 confirmation
// with NO extra reorg-protection buffer.
package xchain

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/txscript"
)

// Leg identifies which chain a primitive is operating on. The two legs differ
// only in transaction serialization / sighash (Bitcoin-script vs Elements);
// the lock script itself is byte-for-byte identical, so a LockPrimitive is
// leg-agnostic and the leg-specific work lives in the *Leg builders.
type Leg int

const (
	// LegBTC is the Bitcoin-script leg (the parent / anchor-source chain).
	LegBTC Leg = iota
	// LegSEQ is the Sequentia-asset leg (the anchored chain).
	LegSEQ
)

func (l Leg) String() string {
	if l == LegBTC {
		return "BTC"
	}
	return "SEQ"
}

// LockPrimitive abstracts the cryptographic lock used by a swap leg. Today the
// only implementation is HashLock (a SHA256 hashlock HTLC), but the swap
// orchestration in orchestrator.go is written purely against this interface so
// a PTLC / adaptor-signature primitive can be slotted in later without touching
// the orchestration.
//
// A primitive produces three artefacts, all leg-agnostic raw scripts:
//   - LockScript: the redeemScript funded by both parties (-> P2SH address).
//   - RedeemUnlockItems: the data items that satisfy the "claim/IF" branch
//     given a signature over the spend (e.g. <sig> <preimage> 1 for a
//     hashlock; just <sig> for a PTLC). The leg builder is responsible for
//     wrapping these into a scriptSig/witness together with the redeemScript.
//   - RefundUnlockItems: the data items that satisfy the "refund/ELSE" branch
//     (e.g. <sig> 0 for the CLTV refund).
//
// Splitting "what unlocks the branch" (here) from "how it is serialized into a
// scriptSig vs a witness" (the leg) is what keeps the abstraction clean across
// btcd and go-elements.
type LockPrimitive interface {
	// Kind is a short human label ("hashlock", "ptlc", ...).
	Kind() string

	// LockScript builds the redeemScript for the given claim/refund pubkeys
	// and CLTV refund locktime.
	LockScript(claimPub, refundPub []byte, locktime uint32) ([]byte, error)

	// RedeemUnlockItems returns the stack items (excluding the trailing
	// redeemScript push, which the leg adds) for the claim/IF branch, given a
	// signature already produced over the spend's sighash and any
	// primitive-specific secret material.
	RedeemUnlockItems(sig []byte) ([][]byte, error)

	// RefundUnlockItems returns the stack items (excluding the trailing
	// redeemScript push) for the refund/ELSE branch, given a signature over
	// the spend's sighash.
	RefundUnlockItems(sig []byte) ([][]byte, error)
}

// HashLock is the Design-A SHA256 hashlock primitive. It holds the hash H of
// the swap secret; only the redeeming party needs Secret set, and only when
// actually building a redeem spend (RedeemUnlockItems checks it).
type HashLock struct {
	Hash   []byte // 32-byte sha256(secret); the public part of the lock.
	Secret []byte // 32-byte preimage; required to build a redeem spend.
}

// NewHashLock builds a HashLock from a known preimage (the secret-holder side).
func NewHashLock(secret []byte) *HashLock {
	h := sha256.Sum256(secret)
	return &HashLock{Hash: h[:], Secret: append([]byte(nil), secret...)}
}

// NewHashLockFromHash builds a HashLock from only the hash (the counterparty
// side, before the secret is revealed on-chain).
func NewHashLockFromHash(hash []byte) *HashLock {
	return &HashLock{Hash: append([]byte(nil), hash...)}
}

func (h *HashLock) Kind() string { return "hashlock" }

// LockScript renders the Design-A HTLC redeemScript. It is identical to
// contrib/sequentia/swap-demo.py's htlc_script() and to a real BTC<->SEQ HTLC.
func (h *HashLock) LockScript(claimPub, refundPub []byte, locktime uint32) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	b.AddOp(txscript.OP_IF)
	b.AddOp(txscript.OP_SHA256).AddData(h.Hash).AddOp(txscript.OP_EQUALVERIFY)
	b.AddData(claimPub).AddOp(txscript.OP_CHECKSIG)
	b.AddOp(txscript.OP_ELSE)
	b.AddInt64(int64(locktime)).AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).AddOp(txscript.OP_DROP)
	b.AddData(refundPub).AddOp(txscript.OP_CHECKSIG)
	b.AddOp(txscript.OP_ENDIF)
	return b.Script()
}

// RedeemUnlockItems: <sig> <preimage> OP_TRUE — selects the IF branch and
// satisfies SHA256(<preimage>)==H plus the claim-key CHECKSIG. (The leg appends
// the redeemScript push afterwards.)
func (h *HashLock) RedeemUnlockItems(sig []byte) ([][]byte, error) {
	if len(h.Secret) == 0 {
		return nil, errNoSecret
	}
	// OP_TRUE is encoded as a 1-byte 0x01 push here; the leg serializers turn
	// an empty slice into OP_0 and {0x01} into the minimal true value, matching
	// CScript([... , 1, script]) in the demo.
	return [][]byte{sig, h.Secret, {0x01}}, nil
}

// RefundUnlockItems: <sig> OP_FALSE — selects the ELSE (refund) branch.
func (h *HashLock) RefundUnlockItems(sig []byte) ([][]byte, error) {
	return [][]byte{sig, {}}, nil
}

// compile-time assertion.
var _ LockPrimitive = (*HashLock)(nil)
