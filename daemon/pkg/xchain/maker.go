package xchain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// This file adds the MAKER-role helpers used by the daemon's XchainService
// (Phase 5, milestone 2). The orchestrator (orchestrator.go) drives BOTH swap
// roles in one process for the mechanism proof; the daemon, by contrast, plays
// only the counterparty/maker and talks to a remote taker over gRPC. The maker:
//
//   - VERIFIES the taker's already-funded BTC leg (it does NOT fund it — the
//     taker, as initiator, locks the BTC leg first).
//   - LOCKS the SEQ leg with its own reserves (reusing Swap.LockSEQLeg).
//   - watches the SEQ chain for the taker's claim, EXTRACTS the preimage
//     (Chain.ExtractPreimage), and CLAIMS the BTC leg with it
//     (InjectSecret + Swap.ClaimBTCLeg).
//   - REFUNDS its SEQ leg after T_seq if the taker stalls (Swap.RefundSEQLeg).
//
// All of this is built on the existing primitives; nothing here re-implements
// the HTLC.

// InjectSecret fills in the preimage on a Swap's shared hashlock after the maker
// has read it off the taker's SEQ-leg claim. It verifies sha256(secret) == H
// before accepting it, so a malformed extraction can never produce a wrong-key
// claim. After this, Swap.ClaimBTCLeg can build the BTC redeem.
func (s *Swap) InjectSecret(secret []byte) error {
	h := sha256.Sum256(secret)
	if !bytes.Equal(h[:], s.hash.Hash) {
		return fmt.Errorf("xchain: injected secret hashes to %x, want H=%x", h[:], s.hash.Hash)
	}
	s.hash.Secret = append([]byte(nil), secret...)
	return nil
}

// HashHex returns the swap hashlock H as hex (known to both parties).
func (s *Swap) HashHex() string { return toHex(s.hash.Hash) }

// VerifiedBTCLeg is the maker's view of the taker's BTC-leg HTLC, reconstructed
// and checked so the maker can later claim it.
type VerifiedBTCLeg struct {
	Leg            *LegLock
	Height         int64
	Confirmations  int
	ExpectedScript []byte
}

// VerifyBTCLeg checks that the taker's claimed BTC leg really is a Design-A HTLC
// that pays the agreed amount, embeds the agreed hashlock H, is claimable by the
// MAKER's claim key and refundable by the TAKER's refund key after btcLocktime,
// is funded to the matching P2SH, and is confirmed. It returns a *LegLock the
// maker can feed to ClaimBTCLeg once it has the secret.
//
// makerClaimPub is the maker's BTC-leg claim pubkey (from the quote);
// takerRefundPub is the taker's BTC-leg refund pubkey (from ProposeXchainSwap).
// providedScript is the redeemScript the taker sent; it must equal the script we
// recompute from (H, makerClaimPub, takerRefundPub, btcLocktime) byte-for-byte.
func (s *Swap) VerifyBTCLeg(
	hashH, makerClaimPub, takerRefundPub, providedScript []byte,
	btcLocktime uint32,
	txid string, vout uint32, amount uint64, assetID string,
	minConf int,
) (*VerifiedBTCLeg, error) {
	if !bytes.Equal(hashH, s.hash.Hash) {
		return nil, fmt.Errorf("%w: btc-leg H=%x != quote H=%x", ErrBTCLegInvalid, hashH, s.hash.Hash)
	}
	// Recompute the canonical Design-A script and compare to what the taker sent.
	want, err := s.btcLeg.HTLCScript(makerClaimPub, takerRefundPub, btcLocktime)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, providedScript) {
		return nil, fmt.Errorf("%w: redeemScript mismatch (want %x, got %x)", ErrBTCLegInvalid, want, providedScript)
	}

	// The funded output must pay the recomputed script's P2SH at the claimed
	// outpoint, with the agreed amount/asset, and be confirmed.
	wantP2SH, err := s.btc.P2SHAddress(want)
	if err != nil {
		return nil, err
	}
	out, err := s.btc.OutputAt(txid, vout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBTCLegInvalid, err)
	}
	wantSPK, err := s.btc.AddressScriptPubKey(wantP2SH)
	if err != nil {
		return nil, err
	}
	if out.ScriptPubKeyHex != wantSPK {
		return nil, fmt.Errorf("%w: vout %d:%d does not pay the HTLC P2SH", ErrBTCLegInvalid, vout, vout)
	}
	if out.ValueAtoms != amount {
		return nil, fmt.Errorf("%w: btc-leg value %d != quoted %d", ErrBTCLegInvalid, out.ValueAtoms, amount)
	}
	if assetID != "" && out.AssetID != assetID {
		return nil, fmt.Errorf("%w: btc-leg asset %s != %s", ErrBTCLegInvalid, out.AssetID, assetID)
	}
	confs, err := s.btc.TxConfirmations(txid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBTCLegInvalid, err)
	}
	if confs < minConf {
		return nil, fmt.Errorf("%w: btc-leg has %d confirmations, need %d", ErrBTCLegUnconfirmed, confs, minConf)
	}

	height, err := s.btc.BlockCount()
	if err != nil {
		return nil, err
	}
	legHeight := height - int64(confs) + 1 // height at which it confirmed

	return &VerifiedBTCLeg{
		Leg: &LegLock{
			Script: want,
			Funded: &FundedHTLC{TxID: txid, Vout: vout, Amount: out.ValueAtoms, AssetID: out.AssetID},
			Locktime: btcLocktime,
		},
		Height:         legHeight,
		Confirmations:  confs,
		ExpectedScript: want,
	}, nil
}

// WatchSEQClaim polls the SEQ chain for a spend of the SEQ-leg outpoint and,
// when found, extracts the preimage from its scriptSig. It returns the claim
// txid and the secret. It does NOT block forever; callers run it on a ticker.
//
// We detect the claim by asking the node for spends of the funding outpoint via
// gettxout (nil => spent) and then scanning recent blocks/mempool for the
// spender; to keep the MVP self-contained we instead accept the claim txid the
// taker can be observed to have broadcast, so the daemon scans by re-deriving it
// from the funding tx's spend. See SpenderOf.
func (s *Swap) WatchSEQClaim(seqLeg *LegLock) (claimTxid string, secret []byte, err error) {
	claimTxid, err = s.seq.SpenderOf(seqLeg.Funded.TxID, seqLeg.Funded.Vout)
	if err != nil {
		return "", nil, err
	}
	if claimTxid == "" {
		return "", nil, nil // not yet claimed
	}
	secret, err = s.seq.ExtractPreimage(claimTxid, s.hash.Hash)
	if err != nil {
		return claimTxid, nil, err
	}
	return claimTxid, secret, nil
}
