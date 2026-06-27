package xchain

import "fmt"

// Direction documents which way value flows. We implement and document ONE
// direction: the secret-holder (Alice) holds BTC and wants the SEQ asset; the
// counterparty (Bob) holds the SEQ asset and wants BTC. A single preimage,
// chosen by Alice, locks both legs (Design A).
//
// Flow (with the anchor-shortened ordering as the headline rule):
//
//  1. Alice (secret holder) LOCKS the BTC leg first. claim=Bob, refund=Alice,
//     CLTV = btcLocktime (the LONGER timeout — Alice refunds last).
//  2. Once the BTC leg is confirmed at parent height Hp, Bob LOCKS the SEQ leg.
//     claim=Alice, refund=Bob, CLTV = seqLocktime (the SHORTER timeout).
//  3. ORDERING CHECK (the Sequentia value-add): the SEQ leg must land in a
//     Sequentia block whose anchorheight >= Hp, and getanchorstatus must be
//     "ok". VerifySeqLegSafe enforces this; if it fails the orchestrator
//     refuses to treat the SEQ leg as safe (ErrAnchorOrdering). Because of
//     anchoring, once this holds the SEQ leg needs only ~1 confirmation with NO
//     extra reorg buffer: if the BTC leg is later reorged, the SEQ block
//     (anchored to the now-orphaned parent height) reorgs with it, reverting
//     BOTH legs together — proven in
//     test/functional/feature_anchor_swap_consistency.py.
//  4. Alice REDEEMS the SEQ leg with the preimage (revealing it on-chain).
//  5. Bob reads the preimage off Alice's SEQ redeem and REDEEMS the BTC leg.
//
// If a counterparty stalls, the locker REFUNDS via the CLTV branch after its
// timeout (RefundPath).
type Direction struct{}

// Party holds the per-party keys for a swap. claim keys sign the IF branch on
// the leg that party receives; refund keys sign the ELSE branch on the leg that
// party funded.
type Party struct {
	// Alice = secret holder, funds BTC, receives SEQ.
	AliceClaimSEQ  *Key // Alice claims the SEQ leg
	AliceRefundBTC *Key // Alice refunds the BTC leg she funded
	// Bob = counterparty, funds SEQ, receives BTC.
	BobClaimBTC  *Key // Bob claims the BTC leg
	BobRefundSEQ *Key // Bob refunds the SEQ leg he funded
}

// Swap orchestrates a single Design-A cross-chain HTLC swap. It is written
// purely against LockPrimitive and the leg builders, so swapping in a PTLC
// primitive later requires no orchestration change.
//
// The BTC (parent / anchor-source) leg is pluggable via btcBackend: it runs
// either against an Elements-mode parent (NewSwap) or a REAL bitcoind regtest/
// testnet4 (NewSwapBitcoin). The SEQ (anchored Sequentia) leg is always
// Elements-format.
type Swap struct {
	btcBackend btcBackend // the BTC (parent / anchor-source) leg, Elements or Bitcoin
	seq        *Chain     // the Sequentia (anchored) leg

	seqLeg *ElementsLeg

	hash *HashLock // the shared hashlock (hash known to both; secret to Alice)
}

// NewSwap wires an orchestrator to an ELEMENTS-mode parent (BTC leg) and the
// anchored Sequentia node (SEQ leg). This is the original constructor and the
// default for back-compat.
func NewSwap(btc, seq *Chain, prim *HashLock) *Swap {
	return &Swap{
		btcBackend: newElementsBTCBackend(btc, prim),
		seq:        seq,
		seqLeg:     NewElementsLeg(LegSEQ, prim),
		hash:       prim,
	}
}

// NewSwapBitcoin wires an orchestrator to a REAL bitcoind parent (BTC leg, in
// Bitcoin transaction format) and the anchored Sequentia node (SEQ leg, still
// Elements-format). This is the "real-bitcoind-leg": use it when the parent is a
// genuine bitcoind (regtest or testnet4), where the taker funds/refunds the BTC
// HTLC with a real Bitcoin signer and the maker must verify/claim it in Bitcoin
// format.
func NewSwapBitcoin(btc *BitcoinChain, seq *Chain, prim *HashLock) *Swap {
	return &Swap{
		btcBackend: newBitcoinBTCBackend(btc, prim),
		seq:        seq,
		seqLeg:     NewElementsLeg(LegSEQ, prim),
		hash:       prim,
	}
}

// LegLock records a funded HTLC leg.
type LegLock struct {
	Script   []byte
	Funded   *FundedHTLC
	Locktime uint32
}

// LockBTCLeg performs step 1: Alice locks the BTC leg first. Returns the funded
// leg and the parent height at which it confirmed (Hp), which the SEQ-leg
// ordering check is measured against.
func (s *Swap) LockBTCLeg(claimPub, refundPub []byte, amountCoins string, locktime uint32) (*LegLock, int64, error) {
	script, err := s.btcBackend.HTLCScript(claimPub, refundPub, locktime)
	if err != nil {
		return nil, 0, err
	}
	return s.btcBackend.LockBTCLeg(script, amountCoins, locktime)
}

// LockSEQLeg performs step 2: Bob locks the SEQ leg only after the BTC leg is
// on-chain (paper principle 7). It mines one Sequentia block and returns the
// funded leg plus the hash of the block that confirmed it (for the ordering
// check). The caller must then call VerifySeqLegSafe before treating it as safe.
func (s *Swap) LockSEQLeg(claimPub, refundPub []byte, amountCoins, assetLabel string, locktime uint32) (*LegLock, string, error) {
	script, err := s.seqLeg.HTLCScript(claimPub, refundPub, locktime)
	if err != nil {
		return nil, "", err
	}
	funded, err := s.seq.LockHTLC(script, amountCoins, assetLabel)
	if err != nil {
		return nil, "", err
	}
	if err := s.seq.Mine(1); err != nil { // only ~1 conf needed thanks to anchoring
		return nil, "", err
	}
	blockHash, err := s.seq.BlockHashOfTx(funded.TxID)
	if err != nil {
		return nil, "", err
	}
	return &LegLock{Script: script, Funded: funded, Locktime: locktime}, blockHash, nil
}

// AnchorEvidence captures what VerifySeqLegSafe checked, for proof/printing.
type AnchorEvidence struct {
	BTCLegHeight     int64
	SeqBlockHash     string
	SeqBlockAnchor   int64
	AnchorStatus     string
	NodeAnchorHeight int64
	OK               bool
}

// VerifySeqLegSafe is the anchor-shortened ordering check (step 3): it confirms
// the Sequentia block carrying the SEQ leg anchors at a height >= the BTC-leg
// height AND that the node's anchor status is "ok". Returns ErrAnchorOrdering
// (wrapped) if not — the orchestrator must NOT let the SEQ-side claimant treat
// the leg as final unless this passes.
func (s *Swap) VerifySeqLegSafe(seqBlockHash string, btcLegHeight int64) (*AnchorEvidence, error) {
	anchor, err := s.seq.BlockAnchorHeight(seqBlockHash)
	if err != nil {
		return nil, err
	}
	status, err := s.seq.GetAnchorStatus()
	if err != nil {
		return nil, err
	}
	ev := &AnchorEvidence{
		BTCLegHeight:     btcLegHeight,
		SeqBlockHash:     seqBlockHash,
		SeqBlockAnchor:   anchor,
		AnchorStatus:     status.AnchorStatus,
		NodeAnchorHeight: status.AnchorHeight,
		OK:               anchor >= btcLegHeight && status.AnchorStatus == "ok",
	}
	if !ev.OK {
		return ev, fmt.Errorf("%w (seq block %s anchorheight=%d, btc-leg height=%d, anchorstatus=%q)",
			ErrAnchorOrdering, seqBlockHash, anchor, btcLegHeight, status.AnchorStatus)
	}
	return ev, nil
}

// ClaimSEQLeg performs step 4: Alice redeems the SEQ leg with the preimage,
// revealing it on-chain. Returns the redeem txid.
func (s *Swap) ClaimSEQLeg(leg *LegLock, aliceClaim *Key, fee uint64) (string, error) {
	dest, err := s.seq.NewDestScript()
	if err != nil {
		return "", err
	}
	rawHex, err := s.seqLeg.Redeem(leg.Script, ElementsSpendInput{
		TxID:    leg.Funded.TxID,
		Vout:    leg.Funded.Vout,
		Amount:  leg.Funded.Amount,
		AssetID: leg.Funded.AssetID,
		DestSPK: dest,
		Fee:     fee,
	}, aliceClaim)
	if err != nil {
		return "", err
	}
	txid, err := s.seq.Broadcast(rawHex)
	if err != nil {
		return "", err
	}
	if err := s.seq.Mine(1); err != nil {
		return "", err
	}
	return txid, nil
}

// ClaimBTCLeg performs step 5: Bob redeems the BTC leg with the now-revealed
// preimage. Returns the redeem txid. The spend is built in the BTC backend's
// transaction format (Elements or Bitcoin).
func (s *Swap) ClaimBTCLeg(leg *LegLock, bobClaim *Key, fee uint64) (string, error) {
	return s.btcBackend.ClaimBTCLeg(leg, bobClaim, fee)
}

// RefundSEQLeg builds (but does not broadcast) the SEQ-leg CLTV refund for Bob,
// at the given nLockTime. Returns the raw tx hex so callers can demonstrate the
// pre-timeout rejection and the post-timeout acceptance.
func (s *Swap) RefundSEQLeg(leg *LegLock, bobRefund *Key, nLockTime uint32, fee uint64) (string, error) {
	dest, err := s.seq.NewDestScript()
	if err != nil {
		return "", err
	}
	return s.seqLeg.Refund(leg.Script, ElementsSpendInput{
		TxID:    leg.Funded.TxID,
		Vout:    leg.Funded.Vout,
		Amount:  leg.Funded.Amount,
		AssetID: leg.Funded.AssetID,
		DestSPK: dest,
		Fee:     fee,
	}, nLockTime, bobRefund)
}

// RefundBTCLeg builds, broadcasts, and returns the txid of the BTC-leg CLTV
// refund (ELSE branch) at the given nLockTime. It is the reverse-direction
// (asset->BTC) mirror of RefundSEQLeg: the maker funds the BTC leg, so it must
// be able to reclaim that BTC after btcLocktime if the taker never funds/claims
// the SEQ leg. Delegates to the BTC backend (Elements or Bitcoin tx format).
func (s *Swap) RefundBTCLeg(leg *LegLock, makerRefund *Key, nLockTime uint32, fee uint64) (string, error) {
	return s.btcBackend.RefundBTCLeg(leg, makerRefund, nLockTime, fee)
}

// SecretHex returns the swap preimage as hex (Alice side only).
func (s *Swap) SecretHex() string { return toHex(s.hash.Secret) }
