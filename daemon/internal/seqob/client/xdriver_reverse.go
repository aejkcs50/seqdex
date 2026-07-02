package client

// xdriver_reverse.go runs the REVERSE cross-chain lift (offer.direction =
// ASSET_TO_BTC: the taker sells a Sequentia asset for real BTC; the MAKER holds
// the secret and funds the BTC leg FIRST, mirroring the deployed RFQ reverse
// design). Same construction rules as the forward driver in xdriver.go: the
// drivers own Seal/Open, everything from the peer binds to the SIGNED offer,
// redeem scripts are re-derived byte-for-byte, anchor gating uses only
// self-derived chain data, and every value-bearing transition is surfaced to a
// persistence hook BEFORE the next wait.
//
// Secret transfer: the maker's ClaimSEQLeg reveals s on-chain in the claim's
// scriptSig; the taker learns it by watching ITS OWN funded SEQ leg
// (WatchSEQClaim), never by trusting the courier. The courtesy
// XcSecretRevealed message is still sent for other implementations, but this
// taker deliberately ignores it: the on-chain path cannot be withheld or
// spoofed by the peer or relay.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// --- REVERSE taker (sells the asset, receives BTC) ----------------------------

// TakerReverseParams configures RunTakerReverse. Expectations come from the
// SIGNED offer (a maker BUY: it gives BTC, wants the asset).
type TakerReverseParams struct {
	// NewOps binds the settlement engine to the hashlock H once the maker's
	// terms arrive. The taker does not know the secret, but its SEQ leg script
	// and its BTC claim both embed H, so the swap must be built from the H in
	// the terms (mirrors the forward maker's NewOps(hashH)).
	NewOps  func(hashH []byte) (XcOps, error)
	Crypter *Crypter

	BtcClaimKey  *xchain.Key // claims the maker's BTC leg once the secret is revealed
	SeqRefundKey *xchain.Key // refunds our SEQ leg after T_seq if the maker never claims

	ExpectAsset     string // SEQ asset hex we sell (required)
	ExpectSeqAmount uint64 // atoms we deliver (required; whole-HTLC lift)
	ExpectBtcAmount uint64 // sats the offer pays (required)
	MaxFeeBtc       uint64 // refuse terms whose fee_btc exceeds this

	// Locktime sanity. T_btc is when the MAKER can take its BTC back, so it
	// must leave us real runway to claim after the secret appears; T_seq is
	// when WE can refund our asset leg, so it must fit the funding +
	// confirmation + the maker's gate-and-claim.
	MinBtcClaimDelta uint32 // T_btc >= btcTip + this (default 30 parent blocks)
	MinSeqFundWindow uint32 // T_seq >= seqTip + this (default 120 SEQ blocks)
	BtcClaimMargin   uint32 // refuse to claim closer than this to T_btc (default 6)

	MinBTCConf   int    // confirmations required on the MAKER's BTC leg before we fund (default 1)
	SpendFeeSats uint64 // fee target in native sats (default 1000)
	Timing       XcTiming
	Log          func(format string, args ...interface{})

	// OnSeqLegFunded is invoked the moment our SEQ leg is funded, BEFORE any
	// further wait: the caller must persist the result there so a crash never
	// strands the asset behind an unknowable redeem script.
	OnSeqLegFunded func(*TakerReverseResult)
}

// TakerReverseResult is returned even alongside an error once the SEQ leg is
// funded, so the caller can persist it and refund after T_seq.
type TakerReverseResult struct {
	Terms        *XcMsg // the maker's XcBtcLegLocked (terms ride in it)
	BtcLeg       *xchain.LegLock
	BtcLocktime  uint32
	SeqLeg       *xchain.LegLock
	SeqBlockHash string
	SeqLocktime  uint32
	Secret       []byte
	BtcClaimTxid string
	SeqRefundTx  string
}

func (p *TakerReverseParams) logf(format string, args ...interface{}) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// RunTakerReverse executes the reverse handshake as the taker: request terms
// (shipping both taker keys), verify the maker's BTC leg through our own
// node's confirmation, fund the SEQ asset leg, then watch our leg for the
// maker's claim (which reveals the secret on-chain) and claim the BTC leg —
// or refund the SEQ leg once T_seq passes without a claim.
func RunTakerReverse(p TakerReverseParams, send XcSend, recv XcRecv) (*TakerReverseResult, error) {
	p.Timing.setDefaults()
	if p.NewOps == nil || p.Crypter == nil || p.BtcClaimKey == nil || p.SeqRefundKey == nil {
		return nil, errors.New("taker reverse: incomplete params")
	}
	if p.ExpectAsset == "" || p.ExpectSeqAmount == 0 || p.ExpectBtcAmount == 0 {
		return nil, errors.New("taker reverse: offer expectations required")
	}
	if p.MinBtcClaimDelta == 0 {
		p.MinBtcClaimDelta = 30
	}
	if p.MinSeqFundWindow == 0 {
		p.MinSeqFundWindow = 120
	}
	if p.BtcClaimMargin == 0 {
		p.BtcClaimMargin = 6
	}
	if p.MinBTCConf <= 0 {
		p.MinBTCConf = 1
	}
	if p.SpendFeeSats == 0 {
		p.SpendFeeSats = 1000
	}
	res := &TakerReverseResult{}

	// 1. Request terms, shipping the keys the maker's BTC HTLC must pay.
	req := &XcMsg{
		Type:              XcTermsRequest,
		TakerSeqRefundPub: hex.EncodeToString(p.SeqRefundKey.PubKey()),
		TakerBtcClaimPub:  hex.EncodeToString(p.BtcClaimKey.PubKey()),
	}
	if err := sendXc(req, p.Crypter, send); err != nil {
		return res, err
	}

	// 2. The maker's BTC leg + terms (one message; the lock is broadcast-only
	// so it arrives fast, but give it the leg-wait budget, not the terms one).
	locked, err := recvXcType(recv, p.Crypter, XcBtcLegLocked, p.Timing.SeqLockWait)
	if err != nil {
		return res, err
	}
	res.Terms = locked
	if locked.Leg == nil {
		return res, errors.New("btc_leg_locked without a leg")
	}
	if locked.BtcAmount != p.ExpectBtcAmount || locked.Leg.Amount != p.ExpectBtcAmount {
		sendXcFail(p.Crypter, send, "terms_mismatch", "btc amount differs from the signed offer")
		return res, fmt.Errorf("%w: btc %d/%d != offer %d", ErrXcBadTerms, locked.BtcAmount, locked.Leg.Amount, p.ExpectBtcAmount)
	}
	if locked.SeqAmount != p.ExpectSeqAmount {
		sendXcFail(p.Crypter, send, "terms_mismatch", "seq_amount differs from the signed offer")
		return res, fmt.Errorf("%w: seq_amount %d != offer %d", ErrXcBadTerms, locked.SeqAmount, p.ExpectSeqAmount)
	}
	if locked.FeeBtc > p.MaxFeeBtc {
		sendXcFail(p.Crypter, send, "terms_mismatch", "fee_btc exceeds the taker bound")
		return res, fmt.Errorf("%w: fee_btc %d > max %d", ErrXcBadTerms, locked.FeeBtc, p.MaxFeeBtc)
	}
	hashH, err := hex.DecodeString(locked.HashH)
	if err != nil || len(hashH) != 32 {
		return res, fmt.Errorf("%w: bad hash_h", ErrXcBadTerms)
	}
	makerSeqClaimPub, err := hex.DecodeString(locked.MakerSeqClaimPub)
	if err != nil || len(makerSeqClaimPub) != 33 {
		return res, fmt.Errorf("%w: bad maker_seq_claim_pub", ErrXcBadTerms)
	}
	makerBtcRefundPub, err := hex.DecodeString(locked.MakerRefundPub)
	if err != nil || len(makerBtcRefundPub) != 33 {
		return res, fmt.Errorf("%w: bad maker_refund_pub", ErrXcBadTerms)
	}
	// Bind the settlement engine to H now that we know it (our SEQ leg script
	// and BTC claim both embed it).
	ops, err := p.NewOps(hashH)
	if err != nil {
		return res, err
	}
	btcTip, err := ops.BtcTip()
	if err != nil {
		return res, err
	}
	seqTip, err := ops.SeqTip()
	if err != nil {
		return res, err
	}
	tBtc := locked.Leg.Locktime
	tSeq := locked.SeqLocktime
	res.BtcLocktime, res.SeqLocktime = tBtc, tSeq
	if tBtc < uint32(btcTip)+p.MinBtcClaimDelta {
		sendXcFail(p.Crypter, send, "terms_mismatch", "btc_locktime leaves no claim runway")
		return res, fmt.Errorf("%w: T_btc %d vs tip %d (min delta %d)", ErrXcBadTerms, tBtc, btcTip, p.MinBtcClaimDelta)
	}
	if tSeq < uint32(seqTip)+p.MinSeqFundWindow {
		sendXcFail(p.Crypter, send, "terms_mismatch", "seq_locktime leaves no funding window")
		return res, fmt.Errorf("%w: T_seq %d vs tip %d (min window %d)", ErrXcBadTerms, tSeq, seqTip, p.MinSeqFundWindow)
	}

	// 3. Verify the maker's BTC leg against OUR node, polling out propagation
	// and confirmation (the maker broadcasts at 0-conf; we fund the asset only
	// against a leg confirmed to OUR satisfaction). Only a proven-invalid leg
	// is terminal.
	script, err := hex.DecodeString(locked.Leg.RedeemScript)
	if err != nil {
		return res, fmt.Errorf("bad btc redeem_script hex: %w", err)
	}
	var verifiedBtc *xchain.VerifiedBTCLeg
	confDeadline := time.Now().Add(p.Timing.BtcConfWait)
	for {
		verifiedBtc, err = ops.VerifyBTCLeg(hashH, p.BtcClaimKey.PubKey(), makerBtcRefundPub, script,
			tBtc, locked.Leg.Txid, locked.Leg.Vout, locked.Leg.Amount, p.MinBTCConf)
		if err == nil {
			break
		}
		if errors.Is(err, xchain.ErrBTCLegInvalid) {
			sendXcFail(p.Crypter, send, "btc_leg_invalid", err.Error())
			return res, err
		}
		if time.Now().After(confDeadline) {
			sendXcFail(p.Crypter, send, "btc_conf_timeout", "maker btc leg did not confirm in time")
			return res, fmt.Errorf("maker btc leg %s: not confirmed within %s", locked.Leg.Txid, p.Timing.BtcConfWait)
		}
		time.Sleep(p.Timing.Poll)
	}
	res.BtcLeg = verifiedBtc.Leg
	p.logf("maker BTC leg verified + confirmed: %s (%d sats, T_btc=%d)", locked.Leg.Txid, locked.Leg.Amount, tBtc)

	// 4. Fund our SEQ asset leg (claim = the maker's key, refund = ours after
	// T_seq), persisting the moment it is funded; poll out a slow confirmation
	// instead of orphaning the leg.
	seqLeg, seqBlockHash, err := ops.LockSEQLeg(makerSeqClaimPub, p.SeqRefundKey.PubKey(),
		atomsToCoins(p.ExpectSeqAmount), p.ExpectAsset, tSeq)
	if seqLeg != nil {
		res.SeqLeg = seqLeg
		if p.OnSeqLegFunded != nil {
			p.OnSeqLegFunded(res)
		}
	}
	if err != nil {
		if seqLeg == nil {
			sendXcFail(p.Crypter, send, "seq_lock_failed", err.Error())
			return res, err
		}
		p.logf("SEQ leg %s funded but slow to confirm; polling: %v", seqLeg.Funded.TxID, err)
		confirmDeadline := time.Now().Add(p.Timing.SeqLockWait)
		for seqBlockHash == "" {
			if bh, berr := ops.SeqBlockHashOfTx(seqLeg.Funded.TxID); berr == nil && bh != "" {
				seqBlockHash = bh
				break
			}
			if time.Now().After(confirmDeadline) {
				return res, fmt.Errorf("seq leg %s funded but unconfirmed within %s (refund after T_seq %d)",
					seqLeg.Funded.TxID, p.Timing.SeqLockWait, tSeq)
			}
			time.Sleep(p.Timing.Poll)
		}
	}
	res.SeqBlockHash = seqBlockHash
	if p.OnSeqLegFunded != nil {
		p.OnSeqLegFunded(res)
	}
	anchorH, aerr := ops.SeqAnchorHeightOf(seqBlockHash)
	if aerr != nil {
		anchorH = 0 // advisory only; the maker gates via its own node
	}
	fundedMsg := &XcMsg{
		Type: XcSeqLegFunded,
		Leg: &XcLeg{
			Txid:         seqLeg.Funded.TxID,
			Vout:         seqLeg.Funded.Vout,
			Amount:       seqLeg.Funded.Amount,
			Asset:        seqLeg.Funded.AssetID,
			RedeemScript: hex.EncodeToString(seqLeg.Script),
			Locktime:     tSeq,
			BlockHash:    seqBlockHash,
			AnchorHeight: anchorH,
		},
	}
	if err := sendXc(fundedMsg, p.Crypter, send); err != nil {
		// The leg is on-chain: proceed to the watch loop regardless; if the
		// maker never learned of it, our T_seq refund recovers it.
		p.logf("seq_leg_funded announce failed (%v); continuing to watch on-chain", err)
	}
	p.logf("SEQ leg funded: %s in block %s", seqLeg.Funded.TxID, seqBlockHash)

	// 5. Watch OUR leg for the maker's claim: its scriptSig carries the secret
	// (the courier's XcSecretRevealed is deliberately not relied upon). If
	// T_seq passes unclaimed, refund the asset.
	for {
		_, secret, werr := ops.WatchSEQClaim(seqLeg)
		if werr == nil && len(secret) > 0 {
			res.Secret = secret
			break
		}
		tip, terr := ops.SeqTip()
		if terr == nil && uint32(tip) >= tSeq {
			raw, rerr := ops.RefundSEQLeg(seqLeg, p.SeqRefundKey, tSeq, xcSeqLegFee(ops, p.ExpectAsset, p.SpendFeeSats, p.ExpectSeqAmount))
			if rerr == nil {
				if txid, berr := ops.SeqBroadcast(raw); berr == nil {
					res.SeqRefundTx = txid
					p.logf("refunded SEQ leg after T_seq: %s", txid)
					return res, fmt.Errorf("%w: maker never claimed by T_seq %d", ErrXcRefunded, tSeq)
				}
			}
			// Build/broadcast hiccup: retry next tick until it lands.
		}
		time.Sleep(p.Timing.Poll)
	}

	// 6. Claim the BTC leg with the revealed secret, retried until the maker's
	// refund path nears (T_btc); the margin stops a claim-vs-refund race.
	if err := ops.InjectSecret(res.Secret); err != nil {
		return res, err
	}
	for {
		tip, terr := ops.BtcTip()
		if terr == nil && uint32(tip)+p.BtcClaimMargin >= tBtc {
			return res, fmt.Errorf("btc claim window closed (tip %d within %d of T_btc %d; secret %x persisted)",
				tip, p.BtcClaimMargin, tBtc, res.Secret)
		}
		txid, cerr := ops.ClaimBTCLeg(verifiedBtc.Leg, p.BtcClaimKey, xcSafeFee(p.SpendFeeSats, p.ExpectBtcAmount))
		if cerr == nil {
			res.BtcClaimTxid = txid
			p.logf("settled: maker claimed our asset, we claimed BTC (%s)", txid)
			return res, nil
		}
		p.logf("btc claim retrying: %v", cerr)
		time.Sleep(p.Timing.Poll)
	}
}

// RefundTakerSEQ spends the taker's SEQ leg through the CLTV refund path once
// T_seq has passed. With wait=false it returns ErrXcRefundNotDue when early.
func RefundTakerSEQ(ops XcOps, leg *xchain.LegLock, key *xchain.Key, locktime uint32,
	assetHex string, spendFeeSats uint64, wait bool, poll time.Duration) (string, error) {
	if poll <= 0 {
		poll = 15 * time.Second
	}
	if spendFeeSats == 0 {
		spendFeeSats = 1000
	}
	for {
		tip, err := ops.SeqTip()
		if err != nil {
			return "", err
		}
		if uint32(tip) >= locktime {
			break
		}
		if !wait {
			return "", fmt.Errorf("%w: seq tip %d < T_seq %d", ErrXcRefundNotDue, tip, locktime)
		}
		time.Sleep(poll)
	}
	raw, err := ops.RefundSEQLeg(leg, key, locktime, xcSeqLegFee(ops, assetHex, spendFeeSats, leg.Funded.Amount))
	if err != nil {
		return "", err
	}
	return ops.SeqBroadcast(raw)
}

// --- REVERSE maker (buys the asset with BTC; holds the secret) ----------------

// MakerReverseParams configures RunMakerReverse.
type MakerReverseParams struct {
	// NewOps binds the settlement engine to the freshly minted SECRET (the
	// maker is the secret holder in reverse).
	NewOps  func(secret []byte) (XcOps, error)
	Crypter *Crypter

	// Tip queries usable BEFORE the engine exists.
	BtcTip func() (int64, error)
	SeqTip func() (int64, error)

	AssetHex  string // SEQ asset we buy (offer pair base)
	SeqAmount uint64 // atoms we require
	BtcAmount uint64 // sats we pay
	FeeBtc    uint64 // advisory fee surfaced in terms

	BtcLocktimeDelta uint32 // default 100 (our BTC refund if the taker vanishes; ~16h)
	SeqLocktimeDelta uint32 // default 240 (the taker's refund horizon; ~2h)

	MinBTCConf     int    // confirmations we need on our OWN BTC leg before the anchor gate (default 1)
	SeqClaimMargin uint32 // never reveal the secret closer than this to T_seq (default 10)
	SpendFeeSats   uint64
	Timing         XcTiming
	Log            func(format string, args ...interface{})

	// OnUpdate persists the evolving result; in reverse the SECRET is the
	// maker's crown jewel and is minted here, so the first call (before any
	// coins move) must already durably hold it and both keys.
	OnUpdate func(*MakerReverseResult)
}

// MakerReverseResult is the reverse maker's persistence record.
type MakerReverseResult struct {
	Secret       []byte
	HashH        []byte
	SeqClaimKey  *xchain.Key // claims the taker's asset leg (reveals the secret)
	BtcRefundKey *xchain.Key // refunds our BTC leg after T_btc
	BtcLocktime  uint32
	SeqLocktime  uint32
	BtcLeg       *xchain.LegLock // our funded BTC leg
	BtcLegHeight int64
	SeqLeg       *xchain.LegLock // the taker's verified asset leg
	SeqBlockHash string
	SeqClaimTxid string
	BtcRefundTx  string
	Settled      bool
}

func (p *MakerReverseParams) logf(format string, args ...interface{}) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// RunMakerReverse executes the reverse handshake as the maker: mint the secret
// and per-lift keys, fund the BTC leg FIRST, announce it with the terms, verify
// the taker's asset leg through the anchor gate, and claim it (revealing the
// secret; the taker then claims the BTC leg). If the taker never funds, the
// session ends with the BTC leg persisted for a T_btc refund.
func RunMakerReverse(p MakerReverseParams, in <-chan []byte, send XcSend) (*MakerReverseResult, error) {
	p.Timing.setDefaults()
	if p.NewOps == nil || p.Crypter == nil || p.BtcTip == nil || p.SeqTip == nil {
		return nil, errors.New("maker reverse: incomplete params")
	}
	if p.AssetHex == "" || p.SeqAmount == 0 || p.BtcAmount == 0 {
		return nil, errors.New("maker reverse: offer amounts required")
	}
	if p.BtcLocktimeDelta == 0 {
		p.BtcLocktimeDelta = 100
	}
	if p.SeqLocktimeDelta == 0 {
		p.SeqLocktimeDelta = 240
	}
	if p.MinBTCConf <= 0 {
		p.MinBTCConf = 1
	}
	if p.SeqClaimMargin == 0 {
		p.SeqClaimMargin = 10
	}
	if p.SpendFeeSats == 0 {
		p.SpendFeeSats = 1000
	}
	recv := func(timeout time.Duration) ([]byte, error) {
		select {
		case sealed, ok := <-in:
			if !ok {
				return nil, errors.New("session closed")
			}
			return sealed, nil
		case <-time.After(timeout):
			return nil, errors.New("courier timeout")
		}
	}
	res := &MakerReverseResult{}

	// 1. Terms request must carry BOTH taker keys (the BTC HTLC pays the
	// taker's claim key; the asset HTLC refunds to the taker's refund key).
	req, err := recvXcType(recv, p.Crypter, XcTermsRequest, p.Timing.TermsReqWait)
	if err != nil {
		return res, err
	}
	takerSeqRefundPub, err := hex.DecodeString(req.TakerSeqRefundPub)
	if err != nil || len(takerSeqRefundPub) != 33 {
		sendXcFail(p.Crypter, send, "bad_pubkey", "taker_seq_refund_pub required for a reverse lift")
		return res, errors.New("bad taker_seq_refund_pub")
	}
	takerBtcClaimPub, err := hex.DecodeString(req.TakerBtcClaimPub)
	if err != nil || len(takerBtcClaimPub) != 33 {
		sendXcFail(p.Crypter, send, "bad_pubkey", "taker_btc_claim_pub required for a reverse lift")
		return res, errors.New("bad taker_btc_claim_pub")
	}

	// 2. Mint the secret + per-lift keys and PERSIST before any coins move.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return res, err
	}
	hashH := sha256.Sum256(secret)
	seqClaim, err := xchain.NewKey()
	if err != nil {
		return res, err
	}
	btcRefund, err := xchain.NewKey()
	if err != nil {
		return res, err
	}
	btcTip, err := p.BtcTip()
	if err != nil {
		return res, err
	}
	seqTip, err := p.SeqTip()
	if err != nil {
		return res, err
	}
	res.Secret, res.HashH = secret, hashH[:]
	res.SeqClaimKey, res.BtcRefundKey = seqClaim, btcRefund
	res.BtcLocktime = uint32(btcTip) + p.BtcLocktimeDelta
	res.SeqLocktime = uint32(seqTip) + p.SeqLocktimeDelta
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	ops, err := p.NewOps(secret)
	if err != nil {
		return res, err
	}

	// 3. Fund the BTC leg FIRST (the reverse design: the taker will only fund
	// the asset against our confirmed leg). Broadcast-only on a live parent.
	btcLeg, _, err := ops.LockBTCLeg(takerBtcClaimPub, btcRefund.PubKey(), atomsToCoins(p.BtcAmount), res.BtcLocktime)
	if err != nil {
		sendXcFail(p.Crypter, send, "btc_lock_failed", err.Error())
		return res, err
	}
	res.BtcLeg = btcLeg
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	announce := &XcMsg{
		Type:             XcBtcLegLocked,
		HashH:            hex.EncodeToString(hashH[:]),
		MakerSeqClaimPub: hex.EncodeToString(seqClaim.PubKey()),
		MakerRefundPub:   hex.EncodeToString(btcRefund.PubKey()),
		SeqLocktime:      res.SeqLocktime,
		BtcAmount:        p.BtcAmount,
		SeqAmount:        p.SeqAmount,
		FeeBtc:           p.FeeBtc,
		Leg: &XcLeg{
			Txid:         btcLeg.Funded.TxID,
			Vout:         btcLeg.Funded.Vout,
			Amount:       btcLeg.Funded.Amount,
			RedeemScript: hex.EncodeToString(btcLeg.Script),
			Locktime:     res.BtcLocktime,
		},
	}
	if err := sendXc(announce, p.Crypter, send); err != nil {
		// Our BTC is already locked; the taker will never see the leg, so no
		// asset is coming. The leg is persisted; refund after T_btc.
		return res, fmt.Errorf("btc_leg_locked announce failed (BTC refundable after T_btc %d): %w", res.BtcLocktime, err)
	}
	p.logf("BTC leg funded + announced: %s (%d sats, T_btc=%d T_seq=%d)",
		btcLeg.Funded.TxID, p.BtcAmount, res.BtcLocktime, res.SeqLocktime)

	// 4. The taker's asset leg (it waits for OUR confirmation first, so give it
	// the long budget). A no-show leaves our BTC leg persisted for the T_btc
	// refund; that griefing cost is inherent to funding first (as in the RFQ).
	funded, err := recvXcType(recv, p.Crypter, XcSeqLegFunded, p.Timing.BtcFundWait)
	if err != nil {
		return res, fmt.Errorf("no seq leg from the taker (BTC refundable after T_btc %d): %w", res.BtcLocktime, err)
	}
	if funded.Leg == nil {
		return res, errors.New("seq_leg_funded without a leg")
	}
	if funded.Leg.Amount != p.SeqAmount || funded.Leg.Asset != p.AssetHex {
		sendXcFail(p.Crypter, send, "seq_leg_mismatch", "amount/asset differ from the signed offer")
		return res, fmt.Errorf("seq leg %d %s != offer %d %s", funded.Leg.Amount, funded.Leg.Asset, p.SeqAmount, p.AssetHex)
	}
	if funded.Leg.Locktime != res.SeqLocktime {
		sendXcFail(p.Crypter, send, "seq_leg_mismatch", "locktime differs from terms")
		return res, fmt.Errorf("seq leg locktime %d != terms %d", funded.Leg.Locktime, res.SeqLocktime)
	}
	script, err := hex.DecodeString(funded.Leg.RedeemScript)
	if err != nil {
		return res, fmt.Errorf("bad seq redeem_script hex: %w", err)
	}
	var verifiedSeq *xchain.VerifiedSEQLeg
	verifyDeadline := time.Now().Add(p.Timing.SeqLockWait)
	for {
		verifiedSeq, err = ops.VerifySEQLeg(hashH[:], seqClaim.PubKey(), takerSeqRefundPub, script,
			res.SeqLocktime, funded.Leg.Txid, funded.Leg.Vout, funded.Leg.Amount, funded.Leg.Asset, 1)
		if err == nil {
			break
		}
		if errors.Is(err, xchain.ErrSEQLegInvalid) || time.Now().After(verifyDeadline) {
			sendXcFail(p.Crypter, send, "seq_leg_invalid", err.Error())
			return res, err
		}
		time.Sleep(p.Timing.Poll)
	}
	res.SeqLeg = verifiedSeq.Leg
	res.SeqBlockHash = verifiedSeq.BlockHash
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}

	// 5. Measure our OWN BTC leg's confirmation height (broadcast-only earlier)
	// for the anchor gate: the taker's asset block must anchor at/above it so
	// a parent reorg reverts both legs together before we reveal anything.
	var btcLegHeight int64
	hDeadline := time.Now().Add(p.Timing.BtcConfWait)
	for {
		confs, cerr := ops.BtcConfirmations(btcLeg.Funded.TxID)
		if cerr == nil && confs >= p.MinBTCConf {
			tip, terr := ops.BtcTip()
			if terr == nil {
				btcLegHeight = tip - int64(confs) + 1
				break
			}
		}
		if time.Now().After(hDeadline) {
			return res, fmt.Errorf("own btc leg %s never reached %d conf (refund after T_btc %d)",
				btcLeg.Funded.TxID, p.MinBTCConf, res.BtcLocktime)
		}
		time.Sleep(p.Timing.Poll)
	}
	res.BtcLegHeight = btcLegHeight
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}

	// 6. Anchor gate on the SELF-derived confirming block, then the no-reveal
	// margin, then claim the asset (revealing the secret on-chain).
	anchorDeadline := time.Now().Add(p.Timing.AnchorWait)
	for {
		if _, err = ops.VerifySeqLegSafe(verifiedSeq.BlockHash, btcLegHeight); err == nil {
			break
		}
		if time.Now().After(anchorDeadline) {
			return res, fmt.Errorf("anchor gate not passed in %s: %w (not revealing; both legs refundable)", p.Timing.AnchorWait, err)
		}
		time.Sleep(p.Timing.Poll)
	}
	tip, err := p.SeqTip()
	if err != nil {
		return res, err
	}
	if uint32(tip)+p.SeqClaimMargin >= res.SeqLocktime {
		return res, fmt.Errorf("seq tip %d within %d of T_seq %d; not revealing the secret", tip, p.SeqClaimMargin, res.SeqLocktime)
	}
	claimTxid, err := ops.ClaimSEQLeg(verifiedSeq.Leg, seqClaim, xcSeqLegFee(ops, p.AssetHex, p.SpendFeeSats, p.SeqAmount))
	if err != nil {
		return res, fmt.Errorf("seq claim failed: %w", err)
	}
	res.SeqClaimTxid = claimTxid
	res.Settled = true
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	// Courtesy reveal (the taker can also read the secret off our claim).
	reveal := &XcMsg{Type: XcSecretRevealed, Preimage: hex.EncodeToString(secret)}
	if sealed, serr := reveal.Seal(p.Crypter); serr == nil {
		_ = send(sealed)
	}
	p.logf("settled: claimed the asset in %s (secret revealed; taker claims the BTC leg)", claimTxid)
	return res, nil
}

// --- REVERSE maker resume (post-restart) -------------------------------------

// MakerReverseResumeParams reconstructs a reverse maker session from persisted
// state. The maker holds the secret and has funded the BTC leg; depending on how
// far the swap got, resume either claims the taker's asset leg (if the taker
// funded it and it is still claimable before T_seq) or refunds the maker's own
// BTC leg after T_btc. All material comes from the on-disk record.
type MakerReverseResumeParams struct {
	Ops          XcOps
	BtcLeg       *xchain.LegLock // ours; refunded after T_btc if we cannot settle
	SeqLeg       *xchain.LegLock // the taker's asset leg (nil if never funded/verified)
	SeqBlockHash string          // the taker leg's confirming block (for the anchor gate)
	Secret       []byte
	HashH        []byte
	SeqClaimKey  *xchain.Key // claims the taker's asset leg (reveals the secret)
	BtcRefundKey *xchain.Key // refunds our BTC leg after T_btc
	BtcLocktime  uint32
	SeqLocktime  uint32
	AssetHex     string
	BtcAmount    uint64
	SeqAmount    uint64
	SeqClaimMargin uint32
	MinBTCConf     int
	SpendFeeSats   uint64
	Timing         XcTiming
	OnUpdate       func(*MakerReverseResult)
	Log            func(string, ...interface{})
}

// ResumeMakerReverse finishes a reverse maker session after a restart. If the
// taker's asset leg is present and still claimable, it anchor-gates and claims
// it (revealing the secret; the taker then claims BTC). Otherwise it refunds the
// maker's BTC leg once T_btc passes. Claim and refund are mutually exclusive, so
// the secret is never revealed on a path we also refund.
func ResumeMakerReverse(p MakerReverseResumeParams) (*MakerReverseResult, error) {
	if p.Ops == nil || p.BtcLeg == nil || p.BtcRefundKey == nil {
		return nil, errors.New("maker reverse resume: incomplete state")
	}
	p.Timing.setDefaults()
	if p.SeqClaimMargin == 0 {
		p.SeqClaimMargin = 10
	}
	if p.MinBTCConf <= 0 {
		p.MinBTCConf = 1
	}
	if p.SpendFeeSats == 0 {
		p.SpendFeeSats = 1000
	}
	logf := func(string, ...interface{}) {}
	if p.Log != nil {
		logf = p.Log
	}
	res := &MakerReverseResult{
		Secret: p.Secret, HashH: p.HashH,
		SeqClaimKey: p.SeqClaimKey, BtcRefundKey: p.BtcRefundKey,
		BtcLocktime: p.BtcLocktime, SeqLocktime: p.SeqLocktime,
		BtcLeg: p.BtcLeg, SeqLeg: p.SeqLeg, SeqBlockHash: p.SeqBlockHash,
	}

	// Try to claim the taker's asset leg if we have it and can still do so
	// safely before T_seq. Anything that prevents a safe claim falls through to
	// the BTC refund.
	if p.SeqLeg != nil && p.SeqClaimKey != nil && len(p.Secret) == 32 && p.SeqBlockHash != "" {
		claimed, err := resumeReverseTryClaim(p, res, logf)
		if err != nil {
			return res, err
		}
		if claimed {
			return res, nil
		}
	} else {
		logf("reverse resume: no claimable asset leg (taker never funded / not verified); will refund the BTC leg after T_btc %d", p.BtcLocktime)
	}

	// Refund our BTC leg once T_btc passes. By then T_seq (the shorter leg) has
	// also passed, so the taker has already (or will) refund its asset leg — no
	// double-settlement.
	for {
		tip, err := p.Ops.BtcTip()
		if err != nil {
			return res, err
		}
		if uint32(tip) >= p.BtcLocktime {
			break
		}
		time.Sleep(p.Timing.Poll)
	}
	txid, err := p.Ops.RefundBTCLeg(p.BtcLeg, p.BtcRefundKey, p.BtcLocktime, xcSafeFee(p.SpendFeeSats, p.BtcAmount))
	if err != nil {
		return res, fmt.Errorf("btc refund after T_btc %d: %w", p.BtcLocktime, err)
	}
	res.BtcRefundTx = txid
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	logf("reverse resume: refunded BTC leg after T_btc: %s", txid)
	return res, fmt.Errorf("%w: reverse lift refunded (btc %s)", ErrXcRefunded, txid)
}

// resumeReverseTryClaim measures the BTC-leg height, runs the anchor gate, checks
// the T_seq margin, and claims the taker's asset leg. Returns (true, nil) on a
// successful claim; (false, nil) means "cannot claim safely, refund BTC instead".
func resumeReverseTryClaim(p MakerReverseResumeParams, res *MakerReverseResult, logf func(string, ...interface{})) (bool, error) {
	// Our BTC leg's confirmation height for the anchor ordering check.
	var btcLegHeight int64
	hDeadline := time.Now().Add(p.Timing.BtcConfWait)
	for {
		confs, cerr := p.Ops.BtcConfirmations(p.BtcLeg.Funded.TxID)
		if cerr == nil && confs >= p.MinBTCConf {
			if tip, terr := p.Ops.BtcTip(); terr == nil {
				btcLegHeight = tip - int64(confs) + 1
				break
			}
		}
		if time.Now().After(hDeadline) {
			logf("reverse resume: own BTC leg never reached %d conf; refunding", p.MinBTCConf)
			return false, nil
		}
		time.Sleep(p.Timing.Poll)
	}
	// Anchor gate on the taker leg's confirming block.
	anchorDeadline := time.Now().Add(p.Timing.AnchorWait)
	for {
		if _, err := p.Ops.VerifySeqLegSafe(p.SeqBlockHash, btcLegHeight); err == nil {
			break
		}
		if time.Now().After(anchorDeadline) {
			logf("reverse resume: anchor gate did not pass; refunding BTC instead of revealing the secret")
			return false, nil
		}
		time.Sleep(p.Timing.Poll)
	}
	// Never reveal the secret inside the T_seq margin (the taker could be
	// refunding its asset leg).
	tip, err := p.Ops.SeqTip()
	if err != nil {
		return false, err
	}
	if uint32(tip)+p.SeqClaimMargin >= p.SeqLocktime {
		logf("reverse resume: within %d of T_seq %d; too late to claim safely, refunding BTC", p.SeqClaimMargin, p.SeqLocktime)
		return false, nil
	}
	if err := p.Ops.InjectSecret(p.Secret); err != nil {
		return false, err
	}
	txid, err := p.Ops.ClaimSEQLeg(p.SeqLeg, p.SeqClaimKey, xcSeqLegFee(p.Ops, p.AssetHex, p.SpendFeeSats, p.SeqAmount))
	if err != nil {
		return false, fmt.Errorf("seq claim on resume: %w", err)
	}
	res.SeqClaimTxid = txid
	res.Settled = true
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	logf("reverse resume: claimed the taker's asset leg %s (secret revealed)", txid)
	return true, nil
}
