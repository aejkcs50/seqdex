package client

// xdriver.go runs the CROSS-CHAIN lift handshake defined in xcourier.go over the
// opaque relay courier, settling with the proven pkg/xchain HTLC engine (the same
// engine the RFQ daemon drives; this file re-fronts it onto the order book, it does
// not reimplement settlement). Phase 2b implements the FORWARD direction
// (offer.direction = BTC_TO_ASSET: the taker pays BTC and holds the secret); the
// REVERSE direction (maker = secret holder) lands in phase 2e.
//
// Shape notes, mirrored from driver.go and the RFQ flows:
//   - The drivers own Seal/Open. The maker's FIRST act on any courier bytes is
//     Crypter.Open, so a relay substituting session keys can only ever deny
//     service, never elicit a signed/funded artifact (driver.go "ITEM C").
//   - Everything from the peer is untrusted: redeem scripts are re-derived from
//     the agreed terms and byte-compared by pkg/xchain's verifiers; amounts and
//     locktimes are checked against the SIGNED offer's expectations.
//   - On a live parent chain LockBTCLeg returns height 0 (broadcast-only); the
//     TAKER waits out MinBTCConf itself and computes the confirmation height
//     Hp = tip - confs + 1 before announcing the leg, exactly like the RFQ
//     maker's watcher does, so the maker's VerifyBTCLeg and the later anchor
//     gate (SEQ block anchored at/above Hp) line up.
//   - State is in-memory, like the RFQ MVP: a process restart mid-swap loses the
//     session and the CLTV refund paths are the safety net. Callers should
//     persist (secret, keys, legs, locktimes) before funding anything; the
//     taker result carries them all even on error for exactly that reason.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// XcSend delivers one sealed courier frame to the peer (a relay SwapMsg write).
type XcSend func(sealed []byte) error

// XcRecv blocks for the next sealed courier frame, up to timeout.
type XcRecv func(timeout time.Duration) ([]byte, error)

// XcOps is the narrow settlement seam the drivers run against. LiveXcOps binds it
// to a real *xchain.Swap + chains; tests substitute a fake to exercise the
// handshake without RPC. Method contracts are pkg/xchain's.
type XcOps interface {
	// BTC side.
	BtcTip() (int64, error)
	BtcConfirmations(txid string) (int, error)
	LockBTCLeg(claimPub, refundPub []byte, amountCoins string, locktime uint32) (*xchain.LegLock, int64, error)
	VerifyBTCLeg(hashH, makerClaimPub, takerRefundPub, providedScript []byte, btcLocktime uint32,
		txid string, vout uint32, amount uint64, minConf int) (*xchain.VerifiedBTCLeg, error)
	ClaimBTCLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error)
	RefundBTCLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error)

	// SEQ side (always the anchored Sequentia/Elements node).
	SeqTip() (int64, error)
	SeqAnchorHeightOf(blockHash string) (int64, error)
	SeqBlockHashOfTx(txid string) (string, error)
	SeqFeeRate(assetHex string) (uint64, bool)
	LockSEQLeg(claimPub, refundPub []byte, amountCoins, assetLabel string, locktime uint32) (*xchain.LegLock, string, error)
	VerifySEQLeg(hashH, claimPub, refundPub, providedScript []byte, seqLocktime uint32,
		txid string, vout uint32, amount uint64, assetID string, minConf int) (*xchain.VerifiedSEQLeg, error)
	VerifySeqLegSafe(seqBlockHash string, btcLegHeight int64) (*xchain.AnchorEvidence, error)
	ClaimSEQLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error)
	WatchSEQClaim(leg *xchain.LegLock) (claimTxid string, secret []byte, err error)
	InjectSecret(secret []byte) error
	RefundSEQLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error)
	SeqBroadcast(rawHex string) (string, error)
}

// LiveXcOps implements XcOps over a real swap and its chains.
type LiveXcOps struct {
	Swap *xchain.Swap
	BTC  *xchain.BitcoinChain
	SEQ  *xchain.Chain
}

func (o *LiveXcOps) BtcTip() (int64, error)                    { return o.BTC.BlockCount() }
func (o *LiveXcOps) BtcConfirmations(txid string) (int, error) { return o.BTC.Confirmations(txid) }
func (o *LiveXcOps) LockBTCLeg(claimPub, refundPub []byte, amountCoins string, locktime uint32) (*xchain.LegLock, int64, error) {
	return o.Swap.LockBTCLeg(claimPub, refundPub, amountCoins, locktime)
}
func (o *LiveXcOps) VerifyBTCLeg(hashH, makerClaimPub, takerRefundPub, providedScript []byte, btcLocktime uint32,
	txid string, vout uint32, amount uint64, minConf int) (*xchain.VerifiedBTCLeg, error) {
	// assetID "" = real BTC on the parent chain.
	return o.Swap.VerifyBTCLeg(hashH, makerClaimPub, takerRefundPub, providedScript, btcLocktime, txid, vout, amount, "", minConf)
}
func (o *LiveXcOps) ClaimBTCLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error) {
	return o.Swap.ClaimBTCLeg(leg, key, fee)
}
func (o *LiveXcOps) RefundBTCLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error) {
	return o.Swap.RefundBTCLeg(leg, key, nLockTime, fee)
}
func (o *LiveXcOps) SeqTip() (int64, error) { return o.SEQ.BlockCount() }
func (o *LiveXcOps) SeqAnchorHeightOf(blockHash string) (int64, error) {
	return o.SEQ.BlockAnchorHeight(blockHash)
}
func (o *LiveXcOps) SeqBlockHashOfTx(txid string) (string, error) {
	return o.SEQ.BlockHashOfTx(txid)
}
func (o *LiveXcOps) SeqFeeRate(assetHex string) (uint64, bool) { return o.SEQ.FeeExchangeRate(assetHex) }
func (o *LiveXcOps) LockSEQLeg(claimPub, refundPub []byte, amountCoins, assetLabel string, locktime uint32) (*xchain.LegLock, string, error) {
	return o.Swap.LockSEQLeg(claimPub, refundPub, amountCoins, assetLabel, locktime)
}
func (o *LiveXcOps) VerifySEQLeg(hashH, claimPub, refundPub, providedScript []byte, seqLocktime uint32,
	txid string, vout uint32, amount uint64, assetID string, minConf int) (*xchain.VerifiedSEQLeg, error) {
	return o.Swap.VerifySEQLeg(hashH, claimPub, refundPub, providedScript, seqLocktime, txid, vout, amount, assetID, minConf)
}
func (o *LiveXcOps) VerifySeqLegSafe(seqBlockHash string, btcLegHeight int64) (*xchain.AnchorEvidence, error) {
	return o.Swap.VerifySeqLegSafe(seqBlockHash, btcLegHeight)
}
func (o *LiveXcOps) ClaimSEQLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error) {
	return o.Swap.ClaimSEQLeg(leg, key, fee)
}
func (o *LiveXcOps) WatchSEQClaim(leg *xchain.LegLock) (string, []byte, error) {
	return o.Swap.WatchSEQClaim(leg)
}
func (o *LiveXcOps) InjectSecret(secret []byte) error { return o.Swap.InjectSecret(secret) }
func (o *LiveXcOps) RefundSEQLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error) {
	return o.Swap.RefundSEQLeg(leg, key, nLockTime, fee)
}
func (o *LiveXcOps) SeqBroadcast(rawHex string) (string, error) { return o.SEQ.Broadcast(rawHex) }

// XcTiming bundles the polling/wait knobs; zero values take the defaults.
type XcTiming struct {
	Poll         time.Duration // chain/watch polling cadence (default 5s)
	TermsWait    time.Duration // taker: wait for XcTerms (default 2m)
	BtcConfWait  time.Duration // taker: wait for own BTC-leg confirmation (default 90m)
	SeqLockWait  time.Duration // taker: wait for XcSeqLegLocked after announcing (default 15m; maker's LockSEQLeg alone can take ~3m)
	AnchorWait   time.Duration // taker: wait for the anchor gate to pass (default 20m)
	TermsReqWait time.Duration // maker: wait for XcTermsRequest (default 2m)
	BtcFundWait  time.Duration // maker: wait for XcBtcLegFunded (default 2h; covers the taker's conf wait)
}

func (t *XcTiming) setDefaults() {
	if t.Poll <= 0 {
		t.Poll = 5 * time.Second
	}
	if t.TermsWait <= 0 {
		t.TermsWait = 2 * time.Minute
	}
	if t.BtcConfWait <= 0 {
		t.BtcConfWait = 90 * time.Minute
	}
	if t.SeqLockWait <= 0 {
		t.SeqLockWait = 15 * time.Minute
	}
	if t.AnchorWait <= 0 {
		t.AnchorWait = 20 * time.Minute
	}
	if t.TermsReqWait <= 0 {
		t.TermsReqWait = 2 * time.Minute
	}
	if t.BtcFundWait <= 0 {
		t.BtcFundWait = 2 * time.Hour
	}
}

// Sentinel errors.
var (
	ErrXcPeerFailed = errors.New("peer failed the cross-chain lift") // wraps an XcFail from the counterparty
	ErrXcBadTerms   = errors.New("cross-chain terms rejected")
	ErrXcRefunded   = errors.New("cross-chain leg refunded")
)

// atomsToCoins renders atoms as an 8-decimal coin string for wallet RPCs.
func atomsToCoins(a uint64) string { return fmt.Sprintf("%d.%08d", a/100_000_000, a%100_000_000) }

// xcSafeFee clamps a flat sat fee to half the leg so the output stays positive.
func xcSafeFee(spendFee, legAmount uint64) uint64 {
	if max := legAmount / 2; spendFee > max {
		return max
	}
	return spendFee
}

// xcSeqLegFee sizes the fee for spending a SEQ-side leg IN THE LEG'S OWN asset:
// the flat native-sats target converted through the open-fee-market exchange rate
// (asset_atoms = ceil(spendFee*1e8/rate)), exactly like the RFQ watcher and the
// wallet do — a valuable asset correctly pays FEWER atoms. Falls back to the flat
// target when no rate is published; clamped to half the leg.
func xcSeqLegFee(ops XcOps, assetHex string, spendFee, legAmount uint64) uint64 {
	fee := spendFee
	if rate, ok := ops.SeqFeeRate(assetHex); ok && rate > 0 {
		const scale = 100_000_000
		fee = (spendFee*scale + rate - 1) / rate
		if fee == 0 {
			fee = 1
		}
	}
	return xcSafeFee(fee, legAmount)
}

// sendXc seals and sends one message; sendXcFail is its best-effort error twin.
func sendXc(m *XcMsg, c *Crypter, send XcSend) error {
	sealed, err := m.Seal(c)
	if err != nil {
		return err
	}
	return send(sealed)
}

func sendXcFail(c *Crypter, send XcSend, code, msg string) {
	if sealed, err := failMsg(code, msg).Seal(c); err == nil {
		_ = send(sealed)
	}
}

// recvXcType receives, opens, and filters courier frames until one of the wanted
// type arrives, the peer fails the session, or the deadline passes. Unknown or
// out-of-order message types are skipped (the courier is at-least-once-ish and a
// future peer may add courtesy messages).
func recvXcType(recv XcRecv, c *Crypter, want XcMsgType, wait time.Duration) (*XcMsg, error) {
	deadline := time.Now().Add(wait)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil, fmt.Errorf("timed out waiting for %q", want)
		}
		sealed, err := recv(remain)
		if err != nil {
			return nil, fmt.Errorf("courier recv while waiting for %q: %w", want, err)
		}
		m, err := OpenXcMsg(sealed, c)
		if err != nil {
			// An undecryptable frame is at most relay noise/injection (the relay
			// can always drop or garble; killing the session here would hand it
			// MORE power than dropping). Skip it; the deadline bounds the loop.
			continue
		}
		switch m.Type {
		case want:
			return m, nil
		case XcFail:
			return nil, fmt.Errorf("%w: %s: %s", ErrXcPeerFailed, m.Code, m.Message)
		default:
			continue
		}
	}
}

// --- FORWARD taker -----------------------------------------------------------

// TakerForwardParams configures RunTakerForward. Expectations come from the
// SIGNED offer the taker verified before lifting; the courier peer and relay are
// untrusted beyond it.
type TakerForwardParams struct {
	Ops     XcOps
	Crypter *Crypter

	Secret       []byte      // 32-byte preimage; Ops' hashlock must be built from it
	BtcRefundKey *xchain.Key // refunds our BTC leg after T_btc
	SeqClaimKey  *xchain.Key // claims the SEQ leg (the claim reveals Secret on-chain)

	ExpectAsset     string // SEQ asset hex the offer sells (required)
	ExpectSeqAmount uint64 // atoms the offer promises (required; whole-HTLC lift)
	ExpectBtcAmount uint64 // sats the offer wants (required)
	MaxFeeBtc       uint64 // refuse terms whose fee_btc exceeds this

	// Locktime sanity. T_btc bounds how long our BTC can be locked before the
	// refund path opens; T_seq must leave us a real window to claim after the
	// anchor gate, and we must never reveal the secret when the maker's refund
	// path is about to open (it could race our claim with its refund). The
	// window must cover a REAL parent confirmation (median ~10 min, long tail)
	// plus the maker's SEQ lock (~3 min worst) plus the anchor gate, in ~30 s
	// SEQ slots — hence the 120-slot (~1 h) default; a maker quoting less is
	// refused BEFORE any BTC moves.
	MaxBtcLockDelta   uint32 // default 400 parent blocks
	MinSeqClaimWindow uint32 // default 120 SEQ blocks at terms time
	SeqClaimMargin    uint32 // default 10 SEQ blocks: refuse to claim closer than this to T_seq

	MinBTCConf   int    // confirmations before announcing our BTC leg (default 1)
	SpendFeeSats uint64 // fee target in native sats (default 1000)
	Timing       XcTiming
	Log          func(format string, args ...interface{})

	// OnBtcLegFunded is invoked the moment the BTC leg is funded, BEFORE the
	// confirmation wait: the caller must persist the result's leg, locktime,
	// and its own keys/secret there, so a crash during the (potentially long)
	// wait never strands coins behind an unknowable redeem script.
	OnBtcLegFunded func(*TakerForwardResult)
}

// TakerForwardResult is returned even alongside an error once the BTC leg is
// funded, so the caller can persist it and refund after T_btc.
type TakerForwardResult struct {
	Terms        *XcMsg
	BtcLeg       *xchain.LegLock
	BtcLegHeight int64
	BtcLocktime  uint32
	SeqLeg       *xchain.LegLock
	SeqClaimTxid string
	Evidence     *xchain.AnchorEvidence
}

func (p *TakerForwardParams) logf(format string, args ...interface{}) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// RunTakerForward executes the forward handshake as the taker: request terms,
// fund + confirm the BTC leg, announce it, verify the maker's SEQ leg through
// the anchor gate, and claim it (revealing the secret). The maker then extracts
// the secret from our claim on-chain; no further courier messages are needed.
func RunTakerForward(p TakerForwardParams, send XcSend, recv XcRecv) (*TakerForwardResult, error) {
	p.Timing.setDefaults()
	if p.Ops == nil || p.Crypter == nil || len(p.Secret) != 32 || p.BtcRefundKey == nil || p.SeqClaimKey == nil {
		return nil, errors.New("taker forward: incomplete params")
	}
	if p.ExpectAsset == "" || p.ExpectSeqAmount == 0 || p.ExpectBtcAmount == 0 {
		return nil, errors.New("taker forward: offer expectations required")
	}
	if p.MaxBtcLockDelta == 0 {
		p.MaxBtcLockDelta = 400
	}
	if p.MinSeqClaimWindow == 0 {
		p.MinSeqClaimWindow = 120
	}
	if p.SeqClaimMargin == 0 {
		p.SeqClaimMargin = 10
	}
	if p.MinBTCConf <= 0 {
		p.MinBTCConf = 1
	}
	if p.SpendFeeSats == 0 {
		p.SpendFeeSats = 1000
	}
	res := &TakerForwardResult{}
	hashH := sha256.Sum256(p.Secret)

	// 1. Ask for per-lift terms.
	if err := sendXc(&XcMsg{Type: XcTermsRequest}, p.Crypter, send); err != nil {
		return res, err
	}
	terms, err := recvXcType(recv, p.Crypter, XcTerms, p.Timing.TermsWait)
	if err != nil {
		return res, err
	}
	res.Terms = terms
	res.BtcLocktime = terms.BtcLocktime

	// 2. Bind the terms to the signed offer and sanity-check the locktimes.
	if terms.BtcAmount != p.ExpectBtcAmount {
		sendXcFail(p.Crypter, send, "terms_mismatch", "btc_amount differs from the signed offer")
		return res, fmt.Errorf("%w: btc_amount %d != offer %d", ErrXcBadTerms, terms.BtcAmount, p.ExpectBtcAmount)
	}
	if terms.SeqAmount != p.ExpectSeqAmount {
		sendXcFail(p.Crypter, send, "terms_mismatch", "seq_amount differs from the signed offer")
		return res, fmt.Errorf("%w: seq_amount %d != offer %d", ErrXcBadTerms, terms.SeqAmount, p.ExpectSeqAmount)
	}
	if terms.FeeBtc > p.MaxFeeBtc {
		sendXcFail(p.Crypter, send, "terms_mismatch", "fee_btc exceeds the taker bound")
		return res, fmt.Errorf("%w: fee_btc %d > max %d", ErrXcBadTerms, terms.FeeBtc, p.MaxFeeBtc)
	}
	makerBtcClaimPub, err := hex.DecodeString(terms.MakerBtcClaimPub)
	if err != nil || len(makerBtcClaimPub) != 33 {
		return res, fmt.Errorf("%w: bad maker_btc_claim_pub", ErrXcBadTerms)
	}
	makerSeqRefundPub, err := hex.DecodeString(terms.MakerRefundPub)
	if err != nil || len(makerSeqRefundPub) != 33 {
		return res, fmt.Errorf("%w: bad maker_refund_pub", ErrXcBadTerms)
	}
	btcTip, err := p.Ops.BtcTip()
	if err != nil {
		return res, err
	}
	seqTip, err := p.Ops.SeqTip()
	if err != nil {
		return res, err
	}
	if terms.BtcLocktime <= uint32(btcTip) || terms.BtcLocktime > uint32(btcTip)+p.MaxBtcLockDelta {
		sendXcFail(p.Crypter, send, "terms_mismatch", "btc_locktime out of bounds")
		return res, fmt.Errorf("%w: btc_locktime %d vs tip %d (max delta %d)", ErrXcBadTerms, terms.BtcLocktime, btcTip, p.MaxBtcLockDelta)
	}
	if terms.SeqLocktime < uint32(seqTip)+p.MinSeqClaimWindow {
		sendXcFail(p.Crypter, send, "terms_mismatch", "seq_locktime leaves no claim window")
		return res, fmt.Errorf("%w: seq_locktime %d vs tip %d (min window %d)", ErrXcBadTerms, terms.SeqLocktime, seqTip, p.MinSeqClaimWindow)
	}

	// 3. Fund the BTC leg and wait out our own confirmation: on a live parent
	// LockBTCLeg is broadcast-only (Hp=0) and the maker will reject an
	// unconfirmed leg, so we only announce once MinBTCConf is reached, with the
	// confirmation height the anchor gate will be measured against.
	p.logf("locking BTC leg: %d sats, T_btc=%d", terms.BtcAmount, terms.BtcLocktime)
	btcLeg, hp, err := p.Ops.LockBTCLeg(makerBtcClaimPub, p.BtcRefundKey.PubKey(), atomsToCoins(terms.BtcAmount), terms.BtcLocktime)
	if err != nil {
		sendXcFail(p.Crypter, send, "btc_lock_failed", err.Error())
		return res, err
	}
	res.BtcLeg = btcLeg
	if p.OnBtcLegFunded != nil {
		p.OnBtcLegFunded(res)
	}
	if hp <= 0 {
		confDeadline := time.Now().Add(p.Timing.BtcConfWait)
		for {
			confs, cerr := p.Ops.BtcConfirmations(btcLeg.Funded.TxID)
			if cerr == nil && confs >= p.MinBTCConf {
				tip, terr := p.Ops.BtcTip()
				if terr == nil {
					hp = tip - int64(confs) + 1
					break
				}
			}
			if time.Now().After(confDeadline) {
				sendXcFail(p.Crypter, send, "btc_conf_timeout", "btc leg did not confirm in time")
				return res, fmt.Errorf("btc leg %s: no %d-conf within %s (refund after T_btc %d)",
					btcLeg.Funded.TxID, p.MinBTCConf, p.Timing.BtcConfWait, terms.BtcLocktime)
			}
			time.Sleep(p.Timing.Poll)
		}
	}
	res.BtcLegHeight = hp
	p.logf("BTC leg %s confirmed at height %d", btcLeg.Funded.TxID, hp)

	// 4. Announce the leg.
	announce := &XcMsg{
		Type:              XcBtcLegFunded,
		HashH:             hex.EncodeToString(hashH[:]),
		TakerSeqClaimPub:  hex.EncodeToString(p.SeqClaimKey.PubKey()),
		TakerBtcRefundPub: hex.EncodeToString(p.BtcRefundKey.PubKey()),
		Leg: &XcLeg{
			Txid:         btcLeg.Funded.TxID,
			Vout:         btcLeg.Funded.Vout,
			Amount:       btcLeg.Funded.Amount,
			RedeemScript: hex.EncodeToString(btcLeg.Script),
			Locktime:     terms.BtcLocktime,
			Height:       hp,
		},
	}
	if err := sendXc(announce, p.Crypter, send); err != nil {
		return res, err
	}

	// 5. Await + verify the maker's SEQ leg. The redeem script is re-derived
	// byte-for-byte by VerifySEQLeg (claim = our key, refund = the maker's from
	// terms), and the amount/asset are bound to the signed offer.
	locked, err := recvXcType(recv, p.Crypter, XcSeqLegLocked, p.Timing.SeqLockWait)
	if err != nil {
		return res, err
	}
	if locked.Leg == nil {
		return res, errors.New("seq_leg_locked without a leg")
	}
	if locked.Leg.Amount != p.ExpectSeqAmount || locked.Leg.Asset != p.ExpectAsset {
		sendXcFail(p.Crypter, send, "seq_leg_mismatch", "amount/asset differ from the signed offer")
		return res, fmt.Errorf("seq leg %d %s != offer %d %s", locked.Leg.Amount, locked.Leg.Asset, p.ExpectSeqAmount, p.ExpectAsset)
	}
	if locked.Leg.Locktime != terms.SeqLocktime {
		sendXcFail(p.Crypter, send, "seq_leg_mismatch", "locktime differs from terms")
		return res, fmt.Errorf("seq leg locktime %d != terms %d", locked.Leg.Locktime, terms.SeqLocktime)
	}
	script, err := hex.DecodeString(locked.Leg.RedeemScript)
	if err != nil {
		return res, fmt.Errorf("bad seq redeem_script hex: %w", err)
	}
	verified, err := p.Ops.VerifySEQLeg(hashH[:], p.SeqClaimKey.PubKey(), makerSeqRefundPub, script,
		terms.SeqLocktime, locked.Leg.Txid, locked.Leg.Vout, locked.Leg.Amount, locked.Leg.Asset, 1)
	if err != nil {
		sendXcFail(p.Crypter, send, "seq_leg_invalid", err.Error())
		return res, err
	}
	res.SeqLeg = verified.Leg

	// 6. Anchor gate: the SEQ block holding the leg must anchor at/above our BTC
	// confirmation height and the node's anchor must be healthy. The block hash
	// is the SELF-DERIVED one from our own node's view of the leg (VerifySEQLeg),
	// NEVER the courier-supplied value: a malicious maker could otherwise quote
	// any well-anchored block for a leg that actually confirmed in a badly
	// anchored one, voiding the exact ordering guarantee this gate exists for.
	// Retried: a parent flap makes this transiently fail and anchoring
	// supremacy sorts it.
	anchorDeadline := time.Now().Add(p.Timing.AnchorWait)
	var ev *xchain.AnchorEvidence
	for {
		ev, err = p.Ops.VerifySeqLegSafe(verified.BlockHash, hp)
		if err == nil {
			break
		}
		if time.Now().After(anchorDeadline) {
			return res, fmt.Errorf("anchor gate not passed in %s: %w (BTC refundable after T_btc %d)", p.Timing.AnchorWait, err, terms.BtcLocktime)
		}
		time.Sleep(p.Timing.Poll)
	}
	res.Evidence = ev

	// 7. Claim window re-check: never reveal the secret when the maker's refund
	// path is about to open (it could race our claim). Abort WITHOUT revealing;
	// our BTC refund after T_btc is then the exit.
	seqTip2, err := p.Ops.SeqTip()
	if err != nil {
		return res, err
	}
	if uint32(seqTip2)+p.SeqClaimMargin >= terms.SeqLocktime {
		return res, fmt.Errorf("%w: seq tip %d within %d of T_seq %d; not revealing the secret",
			ErrXcBadTerms, seqTip2, p.SeqClaimMargin, terms.SeqLocktime)
	}

	// 8. Claim the SEQ leg (reveals the secret on-chain; the maker's watcher
	// extracts it and claims the BTC leg — the handshake is complete for us).
	fee := xcSeqLegFee(p.Ops, p.ExpectAsset, p.SpendFeeSats, locked.Leg.Amount)
	claimTxid, err := p.Ops.ClaimSEQLeg(verified.Leg, p.SeqClaimKey, fee)
	if err != nil {
		return res, fmt.Errorf("seq claim failed: %w (BTC refundable after T_btc %d)", err, terms.BtcLocktime)
	}
	res.SeqClaimTxid = claimTxid
	p.logf("claimed SEQ leg: %s (secret revealed)", claimTxid)
	return res, nil
}

// RefundTakerBTC spends the taker's BTC leg through the CLTV refund path once
// T_btc has passed. With wait=false it returns ErrXcRefundNotDue when early.
var ErrXcRefundNotDue = errors.New("btc refund locktime not yet reached")

func RefundTakerBTC(ops XcOps, leg *xchain.LegLock, key *xchain.Key, locktime uint32, spendFeeSats uint64, wait bool, poll time.Duration) (string, error) {
	if poll <= 0 {
		poll = 15 * time.Second
	}
	if spendFeeSats == 0 {
		spendFeeSats = 1000
	}
	for {
		tip, err := ops.BtcTip()
		if err != nil {
			return "", err
		}
		if uint32(tip) >= locktime {
			break
		}
		if !wait {
			return "", fmt.Errorf("%w: tip %d < T_btc %d", ErrXcRefundNotDue, tip, locktime)
		}
		time.Sleep(poll)
	}
	return ops.RefundBTCLeg(leg, key, locktime, xcSafeFee(spendFeeSats, leg.Funded.Amount))
}

// --- FORWARD maker -----------------------------------------------------------

// MakerForwardParams configures RunMakerForward. Amounts and the asset come from
// the maker's own SIGNED offer (whole-HTLC: the lift's take_amount must equal the
// offer's base amount; the caller enforces that before starting the driver).
type MakerForwardParams struct {
	// NewOps binds the settlement engine to the taker's hashlock once it arrives
	// (the maker never knows the secret; it builds from the hash).
	NewOps  func(hashH []byte) (XcOps, error)
	Crypter *Crypter

	// Tip queries usable BEFORE the hashlock exists (terms are minted first).
	BtcTip func() (int64, error)
	SeqTip func() (int64, error)

	AssetHex  string // SEQ asset we deliver (offer pair base)
	SeqAmount uint64 // atoms we lock
	BtcAmount uint64 // sats we require
	FeeBtc    uint64 // advisory fee surfaced in terms

	// Locktime deltas above the respective tips. T_btc must be LONGER IN TIME
	// than T_seq, and T_seq must leave the taker room for a REAL parent
	// confirmation before its claim: 100 parent blocks ~16 h vs 240 SEQ slots
	// ~2 h. (The RFQ's 50-slot delta was tuned for regtest; on a live parent a
	// taker with the default 120-slot minimum window rightly refuses it.)
	BtcLocktimeDelta uint32 // default 100
	SeqLocktimeDelta uint32 // default 240

	MinBTCConf   int    // confirmations required on the taker's BTC leg (default 1; testnet-grade — depth, not anchoring, protects the maker's BTC side)
	SpendFeeSats uint64 // fee target in native sats (default 1000)
	Timing       XcTiming
	Log          func(format string, args ...interface{})

	// OnUpdate is invoked after every state transition that creates or changes
	// recoverable value (keys minted, legs funded/verified, secret learned,
	// settled/refunded). The caller must persist the result snapshot there: the
	// per-lift keys exist nowhere else, and losing them mid-swap burns a leg.
	OnUpdate func(*MakerForwardResult)
}

// MakerForwardResult reports the lift's evolving state; with OnUpdate it is the
// maker's persistence record (the keys are the recovery material).
type MakerForwardResult struct {
	HashH        []byte
	BtcClaimKey  *xchain.Key // claims the taker's BTC leg once the secret is known
	SeqRefundKey *xchain.Key // refunds our SEQ leg after T_seq
	BtcLocktime  uint32
	SeqLocktime  uint32
	BtcLeg       *xchain.LegLock // the taker's verified BTC leg
	SeqLeg       *xchain.LegLock
	SeqBlockHash string
	Secret       []byte
	BtcClaimTxid string
	SeqRefundTx  string
	Settled      bool
}

func (p *MakerForwardParams) logf(format string, args ...interface{}) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// RunMakerForward executes the forward handshake as the maker: mint per-lift
// terms, verify the taker's confirmed BTC leg, lock the SEQ leg, then watch for
// the taker's claim and redeem the BTC leg with the revealed secret — or refund
// the SEQ leg once T_seq passes without a claim. `in` delivers sealed courier
// frames for this session; the driver owns Open (first act) and Seal.
func RunMakerForward(p MakerForwardParams, in <-chan []byte, send XcSend) (*MakerForwardResult, error) {
	p.Timing.setDefaults()
	if p.NewOps == nil || p.Crypter == nil || p.BtcTip == nil || p.SeqTip == nil {
		return nil, errors.New("maker forward: incomplete params")
	}
	if p.AssetHex == "" || p.SeqAmount == 0 || p.BtcAmount == 0 {
		return nil, errors.New("maker forward: offer amounts required")
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
	res := &MakerForwardResult{}

	// 1. Terms request, then mint per-lift terms with FRESH keys (the offer's
	// resting keys are advisory/discovery only).
	if _, err := recvXcType(recv, p.Crypter, XcTermsRequest, p.Timing.TermsReqWait); err != nil {
		return res, err
	}
	makerBtcClaim, err := xchain.NewKey()
	if err != nil {
		return res, err
	}
	makerSeqRefund, err := xchain.NewKey()
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
	btcLocktime := uint32(btcTip) + p.BtcLocktimeDelta
	seqLocktime := uint32(seqTip) + p.SeqLocktimeDelta
	res.BtcClaimKey, res.SeqRefundKey = makerBtcClaim, makerSeqRefund
	res.BtcLocktime, res.SeqLocktime = btcLocktime, seqLocktime
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	terms := &XcMsg{
		Type:             XcTerms,
		MakerBtcClaimPub: hex.EncodeToString(makerBtcClaim.PubKey()),
		MakerRefundPub:   hex.EncodeToString(makerSeqRefund.PubKey()),
		BtcLocktime:      btcLocktime,
		SeqLocktime:      seqLocktime,
		BtcAmount:        p.BtcAmount,
		SeqAmount:        p.SeqAmount,
		FeeBtc:           p.FeeBtc,
	}
	if err := sendXc(terms, p.Crypter, send); err != nil {
		return res, err
	}
	p.logf("terms sent: %d sats <- %d atoms %s, T_btc=%d T_seq=%d", p.BtcAmount, p.SeqAmount, p.AssetHex, btcLocktime, seqLocktime)

	// 2. The taker's confirmed BTC leg.
	funded, err := recvXcType(recv, p.Crypter, XcBtcLegFunded, p.Timing.BtcFundWait)
	if err != nil {
		return res, err
	}
	if funded.Leg == nil {
		return res, errors.New("btc_leg_funded without a leg")
	}
	hashH, err := hex.DecodeString(funded.HashH)
	if err != nil || len(hashH) != 32 {
		sendXcFail(p.Crypter, send, "bad_hash", "hash_h must be 32 bytes hex")
		return res, errors.New("bad hash_h")
	}
	takerSeqClaimPub, err := hex.DecodeString(funded.TakerSeqClaimPub)
	if err != nil || len(takerSeqClaimPub) != 33 {
		sendXcFail(p.Crypter, send, "bad_pubkey", "taker_seq_claim_pub invalid")
		return res, errors.New("bad taker_seq_claim_pub")
	}
	takerBtcRefundPub, err := hex.DecodeString(funded.TakerBtcRefundPub)
	if err != nil || len(takerBtcRefundPub) != 33 {
		sendXcFail(p.Crypter, send, "bad_pubkey", "taker_btc_refund_pub invalid")
		return res, errors.New("bad taker_btc_refund_pub")
	}
	if funded.Leg.Amount != p.BtcAmount {
		sendXcFail(p.Crypter, send, "btc_leg_mismatch", "amount differs from terms")
		return res, fmt.Errorf("btc leg amount %d != terms %d", funded.Leg.Amount, p.BtcAmount)
	}
	ops, err := p.NewOps(hashH)
	if err != nil {
		return res, err
	}
	res.HashH = hashH
	script, err := hex.DecodeString(funded.Leg.RedeemScript)
	if err != nil {
		return res, fmt.Errorf("bad btc redeem_script hex: %w", err)
	}
	// The taker announces the instant ITS node reports MinBTCConf; ours can lag
	// by propagation/indexing or run a stricter -min-btc-conf. Only a proven
	// INVALID leg is terminal; unconfirmed / not-yet-visible is polled out (the
	// RFQ path got the same tolerance from the taker retrying the RPC).
	var verifiedBtc *xchain.VerifiedBTCLeg
	verifyDeadline := time.Now().Add(p.Timing.SeqLockWait)
	for {
		verifiedBtc, err = ops.VerifyBTCLeg(hashH, makerBtcClaim.PubKey(), takerBtcRefundPub, script,
			btcLocktime, funded.Leg.Txid, funded.Leg.Vout, funded.Leg.Amount, p.MinBTCConf)
		if err == nil {
			break
		}
		if errors.Is(err, xchain.ErrBTCLegInvalid) || time.Now().After(verifyDeadline) {
			sendXcFail(p.Crypter, send, "btc_leg_invalid", err.Error())
			return res, err
		}
		time.Sleep(p.Timing.Poll)
	}
	res.BtcLeg = verifiedBtc.Leg
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	p.logf("taker BTC leg verified: %s (height %d)", funded.Leg.Txid, funded.Leg.Height)

	// 3. Lock the SEQ leg and announce it with its anchor evidence. A funded-
	// but-unconfirmed lock (LockSEQLeg's ~3 min budget on a stalled chain) is
	// NOT abandoned: the leg is persisted and its confirming block polled out,
	// so the coins are never stranded behind an unknowable script.
	seqLeg, seqBlockHash, err := ops.LockSEQLeg(takerSeqClaimPub, makerSeqRefund.PubKey(),
		atomsToCoins(p.SeqAmount), p.AssetHex, seqLocktime)
	if seqLeg != nil {
		res.SeqLeg = seqLeg
		if p.OnUpdate != nil {
			p.OnUpdate(res)
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
				sendXcFail(p.Crypter, send, "seq_lock_failed", "seq leg funded but unconfirmed; will refund after T_seq")
				return res, fmt.Errorf("seq leg %s funded but unconfirmed within %s (refund after T_seq %d)",
					seqLeg.Funded.TxID, p.Timing.SeqLockWait, seqLocktime)
			}
			time.Sleep(p.Timing.Poll)
		}
	}
	res.SeqBlockHash = seqBlockHash
	if p.OnUpdate != nil {
		p.OnUpdate(res)
	}
	anchorH, err := ops.SeqAnchorHeightOf(seqBlockHash)
	if err != nil {
		// Non-fatal for the announcement: the taker re-checks via its own node.
		anchorH = 0
	}
	lockedMsg := &XcMsg{
		Type: XcSeqLegLocked,
		Leg: &XcLeg{
			Txid:         seqLeg.Funded.TxID,
			Vout:         seqLeg.Funded.Vout,
			Amount:       seqLeg.Funded.Amount,
			Asset:        seqLeg.Funded.AssetID,
			RedeemScript: hex.EncodeToString(seqLeg.Script),
			Locktime:     seqLocktime,
			BlockHash:    seqBlockHash,
			AnchorHeight: anchorH,
		},
	}
	if err := sendXc(lockedMsg, p.Crypter, send); err != nil {
		// The SEQ leg is on-chain: from here the session must end in claim or
		// refund regardless of courier health, so a failed announce is logged,
		// not fatal. The taker most likely never learns the leg and never
		// claims; the T_seq refund below then recovers it automatically.
		p.logf("seq_leg_locked announce failed (%v); continuing to watch on-chain", err)
	}
	p.logf("SEQ leg locked: %s in block %s (anchor %d)", seqLeg.Funded.TxID, seqBlockHash, anchorH)

	// 4. Watch for the taker's claim (which reveals the secret) and redeem the
	// BTC leg — or refund the SEQ leg once T_seq passes without a claim. This
	// is a pure ON-CHAIN loop with no further courier dependency, so it is also
	// the resume entrypoint (settleMakerForward): a maker that restarts mid-swap
	// reconstructs the legs/keys from persisted state and re-enters it.
	return settleMakerForward(ops, res, verifiedBtc.Leg, seqLeg, makerBtcClaim, makerSeqRefund,
		btcLocktime, seqLocktime, p.AssetHex, p.BtcAmount, p.SeqAmount, p.SpendFeeSats, p.Timing,
		func(code, msg string) { sendXcFail(p.Crypter, send, code, msg) }, p.OnUpdate, p.logf)
}

// settleMakerForward is the maker's on-chain settle loop, shared by
// RunMakerForward (live) and ResumeMakerForward (post-restart). It watches the
// maker's SEQ leg for the taker's claim (which reveals the secret) and redeems
// the taker's BTC leg, or refunds the SEQ leg once T_seq passes. res is mutated
// and returned; onUpdate persists each transition. onRefundNote couriers an
// advisory XcFail if a live session is still attached (nil-safe).
func settleMakerForward(ops XcOps, res *MakerForwardResult, btcLeg, seqLeg *xchain.LegLock,
	makerBtcClaim, makerSeqRefund *xchain.Key, btcLocktime, seqLocktime uint32,
	assetHex string, btcAmount, seqAmount, spendFeeSats uint64, timing XcTiming,
	onRefundNote func(code, msg string), onUpdate func(*MakerForwardResult), logf func(string, ...interface{})) (*MakerForwardResult, error) {
	timing.setDefaults()
	for {
		claimTxid, secret, werr := ops.WatchSEQClaim(seqLeg)
		if werr == nil && len(secret) > 0 {
			if err := ops.InjectSecret(secret); err != nil {
				return res, err
			}
			res.Secret = secret
			if onUpdate != nil {
				onUpdate(res)
			}
			btcClaimTxid, cerr := ops.ClaimBTCLeg(btcLeg, makerBtcClaim, xcSafeFee(spendFeeSats, btcAmount))
			if cerr != nil {
				if tip, terr := ops.BtcTip(); terr == nil && uint32(tip) >= btcLocktime-6 {
					return res, fmt.Errorf("btc claim still failing near T_btc %d (secret persisted): %w", btcLocktime, cerr)
				}
				logf("btc claim retrying: %v", cerr)
				time.Sleep(timing.Poll)
				continue
			}
			res.BtcClaimTxid = btcClaimTxid
			res.Settled = true
			if onUpdate != nil {
				onUpdate(res)
			}
			logf("settled: taker claimed SEQ (%s), we claimed BTC (%s)", claimTxid, btcClaimTxid)
			return res, nil
		}
		tip, terr := ops.SeqTip()
		if terr == nil && uint32(tip) >= seqLocktime {
			raw, rerr := ops.RefundSEQLeg(seqLeg, makerSeqRefund, seqLocktime, xcSeqLegFee(ops, assetHex, spendFeeSats, seqAmount))
			if rerr == nil {
				if txid, berr := ops.SeqBroadcast(raw); berr == nil {
					res.SeqRefundTx = txid
					if onUpdate != nil {
						onUpdate(res)
					}
					if onRefundNote != nil {
						onRefundNote("refunded", "seq leg refunded after T_seq")
					}
					logf("refunded SEQ leg after T_seq: %s", txid)
					return res, fmt.Errorf("%w: no claim by T_seq %d", ErrXcRefunded, seqLocktime)
				}
			}
			// Build/broadcast hiccup: retry next tick until it lands.
		}
		time.Sleep(timing.Poll)
	}
}

// MakerForwardResumeParams reconstructs a maker forward session from persisted
// state after a restart. All legs/keys/locktimes come from the on-disk record;
// the driver re-enters the on-chain settle loop with no courier.
type MakerForwardResumeParams struct {
	Ops          XcOps
	BtcLeg       *xchain.LegLock // the taker's BTC leg (we claim it with the secret)
	SeqLeg       *xchain.LegLock // our asset leg (we watch it / refund it)
	BtcClaimKey  *xchain.Key
	SeqRefundKey *xchain.Key
	HashH        []byte
	BtcLocktime  uint32
	SeqLocktime  uint32
	AssetHex     string
	BtcAmount    uint64
	SeqAmount    uint64
	SpendFeeSats uint64
	Timing       XcTiming
	OnUpdate     func(*MakerForwardResult)
	Log          func(string, ...interface{})
}

// ResumeMakerForward finishes a maker forward session after a restart: it drives
// the same on-chain settle loop RunMakerForward ends with, so a mid-swap crash
// or courier timeout completes (claim on the taker's reveal) or refunds (after
// T_seq) instead of stranding the maker's asset leg.
func ResumeMakerForward(p MakerForwardResumeParams) (*MakerForwardResult, error) {
	if p.Ops == nil || p.BtcLeg == nil || p.SeqLeg == nil || p.BtcClaimKey == nil || p.SeqRefundKey == nil {
		return nil, errors.New("maker forward resume: incomplete state")
	}
	logf := func(string, ...interface{}) {}
	if p.Log != nil {
		logf = p.Log
	}
	res := &MakerForwardResult{
		HashH: p.HashH, BtcClaimKey: p.BtcClaimKey, SeqRefundKey: p.SeqRefundKey,
		BtcLocktime: p.BtcLocktime, SeqLocktime: p.SeqLocktime,
		BtcLeg: p.BtcLeg, SeqLeg: p.SeqLeg,
	}
	return settleMakerForward(p.Ops, res, p.BtcLeg, p.SeqLeg, p.BtcClaimKey, p.SeqRefundKey,
		p.BtcLocktime, p.SeqLocktime, p.AssetHex, p.BtcAmount, p.SeqAmount, p.SpendFeeSats,
		p.Timing, nil, p.OnUpdate, logf)
}
