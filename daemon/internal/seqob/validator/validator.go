// Package validator validates SeqOB offers before they enter the book.
//
// Checks: signature, schema, amounts > 0, known assets, trade-direction/asset
// consistency, a mandatory non-absurd expiry (short self-expiry so a suppressed
// cancel self-heals — review M3), and per-maker_pubkey + per-IP rate limits.
//
// It does NOT enforce a min_anchor_depth floor: per the project policy override
// the DEX is 0-conf tolerant and min_anchor_depth is a maker-only dial that
// defaults to 0. The liveness probe is an interface with a no-op default and is
// explicitly a Phase-1 stub (confidential balances make a precise probe
// impossible; atomic co-signing is the real safety net).
package validator

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/offer"
)

// ErrReplay signals that the submitted offer is a byte-identical replay of an
// offer already resting in the book (same maker_pubkey + offer_id + maker_sig):
// a no-op. It is NOT a validation failure; the caller should drop the submission
// silently (re-acking the live order status) WITHOUT treating it as an error.
// Crucially, an ErrReplay submission consumes NO per-maker_pubkey rate budget,
// which is the whole point: see RestingOffers and ValidateOffer.
var ErrReplay = errors.New("offer is an exact replay of an already-resting offer")

// RestingOffers lets the validator consult the live order book so a byte-identical
// replay of an already-resting offer is dropped WITHOUT charging the per-maker
// pubkey rate budget. The offerstore.Store satisfies this interface. If no book
// is wired (SetBook never called), the replay gate is skipped.
type RestingOffers interface {
	// RestingMakerSig returns the maker_sig of the offer currently resting under
	// (makerPubkey, offerID), or ok=false if none rests.
	RestingMakerSig(makerPubkey, offerID string) (sig []byte, ok bool)
}

// LivenessProbe checks (best-effort, read-only) that a maker plausibly holds the
// asset it is offering. PHASE-1 STUB: the default NoopLivenessProbe always
// passes. A later implementation would query a read-only Sequentia node RPC.
type LivenessProbe interface {
	CheckOffer(ctx context.Context, o *seqobv1.Offer) error
}

// NoopLivenessProbe is the Phase-1 default: it accepts every offer.
type NoopLivenessProbe struct{}

// CheckOffer always returns nil (Phase-1 stub).
func (NoopLivenessProbe) CheckOffer(context.Context, *seqobv1.Offer) error { return nil }

// Config tunes validation.
type Config struct {
	// SchemaVersion the relay accepts (default 1).
	SchemaVersion uint32
	// KnownAssets, if non-empty, restricts offers to these asset ids (hex). Empty
	// = accept any asset (registry wiring is deferred).
	KnownAssets map[string]bool
	// MinExpiry / MaxExpiry bound how soon / far an offer may expire from now.
	// Expiry is mandatory: an offer with no future expiry is rejected.
	MinExpiry time.Duration
	MaxExpiry time.Duration
	// Rate limits (sliding 1-minute window).
	MaxOffersPerMinPerPubkey int
	MaxOffersPerMinPerIP     int
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// DefaultConfig returns sane Phase-1 defaults.
func DefaultConfig() Config {
	return Config{
		SchemaVersion:            1,
		MinExpiry:                30 * time.Second,
		MaxExpiry:                7 * 24 * time.Hour,
		MaxOffersPerMinPerPubkey: 60,
		MaxOffersPerMinPerIP:     120,
		Now:                      time.Now,
	}
}

// Validator validates offers and enforces rate limits.
type Validator struct {
	cfg     Config
	probe   LivenessProbe
	book    RestingOffers
	mu      sync.Mutex
	pubHits map[string][]time.Time
	ipHits  map[string][]time.Time
}

// SetBook wires the live order book so ValidateOffer can recognize a byte-identical
// replay of an already-resting offer and decline to charge it the per-maker_pubkey
// rate budget. Call once at wiring time (e.g. api.New); b may be nil to disable.
func (v *Validator) SetBook(b RestingOffers) { v.book = b }

// New returns a Validator. If probe is nil, NoopLivenessProbe is used.
func New(cfg Config, probe LivenessProbe) *Validator {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SchemaVersion == 0 {
		cfg.SchemaVersion = 1
	}
	if probe == nil {
		probe = NoopLivenessProbe{}
	}
	return &Validator{
		cfg:     cfg,
		probe:   probe,
		pubHits: make(map[string][]time.Time),
		ipHits:  make(map[string][]time.Time),
	}
}

// ValidateOffer runs all structural/semantic checks and rate limits. ip may be
// empty (e.g. for a local CLI); IP rate limiting is then skipped.
//
// Order matters for rate limiting (review: per-maker_pubkey griefing). The
// per-IP limit is charged FIRST, before the (relatively expensive) signature
// verification, so a flood from one IP is throttled cheaply. The maker signature
// is then verified, and ONLY after it succeeds is the per-maker_pubkey budget
// charged: a maker_pubkey is attacker-replayable PUBLIC data, so a forged offer
// bearing a victim's maker_pubkey must never consume the victim's budget. The
// genuine maker (the only party able to produce a valid maker_sig) is therefore
// the only one who spends its own per-pubkey budget.
func (v *Validator) ValidateOffer(ctx context.Context, o *seqobv1.Offer, ip string) error {
	if err := v.checkIPRate(ip); err != nil {
		return err
	}
	if err := offer.VerifyOffer(o); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if o.GetSchemaVersion() != v.cfg.SchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (want %d)", o.GetSchemaVersion(), v.cfg.SchemaVersion)
	}
	if err := v.checkTerms(o); err != nil {
		return err
	}
	if err := v.checkExpiry(o); err != nil {
		return err
	}
	// Replay-griefing defense: an attacker can harvest a victim maker's GENUINE
	// signed offer from the public book and replay it here. It passes VerifyOffer
	// (the signature is real), so without this gate it would consume the victim's
	// per-maker_pubkey budget and could lock the victim out. If an offer with this
	// (maker_pubkey, offer_id) is already resting with a byte-identical maker_sig
	// -- i.e. identical signed content, since the signature is a deterministic,
	// collision-resistant function of the whole signed payload -- the submission is
	// a no-op replay: return ErrReplay WITHOUT charging the per-pubkey budget. A new
	// offer_id, or a genuinely changed (re-signed) offer_edit, has a different
	// maker_sig and falls through to consume budget and be stored.
	if v.book != nil {
		if sig, ok := v.book.RestingMakerSig(o.GetMakerPubkey(), o.GetOfferId()); ok && bytes.Equal(sig, o.GetMakerSig()) {
			return ErrReplay
		}
	}
	// Charge the per-maker_pubkey budget only now that maker_sig is verified and the
	// offer is a genuinely new or changed resting offer (not a no-op replay).
	if err := v.checkPubkeyRate(o.GetMakerPubkey()); err != nil {
		return err
	}
	if err := v.probe.CheckOffer(ctx, o); err != nil {
		return fmt.Errorf("liveness: %w", err)
	}
	return nil
}

func (v *Validator) checkTerms(o *seqobv1.Offer) error {
	p := o.GetPair()
	if p == nil || p.GetBaseAsset() == "" || p.GetQuoteAsset() == "" {
		return fmt.Errorf("offer missing pair assets")
	}
	if p.GetBaseAsset() == p.GetQuoteAsset() {
		return fmt.Errorf("base and quote asset are identical")
	}
	if o.GetBaseAmount() == 0 || o.GetOfferAmount() == 0 || o.GetWantAmount() == 0 {
		return fmt.Errorf("amounts must be > 0")
	}
	if o.GetOfferAsset() == "" || o.GetWantAsset() == "" {
		return fmt.Errorf("offer/want asset missing")
	}
	// Direction/asset consistency: a SELL gives base and wants quote (and
	// offer_amount is the base side); a BUY gives quote and wants base (and
	// want_amount is the base side).
	switch o.GetTradeDir() {
	case seqobv1.TradeDir_TRADE_DIR_SELL:
		if o.GetOfferAsset() != p.GetBaseAsset() || o.GetWantAsset() != p.GetQuoteAsset() {
			return fmt.Errorf("SELL must offer base for quote")
		}
		if o.GetOfferAmount() != o.GetBaseAmount() {
			return fmt.Errorf("SELL offer_amount must equal base_amount")
		}
	case seqobv1.TradeDir_TRADE_DIR_BUY:
		if o.GetOfferAsset() != p.GetQuoteAsset() || o.GetWantAsset() != p.GetBaseAsset() {
			return fmt.Errorf("BUY must offer quote for base")
		}
		if o.GetWantAmount() != o.GetBaseAmount() {
			return fmt.Errorf("BUY want_amount must equal base_amount")
		}
	default:
		return fmt.Errorf("unspecified trade_dir")
	}
	if o.GetMinFill() > o.GetBaseAmount() {
		return fmt.Errorf("min_fill exceeds base_amount")
	}
	if len(v.cfg.KnownAssets) > 0 {
		for _, a := range []string{p.GetBaseAsset(), p.GetQuoteAsset(), o.GetOfferAsset(), o.GetWantAsset()} {
			if offer.IsBTCSentinel(a) {
				continue // the BTC sentinel is the cross-chain parent-chain placeholder, not a Sequentia asset
			}
			if !v.cfg.KnownAssets[strings.ToLower(a)] && !v.cfg.KnownAssets[a] {
				return fmt.Errorf("unknown asset %q", a)
			}
		}
	}
	if o.GetCrossChain() != nil {
		return v.checkCrossChain(o)
	}
	return nil
}

// checkCrossChain validates a cross-chain (BTC<->asset) offer's CrossChainTerms.
// The resting offer is DISCOVERY-ONLY: maker_claim_pub/maker_refund_pub/
// maker_leg_locktime are advisory (display + a stable signed commitment); the
// load-bearing HTLC keys and locktimes are minted per-lift over the E2E courier and
// bound at settlement by recomputing the redeemScript byte-for-byte. Here we only
// check the offer is well-formed and self-consistent. Convention: base = the SEQ
// asset, quote = the BTC sentinel.
func (v *Validator) checkCrossChain(o *seqobv1.Offer) error {
	cc := o.GetCrossChain()
	if cc == nil {
		return fmt.Errorf("cross-chain offer missing cross_chain terms")
	}
	p := o.GetPair()
	baseBTC, quoteBTC := offer.IsBTCSentinel(p.GetBaseAsset()), offer.IsBTCSentinel(p.GetQuoteAsset())
	if baseBTC == quoteBTC {
		return fmt.Errorf("cross-chain pair must have exactly one BTC-sentinel side")
	}
	if !quoteBTC {
		return fmt.Errorf("cross-chain pair must be base=asset, quote=%s", offer.BTCSentinel)
	}
	if cc.GetBtcSentinel() != offer.BTCSentinel {
		return fmt.Errorf("cross_chain btc_sentinel must be %q", offer.BTCSentinel)
	}
	for _, pk := range []struct{ name, hexv string }{
		{"maker_claim_pub", cc.GetMakerClaimPub()},
		{"maker_refund_pub", cc.GetMakerRefundPub()},
	} {
		b, err := hex.DecodeString(pk.hexv)
		if err != nil {
			return fmt.Errorf("cross_chain %s not hex: %v", pk.name, err)
		}
		if _, err := btcec.ParsePubKey(b); err != nil {
			return fmt.Errorf("cross_chain %s invalid: %v", pk.name, err)
		}
	}
	if cc.GetMakerLegLocktime() == 0 {
		return fmt.Errorf("cross_chain maker_leg_locktime must be > 0")
	}
	if cc.GetDirection() > 1 {
		return fmt.Errorf("cross_chain direction must be 0 (BTC->asset) or 1 (asset->BTC)")
	}
	if !offer.DirectionConsistent(cc.GetDirection(), o.GetTradeDir() == seqobv1.TradeDir_TRADE_DIR_SELL) {
		return fmt.Errorf("cross_chain direction inconsistent with trade_dir")
	}
	return nil
}

func (v *Validator) checkExpiry(o *seqobv1.Offer) error {
	now := v.cfg.Now()
	exp := o.GetExpiresAtUnix()
	if exp == 0 {
		return fmt.Errorf("expires_at_unix is mandatory")
	}
	t := time.Unix(int64(exp), 0)
	if !t.After(now) {
		return fmt.Errorf("offer already expired")
	}
	if v.cfg.MinExpiry > 0 && t.Before(now.Add(v.cfg.MinExpiry)) {
		return fmt.Errorf("expiry too soon (min %s)", v.cfg.MinExpiry)
	}
	if v.cfg.MaxExpiry > 0 && t.After(now.Add(v.cfg.MaxExpiry)) {
		return fmt.Errorf("expiry too far in the future (max %s)", v.cfg.MaxExpiry)
	}
	return nil
}

// checkIPRate enforces the per-IP sliding-window limit. It is keyed on the
// connection (not the maker_pubkey) and is charged before signature verification
// so a flood is throttled cheaply. ip may be empty (limit skipped).
func (v *Validator) checkIPRate(ip string) error {
	if ip == "" || v.cfg.MaxOffersPerMinPerIP <= 0 {
		return nil
	}
	now := v.cfg.Now()
	cutoff := now.Add(-time.Minute)
	v.mu.Lock()
	defer v.mu.Unlock()
	hits := prune(v.ipHits[ip], cutoff)
	if len(hits) >= v.cfg.MaxOffersPerMinPerIP {
		v.ipHits[ip] = hits
		return fmt.Errorf("rate limit: too many offers from this IP")
	}
	v.ipHits[ip] = append(hits, now)
	return nil
}

// checkPubkeyRate enforces the per-maker_pubkey sliding-window limit. The CALLER
// MUST have already verified maker_sig: maker_pubkey is attacker-replayable
// public data, so only a genuine maker (which alone can produce a valid sig) may
// reach here and consume its own budget.
func (v *Validator) checkPubkeyRate(makerPubkey string) error {
	if v.cfg.MaxOffersPerMinPerPubkey <= 0 {
		return nil
	}
	now := v.cfg.Now()
	cutoff := now.Add(-time.Minute)
	v.mu.Lock()
	defer v.mu.Unlock()
	hits := prune(v.pubHits[makerPubkey], cutoff)
	if len(hits) >= v.cfg.MaxOffersPerMinPerPubkey {
		v.pubHits[makerPubkey] = hits
		return fmt.Errorf("rate limit: too many offers for this maker_pubkey")
	}
	v.pubHits[makerPubkey] = append(hits, now)
	return nil
}

// ValidateCancel verifies a signed cancel's signature. (Nonce/replay enforcement
// is the offerstore's job, since it holds the per-key nonce high-water mark.)
func (v *Validator) ValidateCancel(c *seqobv1.OfferCancel) error {
	return offer.VerifyCancel(c)
}

func prune(hits []time.Time, cutoff time.Time) []time.Time {
	out := hits[:0]
	for _, h := range hits {
		if h.After(cutoff) {
			out = append(out, h)
		}
	}
	return out
}
