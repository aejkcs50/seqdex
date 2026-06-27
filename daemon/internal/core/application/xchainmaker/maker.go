// Package xchainmaker is the daemon-side cross-chain swap MAKER service
// (Phase 5, milestone 2). It implements the gRPC XchainService (seqdex.v1) on
// top of the proven pkg/xchain HTLC mechanism, holding reserves of the parent
// "BTC" asset and the anchored SEQ asset and driving a Design-A single-secret
// swap as the taker's counterparty.
//
// MVP direction: the taker BUYS a SEQ asset paying BTC. The taker is the
// INITIATOR (locks the BTC leg first); the maker (this service) locks the SEQ
// leg, watches for the taker's SEQ-leg claim, extracts the preimage, and claims
// the BTC leg.
//
// State machine (per swap), all in-memory for this MVP (persistence/restart
// recovery is deferred):
//
//	GetXchainQuote        -> (quote held; no swap yet)
//	ProposeXchainSwap     -> PENDING_BTC_LOCK (verifying) -> SEQ_LOCKED
//	background watcher     -> SEQ_CLAIMED (preimage read) -> BTC_CLAIMED
//	refund path (taker stalls past T_seq) -> REFUNDED
//	verification/RPC error -> FAILED
//
// Who does what, when:
//   - taker: generates secret s & H, LOCKS the BTC leg (claim=maker w/ s,
//     refund=taker after T_btc), confirms it, then ProposeXchainSwap.
//   - maker: VERIFIES the BTC leg, LOCKS the SEQ leg (claim=taker w/ s,
//     refund=maker after T_seq), anchored; replies with the SEQ leg.
//   - taker: VerifySeqLegSafe, then CLAIMS the SEQ leg with s (reveals s).
//   - maker: WATCHES the SEQ chain, EXTRACTS s, CLAIMS the BTC leg with s.
package xchainmaker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// Market is a configured BTC/SEQ-asset pair the maker will swap.
type Market struct {
	SeqAsset string // anchored SEQ asset id (hex)
	BtcAsset string // parent-chain pegged "bitcoin" asset id (hex); "" => default
	Name     string
	// PriceSeqPerBtc: how many SEQ-asset atoms the maker gives per 1 BTC atom.
	PriceSeqPerBtc float64
	// FeeBps: maker fee in basis points, charged on the BTC the taker pays.
	FeeBps uint64
}

// ParentKind selects the BTC-leg (parent / anchor-source) transaction format.
type ParentKind int

const (
	// ParentElements: the parent is an Elements-mode node (asset commitments,
	// Elements serialization). The maker uses xchain.Chain + ElementsLeg. This is
	// the default for back-compat.
	ParentElements ParentKind = iota
	// ParentBitcoin: the parent is a REAL bitcoind (regtest or testnet4). The
	// maker uses xchain.BitcoinChain + BitcoinLeg, verifying/claiming the BTC
	// HTLC in Bitcoin transaction format. This is the "real-bitcoind-leg".
	ParentBitcoin
)

// Config wires the maker to the two chains and its reserves/keys.
type Config struct {
	// ParentKind selects the BTC-leg format. When ParentBitcoin, BTCBitcoin is
	// used for the parent and BTC may be nil; otherwise BTC (Elements) is used.
	ParentKind ParentKind

	BTC        *xchain.Chain        // Elements parent ("BTC") leg, maker's wallet (ParentElements)
	BTCBitcoin *xchain.BitcoinChain // real bitcoind parent ("BTC") leg (ParentBitcoin)
	SEQ        *xchain.Chain        // anchored Sequentia leg, maker's wallet

	// SeqAmountCoins formats SEQ atoms -> decimal coin string for sendtoaddress.
	// CoinDivisor is the smallest-unit divisor for both assets (1e8).
	CoinDivisor float64

	Markets []Market

	// QuoteTTL is how long a quote is honoured.
	QuoteTTL time.Duration
	// BtcLocktimeDelta / SeqLocktimeDelta are the CLTV offsets (in blocks) above
	// the current height for T_btc (taker refund, longer) and T_seq (maker
	// refund, shorter). BtcLocktimeDelta MUST exceed SeqLocktimeDelta.
	BtcLocktimeDelta uint32
	SeqLocktimeDelta uint32
	// MinBTCConf is the confirmation depth the maker requires on the taker's BTC
	// leg before locking the SEQ leg.
	MinBTCConf int
	// SpendFee is the explicit fee (atoms) used on the maker's BTC-leg claim and
	// SEQ-leg refund spends.
	SpendFee uint64

	// PollInterval is how often the background watcher checks for the taker's
	// SEQ-leg claim.
	PollInterval time.Duration
}

// quote is a held quote awaiting a ProposeXchainSwap (forward) or an
// OpenReverseXchainSwap (reverse).
type quote struct {
	id          string
	market      Market
	seqAmount   uint64
	btcAmount   uint64
	feeBtc      uint64
	makerBTCKey *xchain.Key // maker's BTC-leg claim key (FORWARD)
	makerSEQKey *xchain.Key // maker's SEQ-leg refund key (FORWARD)
	btcLocktime uint32
	seqLocktime uint32
	expiresAt   time.Time

	// REVERSE (asset->BTC) fields. Here the maker is the secret holder: it funds
	// the BTC leg (refund key) and claims the taker's SEQ asset leg (claim key).
	reverse           bool
	secret            []byte      // maker-generated preimage
	hash              []byte      // H = sha256(secret)
	makerSEQClaimKey  *xchain.Key // maker's SEQ-leg claim key (reveals s)
	makerBTCRefundKey *xchain.Key // maker's BTC-leg refund key
}

// State mirrors the proto XchainSwapState.
type State int

const (
	StatePendingBTCLock State = iota + 1
	StateSeqLocked
	StateSeqClaimed
	StateBTCClaimed
	StateRefunded
	StateFailed
	// REVERSE (asset->BTC) states.
	StateBTCLocked    // maker locked the BTC leg; awaiting the taker's SEQ asset leg
	StateSeqSubmitted // taker submitted its SEQ leg, verified; awaiting anchor gate + maker claim
)

// Swap is a live maker-side swap.
type Swap struct {
	mu sync.Mutex

	id    string
	state State
	q     *quote

	// reverse selects the asset->BTC direction. It flips the leg roles:
	//   forward: btcLeg = taker's (maker claims), seqLeg = maker's (taker claims)
	//   reverse: btcLeg = maker's (taker claims), seqLeg = taker's (maker claims)
	reverse bool

	orch   *xchain.Swap
	btcLeg *xchain.LegLock // forward: taker's leg (maker claims); reverse: maker's leg (taker claims)
	seqLeg *xchain.LegLock // forward: maker's leg (taker claims); reverse: taker's leg (maker claims)

	seqBlockHash string
	anchorHeight int64
	btcLegHeight int64

	// reverse-only: the taker's SEQ-leg refund pubkey (from OpenReverseXchainSwap),
	// needed to recompute + verify the taker's SEQ-leg redeemScript at submit time.
	takerSeqRefundPub []byte

	seqClaimTxid string
	btcClaimTxid string
	preimage     []byte
	detail       string
}

// Service implements seqdex.v1.XchainService.
type Service struct {
	cfg Config

	mu     sync.Mutex
	quotes map[string]*quote
	swaps  map[string]*Swap

	// reserved tracks SEQ atoms committed to in-flight swaps so concurrent
	// quotes do not over-commit the SEQ reserve.
	reservedSeq map[string]uint64 // seqAsset -> atoms reserved

	// reservedBtc tracks BTC atoms committed to in-flight REVERSE (asset->BTC)
	// swaps — where the maker funds the BTC leg — so concurrent reverse quotes do
	// not over-commit the BTC reserve. BTC is a single asset, so this is one total.
	reservedBtc uint64

	// dynamic pricing: cached USD reference prices from the SEQ node, used to
	// quote BTC<->asset at live rates (ref[BTC]/ref[asset]) instead of the static
	// per-market PriceSeqPerBtc. Maps are replaced wholesale, never mutated.
	priceMu    sync.RWMutex
	refPrices  map[string]float64 // reference symbol (e.g. "BTC","GOLD") -> USD
	hex2label  map[string]string  // asset id hex -> dumpassetlabels label
	refFetched time.Time

	stop chan struct{}
}

// New builds a maker service. The caller must Start it to run the watcher loop.
func New(cfg Config) (*Service, error) {
	if cfg.SEQ == nil {
		return nil, fmt.Errorf("xchainmaker: SEQ chain is required")
	}
	switch cfg.ParentKind {
	case ParentBitcoin:
		if cfg.BTCBitcoin == nil {
			return nil, fmt.Errorf("xchainmaker: ParentBitcoin requires BTCBitcoin (a bitcoind parent)")
		}
	default:
		if cfg.BTC == nil {
			return nil, fmt.Errorf("xchainmaker: ParentElements requires BTC (an Elements parent)")
		}
	}
	if cfg.BtcLocktimeDelta <= cfg.SeqLocktimeDelta {
		return nil, fmt.Errorf("xchainmaker: BtcLocktimeDelta (%d) must exceed SeqLocktimeDelta (%d)",
			cfg.BtcLocktimeDelta, cfg.SeqLocktimeDelta)
	}
	if cfg.CoinDivisor == 0 {
		cfg.CoinDivisor = 1e8
	}
	if cfg.QuoteTTL == 0 {
		cfg.QuoteTTL = 2 * time.Minute
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 1 * time.Second
	}
	if cfg.MinBTCConf == 0 {
		cfg.MinBTCConf = 1
	}
	if cfg.SpendFee == 0 {
		cfg.SpendFee = 100000
	}
	return &Service{
		cfg:         cfg,
		quotes:      make(map[string]*quote),
		swaps:       make(map[string]*Swap),
		reservedSeq: make(map[string]uint64),
		stop:        make(chan struct{}),
	}, nil
}

// Start launches the background watcher that drives SEQ_LOCKED -> SEQ_CLAIMED ->
// BTC_CLAIMED (and the maker's refund after T_seq).
func (s *Service) Start() {
	go s.watchLoop()
}

// Close stops the watcher.
func (s *Service) Close() { close(s.stop) }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Service) marketBySeqAsset(seqAsset string) (Market, bool) {
	for _, m := range s.cfg.Markets {
		if m.SeqAsset == seqAsset {
			return m, true
		}
	}
	return Market{}, false
}

// seqReserveAtoms reports the maker's confirmed SEQ-asset balance (atoms).
func (s *Service) seqReserveAtoms(seqAsset string) (uint64, error) {
	bal, err := s.cfg.SEQ.AssetBalance(seqAsset)
	if err != nil {
		return 0, err
	}
	return bal, nil
}

// btcReserveAtoms reports the maker's confirmed BTC balance (atoms/sats). For a
// real bitcoind parent it reads getbalance (the wallet's spendable BTC); for an
// Elements parent it reads the pegged "bitcoin" asset balance.
func (s *Service) btcReserveAtoms() (uint64, error) {
	if s.cfg.ParentKind == ParentBitcoin {
		var bal float64
		if err := s.cfg.BTCBitcoin.RPC().Call(&bal, "getbalance"); err != nil {
			return 0, err
		}
		return uint64(bal*1e8 + 0.5), nil
	}
	return s.cfg.BTC.AssetBalance("") // "" => default pegged bitcoin
}

// btcHeight reports the parent chain height (either backend).
func (s *Service) btcHeight() (int64, error) {
	if s.cfg.ParentKind == ParentBitcoin {
		return s.cfg.BTCBitcoin.BlockCount()
	}
	return s.cfg.BTC.BlockCount()
}

// newOrch builds a swap orchestrator bound to the configured parent backend
// (Elements or real Bitcoin) for the BTC leg and the Sequentia node for the SEQ
// leg, sharing the given hashlock primitive.
func (s *Service) newOrch(prim *xchain.HashLock) *xchain.Swap {
	if s.cfg.ParentKind == ParentBitcoin {
		return xchain.NewSwapBitcoin(s.cfg.BTCBitcoin, s.cfg.SEQ, prim)
	}
	return xchain.NewSwap(s.cfg.BTC, s.cfg.SEQ, prim)
}

func (s *Service) availableSeq(seqAsset string) (uint64, error) {
	total, err := s.seqReserveAtoms(seqAsset)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	reserved := s.reservedSeq[seqAsset]
	s.mu.Unlock()
	if reserved >= total {
		return 0, nil
	}
	return total - reserved, nil
}

// availableBtc reports the maker's spendable BTC reserve (atoms) net of BTC
// committed to in-flight REVERSE swaps. Mirror of availableSeq for the BTC side.
func (s *Service) availableBtc() (uint64, error) {
	total, err := s.btcReserveAtoms()
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	reserved := s.reservedBtc
	s.mu.Unlock()
	if reserved >= total {
		return 0, nil
	}
	return total - reserved, nil
}

// reserveBtc commits atoms of the BTC reserve to a reverse swap (caller holds no
// lock; this takes s.mu).
func (s *Service) reserveBtc(atoms uint64) {
	s.mu.Lock()
	s.reservedBtc += atoms
	s.mu.Unlock()
}

// releaseBtcReserve frees previously-reserved BTC (idempotent guard against
// underflow). Called on terminal reverse-swap states and on open failure.
func (s *Service) releaseBtcReserve(atoms uint64) {
	s.mu.Lock()
	if atoms >= s.reservedBtc {
		s.reservedBtc = 0
	} else {
		s.reservedBtc -= atoms
	}
	s.mu.Unlock()
}

// atomsToCoins formats atoms as a decimal coin string for sendtoaddress.
func (s *Service) atomsToCoins(atoms uint64) string {
	return fmt.Sprintf("%.8f", float64(atoms)/s.cfg.CoinDivisor)
}

var _ = context.Background // keep context import even if unused by helpers
