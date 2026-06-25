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

// Config wires the maker to the two chains and its reserves/keys.
type Config struct {
	BTC *xchain.Chain // parent ("BTC") leg, maker's wallet
	SEQ *xchain.Chain // anchored Sequentia leg, maker's wallet

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

// quote is a held quote awaiting a ProposeXchainSwap.
type quote struct {
	id          string
	market      Market
	seqAmount   uint64
	btcAmount   uint64
	feeBtc      uint64
	makerBTCKey *xchain.Key // maker's BTC-leg claim key
	makerSEQKey *xchain.Key // maker's SEQ-leg refund key
	btcLocktime uint32
	seqLocktime uint32
	expiresAt   time.Time
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
)

// Swap is a live maker-side swap.
type Swap struct {
	mu sync.Mutex

	id    string
	state State
	q     *quote

	orch   *xchain.Swap
	btcLeg *xchain.LegLock // the taker's verified BTC leg (maker claims this)
	seqLeg *xchain.LegLock // the maker-locked SEQ leg (taker claims this)

	seqBlockHash string
	anchorHeight int64
	btcLegHeight int64

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

	stop chan struct{}
}

// New builds a maker service. The caller must Start it to run the watcher loop.
func New(cfg Config) (*Service, error) {
	if cfg.BTC == nil || cfg.SEQ == nil {
		return nil, fmt.Errorf("xchainmaker: BTC and SEQ chains are required")
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

// btcReserveAtoms reports the maker's confirmed BTC (pegged) balance (atoms).
func (s *Service) btcReserveAtoms() (uint64, error) {
	return s.cfg.BTC.AssetBalance("") // "" => default pegged bitcoin
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

// atomsToCoins formats atoms as a decimal coin string for sendtoaddress.
func (s *Service) atomsToCoins(atoms uint64) string {
	return fmt.Sprintf("%.8f", float64(atoms)/s.cfg.CoinDivisor)
}

var _ = context.Background // keep context import even if unused by helpers
