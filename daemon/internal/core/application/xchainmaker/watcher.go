package xchainmaker

import (
	"time"
)

// watchLoop is the maker's background driver. On each tick it advances every
// live swap:
//
//   - SEQ_LOCKED: poll the SEQ chain for the taker's claim of the SEQ leg. When
//     found, extract the preimage (-> SEQ_CLAIMED), then immediately claim the
//     BTC leg with it (-> BTC_CLAIMED). If the taker never claims and T_seq is
//     reached, refund the maker's SEQ leg (-> REFUNDED).
//
// All chain effects go through the proven pkg/xchain orchestrator.
func (s *Service) watchLoop() {
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.tick()
		}
	}
}

func (s *Service) tick() {
	s.mu.Lock()
	live := make([]*Swap, 0, len(s.swaps))
	for _, sw := range s.swaps {
		live = append(live, sw)
	}
	s.mu.Unlock()

	for _, sw := range live {
		s.advance(sw)
	}
}

func (s *Service) advance(sw *Swap) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.state != StateSeqLocked {
		return // terminal or in-flight elsewhere
	}

	// 1) Has the taker claimed the SEQ leg yet?
	claimTxid, secret, err := sw.orch.WatchSEQClaim(sw.seqLeg)
	if err != nil {
		// transient (e.g. spent-but-spender-not-yet-indexed); try again next tick.
		return
	}
	if claimTxid != "" && len(secret) > 0 {
		sw.seqClaimTxid = claimTxid
		sw.preimage = secret
		sw.state = StateSeqClaimed

		// 2) Inject the secret and claim the BTC leg with it.
		if err := sw.orch.InjectSecret(secret); err != nil {
			sw.state = StateFailed
			sw.detail = "inject secret: " + err.Error()
			s.releaseReserve(sw)
			return
		}
		btcTxid, err := sw.orch.ClaimBTCLeg(sw.btcLeg, sw.q.makerBTCKey, s.safeFee(sw.btcLeg.Funded.Amount))
		if err != nil {
			// Stay in SEQ_CLAIMED; retry the BTC claim next tick (the preimage is
			// already in hand, so this is safe to retry).
			sw.state = StateSeqClaimed
			sw.detail = "btc claim retrying: " + err.Error()
			return
		}
		sw.btcClaimTxid = btcTxid
		sw.state = StateBTCClaimed
		sw.detail = ""
		s.releaseReserve(sw) // SEQ leg consumed by the taker; reservation done
		return
	}

	// 3) Taker hasn't claimed. If T_seq has been reached, refund the SEQ leg.
	height, err := s.cfg.SEQ.BlockCount()
	if err != nil {
		return
	}
	if uint32(height) >= sw.q.seqLocktime {
		refundTxid, err := sw.orch.RefundSEQLeg(sw.seqLeg, sw.q.makerSEQKey, uint32(height), s.safeFee(sw.seqLeg.Funded.Amount))
		if err != nil {
			sw.detail = "refund build: " + err.Error()
			return
		}
		if _, err := s.cfg.SEQ.Broadcast(refundTxid); err != nil {
			sw.detail = "refund broadcast: " + err.Error()
			return
		}
		_ = s.cfg.SEQ.Mine(1)
		sw.state = StateRefunded
		sw.detail = "taker stalled past T_seq; SEQ leg refunded"
		s.releaseReserve(sw)
	}
}

// safeFee returns a spend fee that will not drive the output negative: the
// configured SpendFee, clamped to at most half the leg's value. HTLC legs can
// be small (the BTC leg in particular), so a fixed fee may exceed the input;
// this keeps the explicit Elements fee output non-negative on any leg size.
func (s *Service) safeFee(legAmount uint64) uint64 {
	fee := s.cfg.SpendFee
	if max := legAmount / 2; fee > max {
		fee = max
	}
	return fee
}

// releaseReserve frees the SEQ atoms a swap had committed (idempotent per swap).
func (s *Service) releaseReserve(sw *Swap) {
	if sw.q == nil {
		return
	}
	s.mu.Lock()
	if s.reservedSeq[sw.q.market.SeqAsset] >= sw.q.seqAmount {
		s.reservedSeq[sw.q.market.SeqAsset] -= sw.q.seqAmount
	}
	s.mu.Unlock()
}
