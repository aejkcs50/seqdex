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

	if sw.reverse {
		s.advanceReverse(sw)
		return
	}

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
		refundTxid, err := sw.orch.RefundSEQLeg(sw.seqLeg, sw.q.makerSEQKey, uint32(height), s.seqLegFee(sw.seqLeg.Funded.AssetID, sw.seqLeg.Funded.Amount))
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

// advanceReverse drives a REVERSE (asset->BTC) swap. Caller holds sw.mu.
//
//   - BTC_LOCKED: the maker funded the BTC leg; it waits for the taker to fund
//     and submit the SEQ asset leg (SubmitReverseSeqLeg -> SEQ_SUBMITTED). If the
//     taker never submits and the parent height reaches T_btc, the maker REFUNDS
//     its own BTC leg.
//   - SEQ_SUBMITTED: run VerifySeqLegSafe (the anchor-ordering gate) as a HARD
//     precondition, then CLAIM the SEQ leg with the maker's secret, revealing it
//     on the Sequentia chain. The taker reads the secret (GetXchainSwap.preimage)
//     and claims the maker's BTC leg off-daemon, so the maker stops at
//     SEQ_CLAIMED (it has the asset and revealed s).
func (s *Service) advanceReverse(sw *Swap) {
	switch sw.state {
	case StateBTCLocked:
		h, err := s.btcHeight()
		if err != nil {
			return
		}
		// On a live network the maker's BTC leg is broadcast at 0 conf (LockBTCLeg
		// returns Hp=0). Record its real confirmation height once it lands; the
		// taker waits for btc_leg_height > 0 (GetXchainSwap) before funding the SEQ
		// leg, so the SEQ block can anchor at/above Hp. (Regtest already has Hp set.)
		if sw.btcLegHeight <= 0 {
			confs, cerr := s.btcConfirmations(sw.btcLeg.Funded.TxID)
			if cerr == nil && confs >= s.cfg.MinBTCConf {
				sw.btcLegHeight = h - int64(confs) + 1 // in-memory persist (this MVP has no store)
			}
		}
		// Refund the maker's BTC leg if the taker never funded the SEQ leg by T_btc.
		if uint32(h) >= sw.q.btcLocktime {
			txid, rerr := sw.orch.RefundBTCLeg(
				sw.btcLeg, sw.q.makerBTCRefundKey, sw.q.btcLocktime, s.safeFee(sw.btcLeg.Funded.Amount),
			)
			if rerr != nil {
				sw.detail = "btc refund retrying: " + rerr.Error()
				return
			}
			sw.btcClaimTxid = txid // the maker's BTC-leg spend (here a refund)
			sw.state = StateRefunded
			sw.detail = "taker did not submit the SEQ leg before T_btc; BTC leg refunded"
			s.releaseBtcReserve(sw.q.btcAmount)
		}

	case StateSeqSubmitted:
		// HARD anchor-ordering precondition before revealing the secret: the taker's
		// SEQ leg must anchor at/above the maker's BTC-leg height and the node's
		// anchor status must be ok. The anchor may not have caught up yet — retry.
		if _, err := sw.orch.VerifySeqLegSafe(sw.seqBlockHash, sw.btcLegHeight); err != nil {
			sw.detail = "awaiting anchor gate: " + err.Error()
			return
		}
		// Claim the taker's SEQ asset leg with the maker's secret, revealing it.
		txid, cerr := sw.orch.ClaimSEQLeg(sw.seqLeg, sw.q.makerSEQClaimKey, s.seqLegFee(sw.seqLeg.Funded.AssetID, sw.seqLeg.Funded.Amount))
		if cerr != nil {
			sw.detail = "claim seq leg retrying: " + cerr.Error()
			return
		}
		sw.seqClaimTxid = txid
		sw.preimage = sw.q.secret // surfaced via GetXchainSwap so the taker claims BTC
		sw.state = StateSeqClaimed
		sw.detail = ""
		// The maker has the asset and revealed s; its funded BTC will be swept by
		// the taker. Free the BTC reservation (it has left the maker's pool).
		s.releaseBtcReserve(sw.q.btcAmount)
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

// seqLegFee sizes the explicit fee for spending a SEQ-side leg IN THE LEG'S OWN
// asset. SpendFee is a target fee in native sats; emitting it as a flat atom amount
// of a VALUABLE asset (e.g. GOLD) gives a huge native-equivalent value that the node
// rejects on broadcast (rpc -25, maxfeerate). Convert the target into the leg's
// asset via the open-fee-market exchange rate (asset_atoms = ceil(SpendFee*1e8 /
// rate)), exactly as the wallet/price-server do, so the fee's native-equivalent
// value lands inside the node's relay fee bounds. Falls back to the flat SpendFee
// when no rate is published (e.g. the native asset, where flat atoms are fine).
// Clamped to half the leg so the output stays positive on small legs.
func (s *Service) seqLegFee(assetHex string, legAmount uint64) uint64 {
	fee := s.cfg.SpendFee
	if rate, ok := s.cfg.SEQ.FeeExchangeRate(assetHex); ok && rate > 0 {
		const scale = 100_000_000 // 1e8; matches price_server.py / exchangerates.cpp
		fee = (s.cfg.SpendFee*scale + rate - 1) / rate // ceil
		if fee == 0 {
			fee = 1
		}
	}
	if maxFee := legAmount / 2; fee > maxFee {
		fee = maxFee
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
