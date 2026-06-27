package xchainmaker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// compile-time assertion: Service is the gRPC server.
var _ seqdexv1.XchainServiceServer = (*Service)(nil)

// ListXchainMarkets returns the configured pairs and the maker's live reserves.
func (s *Service) ListXchainMarkets(
	ctx context.Context, _ *seqdexv1.ListXchainMarketsRequest,
) (*seqdexv1.ListXchainMarketsResponse, error) {
	btcReserve, err := s.btcReserveAtoms()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read btc reserve: %v", err)
	}
	out := make([]*seqdexv1.XchainMarket, 0, len(s.cfg.Markets))
	for _, m := range s.cfg.Markets {
		seqAvail, err := s.availableSeq(m.SeqAsset)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read seq reserve: %v", err)
		}
		out = append(out, &seqdexv1.XchainMarket{
			BtcAsset:       m.BtcAsset,
			SeqAsset:       m.SeqAsset,
			Name:           m.Name,
			SeqReserve:     seqAvail,
			BtcReserve:     btcReserve,
			PriceSeqPerBtc: s.effectivePrice(m),
		})
	}
	return &seqdexv1.ListXchainMarketsResponse{Markets: out}, nil
}

// GetXchainQuote prices a buy of seq_amount SEQ-asset atoms with BTC and reserves
// the maker's keys + timeouts. The quote is held in memory until expiry.
func (s *Service) GetXchainQuote(
	ctx context.Context, req *seqdexv1.GetXchainQuoteRequest,
) (*seqdexv1.GetXchainQuoteResponse, error) {
	m, ok := s.marketBySeqAsset(req.GetSeqAsset())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no market for seq asset %s", req.GetSeqAsset())
	}
	if req.GetSeqAmount() == 0 {
		return nil, status.Error(codes.InvalidArgument, "seq_amount must be > 0")
	}

	// Reserve check.
	avail, err := s.availableSeq(m.SeqAsset)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read seq reserve: %v", err)
	}
	if req.GetSeqAmount() > avail {
		return nil, status.Errorf(codes.ResourceExhausted,
			"requested %d exceeds available SEQ reserve %d", req.GetSeqAmount(), avail)
	}

	// Pricing: btc = seq / price; fee added on top. Price is the SEQ node's live
	// reference rate (ref[BTC]/ref[asset]) when available, else the market's static
	// configured price.
	price := s.effectivePrice(m)
	if price <= 0 {
		return nil, status.Error(codes.FailedPrecondition, "market price not set")
	}
	btcBase := uint64(float64(req.GetSeqAmount()) / price)
	if btcBase == 0 {
		btcBase = 1
	}
	feeBtc := btcBase * m.FeeBps / 10000
	btcAmount := btcBase + feeBtc

	// Keys + timeouts.
	makerBTCKey, err := xchain.NewKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "gen btc key: %v", err)
	}
	makerSEQKey, err := xchain.NewKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "gen seq key: %v", err)
	}
	btcHeight, err := s.btcHeight()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "btc height: %v", err)
	}
	seqHeight, err := s.cfg.SEQ.BlockCount()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "seq height: %v", err)
	}
	btcLocktime := uint32(btcHeight) + s.cfg.BtcLocktimeDelta // T_btc (longer)
	seqLocktime := uint32(seqHeight) + s.cfg.SeqLocktimeDelta // T_seq (shorter)

	q := &quote{
		id:          newID(),
		market:      m,
		seqAmount:   req.GetSeqAmount(),
		btcAmount:   btcAmount,
		feeBtc:      feeBtc,
		makerBTCKey: makerBTCKey,
		makerSEQKey: makerSEQKey,
		btcLocktime: btcLocktime,
		seqLocktime: seqLocktime,
		expiresAt:   time.Now().Add(s.cfg.QuoteTTL),
	}
	s.mu.Lock()
	s.quotes[q.id] = q
	s.mu.Unlock()

	return &seqdexv1.GetXchainQuoteResponse{
		QuoteId:           q.id,
		SeqAmount:         q.seqAmount,
		BtcAmount:         q.btcAmount,
		PriceSeqPerBtc:    price,
		FeeBtc:            q.feeBtc,
		MakerBtcClaimPub:  hex.EncodeToString(makerBTCKey.PubKey()),
		MakerSeqRefundPub: hex.EncodeToString(makerSEQKey.PubKey()),
		BtcLocktime:       btcLocktime,
		SeqLocktime:       seqLocktime,
		ExpiresAtUnix:     q.expiresAt.Unix(),
	}, nil
}

// ProposeXchainSwap is the heart of the maker state machine. The taker has
// locked + confirmed the BTC leg; the maker verifies it, locks the SEQ leg
// (anchored), and returns it — or a structured failure.
func (s *Service) ProposeXchainSwap(
	ctx context.Context, req *seqdexv1.ProposeXchainSwapRequest,
) (*seqdexv1.ProposeXchainSwapResponse, error) {
	s.mu.Lock()
	q := s.quotes[req.GetQuoteId()]
	s.mu.Unlock()
	if q == nil {
		return nil, status.Error(codes.NotFound, "unknown or expired quote_id")
	}
	if time.Now().After(q.expiresAt) {
		return fail("QUOTE_EXPIRED", "quote expired"), nil
	}

	hashH, err := hex.DecodeString(req.GetHash())
	if err != nil || len(hashH) != 32 {
		return fail("BAD_HASH", "hash must be 32-byte hex"), nil
	}
	takerSeqClaimPub, err := hex.DecodeString(req.GetTakerSeqClaimPub())
	if err != nil || len(takerSeqClaimPub) != 33 {
		return fail("BAD_PUBKEY", "taker_seq_claim_pub must be 33-byte compressed hex"), nil
	}
	takerBtcRefundPub, err := hex.DecodeString(req.GetTakerBtcRefundPub())
	if err != nil || len(takerBtcRefundPub) != 33 {
		return fail("BAD_PUBKEY", "taker_btc_refund_pub must be 33-byte compressed hex"), nil
	}
	bl := req.GetBtcLeg()
	if bl == nil {
		return fail("MISSING_BTC_LEG", "btc_leg is required"), nil
	}
	providedScript, err := hex.DecodeString(bl.GetRedeemScript())
	if err != nil {
		return fail("BAD_SCRIPT", "btc_leg.redeem_script must be hex"), nil
	}

	// Build the orchestrator with the hash-only primitive (maker side: no secret
	// yet). The SAME primitive is shared by both legs, so injecting the secret
	// later lets ClaimBTCLeg build the BTC redeem.
	prim := xchain.NewHashLockFromHash(hashH)
	orch := s.newOrch(prim)

	// --- PENDING_BTC_LOCK: verify the taker's BTC leg. ---
	vbtc, err := orch.VerifyBTCLeg(
		hashH, q.makerBTCKey.PubKey(), takerBtcRefundPub, providedScript,
		q.btcLocktime,
		bl.GetTxid(), bl.GetVout(), q.btcAmount, q.market.BtcAsset,
		s.cfg.MinBTCConf,
	)
	if err != nil {
		switch {
		case errors.Is(err, xchain.ErrBTCLegUnconfirmed):
			return fail("BTC_LEG_UNCONFIRMED", err.Error()), nil
		case errors.Is(err, xchain.ErrBTCLegInvalid):
			return fail("BTC_LEG_INVALID", err.Error()), nil
		default:
			return fail("BTC_LEG_VERIFY_ERROR", err.Error()), nil
		}
	}

	// --- reserve & lock the SEQ leg. ---
	s.mu.Lock()
	s.reservedSeq[q.market.SeqAsset] += q.seqAmount
	delete(s.quotes, q.id) // single-use quote
	s.mu.Unlock()

	unreserve := func() {
		s.mu.Lock()
		if s.reservedSeq[q.market.SeqAsset] >= q.seqAmount {
			s.reservedSeq[q.market.SeqAsset] -= q.seqAmount
		}
		s.mu.Unlock()
	}

	seqLeg, seqBlock, err := orch.LockSEQLeg(
		takerSeqClaimPub, q.makerSEQKey.PubKey(),
		s.atomsToCoins(q.seqAmount), q.market.SeqAsset, q.seqLocktime,
	)
	if err != nil {
		unreserve()
		return fail("SEQ_LOCK_FAILED", fmt.Sprintf("lock SEQ leg: %v", err)), nil
	}

	// Record the SEQ-leg anchorheight (the value-add: it must be >= the BTC-leg
	// height; the TAKER independently re-verifies this before claiming).
	anchorHeight, aerr := s.cfg.SEQ.BlockAnchorHeight(seqBlock)
	if aerr != nil {
		anchorHeight = -1
	}

	sw := &Swap{
		id:           newID(),
		state:        StateSeqLocked,
		q:            q,
		orch:         orch,
		btcLeg:       vbtc.Leg,
		seqLeg:       seqLeg,
		seqBlockHash: seqBlock,
		anchorHeight: anchorHeight,
		btcLegHeight: vbtc.Height,
	}
	s.mu.Lock()
	s.swaps[sw.id] = sw
	s.mu.Unlock()

	return &seqdexv1.ProposeXchainSwapResponse{
		Result: &seqdexv1.ProposeXchainSwapResponse_Accepted{
			Accepted: &seqdexv1.XchainSwapAccepted{
				SwapId: sw.id,
				SeqLeg: seqLegToProto(seqLeg, seqBlock, anchorHeight, q.market.SeqAsset),
			},
		},
	}, nil
}

// GetXchainSwap reports the current state so the taker can poll for the maker's
// BTC-leg claim.
func (s *Service) GetXchainSwap(
	ctx context.Context, req *seqdexv1.GetXchainSwapRequest,
) (*seqdexv1.GetXchainSwapResponse, error) {
	s.mu.Lock()
	sw := s.swaps[req.GetSwapId()]
	s.mu.Unlock()
	if sw == nil {
		return nil, status.Error(codes.NotFound, "unknown swap_id")
	}
	sw.mu.Lock()
	defer sw.mu.Unlock()

	resp := &seqdexv1.GetXchainSwapResponse{
		SwapId:       sw.id,
		State:        stateToProto(sw.state),
		SeqClaimTxid: sw.seqClaimTxid,
		BtcClaimTxid: sw.btcClaimTxid,
		Detail:       sw.detail,
	}
	if sw.seqLeg != nil {
		resp.SeqLeg = seqLegToProto(sw.seqLeg, sw.seqBlockHash, sw.anchorHeight, sw.q.market.SeqAsset)
	}
	if len(sw.preimage) > 0 {
		resp.Preimage = hex.EncodeToString(sw.preimage)
	}
	return resp, nil
}

// --- helpers ---

func fail(code, msg string) *seqdexv1.ProposeXchainSwapResponse {
	return &seqdexv1.ProposeXchainSwapResponse{
		Result: &seqdexv1.ProposeXchainSwapResponse_Fail{
			Fail: &seqdexv1.XchainSwapFail{Code: code, Message: msg},
		},
	}
}

func seqLegToProto(leg *xchain.LegLock, blockHash string, anchorHeight int64, assetID string) *seqdexv1.XchainSeqLeg {
	return &seqdexv1.XchainSeqLeg{
		Txid:         leg.Funded.TxID,
		Vout:         leg.Funded.Vout,
		BlockHash:    blockHash,
		AnchorHeight: anchorHeight,
		RedeemScript: hex.EncodeToString(leg.Script),
		Amount:       leg.Funded.Amount,
		AssetId:      leg.Funded.AssetID,
	}
}

func stateToProto(st State) seqdexv1.XchainSwapState {
	switch st {
	case StatePendingBTCLock:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_PENDING_BTC_LOCK
	case StateSeqLocked:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_SEQ_LOCKED
	case StateSeqClaimed:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_SEQ_CLAIMED
	case StateBTCClaimed:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_BTC_CLAIMED
	case StateRefunded:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_REFUNDED
	case StateFailed:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_FAILED
	case StateBTCLocked:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_BTC_LOCKED
	case StateSeqSubmitted:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_SEQ_SUBMITTED
	default:
		return seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_UNSPECIFIED
	}
}
