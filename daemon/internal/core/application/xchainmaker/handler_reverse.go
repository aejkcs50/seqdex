package xchainmaker

// Reverse-direction (asset->BTC) handlers: the taker SELLS a Sequentia asset for
// BTC. Roles flip vs the forward flow — the MAKER is the secret holder:
//
//   GetReverseXchainQuote -> price asset->BTC, generate s+H, hold the quote.
//   OpenReverseXchainSwap -> reserve BTC, LOCK the BTC leg (claim=taker,
//     refund=maker, T_btc, the LONGER timeout), return the funded BTC leg + H +
//     the maker's SEQ-leg claim pubkey.
//   (taker funds the SEQ asset leg: claim=maker, refund=taker, T_seq, anchored.)
//   SubmitReverseSeqLeg -> verify the taker's SEQ leg; the watcher then runs the
//     anchor gate and CLAIMS the SEQ leg (revealing s); the taker reads s from
//     GetXchainSwap.preimage and claims the maker's BTC leg.
//
// Invariants are unchanged from the forward direction: T_btc > T_seq, and the
// SEQ leg is the second/anchored leg gated by VerifySeqLegSafe before the secret
// is revealed.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetReverseXchainQuote prices SELLING seq_amount of the asset for BTC and holds
// a quote (including the maker-generated secret + keys). No leg is locked yet.
func (s *Service) GetReverseXchainQuote(
	ctx context.Context, req *seqdexv1.GetReverseXchainQuoteRequest,
) (*seqdexv1.GetReverseXchainQuoteResponse, error) {
	m, ok := s.marketBySeqAsset(req.GetSeqAsset())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no market for seq asset %s", req.GetSeqAsset())
	}
	if req.GetSeqAmount() == 0 {
		return nil, status.Error(codes.InvalidArgument, "seq_amount must be > 0")
	}

	price := s.effectivePrice(m) // SEQ-asset atoms per BTC atom
	if price <= 0 {
		return nil, status.Error(codes.FailedPrecondition, "market price not set")
	}
	// asset->BTC: gross BTC = seqAmount / price; the maker keeps the fee, so the
	// taker RECEIVES btcGross - fee (the maker funds exactly that).
	btcGross := uint64(float64(req.GetSeqAmount()) / price)
	if btcGross == 0 {
		btcGross = 1
	}
	feeBtc := btcGross * m.FeeBps / 10000
	if feeBtc >= btcGross {
		return nil, status.Error(codes.FailedPrecondition, "amount too small to net any BTC after fee")
	}
	btcAmount := btcGross - feeBtc

	// Advisory availability check (the firm reservation happens at Open).
	avail, err := s.availableBtc()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read btc reserve: %v", err)
	}
	if btcAmount > avail {
		return nil, status.Errorf(codes.ResourceExhausted,
			"quoted %d BTC exceeds available reserve %d", btcAmount, avail)
	}

	// The maker is the secret holder in reverse: generate s + H now.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, status.Errorf(codes.Internal, "gen secret: %v", err)
	}
	prim := xchain.NewHashLock(secret)
	makerSEQClaimKey, err := xchain.NewKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "gen seq key: %v", err)
	}
	makerBTCRefundKey, err := xchain.NewKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "gen btc key: %v", err)
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
		id:                newID(),
		market:            m,
		seqAmount:         req.GetSeqAmount(),
		btcAmount:         btcAmount,
		feeBtc:            feeBtc,
		btcLocktime:       btcLocktime,
		seqLocktime:       seqLocktime,
		expiresAt:         time.Now().Add(s.cfg.QuoteTTL),
		reverse:           true,
		secret:            secret,
		hash:              prim.Hash,
		makerSEQClaimKey:  makerSEQClaimKey,
		makerBTCRefundKey: makerBTCRefundKey,
	}
	s.mu.Lock()
	s.quotes[q.id] = q
	s.mu.Unlock()

	return &seqdexv1.GetReverseXchainQuoteResponse{
		QuoteId:        q.id,
		SeqAmount:      q.seqAmount,
		BtcAmount:      q.btcAmount,
		PriceSeqPerBtc: price,
		FeeBtc:         q.feeBtc,
		BtcLocktime:    btcLocktime,
		SeqLocktime:    seqLocktime,
		ExpiresAtUnix:  q.expiresAt.Unix(),
	}, nil
}

// OpenReverseXchainSwap commits the maker: it reserves BTC, locks the BTC leg
// (claim=taker, refund=maker, T_btc), and returns the funded BTC leg + H + the
// maker's SEQ-leg claim pubkey so the taker can fund the asset leg.
func (s *Service) OpenReverseXchainSwap(
	ctx context.Context, req *seqdexv1.OpenReverseXchainSwapRequest,
) (*seqdexv1.OpenReverseXchainSwapResponse, error) {
	s.mu.Lock()
	q := s.quotes[req.GetQuoteId()]
	s.mu.Unlock()
	if q == nil || !q.reverse {
		return nil, status.Error(codes.NotFound, "unknown or non-reverse quote_id")
	}
	if time.Now().After(q.expiresAt) {
		return openFail("QUOTE_EXPIRED", "quote expired"), nil
	}

	takerBtcClaimPub, err := hex.DecodeString(req.GetTakerBtcClaimPub())
	if err != nil || len(takerBtcClaimPub) != 33 {
		return openFail("BAD_PUBKEY", "taker_btc_claim_pub must be 33-byte compressed hex"), nil
	}
	takerSeqRefundPub, err := hex.DecodeString(req.GetTakerSeqRefundPub())
	if err != nil || len(takerSeqRefundPub) != 33 {
		return openFail("BAD_PUBKEY", "taker_seq_refund_pub must be 33-byte compressed hex"), nil
	}

	// Firm BTC reservation (mirror the forward's reserve-at-commit).
	avail, err := s.availableBtc()
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read btc reserve: %v", err)
	}
	if q.btcAmount > avail {
		return openFail("INSUFFICIENT_BTC_RESERVE",
			fmt.Sprintf("need %d BTC, have %d available", q.btcAmount, avail)), nil
	}
	s.reserveBtc(q.btcAmount)
	s.mu.Lock()
	delete(s.quotes, q.id) // single-use
	s.mu.Unlock()

	// Build the orchestrator WITH the maker's secret (reverse: maker holds s).
	prim := xchain.NewHashLock(q.secret)
	orch := s.newOrch(prim)

	// Lock the BTC leg FIRST: claim=taker, refund=maker, T_btc (longer).
	btcLeg, hp, err := orch.LockBTCLeg(
		takerBtcClaimPub, q.makerBTCRefundKey.PubKey(),
		s.atomsToCoins(q.btcAmount), q.btcLocktime,
	)
	if err != nil {
		s.releaseBtcReserve(q.btcAmount)
		return openFail("BTC_LOCK_FAILED", fmt.Sprintf("lock BTC leg: %v", err)), nil
	}

	sw := &Swap{
		id:                newID(),
		state:             StateBTCLocked,
		q:                 q,
		reverse:           true,
		orch:              orch,
		btcLeg:            btcLeg,
		btcLegHeight:      hp,
		takerSeqRefundPub: takerSeqRefundPub,
	}
	s.mu.Lock()
	s.swaps[sw.id] = sw
	s.mu.Unlock()

	return &seqdexv1.OpenReverseXchainSwapResponse{
		Result: &seqdexv1.OpenReverseXchainSwapResponse_Opened{
			Opened: &seqdexv1.ReverseXchainSwapOpened{
				SwapId:            sw.id,
				BtcLeg:            btcLegToProto(btcLeg, hp),
				Hash:              hex.EncodeToString(q.hash),
				MakerSeqClaimPub:  hex.EncodeToString(q.makerSEQClaimKey.PubKey()),
				MakerBtcRefundPub: hex.EncodeToString(q.makerBTCRefundKey.PubKey()),
				BtcLocktime:       q.btcLocktime,
				SeqLocktime:       q.seqLocktime,
			},
		},
	}, nil
}

// SubmitReverseSeqLeg verifies the taker's funded SEQ asset leg and admits it.
// The background watcher then runs the anchor gate and claims it (revealing s).
func (s *Service) SubmitReverseSeqLeg(
	ctx context.Context, req *seqdexv1.SubmitReverseSeqLegRequest,
) (*seqdexv1.SubmitReverseSeqLegResponse, error) {
	s.mu.Lock()
	sw := s.swaps[req.GetSwapId()]
	s.mu.Unlock()
	if sw == nil {
		return nil, status.Error(codes.NotFound, "unknown swap_id")
	}
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if !sw.reverse {
		return submitFail("NOT_REVERSE", "swap is not a reverse (asset->BTC) swap"), nil
	}
	if sw.state != StateBTCLocked {
		return submitFail("BAD_STATE", fmt.Sprintf("swap not awaiting a SEQ leg (state %d)", sw.state)), nil
	}
	// The maker's BTC leg must have confirmed first: its height Hp is the anchor
	// floor for the taker's SEQ leg (VerifySeqLegSafe requires the SEQ block to
	// anchor at/above Hp before the maker reveals s). On a live network LockBTCLeg
	// returns Hp=0 and the watcher fills it in on confirmation; until then the
	// taker must wait (poll GetXchainSwap.btc_leg_height) before funding the SEQ leg.
	if sw.btcLegHeight <= 0 {
		return submitFail("BTC_LEG_UNCONFIRMED",
			"maker BTC leg not yet confirmed; wait until GetXchainSwap reports btc_leg_height > 0 before funding the SEQ leg"), nil
	}
	sl := req.GetSeqLeg()
	if sl == nil {
		return submitFail("MISSING_SEQ_LEG", "seq_leg is required"), nil
	}
	providedScript, err := hex.DecodeString(sl.GetRedeemScript())
	if err != nil {
		return submitFail("BAD_SCRIPT", "seq_leg.redeem_script must be hex"), nil
	}

	q := sw.q
	// Verify the taker funded the agreed asset+amount, claimable by the maker's
	// seq-claim key and refundable by the taker after T_seq. ~1 conf suffices for
	// the SEQ leg (anchoring); VerifySeqLegSafe (run by the watcher) is the real
	// reorg-safety gate before the maker reveals the secret.
	vseq, err := sw.orch.VerifySEQLeg(
		q.hash, q.makerSEQClaimKey.PubKey(), sw.takerSeqRefundPub, providedScript,
		q.seqLocktime, sl.GetTxid(), sl.GetVout(), q.seqAmount, q.market.SeqAsset, 1,
	)
	if err != nil {
		switch {
		case errors.Is(err, xchain.ErrSEQLegUnconfirmed):
			return submitFail("SEQ_LEG_UNCONFIRMED", err.Error()), nil
		case errors.Is(err, xchain.ErrSEQLegInvalid):
			return submitFail("SEQ_LEG_INVALID", err.Error()), nil
		default:
			return submitFail("SEQ_LEG_VERIFY_ERROR", err.Error()), nil
		}
	}

	sw.seqLeg = vseq.Leg
	sw.seqBlockHash = vseq.BlockHash
	if ah, aerr := s.cfg.SEQ.BlockAnchorHeight(vseq.BlockHash); aerr == nil {
		sw.anchorHeight = ah
	} else {
		sw.anchorHeight = -1
	}
	sw.state = StateSeqSubmitted
	sw.detail = ""

	return &seqdexv1.SubmitReverseSeqLegResponse{
		Result: &seqdexv1.SubmitReverseSeqLegResponse_Accepted{
			Accepted: &seqdexv1.XchainSwapAccepted{
				SwapId: sw.id,
				SeqLeg: seqLegToProto(vseq.Leg, vseq.BlockHash, sw.anchorHeight, q.market.SeqAsset),
			},
		},
	}, nil
}

// --- reverse helpers ---

func openFail(code, msg string) *seqdexv1.OpenReverseXchainSwapResponse {
	return &seqdexv1.OpenReverseXchainSwapResponse{
		Result: &seqdexv1.OpenReverseXchainSwapResponse_Fail{
			Fail: &seqdexv1.XchainSwapFail{Code: code, Message: msg},
		},
	}
}

func submitFail(code, msg string) *seqdexv1.SubmitReverseSeqLegResponse {
	return &seqdexv1.SubmitReverseSeqLegResponse{
		Result: &seqdexv1.SubmitReverseSeqLegResponse_Fail{
			Fail: &seqdexv1.XchainSwapFail{Code: code, Message: msg},
		},
	}
}

func btcLegToProto(leg *xchain.LegLock, height int64) *seqdexv1.XchainBtcLeg {
	return &seqdexv1.XchainBtcLeg{
		Txid:         leg.Funded.TxID,
		Vout:         leg.Funded.Vout,
		Height:       height,
		RedeemScript: hex.EncodeToString(leg.Script),
		Amount:       leg.Funded.Amount,
		AssetId:      leg.Funded.AssetID,
	}
}
