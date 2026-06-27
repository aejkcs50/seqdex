// Command seqdex-xchain-reverse-taker drives a FULL asset->BTC (SELL a Sequentia
// asset for BTC) cross-chain swap over the daemon's gRPC XchainService, using the
// REVERSE RPCs (GetReverseXchainQuote / OpenReverseXchainSwap / SubmitReverseSeqLeg
// / GetXchainSwap). It is the reverse-direction counterpart of
// cmd/seqdex-xchain-taker: there the taker BUYS an asset with BTC and is the
// secret holder; here the taker SELLS an asset for BTC and the MAKER is the secret
// holder.
//
// Flow (the maker holds the secret and funds BTC first):
//  1. GetReverseXchainQuote -> btc_amount, T_btc > T_seq.
//  2. OpenReverseXchainSwap  -> the MAKER locks the BTC leg (claim=taker, refund=
//     maker, T_btc) and returns the funded BTC leg + H + maker_seq_claim_pub.
//  3. poll GetXchainSwap until btc_leg_height > 0 (the maker's BTC leg confirmed).
//  4. FUND the taker's SEQ asset leg (claim=maker w/ s, refund=taker after T_seq).
//  5. SubmitReverseSeqLeg -> maker verifies it; its watcher runs VerifySeqLegSafe
//     (the anchor gate) then CLAIMS the SEQ leg, REVEALING s.
//  6. poll GetXchainSwap until SEQ_CLAIMED + preimage set, then CLAIM the maker's
//     BTC leg with the revealed s.
//
// Env (no secrets on argv; the maker owns the secret here):
//
//	XCHAIN_ADDR    maker gRPC addr (default 127.0.0.1:9955)
//	PARENT_KIND    "elements" (default; regtest harness) | "bitcoin" (real bitcoind)
//	PARENT_CHAIN   bitcoin parent network when PARENT_KIND=bitcoin: regtest (default) | testnet4
//	PARENT_RPC     parent ("BTC") node RPC url (the taker claims the maker's BTC leg here)
//	SEQ_RPC        anchored Sequentia node RPC url (the taker funds the SEQ leg here)
//	WALLET         wallet name (default "w")
//	SEQ_ASSET      the market's SEQ asset id (hex)
//	SEQ_AMOUNT     SEQ-asset atoms to SELL (default 1000)
//	MODE           "happy" (default) or "refund" (don't fund SEQ; maker refunds BTC after T_btc)
//
// NOTE: the regtest path mines on demand (PARENT_KIND=elements + a Sequentia
// regtest node). A real testnet4 run needs no-mine funding + waiting for natural
// confirmations on BOTH legs (the SEQ-leg LockSEQLeg below mines), mirroring the
// maker-side bitcoinBTCBackend change; that is left for the wallet taker.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
	"github.com/btcsuite/btcd/chaincfg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := envOr("XCHAIN_ADDR", "127.0.0.1:9955")
	wallet := envOr("WALLET", "w")
	parentKind := envOr("PARENT_KIND", "elements")
	seqAsset := os.Getenv("SEQ_ASSET")
	if seqAsset == "" {
		return fmt.Errorf("SEQ_ASSET not set")
	}
	seqAmount := uintEnv("SEQ_AMOUNT", 1000)
	mode := envOr("MODE", "happy")

	btcRPC, err := rpcFromEnv("PARENT_RPC")
	if err != nil {
		return err
	}
	seqRPC, err := rpcFromEnv("SEQ_RPC")
	if err != nil {
		return err
	}
	seq := xchain.NewChain(seqRPC, wallet)

	// Backend selection mirrors the maker (cmd/seqdex-xchaind): an Elements parent
	// (regtest harness) or a REAL bitcoind. newOrch builds the orchestrator once we
	// have H; mineParent advances the parent chain on regtest to let the anchor
	// catch up.
	var (
		btcElements *xchain.Chain
		btcBitcoin  *xchain.BitcoinChain
		mineParent  func() error
	)
	switch parentKind {
	case "bitcoin":
		params, perr := xchain.BitcoinChainParams(envOr("PARENT_CHAIN", "regtest"))
		if perr != nil {
			return perr
		}
		btcBitcoin = xchain.NewBitcoinChain(btcRPC, wallet, params)
		regtest := params == &chaincfg.RegressionNetParams
		mineParent = func() error {
			if !regtest {
				return nil // testnet4: no on-demand mining
			}
			var a string
			if err := btcBitcoin.RPC().Call(&a, "getnewaddress"); err != nil {
				return err
			}
			var h []string
			return btcBitcoin.RPC().Call(&h, "generatetoaddress", 1, a)
		}
	default: // "elements"
		btcElements = xchain.NewChain(btcRPC, wallet)
		mineParent = func() error { return btcElements.Mine(1) }
	}
	newOrch := func(prim *xchain.HashLock) *xchain.Swap {
		if btcBitcoin != nil {
			return xchain.NewSwapBitcoin(btcBitcoin, seq, prim)
		}
		return xchain.NewSwap(btcElements, seq, prim)
	}

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial maker %s: %w", addr, err)
	}
	defer conn.Close()
	cli := seqdexv1.NewXchainServiceClient(conn)
	ctx := context.Background()

	// 0) markets + reserves.
	mk, err := cli.ListXchainMarkets(ctx, &seqdexv1.ListXchainMarketsRequest{})
	if err != nil {
		return fmt.Errorf("ListXchainMarkets: %w", err)
	}
	fmt.Println("=== MARKETS ===")
	for _, m := range mk.GetMarkets() {
		fmt.Printf("  %s  seq_reserve=%d btc_reserve=%d price(seq/btc)=%.4f\n",
			m.GetName(), m.GetSeqReserve(), m.GetBtcReserve(), m.GetPriceSeqPerBtc())
	}

	// 1) reverse quote: SELL seqAmount of the asset for BTC.
	q, err := cli.GetReverseXchainQuote(ctx, &seqdexv1.GetReverseXchainQuoteRequest{
		SeqAsset: seqAsset, SeqAmount: seqAmount,
	})
	if err != nil {
		return fmt.Errorf("GetReverseXchainQuote: %w", err)
	}
	fmt.Printf("\n=== REVERSE QUOTE %s ===\n  sell %d SEQ-atoms for %d BTC-atoms, T_btc=%d > T_seq=%d\n",
		q.GetQuoteId(), q.GetSeqAmount(), q.GetBtcAmount(), q.GetBtcLocktime(), q.GetSeqLocktime())
	if q.GetBtcLocktime() <= q.GetSeqLocktime() {
		return fmt.Errorf("ORDERING VIOLATION: T_btc(%d) must exceed T_seq(%d)", q.GetBtcLocktime(), q.GetSeqLocktime())
	}

	// 2) taker keys: claim the maker's BTC leg with s; refund the taker's SEQ leg.
	takerBtcClaim, err := xchain.NewKey()
	if err != nil {
		return err
	}
	takerSeqRefund, err := xchain.NewKey()
	if err != nil {
		return err
	}

	// 3) OPEN: the maker reserves BTC, locks the BTC leg first, returns it + H.
	openResp, err := cli.OpenReverseXchainSwap(ctx, &seqdexv1.OpenReverseXchainSwapRequest{
		QuoteId:           q.GetQuoteId(),
		TakerBtcClaimPub:  hex.EncodeToString(takerBtcClaim.PubKey()),
		TakerSeqRefundPub: hex.EncodeToString(takerSeqRefund.PubKey()),
	})
	if err != nil {
		return fmt.Errorf("OpenReverseXchainSwap: %w", err)
	}
	if f := openResp.GetFail(); f != nil {
		return fmt.Errorf("maker rejected open: %s: %s", f.GetCode(), f.GetMessage())
	}
	opened := openResp.GetOpened()
	swapID := opened.GetSwapId()
	btcLegPb := opened.GetBtcLeg()
	hashHex := opened.GetHash()
	makerSeqClaimPub, err := hex.DecodeString(opened.GetMakerSeqClaimPub())
	if err != nil {
		return fmt.Errorf("decode maker_seq_claim_pub: %w", err)
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}
	fmt.Printf("\n=== BTC LEG LOCKED (by maker) ===\n  swap_id=%s txid=%s vout=%d H=%s\n",
		swapID, btcLegPb.GetTxid(), btcLegPb.GetVout(), hashHex)

	// orchestrator: the taker only holds H (NewHashLockFromHash); s is injected
	// later from GetXchainSwap.preimage once the maker reveals it.
	orch := newOrch(xchain.NewHashLockFromHash(hashBytes))

	// Reconstruct the maker's BTC leg so we can claim it later.
	btcScript, err := hex.DecodeString(btcLegPb.GetRedeemScript())
	if err != nil {
		return fmt.Errorf("decode btc redeem script: %w", err)
	}
	btcLeg := &xchain.LegLock{
		Script:   btcScript,
		Funded:   &xchain.FundedHTLC{TxID: btcLegPb.GetTxid(), Vout: btcLegPb.GetVout(), Amount: btcLegPb.GetAmount(), AssetID: btcLegPb.GetAssetId()},
		Locktime: opened.GetBtcLocktime(),
	}

	if mode == "refund" {
		fmt.Println("\nMODE=refund: NOT funding the SEQ leg; advancing the parent past T_btc so the maker refunds its BTC leg...")
		deadline := time.Now().Add(120 * time.Second)
		for time.Now().Before(deadline) {
			_ = mineParent()
			gs, err := cli.GetXchainSwap(ctx, &seqdexv1.GetXchainSwapRequest{SwapId: swapID})
			if err != nil {
				return fmt.Errorf("GetXchainSwap: %w", err)
			}
			if gs.GetState() == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_REFUNDED {
				fmt.Printf("\n=== REFUNDED ===\n  maker refunded its BTC leg after T_btc=%d: %s\nREVERSE REFUND PATH PASS\n", q.GetBtcLocktime(), gs.GetDetail())
				return nil
			}
			time.Sleep(time.Second)
		}
		return fmt.Errorf("maker did not refund its BTC leg within timeout")
	}

	// 4) wait for the maker's BTC leg to confirm (Hp known) before funding SEQ, so
	// the SEQ block can anchor at/above the BTC-leg height.
	fmt.Println("\n=== WAITING for maker BTC leg to confirm (btc_leg_height > 0) ===")
	var btcLegHeight int64
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		gs, err := cli.GetXchainSwap(ctx, &seqdexv1.GetXchainSwapRequest{SwapId: swapID})
		if err != nil {
			return fmt.Errorf("GetXchainSwap: %w", err)
		}
		if gs.GetBtcLegHeight() > 0 {
			btcLegHeight = gs.GetBtcLegHeight()
			break
		}
		_ = mineParent() // regtest: advance toward confirmation
		time.Sleep(time.Second)
	}
	if btcLegHeight == 0 {
		return fmt.Errorf("maker BTC leg did not confirm in time")
	}
	fmt.Printf("  maker BTC leg confirmed at parent height %d\n", btcLegHeight)

	// 5) FUND the SEQ asset leg: claim=maker (with s), refund=taker (after T_seq).
	seqLeg, seqBlock, err := orch.LockSEQLeg(
		makerSeqClaimPub, takerSeqRefund.PubKey(),
		atomsToCoins(q.GetSeqAmount()), seqAsset, q.GetSeqLocktime(),
	)
	if err != nil {
		return fmt.Errorf("fund SEQ leg: %w", err)
	}
	fmt.Printf("\n=== SEQ LEG FUNDED (by taker) ===\n  txid=%s vout=%d block=%s\n",
		seqLeg.Funded.TxID, seqLeg.Funded.Vout, seqBlock)

	// 6) submit the SEQ leg; the maker verifies + (via its watcher) claims it.
	subResp, err := cli.SubmitReverseSeqLeg(ctx, &seqdexv1.SubmitReverseSeqLegRequest{
		SwapId: swapID,
		SeqLeg: &seqdexv1.XchainSeqLeg{
			Txid:         seqLeg.Funded.TxID,
			Vout:         seqLeg.Funded.Vout,
			BlockHash:    seqBlock,
			RedeemScript: hex.EncodeToString(seqLeg.Script),
			Amount:       seqLeg.Funded.Amount,
			AssetId:      seqAsset,
		},
	})
	if err != nil {
		return fmt.Errorf("SubmitReverseSeqLeg: %w", err)
	}
	if f := subResp.GetFail(); f != nil {
		return fmt.Errorf("maker rejected SEQ leg: %s: %s", f.GetCode(), f.GetMessage())
	}
	fmt.Printf("\n=== SEQ LEG SUBMITTED + ACCEPTED ===\n  swap_id=%s\n", subResp.GetAccepted().GetSwapId())

	// 7) wait for the maker to pass the anchor gate + CLAIM the SEQ leg (reveal s).
	fmt.Println("\n=== WAITING for maker to anchor-gate + claim the SEQ leg (reveal s) ===")
	var preimage string
	deadline = time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		_ = mineParent() // advance the parent so the SEQ block can anchor >= Hp
		_ = seq.Mine(1)  // advance the SEQ chain / let anchoring catch up
		gs, err := cli.GetXchainSwap(ctx, &seqdexv1.GetXchainSwapRequest{SwapId: swapID})
		if err != nil {
			return fmt.Errorf("GetXchainSwap: %w", err)
		}
		st := gs.GetState()
		if st == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_SEQ_CLAIMED && gs.GetPreimage() != "" {
			preimage = gs.GetPreimage()
			fmt.Printf("  maker claimed the SEQ leg: seq_claim_txid=%s, preimage revealed\n", gs.GetSeqClaimTxid())
			break
		}
		if st == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_FAILED || st == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_REFUNDED {
			return fmt.Errorf("swap ended without a SEQ claim (state=%s): %s", st.String(), gs.GetDetail())
		}
		time.Sleep(time.Second)
	}
	if preimage == "" {
		return fmt.Errorf("maker did not claim the SEQ leg in time")
	}

	// 8) claim the maker's BTC leg with the revealed s.
	secret, err := hex.DecodeString(preimage)
	if err != nil {
		return fmt.Errorf("decode preimage: %w", err)
	}
	if err := orch.InjectSecret(secret); err != nil {
		return fmt.Errorf("inject revealed secret: %w", err)
	}
	btcClaimTxid, err := orch.ClaimBTCLeg(btcLeg, takerBtcClaim, safeFee(btcLeg.Funded.Amount))
	if err != nil {
		return fmt.Errorf("claim BTC leg: %w", err)
	}
	_ = mineParent() // regtest: confirm the taker's BTC claim
	fmt.Printf("\n=== BTC LEG CLAIMED (by taker, with revealed s) ===\n  btc claim txid=%s\n", btcClaimTxid)

	fmt.Println("\n=== PROOF ===")
	fmt.Printf("  the maker revealed s by claiming the SEQ asset leg; the taker swept the BTC leg with it.\n")
	fmt.Printf("  SEQ leg funded by taker:  %s\n", seqLeg.Funded.TxID)
	fmt.Printf("  BTC leg claimed by taker: %s (preimage %s)\n", btcClaimTxid, preimage)
	fmt.Println("\nREVERSE SWAP COMPLETE (asset->BTC, gRPC-driven). PASS")
	return nil
}

func safeFee(amount uint64) uint64 {
	fee := uint64(1000)
	if max := amount / 2; fee > max {
		fee = max
	}
	return fee
}

func atomsToCoins(atoms uint64) string { return fmt.Sprintf("%.8f", float64(atoms)/1e8) }

func rpcFromEnv(key string) (*xchain.RPC, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return nil, fmt.Errorf("%s not set (expected http://user:pass@host:port)", key)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	user := u.User.Username()
	pass, _ := u.User.Password()
	return xchain.NewRPC(host, port, user, pass), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func uintEnv(k string, def uint64) uint64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
