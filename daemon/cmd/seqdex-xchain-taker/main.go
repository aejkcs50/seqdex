// Command seqdex-xchain-taker drives a FULL BTC->SEQ-asset cross-chain swap over
// the daemon's gRPC XchainService (Phase 5, milestone 2). It is the gRPC-driven
// counterpart to cmd/seqdex-xchain-swapdemo (which exercises the raw mechanism
// in-process): here the maker side runs in seqdex-xchaind and the taker speaks
// to it over the wire.
//
// Flow:
//  1. GetXchainQuote        -> amounts, maker pubkeys, T_btc > T_seq.
//  2. generate secret s & H, LOCK the BTC leg (claim=maker w/ s, refund=taker
//     after T_btc) and confirm it on the parent chain.
//  3. ProposeXchainSwap     -> maker verifies BTC leg, locks SEQ leg, replies.
//  4. VerifySeqLegSafe      -> anchorheight >= btc height && anchor ok.
//  5. CLAIM the SEQ leg with s (revealing s on the SEQ chain).
//  6. poll GetXchainSwap until the maker claims the BTC leg (BTC_CLAIMED).
//
// PROOF printed: both legs' claim txids, the preimage linking them, the SEQ
// balance delta, and the anchor ordering.
//
// Env (secrets generated in-process / written to SECRET_FILE, never on argv):
//
//	XCHAIN_ADDR   maker gRPC addr (default 127.0.0.1:9955)
//	PARENT_RPC    parent ("BTC") node RPC url (taker funds the BTC leg here)
//	SEQ_RPC       anchored Sequentia node RPC url (taker claims the SEQ leg here)
//	WALLET        wallet name (default "w")
//	SEQ_ASSET     the market's SEQ asset id (hex)
//	SEQ_AMOUNT    SEQ-asset atoms to buy (default 1000)
//	SECRET_FILE   optional path to write the swap preimage (hex)
//	MODE          "happy" (default) or "refund" (let the maker refund T_seq)
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
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
	btc := xchain.NewChain(btcRPC, wallet)
	seq := xchain.NewChain(seqRPC, wallet)

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

	// taker balance before (proof of receipt).
	seqBalBefore, _ := seq.AssetBalance(seqAsset)

	// 1) quote.
	q, err := cli.GetXchainQuote(ctx, &seqdexv1.GetXchainQuoteRequest{
		SeqAsset: seqAsset, SeqAmount: seqAmount,
	})
	if err != nil {
		return fmt.Errorf("GetXchainQuote: %w", err)
	}
	fmt.Printf("\n=== QUOTE %s ===\n  buy %d SEQ-atoms for %d BTC-atoms (fee %d), T_btc=%d > T_seq=%d\n",
		q.GetQuoteId(), q.GetSeqAmount(), q.GetBtcAmount(), q.GetFeeBtc(), q.GetBtcLocktime(), q.GetSeqLocktime())
	if q.GetBtcLocktime() <= q.GetSeqLocktime() {
		return fmt.Errorf("ORDERING VIOLATION: T_btc(%d) must exceed T_seq(%d)", q.GetBtcLocktime(), q.GetSeqLocktime())
	}

	makerBTCClaimPub, err := hex.DecodeString(q.GetMakerBtcClaimPub())
	if err != nil {
		return fmt.Errorf("decode maker btc claim pub: %w", err)
	}

	// 2) taker secret + BTC-leg lock (taker is the initiator).
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	if f := os.Getenv("SECRET_FILE"); f != "" {
		if err := os.WriteFile(f, []byte(hex.EncodeToString(secret)), 0o600); err != nil {
			return fmt.Errorf("write SECRET_FILE: %w", err)
		}
		fmt.Println("swap secret written to", f)
	}
	H := sha256.Sum256(secret)
	fmt.Printf("\nhashlock H = %s\n", hex.EncodeToString(H[:]))

	prim := xchain.NewHashLock(secret)
	orch := xchain.NewSwap(btc, seq, prim)

	takerRefundBTC, err := xchain.NewKey() // taker refunds its own BTC leg
	if err != nil {
		return err
	}
	takerClaimSEQ, err := xchain.NewKey() // taker claims the SEQ leg
	if err != nil {
		return err
	}

	// Lock the BTC leg: claim=maker (with preimage), refund=taker (after T_btc).
	btcLeg, hp, err := orch.LockBTCLeg(
		makerBTCClaimPub, takerRefundBTC.PubKey(),
		atomsToCoins(q.GetBtcAmount()), q.GetBtcLocktime(),
	)
	if err != nil {
		return fmt.Errorf("lock BTC leg: %w", err)
	}
	fmt.Printf("\n=== BTC LEG LOCKED ===\n  txid=%s vout=%d confirmed at parent height %d\n",
		btcLeg.Funded.TxID, btcLeg.Funded.Vout, hp)

	if mode == "refund" {
		fmt.Println("\nMODE=refund: NOT proposing the swap; maker should refund its SEQ leg after T_seq.")
		fmt.Println("(The taker would refund its OWN BTC leg after T_btc; this run only exercises the maker-side refund via Propose+stall.)")
	}

	// 3) propose: maker verifies BTC leg + locks SEQ leg.
	resp, err := cli.ProposeXchainSwap(ctx, &seqdexv1.ProposeXchainSwapRequest{
		QuoteId: q.GetQuoteId(),
		Hash:    hex.EncodeToString(H[:]),
		BtcLeg: &seqdexv1.XchainBtcLeg{
			Txid:         btcLeg.Funded.TxID,
			Vout:         btcLeg.Funded.Vout,
			Height:       hp,
			RedeemScript: hex.EncodeToString(btcLeg.Script),
			Amount:       btcLeg.Funded.Amount,
			AssetId:      btcLeg.Funded.AssetID,
		},
		TakerSeqClaimPub:  hex.EncodeToString(takerClaimSEQ.PubKey()),
		TakerBtcRefundPub: hex.EncodeToString(takerRefundBTC.PubKey()),
	})
	if err != nil {
		return fmt.Errorf("ProposeXchainSwap: %w", err)
	}
	if f := resp.GetFail(); f != nil {
		return fmt.Errorf("maker rejected swap: %s: %s", f.GetCode(), f.GetMessage())
	}
	acc := resp.GetAccepted()
	seqLegPb := acc.GetSeqLeg()
	fmt.Printf("\n=== SEQ LEG LOCKED (by maker) ===\n  swap_id=%s txid=%s vout=%d block=%s anchorheight=%d\n",
		acc.GetSwapId(), seqLegPb.GetTxid(), seqLegPb.GetVout(), seqLegPb.GetBlockHash(), seqLegPb.GetAnchorHeight())

	// 4) anchor-ordering verification (the Sequentia value-add) using pkg/xchain.
	ev, err := orch.VerifySeqLegSafe(seqLegPb.GetBlockHash(), hp)
	if err != nil {
		return fmt.Errorf("ANCHOR ORDERING FAILED: %w", err)
	}
	fmt.Printf("\n=== ANCHOR ORDERING OK ===\n  anchorheight=%d >= btc-leg height=%d, status=%q (node anchorheight=%d)\n",
		ev.SeqBlockAnchor, ev.BTCLegHeight, ev.AnchorStatus, ev.NodeAnchorHeight)

	if mode == "refund" {
		fmt.Println("\nMODE=refund: taker WILL NOT claim the SEQ leg. Polling for the maker to refund after T_seq...")
		return pollRefund(ctx, cli, acc.GetSwapId(), seq, q.GetSeqLocktime())
	}

	// 5) claim the SEQ leg with the secret (reveals s).
	seqLeg := protoToLeg(seqLegPb)
	seqRedeem, err := orch.ClaimSEQLeg(seqLeg, takerClaimSEQ, 100000)
	if err != nil {
		return fmt.Errorf("claim SEQ leg: %w", err)
	}
	fmt.Printf("\n=== SEQ LEG CLAIMED (by taker, preimage revealed) ===\n  redeem txid=%s\n", seqRedeem)
	found, _, _ := seq.RedeemScriptSigContains(seqRedeem, hex.EncodeToString(secret))
	fmt.Printf("  preimage on-chain in SEQ redeem: %v\n", found)

	// 6) poll until the maker claims the BTC leg.
	fmt.Println("\n=== WAITING for maker to extract preimage + claim BTC leg ===")
	var final *seqdexv1.GetXchainSwapResponse
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		// keep mining BTC so the maker's claim can confirm (regtest).
		_ = btc.Mine(1)
		gs, err := cli.GetXchainSwap(ctx, &seqdexv1.GetXchainSwapRequest{SwapId: acc.GetSwapId()})
		if err != nil {
			return fmt.Errorf("GetXchainSwap: %w", err)
		}
		final = gs
		if gs.GetState() == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_BTC_CLAIMED {
			break
		}
		if gs.GetState() == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_FAILED {
			return fmt.Errorf("swap FAILED: %s", gs.GetDetail())
		}
		time.Sleep(time.Second)
	}
	if final == nil || final.GetState() != seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_BTC_CLAIMED {
		st := "nil"
		if final != nil {
			st = final.GetState().String()
		}
		return fmt.Errorf("maker did not claim BTC leg in time (state=%s)", st)
	}

	fmt.Printf("\n=== BTC LEG CLAIMED (by maker, with preimage) ===\n  btc claim txid=%s\n  preimage seen by maker=%s\n",
		final.GetBtcClaimTxid(), final.GetPreimage())

	// PROOF.
	seqBalAfter, _ := seq.AssetBalance(seqAsset)
	fmt.Println("\n=== PROOF ===")
	fmt.Printf("  preimage links both legs: maker-extracted %s == taker secret %s -> %v\n",
		final.GetPreimage(), hex.EncodeToString(secret), final.GetPreimage() == hex.EncodeToString(secret))
	fmt.Printf("  SEQ leg claim txid (taker): %s\n", seqRedeem)
	fmt.Printf("  BTC leg claim txid (maker): %s\n", final.GetBtcClaimTxid())
	fmt.Printf("  SEQ-asset balance: before=%d after=%d delta=%+d (expected +%d minus claim fee)\n",
		seqBalBefore, seqBalAfter, int64(seqBalAfter)-int64(seqBalBefore), q.GetSeqAmount())
	fmt.Printf("  anchor ordering held: anchorheight %d >= btc-leg height %d\n", ev.SeqBlockAnchor, hp)
	fmt.Println("\nSWAP COMPLETE (gRPC-driven). PASS")
	return nil
}

func pollRefund(ctx context.Context, cli seqdexv1.XchainServiceClient, swapID string, seq *xchain.Chain, seqLocktime uint32) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_ = seq.Mine(1) // advance toward T_seq so the maker can refund
		gs, err := cli.GetXchainSwap(ctx, &seqdexv1.GetXchainSwapRequest{SwapId: swapID})
		if err != nil {
			return fmt.Errorf("GetXchainSwap: %w", err)
		}
		if gs.GetState() == seqdexv1.XchainSwapState_XCHAIN_SWAP_STATE_REFUNDED {
			fmt.Printf("\n=== REFUNDED ===\n  maker refunded its SEQ leg after T_seq=%d: %s\nREFUND PATH PASS\n", seqLocktime, gs.GetDetail())
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("maker did not refund within timeout")
}

func protoToLeg(pb *seqdexv1.XchainSeqLeg) *xchain.LegLock {
	script, _ := hex.DecodeString(pb.GetRedeemScript())
	return &xchain.LegLock{
		Script: script,
		Funded: &xchain.FundedHTLC{
			TxID:    pb.GetTxid(),
			Vout:    pb.GetVout(),
			Amount:  pb.GetAmount(),
			AssetID: pb.GetAssetId(),
		},
	}
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
