// Command seqdex-xchain-swapdemo runs the Phase-5 cross-chain atomic-swap
// MECHANISM (pkg/xchain) end-to-end against a running two-chain regtest: a
// parent Elements node standing in for Bitcoin (the anchor source) and an
// anchored Sequentia node. It is the non-test, runnable counterpart to the
// integration test in pkg/xchain, and mirrors contrib/sequentia/swap-demo.py.
//
// It demonstrates, in one run:
//   - HAPPY PATH: BTC leg locked first; SEQ leg confirmed in a Sequentia block
//     whose anchorheight >= the BTC-leg height (verified before proceeding —
//     the Sequentia anchor-shortened-ordering value-add); Alice redeems the SEQ
//     leg revealing the preimage; Bob redeems the BTC leg with it.
//   - ANCHOR negative test: the orchestrator REJECTS a SEQ leg whose
//     anchorheight is below the BTC-leg height.
//   - REFUND PATH: a CLTV refund rejected before timeout, accepted after.
//
// All keys + the swap secret are generated in-process (regtest only). If
// SECRET_FILE is set, the 32-byte preimage is written there (hex) rather than
// printed, so no secret material lands on the command line.
//
// Env:
//
//	PARENT_RPC   parent ("BTC") node RPC url, http://user:pass@host:port
//	SEQ_RPC      anchored Sequentia node RPC url, http://user:pass@host:port
//	WALLET       wallet name on both nodes (default "w")
//	ASSET        SEQ-side asset hex; if empty, the demo issues a fresh asset
//	SECRET_FILE  optional path to write the swap preimage (hex)
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	btcRPC, err := rpcFromEnv("PARENT_RPC")
	if err != nil {
		return err
	}
	seqRPC, err := rpcFromEnv("SEQ_RPC")
	if err != nil {
		return err
	}
	wallet := envOr("WALLET", "w")
	btc := xchain.NewChain(btcRPC, wallet)
	seq := xchain.NewChain(seqRPC, wallet)

	// Ensure both chains are funded and the anchor watcher is synced.
	if err := ensureFunded(btc); err != nil {
		return fmt.Errorf("fund BTC chain: %w", err)
	}
	if err := ensureFunded(seq); err != nil {
		return fmt.Errorf("fund SEQ chain: %w", err)
	}
	if err := waitAnchorOK(seq); err != nil {
		return err
	}

	asset := os.Getenv("ASSET")
	if asset == "" {
		if asset, err = issueAsset(seqRPC, wallet); err != nil {
			return fmt.Errorf("issueasset: %w", err)
		}
		_ = seqRPC.WithWallet(wallet).Call(nil, "setfeeexchangerates",
			map[string]interface{}{asset: 100000000})
		_ = seq.Mine(1)
	}
	fmt.Println("SEQ asset:", asset)

	// Keys (regtest only).
	aliceClaimSEQ := mustKey()
	aliceRefundBTC := mustKey()
	bobClaimBTC := mustKey()
	bobRefundSEQ := mustKey()

	// Shared secret (Design A).
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
	prim := xchain.NewHashLock(secret)
	H := sha256.Sum256(secret)
	fmt.Println("hashlock H =", hex.EncodeToString(H[:]))

	swap := xchain.NewSwap(btc, seq, prim)
	btcH, _ := btc.BlockCount()
	seqH, _ := seq.BlockCount()

	// ---- HAPPY PATH ----
	fmt.Println("\n=== HAPPY PATH ===")
	btcLeg, hp, err := swap.LockBTCLeg(bobClaimBTC.PubKey(), aliceRefundBTC.PubKey(), "10", uint32(btcH+100))
	if err != nil {
		return fmt.Errorf("lock BTC leg: %w", err)
	}
	fmt.Printf("1. BTC leg LOCKED %s:%d (parent height %d)\n", btcLeg.Funded.TxID, btcLeg.Funded.Vout, hp)

	seqLeg, seqBlock, err := swap.LockSEQLeg(aliceClaimSEQ.PubKey(), bobRefundSEQ.PubKey(), "1000", asset, uint32(seqH+50))
	if err != nil {
		return fmt.Errorf("lock SEQ leg: %w", err)
	}
	fmt.Printf("2. SEQ leg LOCKED %s:%d (seq block %s)\n", seqLeg.Funded.TxID, seqLeg.Funded.Vout, seqBlock)

	ev, err := swap.VerifySeqLegSafe(seqBlock, hp)
	if err != nil {
		return fmt.Errorf("anchor ordering check: %w", err)
	}
	fmt.Printf("3. ANCHOR OK: anchorheight=%d >= btc-leg height=%d, status=%q\n", ev.SeqBlockAnchor, ev.BTCLegHeight, ev.AnchorStatus)

	seqRedeem, err := swap.ClaimSEQLeg(seqLeg, aliceClaimSEQ, 100000)
	if err != nil {
		return fmt.Errorf("claim SEQ leg: %w", err)
	}
	fmt.Printf("4. SEQ leg REDEEMED (preimage revealed): %s\n", seqRedeem)

	found, _, err := seq.RedeemScriptSigContains(seqRedeem, hex.EncodeToString(secret))
	if err != nil {
		return err
	}
	fmt.Printf("   preimage on-chain in SEQ redeem: %v\n", found)

	btcRedeem, err := swap.ClaimBTCLeg(btcLeg, bobClaimBTC, 100000)
	if err != nil {
		return fmt.Errorf("claim BTC leg: %w", err)
	}
	fmt.Printf("5. BTC leg REDEEMED with preimage: %s\n", btcRedeem)
	fmt.Println("=> SWAP COMPLETE atomically.")

	// ---- ANCHOR negative test ----
	fmt.Println("\n=== ANCHOR CHECK (negative) ===")
	if _, nerr := swap.VerifySeqLegSafe(seqBlock, ev.SeqBlockAnchor+1); nerr != nil {
		fmt.Printf("orchestrator REJECTED unsafe SEQ leg: %v\n", nerr)
	} else {
		return fmt.Errorf("negative test failed: expected rejection")
	}

	// ---- REFUND PATH ----
	fmt.Println("\n=== REFUND PATH ===")
	rk := mustKey()
	now, _ := seq.BlockCount()
	lt := uint32(now + 5)
	refundLeg, _, err := swap.LockSEQLeg(rk.PubKey(), rk.PubKey(), "500", asset, lt)
	if err != nil {
		return fmt.Errorf("lock refund HTLC: %w", err)
	}
	early, err := swap.RefundSEQLeg(refundLeg, rk, lt, 100000)
	if err != nil {
		return err
	}
	if _, berr := seq.TryBroadcast(early); berr != nil {
		fmt.Printf("refund BEFORE timeout REJECTED: %v\n", berr)
	} else {
		return fmt.Errorf("early refund unexpectedly accepted")
	}
	if err := seq.Mine(6); err != nil {
		return err
	}
	after, _ := seq.BlockCount()
	late, err := swap.RefundSEQLeg(refundLeg, rk, uint32(after), 100000)
	if err != nil {
		return err
	}
	refundTxid, err := seq.Broadcast(late)
	if err != nil {
		return fmt.Errorf("broadcast refund: %w", err)
	}
	_ = seq.Mine(1)
	fmt.Printf("refund AFTER timeout accepted: %s\n", refundTxid)
	fmt.Println("\nDONE.")
	return nil
}

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

func ensureFunded(c *xchain.Chain) error {
	h, err := c.BlockCount()
	if err != nil {
		return err
	}
	if h < 110 {
		return c.Mine(int(110 - h))
	}
	return nil
}

func waitAnchorOK(seq *xchain.Chain) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s, err := seq.GetAnchorStatus()
		if err == nil && s.AnchorStatus == "ok" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("anchor status did not reach ok within timeout")
}

func issueAsset(rpc *xchain.RPC, wallet string) (string, error) {
	var res struct {
		Asset string `json:"asset"`
	}
	if err := rpc.WithWallet(wallet).Call(&res, "issueasset", "100000", "0"); err != nil {
		return "", err
	}
	return res.Asset, nil
}

func mustKey() *xchain.Key {
	k, err := xchain.NewKey()
	if err != nil {
		panic(err)
	}
	return k
}
