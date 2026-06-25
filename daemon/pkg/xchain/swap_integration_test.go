package xchain_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// TestCrossChainSwap drives the full Design-A cross-chain atomic swap end-to-end
// on a live two-chain regtest:
//
//   - HAPPY PATH: BTC leg locked first; SEQ leg lands in a Sequentia block whose
//     anchorheight >= the BTC-leg height (asserted); Alice redeems the SEQ leg
//     revealing the preimage; Bob redeems the BTC leg with that preimage.
//   - ANCHOR CHECK: prints anchorheight + anchorstatus=ok, and a negative test
//     showing the orchestrator REJECTS a SEQ leg whose anchorheight is below the
//     BTC-leg height.
//   - REFUND PATH: a fresh HTLC, refund rejected before its CLTV timeout and
//     accepted after.
func TestCrossChainSwap(t *testing.T) {
	h := setupHarness(t)

	puser, ppass := h.cookie(t, h.parentDir)
	suser, spass := h.cookie(t, h.seqDir)

	btcRPC := xchain.NewRPC("127.0.0.1", h.parentRPC, puser, ppass)
	seqRPC := xchain.NewRPC("127.0.0.1", h.seqRPC, suser, spass)
	btc := xchain.NewChain(btcRPC, "w")
	seq := xchain.NewChain(seqRPC, "w")

	// --- chain warm-up: fund both wallets, sync the anchor watcher. ---
	mustNoErr(t, "btc mine", btc.Mine(110))
	mustNoErr(t, "seq mine", seq.Mine(110))
	// Give the anchor poller (-anchorpollinterval=1) a moment to catch up.
	waitAnchorOK(t, seq)

	// Issue the SEQ-side asset and let it pay its own fee.
	asset := issueAsset(t, seqRPC, "w")
	t.Logf("SEQ asset issued: %s", asset)
	mustNoErr(t, "setfeeexchangerates", seqRPC.WithWallet("w").Call(nil,
		"setfeeexchangerates", map[string]interface{}{asset: 100000000}))
	mustNoErr(t, "seq mine asset", seq.Mine(1))

	// --- keys (regtest-only, generated in-process). ---
	aliceClaimSEQ := mustKey(t)  // Alice claims the SEQ leg
	aliceRefundBTC := mustKey(t) // Alice refunds the BTC leg she funded
	bobClaimBTC := mustKey(t)    // Bob claims the BTC leg
	bobRefundSEQ := mustKey(t)   // Bob refunds the SEQ leg he funded

	// --- the shared secret (Design A: one preimage locks both legs). ---
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	prim := xchain.NewHashLock(secret)
	H := sha256.Sum256(secret)
	t.Logf("hashlock H = sha256(secret) = %s", hex.EncodeToString(H[:]))

	swap := xchain.NewSwap(btc, seq, prim)

	btcHeight, _ := btc.BlockCount()
	seqHeight, _ := seq.BlockCount()
	btcLocktime := uint32(btcHeight + 100) // Alice's refund timeout (longer)
	seqLocktime := uint32(seqHeight + 50)  // Bob's refund timeout (shorter)

	// ================= HAPPY PATH =================
	t.Log("=== HAPPY PATH ===")

	// Step 1: Alice locks the BTC leg first. claim=Bob, refund=Alice.
	btcLeg, hp, err := swap.LockBTCLeg(bobClaimBTC.PubKey(), aliceRefundBTC.PubKey(), "10", btcLocktime)
	mustNoErr(t, "lock BTC leg", err)
	t.Logf("1. BTC leg LOCKED: txid=%s vout=%d (confirmed at parent height %d)",
		btcLeg.Funded.TxID, btcLeg.Funded.Vout, hp)

	// Step 2: Bob locks the SEQ leg only now. claim=Alice, refund=Bob.
	seqLeg, seqBlock, err := swap.LockSEQLeg(aliceClaimSEQ.PubKey(), bobRefundSEQ.PubKey(), "1000", asset, seqLocktime)
	mustNoErr(t, "lock SEQ leg", err)
	t.Logf("2. SEQ leg LOCKED: txid=%s vout=%d (in seq block %s)",
		seqLeg.Funded.TxID, seqLeg.Funded.Vout, seqBlock)

	// Step 3: anchor-shortened ordering check (the Sequentia value-add).
	ev, err := swap.VerifySeqLegSafe(seqBlock, hp)
	mustNoErr(t, "verify SEQ leg anchor ordering", err)
	if !ev.OK {
		t.Fatalf("expected SEQ leg to be anchor-safe, got %+v", ev)
	}
	t.Logf("3. ANCHOR ORDERING OK: seq-block anchorheight=%d >= BTC-leg height=%d, anchorstatus=%q (node anchorheight=%d)",
		ev.SeqBlockAnchor, ev.BTCLegHeight, ev.AnchorStatus, ev.NodeAnchorHeight)
	t.Log("   => SEQ leg needs only ~1 confirmation: a BTC-leg reorg would revert this SEQ block with it (no extra buffer).")

	// Step 4: Alice redeems the SEQ leg revealing the preimage.
	seqRedeem, err := swap.ClaimSEQLeg(seqLeg, aliceClaimSEQ, 100000)
	mustNoErr(t, "claim SEQ leg", err)
	t.Logf("4. SEQ leg REDEEMED by Alice (preimage revealed): txid=%s", seqRedeem)

	// The preimage is now visible on-chain in Alice's SEQ redeem scriptSig.
	found, asm, err := seq.RedeemScriptSigContains(seqRedeem, hex.EncodeToString(secret))
	mustNoErr(t, "read preimage from SEQ redeem", err)
	if !found {
		t.Fatalf("preimage not found in SEQ redeem scriptSig asm: %s", asm)
	}
	t.Logf("   preimage %s found in SEQ redeem scriptSig (Bob can now read it)", hex.EncodeToString(secret))

	// Step 5: Bob redeems the BTC leg with that preimage.
	btcRedeem, err := swap.ClaimBTCLeg(btcLeg, bobClaimBTC, 100000)
	mustNoErr(t, "claim BTC leg", err)
	t.Logf("5. BTC leg REDEEMED by Bob with the preimage: txid=%s", btcRedeem)

	// Confirm both redeems.
	if c, _ := seq.Confirmations(seqRedeem); c < 1 {
		t.Fatalf("SEQ redeem not confirmed (confs=%d)", c)
	}
	if c, _ := btc.Confirmations(btcRedeem); c < 1 {
		t.Fatalf("BTC redeem not confirmed (confs=%d)", c)
	}
	t.Logf("HAPPY PATH PASS: SEQ redeem %s and BTC redeem %s both confirmed; same preimage links the two legs.",
		seqRedeem, btcRedeem)

	// ================= ANCHOR CHECK: negative test =================
	t.Log("=== ANCHOR CHECK (negative) ===")
	// Take the real SEQ block but assert it against an artificially HIGHER
	// BTC-leg height than its anchorheight: the orchestrator must refuse.
	bogusBTCHeight := ev.SeqBlockAnchor + 1
	negEv, negErr := swap.VerifySeqLegSafe(seqBlock, bogusBTCHeight)
	if negErr == nil {
		t.Fatalf("expected ErrAnchorOrdering when anchorheight(%d) < btc-leg height(%d), got nil",
			ev.SeqBlockAnchor, bogusBTCHeight)
	}
	if negEv.OK {
		t.Fatalf("negative test: orchestrator wrongly reported OK: %+v", negEv)
	}
	t.Logf("NEGATIVE TEST PASS: orchestrator REJECTED SEQ leg (anchorheight=%d < btc-leg height=%d): %v",
		negEv.SeqBlockAnchor, bogusBTCHeight, negErr)

	// ================= REFUND PATH =================
	t.Log("=== REFUND PATH ===")
	refundKey := mustKey(t)
	seqNow, _ := seq.BlockCount()
	refundLocktime := uint32(seqNow + 5)
	// A fresh HTLC funded by the SEQ wallet; refund key signs both branches.
	refundLeg, _, err := swap.LockSEQLeg(refundKey.PubKey(), refundKey.PubKey(), "500", asset, refundLocktime)
	mustNoErr(t, "lock refund HTLC", err)
	t.Logf("refund HTLC funded: txid=%s, CLTV locktime=%d (current height %d)",
		refundLeg.Funded.TxID, refundLocktime, seqNow)

	// Refund BEFORE timeout must be rejected by consensus (CLTV not satisfied).
	early, err := swap.RefundSEQLeg(refundLeg, refundKey, refundLocktime, 100000)
	mustNoErr(t, "build early refund", err)
	if txid, berr := seq.TryBroadcast(early); berr == nil {
		t.Fatalf("early refund unexpectedly accepted: %s", txid)
	} else {
		t.Logf("refund BEFORE timeout correctly REJECTED: %v", berr)
	}

	// Advance past the timeout, then refund.
	mustNoErr(t, "advance past CLTV", seq.Mine(6))
	heightAfter, _ := seq.BlockCount()
	late, err := swap.RefundSEQLeg(refundLeg, refundKey, uint32(heightAfter), 100000)
	mustNoErr(t, "build late refund", err)
	refundTxid, err := seq.Broadcast(late)
	mustNoErr(t, "broadcast late refund", err)
	mustNoErr(t, "mine refund", seq.Mine(1))
	if c, _ := seq.Confirmations(refundTxid); c < 1 {
		t.Fatalf("refund not confirmed (confs=%d)", c)
	}
	t.Logf("REFUND PATH PASS: refund AFTER timeout accepted+confirmed: txid=%s", refundTxid)
}

// --- helpers ---

func mustNoErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func mustKey(t *testing.T) *xchain.Key {
	t.Helper()
	k, err := xchain.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func waitAnchorOK(t *testing.T, seq *xchain.Chain) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		s, err := seq.GetAnchorStatus()
		if err == nil && s.AnchorStatus == "ok" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("anchor status did not reach ok within timeout")
}

func issueAsset(t *testing.T, rpc *xchain.RPC, wallet string) string {
	t.Helper()
	var res struct {
		Asset string `json:"asset"`
	}
	if err := rpc.WithWallet(wallet).Call(&res, "issueasset", "100000", "0"); err != nil {
		t.Fatalf("issueasset: %v", err)
	}
	return res.Asset
}
