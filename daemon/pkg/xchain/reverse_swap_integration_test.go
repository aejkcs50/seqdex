package xchain_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// TestReverseCrossChainSwap drives the REVERSE (asset->BTC) Design-A swap
// end-to-end on a live two-chain regtest, with the roles swapped vs
// TestCrossChainSwap:
//
//   - The MAKER is the secret holder. It LOCKS the BTC leg FIRST (claim=taker,
//     refund=maker, T_btc the LONGER timeout).
//   - The TAKER funds the SEQ asset leg SECOND (claim=maker, refund=taker, T_seq
//     the SHORTER timeout). The maker VERIFIES it (VerifySEQLeg) and the SEQ-leg
//     anchor ordering (VerifySeqLegSafe) before revealing.
//   - The MAKER claims the SEQ asset leg, revealing the preimage; the TAKER reads
//     it off-chain and claims the BTC leg.
//   - REFUND PATH: the maker's BTC-leg CLTV refund is rejected before T_btc and
//     accepted after (RefundBTCLeg).
//
// The two invariants are unchanged: T_btc > T_seq, and the SEQ leg is the
// second/anchored leg gated by VerifySeqLegSafe.
func TestReverseCrossChainSwap(t *testing.T) {
	h := setupHarness(t)

	puser, ppass := h.cookie(t, h.parentDir)
	suser, spass := h.cookie(t, h.seqDir)

	btcRPC := xchain.NewRPC("127.0.0.1", h.parentRPC, puser, ppass)
	seqRPC := xchain.NewRPC("127.0.0.1", h.seqRPC, suser, spass)
	btc := xchain.NewChain(btcRPC, "w")
	seq := xchain.NewChain(seqRPC, "w")

	mustNoErr(t, "btc mine", btc.Mine(110))
	mustNoErr(t, "seq mine", seq.Mine(110))
	waitAnchorOK(t, seq)

	asset := issueAsset(t, seqRPC, "w")
	t.Logf("SEQ asset issued: %s", asset)
	mustNoErr(t, "setfeeexchangerates", seqRPC.WithWallet("w").Call(nil,
		"setfeeexchangerates", map[string]interface{}{asset: 100000000}))
	mustNoErr(t, "seq mine asset", seq.Mine(1))

	// --- keys (reverse roles). ---
	makerClaimSEQ := mustKey(t)  // maker claims the SEQ asset leg (reveals s)
	makerRefundBTC := mustKey(t) // maker refunds the BTC leg it funded
	takerClaimBTC := mustKey(t)  // taker claims the BTC leg
	takerRefundSEQ := mustKey(t) // taker refunds the SEQ leg it funded

	// --- the shared secret. In reverse the MAKER is the holder. ---
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
	btcLocktime := uint32(btcHeight + 100) // maker's BTC refund timeout (LONGER)
	seqLocktime := uint32(seqHeight + 50)  // taker's SEQ refund timeout (SHORTER)

	// ================= HAPPY PATH =================
	t.Log("=== REVERSE HAPPY PATH ===")

	// Step 1: the MAKER locks the BTC leg first. claim=taker, refund=maker.
	btcLeg, hp, err := swap.LockBTCLeg(takerClaimBTC.PubKey(), makerRefundBTC.PubKey(), "10", btcLocktime)
	mustNoErr(t, "maker lock BTC leg", err)
	t.Logf("1. BTC leg LOCKED by maker: txid=%s vout=%d (parent height %d)",
		btcLeg.Funded.TxID, btcLeg.Funded.Vout, hp)

	// Step 2: the TAKER funds the SEQ asset leg. claim=maker, refund=taker.
	seqLeg, seqBlock, err := swap.LockSEQLeg(makerClaimSEQ.PubKey(), takerRefundSEQ.PubKey(), "1000", asset, seqLocktime)
	mustNoErr(t, "taker lock SEQ leg", err)
	t.Logf("2. SEQ leg LOCKED by taker: txid=%s vout=%d (seq block %s)",
		seqLeg.Funded.TxID, seqLeg.Funded.Vout, seqBlock)

	// Step 3a: the MAKER verifies the taker-funded SEQ leg (reverse VerifySEQLeg).
	vseq, err := swap.VerifySEQLeg(
		H[:], makerClaimSEQ.PubKey(), takerRefundSEQ.PubKey(), seqLeg.Script,
		seqLocktime, seqLeg.Funded.TxID, seqLeg.Funded.Vout, seqLeg.Funded.Amount, asset, 1,
	)
	mustNoErr(t, "maker verify SEQ leg", err)
	t.Logf("3a. SEQ leg VERIFIED by maker: height=%d confs=%d block=%s",
		vseq.Height, vseq.Confirmations, vseq.BlockHash)

	// Step 3b: anchor-ordering gate (HARD precondition before the maker reveals).
	ev, err := swap.VerifySeqLegSafe(seqBlock, hp)
	mustNoErr(t, "verify SEQ leg anchor ordering", err)
	if !ev.OK {
		t.Fatalf("expected SEQ leg anchor-safe, got %+v", ev)
	}
	t.Logf("3b. ANCHOR ORDERING OK: anchorheight=%d >= BTC-leg height=%d, status=%q",
		ev.SeqBlockAnchor, ev.BTCLegHeight, ev.AnchorStatus)

	// Step 4: the MAKER claims the SEQ asset leg, revealing the preimage.
	seqRedeem, err := swap.ClaimSEQLeg(vseq.Leg, makerClaimSEQ, 100000)
	mustNoErr(t, "maker claim SEQ leg", err)
	t.Logf("4. SEQ leg REDEEMED by maker (preimage revealed): txid=%s", seqRedeem)

	found, asm, err := seq.RedeemScriptSigContains(seqRedeem, hex.EncodeToString(secret))
	mustNoErr(t, "read preimage from SEQ redeem", err)
	if !found {
		t.Fatalf("preimage not found in SEQ redeem scriptSig asm: %s", asm)
	}
	t.Logf("   preimage %s revealed (taker can now read it)", hex.EncodeToString(secret))

	// Step 5: the TAKER claims the BTC leg with the revealed preimage.
	btcRedeem, err := swap.ClaimBTCLeg(btcLeg, takerClaimBTC, 100000)
	mustNoErr(t, "taker claim BTC leg", err)
	t.Logf("5. BTC leg REDEEMED by taker with the preimage: txid=%s", btcRedeem)

	if c, _ := seq.Confirmations(seqRedeem); c < 1 {
		t.Fatalf("SEQ redeem not confirmed (confs=%d)", c)
	}
	if c, _ := btc.Confirmations(btcRedeem); c < 1 {
		t.Fatalf("BTC redeem not confirmed (confs=%d)", c)
	}
	t.Logf("REVERSE HAPPY PATH PASS: maker got the asset, taker got the BTC; same preimage links both legs.")

	// ================= REVERSE REFUND PATH =================
	t.Log("=== REVERSE REFUND PATH (maker refunds its BTC leg) ===")
	refundKey := mustKey(t)
	btcNow, _ := btc.BlockCount()
	refundLocktime := uint32(btcNow + 5)
	refundLeg, _, err := swap.LockBTCLeg(refundKey.PubKey(), refundKey.PubKey(), "5", refundLocktime)
	mustNoErr(t, "lock refund BTC HTLC", err)
	t.Logf("refund BTC HTLC funded: txid=%s, CLTV locktime=%d (height %d)",
		refundLeg.Funded.TxID, refundLocktime, btcNow)

	// Refund BEFORE timeout must be rejected by consensus (CLTV not satisfied).
	if txid, berr := swap.RefundBTCLeg(refundLeg, refundKey, refundLocktime, 100000); berr == nil {
		t.Fatalf("early BTC refund unexpectedly accepted: %s", txid)
	} else {
		t.Logf("BTC refund BEFORE timeout correctly REJECTED: %v", berr)
	}

	// Advance past the timeout, then refund.
	mustNoErr(t, "advance past CLTV", btc.Mine(6))
	heightAfter, _ := btc.BlockCount()
	refundTxid, err := swap.RefundBTCLeg(refundLeg, refundKey, uint32(heightAfter), 100000)
	mustNoErr(t, "late BTC refund", err)
	if c, _ := btc.Confirmations(refundTxid); c < 1 {
		t.Fatalf("BTC refund not confirmed (confs=%d)", c)
	}
	t.Logf("REVERSE REFUND PATH PASS: BTC refund AFTER timeout accepted+confirmed: txid=%s", refundTxid)
}
