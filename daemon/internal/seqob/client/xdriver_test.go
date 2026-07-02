package client

// xdriver_test.go exercises the FORWARD cross-chain handshake fully in-process:
// both drivers run concurrently, wired to each other through channels standing in
// for the relay courier, against a fake XcOps that mimics pkg/xchain semantics
// (including the live-net Hp=0 broadcast-only LockBTCLeg and the on-chain secret
// reveal via WatchSEQClaim). No RPC, no chains — this pins the protocol logic;
// the settlement engine itself is proven separately by the RFQ flows.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// fakeXcNet couples the two drivers: whatever one sends, the other receives.
type fakeXcNet struct {
	toMaker chan []byte
	toTaker chan []byte
}

func newFakeXcNet() *fakeXcNet {
	return &fakeXcNet{toMaker: make(chan []byte, 8), toTaker: make(chan []byte, 8)}
}

func (n *fakeXcNet) takerSend(sealed []byte) error { n.toMaker <- sealed; return nil }
func (n *fakeXcNet) makerSend(sealed []byte) error { n.toTaker <- sealed; return nil }
func (n *fakeXcNet) takerRecv(timeout time.Duration) ([]byte, error) {
	select {
	case b := <-n.toTaker:
		return b, nil
	case <-time.After(timeout):
		return nil, errors.New("taker recv timeout")
	}
}

// fakeChainState is shared by both sides' ops, like the real chains are.
type fakeChainState struct {
	mu           sync.Mutex
	btcTip       int64
	seqTip       int64
	btcConfs     map[string]int
	seqClaimedBy []byte // secret revealed by a SEQ claim (extracted by WatchSEQClaim)
	seqRefunded  bool
	makerSecret  []byte // reverse: the secret the maker minted (the taker derives its hash from it)
}

// fakeOps implements XcOps for one side over the shared state.
type fakeOps struct {
	st            *fakeChainState
	hashH         []byte
	secretForTest []byte // taker side: preimage exposed by ClaimSEQLeg
}

func (f *fakeOps) BtcTip() (int64, error) {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	return f.st.btcTip, nil
}
func (f *fakeOps) BtcConfirmations(txid string) (int, error) {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	return f.st.btcConfs[txid], nil
}
func (f *fakeOps) LockBTCLeg(claimPub, refundPub []byte, amountCoins string, locktime uint32) (*xchain.LegLock, int64, error) {
	// Live-net semantics: broadcast only, Hp=0; a "confirmation" appears shortly.
	f.st.mu.Lock()
	f.st.btcConfs["btc-htlc"] = 1 // instant single conf for the test
	f.st.mu.Unlock()
	script := fakeScript("btc", f.hashH, claimPub, refundPub, locktime)
	return &xchain.LegLock{
		Script:   script,
		Funded:   &xchain.FundedHTLC{TxID: "btc-htlc", Vout: 0, Amount: coinsToAtoms(amountCoins)},
		Locktime: locktime,
	}, 0, nil
}
func (f *fakeOps) VerifyBTCLeg(hashH, makerClaimPub, takerRefundPub, providedScript []byte, btcLocktime uint32,
	txid string, vout uint32, amount uint64, minConf int) (*xchain.VerifiedBTCLeg, error) {
	want := fakeScript("btc", hashH, makerClaimPub, takerRefundPub, btcLocktime)
	if string(want) != string(providedScript) {
		return nil, errors.New("btc redeemScript mismatch")
	}
	f.st.mu.Lock()
	confs := f.st.btcConfs[txid]
	f.st.mu.Unlock()
	if confs < minConf {
		return nil, errors.New("btc leg unconfirmed")
	}
	return &xchain.VerifiedBTCLeg{
		Leg: &xchain.LegLock{Script: providedScript, Funded: &xchain.FundedHTLC{TxID: txid, Vout: vout, Amount: amount}, Locktime: btcLocktime},
	}, nil
}
func (f *fakeOps) ClaimBTCLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error) {
	return "btc-claim", nil
}
func (f *fakeOps) RefundBTCLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error) {
	return "btc-refund", nil
}
func (f *fakeOps) SeqTip() (int64, error) {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	return f.st.seqTip, nil
}
func (f *fakeOps) SeqAnchorHeightOf(blockHash string) (int64, error) { return f.st.btcTip, nil }
func (f *fakeOps) SeqBlockHashOfTx(txid string) (string, error)      { return "seq-block-hash", nil }
func (f *fakeOps) SeqFeeRate(assetHex string) (uint64, bool)         { return 50_000_000_000, true }
func (f *fakeOps) LockSEQLeg(claimPub, refundPub []byte, amountCoins, assetLabel string, locktime uint32) (*xchain.LegLock, string, error) {
	script := fakeScript("seq", f.hashH, claimPub, refundPub, locktime)
	return &xchain.LegLock{
		Script:   script,
		Funded:   &xchain.FundedHTLC{TxID: "seq-htlc", Vout: 1, Amount: coinsToAtoms(amountCoins), AssetID: assetLabel},
		Locktime: locktime,
	}, "seq-block-hash", nil
}
func (f *fakeOps) VerifySEQLeg(hashH, claimPub, refundPub, providedScript []byte, seqLocktime uint32,
	txid string, vout uint32, amount uint64, assetID string, minConf int) (*xchain.VerifiedSEQLeg, error) {
	want := fakeScript("seq", hashH, claimPub, refundPub, seqLocktime)
	if string(want) != string(providedScript) {
		return nil, errors.New("seq redeemScript mismatch")
	}
	return &xchain.VerifiedSEQLeg{
		Leg:       &xchain.LegLock{Script: providedScript, Funded: &xchain.FundedHTLC{TxID: txid, Vout: vout, Amount: amount, AssetID: assetID}, Locktime: seqLocktime},
		BlockHash: "seq-block-hash", // self-derived confirming block (the anchor gate must use THIS, not courier data)
	}, nil
}
func (f *fakeOps) VerifySeqLegSafe(seqBlockHash string, btcLegHeight int64) (*xchain.AnchorEvidence, error) {
	return &xchain.AnchorEvidence{BTCLegHeight: btcLegHeight, SeqBlockHash: seqBlockHash, OK: true}, nil
}
func (f *fakeOps) ClaimSEQLeg(leg *xchain.LegLock, key *xchain.Key, fee uint64) (string, error) {
	// The claim reveals the secret "on-chain": expose it to the shared state so
	// the maker's watcher can extract it, exactly like scriptSig extraction.
	f.st.mu.Lock()
	f.st.seqClaimedBy = f.secretForTest
	f.st.mu.Unlock()
	return "seq-claim", nil
}
func (f *fakeOps) WatchSEQClaim(leg *xchain.LegLock) (string, []byte, error) {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	if len(f.st.seqClaimedBy) > 0 {
		return "seq-claim", f.st.seqClaimedBy, nil
	}
	return "", nil, nil
}
func (f *fakeOps) InjectSecret(secret []byte) error {
	if h := sha256.Sum256(secret); string(h[:]) != string(f.hashH) {
		return errors.New("secret does not match hash")
	}
	return nil
}
func (f *fakeOps) RefundSEQLeg(leg *xchain.LegLock, key *xchain.Key, nLockTime uint32, fee uint64) (string, error) {
	return "seq-refund-raw", nil
}
func (f *fakeOps) SeqBroadcast(rawHex string) (string, error) {
	f.st.mu.Lock()
	f.st.seqRefunded = true
	f.st.mu.Unlock()
	return "seq-refund", nil
}

func (f *fakeOps) withSecret(secret []byte) *fakeOps { f.secretForTest = secret; return f }

// fakeScript derives a deterministic pseudo-redeem-script so byte-comparison
// verification is meaningful without real Script.
func fakeScript(chain string, hashH, claimPub, refundPub []byte, locktime uint32) []byte {
	h := sha256.New()
	h.Write([]byte(chain))
	h.Write(hashH)
	h.Write(claimPub)
	h.Write(refundPub)
	h.Write([]byte{byte(locktime), byte(locktime >> 8), byte(locktime >> 16), byte(locktime >> 24)})
	return h.Sum([]byte("script:"))
}

func coinsToAtoms(coins string) uint64 {
	parts := strings.SplitN(coins, ".", 2)
	var whole, frac uint64
	for _, c := range parts[0] {
		whole = whole*10 + uint64(c-'0')
	}
	fs := parts[1]
	for len(fs) < 8 {
		fs += "0"
	}
	for _, c := range fs[:8] {
		frac = frac*10 + uint64(c-'0')
	}
	return whole*100_000_000 + frac
}

func mustKey(t *testing.T) *xchain.Key {
	t.Helper()
	k, err := xchain.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testCrypters(t *testing.T) (*Crypter, *Crypter) {
	t.Helper()
	makerPriv, _ := btcec.NewPrivateKey()
	takerPriv, _ := btcec.NewPrivateKey()
	tc, err := NewCrypter(takerPriv, makerPriv.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	mc, err := NewCrypter(makerPriv, takerPriv.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return tc, mc
}

const testAsset = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"

func forwardFixture(t *testing.T) (st *fakeChainState, net *fakeXcNet, tp TakerForwardParams, mp MakerForwardParams) {
	t.Helper()
	st = &fakeChainState{btcTip: 1000, seqTip: 5000, btcConfs: map[string]int{}}
	net = newFakeXcNet()
	tc, mc := testCrypters(t)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	hashH := sha256.Sum256(secret)

	takerOps := (&fakeOps{st: st, hashH: hashH[:]}).withSecret(secret)
	tp = TakerForwardParams{
		Ops:             takerOps,
		Crypter:         tc,
		Secret:          secret,
		BtcRefundKey:    mustKey(t),
		SeqClaimKey:     mustKey(t),
		ExpectAsset:     testAsset,
		ExpectSeqAmount: 5_000_000,
		ExpectBtcAmount: 25_000,
		Timing:          XcTiming{Poll: 5 * time.Millisecond, TermsWait: 2 * time.Second, BtcConfWait: 2 * time.Second, SeqLockWait: 2 * time.Second, AnchorWait: 2 * time.Second, TermsReqWait: 2 * time.Second, BtcFundWait: 2 * time.Second},
	}
	mp = MakerForwardParams{
		NewOps:    func(h []byte) (XcOps, error) { return &fakeOps{st: st, hashH: h}, nil },
		Crypter:   mc,
		BtcTip:    func() (int64, error) { st.mu.Lock(); defer st.mu.Unlock(); return st.btcTip, nil },
		SeqTip:    func() (int64, error) { st.mu.Lock(); defer st.mu.Unlock(); return st.seqTip, nil },
		AssetHex:  testAsset,
		SeqAmount: 5_000_000,
		BtcAmount: 25_000,
		Timing:    tp.Timing,
	}
	return st, net, tp, mp
}

func TestForwardHappyPath(t *testing.T) {
	_, net, tp, mp := forwardFixture(t)

	var (
		wg   sync.WaitGroup
		mres *MakerForwardResult
		merr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		mres, merr = RunMakerForward(mp, net.toMaker, net.makerSend)
	}()

	tres, terr := RunTakerForward(tp, net.takerSend, net.takerRecv)
	if terr != nil {
		t.Fatalf("taker: %v", terr)
	}
	wg.Wait()
	if merr != nil {
		t.Fatalf("maker: %v", merr)
	}
	if tres.SeqClaimTxid != "seq-claim" {
		t.Fatalf("taker did not claim: %+v", tres)
	}
	if mres.BtcClaimTxid != "btc-claim" {
		t.Fatalf("maker did not claim BTC: %+v", mres)
	}
	if string(mres.Secret) != string(tp.Secret) {
		t.Fatalf("maker extracted wrong secret")
	}
	if tres.BtcLegHeight != 1000 { // tip 1000, 1 conf -> Hp = 1000-1+1
		t.Fatalf("taker Hp = %d, want 1000", tres.BtcLegHeight)
	}
}

func TestForwardTermsMismatchAborts(t *testing.T) {
	_, net, tp, mp := forwardFixture(t)
	mp.BtcAmount = 26_000 // maker quotes more sats than the signed offer said

	go func() { _, _ = RunMakerForward(mp, net.toMaker, net.makerSend) }()
	res, err := RunTakerForward(tp, net.takerSend, net.takerRecv)
	if err == nil || !errors.Is(err, ErrXcBadTerms) {
		t.Fatalf("want ErrXcBadTerms, got %v", err)
	}
	if res.BtcLeg != nil {
		t.Fatalf("taker must not fund BTC on mismatched terms")
	}
}

func TestForwardMakerRefundsWithoutClaim(t *testing.T) {
	st, net, tp, mp := forwardFixture(t)
	// Let the handshake reach seq_leg_locked, but the taker never claims: run
	// only the maker against a scripted taker.
	go func() {
		// Scripted taker: terms_request, then a valid confirmed BTC leg.
		tc := tp.Crypter
		_ = sendXc(&XcMsg{Type: XcTermsRequest}, tc, net.takerSend)
		sealed, err := net.takerRecv(2 * time.Second)
		if err != nil {
			return
		}
		terms, err := OpenXcMsg(sealed, tc)
		if err != nil || terms.Type != XcTerms {
			return
		}
		makerClaim, _ := hex.DecodeString(terms.MakerBtcClaimPub)
		hashH := sha256.Sum256(tp.Secret)
		st.mu.Lock()
		st.btcConfs["btc-htlc"] = 1
		st.mu.Unlock()
		leg := &XcLeg{
			Txid: "btc-htlc", Vout: 0, Amount: terms.BtcAmount,
			RedeemScript: hex.EncodeToString(fakeScript("btc", hashH[:], makerClaim, tp.BtcRefundKey.PubKey(), terms.BtcLocktime)),
			Locktime:     terms.BtcLocktime, Height: 1000,
		}
		_ = sendXc(&XcMsg{
			Type: XcBtcLegFunded, HashH: hex.EncodeToString(hashH[:]),
			TakerSeqClaimPub:  hex.EncodeToString(tp.SeqClaimKey.PubKey()),
			TakerBtcRefundPub: hex.EncodeToString(tp.BtcRefundKey.PubKey()),
			Leg:               leg,
		}, tc, net.takerSend)
		// Never claim; advance the SEQ tip past T_seq instead.
		time.Sleep(50 * time.Millisecond)
		st.mu.Lock()
		st.seqTip = int64(terms.SeqLocktime) + 1
		st.mu.Unlock()
	}()

	res, err := RunMakerForward(mp, net.toMaker, net.makerSend)
	if err == nil || !errors.Is(err, ErrXcRefunded) {
		t.Fatalf("want ErrXcRefunded, got %v", err)
	}
	if res.SeqRefundTx != "seq-refund" {
		t.Fatalf("maker refund not broadcast: %+v", res)
	}
	st.mu.Lock()
	refunded := st.seqRefunded
	st.mu.Unlock()
	if !refunded {
		t.Fatalf("refund did not reach the chain")
	}
}

func TestForwardTakerAbortsNearSeqLocktime(t *testing.T) {
	st, net, tp, mp := forwardFixture(t)
	// Make T_seq land inside the claim margin by the time the leg is locked:
	// terms pass the MinSeqClaimWindow check (window 20 < delta 50), then the
	// SEQ tip jumps close to T_seq before the claim step.
	go func() { _, _ = RunMakerForward(mp, net.toMaker, net.makerSend) }()

	// Intercept: wrap taker recv so that after seq_leg_locked arrives we advance
	// the tip to within the margin.
	recv := func(timeout time.Duration) ([]byte, error) {
		b, err := net.takerRecv(timeout)
		if err == nil {
			if m, oerr := OpenXcMsg(b, tp.Crypter); oerr == nil && m.Type == XcSeqLegLocked {
				st.mu.Lock()
				st.seqTip = int64(m.Leg.Locktime) - 2 // inside the default margin 10
				st.mu.Unlock()
			}
		}
		return b, err
	}
	res, err := RunTakerForward(tp, net.takerSend, recv)
	if err == nil || !strings.Contains(err.Error(), "not revealing the secret") {
		t.Fatalf("want claim-margin abort, got %v", err)
	}
	if res.SeqClaimTxid != "" {
		t.Fatalf("taker must not have claimed")
	}
	if res.BtcLeg == nil || res.BtcLocktime == 0 {
		t.Fatalf("result must carry the refundable BTC leg: %+v", res)
	}
}

// scriptedTaker drives the maker with hand-built messages (bypassing
// RunTakerForward) so malformed announcements can be injected.
type scriptedTaker struct {
	t   *testing.T
	tp  TakerForwardParams
	net *fakeXcNet
}

func (s *scriptedTaker) requestTerms() *XcMsg {
	s.t.Helper()
	if err := sendXc(&XcMsg{Type: XcTermsRequest}, s.tp.Crypter, s.net.takerSend); err != nil {
		s.t.Fatal(err)
	}
	sealed, err := s.net.takerRecv(2 * time.Second)
	if err != nil {
		s.t.Fatal(err)
	}
	m, err := OpenXcMsg(sealed, s.tp.Crypter)
	if err != nil || m.Type != XcTerms {
		s.t.Fatalf("expected terms, got %v %v", m, err)
	}
	return m
}

func TestForwardMakerRejectsWrongBtcAmount(t *testing.T) {
	st, net, tp, mp := forwardFixture(t)
	var (
		wg   sync.WaitGroup
		merr error
	)
	wg.Add(1)
	go func() { defer wg.Done(); _, merr = RunMakerForward(mp, net.toMaker, net.makerSend) }()

	s := &scriptedTaker{t: t, tp: tp, net: net}
	terms := s.requestTerms()
	makerClaim, _ := hex.DecodeString(terms.MakerBtcClaimPub)
	hashH := sha256.Sum256(tp.Secret)
	st.mu.Lock()
	st.btcConfs["btc-htlc"] = 1
	st.mu.Unlock()
	// Announce a leg whose amount is 1 sat short of terms.
	_ = sendXc(&XcMsg{
		Type: XcBtcLegFunded, HashH: hex.EncodeToString(hashH[:]),
		TakerSeqClaimPub:  hex.EncodeToString(tp.SeqClaimKey.PubKey()),
		TakerBtcRefundPub: hex.EncodeToString(tp.BtcRefundKey.PubKey()),
		Leg: &XcLeg{
			Txid: "btc-htlc", Vout: 0, Amount: terms.BtcAmount - 1,
			RedeemScript: hex.EncodeToString(fakeScript("btc", hashH[:], makerClaim, tp.BtcRefundKey.PubKey(), terms.BtcLocktime)),
			Locktime:     terms.BtcLocktime, Height: 1000,
		},
	}, tp.Crypter, net.takerSend)
	wg.Wait()
	if merr == nil || !strings.Contains(merr.Error(), "btc leg amount") {
		t.Fatalf("maker must reject a short BTC leg; got %v", merr)
	}
	// And the maker must have couriered an XcFail to the taker.
	sealed, err := net.takerRecv(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m, err := OpenXcMsg(sealed, tp.Crypter)
	if err != nil || m.Type != XcFail {
		t.Fatalf("expected XcFail, got %v %v", m, err)
	}
}

func TestForwardTakerRejectsWrongSeqLeg(t *testing.T) {
	_, net, tp, mp := forwardFixture(t)
	mp.SeqAmount = tp.ExpectSeqAmount - 1 // maker under-locks the asset leg

	go func() { _, _ = RunMakerForward(mp, net.toMaker, net.makerSend) }()
	res, err := RunTakerForward(tp, net.takerSend, net.takerRecv)
	// The taker refuses at TERMS time already (seq_amount != signed offer), so
	// no BTC ever moves.
	if err == nil || !errors.Is(err, ErrXcBadTerms) {
		t.Fatalf("want ErrXcBadTerms for under-locked seq amount, got %v", err)
	}
	if res.BtcLeg != nil {
		t.Fatalf("no BTC may move on mismatched terms")
	}
}

func TestForwardTakerAbortsOnAnchorGateFailure(t *testing.T) {
	_, net, tp, mp := forwardFixture(t)
	failing := &anchorFailOps{fakeOps: tp.Ops.(*fakeOps)}
	tp.Ops = failing
	tp.Timing.AnchorWait = 100 * time.Millisecond

	go func() { _, _ = RunMakerForward(mp, net.toMaker, net.makerSend) }()
	res, err := RunTakerForward(tp, net.takerSend, net.takerRecv)
	if err == nil || !strings.Contains(err.Error(), "anchor gate not passed") {
		t.Fatalf("want anchor-gate abort, got %v", err)
	}
	if res.SeqClaimTxid != "" {
		t.Fatalf("taker must not claim (reveal the secret) without the anchor gate")
	}
	if res.BtcLeg == nil {
		t.Fatalf("result must carry the refundable BTC leg")
	}
}

// anchorFailOps makes the anchor gate fail persistently.
type anchorFailOps struct{ *fakeOps }

func (a *anchorFailOps) VerifySeqLegSafe(seqBlockHash string, btcLegHeight int64) (*xchain.AnchorEvidence, error) {
	return nil, errors.New("anchor ordering not satisfied (test)")
}

// --- reverse-direction tests -------------------------------------------------

// reverseFixture wires a maker (secret holder, funds BTC first) and taker
// (sells the asset) over the fake net + shared chain state.
func reverseFixture(t *testing.T) (st *fakeChainState, net *fakeXcNet, tp TakerReverseParams, mp MakerReverseParams) {
	t.Helper()
	st = &fakeChainState{btcTip: 2000, seqTip: 8000, btcConfs: map[string]int{}}
	net = newFakeXcNet()
	tc, mc := testCrypters(t)

	// The maker mints the secret; both ops share state. The maker's NewOps
	// records the minted secret into the shared chain state, and the taker's
	// lazyHashOps derives its hash from it the first time it is needed (the
	// maker funds+announces before the taker builds any script, so it is set
	// by then). This mirrors reality: the taker only ever learns H, off the
	// wire, and its scripts must match the maker's.
	tp = TakerReverseParams{
		Crypter:         tc,
		BtcClaimKey:     mustKey(t),
		SeqRefundKey:    mustKey(t),
		ExpectAsset:     testAsset,
		ExpectSeqAmount: 5_000_000,
		ExpectBtcAmount: 25_000,
		Timing:          XcTiming{Poll: 5 * time.Millisecond, TermsWait: 2 * time.Second, BtcConfWait: 2 * time.Second, SeqLockWait: 2 * time.Second, AnchorWait: 2 * time.Second, TermsReqWait: 2 * time.Second, BtcFundWait: 2 * time.Second},
	}
	mp = MakerReverseParams{
		NewOps:    makerReverseOps(st),
		Crypter:   mc,
		BtcTip:    func() (int64, error) { st.mu.Lock(); defer st.mu.Unlock(); return st.btcTip, nil },
		SeqTip:    func() (int64, error) { st.mu.Lock(); defer st.mu.Unlock(); return st.seqTip, nil },
		AssetHex:  testAsset,
		SeqAmount: 5_000_000,
		BtcAmount: 25_000,
		Timing:    tp.Timing,
	}
	tp.Ops = &lazyHashOps{st: st}
	return st, net, tp, mp
}

// makerReverseOps builds the maker's ops: it records the minted secret in the
// shared state (so the taker can derive H) and exposes it on claim.
func makerReverseOps(st *fakeChainState) func([]byte) (XcOps, error) {
	return func(secret []byte) (XcOps, error) {
		st.mu.Lock()
		st.makerSecret = secret
		st.mu.Unlock()
		h := sha256.Sum256(secret)
		return (&fakeOps{st: st, hashH: h[:]}).withSecret(secret), nil
	}
}

// lazyHashOps is a taker-side fakeOps whose hash is resolved from the maker's
// minted secret (via the shared chain state) the first time it is needed.
type lazyHashOps struct {
	fakeOps
	st *fakeChainState
}

func (l *lazyHashOps) ensure() {
	if l.fakeOps.st == nil {
		l.fakeOps.st = l.st
	}
	if l.fakeOps.hashH == nil {
		l.st.mu.Lock()
		s := l.st.makerSecret
		l.st.mu.Unlock()
		if len(s) > 0 {
			h := sha256.Sum256(s)
			l.fakeOps.hashH = h[:]
		}
	}
}
func (l *lazyHashOps) BtcTip() (int64, error)                    { l.ensure(); return l.fakeOps.BtcTip() }
func (l *lazyHashOps) BtcConfirmations(t string) (int, error)   { l.ensure(); return l.fakeOps.BtcConfirmations(t) }
func (l *lazyHashOps) LockBTCLeg(a, b []byte, c string, d uint32) (*xchain.LegLock, int64, error) {
	l.ensure()
	return l.fakeOps.LockBTCLeg(a, b, c, d)
}
func (l *lazyHashOps) VerifyBTCLeg(h, mc, tr, ps []byte, bl uint32, tx string, v uint32, am uint64, mn int) (*xchain.VerifiedBTCLeg, error) {
	l.ensure()
	return l.fakeOps.VerifyBTCLeg(h, mc, tr, ps, bl, tx, v, am, mn)
}
func (l *lazyHashOps) ClaimBTCLeg(lg *xchain.LegLock, k *xchain.Key, f uint64) (string, error) {
	l.ensure()
	return "btc-claim", nil
}
func (l *lazyHashOps) RefundBTCLeg(lg *xchain.LegLock, k *xchain.Key, nl uint32, f uint64) (string, error) {
	return "btc-refund", nil
}
func (l *lazyHashOps) SeqTip() (int64, error)                    { l.ensure(); return l.fakeOps.SeqTip() }
func (l *lazyHashOps) SeqAnchorHeightOf(b string) (int64, error) { l.ensure(); return l.fakeOps.SeqAnchorHeightOf(b) }
func (l *lazyHashOps) SeqBlockHashOfTx(t string) (string, error) { return "seq-block-hash", nil }
func (l *lazyHashOps) SeqFeeRate(a string) (uint64, bool)        { return 50_000_000_000, true }
func (l *lazyHashOps) LockSEQLeg(a, b []byte, c, d string, e uint32) (*xchain.LegLock, string, error) {
	l.ensure()
	return l.fakeOps.LockSEQLeg(a, b, c, d, e)
}
func (l *lazyHashOps) VerifySEQLeg(h, c, r, ps []byte, sl uint32, tx string, v uint32, am uint64, as string, mn int) (*xchain.VerifiedSEQLeg, error) {
	l.ensure()
	return l.fakeOps.VerifySEQLeg(h, c, r, ps, sl, tx, v, am, as, mn)
}
func (l *lazyHashOps) VerifySeqLegSafe(b string, h int64) (*xchain.AnchorEvidence, error) {
	return &xchain.AnchorEvidence{OK: true, SeqBlockHash: b, BTCLegHeight: h}, nil
}
func (l *lazyHashOps) ClaimSEQLeg(lg *xchain.LegLock, k *xchain.Key, f uint64) (string, error) {
	l.ensure()
	return l.fakeOps.ClaimSEQLeg(lg, k, f)
}
func (l *lazyHashOps) WatchSEQClaim(lg *xchain.LegLock) (string, []byte, error) {
	return l.fakeOps.WatchSEQClaim(lg)
}
func (l *lazyHashOps) InjectSecret(s []byte) error { l.ensure(); return l.fakeOps.InjectSecret(s) }
func (l *lazyHashOps) RefundSEQLeg(lg *xchain.LegLock, k *xchain.Key, nl uint32, f uint64) (string, error) {
	return "seq-refund-raw", nil
}
func (l *lazyHashOps) SeqBroadcast(r string) (string, error) { return l.fakeOps.SeqBroadcast(r) }

func TestReverseHappyPath(t *testing.T) {
	_, net, tp, mp := reverseFixture(t)
	var (
		wg   sync.WaitGroup
		mres *MakerReverseResult
		merr error
	)
	wg.Add(1)
	go func() { defer wg.Done(); mres, merr = RunMakerReverse(mp, net.toMaker, net.makerSend) }()

	tres, terr := RunTakerReverse(tp, net.takerSend, net.takerRecv)
	if terr != nil {
		t.Fatalf("taker: %v", terr)
	}
	wg.Wait()
	if merr != nil {
		t.Fatalf("maker: %v", merr)
	}
	if mres.SeqClaimTxid != "seq-claim" || !mres.Settled {
		t.Fatalf("maker did not claim the asset: %+v", mres)
	}
	if tres.BtcClaimTxid != "btc-claim" {
		t.Fatalf("taker did not claim BTC: %+v", tres)
	}
	if string(tres.Secret) != string(mres.Secret) {
		t.Fatalf("taker learned the wrong secret")
	}
}

func TestReverseTakerRejectsWrongBtcAmount(t *testing.T) {
	_, net, tp, mp := reverseFixture(t)
	mp.BtcAmount = 24_000 // maker offers fewer sats than the signed offer promised

	go func() { _, _ = RunMakerReverse(mp, net.toMaker, net.makerSend) }()
	res, err := RunTakerReverse(tp, net.takerSend, net.takerRecv)
	if err == nil || !errors.Is(err, ErrXcBadTerms) {
		t.Fatalf("want ErrXcBadTerms, got %v", err)
	}
	if res.SeqLeg != nil {
		t.Fatalf("taker must not fund the asset on mismatched terms")
	}
}

func TestReverseTakerRefundsWithoutMakerClaim(t *testing.T) {
	st, net, tp, mp := reverseFixture(t)
	// The real maker funds BTC and announces, but its anchor gate never passes,
	// so it never claims the asset. The taker funds the asset, watches, and once
	// the SEQ tip passes T_seq refunds it. We drive the tip from a goroutine
	// once the taker's leg is on-chain.
	mp.NewOps = func(secret []byte) (XcOps, error) {
		st.mu.Lock()
		st.makerSecret = secret
		st.mu.Unlock()
		h := sha256.Sum256(secret)
		base := (&fakeOps{st: st, hashH: h[:]}).withSecret(secret)
		return &anchorFailOps{fakeOps: base}, nil
	}
	mp.Timing.AnchorWait = 50 * time.Millisecond
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = RunMakerReverse(mp, net.toMaker, net.makerSend) }()

	go func() {
		// Wait until the taker's asset leg exists, then push the SEQ tip past
		// T_seq (seqTip 8000 + delta 240).
		for i := 0; i < 400; i++ {
			st.mu.Lock()
			funded := st.seqRefunded // set only after a refund; use a leg marker instead
			_ = funded
			st.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			if i == 20 {
				st.mu.Lock()
				st.seqTip = int64(8000 + 240 + 1)
				st.mu.Unlock()
			}
		}
	}()

	res, err := RunTakerReverse(tp, net.takerSend, net.takerRecv)
	wg.Wait()
	if err == nil || !errors.Is(err, ErrXcRefunded) {
		t.Fatalf("want ErrXcRefunded, got %v", err)
	}
	if res.SeqRefundTx != "seq-refund" {
		t.Fatalf("taker asset refund not broadcast: %+v", res)
	}
}

// TestResumeMakerForwardSettles proves a maker that "restarted" (only persisted
// legs/keys, no live courier) still claims the BTC leg when the taker's SEQ
// claim reveals the secret on-chain.
func TestResumeMakerForwardSettles(t *testing.T) {
	secret := make([]byte, 32)
	secret[0] = 9
	h := sha256.Sum256(secret)
	st := &fakeChainState{btcTip: 1000, seqTip: 5000, btcConfs: map[string]int{"btc-htlc": 3}, seqClaimedBy: secret}
	ops := (&fakeOps{st: st, hashH: h[:]}).withSecret(secret)
	res, err := ResumeMakerForward(MakerForwardResumeParams{
		Ops:          ops,
		BtcLeg:       &xchain.LegLock{Script: []byte("btc"), Funded: &xchain.FundedHTLC{TxID: "btc-htlc", Vout: 0, Amount: 25000}, Locktime: 1100},
		SeqLeg:       &xchain.LegLock{Script: []byte("seq"), Funded: &xchain.FundedHTLC{TxID: "seq-htlc", Vout: 1, Amount: 5000000, AssetID: testAsset}, Locktime: 5240},
		BtcClaimKey:  mustKey(t),
		SeqRefundKey: mustKey(t),
		HashH:        h[:],
		BtcLocktime:  1100,
		SeqLocktime:  5240,
		AssetHex:     testAsset,
		BtcAmount:    25000,
		SeqAmount:    5000000,
		Timing:       XcTiming{Poll: 2 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if !res.Settled || res.BtcClaimTxid != "btc-claim" {
		t.Fatalf("resume did not settle: %+v", res)
	}
	if string(res.Secret) != string(secret) {
		t.Fatalf("resume learned the wrong secret")
	}
}

// TestResumeMakerForwardRefunds proves a maker resume refunds the SEQ leg when
// T_seq has passed with no taker claim.
func TestResumeMakerForwardRefunds(t *testing.T) {
	h := sha256.Sum256([]byte("nobody-claims"))
	st := &fakeChainState{btcTip: 1000, seqTip: 5241, btcConfs: map[string]int{}} // seqTip already past T_seq
	ops := &fakeOps{st: st, hashH: h[:]}
	res, err := ResumeMakerForward(MakerForwardResumeParams{
		Ops:          ops,
		BtcLeg:       &xchain.LegLock{Script: []byte("btc"), Funded: &xchain.FundedHTLC{TxID: "btc-htlc", Vout: 0, Amount: 25000}, Locktime: 1100},
		SeqLeg:       &xchain.LegLock{Script: []byte("seq"), Funded: &xchain.FundedHTLC{TxID: "seq-htlc", Vout: 1, Amount: 5000000, AssetID: testAsset}, Locktime: 5240},
		BtcClaimKey:  mustKey(t),
		SeqRefundKey: mustKey(t),
		HashH:        h[:],
		BtcLocktime:  1100,
		SeqLocktime:  5240,
		AssetHex:     testAsset,
		BtcAmount:    25000,
		SeqAmount:    5000000,
		Timing:       XcTiming{Poll: 2 * time.Millisecond},
	})
	if err == nil || !errors.Is(err, ErrXcRefunded) {
		t.Fatalf("want ErrXcRefunded, got %v", err)
	}
	if res.SeqRefundTx != "seq-refund" {
		t.Fatalf("resume did not refund: %+v", res)
	}
}
