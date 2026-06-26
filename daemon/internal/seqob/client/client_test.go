package client

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"

	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
)

func sampleOffer() *seqobv1.Offer {
	return &seqobv1.Offer{
		OfferId:      "aaaa",
		Pair:         &seqobv1.AssetPair{BaseAsset: "gold", QuoteAsset: "usdx"},
		TradeDir:     seqobv1.TradeDir_TRADE_DIR_SELL,
		BaseAmount:   100,
		OfferAmount:  100,
		OfferAsset:   "gold",
		WantAmount:   45,
		WantAsset:    "usdx",
		AllowPartial: true,
		Settlement:   &seqobv1.Offer_SameChain{SameChain: &seqobv1.SameChainTerms{MakerRecvAddress: "addr"}},
	}
}

// TestEndToEndEncryptedLift drives the whole Phase-1 message flow over the E2E
// crypter, with the relay modeled as an opaque byte courier: taker Propose ->
// maker HandleRequest -> taker Finalize, all on sealed bytes.
func TestEndToEndEncryptedLift(t *testing.T) {
	takerKey, _ := btcec.NewPrivateKey()
	makerKey, _ := btcec.NewPrivateKey()

	takerCrypter, err := NewCrypter(takerKey, makerKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	makerCrypter, err := NewCrypter(makerKey, takerKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}

	taker := &Taker{Wallet: &StubWallet{Name: "taker"}}
	maker := &Maker{Wallet: &StubWallet{Name: "maker"}}
	o := sampleOffer()

	// Taker proposes a 50-base partial lift; the courier carries only ciphertext.
	sealedReq, req, err := taker.Propose(o, 50, "gold", takerCrypter)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if req.GetAmountR() != 50 || req.GetAssetR() != "gold" {
		t.Fatalf("unexpected proposer receive leg: %+v", req)
	}
	if req.GetAmountP() == 0 || req.GetAssetP() != "usdx" {
		t.Fatalf("unexpected proposer pay leg: %+v", req)
	}

	// The relay must not be able to read the sealed bytes (sanity: they differ
	// from any plaintext and are AEAD-protected; a wrong key fails to open).
	wrongKey, _ := btcec.NewPrivateKey()
	relayCrypter, _ := NewCrypter(wrongKey, makerKey.PubKey())
	if _, err := relayCrypter.Open(sealedReq); err == nil {
		t.Fatalf("relay (wrong key) must NOT be able to open the courier payload")
	}

	// Maker handles the sealed request and seals an accept back.
	sealedAccept, err := maker.HandleRequest(sealedReq, makerCrypter)
	if err != nil {
		t.Fatalf("maker handle: %v", err)
	}

	// Taker finalizes -> SwapComplete + txid.
	sealedComplete, txid, err := taker.Finalize(sealedAccept, takerCrypter)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected a txid")
	}
	if len(sealedComplete) == 0 {
		t.Fatalf("expected sealed complete")
	}
}

func TestProRataRounding(t *testing.T) {
	o := sampleOffer() // 100 base -> offer 100 gold, want 45 usdx
	recv, pay, err := proRata(o, 50)
	if err != nil {
		t.Fatal(err)
	}
	if recv != 50 {
		t.Fatalf("recv = %d, want 50", recv)
	}
	// 45*50/100 = 22.5 -> ceil 23 (maker never short-changed).
	if pay != 23 {
		t.Fatalf("pay = %d, want 23 (ceil of 22.5)", pay)
	}
}

func TestCrypterRoundTrip(t *testing.T) {
	a, _ := btcec.NewPrivateKey()
	b, _ := btcec.NewPrivateKey()
	ca, _ := NewCrypter(a, b.PubKey())
	cb, _ := NewCrypter(b, a.PubKey())
	msg := []byte("confidential swap payload")
	sealed, err := ca.Seal(msg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := cb.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(msg) {
		t.Fatalf("round trip mismatch: %q", out)
	}
}

// TestMakerCrypterFromLift proves the reusable maker seam: a maker derives the
// E2E key from its OFFER key + the taker's session pubkey (as delivered in
// From.lift_requested) and completes the handshake, with no shared secret beyond
// what the relay couriered.
func TestMakerCrypterFromLift(t *testing.T) {
	makerOfferKey, _ := btcec.NewPrivateKey() // the maker's offer (signing) key
	takerSession, _ := btcec.NewPrivateKey()  // the taker's ephemeral session key

	// Taker seals to the maker's offer pubkey (known from the offer).
	takerCrypter, err := NewCrypter(takerSession, makerOfferKey.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	// Maker derives the matching key purely from lift_requested fields.
	makerCrypter, err := NewMakerCrypterFromLift(makerOfferKey, takerSession.PubKey().SerializeCompressed())
	if err != nil {
		t.Fatalf("NewMakerCrypterFromLift: %v", err)
	}

	taker := &Taker{Wallet: &StubWallet{Name: "taker"}}
	maker := &Maker{Wallet: &StubWallet{Name: "maker"}}
	o := sampleOffer()

	sealedReq, _, err := taker.Propose(o, 50, "gold", takerCrypter)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	sealedAcc, err := maker.HandleRequest(sealedReq, makerCrypter)
	if err != nil {
		t.Fatalf("maker handle (derived crypter): %v", err)
	}
	_, txid, err := taker.Finalize(sealedAcc, takerCrypter)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if txid == "" {
		t.Fatalf("expected a txid")
	}
}

func TestLiveWalletNotWired(t *testing.T) {
	var w LiveWallet
	if _, err := w.ProposerBuildRequest(sampleOffer(), 50, "gold"); err == nil {
		t.Fatalf("expected not-wired error from unconfigured LiveWallet")
	}
}
