// Command seqob-maker is the long-running MAKER participant for the SeqOB
// order-book DEX. It is just one participant (anyone can run it the same way):
// it posts a signed resting offer to the relay over WebSocket, then settles each
// lift by reusing the PROVEN Ocean settlement (wallet.Service.CompleteSwap, now
// blind-aware) via the shared internal/seqob/client primitives. Confidential is
// opt-in: a confidential offer publishes a blinding pubkey and settles blinded;
// an explicit offer omits it and settles explicit. The relay never decrypts the
// couriered swap messages; it only routes ciphertext.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/gorilla/websocket"
	"github.com/thanhpk/randstr"
	"google.golang.org/protobuf/encoding/protojson"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/core/application"
	"github.com/aejkcs50/seqdex/daemon/internal/core/ports"
	oceanwallet "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/ocean-wallet"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/client"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/offer"
	"github.com/aejkcs50/seqdex/daemon/pkg/seqnet"
	"github.com/aejkcs50/seqdex/daemon/pkg/swap"
)

var jsonMarshal = protojson.MarshalOptions{UseProtoNames: true}
var jsonUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

func main() {
	relay := flag.String("relay", "http://127.0.0.1:9955", "relay base URL")
	ocean := flag.String("ocean", "127.0.0.1:18000", "ocean wallet endpoint")
	nodeRPC := flag.String("node-rpc", "", "Sequentia node RPC URL (for the open fee market)")
	account := flag.String("account", "", "Ocean account that holds the OFFER asset (and funds the fee)")
	makerPriv := flag.String("maker-priv", "", "maker offer/identity + E2E key (32-byte hex); generated if empty")
	base := flag.String("base", "gold", "base asset id")
	quote := flag.String("quote", "usdx", "quote asset id")
	side := flag.String("side", "sell", "maker side: sell|buy (sells/buys the base)")
	baseAmt := flag.Uint64("base-amount", 100, "base size (base atoms)")
	quoteAmt := flag.Uint64("quote-amount", 45, "quote size (quote atoms)")
	feeAsset := flag.String("fee-asset", "", "preferred fee asset hint (any-asset fee market)")
	expiry := flag.Duration("expiry", time.Hour, "time until the offer expires")
	minAnchor := flag.Uint("min-anchor-depth", 0, "Bitcoin-anchor confs before FILLED (0 = 0-conf tolerant)")
	confidential := flag.Bool("confidential", true, "post a confidential offer (blinded settlement); false = explicit")
	msats := flag.Uint64("msats-per-byte", 110, "network fee rate (milli-sat/vByte); raise if the node rejects for low fee")
	offerID := flag.String("offer-id", "", "offer id (random 16-byte hex if empty)")
	mode := flag.String("mode", "samechain", "settlement mode: samechain | cross (cross = BTC<->asset HTLC over the order book; quote is forced to the BTC sentinel, base is the asset)")
	flag.Parse()

	if *account == "" {
		fatal("-account is required (the Ocean account holding the offer asset)")
	}

	makerKey := loadOrGenKey(*makerPriv)
	makerPubHex := hex.EncodeToString(makerKey.PubKey().SerializeCompressed())
	ctx := context.Background()

	// Reuse the proven Ocean settlement exactly like the daemon.
	w, err := oceanwallet.NewService(*ocean)
	if err != nil {
		fatal("connect ocean wallet %q: %v", *ocean, err)
	}
	svc, err := application.NewWalletService(w, *nodeRPC)
	if err != nil {
		fatal("wallet service: %v", err)
	}
	defer svc.Close()
	net := svc.Network()

	// Derive the maker's receive address; publish its blinding pubkey only for a
	// confidential offer so the taker mirrors the maker's confidentiality posture.
	addrs, err := svc.Account().DeriveAddresses(ctx, *account, 1)
	if err != nil || len(addrs) == 0 {
		fatal("derive recv address for account %q: %v", *account, err)
	}
	recvAddr := addrs[0]
	blindingPub := ""
	if *confidential {
		info, err := seqnet.FromConfidential(recvAddr, &net)
		if err != nil {
			fatal("parse recv address: %v", err)
		}
		blindingPub = hex.EncodeToString(info.BlindingKey)
	}

	var o *seqobv1.Offer
	if strings.ToLower(*mode) == "cross" {
		o = buildCrossOffer(*base, *side, *baseAmt, *quoteAmt, *feeAsset,
			*expiry, uint32(*minAnchor), recvAddr, makerPubHex, *offerID)
	} else {
		o = buildOffer(*base, *quote, *side, *baseAmt, *quoteAmt, *feeAsset,
			*expiry, uint32(*minAnchor), recvAddr, blindingPub, *offerID)
	}
	if err := offer.SignOffer(o, makerKey); err != nil {
		fatal("sign offer: %v", err)
	}

	// Maker-only backend: the LiveWallet only calls ResponderComplete, which uses
	// CompleteSwapFn. Wire it to the blind-aware CompleteSwap; the taker-side seams
	// are unused here (dummy key, never exercised).
	rb := client.NewRealBackend(&net, makerKey.Serialize(), makerKey.Serialize())
	rb.CompleteSwapFn = func(req *seqdexv1.SwapRequest, blind bool) (string, []swap.UnblindedInput, error) {
		signedPSET, utxos, _, err := svc.CompleteSwap(*account, swapReqAdapter{req}, *msats, true, blind)
		if err != nil {
			return "", nil, err
		}
		return signedPSET, utxosToSwapUnblinded(utxos), nil
	}
	maker := &client.Maker{
		Wallet: &client.LiveWallet{Backend: rb, MakerOutputsConfidential: *confidential},
		// Bind every co-sign to this signed offer (asset legs, price floor,
		// remaining size) so a malicious taker cannot drain the maker.
		Offer: o,
	}

	// Connect, submit the offer (this registers the conn for live lifts), then
	// serve lifts until killed.
	wsURL := "ws" + strings.TrimPrefix(*relay, "http") + "/v1/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		fatal("dial ws %s: %v", wsURL, err)
	}
	defer conn.Close()

	writeWS(conn, &seqobv1.To{Msg: &seqobv1.To_OfferSubmit{OfferSubmit: o}})
	fmt.Printf("seqob-maker up: posted %s offer %s by maker %s\n", *side, o.GetOfferId(), makerPubHex)
	fmt.Printf("  pair %s/%s  give %d %s  want %d %s  confidential=%v  fee-rate=%d msat/vB\n",
		o.GetPair().GetBaseAsset(), o.GetPair().GetQuoteAsset(), o.GetOfferAmount(), o.GetOfferAsset(), o.GetWantAmount(), o.GetWantAsset(), *confidential, *msats)
	fmt.Printf("  taker lifts with: -offer-id %s -maker-pubkey %s\n", o.GetOfferId(), makerPubHex)

	serve(conn, maker, makerKey)
}

// serve is the maker's single-goroutine event loop: derive a per-lift E2E key on
// lift_requested, then on the taker's couriered SwapRequest run the responder and
// courier back the SwapAccept. A later swap_msg for the same session is the
// taker's SwapComplete (the swap settled).
func serve(conn *websocket.Conn, maker *client.Maker, makerKey *btcec.PrivateKey) {
	crypters := make(map[string]*client.Crypter)
	accepted := make(map[string]bool)
	for {
		var from seqobv1.From
		_, data, err := conn.ReadMessage()
		if err != nil {
			fatal("ws read: %v", err)
		}
		if err := jsonUnmarshal.Unmarshal(data, &from); err != nil {
			continue
		}
		switch {
		case from.GetLiftRequested() != nil:
			lr := from.GetLiftRequested()
			cr, err := client.NewMakerCrypterFromLift(makerKey, lr.GetTakerSessionPubkey())
			if err != nil {
				fmt.Printf("lift %s: crypter error: %v\n", lr.GetSessionId(), err)
				continue
			}
			crypters[lr.GetSessionId()] = cr
			fmt.Printf("lift requested: session %s offer %s take %d\n",
				lr.GetSessionId(), lr.GetOfferId(), lr.GetTakeAmount())

		case from.GetSwapMsg() != nil:
			sm := from.GetSwapMsg()
			sid := sm.GetSessionId()
			if accepted[sid] {
				fmt.Printf("session %s: SWAP SETTLED (taker couriered SwapComplete)\n", sid)
				continue
			}
			cr := crypters[sid]
			if cr == nil {
				fmt.Printf("session %s: swap_msg before lift_requested; ignoring\n", sid)
				continue
			}
			sealedAccept, err := maker.HandleRequest(sm.GetCiphertext(), cr)
			if err != nil {
				fmt.Printf("session %s: complete swap failed: %v\n", sid, err)
				continue
			}
			writeWS(conn, &seqobv1.To{Msg: &seqobv1.To_SwapMsg{SwapMsg: &seqobv1.SwapMsg{SessionId: sid, Ciphertext: sealedAccept}}})
			accepted[sid] = true
			fmt.Printf("session %s: couriered SwapAccept (%d bytes); awaiting taker broadcast\n", sid, len(sealedAccept))

		case from.GetOrderStatus() != nil:
			st := from.GetOrderStatus()
			fmt.Printf("order %s status=%s active=%d txid=%s\n",
				st.GetOfferId(), st.GetStatus(), st.GetActiveAmount(), st.GetSettleTxid())

		case from.GetError() != nil:
			e := from.GetError()
			fmt.Printf("relay error %d: %s\n", e.GetCode(), e.GetMessage())
		}
	}
}

func buildOffer(base, quote, side string, baseAmt, quoteAmt uint64, feeAsset string,
	expiry time.Duration, minAnchor uint32, recvAddr, blindingPub, id string) *seqobv1.Offer {
	o := &seqobv1.Offer{
		OfferId:        orDefault(id, randstr.Hex(16)),
		SchemaVersion:  1,
		Pair:           &seqobv1.AssetPair{BaseAsset: base, QuoteAsset: quote},
		BaseAmount:     baseAmt,
		AllowPartial:   true,
		CreatedAtUnix:  uint64(time.Now().Unix()),
		ExpiresAtUnix:  uint64(time.Now().Add(expiry).Unix()),
		FeeAssetHint:   feeAsset,
		MinAnchorDepth: minAnchor,
		Settlement: &seqobv1.Offer_SameChain{SameChain: &seqobv1.SameChainTerms{
			MakerRecvAddress: recvAddr,
			MakerBlindingPub: blindingPub,
		}},
	}
	switch strings.ToLower(side) {
	case "sell":
		o.TradeDir = seqobv1.TradeDir_TRADE_DIR_SELL
		o.OfferAsset, o.OfferAmount = base, baseAmt
		o.WantAsset, o.WantAmount = quote, quoteAmt
	case "buy":
		o.TradeDir = seqobv1.TradeDir_TRADE_DIR_BUY
		o.OfferAsset, o.OfferAmount = quote, quoteAmt
		o.WantAsset, o.WantAmount = base, baseAmt
	default:
		fatal("side must be sell or buy")
	}
	return o
}

// buildCrossOffer builds a CROSS-CHAIN (BTC<->asset) order-book offer: pair is
// base=asset, quote=the BTC sentinel. The resting CrossChainTerms keys/locktime are
// ADVISORY (display + a stable signed commitment from the maker identity key); the
// load-bearing HTLC keys and CLTVs are minted per-lift over the E2E courier (Phase 2).
// A SELL gives the asset for BTC (taker pays BTC; direction BTC_TO_ASSET); a BUY gives
// BTC for the asset (taker sells the asset; direction ASSET_TO_BTC).
func buildCrossOffer(asset, side string, assetAmt, btcAmt uint64, feeAsset string,
	expiry time.Duration, minAnchor uint32, recvAddr, makerPubHex, id string) *seqobv1.Offer {
	isSell := strings.ToLower(side) == "sell"
	direction := offer.DirAssetToBTC
	if isSell {
		direction = offer.DirBTCToAsset
	}
	o := &seqobv1.Offer{
		OfferId:        orDefault(id, randstr.Hex(16)),
		SchemaVersion:  1,
		Pair:           &seqobv1.AssetPair{BaseAsset: asset, QuoteAsset: offer.BTCSentinel},
		BaseAmount:     assetAmt,
		AllowPartial:   false, // cross-chain lifts are whole-HTLC; no partial fills (Phase 1)
		CreatedAtUnix:  uint64(time.Now().Unix()),
		ExpiresAtUnix:  uint64(time.Now().Add(expiry).Unix()),
		FeeAssetHint:   feeAsset,
		MinAnchorDepth: minAnchor,
		Settlement: &seqobv1.Offer_CrossChain{CrossChain: &seqobv1.CrossChainTerms{
			BtcSentinel:      offer.BTCSentinel,
			MakerRecvAddress: recvAddr,
			MakerClaimPub:    makerPubHex,
			MakerRefundPub:   makerPubHex,
			MakerLegLocktime: 144,
			Direction:        direction,
		}},
	}
	if isSell {
		o.TradeDir = seqobv1.TradeDir_TRADE_DIR_SELL
		o.OfferAsset, o.OfferAmount = asset, assetAmt
		o.WantAsset, o.WantAmount = offer.BTCSentinel, btcAmt
	} else {
		o.TradeDir = seqobv1.TradeDir_TRADE_DIR_BUY
		o.OfferAsset, o.OfferAmount = offer.BTCSentinel, btcAmt
		o.WantAsset, o.WantAmount = asset, assetAmt
	}
	return o
}

// swapReqAdapter adapts a seqob *seqdexv1.SwapRequest to ports.SwapRequest. The
// seqob request carries no fee asset/amount (the open fee market is resolved
// inside CompleteSwap), so those return zero values; *seqdexv1.UnblindedInput
// already satisfies ports.UnblindedInput.
type swapReqAdapter struct{ r *seqdexv1.SwapRequest }

func (a swapReqAdapter) GetId() string          { return a.r.GetId() }
func (a swapReqAdapter) GetAssetP() string      { return a.r.GetAssetP() }
func (a swapReqAdapter) GetAmountP() uint64     { return a.r.GetAmountP() }
func (a swapReqAdapter) GetAssetR() string      { return a.r.GetAssetR() }
func (a swapReqAdapter) GetAmountR() uint64     { return a.r.GetAmountR() }
func (a swapReqAdapter) GetTransaction() string { return a.r.GetTransaction() }
func (a swapReqAdapter) GetFeeAsset() string    { return "" }
func (a swapReqAdapter) GetFeeAmount() uint64   { return 0 }
func (a swapReqAdapter) GetUnblindedInputs() []ports.UnblindedInput {
	src := a.r.GetUnblindedInputs()
	out := make([]ports.UnblindedInput, 0, len(src))
	for _, u := range src {
		out = append(out, u)
	}
	return out
}

// utxosToSwapUnblinded converts the maker's CompleteSwap-selected utxos to the
// swap.UnblindedInput list for the SwapAccept, using the same index convention as
// the proven trade path (trading.go).
func utxosToSwapUnblinded(utxos []ports.Utxo) []swap.UnblindedInput {
	ins := make([]swap.UnblindedInput, 0, len(utxos))
	for i, u := range utxos {
		ins = append(ins, swap.UnblindedInput{
			Index:         uint32(i),
			Asset:         u.GetAsset(),
			Amount:        u.GetValue(),
			AssetBlinder:  u.GetAssetBlinder(),
			AmountBlinder: u.GetValueBlinder(),
		})
	}
	return ins
}

func loadOrGenKey(hexKey string) *btcec.PrivateKey {
	if hexKey == "" {
		k, err := btcec.NewPrivateKey()
		if err != nil {
			fatal("gen key: %v", err)
		}
		fmt.Printf("generated maker key: priv=%s pub=%s\n",
			hex.EncodeToString(k.Serialize()), hex.EncodeToString(k.PubKey().SerializeCompressed()))
		return k
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil || len(b) != 32 {
		fatal("-maker-priv must be 32-byte hex")
	}
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}

func writeWS(c *websocket.Conn, to *seqobv1.To) {
	b, err := jsonMarshal.Marshal(to)
	if err != nil {
		fatal("marshal To: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		fatal("ws write: %v", err)
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func fatal(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
