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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
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
	// Cross-mode settlement wiring (pkg/xchain, no Ocean needed): the SEQ leg is
	// funded from the Sequentia NODE wallet and the BTC leg is claimed into the
	// bitcoind wallet — the same reserves the RFQ maker uses.
	btcRPCURL := flag.String("btc-rpc", "", "cross: bitcoind RPC URL http://user:pass@host:port (required for -mode cross)")
	btcWallet := flag.String("btc-wallet", "", "cross: bitcoind wallet holding/receiving the BTC side")
	btcChainName := flag.String("btc-chain", "testnet4", "cross: parent chain params: testnet4 | regtest")
	xseqRPCURL := flag.String("xseq-rpc", "", "cross: Sequentia node RPC URL http://user:pass@host:port (required for -mode cross)")
	xseqWallet := flag.String("xseq-wallet", "", "cross: Sequentia node wallet funding the asset leg")
	btcDelta := flag.Uint("btc-locktime-delta", 100, "cross: T_btc = parent tip + this (longer leg in time; ~16h)")
	seqDelta := flag.Uint("seq-locktime-delta", 240, "cross: T_seq = SEQ tip + this (shorter leg in time; ~2h — must cover the taker's real parent confirmation, or takers refuse the terms)")
	minBTCConf := flag.Int("min-btc-conf", 1, "cross: confirmations required on the taker's BTC leg (1 = testnet-grade; confirmation depth, not anchoring, protects the maker's BTC side — raise for real value)")
	spendFee := flag.Uint64("spend-fee", 1000, "cross: HTLC spend fee target in native sats (converted per-asset via the fee market)")
	xstateDir := flag.String("xstate-dir", "xmaker-sessions", "cross: directory for per-lift session state (keys/legs; the recovery material)")
	resume := flag.Bool("resume", false, "cross: instead of serving, finish every non-terminal session in -xstate-dir (post-restart on-chain claim/refund) and exit")
	flag.Parse()

	// Cross resume needs no maker key or offer: it drives on-chain settlement
	// from persisted per-session keys. Handle it before the key/offer setup.
	if strings.ToLower(*mode) == "cross" && *resume {
		resumeCrossSessions(*xstateDir, *btcRPCURL, *btcWallet, *btcChainName, *xseqRPCURL, *xseqWallet, *spendFee)
		return
	}

	cross := strings.ToLower(*mode) == "cross"
	if !cross && *account == "" {
		fatal("-account is required (the Ocean account holding the offer asset)")
	}

	makerKey := loadOrGenKey(*makerPriv)
	makerPubHex := hex.EncodeToString(makerKey.PubKey().SerializeCompressed())
	ctx := context.Background()

	if cross {
		runCrossMaker(crossMakerConfig{
			relay: *relay, makerKey: makerKey, makerPubHex: makerPubHex,
			asset: *base, side: *side, assetAmt: *baseAmt, btcAmt: *quoteAmt,
			feeAsset: *feeAsset, expiry: *expiry, minAnchor: uint32(*minAnchor), offerID: *offerID,
			btcRPCURL: *btcRPCURL, btcWallet: *btcWallet, btcChainName: *btcChainName,
			seqRPCURL: *xseqRPCURL, seqWallet: *xseqWallet,
			btcDelta: uint32(*btcDelta), seqDelta: uint32(*seqDelta),
			minBTCConf: *minBTCConf, spendFee: *spendFee, stateDir: *xstateDir,
		})
		return
	}

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

	o := buildOffer(*base, *quote, *side, *baseAmt, *quoteAmt, *feeAsset,
		*expiry, uint32(*minAnchor), recvAddr, blindingPub, *offerID)
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

// resumeCrossSessions finishes every non-terminal cross session persisted in
// dir after a restart: it reconstructs the legs/keys from each <sid>.json and
// re-enters the on-chain settle loop (claim on the taker's reveal, or refund
// after the CLTV). This is the 2f recovery path — a mid-swap crash or courier
// timeout no longer strands the maker's asset leg. FORWARD sessions only for
// now (the direction served today); reverse resume lands with reverse serving.
func resumeCrossSessions(dir, btcRPCURL, btcWallet, btcChainName, seqRPCURL, seqWallet string, spendFee uint64) {
	if btcRPCURL == "" || seqRPCURL == "" {
		fatal("-resume requires -btc-rpc and -xseq-rpc")
	}
	btcRPC, err := rpcFromURL(btcRPCURL)
	if err != nil {
		fatal("-btc-rpc: %v", err)
	}
	seqRPC, err := rpcFromURL(seqRPCURL)
	if err != nil {
		fatal("-xseq-rpc: %v", err)
	}
	params, err := xchain.BitcoinChainParams(btcChainName)
	if err != nil {
		fatal("-btc-chain: %v", err)
	}
	btcChain := xchain.NewBitcoinChain(btcRPC, btcWallet, params)
	seqChain := xchain.NewChain(seqRPC, seqWallet)

	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		fatal("read -xstate-dir %s: %v", dir, err)
	}
	var pending []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			pending = append(pending, e.Name())
		}
	}
	if len(pending) == 0 {
		fmt.Printf("no cross sessions to resume in %s\n", dir)
		return
	}
	fmt.Printf("resuming %d cross session(s) from %s\n", len(pending), dir)

	var wg sync.WaitGroup
	for _, name := range pending {
		path := filepath.Join(dir, name)
		raw, rerr := ioutil.ReadFile(path)
		if rerr != nil {
			fmt.Printf("%s: read: %v\n", name, rerr)
			continue
		}
		var st xmakerSessionState
		if jerr := json.Unmarshal(raw, &st); jerr != nil {
			fmt.Printf("%s: parse: %v\n", name, jerr)
			continue
		}
		if st.Settled || st.SeqRefundTx != "" || st.BtcRefundTx != "" {
			fmt.Printf("%s: already terminal (settled=%v seqrefund=%s btcrefund=%s); skipping\n", name, st.Settled, st.SeqRefundTx, st.BtcRefundTx)
			continue
		}
		if st.Direction == "reverse" {
			// Reverse resume (maker holds the secret; claim the taker's SEQ leg or
			// refund our BTC leg after T_btc) is not wired yet; surface it so an
			// operator can act rather than silently leaving funds.
			fmt.Printf("%s: reverse session — resume not yet implemented; state has the secret + keys for manual recovery (btc_leg %s, T_btc %d)\n",
				name, st.BtcLegTxid, st.BtcLocktime)
			continue
		}
		if st.SeqLegTxid == "" || st.SeqLegScriptHex == "" || st.BtcClaimPrivHex == "" || st.SeqRefundPrivHex == "" {
			fmt.Printf("%s: no locked SEQ leg / keys to resume (session died before lock); nothing on-chain to settle\n", name)
			continue
		}
		p, perr := resumeParamsFromState(&st, btcChain, seqChain, spendFee, dir)
		if perr != nil {
			fmt.Printf("%s: reconstruct: %v\n", name, perr)
			continue
		}
		wg.Add(1)
		go func(name string, p client.MakerForwardResumeParams) {
			defer wg.Done()
			fmt.Printf("%s: resuming on-chain settle loop\n", name)
			res, rerr := client.ResumeMakerForward(p)
			if rerr != nil {
				fmt.Printf("%s: resume ended: %v\n", name, rerr)
				if res != nil && res.SeqRefundTx != "" {
					fmt.Printf("%s: SEQ leg refunded in %s\n", name, res.SeqRefundTx)
				}
				return
			}
			fmt.Printf("%s: RESUMED + SETTLED: BTC claimed in %s\n", name, res.BtcClaimTxid)
		}(name, p)
	}
	wg.Wait()
	fmt.Println("resume pass complete")
}

// resumeParamsFromState rebuilds the resume params (legs, keys, swap) from a
// persisted session record.
func resumeParamsFromState(st *xmakerSessionState, btcChain *xchain.BitcoinChain, seqChain *xchain.Chain,
	spendFee uint64, dir string) (client.MakerForwardResumeParams, error) {
	var zero client.MakerForwardResumeParams
	hashH, err := hex.DecodeString(st.HashHex)
	if err != nil || len(hashH) != 32 {
		return zero, fmt.Errorf("bad hash_hex")
	}
	btcClaimBytes, err := hex.DecodeString(st.BtcClaimPrivHex)
	if err != nil {
		return zero, fmt.Errorf("bad btc_claim_priv_hex")
	}
	seqRefundBytes, err := hex.DecodeString(st.SeqRefundPrivHex)
	if err != nil {
		return zero, fmt.Errorf("bad seq_refund_priv_hex")
	}
	btcScript, err := hex.DecodeString(st.BtcLegScriptHex)
	if err != nil {
		return zero, fmt.Errorf("bad btc_leg_script_hex")
	}
	seqScript, err := hex.DecodeString(st.SeqLegScriptHex)
	if err != nil {
		return zero, fmt.Errorf("bad seq_leg_script_hex")
	}
	sid := st.SessionID
	return client.MakerForwardResumeParams{
		Ops: &client.LiveXcOps{
			Swap: xchain.NewSwapBitcoin(btcChain, seqChain, xchain.NewHashLockFromHash(hashH)),
			BTC:  btcChain, SEQ: seqChain,
		},
		BtcLeg: &xchain.LegLock{
			Script:   btcScript,
			Funded:   &xchain.FundedHTLC{TxID: st.BtcLegTxid, Vout: st.BtcLegVout, Amount: st.BtcLegAmount},
			Locktime: st.BtcLocktime,
		},
		SeqLeg: &xchain.LegLock{
			Script:   seqScript,
			Funded:   &xchain.FundedHTLC{TxID: st.SeqLegTxid, Vout: st.SeqLegVout, Amount: st.SeqLegAmount, AssetID: st.SeqLegAsset},
			Locktime: st.SeqLocktime,
		},
		BtcClaimKey:  xchain.KeyFromBytes(btcClaimBytes),
		SeqRefundKey: xchain.KeyFromBytes(seqRefundBytes),
		HashH:        hashH,
		BtcLocktime:  st.BtcLocktime,
		SeqLocktime:  st.SeqLocktime,
		AssetHex:     st.SeqLegAsset,
		BtcAmount:    st.BtcLegAmount,
		SeqAmount:    st.SeqLegAmount,
		SpendFeeSats: spendFee,
		OnUpdate: func(r *client.MakerForwardResult) {
			persistXSession(dir, sid, st.OfferID, r)
		},
		Log: func(format string, args ...interface{}) { fmt.Printf("session "+sid+": "+format+"\n", args...) },
	}, nil
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

// wsWriteMu serializes WS writes: cross-mode lift sessions courier from their
// own goroutines and gorilla/websocket allows only one concurrent writer.
var wsWriteMu sync.Mutex

func writeWS(c *websocket.Conn, to *seqobv1.To) {
	b, err := jsonMarshal.Marshal(to)
	if err != nil {
		fatal("marshal To: %v", err)
	}
	wsWriteMu.Lock()
	defer wsWriteMu.Unlock()
	if err := c.WriteMessage(websocket.TextMessage, b); err != nil {
		fatal("ws write: %v", err)
	}
}

// --- Cross-chain (BTC<->asset) maker -----------------------------------------

type crossMakerConfig struct {
	relay        string
	makerKey     *btcec.PrivateKey
	makerPubHex  string
	asset, side  string
	assetAmt     uint64
	btcAmt       uint64
	feeAsset     string
	expiry       time.Duration
	minAnchor    uint32
	offerID      string
	btcRPCURL    string
	btcWallet    string
	btcChainName string
	seqRPCURL    string
	seqWallet    string
	btcDelta     uint32
	seqDelta     uint32
	minBTCConf   int
	spendFee     uint64
	stateDir     string
}

// runCrossMaker posts a cross-chain offer and serves forward lifts with the
// xdriver over pkg/xchain. It needs no Ocean wallet: the SEQ asset leg is
// funded from the Sequentia NODE wallet and the claimed BTC lands in the
// bitcoind wallet — the same reserves the RFQ maker uses (do not re-fund).
func runCrossMaker(cfg crossMakerConfig) {
	sideL := strings.ToLower(cfg.side)
	if sideL != "sell" && sideL != "buy" {
		fatal("-mode cross -side must be sell (taker pays BTC) or buy (taker sells the asset)")
	}
	if cfg.btcRPCURL == "" || cfg.seqRPCURL == "" {
		fatal("-mode cross requires -btc-rpc and -xseq-rpc")
	}
	btcRPC, err := rpcFromURL(cfg.btcRPCURL)
	if err != nil {
		fatal("-btc-rpc: %v", err)
	}
	seqRPC, err := rpcFromURL(cfg.seqRPCURL)
	if err != nil {
		fatal("-xseq-rpc: %v", err)
	}
	params, err := xchain.BitcoinChainParams(cfg.btcChainName)
	if err != nil {
		fatal("-btc-chain: %v", err)
	}
	btcChain := xchain.NewBitcoinChain(btcRPC, cfg.btcWallet, params)
	seqChain := xchain.NewChain(seqRPC, cfg.seqWallet)

	// Sanity: both nodes reachable before we advertise anything.
	if _, err := btcChain.BlockCount(); err != nil {
		fatal("bitcoind unreachable: %v", err)
	}
	if _, err := seqChain.BlockCount(); err != nil {
		fatal("sequentia node unreachable: %v", err)
	}

	// Advisory receive address for the resting offer, from the node wallet.
	var recvAddr string
	if err := seqChain.RPC().Call(&recvAddr, "getnewaddress"); err != nil {
		fatal("getnewaddress on the Sequentia wallet: %v", err)
	}

	o := buildCrossOffer(cfg.asset, cfg.side, cfg.assetAmt, cfg.btcAmt, cfg.feeAsset,
		cfg.expiry, cfg.minAnchor, recvAddr, cfg.makerPubHex, cfg.offerID)
	if err := offer.SignOffer(o, cfg.makerKey); err != nil {
		fatal("sign offer: %v", err)
	}

	if err := os.MkdirAll(cfg.stateDir, 0o700); err != nil {
		fatal("create -xstate-dir %s: %v", cfg.stateDir, err)
	}

	wsURL := "ws" + strings.TrimPrefix(cfg.relay, "http") + "/v1/ws"
	ws := &crossWS{}
	if err := ws.redial(wsURL, o); err != nil {
		fatal("dial ws %s: %v", wsURL, err)
	}
	fmt.Printf("seqob-maker up (CROSS): posted %s offer %s by maker %s\n", cfg.side, o.GetOfferId(), cfg.makerPubHex)
	fmt.Printf("  %d %s <- %d BTC sats  T_btc=+%d T_seq=+%d min-conf=%d\n",
		cfg.assetAmt, cfg.asset, cfg.btcAmt, cfg.btcDelta, cfg.seqDelta, cfg.minBTCConf)
	fmt.Printf("  taker lifts with: seqob-cli xlift -offer-id %s -maker-pubkey %s\n", o.GetOfferId(), cfg.makerPubHex)

	serveCross(ws, wsURL, o, cfg, btcChain, seqChain)
}

// crossWS holds the (re)dialable relay connection: cross sessions run for many
// minutes in their own goroutines, so writes are serialized here and a WS drop
// reconnects instead of killing in-flight ON-CHAIN settlements.
type crossWS struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (w *crossWS) current() *websocket.Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conn
}

func (w *crossWS) write(to *seqobv1.To) error {
	b, err := jsonMarshal.Marshal(to)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn == nil {
		return fmt.Errorf("ws not connected")
	}
	return w.conn.WriteMessage(websocket.TextMessage, b)
}

// redial dials and, when an offer is given, (re)submits it so the relay
// re-registers this connection as the maker's lift route.
func (w *crossWS) redial(wsURL string, o *seqobv1.Offer) error {
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.conn != nil {
		_ = w.conn.Close()
	}
	w.conn = conn
	w.mu.Unlock()
	if o != nil {
		return w.write(&seqobv1.To{Msg: &seqobv1.To_OfferSubmit{OfferSubmit: o}})
	}
	return nil
}

func (w *crossWS) redialLoop(wsURL string, o *seqobv1.Offer) {
	for {
		if err := w.redial(wsURL, o); err == nil {
			fmt.Println("relay reconnected")
			return
		}
		time.Sleep(5 * time.Second)
	}
}

// serveCross is the cross-mode event loop: each lift gets its own goroutine
// running RunMakerForward; the loop routes sealed courier frames to the
// session's inbox. Whole-HTLC discipline: ONE lift in flight at a time, and
// the offer is cancelled after its first settlement (no fill accounting exists
// for cross offers, so serving further lifts would oversell the signed size at
// a stale price; restart the maker to re-quote).
func serveCross(ws *crossWS, wsURL string, o *seqobv1.Offer, cfg crossMakerConfig,
	btcChain *xchain.BitcoinChain, seqChain *xchain.Chain) {
	var mu sync.Mutex
	inboxes := make(map[string]chan []byte)
	inFlight := 0
	filled := false

	refuse := func(sid string, cr *client.Crypter, code, msg string) {
		m := &client.XcMsg{Type: client.XcFail, Code: code, Message: msg}
		if sealed, err := m.Seal(cr); err == nil {
			_ = ws.write(&seqobv1.To{Msg: &seqobv1.To_SwapMsg{SwapMsg: &seqobv1.SwapMsg{SessionId: sid, Ciphertext: sealed}}})
		}
	}

	for {
		conn := ws.current()
		_, data, err := conn.ReadMessage()
		if err != nil {
			mu.Lock()
			done := filled && inFlight == 0
			resubmit := o
			if filled {
				resubmit = nil // never re-advertise a filled offer
			}
			mu.Unlock()
			if done {
				fmt.Println("offer filled and no lift in flight; exiting (restart to re-quote)")
				return
			}
			fmt.Printf("ws read error: %v; reconnecting (in-flight settlements continue on-chain)\n", err)
			ws.redialLoop(wsURL, resubmit)
			continue
		}
		var from seqobv1.From
		if err := jsonUnmarshal.Unmarshal(data, &from); err != nil {
			continue
		}
		switch {
		case from.GetLiftRequested() != nil:
			lr := from.GetLiftRequested()
			sid := lr.GetSessionId()
			cr, err := client.NewMakerCrypterFromLift(cfg.makerKey, lr.GetTakerSessionPubkey())
			if err != nil {
				fmt.Printf("lift %s: crypter error: %v\n", sid, err)
				continue
			}
			mu.Lock()
			busy, done := inFlight > 0, filled
			var in chan []byte
			if !busy && !done {
				inFlight++
				in = make(chan []byte, 8)
				inboxes[sid] = in
			}
			mu.Unlock()
			if done {
				refuse(sid, cr, "offer_filled", "offer already filled; awaiting re-quote")
				continue
			}
			if busy {
				refuse(sid, cr, "busy", "another lift is in flight (whole-HTLC, one at a time)")
				continue
			}
			if lr.GetTakeAmount() != o.GetBaseAmount() {
				fmt.Printf("lift %s: take %d != offer %d (whole-HTLC only); terms will quote the full size\n",
					sid, lr.GetTakeAmount(), o.GetBaseAmount())
			}
			fmt.Printf("cross lift requested: session %s offer %s\n", sid, lr.GetOfferId())

			send := func(sealed []byte) error {
				return ws.write(&seqobv1.To{Msg: &seqobv1.To_SwapMsg{SwapMsg: &seqobv1.SwapMsg{SessionId: sid, Ciphertext: sealed}}})
			}
			logf := func(format string, args ...interface{}) { fmt.Printf("session "+sid+": "+format+"\n", args...) }
			newOpsFromHash := func(hashH []byte) (client.XcOps, error) {
				swp := xchain.NewSwapBitcoin(btcChain, seqChain, xchain.NewHashLockFromHash(hashH))
				return &client.LiveXcOps{Swap: swp, BTC: btcChain, SEQ: seqChain}, nil
			}
			reverse := o.GetCrossChain().GetDirection() == offer.DirAssetToBTC

			go func(sid string, in chan []byte, reverse bool) {
				settled := false
				defer func() {
					mu.Lock()
					inFlight--
					delete(inboxes, sid)
					if settled {
						filled = true
					}
					mu.Unlock()
					if settled {
						cancelOffer(cfg.relay, o, cfg.makerKey)
					}
				}()
				if reverse {
					// BUY: the maker holds the secret and funds the BTC leg first.
					p := client.MakerReverseParams{
						NewOps: func(secret []byte) (client.XcOps, error) {
							swp := xchain.NewSwapBitcoin(btcChain, seqChain, xchain.NewHashLock(secret))
							return &client.LiveXcOps{Swap: swp, BTC: btcChain, SEQ: seqChain}, nil
						},
						Crypter: cr, BtcTip: btcChain.BlockCount, SeqTip: seqChain.BlockCount,
						AssetHex: o.GetPair().GetBaseAsset(), SeqAmount: o.GetWantAmount(), BtcAmount: o.GetOfferAmount(),
						BtcLocktimeDelta: cfg.btcDelta, SeqLocktimeDelta: cfg.seqDelta,
						MinBTCConf: cfg.minBTCConf, SpendFeeSats: cfg.spendFee, Log: logf,
						OnUpdate: func(r *client.MakerReverseResult) { persistXSessionReverse(cfg.stateDir, sid, o.GetOfferId(), r) },
					}
					res, err := client.RunMakerReverse(p, in, send)
					if err != nil {
						fmt.Printf("session %s: reverse cross lift ended: %v\n", sid, err)
						if res != nil && res.BtcRefundTx != "" {
							fmt.Printf("session %s: BTC leg refunded in %s\n", sid, res.BtcRefundTx)
						}
						return
					}
					settled = true
					fmt.Printf("session %s: REVERSE CROSS SWAP SETTLED: claimed the asset in %s\n", sid, res.SeqClaimTxid)
					return
				}
				// SELL (forward): the taker pays BTC and holds the secret.
				p := client.MakerForwardParams{
					NewOps: newOpsFromHash, Crypter: cr,
					BtcTip: btcChain.BlockCount, SeqTip: seqChain.BlockCount,
					AssetHex: o.GetPair().GetBaseAsset(), SeqAmount: o.GetOfferAmount(), BtcAmount: o.GetWantAmount(),
					BtcLocktimeDelta: cfg.btcDelta, SeqLocktimeDelta: cfg.seqDelta,
					MinBTCConf: cfg.minBTCConf, SpendFeeSats: cfg.spendFee, Log: logf,
					OnUpdate: func(r *client.MakerForwardResult) { persistXSession(cfg.stateDir, sid, o.GetOfferId(), r) },
				}
				res, err := client.RunMakerForward(p, in, send)
				if err != nil {
					fmt.Printf("session %s: cross lift ended: %v\n", sid, err)
					if res != nil && res.SeqRefundTx != "" {
						fmt.Printf("session %s: SEQ leg refunded in %s\n", sid, res.SeqRefundTx)
					}
					return
				}
				settled = true
				fmt.Printf("session %s: CROSS SWAP SETTLED: taker claimed the asset, BTC claimed in %s\n",
					sid, res.BtcClaimTxid)
			}(sid, in, reverse)

		case from.GetSwapMsg() != nil:
			sm := from.GetSwapMsg()
			mu.Lock()
			in := inboxes[sm.GetSessionId()]
			mu.Unlock()
			if in == nil {
				fmt.Printf("session %s: swap_msg without a live cross session; ignoring\n", sm.GetSessionId())
				continue
			}
			select {
			case in <- sm.GetCiphertext():
			default:
				fmt.Printf("session %s: inbox full; dropping frame\n", sm.GetSessionId())
			}

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

// xmakerSessionState is the on-disk snapshot of one cross lift: with it, an
// operator can refund the SEQ leg after T_seq or claim the BTC leg with a
// learned secret even if the process died mid-swap.
type xmakerSessionState struct {
	SessionID        string `json:"session_id"`
	OfferID          string `json:"offer_id"`
	Direction        string `json:"direction,omitempty"` // "forward" (sell) | "reverse" (buy)
	HashHex          string `json:"hash_hex,omitempty"`
	BtcClaimPrivHex  string `json:"btc_claim_priv_hex,omitempty"`  // forward: claims taker BTC
	SeqRefundPrivHex string `json:"seq_refund_priv_hex,omitempty"` // forward: refunds our SEQ leg
	// reverse: the maker holds the secret, claims the taker's SEQ leg, refunds its own BTC leg
	SecretForRefundHex string `json:"secret_for_refund_hex,omitempty"` // reverse: same as secret_hex, named for clarity
	SeqClaimPrivHex    string `json:"seq_claim_priv_hex,omitempty"`    // reverse: claims taker SEQ
	BtcRefundPrivHex   string `json:"btc_refund_priv_hex,omitempty"`   // reverse: refunds our BTC leg
	BtcRefundTx        string `json:"btc_refund_tx,omitempty"`         // reverse
	BtcLocktime      uint32 `json:"btc_locktime,omitempty"`
	SeqLocktime      uint32 `json:"seq_locktime,omitempty"`
	BtcLegTxid       string `json:"btc_leg_txid,omitempty"`
	BtcLegVout       uint32 `json:"btc_leg_vout"`
	BtcLegAmount     uint64 `json:"btc_leg_amount,omitempty"`
	BtcLegScriptHex  string `json:"btc_leg_script_hex,omitempty"`
	SeqLegTxid       string `json:"seq_leg_txid,omitempty"`
	SeqLegVout       uint32 `json:"seq_leg_vout"`
	SeqLegAmount     uint64 `json:"seq_leg_amount,omitempty"`
	SeqLegAsset      string `json:"seq_leg_asset,omitempty"`
	SeqLegScriptHex  string `json:"seq_leg_script_hex,omitempty"`
	SeqBlockHash     string `json:"seq_block_hash,omitempty"`
	SecretHex        string `json:"secret_hex,omitempty"`
	BtcClaimTxid     string `json:"btc_claim_txid,omitempty"`  // forward: maker claimed the taker's BTC
	SeqRefundTx      string `json:"seq_refund_tx,omitempty"`   // forward: maker refunded its SEQ leg
	SeqClaimTxid     string `json:"seq_claim_txid,omitempty"`  // reverse: maker claimed the taker's SEQ
	Settled          bool   `json:"settled"`
	UpdatedAt        string `json:"updated_at"`
}

func persistXSession(dir, sid, offerID string, r *client.MakerForwardResult) {
	st := xmakerSessionState{
		SessionID: sid, OfferID: offerID, Direction: "forward",
		BtcLocktime: r.BtcLocktime, SeqLocktime: r.SeqLocktime,
		SeqBlockHash: r.SeqBlockHash,
		BtcClaimTxid: r.BtcClaimTxid, SeqRefundTx: r.SeqRefundTx,
		Settled:   r.Settled,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if len(r.HashH) > 0 {
		st.HashHex = hex.EncodeToString(r.HashH)
	}
	if r.BtcClaimKey != nil {
		st.BtcClaimPrivHex = hex.EncodeToString(r.BtcClaimKey.Bytes())
	}
	if r.SeqRefundKey != nil {
		st.SeqRefundPrivHex = hex.EncodeToString(r.SeqRefundKey.Bytes())
	}
	if r.BtcLeg != nil && r.BtcLeg.Funded != nil {
		st.BtcLegTxid, st.BtcLegVout, st.BtcLegAmount = r.BtcLeg.Funded.TxID, r.BtcLeg.Funded.Vout, r.BtcLeg.Funded.Amount
		st.BtcLegScriptHex = hex.EncodeToString(r.BtcLeg.Script)
	}
	if r.SeqLeg != nil && r.SeqLeg.Funded != nil {
		st.SeqLegTxid, st.SeqLegVout, st.SeqLegAmount = r.SeqLeg.Funded.TxID, r.SeqLeg.Funded.Vout, r.SeqLeg.Funded.Amount
		st.SeqLegAsset = r.SeqLeg.Funded.AssetID
		st.SeqLegScriptHex = hex.EncodeToString(r.SeqLeg.Script)
	}
	if len(r.Secret) > 0 {
		st.SecretHex = hex.EncodeToString(r.Secret)
	}
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		fmt.Printf("session %s: persist marshal: %v\n", sid, err)
		return
	}
	if err := ioutil.WriteFile(filepath.Join(dir, sid+".json"), b, 0o600); err != nil {
		fmt.Printf("session %s: persist write: %v\n", sid, err)
	}
}

// persistXSessionReverse snapshots a reverse (buy) cross lift. The maker holds
// the secret and funds the BTC leg, so the recovery material is the secret plus
// the seq-claim / btc-refund keys and both legs.
func persistXSessionReverse(dir, sid, offerID string, r *client.MakerReverseResult) {
	st := xmakerSessionState{
		SessionID: sid, OfferID: offerID, Direction: "reverse",
		BtcLocktime: r.BtcLocktime, SeqLocktime: r.SeqLocktime,
		SeqBlockHash: r.SeqBlockHash,
		SeqClaimTxid: r.SeqClaimTxid, BtcRefundTx: r.BtcRefundTx,
		Settled:   r.Settled,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if len(r.HashH) > 0 {
		st.HashHex = hex.EncodeToString(r.HashH)
	}
	if len(r.Secret) > 0 {
		st.SecretHex = hex.EncodeToString(r.Secret)
		st.SecretForRefundHex = st.SecretHex
	}
	if r.SeqClaimKey != nil {
		st.SeqClaimPrivHex = hex.EncodeToString(r.SeqClaimKey.Bytes())
	}
	if r.BtcRefundKey != nil {
		st.BtcRefundPrivHex = hex.EncodeToString(r.BtcRefundKey.Bytes())
	}
	if r.BtcLeg != nil && r.BtcLeg.Funded != nil {
		st.BtcLegTxid, st.BtcLegVout, st.BtcLegAmount = r.BtcLeg.Funded.TxID, r.BtcLeg.Funded.Vout, r.BtcLeg.Funded.Amount
		st.BtcLegScriptHex = hex.EncodeToString(r.BtcLeg.Script)
	}
	if r.SeqLeg != nil && r.SeqLeg.Funded != nil {
		st.SeqLegTxid, st.SeqLegVout, st.SeqLegAmount = r.SeqLeg.Funded.TxID, r.SeqLeg.Funded.Vout, r.SeqLeg.Funded.Amount
		st.SeqLegAsset = r.SeqLeg.Funded.AssetID
		st.SeqLegScriptHex = hex.EncodeToString(r.SeqLeg.Script)
	}
	b, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		fmt.Printf("session %s: persist marshal: %v\n", sid, err)
		return
	}
	if err := ioutil.WriteFile(filepath.Join(dir, sid+".json"), b, 0o600); err != nil {
		fmt.Printf("session %s: persist write: %v\n", sid, err)
	}
}

// cancelOffer removes the filled resting offer from the book (signed cancel).
func cancelOffer(relay string, o *seqobv1.Offer, key *btcec.PrivateKey) {
	c := &seqobv1.OfferCancel{OfferId: o.GetOfferId(), Nonce: uint64(time.Now().UnixNano())}
	if err := offer.SignCancel(c, key); err != nil {
		fmt.Printf("cancel offer: sign: %v\n", err)
		return
	}
	b, err := jsonMarshal.Marshal(c)
	if err != nil {
		fmt.Printf("cancel offer: marshal: %v\n", err)
		return
	}
	resp, err := http.Post(relay+"/v1/offers/cancel", "application/json", bytes.NewReader(b))
	if err != nil {
		fmt.Printf("cancel offer: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("cancel offer: status %d: %s\n", resp.StatusCode, string(body))
		return
	}
	fmt.Printf("offer %s cancelled after fill (restart the maker to re-quote)\n", o.GetOfferId())
}

// rpcFromURL parses http://user:pass@host:port into an xchain RPC client.
func rpcFromURL(raw string) (*xchain.RPC, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("expected http://user:pass@host:port, got %q", raw)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("bad port in %q", raw)
	}
	pass, _ := u.User.Password()
	return xchain.NewRPC(u.Hostname(), port, u.User.Username(), pass), nil
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
