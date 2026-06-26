// Command seqdex-taker exercises the Sequentia-adapted pkg/trade taker SDK
// against a running tdexd trade interface, performing a same-chain atomic swap.
//
// It creates a fresh taker wallet (its Sequentia confidential address is
// printed so the node can fund it), then on the second invocation runs
// Preview + Buy/SellAndComplete and prints the resulting swap txid.
//
// Secrets (the taker's private + blinding keys) are persisted to / loaded from
// KEY_FILE so the two phases share the same wallet without putting key material
// on the command line.
//
// Env:
//
//	PHASE       = "addr"  -> create wallet, write keys to KEY_FILE, print address
//	            = "swap"  -> load wallet from KEY_FILE, Preview + (Buy|Sell)AndComplete
//	KEY_FILE    path to the taker key file
//	TRADE_ADDR  daemon trade endpoint host:port (default localhost:9945)
//	NODE_RPC    elements node RPC url http://user:pass@host:port
//	NATIVE      native/policy asset hex (pegged_asset)
//	BASE,QUOTE  market assets (hex)
//	TYPE        "buy" or "sell"
//	AMOUNT      amount (in sats) of QUOTE asset to buy/sell (TDEX amount is in quote)
//	IN_ASSET    asset the taker spends/funds (hex) — used only for logging
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/aejkcs50/seqdex/daemon/pkg/explorer"
	"github.com/aejkcs50/seqdex/daemon/pkg/explorer/elements"
	"github.com/aejkcs50/seqdex/daemon/pkg/seqnet"
	"github.com/aejkcs50/seqdex/daemon/pkg/swap"
	"github.com/aejkcs50/seqdex/daemon/pkg/trade"
	tradeclient "github.com/aejkcs50/seqdex/daemon/pkg/trade/client"
	trademarket "github.com/aejkcs50/seqdex/daemon/pkg/trade/market"
	tradetype "github.com/aejkcs50/seqdex/daemon/pkg/trade/type"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/psetv2"
	"google.golang.org/protobuf/proto"
)

func main() {
	phase := os.Getenv("PHASE")
	keyFile := mustEnv("KEY_FILE")
	native := mustEnv("NATIVE")

	// Sequentia network (CHAIN env: "sequentia-testnet"/"sequentia-regtest"/
	// "sequentia"; default testnet) with the runtime native asset stamped on.
	chain := envDefault("CHAIN", seqnet.Testnet)
	net, ok := seqnet.ByName(chain)
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown CHAIN:", chain)
		os.Exit(1)
	}
	net.AssetID = native

	switch phase {
	case "addr":
		w, err := trade.NewRandomWallet(&net)
		must(err, "NewRandomWallet")
		// Persist keys (hex, one per line: priv, blinding).
		data := hex.EncodeToString(w.PrivateKey()) + "\n" + hex.EncodeToString(w.BlindingKey()) + "\n"
		must(os.WriteFile(keyFile, []byte(data), 0600), "write keyfile")
		fmt.Println(w.Address())
	case "swap":
		priv, blind := loadKeys(keyFile)
		w := trade.NewWalletFromKey(priv, blind, &net)

		nodeRPC := mustEnv("NODE_RPC")
		tradeAddr := envDefault("TRADE_ADDR", "localhost:9945")
		base := mustEnv("BASE")
		quote := mustEnv("QUOTE")
		typ := envDefault("TYPE", "buy")
		// ASSET is the asset whose AMOUNT is specified (must be base or quote);
		// defaults to quote (the classic TDEX convention).
		assetParam := envDefault("ASSET", quote)
		// FEE_ASSET defaults to base (native SEQ, the only asset with an on-node
		// exchange rate).
		feeAsset := envDefault("FEE_ASSET", base)
		amount, err := strconv.ParseUint(mustEnv("AMOUNT"), 10, 64)
		must(err, "parse AMOUNT")

		// Explorer: the elements node, with the Sequentia regtest network so
		// the taker's own confidential-address UTXO lookups resolve.
		expl, err := elements.NewServiceWithNetwork(nodeRPC, nil, &net)
		must(err, "explorer")

		host, portStr := splitHostPort(tradeAddr)
		port, _ := strconv.Atoi(portStr)
		client, err := tradeclient.NewTradeClient(host, port)
		must(err, "trade client")

		t, err := trade.NewTrade(trade.NewTradeOpts{
			Chain:           chain,
			NativeAsset:     native,
			ExplorerService: expl,
			Client:          client,
		})
		must(err, "NewTrade")

		mkt := trademarket.Market{BaseAsset: base, QuoteAsset: quote}

		// Determine the tradeType + the "asset" param. TDEX convention: amount
		// & asset describe the QUOTE leg.
		var tt tradetype.TradeType
		if typ == "buy" {
			tt = tradetype.Buy
		} else {
			tt = tradetype.Sell
		}

		// Preview first.
		preview, err := t.Preview(trade.PreviewOpts{
			Market:    mkt,
			TradeType: int(tt),
			Amount:    amount,
			Asset:     assetParam,
			FeeAsset:  feeAsset,
		})
		must(err, "Preview")
		fmt.Println("PREVIEW:")
		printJSON(map[string]interface{}{
			"asset_to_send":     preview.AssetToSend,
			"amount_to_send":    preview.AmountToSend,
			"asset_to_receive":  preview.AssetToReceive,
			"amount_to_receive": preview.AmountToReceive,
			"fee_asset":         preview.FeeAsset,
			"fee_amount":        preview.FeeAmount,
		})

		opts := trade.BuyOrSellAndCompleteOpts{
			Market:      mkt,
			Amount:      amount,
			Asset:       assetParam,
			PrivateKey:  priv,
			BlindingKey: blind,
			FeeAsset:    feeAsset,
		}

		var txid string
		if tt.IsBuy() {
			txid, err = t.BuyAndComplete(opts)
		} else {
			txid, err = t.SellAndComplete(opts)
		}
		must(err, "Buy/SellAndComplete")
		fmt.Println("SWAP_TXID=" + txid)
		_ = w
	case "swapself":
		// Same as "swap" but, instead of relying on the daemon's flaky
		// CompleteTrade ocean-broadcast, finalize the fully-signed swap PSET
		// ourselves and emit the raw tx hex so the caller can push it straight
		// to a producer via POST /api/tx. The daemon still signs its reserve
		// inputs during TradePropose; we just take over the finalize+broadcast.
		priv, blind := loadKeys(keyFile)
		w := trade.NewWalletFromKey(priv, blind, &net)

		nodeRPC := mustEnv("NODE_RPC")
		tradeAddr := envDefault("TRADE_ADDR", "localhost:9945")
		base := mustEnv("BASE")
		quote := mustEnv("QUOTE")
		typ := envDefault("TYPE", "sell")
		assetParam := envDefault("ASSET", quote)
		feeAsset := envDefault("FEE_ASSET", base)
		amount, err := strconv.ParseUint(mustEnv("AMOUNT"), 10, 64)
		must(err, "parse AMOUNT")

		expl, err := elements.NewServiceWithNetwork(nodeRPC, nil, &net)
		must(err, "explorer")
		host, portStr := splitHostPort(tradeAddr)
		port, _ := strconv.Atoi(portStr)
		client, err := tradeclient.NewTradeClient(host, port)
		must(err, "trade client")

		t, err := trade.NewTrade(trade.NewTradeOpts{
			Chain:           chain,
			NativeAsset:     native,
			ExplorerService: expl,
			Client:          client,
		})
		must(err, "NewTrade")
		mkt := trademarket.Market{BaseAsset: base, QuoteAsset: quote}

		var tt tradetype.TradeType
		if typ == "buy" {
			tt = tradetype.Buy
		} else {
			tt = tradetype.Sell
		}

		preview, err := t.Preview(trade.PreviewOpts{
			Market: mkt, TradeType: int(tt), Amount: amount,
			Asset: assetParam, FeeAsset: feeAsset,
		})
		must(err, "Preview")
		fmt.Println("PREVIEW: send", preview.AmountToSend, preview.AssetToSend,
			"-> receive", preview.AmountToReceive, preview.AssetToReceive)

		utxos, err := expl.GetUnspents(w.Address(), [][]byte{blind})
		must(err, "GetUnspents")
		if len(utxos) == 0 {
			must(fmt.Errorf("taker address not funded"), "utxos")
		}

		outScript, err := seqnet.ToOutputScript(w.Address(), &net)
		must(err, "ToOutputScript")
		_, pk := btcec.PrivKeyFromBytes(blind)
		outBlindKey := pk.SerializeCompressed()

		amounts := map[string]uint64{
			preview.AssetToSend:    preview.AmountToSend,
			preview.AssetToReceive: preview.AmountToReceive,
		}
		feesToAdd := tt.IsBuy() && feeAsset == mkt.QuoteAsset ||
			tt.IsSell() && feeAsset == mkt.BaseAsset
		if feesToAdd {
			amounts[preview.FeeAsset] += preview.FeeAmount
		} else {
			amounts[preview.FeeAsset] -= preview.FeeAmount
		}

		// Mirror NewSwapTx's internal coin selection so the UnblindedInputs we
		// hand to swap.Request match exactly the inputs that end up in the PSET
		// (NewSwapTx only adds the SELECTED utxos, not every utxo the taker owns).
		selectedUtxos, _, err := explorer.SelectUnspents(
			utxos, amounts[preview.AssetToSend], preview.AssetToSend,
		)
		must(err, "SelectUnspents")

		psetBase64, err := trade.NewSwapTx(
			utxos, preview.AssetToSend, preview.AssetToReceive,
			amounts[preview.AssetToSend], amounts[preview.AssetToReceive],
			outScript, outBlindKey,
		)
		must(err, "NewSwapTx")

		swapReqMsg, err := swap.Request(swap.RequestOpts{
			AssetToSend:     preview.AssetToSend,
			AmountToSend:    preview.AmountToSend,
			AssetToReceive:  preview.AssetToReceive,
			AmountToReceive: preview.AmountToReceive,
			Transaction:     psetBase64,
			UnblindedInputs: takerUnblindedIns(selectedUtxos),
			FeeAmount:       preview.FeeAmount,
			FeeAsset:        preview.FeeAsset,
		})
		must(err, "swap.Request")

		reply, err := client.TradePropose(tradeclient.TradeProposeOpts{
			Market: mkt, SwapRequest: swapReqMsg, TradeType: tt,
			FeeAsset: preview.FeeAsset, FeeAmount: preview.FeeAmount,
		})
		must(err, "TradePropose")
		if fail := reply.GetSwapFail(); fail != nil {
			must(fmt.Errorf("%s", fail.GetFailureMessage()), "proposal rejected")
		}
		swapAcceptMsg, err := proto.Marshal(reply.GetSwapAccept())
		must(err, "marshal accept")

		// The maker-signed pset is in the SwapAccept; add the taker's signature.
		signedPset, err := w.Sign(reply.GetSwapAccept().GetTransaction())
		must(err, "taker Sign")
		_ = swapAcceptMsg

		// Finalize + extract the fully-signed pset into a network-ready tx.
		ptx, err := psetv2.NewPsetFromBase64(signedPset)
		must(err, "parse signed pset")
		must(psetv2.FinalizeAll(ptx), "finalize")
		finalTx, err := psetv2.Extract(ptx)
		must(err, "extract")
		txHex, err := finalTx.ToHex()
		must(err, "tx ToHex")
		txid := finalTx.TxHash().String()
		fmt.Println("SWAP_TXHEX=" + txHex)
		fmt.Println("SWAP_TXID=" + txid)
		_ = w
	default:
		fmt.Fprintln(os.Stderr, "unknown PHASE:", phase)
		os.Exit(2)
	}
}

func takerUnblindedIns(utxos []explorer.Utxo) []swap.UnblindedInput {
	ins := make([]swap.UnblindedInput, 0, len(utxos))
	for i, u := range utxos {
		ins = append(ins, swap.UnblindedInput{
			Index:         uint32(i),
			Asset:         u.Asset(),
			Amount:        u.Value(),
			AssetBlinder:  elementsutil.TxIDFromBytes(u.AssetBlinder()),
			AmountBlinder: elementsutil.TxIDFromBytes(u.ValueBlinder()),
		})
	}
	return ins
}

func loadKeys(path string) ([]byte, []byte) {
	raw, err := os.ReadFile(path)
	must(err, "read keyfile")
	var priv, blind string
	fmt.Sscanf(string(raw), "%s\n%s", &priv, &blind)
	p, err := hex.DecodeString(priv)
	must(err, "decode priv")
	b, err := hex.DecodeString(blind)
	must(err, "decode blind")
	return p, b
}

func splitHostPort(s string) (string, string) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func printJSON(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fmt.Fprintln(os.Stderr, "missing env:", k)
		os.Exit(1)
	}
	return v
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func must(err error, ctx string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", ctx, err)
		os.Exit(1)
	}
}
