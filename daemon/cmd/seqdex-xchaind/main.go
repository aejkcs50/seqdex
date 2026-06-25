// Command seqdex-xchaind runs the SeqDEX cross-chain swap MAKER as a standalone
// gRPC service (Phase 5, milestone 2). It exposes seqdex.v1.XchainService on a
// clearly-labeled endpoint (default :9955; the full trade daemon owns :9945)
// and acts as the taker's counterparty for BTC->SEQ-asset swaps, built on the
// proven pkg/xchain mechanism.
//
// It is the API/state-machine counterpart to the mechanism demo
// (cmd/seqdex-xchain-swapdemo): rather than driving both swap roles in one
// process, it plays ONLY the maker and serves a remote taker over gRPC.
//
// Config (env; secrets/keys come from the node wallets via RPC, never argv):
//
//	XCHAIN_LISTEN     gRPC listen addr (default 127.0.0.1:9955)
//	PARENT_RPC        parent ("BTC") node RPC url, http://user:pass@host:port
//	SEQ_RPC           anchored Sequentia node RPC url, http://user:pass@host:port
//	WALLET            wallet name on both nodes (default "w")
//	SEQ_ASSET         the SEQ-side asset id (hex) to offer
//	PRICE_SEQ_PER_BTC SEQ atoms given per BTC atom (default 100)
//	FEE_BPS           maker fee in basis points (default 0)
//	BTC_LOCKTIME_DELTA blocks above tip for T_btc (taker refund) (default 100)
//	SEQ_LOCKTIME_DELTA blocks above tip for T_seq (maker refund) (default 50)
//	MIN_BTC_CONF      required BTC-leg confirmations (default 1)
package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"time"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/core/application/xchainmaker"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := envOr("XCHAIN_LISTEN", "127.0.0.1:9955")
	wallet := envOr("WALLET", "w")

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

	seqAsset := os.Getenv("SEQ_ASSET")
	if seqAsset == "" {
		return fmt.Errorf("SEQ_ASSET not set (the SEQ-side asset id the maker offers)")
	}
	btcAsset, err := btc.PeggedAsset()
	if err != nil {
		return fmt.Errorf("read parent pegged asset: %w", err)
	}

	cfg := xchainmaker.Config{
		BTC:         btc,
		SEQ:         seq,
		CoinDivisor: 1e8,
		Markets: []xchainmaker.Market{{
			SeqAsset:       seqAsset,
			BtcAsset:       btcAsset,
			Name:           "BTC/SEQ-ASSET",
			PriceSeqPerBtc: floatEnv("PRICE_SEQ_PER_BTC", 100),
			FeeBps:         uintEnv("FEE_BPS", 0),
		}},
		QuoteTTL:         2 * time.Minute,
		BtcLocktimeDelta: uint32(uintEnv("BTC_LOCKTIME_DELTA", 100)),
		SeqLocktimeDelta: uint32(uintEnv("SEQ_LOCKTIME_DELTA", 50)),
		MinBTCConf:       int(uintEnv("MIN_BTC_CONF", 1)),
		SpendFee:         uintEnv("SPEND_FEE", 1000),
		PollInterval:     500 * time.Millisecond,
	}

	svc, err := xchainmaker.New(cfg)
	if err != nil {
		return err
	}
	svc.Start()
	defer svc.Close()

	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listen, err)
	}
	grpcSrv := grpc.NewServer()
	seqdexv1.RegisterXchainServiceServer(grpcSrv, svc)
	reflection.Register(grpcSrv)

	fmt.Printf("seqdex-xchaind: XchainService listening on %s\n", listen)
	fmt.Printf("  parent(BTC) asset=%s  seq asset=%s  wallet=%q\n", btcAsset, seqAsset, wallet)
	return grpcSrv.Serve(lis)
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

func floatEnv(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
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
