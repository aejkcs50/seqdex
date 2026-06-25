package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	pricefeeder "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/price-feeder"
	pricefeederstore "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/price-feeder/store/badger"

	"net/url"
	"strconv"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/core/application/xchainmaker"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"

	"github.com/aejkcs50/seqdex/daemon/internal/config"
	"github.com/aejkcs50/seqdex/daemon/internal/core/application"
	"github.com/aejkcs50/seqdex/daemon/internal/core/domain"
	"github.com/aejkcs50/seqdex/daemon/internal/core/ports"
	oceanwallet "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/ocean-wallet"
	pubsub "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/pubsub"
	swap_parser "github.com/aejkcs50/seqdex/daemon/internal/infrastructure/swap-parser"
	"github.com/aejkcs50/seqdex/daemon/internal/interfaces"
	grpcinterface "github.com/aejkcs50/seqdex/daemon/internal/interfaces/grpc"
	boltsecurestore "github.com/aejkcs50/seqdex/daemon/pkg/securestore/bolt"
	"github.com/aejkcs50/seqdex/daemon/pkg/stats"
	"github.com/shopspring/decimal"
	log "github.com/sirupsen/logrus"

	_ "net/http/pprof" // #nosec
)

var (
	// General config
	logLevel, tradeSvcPort, operatorSvcPort, statsInterval int
	noMacaroons, noOperatorTls, profilerEnabled            bool
	datadir, dbDir, profilerDir, tradeTLSKey, tradeTLSCert string
	walletUnlockPasswordFile, dbType, oceanWalletAddr      string
	connectAddr, connectProto, nodeRPC                     string
	operatorTLSExtraIPs, operatorTLSExtraDomains           []string
	// App services config
	feeBalanceThreshold                   uint64
	pricesSlippagePercentage, satsPerByte decimal.Decimal

	// Cross-chain (XchainService) maker; nil unless XCHAIN_PARENT_RPC is set.
	xchainSvc                                                   *xchainmaker.Service
	xchainParentRPC, xchainSeqRPC, xchainWallet, xchainSeqAsset string
	xchainParentKind, xchainParentChain                         string
	xchainPriceSeqPerBtc                                        float64
	xchainFeeBps, xchainSpendFee                                uint64
	xchainBtcLocktimeDelta, xchainSeqLocktimeDelta              uint32
	xchainMinBtcConf                                            int

	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := loadConfig(); err != nil {
		log.WithError(err).Fatal("failed to init config")
	}

	log.SetLevel(log.Level(logLevel))
	domain.SwapParserManager = swap_parser.NewService()

	// Profiler is enabled at url http://localhost:8024/debug/pprof/
	if profilerEnabled {
		runtime.SetBlockProfileRate(1)
		//nolint
		go http.ListenAndServe(":8024", nil)
	}

	// Init services to be used by those of the application layer.
	wallet, err := oceanwallet.NewService(oceanWalletAddr)
	if err != nil {
		log.WithError(err).Fatal("failed to connect to ocean wallet")
	}

	pubsub, err := newPubSubService(dbDir)
	if err != nil {
		log.WithError(err).Fatal("failed to initialize pubsub service")
	}

	priceFeederSvc, err := newPriceFeederService()
	if err != nil {
		log.WithError(err).Fatal("failed to initialize price feeder service")
	}

	appConfig := &application.Config{
		OceanWallet:         wallet,
		SecurePubSub:        pubsub,
		PriceFeederSvc:      priceFeederSvc,
		FeeBalanceThreshold: feeBalanceThreshold,
		TradePriceSlippage:  pricesSlippagePercentage,
		TxSatsPerByte:       satsPerByte,
		DBType:              dbType,
		DBConfig:            dbDir,
		NodeRPC:             nodeRPC,
	}

	// Optionally build the integrated cross-chain swap maker (XchainService).
	xchainSvc, err = newXchainService()
	if err != nil {
		log.WithError(err).Fatal("failed to initialize cross-chain xchain service")
	}
	if xchainSvc != nil {
		log.RegisterExitHandler(xchainSvc.Close)
	}

	runOnOnePort := operatorSvcPort == tradeSvcPort
	svc, err := NewGrpcService(runOnOnePort, appConfig)
	if err != nil {
		log.WithError(err).Fatal("failed to initialize grpc service")
	}
	log.RegisterExitHandler(svc.Stop)

	log.Info("starting daemon")

	if log.GetLevel() >= log.DebugLevel {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		interval := time.Duration(statsInterval) * time.Second
		stats.EnableMemoryStatistics(ctx, interval, profilerDir)
	}

	// Start gRPC service interfaces.
	if err := svc.Start(); err != nil {
		log.WithError(err).Error("failed to start daemon")
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	log.Info("shutting down daemon")
	log.Exit(0)
}

func loadConfig() error {
	if err := config.InitConfig(); err != nil {
		return err
	}
	logLevel = config.GetInt(config.LogLevelKey)
	profilerEnabled = config.GetBool(config.EnableProfilerKey)
	datadir = config.GetDatadir()
	dbDir = filepath.Join(datadir, config.DbLocation)
	profilerDir = filepath.Join(datadir, config.ProfilerLocation)
	noMacaroons = config.GetBool(config.NoMacaroonsKey)
	noOperatorTls = config.GetBool(config.NoOperatorTlsKey)
	statsInterval = config.GetInt(config.StatsIntervalKey)
	tradeTLSKey = config.GetString(config.TradeTLSKeyKey)
	tradeTLSCert = config.GetString(config.TradeTLSCertKey)
	operatorTLSExtraIPs = config.GetStringSlice(config.OperatorExtraIPKey)
	operatorTLSExtraDomains = config.GetStringSlice(config.OperatorExtraDomainKey)
	walletUnlockPasswordFile = config.GetString(config.WalletUnlockPasswordFile)
	connectAddr = config.GetString(config.ConnectAddrKey)
	connectProto = config.GetString(config.ConnectProtoKey)
	dbType = config.GetString(config.DBTypeKey)
	// App services config
	pricesSlippagePercentage = decimal.NewFromFloat(config.GetFloat(config.PriceSlippageKey))
	satsPerByte = decimal.NewFromFloat(config.GetFloat(config.TxSatsPerByteKey))
	feeBalanceThreshold = uint64(config.GetInt(config.FeeAccountBalanceThresholdKey))
	tradeSvcPort = config.GetInt(config.TradeListeningPortKey)
	operatorSvcPort = config.GetInt(config.OperatorListeningPortKey)
	oceanWalletAddr = config.GetString(config.OceanWalletAddrKey)
	nodeRPC = config.GetString(config.NodeRpcKey)
	// Cross-chain maker config (only used when XCHAIN_PARENT_RPC is set).
	xchainParentRPC = config.GetString(config.XchainParentRPCKey)
	xchainParentKind = config.GetString(config.XchainParentKindKey)
	xchainParentChain = config.GetString(config.XchainParentChainKey)
	xchainSeqRPC = config.GetString(config.XchainSeqRPCKey)
	xchainWallet = config.GetString(config.XchainWalletKey)
	xchainSeqAsset = config.GetString(config.XchainSeqAssetKey)
	xchainPriceSeqPerBtc = config.GetFloat(config.XchainPriceSeqPerBtcKey)
	xchainFeeBps = uint64(config.GetInt(config.XchainFeeBpsKey))
	xchainSpendFee = uint64(config.GetInt(config.XchainSpendFeeKey))
	xchainBtcLocktimeDelta = uint32(config.GetInt(config.XchainBtcLocktimeDeltaKey))
	xchainSeqLocktimeDelta = uint32(config.GetInt(config.XchainSeqLocktimeDeltaKey))
	xchainMinBtcConf = config.GetInt(config.XchainMinBtcConfKey)

	return nil
}

// rpcFromURL parses an http://user:pass@host:port RPC url into an xchain.RPC.
func rpcFromURL(raw string) (*xchain.RPC, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse rpc url: %w", err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	user := u.User.Username()
	pass, _ := u.User.Password()
	return xchain.NewRPC(host, port, user, pass), nil
}

// newXchainService builds the integrated cross-chain swap maker from config, or
// returns (nil, nil) when XCHAIN_PARENT_RPC is unset (xchain disabled). When
// enabled it requires XCHAIN_SEQ_RPC and XCHAIN_SEQ_ASSET. The returned service
// is already Start()ed; the caller must Close() it on shutdown.
func newXchainService() (*xchainmaker.Service, error) {
	if xchainParentRPC == "" {
		return nil, nil
	}
	if xchainSeqRPC == "" {
		return nil, fmt.Errorf("%s is set but %s is missing", config.XchainParentRPCKey, config.XchainSeqRPCKey)
	}
	if xchainSeqAsset == "" {
		return nil, fmt.Errorf("%s is set but %s is missing (the SEQ-side asset the maker offers)", config.XchainParentRPCKey, config.XchainSeqAssetKey)
	}

	btcRPC, err := rpcFromURL(xchainParentRPC)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config.XchainParentRPCKey, err)
	}
	seqRPC, err := rpcFromURL(xchainSeqRPC)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config.XchainSeqRPCKey, err)
	}
	seq := xchain.NewChain(seqRPC, xchainWallet)

	cfg := xchainmaker.Config{
		SEQ:         seq,
		CoinDivisor: 1e8,
		Markets: []xchainmaker.Market{{
			SeqAsset:       xchainSeqAsset,
			Name:           "BTC/SEQ-ASSET",
			PriceSeqPerBtc: xchainPriceSeqPerBtc,
			FeeBps:         xchainFeeBps,
		}},
		QuoteTTL:         2 * time.Minute,
		BtcLocktimeDelta: xchainBtcLocktimeDelta,
		SeqLocktimeDelta: xchainSeqLocktimeDelta,
		MinBTCConf:       xchainMinBtcConf,
		SpendFee:         xchainSpendFee,
		PollInterval:     500 * time.Millisecond,
	}

	var btcAsset, parentDesc string
	switch xchainParentKind {
	case "bitcoin":
		params, perr := xchain.BitcoinChainParams(xchainParentChain)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", config.XchainParentChainKey, perr)
		}
		cfg.ParentKind = xchainmaker.ParentBitcoin
		cfg.BTCBitcoin = xchain.NewBitcoinChain(btcRPC, xchainWallet, params)
		btcAsset = "" // real BTC has no asset id
		parentDesc = "bitcoin/" + xchainParentChain
	case "elements", "":
		btc := xchain.NewChain(btcRPC, xchainWallet)
		cfg.ParentKind = xchainmaker.ParentElements
		cfg.BTC = btc
		btcAsset, err = btc.PeggedAsset()
		if err != nil {
			return nil, fmt.Errorf("read parent pegged asset: %w", err)
		}
		parentDesc = "elements asset=" + btcAsset
	default:
		return nil, fmt.Errorf("%s: unknown %q (want bitcoin|elements)", config.XchainParentKindKey, xchainParentKind)
	}
	cfg.Markets[0].BtcAsset = btcAsset

	svc, err := xchainmaker.New(cfg)
	if err != nil {
		return nil, err
	}
	svc.Start()
	log.Infof("cross-chain XchainService enabled: parent(BTC)=%s seq asset=%s wallet=%q", parentDesc, xchainSeqAsset, xchainWallet)
	return svc, nil
}

type buildData struct{}

func (bd buildData) GetVersion() string {
	return version
}
func (bd buildData) GetCommit() string {
	return commit
}
func (bd buildData) GetDate() string {
	return date
}

func newPubSubService(datadir string) (ports.SecurePubSub, error) {
	secureStore, err := boltsecurestore.NewSecureStorage(datadir, "pubsub.db")
	if err != nil {
		return nil, err
	}
	return pubsub.NewService(secureStore)
}

func newPriceFeederService() (ports.PriceFeeder, error) {
	dbDir := filepath.Join(datadir, "db")
	store, err := pricefeederstore.NewPriceFeedStore(dbDir, log.New())
	if err != nil {
		return nil, err
	}

	return pricefeeder.NewService(store), nil
}

func NewGrpcService(
	runOnOnePort bool, appConfig *application.Config,
) (interfaces.Service, error) {
	addr := fmt.Sprintf("localhost:%d", operatorSvcPort)
	if connectAddr != "" {
		addr = connectAddr
	}

	// XchainService is the cross-chain maker; nil when xchain is disabled. The
	// gRPC layer only registers it (gRPC + grpc-web + REST gateway) when set.
	var xchain seqdexv1.XchainServiceServer
	if xchainSvc != nil {
		xchain = xchainSvc
	}

	if runOnOnePort {
		opts := grpcinterface.ServiceOptsOnePort{
			NoMacaroons:              noMacaroons,
			Datadir:                  datadir,
			DBLocation:               config.DbLocation,
			MacaroonsLocation:        config.MacaroonsLocation,
			WalletUnlockPasswordFile: walletUnlockPasswordFile,
			Port:                     tradeSvcPort,
			TLSKey:                   tradeTLSKey,
			TLSCert:                  tradeTLSCert,
			ConnectAddr:              addr,
			ConnectProto:             connectProto,
			BuildData:                buildData{},
			AppConfig:                appConfig,
			XchainService:            xchain,
		}

		return grpcinterface.NewServiceOnePort(opts)
	}

	opts := grpcinterface.ServiceOpts{
		NoMacaroons:              noMacaroons,
		Datadir:                  datadir,
		DBLocation:               config.DbLocation,
		TLSLocation:              config.TLSLocation,
		MacaroonsLocation:        config.MacaroonsLocation,
		OperatorExtraIPs:         operatorTLSExtraIPs,
		OperatorExtraDomains:     operatorTLSExtraDomains,
		OperatorPort:             operatorSvcPort,
		TradePort:                tradeSvcPort,
		TradeTLSKey:              tradeTLSKey,
		TradeTLSCert:             tradeTLSCert,
		WalletUnlockPasswordFile: walletUnlockPasswordFile,
		NoOperatorTls:            noOperatorTls,
		ConnectAddr:              addr,
		ConnectProto:             connectProto,
		BuildData:                buildData{},
		AppConfig:                appConfig,
		XchainService:            xchain,
	}

	return grpcinterface.NewService(opts)
}
