package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "net/http/pprof" // #nosec

	log "github.com/sirupsen/logrus"
	appconfig "github.com/aejkcs50/seqdex/wallet/internal/app-config"
	"github.com/aejkcs50/seqdex/wallet/internal/config"
	electrum_scanner "github.com/aejkcs50/seqdex/wallet/internal/infrastructure/blockchain-scanner/electrum"
	elements_scanner "github.com/aejkcs50/seqdex/wallet/internal/infrastructure/blockchain-scanner/elements"
	neutrino_scanner "github.com/aejkcs50/seqdex/wallet/internal/infrastructure/blockchain-scanner/neutrino"
	postgresdb "github.com/aejkcs50/seqdex/wallet/internal/infrastructure/storage/db/postgres"
	"github.com/aejkcs50/seqdex/wallet/internal/interfaces"
	grpc_interface "github.com/aejkcs50/seqdex/wallet/internal/interfaces/grpc"
	"github.com/aejkcs50/seqdex/wallet/pkg/profiler"
)

var (
	// Build info.
	version string
	commit  string
	date    string

	// Config from env vars.
	dbType             = config.GetString(config.DbTypeKey)
	bcScannerType      = config.GetString(config.BlockchainScannerTypeKey)
	logLevel           = config.GetInt(config.LogLevelKey)
	datadir            = config.GetDatadir()
	port               = config.GetInt(config.PortKey)
	profilerPort       = config.GetInt(config.ProfilerPortKey)
	network            = config.GetNetwork()
	noTLS              = config.GetBool(config.NoTLSKey)
	noProfiler         = config.GetBool(config.NoProfilerKey)
	tlsDir             = filepath.Join(datadir, config.TLSLocation)
	profilerDir        = filepath.Join(datadir, config.ProfilerLocation)
	electrumUrl        = config.GetString(config.ElectrumUrlKey)
	elementsRpcAddr    = config.GetString(config.ElementsNodeRpcAddrKey)
	esploraUrl         = config.GetString(config.EsploraUrlKey)
	nodePeers          = config.GetStringSlice(config.NodePeersKey)
	tlsExtraIPs        = config.GetStringSlice(config.TLSExtraIPKey)
	tlsExtraDomains    = config.GetStringSlice(config.TLSExtraDomainKey)
	statsInterval      = time.Duration(config.GetInt(config.StatsIntervalKey)) * time.Second
	utxoExpiryDuration = time.Duration(config.GetInt(config.UtxoExpiryDurationKey))
	rootPath           = config.GetRootPath()
	dbUser             = config.GetString(config.DbUserKey)
	dbPassword         = config.GetString(config.DbPassKey)
	dbHost             = config.GetString(config.DbHostKey)
	dbPort             = config.GetInt(config.DbPortKey)
	dbName             = config.GetString(config.DbNameKey)
	migrationSourceURL = config.GetString(config.DbMigrationPath)
	dustAmount         = uint64(config.GetInt(config.DustAmountKey))
	walletPassword     = config.GetString(config.PasswordKey)
	walletMnemonic     = config.GetString(config.MnemonicKey)
)

func main() {
	log.SetLevel(log.Level(logLevel))

	if profilerEnabled := !noProfiler; profilerEnabled {
		profilerSvc, err := profiler.NewService(profiler.ServiceOpts{
			Port:          profilerPort,
			StatsInterval: statsInterval,
			Datadir:       profilerDir,
		})
		if err != nil {
			log.WithError(err).Fatal("profiler: error while starting")
		}

		profilerSvc.Start()
		defer profilerSvc.Stop()
	}

	bcScannerConfig := buildScannerConfig()
	serviceCfg := grpc_interface.ServiceConfig{
		Port:         port,
		NoTLS:        noTLS,
		TLSLocation:  tlsDir,
		ExtraIPs:     tlsExtraIPs,
		ExtraDomains: tlsExtraDomains,
	}
	repoManagerConfig := dbConfigFromType()
	appCfg := &appconfig.AppConfig{
		Version:                 version,
		Commit:                  commit,
		Date:                    date,
		RootPath:                rootPath,
		Network:                 network,
		UtxoExpiryDuration:      utxoExpiryDuration * time.Second,
		DustAmount:              dustAmount,
		Password:                walletPassword,
		Mnemonic:                walletMnemonic,
		RepoManagerType:         dbType,
		BlockchainScannerType:   bcScannerType,
		RepoManagerConfig:       repoManagerConfig,
		BlockchainScannerConfig: bcScannerConfig,
	}

	serviceManager, err := interfaces.NewGrpcServiceManager(serviceCfg, appCfg)
	if err != nil {
		log.WithError(err).Fatal("service: error while initializing")
	}

	if err := serviceManager.Service.Start(); err != nil {
		log.WithError(err).Fatal("service: error while starting")
	}
	defer serviceManager.Service.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan
}

// buildScannerConfig assembles the blockchain-scanner config args matching the
// configured scanner type. app-config type-asserts on the concrete type, so it
// must match BlockchainScannerType exactly.
func buildScannerConfig() interface{} {
	scannerDir := filepath.Join(datadir, config.ScannerLocation)
	switch bcScannerType {
	case "elements":
		return elements_scanner.ServiceArgs{
			RpcAddr:    elementsRpcAddr,
			Network:    network.Name,
			EsploraUrl: esploraUrl, // optional; empty => node-RPC-only mode
		}
	case "neutrino":
		return neutrino_scanner.NodeServiceArgs{
			Network:             network.Name,
			FiltersDatadir:      filepath.Join(scannerDir, "filters"),
			BlockHeadersDatadir: filepath.Join(scannerDir, "headers"),
			EsploraUrl:          esploraUrl,
			Peers:               nodePeers,
		}
	case "electrum":
		fallthrough
	default:
		return electrum_scanner.ServiceArgs{
			Addr:    electrumUrl,
			Network: network,
		}
	}
}

func dbConfigFromType() interface{} {
	switch dbType {
	case "postgres":
		return postgresdb.DbConfig{
			DbUser:             dbUser,
			DbPassword:         dbPassword,
			DbHost:             dbHost,
			DbPort:             dbPort,
			DbName:             dbName,
			MigrationSourceURL: migrationSourceURL,
		}
	case "badger":
		return filepath.Join(datadir, "db")
	case "inmemory":
		fallthrough
	default:
		return nil
	}
}
