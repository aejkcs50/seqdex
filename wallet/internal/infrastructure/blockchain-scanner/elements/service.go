package elements_scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/transaction"
	"github.com/vulpemventures/neutrino-elements/pkg/blockservice"
	"github.com/vulpemventures/neutrino-elements/pkg/repository"
	"github.com/aejkcs50/seqdex/wallet/internal/core/domain"
	"github.com/aejkcs50/seqdex/wallet/internal/core/ports"
	"github.com/aejkcs50/seqdex/wallet/pkg/seqnet"
)

type service struct {
	args        ServiceArgs
	rpcClient   *rpcClient
	blockSvc    blockservice.BlockService
	scanners    map[string]*scannerService
	genesisHash *chainhash.Hash

	filtersRepo repository.FilterRepository
	headersRepo repository.BlockHeaderRepository
	lock        *sync.RWMutex

	quit      chan struct{}
	lastTip   uint32
	tipTicker *time.Ticker
}

type ServiceArgs struct {
	RpcAddr string
	Network string
	// EsploraUrl is optional. When empty the scanner fetches blocks directly
	// from the node via JSON-RPC (node-RPC-only mode); when set it uses an
	// external Esplora HTTP endpoint instead. The filters and headers repos are
	// always node-RPC-backed, so no on-disk datadirs are needed here.
	EsploraUrl string
}

func (a ServiceArgs) validate() error {
	if a.RpcAddr == "" {
		return fmt.Errorf("missing elements node rpc address to connect to")
	}
	if a.Network == "" {
		return fmt.Errorf("missing network")
	}
	// EsploraUrl is optional: when empty the scanner uses the node-RPC block
	// service instead of Esplora. No datadir requirements: the filters/headers
	// repos are node-RPC-backed.
	return nil
}

func (a ServiceArgs) network() network.Network {
	if n, ok := seqnet.ByName(a.Network); ok {
		return n
	}
	return seqnet.SequentiaTestnet
}

func NewElementsScanner(args ServiceArgs) (ports.BlockchainScanner, error) {
	if err := args.validate(); err != nil {
		return nil, err
	}

	rpcClient, err := newRpcClient(args.RpcAddr, 5)
	if err != nil {
		return nil, err
	}
	filtersDb := newFiltersRepo(rpcClient)
	headersDb := newHeadersRepo(rpcClient)

	// Node-RPC-only by default: fetch blocks via JSON-RPC. Fall back to Esplora
	// only when an EsploraUrl is explicitly configured.
	var blockSvc blockservice.BlockService
	if args.EsploraUrl != "" {
		blockSvc = blockservice.NewEsploraBlockService(args.EsploraUrl)
	} else {
		blockSvc = NewRpcBlockService(rpcClient)
	}
	// Fetch the real genesis hash from the node rather than relying on the
	// hardcoded neutrino-elements checkpoints (which only know Liquid networks
	// and would otherwise yield a wrong genesis for Sequentia).
	genesisHash, err := fetchGenesisHash(headersDb)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch genesis block hash: %s", err)
	}

	scanners := make(map[string]*scannerService)
	lock := &sync.RWMutex{}
	return &service{
		args:        args,
		rpcClient:   rpcClient,
		blockSvc:    blockSvc,
		scanners:    scanners,
		genesisHash: genesisHash,
		filtersRepo: filtersDb,
		headersRepo: headersDb,
		lock:        lock,
		quit:        make(chan struct{}),
	}, nil
}

func (s *service) Start() {
	// Poll the node for new blocks and re-arm the watches when the chain tip
	// advances. The vendored neutrino-elements scanner is otherwise driven by a
	// P2P node pushing new blocks; in node-RPC-only mode nothing pushes blocks,
	// so without this poll a watch registered before funds arrive would never
	// rescan the blocks that contain them.
	s.tipTicker = time.NewTicker(2 * time.Second)
	go func() {
		for {
			select {
			case <-s.quit:
				return
			case <-s.tipTicker.C:
				s.maybeRescanOnNewTip()
			}
		}
	}()
}

func (s *service) Stop() {
	if s.tipTicker != nil {
		s.tipTicker.Stop()
	}
	close(s.quit)
}

// maybeRescanOnNewTip re-arms every active scanner from the previously-seen tip
// when the chain has grown. Re-watching overlapping ranges is safe: downstream
// UTXO storage is keyed by txid:vout and ignores duplicates.
func (s *service) maybeRescanOnNewTip() {
	tip, err := s.headersRepo.ChainTip(context.Background())
	if err != nil {
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if tip.Height <= s.lastTip {
		return
	}
	from := s.lastTip
	s.lastTip = tip.Height
	for _, scannerSvc := range s.scanners {
		scannerSvc.rescanFrom(from)
	}
}

func (s *service) GetUtxoChannel(accountName string) chan []*domain.Utxo {
	scannerSvc := s.getOrCreateScanner(accountName, 0)
	return scannerSvc.chUtxos
}

func (s *service) GetTxChannel(accountName string) chan *domain.Transaction {
	scannerSvc := s.getOrCreateScanner(accountName, 0)
	return scannerSvc.chTxs
}

func (s *service) WatchForAccount(
	accountName string, startingBlock uint32, addressesInfo []domain.AddressInfo,
) {
	scannerSvc := s.getOrCreateScanner(accountName, startingBlock)
	scannerSvc.watchAddresses(addressesInfo)
}

func (s *service) WatchForUtxos(
	accountName string, utxos []domain.UtxoInfo,
) {
	scannerSvc := s.getOrCreateScanner(accountName, 0)
	scannerSvc.watchUtxos(utxos)
}

func (s *service) RestoreAccount(
	accountIndex uint32, accountName, xpub string, masterBlindingKey []byte,
	startingBlockHeight, _ uint32,
) ([]domain.AddressInfo, []domain.AddressInfo, error) {
	return nil, nil, fmt.Errorf("not implemented")
}

func (s *service) StopWatchForAccount(accountName string) {
	scannerSvc := s.getOrCreateScanner(accountName, 0)
	scannerSvc.stop()
	s.removeScanner(accountName)
}

func (s *service) GetUtxos(utxoList []domain.Utxo) ([]domain.Utxo, error) {
	utxos := make([]domain.Utxo, 0, len(utxoList))
	for _, u := range utxoList {
		key := u.UtxoKey
		addr := addressFromScript(u.Script, s.args.network())
		if _, err := s.rpcClient.call(
			"importaddress", []interface{}{addr},
		); err != nil {
			return nil, err
		}

		var m map[string]interface{}
		for {
			resp, err := s.rpcClient.call("gettransaction", []interface{}{key.TxID})
			if err != nil {
				continue
			}
			m = resp.(map[string]interface{})
			break
		}

		txHex := m["hex"].(string)
		tx, _ := transaction.NewTxFromHex(txHex)

		out := tx.Outputs[key.VOut]
		utxo := domain.Utxo{
			UtxoKey: key,
			Script:  out.Script,
		}
		if out.IsConfidential() {
			utxo.AssetCommitment = out.Asset
			utxo.ValueCommitment = out.Value
			utxo.Nonce = out.Nonce
			utxo.RangeProof = out.RangeProof
			utxo.SurjectionProof = out.SurjectionProof
		} else {
			utxo.Asset = elementsutil.AssetHashFromBytes(out.Asset)
			utxo.Value, _ = elementsutil.ValueFromBytes(out.Value)
		}
		confirmations := m["confirmations"].(float64)
		if confirmations > 0 {
			blockHeight := uint64(m["blockheight"].(float64))
			blockTimestamp := int64(m["blocktime"].(float64))
			blockHash := m["blockhash"].(string)
			utxo.ConfirmedStatus = domain.UtxoStatus{
				BlockHeight: blockHeight,
				BlockTime:   blockTimestamp,
				BlockHash:   blockHash,
			}
		}
		utxos = append(utxos, utxo)
	}

	return utxos, nil
}

func (s *service) GetUtxosForAddresses(
	_ []domain.AddressInfo,
) ([]*domain.Utxo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) BroadcastTransaction(txHex string) (string, error) {
	if _, err := transaction.NewTxFromHex(txHex); err != nil {
		return "", fmt.Errorf("invalid tx: %s", err)
	}
	resp, err := s.rpcClient.call("sendrawtransaction", []interface{}{txHex})
	if err != nil {
		return "", err
	}
	txid := resp.(string)
	return txid, nil
}

func (s *service) GetTransactions(txids []string) ([]domain.Transaction, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *service) GetLatestBlock() ([]byte, uint32, error) {
	block, err := s.headersRepo.ChainTip(context.Background())
	if err != nil {
		return nil, 0, err
	}
	hash, _ := block.Hash()
	return hash.CloneBytes(), block.Height, nil
}

func (s *service) GetBlockHash(height uint32) ([]byte, error) {
	hash, err := s.headersRepo.GetBlockHashByHeight(context.Background(), height)
	if err != nil {
		return nil, err
	}
	return hash.CloneBytes(), nil
}

func (s *service) getOrCreateScanner(
	accountName string, startingBlock uint32,
) *scannerService {
	s.lock.Lock()
	defer s.lock.Unlock()

	if scannerSvc, ok := s.scanners[accountName]; ok {
		return scannerSvc
	}

	scannerSvc := newScannerSvc(
		accountName, startingBlock, s.filtersRepo, s.headersRepo, s.blockSvc,
		s.genesisHash,
	)
	s.scanners[accountName] = scannerSvc
	return scannerSvc
}

func (s *service) removeScanner(accountName string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.scanners, accountName)
}

// fetchGenesisHash returns the height-0 block hash as reported by the node.
func fetchGenesisHash(
	headersRepo repository.BlockHeaderRepository,
) (*chainhash.Hash, error) {
	return headersRepo.GetBlockHashByHeight(context.Background(), 0)
}

func addressFromScript(script []byte, net network.Network) string {
	switch scriptType := address.GetScriptType(script); scriptType {
	case address.P2PkhScript, address.P2ShScript:
		prefix := net.PubKeyHash
		scriptHash := script[3 : len(script)-2]
		if scriptType == address.P2ShScript {
			prefix = net.ScriptHash
			scriptHash = script[2 : len(script)-1]
		}
		return address.ToBase58(&address.Base58{
			Version: prefix,
			Data:    scriptHash,
		})
	default:
		addr, _ := address.ToBech32(&address.Bech32{
			Prefix:  net.Bech32,
			Version: script[0],
			Program: script[2:],
		})
		return addr
	}
}
