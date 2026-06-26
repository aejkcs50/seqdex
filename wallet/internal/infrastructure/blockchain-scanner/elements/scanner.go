package elements_scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aejkcs50/seqdex/wallet/internal/core/domain"
	"github.com/aejkcs50/seqdex/wallet/internal/infrastructure/blockchain-scanner/scanner"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	log "github.com/sirupsen/logrus"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
	"github.com/vulpemventures/neutrino-elements/pkg/blockservice"
	"github.com/vulpemventures/neutrino-elements/pkg/repository"
)

// unspentWatchItem is a scanner.WatchItem that matches an output by its exact
// output script. It replaces scanner.NewUnspentWatchItemFromAddress, whose
// internal address.ToOutputScript hardcodes the Liquid network HRPs and so
// silently returns a nil item for Sequentia addresses (causing a nil-pointer
// panic in the scanner). We build the item directly from the wallet-derived
// output script, which is HRP-agnostic.
type unspentWatchItem struct {
	outputScript []byte
}

func (u *unspentWatchItem) Bytes() []byte { return u.outputScript }

func (u *unspentWatchItem) Match(tx *transaction.Transaction) bool {
	for _, out := range tx.Outputs {
		if bytes.Equal(u.outputScript, out.Script) {
			return true
		}
	}
	return false
}

func (u *unspentWatchItem) EventType() scanner.EventType {
	return scanner.UnspentUtxo
}

type scannerService struct {
	accountName         string
	svc                 scanner.Service
	blindingKeys        map[string][]byte
	watchedScripts      map[string][]byte // script hex -> decoded output script
	startingBlockHeight uint32
	chTxs               chan *domain.Transaction
	chUtxos             chan []*domain.Utxo
	lock                *sync.RWMutex

	log  func(format string, a ...interface{})
	warn func(err error, format string, a ...interface{})
}

func newScannerSvc(
	accountName string,
	startingBlockHeight uint32,
	filtersDb repository.FilterRepository,
	headersDb repository.BlockHeaderRepository,
	blockSvc blockservice.BlockService, genesisHash *chainhash.Hash,
) *scannerService {
	logFn := func(format string, a ...interface{}) {
		format = fmt.Sprintf("scanner: %s", format)
		log.Debugf(format, a...)
	}
	warnFn := func(err error, format string, a ...interface{}) {
		format = fmt.Sprintf("scanner: %s", format)
		log.WithError(err).Warnf(format, a...)
	}
	scannerSvc := &scannerService{
		accountName:         accountName,
		svc:                 scanner.New(filtersDb, headersDb, blockSvc, genesisHash),
		blindingKeys:        make(map[string][]byte),
		watchedScripts:      make(map[string][]byte),
		startingBlockHeight: startingBlockHeight,
		chTxs:               make(chan *domain.Transaction, 10),
		chUtxos:             make(chan []*domain.Utxo, 10),
		lock:                &sync.RWMutex{},
		log:                 logFn,
		warn:                warnFn,
	}
	chReports, _ := scannerSvc.svc.Start()
	go scannerSvc.listenToReports(chReports)
	return scannerSvc
}

func (s *scannerService) stop() {
	s.svc.Stop()
	close(s.chTxs)
	close(s.chUtxos)
}

func (s *scannerService) watchAddresses(addressesInfo []domain.AddressInfo) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, info := range addressesInfo {
		// Prevent duplicates
		if _, ok := s.blindingKeys[info.Script]; ok {
			continue
		}

		s.blindingKeys[info.Script] = info.BlindingKey
		script, err := hex.DecodeString(info.Script)
		if err != nil || len(script) == 0 {
			s.warn(err, "skip watching address with invalid script %q", info.Script)
			continue
		}
		s.watchedScripts[info.Script] = script
		s.svc.Watch(
			scanner.WithWatchItem(&unspentWatchItem{outputScript: script}),
			scanner.WithStartBlock(s.startingBlockHeight),
			scanner.WithPersistentWatch(),
		)
		s.log(
			"start watching address %s for account %s",
			info.DerivationPath, s.accountName,
		)
	}
}

// rescanFrom re-arms all watched addresses starting at the given block height,
// waking the scanner queue so that blocks appended after the initial watch are
// scanned. Overlapping rescans are harmless: UTXO storage is keyed by txid:vout.
func (s *scannerService) rescanFrom(fromHeight uint32) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	for _, script := range s.watchedScripts {
		s.svc.Watch(
			scanner.WithWatchItem(&unspentWatchItem{outputScript: script}),
			scanner.WithStartBlock(fromHeight),
			scanner.WithPersistentWatch(),
		)
	}
	if len(s.watchedScripts) > 0 {
		s.log(
			"rescan %d address(es) from block %d for account %s",
			len(s.watchedScripts), fromHeight, s.accountName,
		)
	}
}

func (s *scannerService) watchUtxos(utxos []domain.UtxoInfo) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, u := range utxos {
		hash, _ := elementsutil.TxIDToBytes(u.TxID)
		item, _ := scanner.NewSpentWatchItemFromInput(
			&transaction.TxInput{Hash: hash, Index: u.VOut}, u.Script,
		)
		s.svc.Watch(
			scanner.WithWatchItem(item),
			scanner.WithStartBlock(s.startingBlockHeight),
		)

		s.log("start watching utxo %s for account %s", u, s.accountName)
	}
}

func (s *scannerService) listenToReports(chReports <-chan scanner.Report) {
	s.log("start listening to incoming reports from node")
	for r := range chReports {
		time.Sleep(time.Millisecond)

		if r.Transaction == nil {
			continue
		}

		tx := r.Transaction
		txid := tx.TxHash().String()
		txHex, _ := tx.ToHex()

		s.log("received report for tx %s", txid)

		var blockHash string
		var blockHeight uint64
		if r.BlockHash != nil {
			blockHash = r.BlockHash.String()
			blockHeight = uint64(r.BlockHeight)
		}
		select {
		case s.chTxs <- &domain.Transaction{
			TxID:  txid,
			TxHex: txHex,
			Accounts: map[string]struct{}{
				s.accountName: {},
			},
			BlockHash:   blockHash,
			BlockHeight: blockHeight,
		}:
		default:
		}

		spentUtxos := make([]*domain.Utxo, 0, len(tx.Inputs))
		for _, in := range tx.Inputs {
			spentUtxos = append(spentUtxos, &domain.Utxo{
				UtxoKey: domain.UtxoKey{
					TxID: elementsutil.TxIDFromBytes(in.Hash),
					VOut: in.Index,
				},
				SpentStatus: domain.UtxoStatus{
					Txid:        txid,
					BlockHeight: blockHeight,
					BlockHash:   blockHash,
				},
			})
		}
		select {
		case s.chUtxos <- spentUtxos:
		default:
		}

		newUtxos := make([]*domain.Utxo, 0)
		for i, out := range tx.Outputs {
			if len(out.Script) == 0 {
				continue
			}

			script := hex.EncodeToString(out.Script)
			blindingKey, ok := s.getBlindingKey(script)
			if !ok {
				continue
			}

			revealed, err := confidential.UnblindOutputWithKey(out, blindingKey)
			if err != nil {
				s.warn(err, "failed to unblind utxo with given blinding key")
				continue
			}

			var assetCommitment, valueCommitment []byte
			if out.IsConfidential() {
				valueCommitment, assetCommitment = out.Value, out.Asset
			}

			newUtxos = append(newUtxos, &domain.Utxo{
				UtxoKey: domain.UtxoKey{
					TxID: txid,
					VOut: uint32(i),
				},
				Value:           revealed.Value,
				Asset:           assetFromBytes(revealed.Asset),
				ValueCommitment: valueCommitment,
				AssetCommitment: assetCommitment,
				ValueBlinder:    revealed.ValueBlindingFactor,
				AssetBlinder:    revealed.AssetBlindingFactor,
				Script:          out.Script,
				Nonce:           out.Nonce,
				RangeProof:      out.RangeProof,
				SurjectionProof: out.SurjectionProof,
				AccountName:     s.accountName,
				ConfirmedStatus: domain.UtxoStatus{
					BlockHeight: blockHeight,
					BlockHash:   blockHash,
				},
			})
		}

		if len(newUtxos) > 0 {
			select {
			case s.chUtxos <- newUtxos:
			default:
			}
		}
	}
}

func (s *scannerService) getBlindingKey(script string) ([]byte, bool) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	key, ok := s.blindingKeys[script]
	return key, ok
}

func assetFromBytes(buf []byte) string {
	return hex.EncodeToString(elementsutil.ReverseBytes(buf))
}
