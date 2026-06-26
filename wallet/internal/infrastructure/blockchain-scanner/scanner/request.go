package scanner

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/google/uuid"
)

type ScanRequest struct {
	// ClientID of the client sending request
	ClientID uuid.UUID
	// StartHeight from which scan should be performed, nil means scan from genesis block
	StartHeight uint32
	// Item to watch
	Item WatchItem
	// IsPersistent if true, the request will be re-added with StartHeight = StartHeiht + 1
	IsPersistent bool
	// LastBlockHash is the hash of the last block this persistent request scanned
	// (the block at StartHeight-1). Used to detect a parent-chain reorg that orphaned
	// it and to roll the scan back to the canonical chain. Nil disables the check.
	LastBlockHash *chainhash.Hash
}

type ScanRequestOption func(req *ScanRequest)

func WithWatchItem(item WatchItem) ScanRequestOption {
	return func(req *ScanRequest) {
		req.Item = item
	}
}

func WithStartBlock(blockHeight uint32) ScanRequestOption {
	return func(req *ScanRequest) {
		req.StartHeight = blockHeight
	}
}

func WithPersistentWatch() ScanRequestOption {
	return func(req *ScanRequest) {
		req.IsPersistent = true
	}
}

func WithRequestID(id uuid.UUID) ScanRequestOption {
	return func(req *ScanRequest) {
		req.ClientID = id
	}
}

// WithLastBlockHash records the hash of the last block the request scanned, so a
// later reorg that orphans it can be detected and the scan rolled back.
func WithLastBlockHash(h *chainhash.Hash) ScanRequestOption {
	return func(req *ScanRequest) {
		req.LastBlockHash = h
	}
}

func newScanRequest(options ...ScanRequestOption) *ScanRequest {
	req := &ScanRequest{}
	for _, option := range options {
		option(req)
	}
	return req
}
