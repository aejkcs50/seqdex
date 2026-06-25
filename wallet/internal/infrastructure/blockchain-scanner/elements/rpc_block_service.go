package elements_scanner

import (
	"bytes"
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/block"
	"github.com/vulpemventures/neutrino-elements/pkg/blockservice"
)

// rpcBlockService implements blockservice.BlockService backed by an Elements/
// Sequentia node JSON-RPC connection. It is the node-RPC-only alternative to
// the Esplora-backed block service, removing the dependency on an external
// Esplora HTTP endpoint.
type rpcBlockService struct {
	rpcClient *rpcClient
}

var _ blockservice.BlockService = (*rpcBlockService)(nil)

// NewRpcBlockService returns a blockservice.BlockService that fetches raw
// blocks from the node via `getblock <hash> 0`.
func NewRpcBlockService(rpcClient *rpcClient) blockservice.BlockService {
	return &rpcBlockService{rpcClient: rpcClient}
}

func (b *rpcBlockService) GetBlock(
	hash *chainhash.Hash,
) (*block.Block, error) {
	// verbosity 0 -> raw block, serialized as a hex string.
	resp, err := b.rpcClient.call(
		"getblock", []interface{}{hash.String(), 0},
	)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, blockservice.ErrorBlockNotFound
		}
		return nil, err
	}

	rawHex, ok := resp.(string)
	if !ok {
		return nil, blockservice.ErrorBlockNotFound
	}

	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, err
	}

	return block.NewFromBuffer(bytes.NewBuffer(raw))
}

func isNotFoundErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "block not found")
}
