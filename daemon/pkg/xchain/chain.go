package xchain

import (
	"fmt"
	"math"
	"strings"
)

// Chain wraps an RPC client with the higher-level operations a swap leg needs
// on one Elements-mode node: funding an HTLC P2SH output, locating the funded
// vout, fetching destination scripts, mining, broadcasting, and (for the
// Sequentia leg) reading anchor metadata.
type Chain struct {
	rpc    *RPC
	wallet string
}

// NewChain binds a Chain to a node and its wallet name.
func NewChain(rpc *RPC, wallet string) *Chain {
	return &Chain{rpc: rpc.WithWallet(wallet), wallet: wallet}
}

// RPC exposes the underlying wallet-scoped client (for ad-hoc calls in tests).
func (c *Chain) RPC() *RPC { return c.rpc }

// BlockCount returns the current chain height.
func (c *Chain) BlockCount() (int64, error) {
	var n int64
	return n, c.rpc.Call(&n, "getblockcount")
}

// P2SHAddress asks the node to derive the P2SH address for a redeemScript.
// Using the node's own decodescript avoids any address-prefix mismatch between
// btcd/go-elements encodings and the node's network parameters.
func (c *Chain) P2SHAddress(redeemScript []byte) (string, error) {
	var res struct {
		P2SH string `json:"p2sh"`
	}
	if err := c.rpc.Call(&res, "decodescript", toHex(redeemScript)); err != nil {
		return "", err
	}
	if res.P2SH == "" {
		return "", fmt.Errorf("decodescript returned no p2sh address")
	}
	return res.P2SH, nil
}

// FundedHTLC is the outpoint + value + asset of a funded HTLC output.
type FundedHTLC struct {
	TxID    string
	Vout    uint32
	Amount  uint64 // atoms
	AssetID string
}

// LockHTLC pays `amountCoins` (a decimal string, e.g. "10") of the given asset
// to the HTLC's P2SH address and returns the funded outpoint. assetLabel may be
// "" to pay the chain's default (pegged "bitcoin") asset — that is how the BTC
// leg is funded.
func (c *Chain) LockHTLC(redeemScript []byte, amountCoins, assetLabel string) (*FundedHTLC, error) {
	p2sh, err := c.P2SHAddress(redeemScript)
	if err != nil {
		return nil, err
	}
	// The funding scriptPubKey we must match in the tx outputs.
	var va struct {
		ScriptPubKey string `json:"scriptPubKey"`
	}
	if err := c.rpc.Call(&va, "validateaddress", p2sh); err != nil {
		return nil, err
	}

	named := map[string]interface{}{"address": p2sh, "amount": amountCoins}
	if assetLabel != "" {
		named["assetlabel"] = assetLabel
	}
	var txid string
	if err := c.rpc.CallNamed(&txid, "sendtoaddress", named); err != nil {
		return nil, err
	}

	var raw struct {
		Vout []struct {
			Value        float64 `json:"value"`
			Asset        string  `json:"asset"`
			N            uint32  `json:"n"`
			ScriptPubKey struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return nil, err
	}
	for _, v := range raw.Vout {
		if v.ScriptPubKey.Hex == va.ScriptPubKey {
			return &FundedHTLC{
				TxID:    txid,
				Vout:    v.N,
				Amount:  coinsToAtoms(v.Value),
				AssetID: v.Asset,
			}, nil
		}
	}
	return nil, fmt.Errorf("HTLC output not found in funding tx %s", txid)
}

// NewDestScript returns a fresh address' scriptPubKey to receive a redeem/refund.
func (c *Chain) NewDestScript() ([]byte, error) {
	var addr string
	if err := c.rpc.Call(&addr, "getnewaddress"); err != nil {
		return nil, err
	}
	var va struct {
		ScriptPubKey string `json:"scriptPubKey"`
	}
	if err := c.rpc.Call(&va, "validateaddress", addr); err != nil {
		return nil, err
	}
	return fromHex(va.ScriptPubKey)
}

// Broadcast submits a raw tx hex and returns its txid.
func (c *Chain) Broadcast(rawHex string) (string, error) {
	var txid string
	return txid, c.rpc.Call(&txid, "sendrawtransaction", rawHex)
}

// TryBroadcast is like Broadcast but returns the node's rejection error (used by
// the negative refund-before-timeout test).
func (c *Chain) TryBroadcast(rawHex string) (string, error) {
	return c.Broadcast(rawHex)
}

// Mine generates n blocks to a fresh address in this wallet.
func (c *Chain) Mine(n int) error {
	var addr string
	if err := c.rpc.Call(&addr, "getnewaddress"); err != nil {
		return err
	}
	var hashes []string
	return c.rpc.Call(&hashes, "generatetoaddress", n, addr)
}

// BestBlockHash returns the current tip hash.
func (c *Chain) BestBlockHash() (string, error) {
	var h string
	return h, c.rpc.Call(&h, "getbestblockhash")
}

// Confirmations returns a wallet tx's confirmation count.
func (c *Chain) Confirmations(txid string) (int, error) {
	var tx struct {
		Confirmations int `json:"confirmations"`
	}
	if err := c.rpc.Call(&tx, "gettransaction", txid); err != nil {
		return 0, err
	}
	return tx.Confirmations, nil
}

// RedeemScriptSigContains reports whether the given on-chain spend's input 0
// scriptSig asm contains the hex needle (used to prove the preimage was
// revealed on-chain, so the counterparty can read it).
func (c *Chain) RedeemScriptSigContains(txid, needleHex string) (bool, string, error) {
	var raw struct {
		Vin []struct {
			ScriptSig struct {
				Asm string `json:"asm"`
				Hex string `json:"hex"`
			} `json:"scriptSig"`
		} `json:"vin"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return false, "", err
	}
	if len(raw.Vin) == 0 {
		return false, "", fmt.Errorf("tx %s has no inputs", txid)
	}
	asm := raw.Vin[0].ScriptSig.Asm
	hexv := raw.Vin[0].ScriptSig.Hex
	return strings.Contains(asm, needleHex) || strings.Contains(hexv, needleHex), asm, nil
}

// --- anchor metadata (Sequentia leg only) ---

// AnchorStatus is the subset of getanchorstatus we care about.
type AnchorStatus struct {
	ValidateAnchor bool   `json:"validateanchor"`
	TipHeight      int64  `json:"tipheight"`
	AnchorHeight   int64  `json:"anchorheight"`
	AnchorHash     string `json:"anchorhash"`
	AnchorStatus   string `json:"anchorstatus"`
}

// GetAnchorStatus reads the node's current anchor view.
func (c *Chain) GetAnchorStatus() (*AnchorStatus, error) {
	var s AnchorStatus
	return &s, c.rpc.Call(&s, "getanchorstatus")
}

// BlockAnchorHeight returns the anchorheight recorded in a Sequentia block
// header (getblockheader <hash> true). This is the per-block anchor commitment
// the SEQ-side claimant checks against the BTC-leg height.
func (c *Chain) BlockAnchorHeight(blockHash string) (int64, error) {
	var hdr struct {
		AnchorHeight int64 `json:"anchorheight"`
	}
	if err := c.rpc.Call(&hdr, "getblockheader", blockHash, true); err != nil {
		return 0, err
	}
	return hdr.AnchorHeight, nil
}

// BlockHashOfTx returns the block hash that confirmed a wallet tx (the SEQ-leg
// block whose anchorheight the orchestrator verifies).
func (c *Chain) BlockHashOfTx(txid string) (string, error) {
	var tx struct {
		BlockHash string `json:"blockhash"`
	}
	if err := c.rpc.Call(&tx, "gettransaction", txid); err != nil {
		return "", err
	}
	if tx.BlockHash == "" {
		return "", fmt.Errorf("tx %s is not confirmed (no blockhash)", txid)
	}
	return tx.BlockHash, nil
}

// PeggedAsset returns the chain's pegged "bitcoin" asset id (used as the BTC
// leg's asset when building spends).
func (c *Chain) PeggedAsset() (string, error) {
	var info struct {
		PeggedAsset string `json:"pegged_asset"`
	}
	if err := c.rpc.Call(&info, "getsidechaininfo"); err != nil {
		return "", err
	}
	return info.PeggedAsset, nil
}

const coin = 100_000_000

func coinsToAtoms(v float64) uint64 {
	return uint64(math.Round(v * coin))
}
