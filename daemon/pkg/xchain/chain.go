package xchain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/btcsuite/btcd/txscript"
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

// FeeExchangeRate returns the node's any-asset fee exchange rate for assetHex (the
// integer getfeeexchangerates publishes: the asset's value in native-sats x 1e8),
// and whether a positive rate is published. The rate map may be keyed by human
// label (asset registry) rather than hex, so resolve labels via dumpassetlabels.
// Returns (0,false) on any RPC error / missing asset / non-positive rate so callers
// fall back to the native fee. Used to size an asset-denominated fee so its
// native-equivalent value stays within the node's relay fee bounds (maxfeerate).
func (c *Chain) FeeExchangeRate(assetHex string) (uint64, bool) {
	var rates map[string]int64
	if err := c.rpc.Call(&rates, "getfeeexchangerates"); err != nil {
		return 0, false
	}
	want := strings.ToLower(assetHex)
	var labels map[string]string // label -> hex; nil if the node has no registry
	_ = c.rpc.Call(&labels, "dumpassetlabels")
	for key, rate := range rates {
		if rate <= 0 {
			continue
		}
		if strings.ToLower(key) == want {
			return uint64(rate), true
		}
		if hexForLabel, ok := labels[key]; ok && strings.ToLower(hexForLabel) == want {
			return uint64(rate), true
		}
	}
	return 0, false
}

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

// TxConfirmations returns a tx's confirmation count via getrawtransaction, which
// (unlike gettransaction) works for txs the local wallet did not create — e.g.
// the taker-funded BTC leg the maker must verify. Returns 0 if unconfirmed.
func (c *Chain) TxConfirmations(txid string) (int, error) {
	var raw struct {
		Confirmations int `json:"confirmations"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return 0, err
	}
	return raw.Confirmations, nil
}

// ChainOutput is a tx output's value/asset/scriptPubKey, as the maker needs it
// to verify the taker's BTC-leg funding.
type ChainOutput struct {
	ValueAtoms      uint64
	AssetID         string
	ScriptPubKeyHex string
}

// OutputAt returns the (txid, vout) output of any on-chain tx.
func (c *Chain) OutputAt(txid string, vout uint32) (*ChainOutput, error) {
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
		if v.N == vout {
			return &ChainOutput{
				ValueAtoms:      coinsToAtoms(v.Value),
				AssetID:         v.Asset,
				ScriptPubKeyHex: v.ScriptPubKey.Hex,
			}, nil
		}
	}
	return nil, fmt.Errorf("tx %s has no vout %d", txid, vout)
}

// AddressScriptPubKey returns the hex scriptPubKey the node derives for an
// address (used to match the HTLC P2SH against the funded output).
func (c *Chain) AddressScriptPubKey(addr string) (string, error) {
	var va struct {
		ScriptPubKey string `json:"scriptPubKey"`
	}
	if err := c.rpc.Call(&va, "validateaddress", addr); err != nil {
		return "", err
	}
	return va.ScriptPubKey, nil
}

// SpenderOf reports the txid that spent the given outpoint, or "" if it is still
// unspent. The maker uses this to detect the taker's SEQ-leg claim: when the
// SEQ-leg output is spent, the spender's scriptSig carries the preimage.
//
// It uses gettxout (which returns null once an outpoint is spent) to learn that
// a spend happened, then scans the mempool + recent blocks for the spender.
func (c *Chain) SpenderOf(txid string, vout uint32) (string, error) {
	// gettxout returns null for spent (and unknown) outputs; a non-null result
	// means the outpoint is still in the UTXO set, i.e. NOT yet claimed.
	var utxo *struct {
		Confirmations int `json:"confirmations"`
	}
	if err := c.rpc.Call(&utxo, "gettxout", txid, vout, true); err != nil {
		return "", err
	}
	if utxo != nil {
		return "", nil // still unspent: not claimed yet
	}

	// Spent. Find the spender: check the mempool first, then walk back from the
	// tip until we find the tx whose input references (txid, vout).
	spends := func(spenderTxid string) (bool, error) {
		var raw struct {
			Vin []struct {
				TxID string `json:"txid"`
				Vout uint32 `json:"vout"`
			} `json:"vin"`
		}
		if err := c.rpc.Call(&raw, "getrawtransaction", spenderTxid, true); err != nil {
			return false, nil // ignore txs we cannot fetch
		}
		for _, in := range raw.Vin {
			if in.TxID == txid && in.Vout == vout {
				return true, nil
			}
		}
		return false, nil
	}

	// 1) mempool.
	var mempool []string
	if err := c.rpc.Call(&mempool, "getrawmempool"); err == nil {
		for _, mt := range mempool {
			if ok, _ := spends(mt); ok {
				return mt, nil
			}
		}
	}

	// 2) recent blocks (most recent first). The claim is expected within a few
	// blocks on regtest; scan a bounded window.
	height, err := c.BlockCount()
	if err != nil {
		return "", err
	}
	const scanWindow = 50
	for h := height; h >= 0 && h > height-scanWindow; h-- {
		var bh string
		if err := c.rpc.Call(&bh, "getblockhash", h); err != nil {
			break
		}
		var blk struct {
			Tx []string `json:"tx"`
		}
		if err := c.rpc.Call(&blk, "getblock", bh); err != nil {
			continue
		}
		for _, bt := range blk.Tx {
			if ok, _ := spends(bt); ok {
				return bt, nil
			}
		}
	}
	return "", fmt.Errorf("outpoint %s:%d is spent but spender not found in mempool or last %d blocks", txid, vout, scanWindow)
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

// ExtractPreimage reads the preimage off a redeem spend's input-0 scriptSig.
// This is the maker's secret-extraction step: the daemon watches the SEQ chain
// for the taker's claim, then recovers the preimage `s` (the data push whose
// sha256 equals the swap's hashlock H) so it can claim the BTC leg with it.
//
// It tokenizes every input's scriptSig and returns the first pushed data item
// whose SHA256 equals wantHash. Returning the raw bytes (rather than a
// contains-check) is what lets the maker actually USE the secret.
func (c *Chain) ExtractPreimage(txid string, wantHash []byte) ([]byte, error) {
	var raw struct {
		Vin []struct {
			ScriptSig struct {
				Hex string `json:"hex"`
			} `json:"scriptSig"`
		} `json:"vin"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return nil, err
	}
	for _, vin := range raw.Vin {
		if vin.ScriptSig.Hex == "" {
			continue
		}
		sig, err := fromHex(vin.ScriptSig.Hex)
		if err != nil {
			continue
		}
		items, err := pushedData(sig)
		if err != nil {
			continue
		}
		for _, it := range items {
			h := sha256.Sum256(it)
			if bytes.Equal(h[:], wantHash) {
				return it, nil
			}
		}
	}
	return nil, fmt.Errorf("preimage for hash %s not found in tx %s scriptSig", toHex(wantHash), txid)
}

// pushedData tokenizes a scriptSig and returns its data pushes (in order),
// skipping opcodes. Used by ExtractPreimage to scan for the preimage.
func pushedData(script []byte) ([][]byte, error) {
	tok := txscript.MakeScriptTokenizer(0, script)
	var out [][]byte
	for tok.Next() {
		if d := tok.Data(); d != nil {
			out = append(out, d)
		}
	}
	return out, tok.Err()
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

// BlockHashOfTx returns the block hash that confirmed a tx (the SEQ-leg block
// whose anchorheight the orchestrator verifies). Uses getrawtransaction so it works
// for txs the local wallet did NOT create — e.g. the taker-funded SEQ leg the reverse
// maker must verify; gettransaction errors -5 ("Invalid or non-wallet transaction id")
// on a non-wallet txid. Relies on the node's txindex (the DEX node has it).
func (c *Chain) BlockHashOfTx(txid string) (string, error) {
	var tx struct {
		BlockHash string `json:"blockhash"`
	}
	if err := c.rpc.Call(&tx, "getrawtransaction", txid, true); err != nil {
		return "", err
	}
	if tx.BlockHash == "" {
		return "", fmt.Errorf("tx %s is not confirmed (no blockhash)", txid)
	}
	return tx.BlockHash, nil
}

// AssetBalance returns the wallet's confirmed balance of an asset, in atoms.
// assetID may be "" to query the default pegged "bitcoin" asset (the BTC leg's
// reserve). For an issued SEQ asset, pass its hex id. Uses getbalance with an
// explicit asset to avoid pulling in confidential-balance machinery.
func (c *Chain) AssetBalance(assetID string) (uint64, error) {
	// getbalance "*" minconf include_watchonly avoid_reuse assetlabel
	// The Elements RPC accepts the asset id directly as the assetlabel arg.
	asset := assetID
	if asset == "" {
		asset = "bitcoin"
	}
	var bal float64
	if err := c.rpc.Call(&bal, "getbalance", "*", 1, false, false, asset); err != nil {
		return 0, err
	}
	return coinsToAtoms(bal), nil
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
