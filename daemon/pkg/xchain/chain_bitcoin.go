package xchain

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// BitcoinChain is the maker's view of the REAL Bitcoin parent (bitcoind regtest
// or testnet4). It is the Bitcoin-format analog of Chain (chain.go, which is
// Elements-format): it talks to a genuine bitcoind over the same JSON-RPC
// plumbing (RPC) but parses Bitcoin transactions — 8-byte satoshi values, no
// asset commitments — and derives the HTLC P2SH address itself via btcd rather
// than via Elements decodescript.
//
// Only the calls the maker's BTC leg needs are implemented: read the raw
// funding tx + its confirmations (to VERIFY the taker's HTLC), broadcast the
// claim, learn the destination scriptPubKey, the height, and detect the
// taker's SEQ-side claim is NOT here — that stays on the SEQ (Elements) Chain.
type BitcoinChain struct {
	rpc    *RPC
	params *chaincfg.Params
	// feeRateSatVb, when > 0, is passed as sendtoaddress's fee_rate (sat/vB) when
	// funding an HTLC leg, so the daemon sets its own fee instead of relying on
	// the node's estimatesmartfee (unavailable on sparse testnet4 without
	// -fallbackfee) or a manual settxfee. 0 keeps the node's default behavior.
	feeRateSatVb float64
}

// SetFeeRate sets the sat/vB fee rate used when funding HTLC legs.
func (c *BitcoinChain) SetFeeRate(satVb float64) { c.feeRateSatVb = satVb }

// FeeRate returns the configured HTLC funding fee rate (sat/vB), 0 if unset.
func (c *BitcoinChain) FeeRate() float64 { return c.feeRateSatVb }

// NewBitcoinChain binds a BitcoinChain to a bitcoind RPC + wallet and chain
// params (regtest/testnet4). The wallet is used for getnewaddress
// (claim destination) and, on regtest, generatetoaddress/sendtoaddress in the
// verification harness; HTLC verification/claim themselves are wallet-agnostic.
func NewBitcoinChain(rpc *RPC, wallet string, params *chaincfg.Params) *BitcoinChain {
	return &BitcoinChain{rpc: rpc.WithWallet(wallet), params: params}
}

// RPC exposes the underlying wallet-scoped client (for the harness / ad-hoc).
func (c *BitcoinChain) RPC() *RPC { return c.rpc }

// Params returns the chain params this BTC leg uses.
func (c *BitcoinChain) Params() *chaincfg.Params { return c.params }

// BlockCount returns the current Bitcoin chain height.
func (c *BitcoinChain) BlockCount() (int64, error) {
	var n int64
	return n, c.rpc.Call(&n, "getblockcount")
}

// RawTx fetches a transaction's raw (Bitcoin-serialized) hex via
// getrawtransaction <txid> false. Works for any tx the node has indexed
// (txindex) or that is in a wallet/mempool — including the taker-funded HTLC the
// maker did not create.
func (c *BitcoinChain) RawTx(txid string) (string, error) {
	var raw string
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, false); err != nil {
		return "", err
	}
	return raw, nil
}

// TxConfirmations returns a tx's confirmation count via the verbose
// getrawtransaction (Bitcoin returns "confirmations" only when the tx is in a
// block or watched; 0/absent => unconfirmed).
func (c *BitcoinChain) TxConfirmations(txid string) (int, error) {
	var raw struct {
		Confirmations int `json:"confirmations"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return 0, err
	}
	return raw.Confirmations, nil
}

// RawTxAndConfirmations returns both the raw hex and the confirmation count in
// one verbose getrawtransaction (the maker needs both to VerifyFundedHTLC).
func (c *BitcoinChain) RawTxAndConfirmations(txid string) (string, int, error) {
	var raw struct {
		Hex           string `json:"hex"`
		Confirmations int    `json:"confirmations"`
	}
	if err := c.rpc.Call(&raw, "getrawtransaction", txid, true); err != nil {
		return "", 0, err
	}
	return raw.Hex, raw.Confirmations, nil
}

// Broadcast submits a raw Bitcoin tx hex and returns its txid.
func (c *BitcoinChain) Broadcast(rawHex string) (string, error) {
	var txid string
	return txid, c.rpc.Call(&txid, "sendrawtransaction", rawHex)
}

// NewDestScript returns a fresh wallet address' scriptPubKey for the maker to
// receive its claimed BTC, derived locally from the address (no Elements
// validateaddress dependency). It accepts any standard Bitcoin address type the
// wallet hands out (P2PKH, P2SH, bech32 v0/v1).
func (c *BitcoinChain) NewDestScript() ([]byte, error) {
	var addr string
	if err := c.rpc.Call(&addr, "getnewaddress"); err != nil {
		return nil, err
	}
	return c.AddressScript(addr)
}

// AddressScript decodes a Bitcoin address (under this chain's params) and
// returns its scriptPubKey.
func (c *BitcoinChain) AddressScript(addr string) ([]byte, error) {
	a, err := btcutil.DecodeAddress(addr, c.params)
	if err != nil {
		return nil, fmt.Errorf("decode address %q: %w", addr, err)
	}
	if !a.IsForNet(c.params) {
		return nil, fmt.Errorf("address %q not valid for %s", addr, c.params.Name)
	}
	return txscript.PayToAddrScript(a)
}

// Confirmations returns the number of confirmations of a Bitcoin tx via the
// wallet's gettransaction (works for wallet txs only); used by the harness.
func (c *BitcoinChain) Confirmations(txid string) (int, error) {
	var tx struct {
		Confirmations int `json:"confirmations"`
	}
	if err := c.rpc.Call(&tx, "gettransaction", txid); err != nil {
		return 0, err
	}
	return tx.Confirmations, nil
}
