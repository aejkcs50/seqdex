package xchain

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"
)

// ElementsLeg builds and spends a Design-A HTLC on an Elements-mode chain. Both
// swap legs use it:
//
//   - The "BTC" leg runs on the parent (anchor-source) node, paid in that
//     chain's pegged "bitcoin" asset. Although we call it the BTC leg, the
//     parent is an Elements node, so its transactions are Elements-serialized;
//     the HTLC is nonetheless an ordinary Bitcoin-Script P2SH HTLC (the same
//     OP_IF/OP_SHA256/OP_CLTV script), which elementsd evaluates unchanged. The
//     script + spend logic are byte-identical to a real Bitcoin HTLC; only the
//     transaction envelope is Elements.
//
//   - The "SEQ" leg runs on the anchored Sequentia node, paid in an issued
//     asset.
//
// We deliberately use explicit (UNCONFIDENTIAL) HTLC outputs — confidential
// outputs (CT/blinding) are unnecessary for this mechanism proof and would only
// complicate the sighash. The redeemScript is leg-agnostic; the only per-leg
// data is the asset id of the output.
//
// Script primitives (the redeemScript itself and the scriptSig assembly) come
// from btcd's txscript; the transaction body, the legacy sighash and value/
// asset serialization come from go-elements. This split mirrors the package
// brief: btcd for Bitcoin-Script, go-elements for the Sequentia/Elements tx.
type ElementsLeg struct {
	leg  Leg
	prim LockPrimitive
}

// NewElementsLeg returns a leg builder for the given chain side.
func NewElementsLeg(leg Leg, prim LockPrimitive) *ElementsLeg {
	return &ElementsLeg{leg: leg, prim: prim}
}

// Leg reports which side this builder serves.
func (l *ElementsLeg) Side() Leg { return l.leg }

// HTLCScript renders the redeemScript for the given pubkeys/CLTV locktime.
func (l *ElementsLeg) HTLCScript(claimPub, refundPub []byte, locktime uint32) ([]byte, error) {
	return l.prim.LockScript(claimPub, refundPub, locktime)
}

// ElementsSpendInput identifies the HTLC output being spent on an Elements leg.
type ElementsSpendInput struct {
	TxID    string // funding txid (big-endian display order)
	Vout    uint32
	Amount  uint64 // value of the HTLC output, in atoms
	AssetID string // 32-byte asset id, hex (big-endian display order)
	DestSPK []byte // scriptPubKey of the redeem/refund destination
	Fee     uint64 // fee in atoms; emitted as an explicit fee output (empty SPK)
}

// Redeem builds a signed redeem (IF-branch) spend revealing the preimage.
func (l *ElementsLeg) Redeem(redeemScript []byte, in ElementsSpendInput, key *Key) (string, error) {
	tx, err := l.buildSpendTx(in, 0, false)
	if err != nil {
		return "", err
	}
	sig, err := l.sign(tx, redeemScript, key)
	if err != nil {
		return "", err
	}
	items, err := l.prim.RedeemUnlockItems(sig)
	if err != nil {
		return "", err
	}
	return l.finalize(tx, redeemScript, items)
}

// Refund builds a signed refund (ELSE-branch) spend, valid once nLockTime
// reaches the CLTV locktime.
func (l *ElementsLeg) Refund(redeemScript []byte, in ElementsSpendInput, locktime uint32, key *Key) (string, error) {
	tx, err := l.buildSpendTx(in, locktime, true)
	if err != nil {
		return "", err
	}
	sig, err := l.sign(tx, redeemScript, key)
	if err != nil {
		return "", err
	}
	items, err := l.prim.RefundUnlockItems(sig)
	if err != nil {
		return "", err
	}
	return l.finalize(tx, redeemScript, items)
}

// buildSpendTx builds the unsigned spend skeleton shared by redeem and refund.
// Refund sets nLockTime + a non-final sequence (0xfffffffe) so CLTV passes;
// redeem uses a final sequence (0xffffffff) and nLockTime 0. Outputs are the
// recipient output and an explicit Elements fee output (empty scriptPubKey),
// both denominated in the input's asset.
func (l *ElementsLeg) buildSpendTx(in ElementsSpendInput, locktime uint32, refund bool) (*transaction.Transaction, error) {
	prevHash, err := elementsutil.TxIDToBytes(in.TxID)
	if err != nil {
		return nil, err
	}
	asset, err := elementsutil.AssetHashToBytes(in.AssetID)
	if err != nil {
		return nil, err
	}
	recvVal, err := elementsutil.ValueToBytes(in.Amount - in.Fee)
	if err != nil {
		return nil, err
	}
	feeVal, err := elementsutil.ValueToBytes(in.Fee)
	if err != nil {
		return nil, err
	}

	tx := transaction.NewTx(2)
	input := transaction.NewTxInput(prevHash, in.Vout)
	if refund {
		input.Sequence = 0xfffffffe // non-final: lets nLockTime/CLTV take effect
		tx.Locktime = locktime
	} else {
		input.Sequence = 0xffffffff
	}
	tx.AddInput(input)
	tx.AddOutput(transaction.NewTxOutput(asset, recvVal, in.DestSPK))
	tx.AddOutput(transaction.NewTxOutput(asset, feeVal, []byte{})) // explicit fee
	return tx, nil
}

// sign computes the Elements legacy SIGHASH_ALL sighash over the redeemScript
// and returns DER(sig) || SIGHASH_ALL. This is the same construction as
// swap-demo.py's LegacySignatureHash + sign_ecdsa.
func (l *ElementsLeg) sign(tx *transaction.Transaction, redeemScript []byte, key *Key) ([]byte, error) {
	sh, err := tx.HashForSignature(0, redeemScript, txscript.SigHashAll)
	if err != nil {
		return nil, err
	}
	return append(key.SignDER(sh[:]), byte(txscript.SigHashAll)), nil
}

// finalize assembles the P2SH scriptSig (<unlock items...> <redeemScript>) and
// returns the serialized Elements tx hex for sendrawtransaction.
func (l *ElementsLeg) finalize(tx *transaction.Transaction, redeemScript []byte, items [][]byte) (string, error) {
	b := txscript.NewScriptBuilder()
	for _, it := range items {
		if len(it) == 0 {
			b.AddOp(txscript.OP_0) // empty slice -> OP_FALSE (selects ELSE branch)
		} else {
			b.AddData(it)
		}
	}
	b.AddData(redeemScript)
	sigScript, err := b.Script()
	if err != nil {
		return "", err
	}
	tx.Inputs[0].Script = sigScript
	return tx.ToHex()
}

// P2SHHash160 returns hex(hash160(redeemScript)); handy for cross-checking the
// node's decodescript output. The funding P2SH address is obtained from the
// node via decodescript (see client.DecodeScriptP2SH) to avoid any address
// prefix mismatch.
func P2SHHash160(redeemScript []byte) string {
	return hex.EncodeToString(btcutil.Hash160(redeemScript))
}
