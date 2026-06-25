package xchain

import (
	"crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// Key is a regtest-only EC keypair used to sign HTLC spends on either leg.
// Both legs use ECDSA over secp256k1 with a DER-encoded signature plus a
// 1-byte SIGHASH_ALL flag, so a single Key type serves both btcd and
// go-elements signing.
type Key struct {
	priv *btcec.PrivateKey
	pub  *btcec.PublicKey
}

// NewKey generates a fresh random keypair (regtest only).
func NewKey() (*Key, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, err
	}
	priv, pub := btcec.PrivKeyFromBytes(buf[:])
	return &Key{priv: priv, pub: pub}, nil
}

// KeyFromBytes reconstructs a Key from 32 secret bytes (e.g. read from a
// regtest key file — never pass secrets on the command line).
func KeyFromBytes(b []byte) *Key {
	priv, pub := btcec.PrivKeyFromBytes(b)
	return &Key{priv: priv, pub: pub}
}

// PubKey returns the 33-byte compressed public key, as embedded in the HTLC
// redeemScript.
func (k *Key) PubKey() []byte { return k.pub.SerializeCompressed() }

// Bytes returns the 32-byte secret scalar (for persisting to a key file).
func (k *Key) Bytes() []byte { return k.priv.Serialize() }

// SignDER signs a 32-byte sighash and returns the DER-encoded signature WITHOUT
// the trailing sighash-type byte (the caller appends it, since the flag value
// is identical on both legs). Low-S is enforced by btcec, satisfying standard
// relay policy.
func (k *Key) SignDER(sighash []byte) []byte {
	return ecdsa.Sign(k.priv, sighash).Serialize()
}
