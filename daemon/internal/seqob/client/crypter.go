// Package client provides the maker + taker helpers that drive a SeqOB lift to
// settlement. The settlement itself REUSES the proven seqdex same-chain PSET
// co-sign (pkg/swap.{Request,Accept,Complete} + wallet.Service.CompleteSwap);
// nothing here rebuilds it.
//
// Because the relay courier is opaque and end-to-end encrypted (review B1), this
// package owns the E2E crypto: each peer derives a shared key by ECDH between its
// ephemeral session key and the peer's, and seals the inner swap message with
// AES-256-GCM. The relay only ever sees ciphertext.
package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Crypter seals/opens the inner swap payload for one session peer. The symmetric
// key is sha256(ECDH(myPriv, peerPub)) over secp256k1 (btcec, the repo's curve
// library). Both peers derive the same key because ECDH is symmetric.
type Crypter struct {
	aead cipher.AEAD
}

// NewCrypter derives the session AEAD from this peer's private session key and
// the counterparty's public session key.
func NewCrypter(myPriv *btcec.PrivateKey, peerPub *btcec.PublicKey) (*Crypter, error) {
	if myPriv == nil || peerPub == nil {
		return nil, errors.New("nil session key")
	}
	secret := btcec.GenerateSharedSecret(myPriv, peerPub)
	key := sha256.Sum256(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypter{aead: aead}, nil
}

// Seal encrypts plaintext, returning nonce||ciphertext.
func (c *Crypter) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts nonce||ciphertext produced by Seal under the matching key.
func (c *Crypter) Open(sealed []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return c.aead.Open(nil, sealed[:ns], sealed[ns:], nil)
}

// NewMakerCrypterFromLift derives a maker's per-lift E2E crypter from the maker's
// offer private key (its key doubles as its session key) and the taker's session
// pubkey, as delivered in From.lift_requested. The maker then drives the existing
// Maker.HandleRequest to open the taker's sealed SwapRequest and seal its accept.
func NewMakerCrypterFromLift(makerOfferPriv *btcec.PrivateKey, takerSessionPubkey []byte) (*Crypter, error) {
	if makerOfferPriv == nil {
		return nil, errors.New("nil maker key")
	}
	pub, err := btcec.ParsePubKey(takerSessionPubkey)
	if err != nil {
		return nil, err
	}
	return NewCrypter(makerOfferPriv, pub)
}
