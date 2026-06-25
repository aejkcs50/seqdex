package seqnet

import (
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
)

// The go-elements high-level address helpers (address.FromConfidential,
// address.ToConfidential, address.ToOutputScript) hardcode the Liquid network
// HRPs ("ex"/"lq", "ert"/"el", "tex"/"tlq") via NetworkForAddress / DecodeType
// and therefore reject every Sequentia address (HRPs "bc"/"sqb", "bcrt", ...).
// The helpers below re-implement the same behaviour using the explicit-HRP
// low-level primitives (FromBech32/ToBech32/FromBlech32/ToBlech32 + base58)
// against an explicitly supplied Sequentia network, mirroring the working
// pattern already used in the elements blockchain scanner.

// AddressInfo mirrors address.AddressInfo: the unconfidential address, its
// output script and (for confidential addresses) the blinding public key.
type AddressInfo struct {
	Address     string
	Script      []byte
	BlindingKey []byte
}

// FromConfidential decodes a confidential Sequentia address into its blinding
// public key and the output script of the embedded unconfidential address.
// It is the network-aware replacement for address.FromConfidential.
func FromConfidential(addr string, net *network.Network) (*AddressInfo, error) {
	// Native-segwit confidential addresses (blech32).
	if hasSegwitPrefix(addr, net.Blech32) {
		if bl, err := address.FromBlech32(addr); err == nil {
			script, err := segwitScript(bl.Version, bl.Program)
			if err != nil {
				return nil, err
			}
			return &AddressInfo{Script: script, BlindingKey: bl.PublicKey}, nil
		}
		// On regtest Blech32 == Bech32 ("bcrt"): a failed blech32 decode means
		// this is actually an unconfidential bech32 address, which is not
		// confidential -> fall through to the base58 attempt below, which fails.
	}

	// Legacy / wrapped-segwit confidential addresses (base58).
	b58, err := address.FromBase58Confidential(addr)
	if err != nil {
		return nil, err
	}
	script, err := base58ConfidentialScript(b58, net)
	if err != nil {
		return nil, err
	}
	return &AddressInfo{Script: script, BlindingKey: b58.PublicKey}, nil
}

// ToOutputScript builds the output script for any (confidential or not)
// Sequentia address. It is the network-aware replacement for
// address.ToOutputScript.
func ToOutputScript(addr string, net *network.Network) ([]byte, error) {
	// Native-segwit (bech32 unconfidential / blech32 confidential). On regtest
	// the two HRPs collide ("bcrt"), so try the confidential (blech32) decode
	// first and fall back to the unconfidential (bech32) decode.
	if hasSegwitPrefix(addr, net.Blech32) {
		if bl, err := address.FromBlech32(addr); err == nil {
			return segwitScript(bl.Version, bl.Program)
		}
	}
	if hasSegwitPrefix(addr, net.Bech32) {
		if bc, err := address.FromBech32(addr); err == nil {
			return segwitScript(bc.Version, bc.Program)
		}
	}

	// base58: legacy p2pkh / p2sh, possibly confidential.
	decoded, version, err := base58.CheckDecode(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}
	switch version {
	case net.PubKeyHash:
		return p2pkhScript(decoded)
	case net.ScriptHash:
		return p2shScript(decoded)
	case net.Confidential:
		// confidential base58: [prefix byte][33-byte blinding key][hash...]
		b58, err := address.FromBase58Confidential(addr)
		if err != nil {
			return nil, err
		}
		return base58ConfidentialScript(b58, net)
	default:
		return nil, fmt.Errorf("unsupported address version %d", version)
	}
}

// IsConfidential reports whether the given address is a confidential Sequentia
// address. It is the network-aware replacement for address.IsConfidential.
func IsConfidential(addr string, net *network.Network) (bool, error) {
	// On regtest Blech32 == Bech32 ("bcrt"), so disambiguate by attempting the
	// blech32 (confidential) decode: it only succeeds on a real blech32 address
	// because it requires the embedded 33-byte blinding key.
	if hasSegwitPrefix(addr, net.Blech32) {
		if _, err := address.FromBlech32(addr); err == nil {
			return true, nil
		}
	}
	if hasSegwitPrefix(addr, net.Bech32) {
		if _, err := address.FromBech32(addr); err == nil {
			return false, nil
		}
	}

	_, version, err := base58.CheckDecode(addr)
	if err != nil {
		return false, fmt.Errorf("invalid address: %s", err)
	}
	switch version {
	case net.PubKeyHash, net.ScriptHash:
		return false, nil
	case net.Confidential:
		return true, nil
	default:
		return false, fmt.Errorf("unsupported address version %d", version)
	}
}

// hasSegwitPrefix reports whether addr is a native-segwit address with the given
// (non-empty) HRP.
func hasSegwitPrefix(addr, hrp string) bool {
	return hrp != "" && strings.HasPrefix(addr, hrp+"1")
}

// ToConfidential builds a confidential Sequentia address from an unconfidential
// address and a blinding public key. It is the network-aware replacement for
// address.ToConfidential.
func ToConfidential(info *AddressInfo, net *network.Network) (string, error) {
	if strings.HasPrefix(info.Address, net.Bech32+"1") {
		bc, err := address.FromBech32(info.Address)
		if err != nil {
			return "", err
		}
		return address.ToBlech32(&address.Blech32{
			Prefix:    net.Blech32,
			Version:   bc.Version,
			Program:   bc.Program,
			PublicKey: info.BlindingKey,
		})
	}

	b58, err := address.FromBase58(info.Address)
	if err != nil {
		return "", err
	}
	return address.ToBase58Confidential(&address.Base58Confidential{
		Base58:    *b58,
		Version:   net.Confidential,
		PublicKey: info.BlindingKey,
	}), nil
}

// segwitScript assembles a native-segwit output script (OP_<version> <program>).
func segwitScript(version byte, program []byte) ([]byte, error) {
	versionOpcode := byte(txscript.OP_0)
	if version == 1 {
		versionOpcode = txscript.OP_1
	}
	return txscript.NewScriptBuilder().
		AddOp(versionOpcode).
		AddData(program).
		Script()
}

func p2pkhScript(pubKeyHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(pubKeyHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

func p2shScript(scriptHash []byte) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(scriptHash).
		AddOp(txscript.OP_EQUAL).
		Script()
}

// base58ConfidentialScript builds the output script for a base58 confidential
// address. The embedded unconfidential hash is the trailing 20 bytes; whether
// it is a p2pkh or p2sh is decided by the underlying base58 version.
func base58ConfidentialScript(
	b58 *address.Base58Confidential, net *network.Network,
) ([]byte, error) {
	hash := b58.Base58.Data
	switch b58.Base58.Version {
	case net.PubKeyHash:
		return p2pkhScript(hash)
	case net.ScriptHash:
		return p2shScript(hash)
	default:
		return nil, fmt.Errorf(
			"unsupported confidential base58 version %d", b58.Base58.Version,
		)
	}
}
