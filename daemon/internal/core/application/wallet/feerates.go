package wallet

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// exchangeRateScale mirrors the node's exchange_rate_scale (= COIN, 1e8): a fee
// asset's rate is "atoms of the asset equal to one reference unit", i.e. atoms
// of the asset per exchange_rate_scale native atoms. The native (policy) asset
// is valued 1:1 at exactly this scale.
const exchangeRateScale = 100_000_000

// feeRateProvider resolves an asset's open-fee-market exchange rate from the
// node: the integer getfeeexchangerates reports for the asset (atoms-of-asset
// per exchange_rate_scale native atoms). It returns (rate, true) only when the
// asset is fee-eligible (rate > 0); otherwise (0, false).
type feeRateProvider interface {
	FeeExchangeRate(assetHex string) (uint64, bool)
}

// nodeFeeRates reads the open fee-market whitelist from a Sequentia node over
// JSON-RPC (getfeeexchangerates). It reuses pkg/xchain's minimal RPC client so
// the wallet service gains no new RPC dependency.
type nodeFeeRates struct {
	rpc *xchain.RPC
}

// newNodeFeeRates builds a fee-rate provider from a node RPC url of the form
// http://user:pass@host:port. An empty url yields (nil, nil): the open fee
// market is disabled and swaps fall back to the native fee asset.
func newNodeFeeRates(rawURL string) (*nodeFeeRates, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse node rpc url: %w", err)
	}
	port, _ := strconv.Atoi(u.Port())
	pass, _ := u.User.Password()
	return &nodeFeeRates{
		rpc: xchain.NewRPC(u.Hostname(), port, u.User.Username(), pass),
	}, nil
}

// FeeExchangeRate queries getfeeexchangerates and returns the rate for assetHex.
// A node with an asset registry keys the rate map by human LABEL (e.g. "GOLD")
// rather than the asset hex, so we also pull dumpassetlabels (label -> hex) and
// resolve label-keyed entries back to their hex before matching. Any RPC error,
// a missing asset, or a non-positive rate yields (0, false) so callers fall back
// to the native fee asset.
func (n *nodeFeeRates) FeeExchangeRate(assetHex string) (uint64, bool) {
	if n == nil || n.rpc == nil {
		return 0, false
	}
	var rates map[string]int64
	if err := n.rpc.Call(&rates, "getfeeexchangerates"); err != nil {
		return 0, false
	}
	want := strings.ToLower(assetHex)
	// Best-effort label -> hex map; nil if the node has no labels (the rate keys
	// are then already hex) or doesn't support the call.
	var labels map[string]string
	_ = n.rpc.Call(&labels, "dumpassetlabels")
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

// feeExchangeRate returns the open-fee-market rate for asset (atoms-of-asset per
// exchange_rate_scale native atoms) and whether the asset is fee-eligible. The
// native asset is always eligible at 1:1. When no node RPC is configured, only
// the native asset is eligible (every other asset falls back to native).
func (s *Service) feeExchangeRate(asset string) (uint64, bool) {
	if asset == s.staticInfo.GetNativeAsset() {
		return exchangeRateScale, true
	}
	if s.rates == nil {
		return 0, false
	}
	return s.rates.FeeExchangeRate(asset)
}

// feeInAsset converts a native-denominated network fee (atoms) into feeAssetNet,
// rounding UP so the native-equivalent the node computes
// (native_equivalent = amount * rate / exchange_rate_scale) never underpays the
// required fee. rate is atoms-of-asset per exchange_rate_scale native atoms; a
// rate equal to exchange_rate_scale (native / 1:1) returns nativeFee unchanged.
func feeInAsset(nativeFee, rate uint64) uint64 {
	if rate == 0 {
		return nativeFee
	}
	return (nativeFee*exchangeRateScale + rate - 1) / rate
}
