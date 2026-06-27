package xchainmaker

import "time"

// refPriceTTL bounds how often the maker re-reads the SEQ node's reference prices.
const refPriceTTL = 30 * time.Second

// refreshPrices refreshes the cached reference USD prices (and the asset-label map)
// from the SEQ node, at most once per refPriceTTL. The reference prices are the
// price-server-fed feed the node exposes via getreferenceprices; the maker reuses
// that single source rather than introducing its own. Best-effort: on any RPC
// error the previous cache is kept and callers fall back to the static price.
func (s *Service) refreshPrices() {
	s.priceMu.RLock()
	fresh := s.refPrices != nil && time.Since(s.refFetched) < refPriceTTL
	s.priceMu.RUnlock()
	if fresh {
		return
	}
	var ref map[string]float64
	if err := s.cfg.SEQ.RPC().Call(&ref, "getreferenceprices"); err != nil || len(ref) == 0 {
		return
	}
	var labels map[string]string // label -> hex
	_ = s.cfg.SEQ.RPC().Call(&labels, "dumpassetlabels")
	hex2label := make(map[string]string, len(labels))
	for lbl, h := range labels {
		hex2label[h] = lbl
	}
	s.priceMu.Lock()
	s.refPrices = ref
	s.hex2label = hex2label
	s.refFetched = time.Now()
	s.priceMu.Unlock()
}

// effectivePrice returns the maker's price for a market in SEQ-asset atoms per BTC
// atom. It prefers the SEQ node's live reference prices (ref[BTC]/ref[asset], which
// both carry the same 1e8 atom scale so it cancels); when those are unavailable it
// falls back to the market's static configured PriceSeqPerBtc.
func (s *Service) effectivePrice(m Market) float64 {
	s.refreshPrices()
	s.priceMu.RLock()
	ref, hex2label := s.refPrices, s.hex2label
	s.priceMu.RUnlock()
	if ref == nil {
		return m.PriceSeqPerBtc
	}
	btc, ok := ref["BTC"]
	if !ok || btc <= 0 {
		return m.PriceSeqPerBtc
	}
	sym := hex2label[m.SeqAsset]
	if sym == "bitcoin" {
		sym = "SEQ" // the native asset is labelled "bitcoin" but priced as "SEQ"
	} else if sym == "" {
		return m.PriceSeqPerBtc // unknown asset: keep the static price
	}
	px, ok := ref[sym]
	if !ok || px <= 0 {
		return m.PriceSeqPerBtc
	}
	return btc / px
}
