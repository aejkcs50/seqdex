package offer

// BTCSentinel is the canonical asset-id placeholder for the Bitcoin (parent-chain)
// side of a cross-chain offer. It is the literal "BTC" (matching the web wallet's
// existing sentinel), deliberately NOT a 64-hex Sequentia asset id so it can never
// collide with a real issued asset and is trivially distinguishable in a pair.
const BTCSentinel = "BTC"

// Cross-chain swap direction (CrossChainTerms.direction). Roles follow the proven
// pkg/xchain single-secret HTLC pattern:
//
//	DirBTCToAsset: the taker pays BTC and receives the SEQ asset; the maker SELLs the
//	  asset. The TAKER holds the secret (locks BTC first; the maker then locks the SEQ leg).
//	DirAssetToBTC: the taker pays the SEQ asset and receives BTC; the maker BUYs the
//	  asset. The MAKER holds the secret (locks BTC first; the taker then funds the SEQ leg).
const (
	DirBTCToAsset uint32 = 0
	DirAssetToBTC uint32 = 1
)

// IsBTCSentinel reports whether an asset id is the BTC sentinel.
func IsBTCSentinel(assetID string) bool { return assetID == BTCSentinel }

// DirectionConsistent checks that a cross-chain offer's direction matches its trade
// direction, for a cross-chain pair whose base is the SEQ asset and quote is the BTC
// sentinel: a SELL (maker gives the asset, wants BTC) is BTC_TO_ASSET (the taker pays
// BTC); a BUY (maker gives BTC, wants the asset) is ASSET_TO_BTC (the taker sells it).
func DirectionConsistent(direction uint32, isSell bool) bool {
	if isSell {
		return direction == DirBTCToAsset
	}
	return direction == DirAssetToBTC
}
