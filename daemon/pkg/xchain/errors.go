package xchain

import "errors"

var (
	// errNoSecret is returned when a redeem spend is requested but the
	// HashLock holds only the hash, not the preimage.
	errNoSecret = errors.New("xchain: hashlock has no secret/preimage to build a redeem spend")

	// ErrAnchorOrdering is returned by the orchestrator when the Sequentia leg
	// does NOT satisfy the anchor-shortened ordering rule (its block's
	// anchorheight is below the BTC-leg's confirmation height, or the anchor
	// status is not "ok"). Proceeding would forfeit the reorg-safety that
	// anchoring provides, so the orchestrator refuses.
	ErrAnchorOrdering = errors.New("xchain: SEQ leg violates anchor-shortened ordering (anchorheight < BTC-leg height, or anchor not ok)")

	// ErrBTCLegInvalid is returned by the maker when the taker's claimed BTC leg
	// does not match the quote (wrong H, wrong redeemScript, wrong amount/asset,
	// or it does not pay the expected HTLC P2SH). The maker MUST refuse to lock
	// its SEQ leg in this case.
	ErrBTCLegInvalid = errors.New("xchain: taker BTC leg invalid (does not match quote)")

	// ErrBTCLegUnconfirmed is returned when the taker's BTC leg is not yet
	// confirmed to the required depth. The taker must confirm it before the
	// maker will lock the SEQ leg (the BTC-leg-first ordering rule).
	ErrBTCLegUnconfirmed = errors.New("xchain: taker BTC leg not confirmed to required depth")

	// ErrSEQLegInvalid is the reverse (asset->BTC) mirror of ErrBTCLegInvalid:
	// returned when the taker's funded SEQ asset leg does not match the quote
	// (wrong H, wrong redeemScript, wrong amount/asset, or it does not pay the
	// expected HTLC P2SH). The maker MUST refuse to reveal the secret (claim the
	// SEQ leg) in this case.
	ErrSEQLegInvalid = errors.New("xchain: taker SEQ leg invalid (does not match quote)")

	// ErrSEQLegUnconfirmed is the reverse mirror of ErrBTCLegUnconfirmed: the
	// taker's SEQ asset leg is not yet confirmed to the required depth.
	ErrSEQLegUnconfirmed = errors.New("xchain: taker SEQ leg not confirmed to required depth")
)
