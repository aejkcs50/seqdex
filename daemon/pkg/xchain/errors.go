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
)
