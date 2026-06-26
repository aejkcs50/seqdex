package client

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/psetv2"
	"google.golang.org/protobuf/proto"

	seqdexv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqdex/v1"
	"github.com/aejkcs50/seqdex/daemon/pkg/explorer"
	"github.com/aejkcs50/seqdex/daemon/pkg/seqnet"
	"github.com/aejkcs50/seqdex/daemon/pkg/swap"
	"github.com/aejkcs50/seqdex/daemon/pkg/trade"
)

// RealBackend wires the LiveWallet to the PROVEN seqdex same-chain settlement.
// It reimplements nothing:
//
//   - taker proposer  = pkg/trade.NewSwapTx (build PSETv2) + pkg/swap.Request
//   - taker finalize  = pkg/trade.Wallet.Sign + pkg/swap.Complete + broadcast
//   - maker responder = CompleteSwapFn (wallet.Service.CompleteSwap building
//     blocks: SelectUtxos, UpdatePset, the any-asset fee vout per Principle 4,
//     BlindPset IFF blind, SignPset) + pkg/swap.Accept
//
// The three func-field seams (FetchUtxos, BroadcastFn, CompleteSwapFn) are wired
// to a live Ocean/LWK wallet + node at deploy time; until then they are nil and
// the relevant method returns errNotWired. Unit tests use a mock Backend, so a
// live node is needed only for the step-3 acceptance test.
//
// CONFIDENTIAL IS OPT-IN: the taker side honors conf (a confidential output gets
// the taker's blinding key; an explicit output gets none, and explicit UTXOs
// reveal all-zero blinders). The maker side passes `blind` through to
// CompleteSwapFn, which MUST skip BlindPset when blind is false.
type RealBackend struct {
	net   *network.Network
	taker *trade.Wallet

	// FetchUtxos returns the taker's spendable UTXOs (unblinded with blindKeys).
	FetchUtxos func(addr string, blindKeys [][]byte) ([]explorer.Utxo, error)
	// BroadcastFn publishes a raw tx hex and returns its txid.
	BroadcastFn func(txHex string) (string, error)
	// CompleteSwapFn runs the maker responder and MUST honor blind (skip BlindPset
	// for an explicit swap). Wired to wallet.Service.CompleteSwap building blocks.
	CompleteSwapFn func(req *seqdexv1.SwapRequest, blind bool) (signedPSET string, combined []swap.UnblindedInput, err error)

	// lastReq is the taker's own most recent proposer SwapRequest. ProposerFinalize
	// validates the maker-returned SwapAccept against it before signing, so it is
	// authentic taker-side state (never relay-supplied).
	lastReq *seqdexv1.SwapRequest
}

// NewRealBackend builds a RealBackend with the taker's signing + blinding keys.
// The maker-side and node seams are set as fields by the deployment.
func NewRealBackend(net *network.Network, takerPriv, takerBlinding []byte) *RealBackend {
	return &RealBackend{net: net, taker: trade.NewWalletFromKey(takerPriv, takerBlinding, net)}
}

// TakerAddress returns the taker wallet's confidential address (the script to
// fund; its explicit form shares the same scriptPubKey).
func (b *RealBackend) TakerAddress() string {
	if b.taker == nil {
		return ""
	}
	return b.taker.Address()
}

// ProposerBuildRequest selects the taker's UTXOs, builds the proposer PSETv2
// (confidential or explicit per conf), and wraps it in a SwapRequest.
func (b *RealBackend) ProposerBuildRequest(req ProposalReq, conf LegConfidentiality) (*seqdexv1.SwapRequest, error) {
	if b.taker == nil || b.FetchUtxos == nil {
		return nil, errNotWired
	}
	addr := b.taker.Address()
	utxos, err := b.FetchUtxos(addr, [][]byte{b.taker.BlindingKey()})
	if err != nil {
		return nil, err
	}
	if len(utxos) == 0 {
		return nil, fmt.Errorf("taker address %s is not funded", addr)
	}
	outScript, err := seqnet.ToOutputScript(addr, b.net)
	if err != nil {
		return nil, err
	}
	// Confidential receive output gets the taker's blinding key; explicit gets nil
	// so NewSwapTx leaves the output unblinded.
	var outBlindingKey []byte
	if conf.TakerRecvConfidential {
		_, pk := btcec.PrivKeyFromBytes(b.taker.BlindingKey())
		outBlindingKey = pk.SerializeCompressed()
	}
	psetB64, err := trade.NewSwapTx(
		utxos, req.PayAsset, req.RecvAsset, req.PayAmount, req.RecvAmount,
		outScript, outBlindingKey,
	)
	if err != nil {
		return nil, err
	}
	// Mirror NewSwapTx's internal coin selection: only the SELECTED utxos become
	// PSET inputs, so the UnblindedInputs must cover exactly those, in the same
	// order. Passing every fetched utxo causes "unblinded input index N out of
	// range" once the taker also holds other utxos (e.g. an asset received from a
	// prior swap). SelectUnspents is deterministic on the same input slice, so it
	// reproduces NewSwapTx's selection.
	selected, _, err := explorer.SelectUnspents(utxos, req.PayAmount, req.PayAsset)
	if err != nil {
		return nil, err
	}
	reqBytes, err := swap.Request(swap.RequestOpts{
		AssetToSend:     req.PayAsset,
		AmountToSend:    req.PayAmount,
		AssetToReceive:  req.RecvAsset,
		AmountToReceive: req.RecvAmount,
		Transaction:     psetB64,
		UnblindedInputs: utxosToUnblinded(selected),
		FeeAsset:        req.TakerFeeAsset,
	})
	if err != nil {
		return nil, fmt.Errorf("swap.Request: %w", err)
	}
	var out seqdexv1.SwapRequest
	if err := proto.Unmarshal(reqBytes, &out); err != nil {
		return nil, err
	}
	// Remember the request so ProposerFinalize can assert the maker-returned tx
	// still pays this exact receive leg to this taker before signing.
	b.lastReq = &out
	return &out, nil
}

// ResponderComplete runs the maker CompleteSwap (blinded or explicit per blind),
// then wraps the maker-signed PSET in a SwapAccept.
func (b *RealBackend) ResponderComplete(req *seqdexv1.SwapRequest, blind bool) (*seqdexv1.SwapAccept, error) {
	if b.CompleteSwapFn == nil {
		return nil, errNotWired
	}
	signedPSET, combined, err := b.CompleteSwapFn(req, blind)
	if err != nil {
		return nil, err
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	_, accBytes, err := swap.Accept(swap.AcceptOpts{
		Message:         reqBytes,
		Transaction:     signedPSET,
		UnblindedInputs: combined,
	})
	if err != nil {
		return nil, fmt.Errorf("swap.Accept: %w", err)
	}
	var acc seqdexv1.SwapAccept
	if err := proto.Unmarshal(accBytes, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

// ProposerFinalize signs the taker's inputs, validates via pkg/swap.Complete,
// extracts the raw tx, and broadcasts.
func (b *RealBackend) ProposerFinalize(acc *seqdexv1.SwapAccept) (*seqdexv1.SwapComplete, string, error) {
	if b.taker == nil || b.BroadcastFn == nil {
		return nil, "", errNotWired
	}
	// SECURITY (taker theft): before signing the taker's inputs, validate the
	// maker-returned tx actually pays the taker's receive leg to the taker's own
	// script and leaves the taker's funding inputs intact. A malicious maker could
	// otherwise return a tx that drops/redirects the taker's receive output (or
	// swaps out its inputs) and steal the taker's pay leg the instant it signs.
	if b.lastReq == nil {
		return nil, "", fmt.Errorf("no prior swap request to validate the accept against")
	}
	if rid := acc.GetRequestId(); rid != "" && rid != b.lastReq.GetId() {
		return nil, "", fmt.Errorf("accept request_id %q does not match our request %q", rid, b.lastReq.GetId())
	}
	recvScript, err := seqnet.ToOutputScript(b.taker.Address(), b.net)
	if err != nil {
		return nil, "", fmt.Errorf("taker receive script: %w", err)
	}
	if err := swap.ValidateProposerReceiveV2(swap.ValidateProposerReceiveV2Opts{
		ProposerPsetBase64: b.lastReq.GetTransaction(),
		FinalPsetBase64:    acc.GetTransaction(),
		RecvScript:         recvScript,
		RecvBlindingKey:    b.taker.BlindingKey(),
		AssetR:             b.lastReq.GetAssetR(),
		AmountR:            b.lastReq.GetAmountR(),
	}); err != nil {
		return nil, "", fmt.Errorf("refusing to sign maker-returned swap: %w", err)
	}
	signed, err := b.taker.Sign(acc.GetTransaction())
	if err != nil {
		return nil, "", err
	}
	accBytes, err := proto.Marshal(acc)
	if err != nil {
		return nil, "", err
	}
	_, completeBytes, err := swap.Complete(swap.CompleteOpts{Message: accBytes, Transaction: signed})
	if err != nil {
		return nil, "", fmt.Errorf("swap.Complete: %w", err)
	}
	var complete seqdexv1.SwapComplete
	if err := proto.Unmarshal(completeBytes, &complete); err != nil {
		return nil, "", err
	}
	txHex, err := rawTxHex(signed)
	if err != nil {
		return nil, "", err
	}
	txid, err := b.BroadcastFn(txHex)
	if err != nil {
		return nil, "", err
	}
	return &complete, txid, nil
}

// rawTxHex finalizes a fully co-signed PSETv2 and extracts the network tx hex.
func rawTxHex(signedPSET string) (string, error) {
	ptx, err := psetv2.NewPsetFromBase64(signedPSET)
	if err != nil {
		return "", err
	}
	if err := psetv2.FinalizeAll(ptx); err != nil {
		return "", err
	}
	rawTx, err := psetv2.Extract(ptx)
	if err != nil {
		return "", err
	}
	return rawTx.ToHex()
}

// utxosToUnblinded mirrors pkg/trade's proposer unblinded-input list. Confidential
// UTXOs reveal real asset/amount blinders; explicit UTXOs carry all-zero blinders
// (which the maker reads as "no blinding needed for this input").
func utxosToUnblinded(utxos []explorer.Utxo) []swap.UnblindedInput {
	ins := make([]swap.UnblindedInput, 0, len(utxos))
	for i, u := range utxos {
		ins = append(ins, swap.UnblindedInput{
			Index:         uint32(i),
			Asset:         u.Asset(),
			Amount:        u.Value(),
			AssetBlinder:  elementsutil.TxIDFromBytes(u.AssetBlinder()),
			AmountBlinder: elementsutil.TxIDFromBytes(u.ValueBlinder()),
		})
	}
	return ins
}
