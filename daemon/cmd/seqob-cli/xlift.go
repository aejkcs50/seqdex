package main

// xlift.go: the CROSS-CHAIN forward taker (buy a Sequentia asset with real BTC)
// over the order book, plus the matching BTC refund command. It drives
// internal/seqob/client.RunTakerForward (the xcourier handshake) over the relay
// courier, settling with pkg/xchain against a real bitcoind (testnet4/regtest)
// and an anchored Sequentia node.
//
// A forward lift spans a real parent-chain confirmation, so the session state
// (secret, keys, the funded BTC leg, T_btc) is persisted to -state-file BEFORE
// any coins move: if the process dies or the maker stalls, `seqob-cli xrefund
// -state-file ...` recovers the BTC leg after T_btc.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/gorilla/websocket"

	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/client"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/offer"
	"github.com/aejkcs50/seqdex/daemon/pkg/xchain"
)

// xliftState is the persisted session: everything needed to prove, resume
// reporting on, or REFUND the lift without any in-memory context.
type xliftState struct {
	CreatedAt        string `json:"created_at"`
	Relay            string `json:"relay"`
	OfferID          string `json:"offer_id"`
	MakerPubkey      string `json:"maker_pubkey"`
	Asset            string `json:"asset"`
	SeqAmount        uint64 `json:"seq_amount"`
	BtcAmount        uint64 `json:"btc_amount"`
	SecretHex        string `json:"secret_hex"`
	HashHex          string `json:"hash_hex"`
	BtcRefundPrivHex string `json:"btc_refund_priv_hex"`
	SeqClaimPrivHex  string `json:"seq_claim_priv_hex"`
	SessionID        string `json:"session_id,omitempty"`
	BtcLegTxid       string `json:"btc_leg_txid,omitempty"`
	BtcLegVout       uint32 `json:"btc_leg_vout"`
	BtcLegAmount     uint64 `json:"btc_leg_amount,omitempty"`
	BtcLegScriptHex  string `json:"btc_leg_script_hex,omitempty"`
	BtcLegHeight     int64  `json:"btc_leg_height,omitempty"`
	BtcLocktime      uint32 `json:"btc_locktime,omitempty"`
	SeqClaimTxid     string `json:"seq_claim_txid,omitempty"`
	Status           string `json:"status"`
}

func (st *xliftState) save(path string) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		fatal("marshal state: %v", err)
	}
	if err := ioutil.WriteFile(path, b, 0o600); err != nil {
		fatal("write state file %s: %v", path, err)
	}
}

func cmdXLift(args []string) {
	fs := newFlagSet("xlift")
	relay := fs.String("relay", "http://127.0.0.1:9955", "relay base URL")
	asset := fs.String("asset", "", "Sequentia asset id (hex) to buy with BTC (required)")
	offerID := fs.String("offer-id", "", "offer id to lift (empty: first verified forward cross offer for -asset)")
	makerPub := fs.String("maker-pubkey", "", "maker pubkey of the offer (with -offer-id)")
	priv := fs.String("priv", "", "taker SESSION secret key (32-byte hex, E2E only); generated if empty")
	btcRPCURL := fs.String("btc-rpc", "", "bitcoind RPC URL http://user:pass@host:port (required)")
	btcWallet := fs.String("btc-wallet", "", "bitcoind wallet funding the BTC leg")
	btcChainName := fs.String("btc-chain", "testnet4", "parent chain params: testnet4 | regtest")
	seqRPCURL := fs.String("seq-rpc", "", "Sequentia node RPC URL http://user:pass@host:port (required)")
	seqWallet := fs.String("seq-wallet", "", "Sequentia node wallet receiving the asset")
	minBTCConf := fs.Int("min-btc-conf", 1, "confirmations on our BTC leg before announcing it")
	spendFee := fs.Uint64("spend-fee", 1000, "HTLC spend fee target in native sats (converted per-asset)")
	btcFeeRate := fs.Float64("btc-fee-rate", 2, "sat/vB fee rate for funding the BTC HTLC leg (explicit; 0 = node default)")
	maxFeeBtc := fs.Uint64("max-fee-btc", 0, "max maker fee_btc (sats) we accept")
	stateFile := fs.String("state-file", "xlift-session.json", "session persistence (refund needs this)")
	btcConfWait := fs.Duration("btc-conf-wait", 90*time.Minute, "max wait for our BTC leg to confirm")
	_ = fs.Parse(args)

	if *asset == "" {
		fatal("xlift requires -asset (the hex asset id; the pair is <asset>/BTC)")
	}
	if *btcRPCURL == "" || *seqRPCURL == "" {
		fatal("xlift requires -btc-rpc and -seq-rpc")
	}

	// 1. Find + verify the offer. The relay is untrusted: only a maker-signed
	// forward (BTC_TO_ASSET) cross offer is liftable, and its amounts become the
	// expectations the courier terms must match exactly.
	var book seqobv1.PublicBook
	if err := getJSON(fmt.Sprintf("%s/v1/market/%s/%s/orderbook", *relay, *asset, offer.BTCSentinel), &book); err != nil {
		fatal("get book: %v", err)
	}
	var target *seqobv1.Offer
	for _, o := range book.GetOffers() {
		if *offerID != "" && (o.GetOfferId() != *offerID || o.GetMakerPubkey() != *makerPub) {
			continue
		}
		if o.GetCrossChain() == nil || o.GetCrossChain().GetDirection() != offer.DirBTCToAsset {
			continue
		}
		if err := offer.VerifyOffer(o); err != nil {
			fmt.Printf("skipping unverified offer %s: %v\n", o.GetOfferId(), err)
			continue
		}
		target = o
		break
	}
	if target == nil {
		fatal("no verified forward cross offer found for %s/BTC (use `seqob-cli book -base %s -quote BTC`)", *asset, *asset)
	}
	expectAsset := target.GetPair().GetBaseAsset()
	expectSeq := target.GetOfferAmount()
	expectBtc := target.GetWantAmount()
	fmt.Printf("lifting cross offer %s by %s: %d %s for %d sats\n",
		target.GetOfferId(), short(target.GetMakerPubkey()), expectSeq, expectAsset, expectBtc)

	// 2. Settlement chains.
	btcRPC, err := xliftRPCFromURL(*btcRPCURL)
	if err != nil {
		fatal("-btc-rpc: %v", err)
	}
	seqRPC, err := xliftRPCFromURL(*seqRPCURL)
	if err != nil {
		fatal("-seq-rpc: %v", err)
	}
	params, err := xchain.BitcoinChainParams(*btcChainName)
	if err != nil {
		fatal("-btc-chain: %v", err)
	}
	btcChain := xchain.NewBitcoinChain(btcRPC, *btcWallet, params)
	btcChain.SetFeeRate(*btcFeeRate)
	seqChain := xchain.NewChain(seqRPC, *seqWallet)

	// 3. Secret + throwaway settlement keys, persisted BEFORE any coins move.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fatal("secret: %v", err)
	}
	hashH := sha256.Sum256(secret)
	btcRefundKey, err := xchain.NewKey()
	if err != nil {
		fatal("key: %v", err)
	}
	seqClaimKey, err := xchain.NewKey()
	if err != nil {
		fatal("key: %v", err)
	}
	// Never clobber a prior session that may still hold a refundable BTC leg:
	// overwriting its secret/keys/script would strand those coins forever.
	if raw, err := ioutil.ReadFile(*stateFile); err == nil {
		var old xliftState
		if json.Unmarshal(raw, &old) == nil && old.Status != "" &&
			old.Status != "settled" && !strings.HasPrefix(old.Status, "refunded") {
			fatal("state file %s holds a session with status %q (possibly a refundable BTC leg); refund it or pass a different -state-file", *stateFile, old.Status)
		}
	}
	st := &xliftState{
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Relay: *relay,
		OfferID: target.GetOfferId(), MakerPubkey: target.GetMakerPubkey(),
		Asset: expectAsset, SeqAmount: expectSeq, BtcAmount: expectBtc,
		SecretHex: hex.EncodeToString(secret), HashHex: hex.EncodeToString(hashH[:]),
		BtcRefundPrivHex: hex.EncodeToString(btcRefundKey.Bytes()),
		SeqClaimPrivHex:  hex.EncodeToString(seqClaimKey.Bytes()),
		Status:           "created",
	}
	st.save(*stateFile)
	fmt.Printf("session state -> %s (keep it: it is the refund path)\n", *stateFile)

	// 4. Open the lift session; E2E key from the SIGNED offer, echo cross-checked
	// only (a relay substituting keys can only deny service).
	takerKey := loadOrGenKey(*priv)
	wsURL := "ws" + strings.TrimPrefix(*relay, "http") + "/v1/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		fatal("dial ws: %v", err)
	}
	defer conn.Close()
	writeWS(conn, &seqobv1.To{Msg: &seqobv1.To_StartLift{StartLift: &seqobv1.StartLift{
		OfferId:            target.GetOfferId(),
		MakerPubkey:        target.GetMakerPubkey(),
		TakeAmount:         target.GetBaseAmount(), // whole-HTLC lift
		TakerSessionPubkey: takerKey.PubKey().SerializeCompressed(),
	}}})
	la := readWS(conn)
	if la.GetLiftAccepted() == nil {
		fatal("expected lift_accepted, got %s", la.String())
	}
	sid := la.GetLiftAccepted().GetSessionId()
	st.SessionID = sid
	st.Status = "session_open"
	st.save(*stateFile)
	fmt.Printf("cross lift session %s opened\n", sid)

	makerOfferPub, err := hex.DecodeString(target.GetMakerPubkey())
	if err != nil {
		fatal("decode maker pubkey: %v", err)
	}
	pk, err := btcec.ParsePubKey(makerOfferPub)
	if err != nil {
		fatal("parse maker pubkey: %v", err)
	}
	if echo := la.GetLiftAccepted().GetMakerSessionPubkey(); len(echo) > 0 && !bytes.Equal(echo, makerOfferPub) {
		fatal("relay MakerSessionPubkey echo does not match the signed offer (possible MITM); aborting")
	}
	crypter, err := client.NewCrypter(takerKey, pk)
	if err != nil {
		fatal("crypter: %v", err)
	}

	// 5. Run the forward driver over the WS courier. The send path must return
	// errors (NOT exit the process like writeWS's fatal): the driver's abort
	// paths and the final state save are what keep a funded BTC leg refundable.
	send := func(sealed []byte) error {
		b, err := jsonMarshal.Marshal(&seqobv1.To{Msg: &seqobv1.To_SwapMsg{SwapMsg: &seqobv1.SwapMsg{SessionId: sid, Ciphertext: sealed}}})
		if err != nil {
			return err
		}
		return conn.WriteMessage(websocket.TextMessage, b)
	}
	recv := func(timeout time.Duration) ([]byte, error) {
		from, err := readWSUntilSwap(conn, timeout)
		if err != nil {
			return nil, err
		}
		return from.GetSwapMsg().GetCiphertext(), nil
	}
	ops := &client.LiveXcOps{
		Swap: xchain.NewSwapBitcoin(btcChain, seqChain, xchain.NewHashLock(secret)),
		BTC:  btcChain,
		SEQ:  seqChain,
	}
	res, err := client.RunTakerForward(client.TakerForwardParams{
		Ops:             ops,
		Crypter:         crypter,
		Secret:          secret,
		BtcRefundKey:    btcRefundKey,
		SeqClaimKey:     seqClaimKey,
		ExpectAsset:     expectAsset,
		ExpectSeqAmount: expectSeq,
		ExpectBtcAmount: expectBtc,
		MaxFeeBtc:       *maxFeeBtc,
		MinBTCConf:      *minBTCConf,
		SpendFeeSats:    *spendFee,
		Timing:          client.XcTiming{BtcConfWait: *btcConfWait},
		Log:             func(format string, a ...interface{}) { fmt.Printf(format+"\n", a...) },
		// Persist the leg the moment it is funded, BEFORE the confirmation
		// wait: a crash in that window must leave the state refundable.
		OnBtcLegFunded: func(r *client.TakerForwardResult) {
			if r.BtcLeg != nil && r.BtcLeg.Funded != nil {
				st.BtcLegTxid = r.BtcLeg.Funded.TxID
				st.BtcLegVout = r.BtcLeg.Funded.Vout
				st.BtcLegAmount = r.BtcLeg.Funded.Amount
				st.BtcLegScriptHex = hex.EncodeToString(r.BtcLeg.Script)
			}
			st.BtcLocktime = r.BtcLocktime
			st.Status = "btc_funded"
			st.save(*stateFile)
			fmt.Printf("BTC leg funded and persisted (%s); awaiting confirmation\n", st.BtcLegTxid)
		},
	}, send, recv)

	// 6. Persist whatever happened; the BTC leg makes the state refundable.
	if res != nil {
		if res.BtcLeg != nil && res.BtcLeg.Funded != nil {
			st.BtcLegTxid = res.BtcLeg.Funded.TxID
			st.BtcLegVout = res.BtcLeg.Funded.Vout
			st.BtcLegAmount = res.BtcLeg.Funded.Amount
			st.BtcLegScriptHex = hex.EncodeToString(res.BtcLeg.Script)
			st.BtcLegHeight = res.BtcLegHeight
		}
		st.BtcLocktime = res.BtcLocktime
		st.SeqClaimTxid = res.SeqClaimTxid
	}
	if err != nil {
		st.Status = "aborted: " + err.Error()
		st.save(*stateFile)
		if st.BtcLegTxid != "" {
			fmt.Printf("lift aborted AFTER funding the BTC leg %s.\n", st.BtcLegTxid)
			fmt.Printf("recover it after parent height %d with:\n  seqob-cli xrefund -state-file %s -btc-rpc <url> -btc-wallet %s -btc-chain %s -wait\n",
				st.BtcLocktime, *stateFile, *btcWallet, *btcChainName)
		}
		fatal("xlift: %v", err)
	}
	st.Status = "settled"
	st.save(*stateFile)
	fmt.Printf("CROSS SWAP SETTLED: claimed %d %s in %s (BTC leg %s, anchor evidence: seq block %s anchored at %d >= BTC leg height %d)\n",
		expectSeq, expectAsset, res.SeqClaimTxid, st.BtcLegTxid,
		res.Evidence.SeqBlockHash, res.Evidence.SeqBlockAnchor, res.Evidence.BTCLegHeight)
}

func cmdXRefund(args []string) {
	fs := newFlagSet("xrefund")
	stateFile := fs.String("state-file", "xlift-session.json", "session state written by xlift")
	btcRPCURL := fs.String("btc-rpc", "", "bitcoind RPC URL http://user:pass@host:port (required)")
	btcWallet := fs.String("btc-wallet", "", "bitcoind wallet")
	btcChainName := fs.String("btc-chain", "testnet4", "parent chain params: testnet4 | regtest")
	spendFee := fs.Uint64("spend-fee", 1000, "refund fee (sats)")
	wait := fs.Bool("wait", false, "poll until T_btc passes instead of failing when early")
	_ = fs.Parse(args)

	raw, err := ioutil.ReadFile(*stateFile)
	if err != nil {
		fatal("read state: %v", err)
	}
	var st xliftState
	if err := json.Unmarshal(raw, &st); err != nil {
		fatal("parse state: %v", err)
	}
	if st.BtcLegTxid == "" || st.BtcLocktime == 0 {
		fatal("state has no funded BTC leg to refund")
	}
	if st.Status == "settled" {
		fatal("session settled (the maker owns the BTC leg); nothing to refund")
	}
	if *btcRPCURL == "" {
		fatal("xrefund requires -btc-rpc")
	}
	btcRPC, err := xliftRPCFromURL(*btcRPCURL)
	if err != nil {
		fatal("-btc-rpc: %v", err)
	}
	params, err := xchain.BitcoinChainParams(*btcChainName)
	if err != nil {
		fatal("-btc-chain: %v", err)
	}
	btcChain := xchain.NewBitcoinChain(btcRPC, *btcWallet, params)

	script, err := hex.DecodeString(st.BtcLegScriptHex)
	if err != nil {
		fatal("state btc_leg_script_hex: %v", err)
	}
	hashH, err := hex.DecodeString(st.HashHex)
	if err != nil {
		fatal("state hash_hex: %v", err)
	}
	keyBytes, err := hex.DecodeString(st.BtcRefundPrivHex)
	if err != nil {
		fatal("state btc_refund_priv_hex: %v", err)
	}
	leg := &xchain.LegLock{
		Script:   script,
		Funded:   &xchain.FundedHTLC{TxID: st.BtcLegTxid, Vout: st.BtcLegVout, Amount: st.BtcLegAmount},
		Locktime: st.BtcLocktime,
	}
	// The refund path only touches the BTC side; no Sequentia node is needed.
	ops := &client.LiveXcOps{
		Swap: xchain.NewSwapBitcoin(btcChain, nil, xchain.NewHashLockFromHash(hashH)),
		BTC:  btcChain,
	}
	txid, err := client.RefundTakerBTC(ops, leg, xchain.KeyFromBytes(keyBytes), st.BtcLocktime, *spendFee, *wait, 15*time.Second)
	if err != nil {
		if errors.Is(err, client.ErrXcRefundNotDue) {
			fatal("%v (re-run with -wait to poll until due)", err)
		}
		fatal("refund: %v", err)
	}
	st.Status = "refunded: " + txid
	st.save(*stateFile)
	fmt.Printf("BTC leg refunded: %s\n", txid)
}

// xliftRPCFromURL parses http://user:pass@host:port into an xchain RPC client.
func xliftRPCFromURL(raw string) (*xchain.RPC, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.User == nil {
		return nil, fmt.Errorf("expected http://user:pass@host:port, got %q", raw)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("bad port in %q", raw)
	}
	pass, _ := u.User.Password()
	return xchain.NewRPC(u.Hostname(), port, u.User.Username(), pass), nil
}
