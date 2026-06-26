// Package api exposes the SeqOB relay over HTTP REST + WebSocket using the
// generated To/From envelope (relay.proto). Bodies are protojson so the Go CLI
// and a browser share one encoding.
//
// REST:
//
//	POST /v1/offers                              submit a signed Offer
//	POST /v1/offers/cancel                       submit a signed OfferCancel
//	GET  /v1/offers?maker_pubkey=...             a maker's own orders
//	GET  /v1/markets                             market summaries
//	GET  /v1/market/{base}/{quote}/orderbook     per-pair snapshot (PublicBook)
//	POST /v1/lift                                open a lift session (StartLift)
//	GET  /v1/ws                                  WebSocket (To/From)
//
// The relay is NON-CUSTODIAL: it stores signed text, serves the book, and
// couriers OPAQUE encrypted SwapMsg frames between peers. It never holds keys or
// funds and never decrypts the courier payload.
package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/offerstore"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/session"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/validator"
)

// Server wires the store, validator, and session router behind HTTP.
type Server struct {
	store     *offerstore.Store
	validator *validator.Validator
	sessions  *session.Router
	log       *log.Logger
	upgrader  websocket.Upgrader

	// makerConns tracks WS connections by registered maker_pubkey so a lift can be
	// routed to an online maker. Best-effort (Phase-1).
	makerConns *connRegistry
}

// New builds a Server.
func New(store *offerstore.Store, v *validator.Validator, sessions *session.Router, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	srv := &Server{
		store:     store,
		validator: v,
		sessions:  sessions,
		log:       logger,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		makerConns: newConnRegistry(),
	}
	// The relay notifies an online maker (via From.lift_requested) whenever a taker
	// lifts one of its offers, so the maker can derive the E2E key and co-sign.
	sessions.SetNotifyMaker(srv.notifyMaker)
	// Wire the book into the validator so a byte-identical replay of a resting offer
	// is recognized and declined the victim maker's per-pubkey rate budget (ITEM A).
	v.SetBook(store)
	return srv
}

var jsonMarshal = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}
var jsonUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

// Handler returns the HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/offers", s.handleOffers)
	mux.HandleFunc("/v1/offers/cancel", s.handleCancel)
	mux.HandleFunc("/v1/markets", s.handleMarkets)
	mux.HandleFunc("/v1/market/", s.handleOrderbook)
	mux.HandleFunc("/v1/lift", s.handleLift)
	mux.HandleFunc("/v1/ws", s.handleWS)
	return mux
}

func (s *Server) handleOffers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleOfferSubmit(w, r)
	case http.MethodGet:
		s.handleOwnOffers(w, r)
	default:
		httpErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleOfferSubmit(w http.ResponseWriter, r *http.Request) {
	var o seqobv1.Offer
	if err := readProto(r, &o); err != nil {
		httpErr(w, http.StatusBadRequest, "decode offer: "+err.Error())
		return
	}
	if err := s.validator.ValidateOffer(r.Context(), &o, clientIP(r)); err != nil {
		if errors.Is(err, validator.ErrReplay) {
			// ITEM A: byte-identical replay of an already-resting offer; a no-op that
			// consumed no rate budget. Echo the live status rather than re-submitting
			// (the store would reject the duplicate key anyway).
			st, ok := s.store.OrderStatusOf(offerstore.Key{MakerPubkey: o.GetMakerPubkey(), OfferID: o.GetOfferId()})
			if !ok {
				st = &seqobv1.OrderStatus{OfferId: o.GetOfferId(), MakerPubkey: o.GetMakerPubkey(), Status: seqobv1.OfferStatus_OFFER_STATUS_OPEN, ActiveAmount: o.GetBaseAmount()}
			}
			writeProto(w, st)
			return
		}
		httpErr(w, http.StatusBadRequest, "invalid offer: "+err.Error())
		return
	}
	k, err := s.store.Submit(&o)
	if err != nil {
		httpErr(w, http.StatusConflict, "submit: "+err.Error())
		return
	}
	writeProto(w, &seqobv1.OrderStatus{
		OfferId:      k.OfferID,
		MakerPubkey:  k.MakerPubkey,
		Status:       seqobv1.OfferStatus_OFFER_STATUS_OPEN,
		ActiveAmount: o.GetBaseAmount(),
	})
}

func (s *Server) handleOwnOffers(w http.ResponseWriter, r *http.Request) {
	maker := r.URL.Query().Get("maker_pubkey")
	if maker == "" {
		httpErr(w, http.StatusBadRequest, "maker_pubkey required")
		return
	}
	entries := s.store.SnapshotMaker(maker)
	book := &seqobv1.PublicBook{}
	for _, e := range entries {
		book.Offers = append(book.Offers, e.Offer)
	}
	writeProto(w, book)
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var c seqobv1.OfferCancel
	if err := readProto(r, &c); err != nil {
		httpErr(w, http.StatusBadRequest, "decode cancel: "+err.Error())
		return
	}
	if err := s.validator.ValidateCancel(&c); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid cancel: "+err.Error())
		return
	}
	if err := s.store.Cancel(&c); err != nil {
		httpErr(w, http.StatusConflict, "cancel: "+err.Error())
		return
	}
	writeProto(w, &seqobv1.OrderStatus{
		OfferId:     c.GetOfferId(),
		MakerPubkey: c.GetMakerPubkey(),
		Status:      seqobv1.OfferStatus_OFFER_STATUS_CANCELLED,
	})
}

func (s *Server) handleMarkets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeProto(w, &seqobv1.MarketList{Markets: s.store.Markets()})
}

// handleOrderbook serves /v1/market/{base}/{quote}/orderbook.
func (s *Server) handleOrderbook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httpErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/market/")
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[2] != "orderbook" || parts[0] == "" || parts[1] == "" {
		httpErr(w, http.StatusNotFound, "expected /v1/market/{base}/{quote}/orderbook")
		return
	}
	pair := &seqobv1.AssetPair{BaseAsset: parts[0], QuoteAsset: parts[1]}
	writeProto(w, &seqobv1.PublicBook{Pair: pair, Offers: s.store.SnapshotPair(pair)})
}

func (s *Server) handleLift(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var sl seqobv1.StartLift
	if err := readProto(r, &sl); err != nil {
		httpErr(w, http.StatusBadRequest, "decode start_lift: "+err.Error())
		return
	}
	sess, err := s.openLift(&sl)
	if err != nil {
		httpErr(w, http.StatusConflict, err.Error())
		return
	}
	writeProto(w, &seqobv1.LiftAccepted{
		SessionId:          sess.ID,
		MakerSessionPubkey: makerPubkeyBytes(sl.GetMakerPubkey()),
	})
}

// makerPubkeyBytes decodes a hex maker pubkey to the 33-byte compressed key the
// taker seals its E2E payload to (the maker's offer key doubles as its session
// key). Returns nil on a malformed key.
func makerPubkeyBytes(hexPub string) []byte {
	b, err := hex.DecodeString(hexPub)
	if err != nil {
		return nil
	}
	return b
}

// openLift validates the referenced offer is live and opens a session.
func (s *Server) openLift(sl *seqobv1.StartLift) (*session.Session, error) {
	k := offerstore.Key{MakerPubkey: sl.GetMakerPubkey(), OfferID: sl.GetOfferId()}
	e, ok := s.store.Get(k)
	if !ok {
		return nil, errString("offer not found or not open")
	}
	if sl.GetTakeAmount() > e.ActiveAmount {
		return nil, errString("take_amount exceeds active_amount")
	}
	return s.sessions.StartLift(session.OpenReq{
		OfferID:            sl.GetOfferId(),
		MakerPubkey:        sl.GetMakerPubkey(),
		TakeAmount:         sl.GetTakeAmount(),
		TakerSessionPubkey: sl.GetTakerSessionPubkey(),
	})
}

// --- helpers ---

type errString string

func (e errString) Error() string { return string(e) }

func readProto(r *http.Request, m proto.Message) error {
	defer r.Body.Close()
	var raw json.RawMessage
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	return jsonUnmarshal.Unmarshal(raw, m)
}

func writeProto(w http.ResponseWriter, m proto.Message) {
	b, err := jsonMarshal.Marshal(m)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	b, _ := json.Marshal(map[string]interface{}{"code": code, "message": msg})
	w.Write(b)
}

func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if i := strings.IndexByte(xf, ','); i >= 0 {
			return strings.TrimSpace(xf[:i])
		}
		return strings.TrimSpace(xf)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		return host[:i]
	}
	return host
}
