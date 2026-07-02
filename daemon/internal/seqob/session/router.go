// Package session is the SeqOB lift-session router.
//
// When a taker lifts an offer, the router mints a session_id and binds the two
// peers (taker + maker). It then couriers OPAQUE, end-to-end-encrypted SwapMsg
// frames between them by session_id only: it never decrypts, parses, or
// introspects the ciphertext (review B1), so confidential amounts and blinders
// never reach the relay. The relay holds no keys and no funds.
//
// Each session has a short co-sign deadline (mirrors the seqdex trade expiry).
// A reorg watcher (interface, no-op default) lets the relay re-open an order if a
// settling tx's Bitcoin anchor is later orphaned (Principle 1): the swap
// un-happens, so the resting order must come back. The same re-open hook fires
// when a session aborts or its deadline elapses, returning the order to the book.
package session

import (
	"errors"
	"sync"
	"time"

	"github.com/thanhpk/randstr"

	seqobv1 "github.com/aejkcs50/seqdex/daemon/api-spec/protobuf/gen/seqob/v1"
)

// Role identifies a session peer.
type Role int

const (
	// RoleTaker is the party that lifted the offer (proposer).
	RoleTaker Role = iota
	// RoleMaker is the offer's author (responder / CompleteSwap).
	RoleMaker
)

// ReorgWatcher is notified to watch a settling tx; if its Bitcoin anchor is later
// orphaned it must invoke onOrphaned. PHASE-1 STUB: NoopReorgWatcher never fires.
type ReorgWatcher interface {
	WatchSettlement(sessionID, txid string, onOrphaned func())
}

// NoopReorgWatcher is the Phase-1 default: it never reports an orphan.
type NoopReorgWatcher struct{}

// WatchSettlement is a no-op (Phase-1 stub).
func (NoopReorgWatcher) WatchSettlement(string, string, func()) {}

// Session is a single lift handshake between two peers.
type Session struct {
	ID                 string
	OfferID            string
	MakerPubkey        string
	TakeAmount         uint64
	TakerSessionPubkey []byte
	MakerSessionPubkey []byte
	Deadline           time.Time

	takerInbox chan *seqobv1.SwapMsg
	makerInbox chan *seqobv1.SwapMsg
	done       chan struct{}

	mu         sync.Mutex
	settleTxid string
	closeOnce  sync.Once
}

// Inbox returns the channel of frames destined for the given role.
func (s *Session) Inbox(r Role) <-chan *seqobv1.SwapMsg {
	if r == RoleTaker {
		return s.takerInbox
	}
	return s.makerInbox
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} { return s.done }

// SettleTxid returns the recorded settling txid, if any.
func (s *Session) SettleTxid() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settleTxid
}

// Router owns all live lift sessions.
type Router struct {
	mu          sync.Mutex
	sessions    map[string]*Session
	deadline    time.Duration
	reorg       ReorgWatcher
	onReopen    func(*Session) // re-open the order (reorg orphan / abort / deadline)
	notifyMaker func(*Session) // notify the maker a taker lifted its offer
	now         func() time.Time
	idFn        func() string
	inboxBuf    int
}

// SetNotifyMaker installs the hook StartLift calls to notify the maker (over its
// live transport) that a taker has lifted one of its offers. The api layer wires
// this to deliver a From.lift_requested to the maker's WS connection. Set once at
// startup, before serving.
func (r *Router) SetNotifyMaker(fn func(*Session)) { r.notifyMaker = fn }

// Options configures a Router.
type Options struct {
	Deadline time.Duration
	Reorg    ReorgWatcher
	// OnReopen is invoked to return an order to the book when a session aborts,
	// times out, or its settled tx's anchor is orphaned. May be nil.
	OnReopen func(*Session)
	Now      func() time.Time
	IDFn     func() string
}

// NewRouter builds a Router.
func NewRouter(opts Options) *Router {
	if opts.Deadline <= 0 {
		opts.Deadline = 2 * time.Minute
	}
	if opts.Reorg == nil {
		opts.Reorg = NoopReorgWatcher{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IDFn == nil {
		opts.IDFn = func() string { return randstr.Hex(16) }
	}
	return &Router{
		sessions: make(map[string]*Session),
		deadline: opts.Deadline,
		reorg:    opts.Reorg,
		onReopen: opts.OnReopen,
		now:      opts.Now,
		idFn:     opts.IDFn,
		inboxBuf: 16,
	}
}

// OpenReq parameterizes StartLift.
type OpenReq struct {
	OfferID            string
	MakerPubkey        string
	TakeAmount         uint64
	TakerSessionPubkey []byte
	// MakerSessionPubkey is the maker's ephemeral session key. In a fully live WS
	// flow the maker supplies it when it accepts the lift; callers that bind both
	// peers up front (CLI / tests) may pass it here.
	MakerSessionPubkey []byte
}

// StartLift mints a session and binds the two peers.
func (r *Router) StartLift(req OpenReq) (*Session, error) {
	if req.OfferID == "" || req.MakerPubkey == "" {
		return nil, errors.New("start_lift: offer_id and maker_pubkey required")
	}
	s := &Session{
		ID:                 r.idFn(),
		OfferID:            req.OfferID,
		MakerPubkey:        req.MakerPubkey,
		TakeAmount:         req.TakeAmount,
		TakerSessionPubkey: req.TakerSessionPubkey,
		MakerSessionPubkey: req.MakerSessionPubkey,
		Deadline:           r.now().Add(r.deadline),
		takerInbox:         make(chan *seqobv1.SwapMsg, r.inboxBuf),
		makerInbox:         make(chan *seqobv1.SwapMsg, r.inboxBuf),
		done:               make(chan struct{}),
	}
	r.mu.Lock()
	r.sessions[s.ID] = s
	r.mu.Unlock()
	// Notify the maker (if online) so it can derive the E2E key from the taker's
	// session pubkey and co-sign. The relay only notifies; it never decrypts.
	if r.notifyMaker != nil {
		r.notifyMaker(s)
	}
	return s, nil
}

// ExtendDeadline pushes a session's courier deadline out to now+d. Cross-chain
// lifts span a real parent-chain confirmation (the taker's BTC leg must confirm
// before the maker locks the asset leg), so the same-chain co-sign deadline
// would sweep them mid-handshake; the server extends sessions opened on a
// CrossChainTerms offer right after StartLift.
func (r *Router) ExtendDeadline(sessionID string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.sessions[sessionID]; ok {
		s.Deadline = r.now().Add(d)
	}
}

// Get returns a live session by id.
func (r *Router) Get(sessionID string) (*Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[sessionID]
	return s, ok
}

// Send couriers ciphertext from one peer to the other. The router moves bytes
// only; it never inspects them.
func (r *Router) Send(sessionID string, from Role, ciphertext []byte) error {
	s, ok := r.Get(sessionID)
	if !ok {
		return errors.New("unknown session")
	}
	// Deadline is read under the router mutex: ExtendDeadline can rewrite it
	// after the session is published (cross-chain lifts).
	r.mu.Lock()
	deadline := s.Deadline
	r.mu.Unlock()
	if r.now().After(deadline) {
		return errors.New("session co-sign deadline elapsed")
	}
	var dst chan *seqobv1.SwapMsg
	if from == RoleTaker {
		dst = s.makerInbox
	} else {
		dst = s.takerInbox
	}
	msg := &seqobv1.SwapMsg{SessionId: sessionID, Ciphertext: ciphertext}
	select {
	case dst <- msg:
		return nil
	case <-s.done:
		return errors.New("session closed")
	}
}

// SetSettleTxid records the settling tx for a session and registers it with the
// reorg watcher so an orphaned anchor re-opens the order (Principle 1).
func (r *Router) SetSettleTxid(sessionID, txid string) error {
	s, ok := r.Get(sessionID)
	if !ok {
		return errors.New("unknown session")
	}
	s.mu.Lock()
	s.settleTxid = txid
	s.mu.Unlock()
	r.reorg.WatchSettlement(sessionID, txid, func() { r.OnAnchorOrphaned(sessionID) })
	return nil
}

// OnAnchorOrphaned is invoked when a settled tx's anchor is orphaned. It closes
// the session and re-opens the order via the OnReopen hook.
func (r *Router) OnAnchorOrphaned(sessionID string) {
	r.closeReopen(sessionID, true)
}

// Close ends a session normally (settlement done). The order is NOT re-opened.
func (r *Router) Close(sessionID string) { r.closeReopen(sessionID, false) }

// Abort ends a session and re-opens the order (maker refused / taker bailed).
func (r *Router) Abort(sessionID string) { r.closeReopen(sessionID, true) }

func (r *Router) closeReopen(sessionID string, reopen bool) {
	r.mu.Lock()
	s, ok := r.sessions[sessionID]
	if ok {
		delete(r.sessions, sessionID)
	}
	r.mu.Unlock()
	if !ok {
		return
	}
	s.closeOnce.Do(func() { close(s.done) })
	if reopen && r.onReopen != nil {
		r.onReopen(s)
	}
}

// SweepExpired aborts (and re-opens) every session past its deadline. Returns the
// number swept.
func (r *Router) SweepExpired() int {
	now := r.now()
	r.mu.Lock()
	var expired []string
	for id, s := range r.sessions {
		if now.After(s.Deadline) {
			expired = append(expired, id)
		}
	}
	r.mu.Unlock()
	for _, id := range expired {
		r.Abort(id)
	}
	return len(expired)
}

// RunDeadlineSweeper sweeps expired sessions every interval until stop closes.
func (r *Router) RunDeadlineSweeper(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			r.SweepExpired()
		}
	}
}
