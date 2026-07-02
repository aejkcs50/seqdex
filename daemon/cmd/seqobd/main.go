// Command seqobd is the SeqOB order-book relay daemon.
//
// It is NON-CUSTODIAL: it stores signed offers, serves the per-pair book
// (snapshot + deltas), and couriers OPAQUE end-to-end-encrypted swap-session
// messages between two peers. It holds NO wallet, NO keys, and NO funds, and it
// never decrypts the courier payload.
//
// Phase 1 wires: offerstore + validator (no-op liveness probe) + session router
// (no-op reorg watcher) + the REST/WS API. The optional read-only Sequentia node
// RPC URL is accepted now for the future liveness/anchor watch but is unused in
// Phase 1.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aejkcs50/seqdex/daemon/internal/seqob/api"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/offerstore"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/session"
	"github.com/aejkcs50/seqdex/daemon/internal/seqob/validator"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		listen        = flag.String("listen", env("SEQOB_LISTEN", ":9955"), "HTTP listen address (env SEQOB_LISTEN)")
		nodeRPC       = flag.String("node-rpc", env("SEQOB_NODE_RPC", ""), "read-only Sequentia node RPC URL for future liveness/anchor watch (env SEQOB_NODE_RPC; unused in Phase 1)")
		sessionTTL    = flag.Duration("session-deadline", 2*time.Minute, "lift session co-sign deadline")
		xsessionTTL   = flag.Duration("xsession-deadline", 3*time.Hour, "courier deadline for CROSS-CHAIN lift sessions (they span a real parent-chain confirmation; 0 = use -session-deadline)")
		expirySweep   = flag.Duration("expiry-sweep", 15*time.Second, "offer expiry sweep interval")
		sessionSweep  = flag.Duration("session-sweep", 10*time.Second, "lift-session deadline sweep interval")
		minExpiry     = flag.Duration("min-expiry", 30*time.Second, "minimum offer expiry horizon")
		maxExpiry     = flag.Duration("max-expiry", 7*24*time.Hour, "maximum offer expiry horizon")
		offersPerMin  = flag.Int("offers-per-min", 60, "max offers/min per maker_pubkey")
		offersPerMinI = flag.Int("offers-per-min-ip", 120, "max offers/min per IP")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "seqobd ", log.LstdFlags|log.Lmsgprefix)
	if *nodeRPC != "" {
		logger.Printf("node RPC configured (%s) — reserved for future liveness/anchor watch, unused in Phase 1", *nodeRPC)
	}

	store := offerstore.New(nil)

	vcfg := validator.DefaultConfig()
	vcfg.MinExpiry = *minExpiry
	vcfg.MaxExpiry = *maxExpiry
	vcfg.MaxOffersPerMinPerPubkey = *offersPerMin
	vcfg.MaxOffersPerMinPerIP = *offersPerMinI
	// Phase-1 stub liveness probe (no-op). A later build wires this to nodeRPC.
	v := validator.New(vcfg, validator.NoopLivenessProbe{})

	// onReopen returns an order to the book when a lift aborts/times out or a
	// settled tx's Bitcoin anchor is orphaned (Principle 1). In Phase 1 the reorg
	// watcher is a no-op and aborts leave the (un-removed) order OPEN, so this is a
	// logging seam; it becomes load-bearing once the anchor watch lands.
	onReopen := func(s *session.Session) {
		k := offerstore.Key{MakerPubkey: s.MakerPubkey, OfferID: s.OfferID}
		if _, ok := store.Get(k); ok {
			logger.Printf("session %s ended; order %s/%s still resting", s.ID, s.MakerPubkey, s.OfferID)
			return
		}
		logger.Printf("session %s ended; order %s/%s would need re-open (cache the offer when the anchor watch lands)", s.ID, s.MakerPubkey, s.OfferID)
	}

	router := session.NewRouter(session.Options{
		Deadline: *sessionTTL,
		Reorg:    session.NoopReorgWatcher{}, // Phase-1 stub
		OnReopen: onReopen,
	})

	srv := api.New(store, v, router, logger)
	srv.SetCrossSessionDeadline(*xsessionTTL)

	stop := make(chan struct{})
	go store.RunExpirySweeper(*expirySweep, stop)
	go router.RunDeadlineSweeper(*sessionSweep, stop)

	httpSrv := &http.Server{Addr: *listen, Handler: srv.Handler()}

	go func() {
		logger.Printf("listening on %s (non-custodial relay; no wallet, no keys)", *listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Printf("shutting down...")
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Printf("graceful shutdown error: %v", err)
	}
}
