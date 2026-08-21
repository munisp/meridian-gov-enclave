// Package httpx provides the shared HTTP server conventions for
// gov-enclave services (QA-01/02/03): full timeout defaults and graceful
// shutdown, mirroring core-platform packages/events/httpx.
package httpx

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ShutdownTimeout bounds graceful shutdown on SIGTERM/SIGINT.
const ShutdownTimeout = 15 * time.Second

// NewServer builds the standard service server with full timeout defaults
// (ReadHeaderTimeout alone leaves the body-read path open to slowloris).
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Serve runs srv until it fails or a SIGTERM/SIGINT arrives, then drains
// in-flight requests via http.Server.Shutdown bounded by ShutdownTimeout.
// A nil error (or http.ErrServerClosed) means a clean shutdown.
func Serve(srv *http.Server) error {
	return serve(srv, srv.ListenAndServe)
}

// ServeTLS is Serve for TLS servers (certFile/keyFile may be empty when
// srv.TLSConfig already carries certificates).
func ServeTLS(srv *http.Server, certFile, keyFile string) error {
	return serve(srv, func() error { return srv.ListenAndServeTLS(certFile, keyFile) })
}

func serve(srv *http.Server, start func() error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		errCh <- start()
	}()
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Printf("shutdown signal received; draining in-flight requests (timeout %s)", ShutdownTimeout)
		dctx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(dctx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}

// ListenAndServe runs the server with graceful shutdown on SIGTERM/SIGINT
// and full timeout defaults.
func ListenAndServe(addr string, h http.Handler) error {
	return Serve(NewServer(addr, h))
}
