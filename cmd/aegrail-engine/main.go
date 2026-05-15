// Command aegrail-engine is the Kubernetes-deployable enforcement
// engine for aegrail. The v0.1.0 milestone replaces this placeholder
// with the real HTTP forward proxy + allowlist enforcement +
// audit-chain emission. Until then, this binary serves a working
// HTTP server that responds 502 to all proxy requests with an
// informative body, plus /healthz and /readyz endpoints so the pod
// can reach Ready state and the Helm chart can be validated
// end-to-end in a kind cluster.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Version is overwritten at build time via -ldflags.
var Version = "0.0.0-dev"

func main() {
	var (
		listen          string
		shutdownTimeout time.Duration
		showVersion     bool
	)

	flag.StringVar(&listen, "listen", ":8080", "address to listen on for proxy traffic")
	flag.DurationVar(&shutdownTimeout, "shutdown-timeout", 10*time.Second, "max time to wait for in-flight requests on SIGTERM")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion || (flag.NArg() > 0 && flag.Arg(0) == "version") {
		fmt.Println(Version)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", livenessHandler)
	mux.HandleFunc("/readyz", readinessHandler)
	mux.HandleFunc("/", placeholderProxyHandler)

	srv := &http.Server{
		Addr:              listen,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown on SIGTERM / SIGINT
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		log.Printf("aegrail-engine %s listening on %s (placeholder build — proxy not yet implemented)", Version, listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("aegrail-engine: received shutdown signal, draining for up to %s", shutdownTimeout)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("aegrail-engine: shutdown error: %v", err)
		os.Exit(1)
	}
	log.Print("aegrail-engine: clean shutdown complete")
}

func livenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func readinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func placeholderProxyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Aegrail-Version", Version)
	w.Header().Set("X-Aegrail-Status", "pre-release-placeholder")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprintf(w,
		"aegrail-engine %s pre-release placeholder.\n\n"+
			"The HTTP forward proxy + allowlist enforcement + audit-chain\n"+
			"emission are part of the v0.1.0 milestone and not yet shipped.\n"+
			"Until then, this binary exists so the Helm chart + Kubernetes\n"+
			"deployment shape can be validated end-to-end in a kind cluster.\n\n"+
			"Request observed: %s %s\n"+
			"See: https://github.com/arpitcoder/aegrail-engine#roadmap\n",
		Version, r.Method, r.URL.RequestURI(),
	)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.RequestURI(), time.Since(started))
	})
}
