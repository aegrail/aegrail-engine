// Command aegrail-engine is the Kubernetes-deployable HTTP forward
// proxy that enforces an egress allowlist for an agent workload and
// emits a SHA-256-chained audit log identical to aegrail-py's
// format. The agent sets HTTP_PROXY / HTTPS_PROXY to point at this
// process; every outbound request is allowed, denied, or surfaced
// as an error, and one audit event is written through the
// configured sink for every decision.
//
// Configuration is env-driven so the same image runs on K8s
// (Helm-managed ConfigMap), Fargate (task definition), App Runner
// where supported, or locally for testing:
//
//	AEGRAIL_ENGINE_ALLOWLIST           comma-separated host patterns
//	                                   (fnmatch-compatible)
//	AEGRAIL_ENGINE_AGENT_IDENTITY      identity in audit events
//	                                   (default: egress-proxy/v1)
//	AEGRAIL_ENGINE_AUDIT_FILE          path to JSONL audit file
//	                                   (mutually exclusive with stdout)
//	AEGRAIL_ENGINE_AUDIT_STDOUT        "1" -> stdout sink (default)
//	AEGRAIL_ENGINE_LISTEN              listen addr (default :8080)
//	AEGRAIL_ENGINE_MAX_REQUESTS        hard cap on total requests
//	                                   served over the engine's
//	                                   lifetime (0 = unlimited)
//	AEGRAIL_ENGINE_RATE_LIMIT          token-bucket rate (e.g.
//	                                   "10/sec", "100/min")
//
// Flags can override any env var; the env-driven path is the
// production path.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arpitcoder/aegrail-engine/internal/audit"
	"github.com/arpitcoder/aegrail-engine/internal/limits"
	"github.com/arpitcoder/aegrail-engine/internal/policy"
	"github.com/arpitcoder/aegrail-engine/internal/proxy"
)

// Version is the source-level fallback. CI builds override this at
// link time via `-ldflags "-X main.Version=$VERSION"` based on the
// git tag, so the value here is what local `go run` / `go build`
// reports — keep it in sync with the most recent tag for hygiene.
var Version = "0.2.0"

func main() {
	if err := run(); err != nil {
		log.Fatalf("aegrail-engine: %v", err)
	}
}

func run() error {
	var (
		listen          string
		agentIdentity   string
		allowlistFlag   string
		auditFile       string
		auditStdout     bool
		maxRequestsRaw  string
		rateLimitRaw    string
		shutdownTimeout time.Duration
		showVersion     bool
	)
	flag.StringVar(&listen, "listen", envDefault("AEGRAIL_ENGINE_LISTEN", ":8080"),
		"address to listen on for proxy traffic")
	flag.StringVar(&agentIdentity, "agent-identity",
		envDefault("AEGRAIL_ENGINE_AGENT_IDENTITY", "egress-proxy/v1"),
		"identity stamped on audit events")
	flag.StringVar(&allowlistFlag, "allowlist", os.Getenv("AEGRAIL_ENGINE_ALLOWLIST"),
		"comma-separated egress host patterns")
	flag.StringVar(&auditFile, "audit-file", os.Getenv("AEGRAIL_ENGINE_AUDIT_FILE"),
		"path to JSONL audit log (mutually exclusive with audit-stdout)")
	flag.BoolVar(&auditStdout, "audit-stdout",
		os.Getenv("AEGRAIL_ENGINE_AUDIT_STDOUT") == "1",
		"emit audit events to stdout (default when no audit-file is given)")
	flag.StringVar(&maxRequestsRaw, "max-requests",
		os.Getenv("AEGRAIL_ENGINE_MAX_REQUESTS"),
		"hard cap on total requests served over engine lifetime (0 = unlimited)")
	flag.StringVar(&rateLimitRaw, "rate-limit",
		os.Getenv("AEGRAIL_ENGINE_RATE_LIMIT"),
		"token-bucket rate (e.g. '10/sec', '100/min')")
	flag.DurationVar(&shutdownTimeout, "shutdown-timeout", 10*time.Second,
		"max time to wait for in-flight requests on SIGTERM")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion || (flag.NArg() > 0 && flag.Arg(0) == "version") {
		fmt.Println(Version)
		return nil
	}

	patterns := parseAllowlist(allowlistFlag)
	if len(patterns) == 0 {
		return errors.New("AEGRAIL_ENGINE_ALLOWLIST is empty — refusing to start with empty allowlist (would deny all)")
	}
	pol, err := policy.New(patterns)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	sink, err := openSink(auditFile, auditStdout)
	if err != nil {
		return fmt.Errorf("audit sink: %w", err)
	}
	defer func() { _ = sink.Close() }()

	session, err := proxy.NewSession(agentIdentity)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}

	var counter *limits.RequestCounter
	if strings.TrimSpace(maxRequestsRaw) != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(maxRequestsRaw), 10, 64)
		if err != nil {
			return fmt.Errorf("max-requests: %w", err)
		}
		if n > 0 {
			counter = limits.NewRequestCounter(n)
		}
	}

	limiter, err := limits.ParseRateSpec(rateLimitRaw)
	if err != nil {
		return fmt.Errorf("rate-limit: %w", err)
	}

	prox := &proxy.Proxy{
		Policy:  pol,
		Sink:    sink,
		Session: session,
		Counter: counter,
		Limiter: limiter,
	}
	prox.EmitEngineStart(Version)

	// CONNECT requests use authority-form URLs (no path component),
	// which http.ServeMux mis-routes — its pattern match assumes a
	// rooted path. Dispatch by method up front: CONNECT goes
	// straight to the proxy; everything else uses the mux for
	// /healthz, /readyz, and the plain-HTTP forward path.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", livenessHandler)
	mux.HandleFunc("/readyz", readinessHandler)
	mux.Handle("/", prox)

	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			prox.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           loggingMiddleware(root),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		log.Printf("aegrail-engine %s listening on %s; policy=%v identity=%s",
			Version, listen, pol.Patterns(), agentIdentity)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("aegrail-engine: received shutdown signal, draining for up to %s", shutdownTimeout)

	prox.EmitEngineShutdown("sigterm")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Print("aegrail-engine: clean shutdown complete")
	return nil
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseAllowlist(raw string) []string {
	out := make([]string, 0)
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func openSink(filePath string, stdoutFlag bool) (audit.Sink, error) {
	if filePath != "" {
		if stdoutFlag {
			return nil, errors.New("set either AEGRAIL_ENGINE_AUDIT_FILE or AEGRAIL_ENGINE_AUDIT_STDOUT, not both")
		}
		return audit.NewFileSink(filePath)
	}
	return audit.NewStdoutSink(), nil
}

func livenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func readinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.RequestURI(), time.Since(started))
	})
}
