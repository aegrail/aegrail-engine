// Command aegrail-webhook is the K8s mutating admission controller
// that auto-injects the aegrail-engine sidecar into pods created
// in namespaces labeled `aegrail.io/inject=enabled`.
//
// Configuration env vars (all required except where noted):
//
//	AEGRAIL_WEBHOOK_TLS_CERT   path to PEM-encoded server cert
//	AEGRAIL_WEBHOOK_TLS_KEY    path to PEM-encoded server key
//	AEGRAIL_WEBHOOK_LISTEN     listen addr (default :8443)
//	AEGRAIL_ENGINE_IMAGE       full container image ref for the
//	                            injected engine sidecar
//	AEGRAIL_ENGINE_ALLOWLIST   comma-separated host patterns the
//	                            injected engine will enforce
//	AEGRAIL_ENGINE_AUDIT_MODE  "stdout" (default) or "file"
//	AEGRAIL_ENGINE_AUDIT_FILE  audit file path when audit mode is "file"
//	AEGRAIL_ENGINE_MAX_REQUESTS (optional) request count cap
//	AEGRAIL_ENGINE_RATE_LIMIT  (optional) token-bucket rate
//	AEGRAIL_ENGINE_DEFAULT_IDENTITY  default aegrail.io/identity
//	                                  label value (default "auto-injected/v1")
//	AEGRAIL_ENGINE_LISTEN_PORT (optional, default 8080)
//	AEGRAIL_WEBHOOK_MITM_CA_SECRET_NAME (optional) Secret name in target
//	                                  namespace containing the MITM CA
//	                                  cert+key. Enables HTTPS termination
//	                                  in the injected sidecar.
//	AEGRAIL_WEBHOOK_MITM_HOSTS  (optional) comma-separated host patterns
//	                              for which the sidecar performs MITM
//	AEGRAIL_WEBHOOK_MITM_CA_CERT_KEY  (optional) key in Secret for CA cert
//	                                    PEM (default "tls.crt")
//	AEGRAIL_WEBHOOK_MITM_CA_KEY_KEY   (optional) key in Secret for CA key
//	                                    PEM (default "tls.key")
//	AEGRAIL_WEBHOOK_MITM_CA_MOUNT_DIR  (optional) in-container dir to
//	                                     mount the CA at
//	                                     (default "/etc/aegrail/mitm-ca")
//
// Health endpoints (HTTP, no TLS — for K8s liveness/readiness):
//
//	/healthz   200 ok
//	/readyz    200 ready
//
// Admission endpoint (HTTPS):
//
//	POST /mutate   AdmissionReview in/out
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aegrail/aegrail-engine/internal/webhook"
)

var Version = "0.4.3"

type admissionReview struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Request    *admissionReq  `json:"request,omitempty"`
	Response   *admissionResp `json:"response,omitempty"`
}

type admissionReq struct {
	UID       string          `json:"uid"`
	Object    json.RawMessage `json:"object"`
	Namespace string          `json:"namespace"`
	Operation string          `json:"operation"`
}

type admissionResp struct {
	UID       string `json:"uid"`
	Allowed   bool   `json:"allowed"`
	PatchType string `json:"patchType,omitempty"`
	Patch     []byte `json:"patch,omitempty"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("aegrail-webhook: %v", err)
	}
}

func run() error {
	certPath := envDefault("AEGRAIL_WEBHOOK_TLS_CERT", "/etc/aegrail/tls/tls.crt")
	keyPath := envDefault("AEGRAIL_WEBHOOK_TLS_KEY", "/etc/aegrail/tls/tls.key")
	listen := envDefault("AEGRAIL_WEBHOOK_LISTEN", ":8443")

	cfg := webhook.Config{
		Image:       requireEnv("AEGRAIL_ENGINE_IMAGE"),
		Allowlist:   os.Getenv("AEGRAIL_ENGINE_ALLOWLIST"),
		AuditMode:   envDefault("AEGRAIL_ENGINE_AUDIT_MODE", "stdout"),
		AuditFile:   envDefault("AEGRAIL_ENGINE_AUDIT_FILE", "/var/log/aegrail/audit.jsonl"),
		MaxRequests: os.Getenv("AEGRAIL_ENGINE_MAX_REQUESTS"),
		RateLimit:   os.Getenv("AEGRAIL_ENGINE_RATE_LIMIT"),
		MaxTokens:   os.Getenv("AEGRAIL_ENGINE_MAX_TOKENS"),
		// MITM injection (v0.4.1+ / fixed v0.4.3). When the Secret
		// is set, the mutator:
		//   - mounts the Secret on agent containers AND the engine sidecar
		//   - sets SSL_CERT_FILE/REQUESTS_CA_BUNDLE/NODE_EXTRA_CA_CERTS
		//     on agent containers
		//   - sets AEGRAIL_ENGINE_MITM_HOSTS/_CA_CERT_FILE/_CA_KEY_FILE
		//     on the engine sidecar so it actually terminates TLS
		// The Secret must already exist in each labeled namespace.
		MITMCASecretName: os.Getenv("AEGRAIL_WEBHOOK_MITM_CA_SECRET_NAME"),
		MITMCACertKey:    envDefault("AEGRAIL_WEBHOOK_MITM_CA_CERT_KEY", "tls.crt"),
		MITMCAKeyKey:     envDefault("AEGRAIL_WEBHOOK_MITM_CA_KEY_KEY", "tls.key"),
		MITMCAMountDir:   envDefault("AEGRAIL_WEBHOOK_MITM_CA_MOUNT_DIR", "/etc/aegrail/mitm-ca"),
		MITMHosts:        os.Getenv("AEGRAIL_WEBHOOK_MITM_HOSTS"),
		DefaultIdentity:  envDefault("AEGRAIL_ENGINE_DEFAULT_IDENTITY", "auto-injected/v1"),
		EngineListenPort: envInt("AEGRAIL_ENGINE_LISTEN_PORT", 8080),
	}
	if cfg.Image == "" {
		return errors.New("AEGRAIL_ENGINE_IMAGE is required (the image the webhook injects)")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", okHandler("ok\n"))
	mux.HandleFunc("/readyz", okHandler("ready\n"))
	mux.HandleFunc("/mutate", mutateHandler(cfg))

	srv := &http.Server{
		Addr:              listen,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		log.Printf("aegrail-webhook %s listening on %s (TLS)", Version, listen)
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("aegrail-webhook: received shutdown signal")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

func mutateHandler(cfg webhook.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var review admissionReview
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, "parse AdmissionReview: "+err.Error(), http.StatusBadRequest)
			return
		}
		if review.Request == nil {
			http.Error(w, "AdmissionReview missing request", http.StatusBadRequest)
			return
		}

		var pod webhook.PodLike
		if err := json.Unmarshal(review.Request.Object, &pod); err != nil {
			writeReview(w, review.APIVersion, &admissionResp{
				UID:     review.Request.UID,
				Allowed: true, // never block on parse errors — fail-open
			})
			log.Printf("mutate: parse pod failed (admitting unchanged): %v", err)
			return
		}

		patch, err := webhook.BuildPatch(pod, cfg)
		if err != nil {
			writeReview(w, review.APIVersion, &admissionResp{
				UID:     review.Request.UID,
				Allowed: true,
			})
			log.Printf("mutate: build patch failed (admitting unchanged): %v", err)
			return
		}

		resp := &admissionResp{
			UID:     review.Request.UID,
			Allowed: true,
		}
		if patch != nil {
			resp.PatchType = "JSONPatch"
			resp.Patch = patch
		}
		writeReview(w, review.APIVersion, resp)
	}
}

func writeReview(w http.ResponseWriter, apiVersion string, resp *admissionResp) {
	if apiVersion == "" {
		apiVersion = "admission.k8s.io/v1"
	}
	out := admissionReview{
		APIVersion: apiVersion,
		Kind:       "AdmissionReview",
		Response:   resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("mutate: encode response failed: %v", err)
	}
}

func okHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
	}
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func requireEnv(key string) string { return os.Getenv(key) }

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(started))
	})
}

// Silence unused-import linter when fmt is only used in dev paths.
var _ = fmt.Sprintf
