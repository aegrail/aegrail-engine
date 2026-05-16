// Package webhook implements the K8s mutating admission controller
// that auto-injects the aegrail-engine sidecar into agent pods.
//
// The controller listens for Pod CREATE events from the K8s API
// server in namespaces labeled `aegrail.io/inject=enabled`. For
// each pod, it returns a JSON Patch that:
//
//   1. Adds the engine container as a sidecar.
//   2. Adds HTTP_PROXY / HTTPS_PROXY env vars to every existing
//      user container so their outbound traffic routes through
//      the engine on localhost:8080.
//   3. Adds an audit volume mount if file-sink mode is configured.
//   4. Defaults the aegrail.io/identity label if missing, so the
//      engine's downward-API binding has something to read.
//
// Idempotent: if the engine container is already present, the
// mutator returns an empty patch.

package webhook

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EngineContainerName is the name we use for the injected engine
// sidecar. Stable so idempotency checks work across webhook
// upgrades.
const EngineContainerName = "aegrail-engine"

// LabelInjectEnabled is the namespace label that opts a namespace
// into auto-injection.
const LabelInjectEnabled = "aegrail.io/inject"

// LabelIdentity is the pod label the engine reads for its
// agent_identity via downward API. Operators can set it on the
// agent pod; if absent, the webhook fills in a sensible default.
const LabelIdentity = "aegrail.io/identity"

// Config captures everything the mutator needs to construct the
// engine sidecar. Loaded from the webhook's own env at startup.
type Config struct {
	// Image is the full container image reference for the engine,
	// e.g. "ghcr.io/arpitcoder/aegrail-engine:0.2.0".
	Image string

	// Allowlist is the comma-separated host patterns the engine
	// will enforce. Operators set this once on the webhook
	// deployment; every injected sidecar inherits it.
	Allowlist string

	// AuditMode is "stdout" or "file".
	AuditMode string

	// AuditFile is the path inside the container the engine writes
	// to when AuditMode == "file".
	AuditFile string

	// MaxRequests / RateLimit / MaxTokens map to AEGRAIL_ENGINE_*.
	// Empty = unlimited.
	MaxRequests string
	RateLimit   string
	MaxTokens   string

	// DefaultIdentity is what we stamp on aegrail.io/identity when
	// the agent pod doesn't already have the label.
	DefaultIdentity string

	// EngineListenPort is the port the sidecar listens on.
	EngineListenPort int

	// MITM trust injection (v0.4.1+). When MITMCASecretName is set,
	// the webhook injects a volume mount + the three standard
	// HTTPS trust env vars into every user container so the engine's
	// TLS-terminated handshake is accepted client-side.
	//
	// The Secret must already exist in the target namespace (Helm
	// can pre-create it via post-install hook or the operator
	// kubectl-copies it). The webhook does NOT create cross-namespace
	// Secrets — that's a controller's job.
	MITMCASecretName string
	// MITMCACertKey is the key inside the Secret holding the CA
	// cert PEM. Defaults to "tls.crt" (kubernetes.io/tls Secret
	// shape).
	MITMCACertKey string
	// MITMCAMountPath is where the CA file appears inside the
	// agent container. Defaults to /etc/aegrail/mitm-ca/ca.crt.
	MITMCAMountPath string
}

// patchOp is one JSON Patch operation per RFC 6902.
type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// envVar mirrors corev1.EnvVar for use in the patch ops.
type envVar struct {
	Name      string         `json:"name"`
	Value     string         `json:"value,omitempty"`
	ValueFrom map[string]any `json:"valueFrom,omitempty"`
}

// container is the minimal shape we need to build the engine
// container patch.
type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	ImagePullPolicy string           `json:"imagePullPolicy,omitempty"`
	Env             []envVar         `json:"env,omitempty"`
	Ports           []map[string]any `json:"ports,omitempty"`
	LivenessProbe   map[string]any   `json:"livenessProbe,omitempty"`
	ReadinessProbe  map[string]any   `json:"readinessProbe,omitempty"`
	Resources       map[string]any   `json:"resources,omitempty"`
	SecurityContext map[string]any   `json:"securityContext,omitempty"`
	VolumeMounts    []map[string]any `json:"volumeMounts,omitempty"`
}

// PodLike is the trimmed pod-spec shape the mutator reads to
// decide what to patch. Unmarshalling the full corev1.Pod would
// pull in the entire k8s API surface; this captures only what
// matters. Env is captured so we know whether to append to an
// existing array or to create one (JSON Patch can't do that
// conditionally on its own).
type PodLike struct {
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		Containers []PodLikeContainer `json:"containers"`
	} `json:"spec"`
}

// PodLikeContainer captures the subset of a container we read.
type PodLikeContainer struct {
	Name string                   `json:"name"`
	Env  []map[string]interface{} `json:"env,omitempty"`
}

// BuildPatch returns the JSON-Patch (RFC 6902) byte sequence that
// the admission controller should send back in its
// AdmissionResponse.patch field. If the pod already has the engine
// container injected, returns nil so the response carries no patch
// and the API server admits the original pod unchanged.
func BuildPatch(pod PodLike, cfg Config) ([]byte, error) {
	if pod.alreadyInjected() {
		return nil, nil
	}

	ops := []patchOp{}

	// 1. Label the pod with aegrail.io/identity if missing. The
	//    engine sidecar reads from this via downward API.
	if pod.Metadata.Labels == nil {
		ops = append(ops, patchOp{
			Op:    "add",
			Path:  "/metadata/labels",
			Value: map[string]string{LabelIdentity: cfg.DefaultIdentity},
		})
	} else if _, has := pod.Metadata.Labels[LabelIdentity]; !has {
		ops = append(ops, patchOp{
			Op:    "add",
			Path:  jsonPointerLabel(LabelIdentity),
			Value: cfg.DefaultIdentity,
		})
	}

	// 2. Inject HTTP_PROXY / HTTPS_PROXY / NO_PROXY into every
	//    existing container so outbound traffic routes through the
	//    engine. JSON Patch can't conditionally create the env
	//    array, so we emit different ops depending on whether the
	//    container already has env defined.
	proxyURL := fmt.Sprintf("http://localhost:%d", cfg.engineListenPort())
	proxyEnv := []envVar{
		{Name: "HTTP_PROXY", Value: proxyURL},
		{Name: "HTTPS_PROXY", Value: proxyURL},
		{Name: "NO_PROXY", Value: "localhost,127.0.0.1,.svc,.cluster.local"},
	}
	// If MITM trust injection is enabled, add the three standard
	// HTTPS trust env vars to the proxy env list so they go to
	// every user container in the same patch operation as the
	// HTTP_PROXY vars. Single source of truth for env injection.
	caPath := cfg.mitmCAMountPath()
	if cfg.MITMCASecretName != "" {
		proxyEnv = append(proxyEnv,
			envVar{Name: "SSL_CERT_FILE", Value: caPath},
			envVar{Name: "REQUESTS_CA_BUNDLE", Value: caPath},
			envVar{Name: "NODE_EXTRA_CA_CERTS", Value: caPath},
			// Go-specific trust: Go reads the system trust store
			// directly; SSL_CERT_FILE works on Linux distros where
			// Go falls back to a known bundle location.
		)
	}

	for idx, c := range pod.Spec.Containers {
		if len(c.Env) == 0 {
			// Container has no env array — create it with our three
			// vars. `add` on a missing object field creates it.
			ops = append(ops, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/env", idx),
				Value: proxyEnv,
			})
		} else {
			// Container has env — append to it.
			for _, ev := range proxyEnv {
				ops = append(ops, patchOp{
					Op:    "add",
					Path:  fmt.Sprintf("/spec/containers/%d/env/-", idx),
					Value: ev,
				})
			}
		}

		// MITM trust mount: add the CA volume mount to each user
		// container so the env vars above point at an existing file.
		if cfg.MITMCASecretName != "" {
			mountOp := mitmCAVolumeMountOp(idx, caPath)
			ops = append(ops, mountOp)
		}
	}

	// MITM trust volume: declare the Secret-backed volume on the
	// pod once (regardless of how many user containers there are).
	if cfg.MITMCASecretName != "" {
		ops = append(ops, mitmCAVolumeOp(cfg))
	}

	// 3. Append the engine sidecar container.
	engineContainer := buildEngineContainer(cfg)
	ops = append(ops, patchOp{
		Op:    "add",
		Path:  "/spec/containers/-",
		Value: engineContainer,
	})

	return json.Marshal(ops)
}

func (p PodLike) alreadyInjected() bool {
	for _, c := range p.Spec.Containers {
		if c.Name == EngineContainerName {
			return true
		}
	}
	return false
}

// jsonPointerLabel returns the JSON-Pointer for /metadata/labels/<key>
// with the key escaped per RFC 6901 (~ -> ~0, / -> ~1).
func jsonPointerLabel(key string) string {
	// Escape per RFC 6901: '~' becomes '~0', '/' becomes '~1'.
	out := []byte{}
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, key[i])
		}
	}
	return "/metadata/labels/" + string(out)
}

func (c Config) engineListenPort() int {
	if c.EngineListenPort > 0 {
		return c.EngineListenPort
	}
	return 8080
}

func (c Config) mitmCACertKey() string {
	if c.MITMCACertKey != "" {
		return c.MITMCACertKey
	}
	return "tls.crt"
}

func (c Config) mitmCAMountPath() string {
	if c.MITMCAMountPath != "" {
		return c.MITMCAMountPath
	}
	return "/etc/aegrail/mitm-ca/ca.crt"
}

// mitmCAVolumeMountOp adds the CA volume mount to the user
// container at index `idx`. JSON Patch can't conditionally create
// the volumeMounts array, so we use a known dir path and add the
// entry. K8s tolerates an `add` on a missing field for arrays of
// objects too.
func mitmCAVolumeMountOp(idx int, caPath string) patchOp {
	// Mount the CA volume at the directory containing the CA file
	// (the file lives at /etc/aegrail/mitm-ca/ca.crt, so mount the
	// dir /etc/aegrail/mitm-ca). The Secret's tls.crt key projects
	// as a file named tls.crt inside that dir; we use subPath to
	// project it as ca.crt so the env vars point at the right path.
	dir := caPath[:strings.LastIndex(caPath, "/")]
	return patchOp{
		Op:   "add",
		Path: fmt.Sprintf("/spec/containers/%d/volumeMounts/-", idx),
		Value: map[string]any{
			"name":      "aegrail-mitm-ca",
			"mountPath": dir,
			"readOnly":  true,
		},
	}
}

// mitmCAVolumeOp declares the Secret-backed volume on the pod.
// Single op regardless of how many user containers mount it.
func mitmCAVolumeOp(cfg Config) patchOp {
	caPath := cfg.mitmCAMountPath()
	caFileName := caPath[strings.LastIndex(caPath, "/")+1:]
	return patchOp{
		Op:   "add",
		Path: "/spec/volumes/-",
		Value: map[string]any{
			"name": "aegrail-mitm-ca",
			"secret": map[string]any{
				"secretName": cfg.MITMCASecretName,
				"items": []map[string]any{
					{"key": cfg.mitmCACertKey(), "path": caFileName},
				},
			},
		},
	}
}

// buildEngineContainer returns the corev1.Container-shape map that
// becomes the injected sidecar.
func buildEngineContainer(cfg Config) container {
	env := []envVar{
		{Name: "AEGRAIL_ENGINE_ALLOWLIST", Value: cfg.Allowlist},
		// agent_identity is read from the pod label via downward
		// API so audit events stamp the *agent's* identity, not
		// the engine's hardcoded default.
		{
			Name: "AEGRAIL_ENGINE_AGENT_IDENTITY",
			ValueFrom: map[string]any{
				"fieldRef": map[string]any{
					"fieldPath": fmt.Sprintf("metadata.labels['%s']", LabelIdentity),
				},
			},
		},
		{Name: "AEGRAIL_ENGINE_LISTEN", Value: fmt.Sprintf(":%d", cfg.engineListenPort())},
	}
	switch cfg.AuditMode {
	case "file":
		env = append(env, envVar{Name: "AEGRAIL_ENGINE_AUDIT_FILE", Value: cfg.AuditFile})
	default: // stdout (and empty)
		env = append(env, envVar{Name: "AEGRAIL_ENGINE_AUDIT_STDOUT", Value: "1"})
	}
	if cfg.MaxRequests != "" {
		env = append(env, envVar{Name: "AEGRAIL_ENGINE_MAX_REQUESTS", Value: cfg.MaxRequests})
	}
	if cfg.RateLimit != "" {
		env = append(env, envVar{Name: "AEGRAIL_ENGINE_RATE_LIMIT", Value: cfg.RateLimit})
	}
	if cfg.MaxTokens != "" {
		env = append(env, envVar{Name: "AEGRAIL_ENGINE_MAX_TOKENS", Value: cfg.MaxTokens})
	}

	return container{
		Name:            EngineContainerName,
		Image:           cfg.Image,
		ImagePullPolicy: "IfNotPresent",
		Env:             env,
		Ports: []map[string]any{
			{
				"name":          "proxy",
				"containerPort": cfg.engineListenPort(),
				"protocol":      "TCP",
			},
		},
		LivenessProbe: map[string]any{
			"httpGet":             map[string]any{"path": "/healthz", "port": "proxy"},
			"initialDelaySeconds": 2,
			"periodSeconds":       10,
		},
		ReadinessProbe: map[string]any{
			"httpGet":             map[string]any{"path": "/readyz", "port": "proxy"},
			"initialDelaySeconds": 1,
			"periodSeconds":       5,
		},
		Resources: map[string]any{
			"requests": map[string]string{"cpu": "50m", "memory": "32Mi"},
			"limits":   map[string]string{"cpu": "200m", "memory": "128Mi"},
		},
		SecurityContext: map[string]any{
			"runAsNonRoot":             true,
			"runAsUser":                65532,
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
	}
}
