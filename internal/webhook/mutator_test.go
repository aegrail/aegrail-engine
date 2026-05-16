package webhook

import (
	"encoding/json"
	"strings"
	"testing"
)

func defaultConfig() Config {
	return Config{
		Image:            "ghcr.io/arpitcoder/aegrail-engine:0.2.0",
		Allowlist:        "api.openai.com,*.anthropic.com",
		AuditMode:        "stdout",
		DefaultIdentity:  "auto-injected-v1",
		EngineListenPort: 8080,
	}
}

func samplePod(containerNames ...string) PodLike {
	p := PodLike{}
	p.Metadata.Name = "agent-1"
	p.Metadata.Namespace = "agents"
	for _, n := range containerNames {
		p.Spec.Containers = append(p.Spec.Containers, PodLikeContainer{Name: n})
	}
	return p
}

func samplePodWithEnv(name string, existing []map[string]interface{}) PodLike {
	p := PodLike{}
	p.Metadata.Name = "agent-1"
	p.Metadata.Namespace = "agents"
	p.Spec.Containers = append(p.Spec.Containers, PodLikeContainer{
		Name: name,
		Env:  existing,
	})
	return p
}

func TestBuildPatch_InjectsEngineContainer(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent")
	patch, err := BuildPatch(pod, defaultConfig())
	if err != nil {
		t.Fatalf("BuildPatch: %v", err)
	}
	if patch == nil {
		t.Fatal("expected a patch, got nil (not-yet-injected pod)")
	}

	var ops []map[string]any
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("patch is not valid JSON: %v\n%s", err, patch)
	}

	// Last op must add the engine container.
	last := ops[len(ops)-1]
	if last["op"] != "add" || last["path"] != "/spec/containers/-" {
		t.Errorf("final op is not the engine-container add: %+v", last)
	}
	c, _ := last["value"].(map[string]any)
	if c["name"] != EngineContainerName {
		t.Errorf("injected container name: got %v, want %s", c["name"], EngineContainerName)
	}
	if c["image"] == "" {
		t.Error("injected container has no image")
	}
}

func TestBuildPatch_CreatesEnvArrayWhenMissing(t *testing.T) {
	t.Parallel()
	// Container has no env field — patch must create it as a whole
	// array rather than trying to append to a missing list.
	pod := samplePod("agent")
	patch, err := BuildPatch(pod, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patch), `"path":"/spec/containers/0/env"`) {
		t.Errorf("patch should target /spec/containers/0/env (create-array form): %s", patch)
	}
	// Must NOT have the append-only form, which would fail server-side
	if strings.Contains(string(patch), `"path":"/spec/containers/0/env/-"`) {
		t.Errorf("patch incorrectly uses append-only form for env-less container: %s", patch)
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
		if !strings.Contains(string(patch), `"name":"`+name+`"`) {
			t.Errorf("patch missing %s env injection", name)
		}
	}
}

func TestBuildPatch_AppendsToExistingEnv(t *testing.T) {
	t.Parallel()
	// Container already has env — patch must append rather than
	// replace the existing entries.
	pod := samplePodWithEnv("agent", []map[string]interface{}{
		{"name": "USER_VAR", "value": "preserved"},
	})
	patch, err := BuildPatch(pod, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patch), `"path":"/spec/containers/0/env/-"`) {
		t.Errorf("patch should use append form for container with existing env: %s", patch)
	}
	// Must NOT replace the env array (no `add /env` op)
	if strings.Contains(string(patch), `"path":"/spec/containers/0/env","value":[`) {
		t.Errorf("patch incorrectly replaces existing env array: %s", patch)
	}
}

func TestBuildPatch_DefaultsIdentityLabelWhenMissing(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent")
	patch, _ := BuildPatch(pod, defaultConfig())
	// pod has no labels at all -> patch should add /metadata/labels
	if !strings.Contains(string(patch), `"path":"/metadata/labels"`) {
		t.Error("patch should add /metadata/labels when pod has none")
	}
}

func TestBuildPatch_PreservesIdentityLabelWhenSet(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent")
	pod.Metadata.Labels = map[string]string{LabelIdentity: "preset-bot/v1"}
	patch, _ := BuildPatch(pod, defaultConfig())
	if strings.Contains(string(patch), `"preset-bot/v1"`) {
		t.Error("patch should NOT include the pre-existing identity value")
	}
	if strings.Contains(string(patch), `"/metadata/labels/aegrail.io~1identity"`) {
		t.Error("patch should NOT add identity label when one is preset")
	}
}

func TestBuildPatch_AddsLabelWhenLabelsExistButIdentityDoes_not(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent")
	pod.Metadata.Labels = map[string]string{"app": "myapp"}
	patch, _ := BuildPatch(pod, defaultConfig())
	if !strings.Contains(string(patch), `"/metadata/labels/aegrail.io~1identity"`) {
		t.Errorf("patch should add identity sub-label when labels exist but identity is absent: %s", patch)
	}
}

func TestBuildPatch_IdempotentWhenEngineAlreadyPresent(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent", EngineContainerName)
	patch, err := BuildPatch(pod, defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if patch != nil {
		t.Errorf("expected nil patch for already-injected pod, got %s", patch)
	}
}

func TestBuildPatch_EngineEnvIncludesIdentityFieldRef(t *testing.T) {
	t.Parallel()
	pod := samplePod("agent")
	patch, _ := BuildPatch(pod, defaultConfig())
	// Engine env should include AEGRAIL_ENGINE_AGENT_IDENTITY with
	// valueFrom.fieldRef pointing at metadata.labels['aegrail.io/identity']
	if !strings.Contains(string(patch), `metadata.labels['aegrail.io/identity']`) {
		t.Error("engine env missing downward-API fieldRef for AEGRAIL_ENGINE_AGENT_IDENTITY")
	}
}

func TestBuildPatch_OptionalLimitsAndRateLimit(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.MaxRequests = "1000"
	cfg.RateLimit = "10/sec"
	patch, _ := BuildPatch(samplePod("agent"), cfg)
	if !strings.Contains(string(patch), `"AEGRAIL_ENGINE_MAX_REQUESTS"`) {
		t.Error("patch missing AEGRAIL_ENGINE_MAX_REQUESTS env when configured")
	}
	if !strings.Contains(string(patch), `"AEGRAIL_ENGINE_RATE_LIMIT"`) {
		t.Error("patch missing AEGRAIL_ENGINE_RATE_LIMIT env when configured")
	}
}

func TestBuildPatch_MITMCAInjectsVolumeAndTrustEnv(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.MITMCASecretName = "aegrail-mitm-ca"
	patch, err := BuildPatch(samplePod("agent"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	patchStr := string(patch)

	// All three standard HTTPS trust env vars should be set
	for _, env := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		if !strings.Contains(patchStr, `"name":"`+env+`"`) {
			t.Errorf("patch missing %s env when MITM CA is configured", env)
		}
	}
	// Volume mount on the user container
	if !strings.Contains(patchStr, `"name":"aegrail-mitm-ca"`) {
		t.Errorf("patch missing aegrail-mitm-ca volume reference")
	}
	if !strings.Contains(patchStr, `"mountPath":"/etc/aegrail/mitm-ca"`) {
		t.Errorf("patch missing /etc/aegrail/mitm-ca mount path")
	}
	// Pod-level volume declaration
	if !strings.Contains(patchStr, `"path":"/spec/volumes/-"`) {
		t.Errorf("patch missing /spec/volumes/- volume declaration")
	}
	if !strings.Contains(patchStr, `"secretName":"aegrail-mitm-ca"`) {
		t.Errorf("patch missing Secret reference")
	}
}

func TestBuildPatch_NoMITMCAMeansNoTrustInjection(t *testing.T) {
	t.Parallel()
	// Default config has empty MITMCASecretName — no trust injection
	cfg := defaultConfig()
	patch, _ := BuildPatch(samplePod("agent"), cfg)
	patchStr := string(patch)
	for _, env := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		if strings.Contains(patchStr, `"name":"`+env+`"`) {
			t.Errorf("patch should NOT include %s env when MITM CA is not configured", env)
		}
	}
	if strings.Contains(patchStr, `"aegrail-mitm-ca"`) {
		t.Errorf("patch should NOT reference the MITM CA volume when not configured")
	}
}

func TestBuildPatch_FileAuditModeAddsFileEnv(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	cfg.AuditMode = "file"
	cfg.AuditFile = "/var/log/aegrail/audit.jsonl"
	patch, _ := BuildPatch(samplePod("agent"), cfg)
	if !strings.Contains(string(patch), `"AEGRAIL_ENGINE_AUDIT_FILE"`) {
		t.Error("file audit mode should set AEGRAIL_ENGINE_AUDIT_FILE")
	}
	if strings.Contains(string(patch), `"AEGRAIL_ENGINE_AUDIT_STDOUT"`) {
		t.Error("file audit mode should NOT set AEGRAIL_ENGINE_AUDIT_STDOUT")
	}
}
