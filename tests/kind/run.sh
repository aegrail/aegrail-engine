#!/usr/bin/env bash
# Robust kind cluster end-to-end test for the aegrail-engine Helm
# chart + proxy. Every scenario MUST pass before the chart and image
# are tag-able as v0.1.0-rc.
#
# Scenarios:
#   1.  prereqs                — every CLI present, daemon running
#   2.  helm lint              — chart syntax / best practice
#   3.  helm template          — rendered manifests valid; ConfigMap
#                                 contains AEGRAIL_ENGINE_* env vars
#   4.  build + cluster + load — image into kind
#   5.  helm install           — deployment becomes Ready
#   6.  health endpoints       — /healthz and /readyz return 200
#   7.  HTTP forward allowed   — POST to Ollama via engine returns
#                                 real model output
#   8.  HTTP forward denied    — request to non-allowlisted host
#                                 returns 403 with X-Aegrail-Decision
#   9.  HTTPS CONNECT allowed  — example.com TLS handshake through
#                                 tunnel succeeds
#   10. HTTPS CONNECT denied   — disallowed host: curl exits 56
#                                 (tunnel refused)
#   11. audit chain validates  — Python aegrail.audit.verify_chain
#                                 over engine logs returns (True, -1)
#   12. helm upgrade           — change allowlist; pod rerolls
#   13. helm uninstall         — every chart-managed resource gone
#
# Run with:
#   bash tests/kind/run.sh
#
# Prereqs on the host:
#   docker, kind, kubectl, helm, go, python3
#   Ollama running on localhost:11434 with at least llama3.2:3b pulled
#   The /Users/arpitnigam/aegrail venv with aegrail==0.2.6 installed

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AEGRAIL_PY="${AEGRAIL_PY:-/Users/arpitnigam/aegrail}"
CLUSTER_NAME="${KIND_CLUSTER:-aegrail-engine-kind-test}"
IMAGE_NAME="aegrail-engine:kind-test"
NAMESPACE="aegrail-test"
RELEASE_NAME="ae-test"
CHART_PATH="${ROOT}/deploy/helm"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2:3b}"

cleanup() {
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "(KEEP_CLUSTER=1; leaving cluster running)"
    return
  fi
  echo ""
  echo "=== cleanup ==="
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  docker image rm "${IMAGE_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; exit 1; }

# ----------------------------------------------------------------
echo "=== Scenario 1: prereqs ==="
command -v docker  >/dev/null || fail "docker not installed"
command -v kind    >/dev/null || fail "kind not installed"
command -v kubectl >/dev/null || fail "kubectl not installed"
command -v helm    >/dev/null || fail "helm not installed"
command -v go      >/dev/null || fail "go not installed"
command -v python3 >/dev/null || fail "python3 not installed"
docker info >/dev/null 2>&1   || fail "docker daemon not running"
curl -sS -m 2 -o /dev/null http://localhost:11434/ || fail "Ollama not reachable at localhost:11434"
if ! curl -sS http://localhost:11434/api/tags | python3 -c "import json,sys; sys.exit(0 if any(m['name']=='$OLLAMA_MODEL' for m in json.load(sys.stdin)['models']) else 1)" 2>/dev/null; then
  fail "Ollama model '$OLLAMA_MODEL' not present (pull with: ollama pull $OLLAMA_MODEL)"
fi
# aegrail Python (for verify_chain cross-language validation)
if [ ! -f "${AEGRAIL_PY}/.venv/bin/python" ]; then
  fail "aegrail Python venv not found at ${AEGRAIL_PY}/.venv"
fi
if ! "${AEGRAIL_PY}/.venv/bin/python" -c "from aegrail.audit import verify_chain" 2>/dev/null; then
  fail "aegrail.audit.verify_chain not importable from ${AEGRAIL_PY}/.venv"
fi
pass "all CLIs present, docker running, Ollama reachable, aegrail-py available"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 2: helm lint ==="
if helm lint "${CHART_PATH}" --set 'policy.allowlist[0]=api.example.com' 2>&1 | grep -q "0 chart(s) failed"; then
  pass "chart lints clean"
else
  helm lint "${CHART_PATH}" --set 'policy.allowlist[0]=api.example.com'
  fail "helm lint reported failures"
fi

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 3: helm template ==="
helm template "${RELEASE_NAME}" "${CHART_PATH}" \
  --set "policy.allowlist[0]=api.openai.com" \
  --set "policy.allowlist[1]=*.anthropic.com" \
  > /tmp/aegrail-helm-rendered.yaml
for kind in Deployment Service ConfigMap ServiceAccount; do
  grep -q "^kind: ${kind}$" /tmp/aegrail-helm-rendered.yaml \
    || { cat /tmp/aegrail-helm-rendered.yaml; fail "rendered output missing kind: ${kind}"; }
done
grep -q "AEGRAIL_ENGINE_ALLOWLIST: \"api.openai.com,\*.anthropic.com\"" /tmp/aegrail-helm-rendered.yaml \
  || fail "ConfigMap does not contain AEGRAIL_ENGINE_ALLOWLIST"
grep -q "AEGRAIL_ENGINE_AGENT_IDENTITY: \"egress-proxy/v1\"" /tmp/aegrail-helm-rendered.yaml \
  || fail "ConfigMap does not contain AEGRAIL_ENGINE_AGENT_IDENTITY"
grep -q "configMapRef:" /tmp/aegrail-helm-rendered.yaml \
  || fail "Deployment does not use envFrom: configMapRef"
pass "rendered manifests have the expected env-var ConfigMap shape"
rm -f /tmp/aegrail-helm-rendered.yaml

# v0.1.1 check: agentIdentityFromLabel renders the downward-API fieldRef
helm template "${RELEASE_NAME}" "${CHART_PATH}" \
  --set "policy.allowlist[0]=api.openai.com" \
  --set "agentIdentityFromLabel=aegrail.io/identity" \
  > /tmp/aegrail-helm-label.yaml
grep -q "metadata.labels\['aegrail.io/identity'\]" /tmp/aegrail-helm-label.yaml \
  || { cat /tmp/aegrail-helm-label.yaml; fail "agentIdentityFromLabel did not render fieldRef"; }
grep -q "AEGRAIL_ENGINE_AGENT_IDENTITY" /tmp/aegrail-helm-label.yaml \
  || fail "AEGRAIL_ENGINE_AGENT_IDENTITY env not present when label binding is set"
pass "agentIdentityFromLabel renders downward-API fieldRef (v0.1.1)"
rm -f /tmp/aegrail-helm-label.yaml

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 4: build image + create cluster + load image ==="
( cd "${ROOT}" && go build -o /tmp/aegrail-engine-bin ./cmd/aegrail-engine ) || fail "go build failed"
rm -f /tmp/aegrail-engine-bin
pass "go binary builds clean"

docker build -t "${IMAGE_NAME}" -f "${ROOT}/deploy/docker/Dockerfile" "${ROOT}" >/tmp/aegrail-build.log 2>&1 \
  || { tail -30 /tmp/aegrail-build.log; fail "docker build failed"; }
pass "docker image built (${IMAGE_NAME})"

kind create cluster --name "${CLUSTER_NAME}" >/tmp/aegrail-kind.log 2>&1 \
  || { cat /tmp/aegrail-kind.log; fail "kind create failed"; }
pass "kind cluster '${CLUSTER_NAME}' created"

kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}" >/dev/null 2>&1 \
  || fail "kind load image failed"
pass "image loaded into cluster"

kubectl create namespace "${NAMESPACE}" >/dev/null
pass "namespace '${NAMESPACE}' created"

# Get host IP for host.docker.internal — kind nodes resolve it; we
# pin it via hostAliases on the test pod so pod DNS reaches the
# host's Ollama deterministically.
HOST_IP=$(docker exec "${CLUSTER_NAME}-control-plane" getent ahosts host.docker.internal 2>/dev/null | awk 'NR==1{print $1}')
if [ -z "${HOST_IP}" ]; then
  HOST_IP=$(docker exec "${CLUSTER_NAME}-control-plane" sh -c "ip route | awk '/default/ {print \$3; exit}'")
fi
[ -n "${HOST_IP}" ] || fail "could not determine host IP reachable from kind"
pass "host.docker.internal -> ${HOST_IP} (from kind node)"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 5: helm install ==="
helm install "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-test" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=host.docker.internal" \
  --set "policy.allowlist[1]=example.com" \
  --wait --timeout 120s >/dev/null \
  || fail "helm install failed"
pass "helm install succeeded"

kubectl rollout status "deployment/${RELEASE_NAME}-aegrail-engine" -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "deployment did not become available"
pass "engine deployment Ready"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 6: health endpoints (via port-forward) ==="
kubectl port-forward -n "${NAMESPACE}" "service/${RELEASE_NAME}-aegrail-engine" 18080:8080 >/tmp/aegrail-pf.log 2>&1 &
PF_PID=$!
for _ in $(seq 1 20); do
  curl -s -o /dev/null --max-time 1 http://localhost:18080/healthz && break
  sleep 0.5
done

[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://localhost:18080/healthz)" = "200" ] \
  && pass "/healthz returns 200" || fail "/healthz did not return 200"
[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://localhost:18080/readyz)" = "200" ] \
  && pass "/readyz returns 200" || fail "/readyz did not return 200"

kill ${PF_PID} 2>/dev/null || true
wait ${PF_PID} 2>/dev/null || true
rm -f /tmp/aegrail-pf.log

# ----------------------------------------------------------------
echo ""
echo "=== Deploy test curl pod (with hostAlias so host.docker.internal resolves) ==="
kubectl -n "${NAMESPACE}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: testcurl
  labels: { app: aegrail-testcurl }
spec:
  restartPolicy: Never
  hostAliases:
    - ip: ${HOST_IP}
      hostnames: [host.docker.internal]
  containers:
    - name: curl
      image: alpine/curl:latest
      command: ["sleep", "600"]
EOF
kubectl -n "${NAMESPACE}" wait pod/testcurl --for=condition=Ready --timeout=60s >/dev/null \
  || fail "testcurl pod did not become Ready"
pass "testcurl pod Ready"

ENGINE_HOST="${RELEASE_NAME}-aegrail-engine.${NAMESPACE}.svc.cluster.local:8080"
PROXY_URL="http://${ENGINE_HOST}"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 7: HTTP forward allowed — POST to Ollama through engine ==="
# Generate one short completion from Ollama via the engine proxy.
RESP=$(kubectl -n "${NAMESPACE}" exec testcurl -- sh -c "
  curl -sS -m 60 --proxy '${PROXY_URL}' \
    -H 'Content-Type: application/json' \
    -d '{\"model\":\"${OLLAMA_MODEL}\",\"prompt\":\"Reply with exactly two words: kind ok\",\"stream\":false,\"options\":{\"num_predict\":8}}' \
    http://host.docker.internal:11434/api/generate
")
echo "${RESP}" | python3 -c "import json,sys; d=json.load(sys.stdin); print('ollama said:', repr(d.get('response','')))" \
  || { echo "raw response: $RESP"; fail "Ollama via engine: response was not valid JSON"; }
pass "Ollama returned a model completion through the engine proxy"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 8: HTTP forward denied — non-allowlisted host returns 403 ==="
DENIED=$(kubectl -n "${NAMESPACE}" exec testcurl -- sh -c "
  curl -sS -m 10 --proxy '${PROXY_URL}' -o /dev/null \
    -w 'status=%{http_code} decision=%header{x-aegrail-decision}' \
    http://api.openai.com/
")
echo "  ${DENIED}"
echo "${DENIED}" | grep -q "status=403" \
  && echo "${DENIED}" | grep -q "decision=denied" \
  && pass "denied host returned 403 with X-Aegrail-Decision: denied" \
  || fail "denied host did not return 403 + denied header (got: ${DENIED})"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 9: HTTPS CONNECT allowed — TLS to example.com via tunnel ==="
HTTPS_OK=$(kubectl -n "${NAMESPACE}" exec testcurl -- sh -c "
  curl -sS -m 15 --proxy '${PROXY_URL}' -o /dev/null -w '%{http_code}' https://example.com/
")
[ "${HTTPS_OK}" = "200" ] && pass "https://example.com via CONNECT tunnel returned 200" \
  || fail "HTTPS CONNECT allowed did not succeed (got: ${HTTPS_OK})"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 10: HTTPS CONNECT denied — disallowed host fails fast ==="
# curl exits 56 when proxy refuses the CONNECT tunnel
HTTPS_DENY_EXIT=$(kubectl -n "${NAMESPACE}" exec testcurl -- sh -c "
  curl -sS -m 10 --proxy '${PROXY_URL}' -o /dev/null https://api.openai.com/ 2>&1
  echo \"exit=\$?\"
" | tail -1)
echo "  ${HTTPS_DENY_EXIT}"
echo "${HTTPS_DENY_EXIT}" | grep -q "exit=56" \
  && pass "denied HTTPS host: curl exit 56 (CONNECT refused)" \
  || fail "denied HTTPS did not yield curl exit 56 (got: ${HTTPS_DENY_EXIT})"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 11: audit chain validates with Python verify_chain ==="
ENGINE_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n "${NAMESPACE}" "${ENGINE_POD}" > /tmp/aegrail-engine.log
grep -E '^\{"ts":' /tmp/aegrail-engine.log > /tmp/aegrail-engine-audit.jsonl
NUM_EVENTS=$(wc -l < /tmp/aegrail-engine-audit.jsonl | tr -d ' ')
[ "${NUM_EVENTS}" -ge 5 ] || fail "expected at least 5 audit events (engine_start + 4 egress events), got ${NUM_EVENTS}"

"${AEGRAIL_PY}/.venv/bin/python" - <<'PY' || fail "audit chain verification failed"
import json
import sys
from aegrail.audit import AuditEvent, verify_chain
with open("/tmp/aegrail-engine-audit.jsonl") as f:
    events = [AuditEvent.model_validate(json.loads(line)) for line in f if line.strip()]
ok, bad = verify_chain(events)
print(f"  events: {len(events)}")
counts = {}
for e in events:
    counts[e.event] = counts.get(e.event, 0) + 1
for k in sorted(counts):
    print(f"    {k}: {counts[k]}")
if not ok:
    print(f"  chain broken at index {bad}", file=sys.stderr)
    sys.exit(1)
expected = {"egress_allowed", "egress_denied"}
present = set(counts) & expected
missing = expected - present
if missing:
    print(f"  missing required event types: {missing}", file=sys.stderr)
    sys.exit(1)
# v0.3.0: verify the Ollama egress_allowed event carries parsed
# LLM token counts (tokens_in, tokens_out, llm_model).
ollama_events = [
    e for e in events
    if e.event == "egress_allowed"
    and e.payload.get("host") == "host.docker.internal"
    and e.payload.get("path", "").startswith("/api/")
]
if not ollama_events:
    print("  no Ollama egress_allowed event found in chain", file=sys.stderr)
    sys.exit(1)
ev = ollama_events[0]
tokens_in = ev.payload.get("tokens_in", 0)
tokens_out = ev.payload.get("tokens_out", 0)
llm_model = ev.payload.get("llm_model", "")
print(f"  Ollama event parsed: model={llm_model!r} tokens_in={tokens_in} tokens_out={tokens_out}")
if tokens_in <= 0 or tokens_out <= 0:
    print(f"  v0.3.0 token parsing failed: expected non-zero tokens, got in={tokens_in} out={tokens_out}", file=sys.stderr)
    sys.exit(1)
if not llm_model:
    print("  v0.3.0 token parsing failed: llm_model field missing/empty", file=sys.stderr)
    sys.exit(1)
PY
pass "Python verify_chain validated the engine's audit chain end-to-end"
pass "v0.3.0 LLM token parsing extracted tokens from Ollama response"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 12: helm upgrade with changed allowlist ==="
ORIGINAL_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}",app.kubernetes.io/name=aegrail-engine -o jsonpath='{.items[0].metadata.name}')
helm upgrade "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-test" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=upgraded.example.com" \
  --set "policy.allowlist[1]=generativelanguage.googleapis.com" \
  --wait --timeout 120s >/dev/null \
  || fail "helm upgrade failed"
kubectl rollout status "deployment/${RELEASE_NAME}-aegrail-engine" -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "deployment did not roll out after upgrade"
NEW_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}",app.kubernetes.io/name=aegrail-engine --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
[ "${NEW_POD}" != "${ORIGINAL_POD}" ] && pass "ConfigMap change rolled the pod (old=${ORIGINAL_POD}, new=${NEW_POD})" \
  || fail "pod did not restart after allowlist change"
NEW_CM=$(kubectl get configmap -n "${NAMESPACE}" "${RELEASE_NAME}-aegrail-engine-policy" -o jsonpath='{.data.AEGRAIL_ENGINE_ALLOWLIST}')
echo "${NEW_CM}" | grep -q "upgraded.example.com" && pass "ConfigMap reflects upgraded allowlist (${NEW_CM})" \
  || fail "ConfigMap allowlist did not update (got: ${NEW_CM})"

# ----------------------------------------------------------------
echo ""
echo "=== Scenario 13: helm uninstall + cleanup verification ==="
kubectl delete pod testcurl -n "${NAMESPACE}" --ignore-not-found >/dev/null
helm uninstall "${RELEASE_NAME}" --namespace "${NAMESPACE}" >/dev/null \
  || fail "helm uninstall failed"
sleep 5
REMAIN_DEPLOY=$(kubectl get deploy -n "${NAMESPACE}" -l "app.kubernetes.io/instance=${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAIN_SVC=$(kubectl get svc -n "${NAMESPACE}" -l "app.kubernetes.io/instance=${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAIN_CM=$(kubectl get cm -n "${NAMESPACE}" -l "app.kubernetes.io/instance=${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAIN_SA=$(kubectl get sa -n "${NAMESPACE}" -l "app.kubernetes.io/instance=${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
[ "${REMAIN_DEPLOY}" -eq 0 ] || fail "Deployment not cleaned up (${REMAIN_DEPLOY} remaining)"
[ "${REMAIN_SVC}" -eq 0 ]    || fail "Service not cleaned up (${REMAIN_SVC} remaining)"
[ "${REMAIN_CM}" -eq 0 ]     || fail "ConfigMap not cleaned up (${REMAIN_CM} remaining)"
[ "${REMAIN_SA}" -eq 0 ]     || fail "ServiceAccount not cleaned up (${REMAIN_SA} remaining)"
pass "all chart-managed resources removed"

# ----------------------------------------------------------------
echo ""
echo "=================================="
echo "all 13 scenarios passed."
echo "v0.1.0-rc gate: green."
echo "=================================="
