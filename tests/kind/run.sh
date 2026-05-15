#!/usr/bin/env bash
# Robust kind cluster smoke test for the aegrail-engine Helm chart.
#
# Six scenarios, each MUST pass before the chart is releasable:
#
#   1. helm lint                — chart syntax + best-practices
#   2. helm template            — rendered manifests parse as valid YAML
#   3. helm install (defaults)  — Deployment becomes Available
#   4. service reachable        — /healthz and /readyz return 200
#   5. helm upgrade w/ override — allowlist change triggers pod restart
#   6. helm uninstall           — every resource is removed
#
# All scenarios use a locally-built image (loaded into kind), so no
# registry / network dependency is required.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER:-aegrail-engine-kind-test}"
IMAGE_NAME="aegrail-engine:kind-test"
NAMESPACE="aegrail-test"
RELEASE_NAME="ae-test"
CHART_PATH="${ROOT}/deploy/helm"

cleanup() {
  echo ""
  echo "=== cleanup ==="
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  docker image rm "${IMAGE_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; exit 1; }

echo "=== Prereqs ==="
command -v docker  >/dev/null || fail "docker not installed"
command -v kind    >/dev/null || fail "kind not installed (brew install kind)"
command -v kubectl >/dev/null || fail "kubectl not installed"
command -v helm    >/dev/null || fail "helm not installed (brew install helm)"
command -v go      >/dev/null || fail "go not installed"
docker info >/dev/null 2>&1   || fail "docker daemon not running"
pass "all CLIs present, docker running"

echo ""
echo "=== Scenario 1: helm lint ==="
if helm lint "${CHART_PATH}" 2>&1 | grep -q "0 chart(s) failed"; then
  pass "chart lints clean"
else
  helm lint "${CHART_PATH}"
  fail "helm lint reported failures"
fi

echo ""
echo "=== Scenario 2: helm template ==="
if helm template "${RELEASE_NAME}" "${CHART_PATH}" \
     --set "policy.allowlist[0]=api.openai.com" \
     --set "policy.allowlist[1]=*.anthropic.com" \
     >/tmp/aegrail-helm-rendered.yaml 2>&1; then
  if grep -q "kind: Deployment" /tmp/aegrail-helm-rendered.yaml \
     && grep -q "kind: Service" /tmp/aegrail-helm-rendered.yaml \
     && grep -q "kind: ConfigMap" /tmp/aegrail-helm-rendered.yaml \
     && grep -q "kind: ServiceAccount" /tmp/aegrail-helm-rendered.yaml; then
    pass "all expected resources rendered"
  else
    cat /tmp/aegrail-helm-rendered.yaml
    fail "rendered output missing expected resources"
  fi
else
  fail "helm template failed"
fi
rm -f /tmp/aegrail-helm-rendered.yaml

echo ""
echo "=== Scenario 3: build image + create cluster ==="
# Build local binary, then container image
( cd "${ROOT}" && go build -o /tmp/aegrail-engine-bin ./cmd/aegrail-engine ) || fail "go build failed"
pass "go binary built"
rm -f /tmp/aegrail-engine-bin

docker build -t "${IMAGE_NAME}" -f "${ROOT}/deploy/docker/Dockerfile" "${ROOT}" >/tmp/aegrail-build.log 2>&1 \
  || { cat /tmp/aegrail-build.log; fail "docker build failed"; }
pass "docker image built"

kind create cluster --name "${CLUSTER_NAME}" >/tmp/aegrail-kind.log 2>&1 \
  || { cat /tmp/aegrail-kind.log; fail "kind create failed"; }
pass "kind cluster '${CLUSTER_NAME}' created"

kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}" >/dev/null 2>&1 \
  || fail "kind load image failed"
pass "image loaded into cluster"

kubectl create namespace "${NAMESPACE}" >/dev/null
pass "namespace '${NAMESPACE}' created"

echo ""
echo "=== Scenario 4: helm install with defaults + override image ==="
helm install "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-test" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=api.openai.com" \
  --set "policy.allowlist[1]=*.anthropic.com" \
  --wait --timeout 120s >/dev/null \
  || fail "helm install failed"
pass "helm install succeeded"

# Deployment should be Available (rolled out)
kubectl rollout status deployment/${RELEASE_NAME}-aegrail-engine -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "deployment did not become available"
pass "deployment rolled out"

# ConfigMap content matches override
ALLOWLIST_CONTENT=$(kubectl get configmap "${RELEASE_NAME}-aegrail-engine-policy" -n "${NAMESPACE}" -o jsonpath='{.data.allowlist\.yaml}')
echo "${ALLOWLIST_CONTENT}" | grep -q "api.openai.com" \
  || fail "ConfigMap allowlist missing api.openai.com"
echo "${ALLOWLIST_CONTENT}" | grep -q "anthropic.com" \
  || fail "ConfigMap allowlist missing *.anthropic.com"
pass "ConfigMap contains override allowlist values"

echo ""
echo "=== Scenario 5: service health endpoints reachable (via port-forward) ==="
# port-forward to the Service, hit it from the host with curl
kubectl port-forward -n "${NAMESPACE}" "service/${RELEASE_NAME}-aegrail-engine" 18080:8080 >/tmp/aegrail-pf.log 2>&1 &
PF_PID=$!
# Wait for port-forward to come up (poll up to 10s)
for i in $(seq 1 20); do
  if curl -s -o /dev/null -w "%{http_code}\n" --max-time 1 http://localhost:18080/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

HEALTHZ=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:18080/healthz)
[ "${HEALTHZ}" = "200" ] && pass "/healthz returned 200" || { cat /tmp/aegrail-pf.log; fail "/healthz did not return 200 (got '${HEALTHZ}')"; }

READYZ=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:18080/readyz)
[ "${READYZ}" = "200" ] && pass "/readyz returned 200" || fail "/readyz did not return 200 (got '${READYZ}')"

# Placeholder proxy handler returns 502 with informative body
PROXY=$(curl -s -o /tmp/aegrail-proxy-body.out -w "%{http_code}" --max-time 2 http://localhost:18080/some/path)
[ "${PROXY}" = "502" ] && pass "placeholder proxy returned 502 (expected — pre-release stub)" || fail "proxy did not return 502 (got '${PROXY}')"

# Verify the response body identifies as placeholder
grep -q "pre-release placeholder" /tmp/aegrail-proxy-body.out \
  && pass "proxy response body identifies as pre-release placeholder" \
  || { cat /tmp/aegrail-proxy-body.out; fail "proxy response body does not contain expected placeholder text"; }

kill ${PF_PID} 2>/dev/null || true
wait ${PF_PID} 2>/dev/null || true
rm -f /tmp/aegrail-pf.log /tmp/aegrail-proxy-body.out

echo ""
echo "=== Scenario 6: helm upgrade with changed allowlist ==="
ORIGINAL_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" -o jsonpath='{.items[0].metadata.name}')
helm upgrade "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-test" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=api.openai.com" \
  --set "policy.allowlist[1]=generativelanguage.googleapis.com" \
  --wait --timeout 120s >/dev/null \
  || fail "helm upgrade failed"
pass "helm upgrade succeeded"

# Deployment should have rolled (because the configmap checksum
# annotation changed -> new pod template hash -> new pod)
kubectl rollout status deployment/${RELEASE_NAME}-aegrail-engine -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "deployment did not roll out after upgrade"

NEW_POD=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
if [ "${NEW_POD}" != "${ORIGINAL_POD}" ]; then
  pass "configmap change rolled the pod (old: ${ORIGINAL_POD}, new: ${NEW_POD})"
else
  fail "pod did not restart after configmap change (still ${NEW_POD})"
fi

# New allowlist content
NEW_ALLOWLIST=$(kubectl get configmap "${RELEASE_NAME}-aegrail-engine-policy" -n "${NAMESPACE}" -o jsonpath='{.data.allowlist\.yaml}')
echo "${NEW_ALLOWLIST}" | grep -q "generativelanguage.googleapis.com" \
  || fail "ConfigMap did not update with the new allowlist value"
echo "${NEW_ALLOWLIST}" | grep -q "anthropic.com" \
  && fail "ConfigMap still contains the old allowlist value" \
  || pass "ConfigMap reflects updated allowlist"

echo ""
echo "=== Scenario 7: helm uninstall + cleanup verification ==="
helm uninstall "${RELEASE_NAME}" --namespace "${NAMESPACE}" >/dev/null \
  || fail "helm uninstall failed"
pass "helm uninstall succeeded"

# Wait briefly for resources to be deleted
sleep 3
REMAINING_DEPLOYS=$(kubectl get deploy -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAINING_SERVICES=$(kubectl get svc -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAINING_CONFIGMAPS=$(kubectl get cm -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
REMAINING_SA=$(kubectl get sa -n "${NAMESPACE}" -l app.kubernetes.io/instance="${RELEASE_NAME}" --no-headers 2>/dev/null | wc -l | tr -d ' ')

[ "${REMAINING_DEPLOYS}" -eq 0 ]    || fail "Deployment not cleaned up (${REMAINING_DEPLOYS} remaining)"
[ "${REMAINING_SERVICES}" -eq 0 ]   || fail "Service not cleaned up (${REMAINING_SERVICES} remaining)"
[ "${REMAINING_CONFIGMAPS}" -eq 0 ] || fail "ConfigMap not cleaned up (${REMAINING_CONFIGMAPS} remaining)"
[ "${REMAINING_SA}" -eq 0 ]         || fail "ServiceAccount not cleaned up (${REMAINING_SA} remaining)"
pass "all chart-managed resources removed"

echo ""
echo "=================================="
echo "all 7 scenarios passed."
echo "the helm chart is releasable to git."
echo "=================================="
