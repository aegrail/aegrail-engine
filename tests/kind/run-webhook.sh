#!/usr/bin/env bash
# Kind cluster end-to-end test for the v0.2.0 mutating admission
# webhook. Independent of run.sh — that one exercises the engine
# proxy directly with a manually-defined sidecar. This one
# exercises the webhook auto-injection path.
#
# Scenarios:
#   1. prereqs (docker, kind, kubectl, helm)
#   2. build image + create cluster + load image
#   3. helm install with webhook.enabled=true; both Deployments Ready
#   4. label test namespace aegrail.io/inject=enabled
#   5. apply a single-container test pod
#   6. assert the pod now has 2 containers (user + injected engine)
#   7. assert HTTP_PROXY env is set on the user container
#   8. assert aegrail.io/identity label is defaulted on the pod
#   9. assert the engine sidecar reaches Ready
#   10. cleanup

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER:-aegrail-webhook-kind-test}"
IMAGE_NAME="aegrail-engine:kind-webhook"
NAMESPACE="aegrail-system"
TEST_NAMESPACE="agents-test"
RELEASE_NAME="ae"
CHART_PATH="${ROOT}/deploy/helm"

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

echo "=== Scenario 1: prereqs ==="
command -v docker  >/dev/null || fail "docker not installed"
command -v kind    >/dev/null || fail "kind not installed"
command -v kubectl >/dev/null || fail "kubectl not installed"
command -v helm    >/dev/null || fail "helm not installed"
docker info >/dev/null 2>&1   || fail "docker daemon not running"
pass "prereqs present"

echo ""
echo "=== Scenario 2: build image + cluster + load ==="
docker build -t "${IMAGE_NAME}" -f "${ROOT}/deploy/docker/Dockerfile" "${ROOT}" >/tmp/aegrail-webhook-build.log 2>&1 \
  || { tail -30 /tmp/aegrail-webhook-build.log; fail "docker build failed"; }
pass "docker image built (engine + webhook binaries)"

kind create cluster --name "${CLUSTER_NAME}" >/tmp/aegrail-webhook-kind.log 2>&1 \
  || { cat /tmp/aegrail-webhook-kind.log; fail "kind create failed"; }
pass "kind cluster '${CLUSTER_NAME}' created"

kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}" >/dev/null 2>&1 \
  || fail "kind load image failed"
pass "image loaded into cluster"

kubectl create namespace "${NAMESPACE}" >/dev/null
pass "namespace '${NAMESPACE}' created"

echo ""
echo "=== Scenario 3: helm install with webhook.enabled=true ==="
helm install "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-webhook" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=api.example.com" \
  --set "webhook.enabled=true" \
  --wait --timeout 180s >/tmp/aegrail-webhook-install.log 2>&1 \
  || { cat /tmp/aegrail-webhook-install.log; fail "helm install failed"; }
pass "helm install succeeded"

kubectl rollout status "deployment/${RELEASE_NAME}-aegrail-engine" -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "engine deployment not Ready"
kubectl rollout status "deployment/${RELEASE_NAME}-aegrail-engine-webhook" -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "webhook deployment not Ready"
pass "both engine and webhook deployments Ready"

echo ""
echo "=== Scenario 4: label test namespace aegrail.io/inject=enabled ==="
kubectl create namespace "${TEST_NAMESPACE}" >/dev/null
kubectl label namespace "${TEST_NAMESPACE}" aegrail.io/inject=enabled >/dev/null
pass "namespace '${TEST_NAMESPACE}' labeled for injection"

echo ""
echo "=== Scenario 5: apply a single-container test pod ==="
kubectl -n "${TEST_NAMESPACE}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: target
spec:
  restartPolicy: Never
  containers:
    - name: app
      image: alpine/curl:latest
      command: ["sleep", "600"]
EOF
# Give the API server a moment to call the webhook
kubectl -n "${TEST_NAMESPACE}" wait pod/target --for=condition=Ready --timeout=90s >/dev/null \
  || fail "target pod did not become Ready"
pass "target pod Ready"

echo ""
echo "=== Scenario 6: pod has 2 containers (user + injected engine) ==="
NUM_CONTAINERS=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' | grep -c .)
[ "${NUM_CONTAINERS}" = "2" ] && pass "pod has 2 containers" \
  || fail "pod has ${NUM_CONTAINERS} container(s), expected 2"

ENGINE_PRESENT=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath='{.spec.containers[*].name}' | grep -c aegrail-engine || true)
[ "${ENGINE_PRESENT}" = "1" ] && pass "aegrail-engine sidecar was injected" \
  || fail "aegrail-engine container not found in injected pod"

echo ""
echo "=== Scenario 7: HTTP_PROXY env present on user container ==="
HTTP_PROXY_VAL=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath="{.spec.containers[?(@.name=='app')].env[?(@.name=='HTTP_PROXY')].value}")
echo "  app HTTP_PROXY=${HTTP_PROXY_VAL}"
echo "${HTTP_PROXY_VAL}" | grep -q "http://localhost:8080" \
  && pass "HTTP_PROXY set to http://localhost:8080" \
  || fail "HTTP_PROXY missing or wrong (got '${HTTP_PROXY_VAL}')"

HTTPS_PROXY_VAL=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath="{.spec.containers[?(@.name=='app')].env[?(@.name=='HTTPS_PROXY')].value}")
echo "${HTTPS_PROXY_VAL}" | grep -q "http://localhost:8080" \
  && pass "HTTPS_PROXY set to http://localhost:8080" \
  || fail "HTTPS_PROXY missing or wrong (got '${HTTPS_PROXY_VAL}')"

echo ""
echo "=== Scenario 8: aegrail.io/identity label defaulted ==="
IDENTITY=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath="{.metadata.labels['aegrail\.io/identity']}")
[ -n "${IDENTITY}" ] && pass "identity label defaulted to '${IDENTITY}'" \
  || fail "aegrail.io/identity label was not set on the pod"

echo ""
echo "=== Scenario 9: engine sidecar reaches Ready inside the pod ==="
ENGINE_READY=$(kubectl -n "${TEST_NAMESPACE}" get pod target -o jsonpath="{.status.containerStatuses[?(@.name=='aegrail-engine')].ready}")
[ "${ENGINE_READY}" = "true" ] && pass "engine sidecar container is Ready" \
  || fail "engine sidecar not Ready (got '${ENGINE_READY}')"

echo ""
echo "=================================="
echo "all 9 webhook-injection scenarios passed."
echo "v0.2.0 webhook gate: green."
echo "=================================="
