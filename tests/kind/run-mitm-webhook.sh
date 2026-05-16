#!/usr/bin/env bash
# Kind cluster end-to-end test for the v0.4.3 fix: when the
# mutating admission webhook is enabled together with MITM, the
# auto-injected engine sidecar must actually terminate TLS.
#
# v0.4.1 shipped half the MITM-injection story: it mounted the CA
# cert + wired the agent's trust store env vars, but it forgot to
# pass the MITM config to the injected engine sidecar itself. The
# sidecar tunneled opaquely → agent's direct TLS to the upstream
# failed because the agent's trust store contained only our CA.
#
# This test catches that regression by exercising the full path:
#
#   1. Generate a self-signed CA, store in a Secret in BOTH the
#      engine namespace and the test namespace (no cross-NS Secret
#      mounts in K8s).
#   2. helm install with webhook.enabled=true, mitm.hosts=...,
#      mitm.caSecretName=...
#   3. Label the test namespace aegrail.io/inject=enabled.
#   4. Deploy an agent pod (single-container, alpine/curl).
#   5. Assert: pod has 2 containers (user + injected engine).
#   6. Assert: agent container has SSL_CERT_FILE pointing at
#      /etc/aegrail/mitm-ca/tls.crt (the fixed path, not the old
#      ca.crt projection).
#   7. Assert: engine sidecar has AEGRAIL_ENGINE_MITM_HOSTS,
#      AEGRAIL_ENGINE_MITM_CA_CERT_FILE, _KEY_FILE env vars set.
#   8. Assert: engine sidecar has the CA volume mounted.
#   9. Assert: agent can `curl --proxy http://localhost:8080
#      https://example.com/` successfully — proving the integrated
#      MITM path (sidecar terminates TLS, signs leaf cert agent
#      trusts, re-encrypts to real upstream).
#  10. Assert: engine audit log records an event with mitm=true
#      for example.com.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KIND_CLUSTER:-aegrail-mitm-webhook-kind-test}"
IMAGE_NAME="aegrail-engine:kind-mitm-webhook"
NAMESPACE="aegrail-system"
TEST_NAMESPACE="agents-test"
RELEASE_NAME="ae"
CHART_PATH="${ROOT}/deploy/helm"
CA_SECRET_NAME="aegrail-mitm-ca"
WORKDIR="$(mktemp -d)"
MITM_HOSTS="example.com,*.example.com"

cleanup() {
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "(KEEP_CLUSTER=1; leaving cluster running, workdir at ${WORKDIR})"
    return
  fi
  echo ""
  echo "=== cleanup ==="
  kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
  docker image rm "${IMAGE_NAME}" 2>/dev/null || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; exit 1; }

echo "=== Scenario 1: prereqs ==="
command -v docker  >/dev/null || fail "docker not installed"
command -v kind    >/dev/null || fail "kind not installed"
command -v kubectl >/dev/null || fail "kubectl not installed"
command -v helm    >/dev/null || fail "helm not installed"
command -v openssl >/dev/null || fail "openssl not installed"
docker info >/dev/null 2>&1   || fail "docker daemon not running"
pass "prereqs present"

echo ""
echo "=== Scenario 2: generate MITM CA ==="
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout "${WORKDIR}/ca.key" -out "${WORKDIR}/ca.crt" \
  -days 7 -subj "/CN=aegrail-test-ca/O=aegrail" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  >/dev/null 2>&1 || fail "openssl ca generation failed"
pass "CA cert + key generated at ${WORKDIR}"

echo ""
echo "=== Scenario 3: build image + cluster + load ==="
docker build -t "${IMAGE_NAME}" -f "${ROOT}/deploy/docker/Dockerfile" "${ROOT}" >/tmp/aegrail-mitm-build.log 2>&1 \
  || { tail -30 /tmp/aegrail-mitm-build.log; fail "docker build failed"; }
pass "docker image built (engine + webhook binaries)"

kind create cluster --name "${CLUSTER_NAME}" >/tmp/aegrail-mitm-kind.log 2>&1 \
  || { cat /tmp/aegrail-mitm-kind.log; fail "kind create failed"; }
pass "kind cluster '${CLUSTER_NAME}' created"

kind load docker-image "${IMAGE_NAME}" --name "${CLUSTER_NAME}" >/dev/null 2>&1 \
  || fail "kind load image failed"
pass "image loaded into cluster"

kubectl create namespace "${NAMESPACE}" >/dev/null
kubectl create namespace "${TEST_NAMESPACE}" >/dev/null
pass "namespaces created"

echo ""
echo "=== Scenario 4: pre-create CA Secret in both namespaces ==="
# K8s does not allow cross-namespace Secret mounts. The webhook
# auto-injects volume references but never creates Secrets. So the
# operator must pre-create the Secret in every namespace where pods
# get injected.
for ns in "${NAMESPACE}" "${TEST_NAMESPACE}"; do
  kubectl -n "${ns}" create secret tls "${CA_SECRET_NAME}" \
    --cert="${WORKDIR}/ca.crt" \
    --key="${WORKDIR}/ca.key" >/dev/null
done
pass "CA Secret created in ${NAMESPACE} and ${TEST_NAMESPACE}"

echo ""
echo "=== Scenario 5: helm install with webhook + MITM ==="
helm install "${RELEASE_NAME}" "${CHART_PATH}" \
  --namespace "${NAMESPACE}" \
  --set "image.repository=aegrail-engine" \
  --set "image.tag=kind-mitm-webhook" \
  --set "image.pullPolicy=Never" \
  --set "policy.allowlist[0]=example.com" \
  --set "policy.allowlist[1]=*.example.com" \
  --set "webhook.enabled=true" \
  --set-string "mitm.hosts=example.com\,*.example.com" \
  --set "mitm.caSecretName=${CA_SECRET_NAME}" \
  --wait --timeout 300s >/tmp/aegrail-mitm-install.log 2>&1 \
  || { cat /tmp/aegrail-mitm-install.log; echo "--- pods:"; kubectl -n "${NAMESPACE}" get pods; echo "--- describe pods:"; kubectl -n "${NAMESPACE}" describe pods | tail -80; echo "--- logs:"; for p in $(kubectl -n "${NAMESPACE}" get pods -o name); do echo "### ${p}"; kubectl -n "${NAMESPACE}" logs "${p}" --all-containers=true --tail=30 2>&1; done; fail "helm install failed"; }
pass "helm install succeeded"

kubectl rollout status "deployment/${RELEASE_NAME}-aegrail-engine-webhook" \
  -n "${NAMESPACE}" --timeout=60s >/dev/null \
  || fail "webhook deployment not Ready"
pass "webhook deployment Ready"

echo ""
echo "=== Scenario 6: label test namespace + deploy agent ==="
kubectl label namespace "${TEST_NAMESPACE}" aegrail.io/inject=enabled >/dev/null
kubectl -n "${TEST_NAMESPACE}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: agent
spec:
  restartPolicy: Never
  containers:
    - name: app
      image: alpine/curl:latest
      command: ["sleep", "600"]
EOF
kubectl -n "${TEST_NAMESPACE}" wait pod/agent --for=condition=Ready --timeout=120s >/dev/null \
  || { kubectl -n "${TEST_NAMESPACE}" describe pod agent | tail -50; fail "agent pod did not become Ready"; }
pass "agent pod Ready"

echo ""
echo "=== Scenario 7: pod has 2 containers (user + injected engine) ==="
NUM_CONTAINERS=$(kubectl -n "${TEST_NAMESPACE}" get pod agent -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' | grep -c .)
[ "${NUM_CONTAINERS}" = "2" ] && pass "pod has 2 containers" \
  || fail "pod has ${NUM_CONTAINERS} container(s), expected 2"

echo ""
echo "=== Scenario 8: agent container SSL_CERT_FILE points at tls.crt ==="
# Regression guard: v0.4.1 projected the Secret with path=ca.crt,
# v0.4.3 projects it as tls.crt. Make sure the env var matches.
SSL_CERT_FILE=$(kubectl -n "${TEST_NAMESPACE}" get pod agent -o jsonpath="{.spec.containers[?(@.name=='app')].env[?(@.name=='SSL_CERT_FILE')].value}")
echo "  app SSL_CERT_FILE=${SSL_CERT_FILE}"
[ "${SSL_CERT_FILE}" = "/etc/aegrail/mitm-ca/tls.crt" ] && pass "SSL_CERT_FILE points at tls.crt" \
  || fail "SSL_CERT_FILE='${SSL_CERT_FILE}', expected /etc/aegrail/mitm-ca/tls.crt"

echo ""
echo "=== Scenario 9 (the v0.4.3 fix): engine sidecar has MITM env ==="
# The headline bug. v0.4.1 forgot to plumb these env vars to the
# auto-injected engine sidecar — sidecar tunneled HTTPS opaquely
# and the agent's trust store (now containing ONLY our CA) failed
# verification against the real upstream. Verify all three.
for env_name in AEGRAIL_ENGINE_MITM_HOSTS AEGRAIL_ENGINE_MITM_CA_CERT_FILE AEGRAIL_ENGINE_MITM_CA_KEY_FILE; do
  VAL=$(kubectl -n "${TEST_NAMESPACE}" get pod agent -o jsonpath="{.spec.containers[?(@.name=='aegrail-engine')].env[?(@.name=='${env_name}')].value}")
  if [ -z "${VAL}" ]; then
    fail "engine sidecar missing ${env_name} — v0.4.3 fix not applied"
  fi
  echo "  ${env_name}=${VAL}"
done
pass "engine sidecar has all three MITM env vars"

ENGINE_MOUNT=$(kubectl -n "${TEST_NAMESPACE}" get pod agent -o jsonpath="{.spec.containers[?(@.name=='aegrail-engine')].volumeMounts[?(@.name=='aegrail-mitm-ca')].mountPath}")
[ "${ENGINE_MOUNT}" = "/etc/aegrail/mitm-ca" ] && pass "engine sidecar has CA volume mounted" \
  || fail "engine sidecar CA mount missing or wrong path (got '${ENGINE_MOUNT}')"

echo ""
echo "=== Scenario 10: agent can curl HTTPS through the MITM proxy ==="
# This is the real proof. Without the v0.4.3 fix, this curl fails
# with a cert-verify error because the sidecar tunneled opaquely
# and example.com's cert isn't signed by our test CA.
set +e
CURL_OUT=$(kubectl -n "${TEST_NAMESPACE}" exec agent -c app -- \
  curl -s -o /dev/null -w "%{http_code}" \
  --proxy http://localhost:8080 \
  https://example.com/ 2>&1)
CURL_RC=$?
set -e
echo "  curl rc=${CURL_RC}, http_code=${CURL_OUT}"
if [ "${CURL_RC}" != "0" ] || [ "${CURL_OUT}" != "200" ]; then
  echo "  engine sidecar logs:"
  kubectl -n "${TEST_NAMESPACE}" logs agent -c aegrail-engine | tail -30
  fail "agent curl through MITM failed (rc=${CURL_RC}, http=${CURL_OUT})"
fi
pass "agent successfully curled https://example.com via MITM proxy"

echo ""
echo "=== Scenario 11: engine audit log records mitm=true event ==="
# Audit mode defaults to stdout; capture pod logs.
LOGS=$(kubectl -n "${TEST_NAMESPACE}" logs agent -c aegrail-engine 2>&1)
echo "${LOGS}" | grep -q '"mitm":true' \
  && pass "audit event has mitm=true" \
  || { echo "${LOGS}" | tail -20; fail "no mitm=true audit event found"; }
echo "${LOGS}" | grep -q '"host":"example.com"' \
  && pass "audit event has host=example.com" \
  || fail "no host=example.com audit event found"

echo ""
echo "=================================="
echo "all 11 mitm-webhook scenarios passed."
echo "v0.4.3 gate: green."
echo "=================================="
