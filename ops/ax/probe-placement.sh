#!/usr/bin/env bash
# Placement probe (plane-on-kubernetes task 1.5, design open question 2): does Agent Substrate place an actor on a
# worker that fits its memory request, or on any free worker of the sandbox class?
#
# Applies a second WorkerPool `probe-pool` (1 replica, 2 CPU / 3Gi) from ops/ax/workerpool.yaml.tmpl with the worker
# image the existing pool already built (no ko build), scales the default pool to one worker so the 7 GB host holds
# both, then runs one model-free repo-facts Task asking 2560Mi (limit 3Gi) and one asking 256Mi, recording after
# each resume which worker holds the actor (`kubectl ate get workers -o json`). Everything it created is removed
# on exit and the default pool is scaled back. Usage: ops/ax/probe-placement.sh OUT_DIR  (the JSON evidence lands there).
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
OUT="${1:?usage: probe-placement.sh OUT_DIR}"
mkdir -p "$OUT"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${OUSAST_PYTHON:-$REPO_ROOT/.venv/bin/python}"
profile() { PYTHONPATH="$REPO_ROOT/src" "$PY" -m openultrasast.plane.profile --profile "${OUSAST_PLANE_PROFILE:-kind}" --print "$@"; }
CTX="$(profile kube_context)"
RUNNER_IMAGE="$(profile images.runner)"
DEFAULT_REPLICAS="$(profile pools.default.replicas)"
K() { kubectl --context "$CTX" -n ax-system "$@"; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/probe.log"; }

cleanup() {
  rc=$?
  log "cleanup (exit $rc): delete the probe tasks and probe-pool, scale ousast-pool back to $DEFAULT_REPLICAS"
  for t in ousast-probe-big ousast-probe-small; do ax delete task "$t" >/dev/null 2>&1 || true; done
  K delete workerpool probe-pool --ignore-not-found >/dev/null 2>&1 || true
  K patch workerpool ousast-pool --type merge -p "{\"spec\":{\"replicas\":$DEFAULT_REPLICAS}}" >/dev/null 2>&1 || true
  echo "probe exit $rc"
}
trap cleanup EXIT

workers() { kubectl ate --context "$CTX" get workers -o json > "$OUT/$1.json"; kubectl ate --context "$CTX" get workers | tee -a "$OUT/probe.log"; }

export POOL_NAME=probe-pool POOL_REPLICAS=1 POOL_CPU=2 POOL_MEMORY=3Gi
WORKER_IMAGE="$(K get workerpool ousast-pool -o jsonpath='{.spec.workerImage}')"   # already built and pulled by the node
SUBSTRATE_VERSION="$(kubectl --context "$CTX" get nodes -o jsonpath='{.items[0].metadata.labels.ate\.dev/substrate-version}')"
export WORKER_IMAGE SUBSTRATE_VERSION
log "default pool to 1 replica (room for a 3Gi worker on this host)"
K patch workerpool ousast-pool --type merge -p '{"spec":{"replicas":1}}'
for i in $(seq 1 60); do [ "$(K get pods -l ate.dev/worker-pool=ousast-pool --no-headers 2>/dev/null | wc -l)" = 1 ] && break; sleep 2; done
log "apply probe-pool: $POOL_REPLICAS x $POOL_CPU CPU / $POOL_MEMORY, image $WORKER_IMAGE"
envsubst < "$(dirname "$0")/workerpool.yaml.tmpl" | tee "$OUT/probe-pool.yaml" | K apply -f -
K wait --for=condition=Ready pod -l ate.dev/worker-pool=probe-pool --timeout=600s
workers workers-before

task() {  # name, request memory, limit memory
  cat > "$OUT/$1.yaml" <<EOF
apiVersion: ax.io/v1alpha1
kind: Workspace
metadata: {name: $1-ws, atespace: default}
spec:
  files:
    - {path: "hello.py", content: "def hello():\n    return greet()\n"}
---
apiVersion: ax.io/v1alpha1
kind: Task
metadata: {name: $1, atespace: default}
spec:
  image: "$RUNNER_IMAGE"
  command: ["repo-facts"]
  env: [{name: OUSAST_OUTPUT_DIR, value: "/workspace/.ousast-out/probe"}]
  resources: {requests: {cpu: "250m", memory: "$2"}, limits: {cpu: "1", memory: "$3"}}
  workspaces: [{name: $1-ws, path: "/workspace"}]
EOF
  ax delete task "$1" >/dev/null 2>&1 || true
  log "apply $1 (requests $2, limits $3)"
  ax apply -f "$OUT/$1.yaml"
  for i in 1 2 3 4 5 6 7 8 9; do
    if ax resume task "$1" 2>&1 | tee -a "$OUT/probe.log"; then break; fi   # the first resume may wait for the golden snapshot
    sleep 20
  done
  sleep 15
  ax get task "$1" | tee "$OUT/$1.status.yaml" | grep -E "phase|message" || true
  workers "workers-$1"
  ax delete task "$1" >/dev/null 2>&1 || true
  for i in $(seq 1 30); do kubectl ate --context "$CTX" get workers | grep -q " 1/1000 " || break; sleep 2; done
}
task ousast-probe-big 2560Mi 3Gi
task ousast-probe-small 256Mi 512Mi
log "done; evidence under $OUT"
