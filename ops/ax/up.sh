#!/usr/bin/env bash
# Bring up ax on this host: kind cluster + local registry, Agent Substrate, the ax control plane, one smoke
# Task. Idempotent enough to rerun; `down.sh` removes everything. Requires docker, go, kubectl, kind, ko, ax.
set -euo pipefail
trap 'rc=$?; echo "up.sh FAILED at line $LINENO (exit $rc)"' ERR
trap 'echo "up.sh exit $?"' EXIT
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
export GOTOOLCHAIN=auto
export KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ousast}"
export KO_DOCKER_REPO="${KO_DOCKER_REPO:-localhost:5001}"
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"

for t in docker go kubectl kind ko ax; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done
mkdir -p "$SRC"
clone() { [ -d "$SRC/$1" ] || git clone -q --depth 1 "$2" "$SRC/$1"; }
clone substrate https://github.com/agent-substrate/substrate.git
clone ax https://github.com/google/ax.git
step() { printf '\n== %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

step "kind cluster '$KIND_CLUSTER_NAME' + registry $KO_DOCKER_REPO"
# Each step is skipped when already done: the substrate helper DELETES an existing cluster before creating one.
CTX="kind-$KIND_CLUSTER_NAME"
ready() { kubectl --context "$CTX" -n "$1" get pods --no-headers 2>/dev/null | awk '$2 ~ /^[0-9]+\/[0-9]+$/ {n++; split($2,a,"/"); if (a[1]!=a[2] && $3!="Completed") bad++} END {exit !(n>0 && bad==0)}'; }
if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
  echo "cluster exists; kept"
else
  (cd "$SRC/substrate" && hack/create-kind-cluster.sh)   # its helpers resolve paths from the git toplevel
fi

step "agent substrate (ate-system)"
if ready ate-system; then echo "substrate ready; kept"; else
  (cd "$SRC/substrate" && hack/install-ate-kind.sh --deploy-ate-system)
fi
kubectl --context "$CTX" -n ate-system get pods

step "ax control plane (ax-system)"
if ready ax-system; then echo "ax ready; kept"; else
  (cd "$SRC/ax" && make deploy AX_IMAGE_REPO="$KO_DOCKER_REPO")
  kubectl --context "$CTX" -n ax-system wait --for=condition=Ready pod --all --timeout=600s
fi
kubectl --context "$CTX" -n ax-system get pods

step "worker pool (gVisor)"
SUBSTRATE_VERSION="$(kubectl --context "$CTX" get nodes -o jsonpath='{.items[0].metadata.labels.ate\.dev/substrate-version}')"
export SUBSTRATE_VERSION
envsubst < "$(dirname "$0")/workerpool.yaml.tmpl" > "$SRC/workerpool.yaml"
(cd "$SRC/substrate" && KO_DOCKER_REPO="$KO_DOCKER_REPO" ko apply -f "$SRC/workerpool.yaml")
kubectl --context "$CTX" -n ax-system wait --for=condition=Ready pod -l ate.dev/worker-pool=ousast-pool --timeout=600s \
  || kubectl --context "$CTX" -n ax-system get pods

step "runner image $KO_DOCKER_REPO/ousast-runner"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
docker build -q -f "$REPO_ROOT/plane/Dockerfile.runner" -t "$KO_DOCKER_REPO/ousast-runner:dev" "$REPO_ROOT"
docker push -q "$KO_DOCKER_REPO/ousast-runner:dev"
RUNNER_IMAGE="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$KO_DOCKER_REPO/ousast-runner:dev" | grep "^$KO_DOCKER_REPO/ousast-runner@" | head -1)"
[ -n "$RUNNER_IMAGE" ] || { echo "no digest for the runner image" >&2; exit 2; }
export RUNNER_IMAGE; echo "$RUNNER_IMAGE" > "$SRC/runner-image"   # the reconciler reads this pin
echo "runner image $RUNNER_IMAGE"

step "ax CLI from the deployed checkout (a release CLI skews from the server)"
(cd "$SRC/ax" && go install ./cmd/ax)

step "smoke task"
ax delete task ousast-smoke >/dev/null 2>&1 || true
envsubst < "$(dirname "$0")/smoke-task.yaml.tmpl" > "$SRC/smoke-task.yaml"
ax apply -f "$SRC/smoke-task.yaml"
ax resume task ousast-smoke || true
ax get tasks

step "footprint"
free -m | sed -n 1,2p
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' | grep -Ei 'kind|registry' || true
