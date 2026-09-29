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
(cd "$SRC/substrate" && hack/create-kind-cluster.sh)   # its helpers resolve paths from the git toplevel

step "agent substrate (ate-system)"
(cd "$SRC/substrate" && hack/install-ate-kind.sh --deploy-ate-system)
kubectl -n ate-system wait --for=condition=Ready pod --all --timeout=900s || true
kubectl -n ate-system get pods

step "ax control plane (ax-system)"
(cd "$SRC/ax" && make deploy AX_IMAGE_REPO="$KO_DOCKER_REPO")
kubectl -n ax-system wait --for=condition=Ready pod --all --timeout=600s || true
kubectl -n ax-system get pods

step "smoke task"
ax apply -f "$(dirname "$0")/smoke-task.yaml"
ax get tasks

step "footprint"
free -m | sed -n 1,2p
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' | grep -Ei 'kind|registry' || true
