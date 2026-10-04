#!/usr/bin/env bash
# Bring up ax on this host: kind cluster + local registry, Agent Substrate, the ax control plane, one smoke
# Task. Idempotent: every step is skipped when already done; `down.sh` removes everything. Requires docker, go,
# kubectl, kind, ko, ax. The cluster's context, the registry and the pool sizes come from the kind profile
# (ops/k8s/profiles/kind.toml; OUSAST_PLANE_PROFILE selects another file with exec = "local"). This script may
# name the kind cluster because it creates it; the code reads the profile (tests/test_plane_literals.py).
set -euo pipefail
trap 'rc=$?; echo "up.sh FAILED at line $LINENO (exit $rc)"' ERR
trap 'echo "up.sh exit $?"' EXIT
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
export GOTOOLCHAIN=auto
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${OUSAST_PYTHON:-$REPO_ROOT/.venv/bin/python}"
profile() { PYTHONPATH="$REPO_ROOT/src" "$PY" -m openultrasast.plane.profile --profile "${OUSAST_PLANE_PROFILE:-kind}" --print "$@"; }
CTX="$(profile kube_context)"                       # kind names its context kind-<cluster>
export KIND_CLUSTER_NAME="${CTX#kind-}"
export KO_DOCKER_REPO="${KO_DOCKER_REPO:-$(profile registry)}"
OBSERVABILITY="$(profile kind_observability)"
IMAGES_FILE="$(profile images)"                     # the digest pins the reconciler and the templates read
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"

for t in docker go kubectl kind ko ax; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done
mkdir -p "$SRC"
clone() { [ -d "$SRC/$1" ] || git clone -q --depth 1 "$2" "$SRC/$1"; }
clone substrate https://github.com/agent-substrate/substrate.git
clone ax https://github.com/google/ax.git
step() { printf '\n== %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

step "kind cluster '$KIND_CLUSTER_NAME' (context $CTX) + registry $KO_DOCKER_REPO"
# Each step is skipped when already done: the substrate helper DELETES an existing cluster before creating one.
ready() { kubectl --context "$CTX" -n "$1" get pods --no-headers 2>/dev/null | awk '$2 ~ /^[0-9]+\/[0-9]+$/ {n++; split($2,a,"/"); if (a[1]!=a[2] && $3!="Completed") bad++} END {exit !(n>0 && bad==0)}'; }
if kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
  echo "cluster exists; kept"
else
  (cd "$SRC/substrate" && hack/create-kind-cluster.sh)   # its helpers resolve paths from the git toplevel
fi

step "agent substrate (ate-system)"
# The upstream installer has fixed manifest paths and also creates secrets/CRDs.
# Give it a temporary checkout view so it never installs the observability resources.
install_substrate() (
  if [ "$OBSERVABILITY" = true ]; then
    cd "$SRC/substrate"
  else
    # Symlinked build inputs must not make the staged view a different binary version.
    export VERSION="${VERSION:-$(git -C "$SRC/substrate" describe --tags --always --dirty)}"
    staged="$(mktemp -d)"
    trap 'rm -rf "$staged"' EXIT
    "$PY" "$REPO_ROOT/ops/ax/prepare-substrate.py" "$SRC/substrate" "$staged"
    cd "$staged"
  fi
  KUBECTL_CONTEXT="$CTX" hack/install-ate-kind.sh --deploy-ate-system
)
if ready ate-system; then echo "substrate ready; kept"; else
  install_substrate
fi
# Reconcile the choice even when the existing control plane is already ready.
if [ "$OBSERVABILITY" = true ]; then
  for manifest in otel-collector prometheus; do
    kubectl --context "$CTX" apply -f "$SRC/substrate/manifests/ate-install/kind/$manifest.yaml"
  done
  otel_config="$SRC/substrate/manifests/ate-install/kind/ate-otel-config.yaml"
else
  otel_config="$REPO_ROOT/ops/ax/substrate-kind-lean/ate-otel-config.yaml"
  for deployment in opentelemetry-collector prometheus jaeger; do
    existing="$(kubectl --context "$CTX" -n otel-system get deployment "$deployment" --ignore-not-found -o name)"
    if [ -n "$existing" ]; then
      kubectl --context "$CTX" -n otel-system scale "$existing" --replicas=0
    fi
  done
  echo "kind observability off: existing otel-system deployments scaled to 0; opt in with OUSAST_KIND_OBSERVABILITY=1 ops/ax/up.sh"
fi
# Replace data to remove stale exporter/endpoint keys in either direction. ConfigMap
# envFrom is read at pod start; a content annotation triggers only changed rollouts.
otel_data="$("$PY" - "$otel_config" <<'PYCONFIG'
import json
import sys
import yaml
config = yaml.safe_load(open(sys.argv[1]))
config["data"].pop("$patch", None)
print(json.dumps(config["data"], sort_keys=True))
PYCONFIG
)"
kubectl --context "$CTX" -n ate-system patch configmap ate-otel-config --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/data\",\"value\":$otel_data}]"
otel_hash="$(printf '%s' "$otel_data" | sha256sum | cut -d ' ' -f1)"
otel_workloads="$(kubectl --context "$CTX" -n ate-system get deployments,daemonsets -o json | "$PY" -c '
import json, sys
for item in json.load(sys.stdin)["items"]:
    spec = item["spec"]["template"]["spec"]
    containers = spec.get("containers", []) + spec.get("initContainers", [])
    if any(env.get("configMapRef", {}).get("name") == "ate-otel-config"
           for container in containers for env in container.get("envFrom", [])):
        print(item["kind"].lower() + "/" + item["metadata"]["name"])
')"
for workload in $otel_workloads; do
  kubectl --context "$CTX" -n ate-system patch "$workload" --type=merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"ousast.io/otel-config\":\"$otel_hash\"}}}}}"
  kubectl --context "$CTX" -n ate-system rollout status "$workload" --timeout=300s
done
kubectl --context "$CTX" -n ate-system get pods

step "egress gateway (atenet-egress, agentgateway variant: one prebuilt image, nothing built)"
# Every actor connection goes through this gateway; without it an actor has no network at all. The Substrate
# install can die before deploying it (e.g. a full disk), so it is applied on its own when absent.
if kubectl --context "$CTX" -n ate-system get deploy atenet-egress >/dev/null 2>&1; then echo "gateway present; kept"; else
  kubectl kustomize --load-restrictor=LoadRestrictionsNone "$SRC/substrate/manifests/ate-install/agentgateway-egress" \
    | kubectl --context "$CTX" apply -f -
  kubectl --context "$CTX" -n ate-system rollout status deploy/atenet-egress --timeout=300s
fi

step "ax control plane (ax-system)"
if ready ax-system; then echo "ax ready; kept"; else
  (cd "$SRC/ax" && make deploy AX_IMAGE_REPO="$KO_DOCKER_REPO")
  kubectl --context "$CTX" -n ax-system wait --for=condition=Ready pod --all --timeout=600s
fi
kubectl --context "$CTX" -n ax-system get pods

step "artifact receiver Service (ousast-receiver.ax-system -> this host)"
KIND_GATEWAY="$(docker network inspect kind --format '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' | tr ' ' '\n' | grep -m1 '\.')"
export KIND_GATEWAY OUSAST_ARTIFACT_PORT="${OUSAST_ARTIFACT_PORT:-18090}"   # the reconciler's fixed receiver port
envsubst < "$(dirname "$0")/receiver-service.yaml.tmpl" | kubectl --context "$CTX" apply -f -

step "worker pool (gVisor): pools.default of the profile"
# `ko apply` builds the worker image from the Substrate checkout (several GB of Go caches): only when the pool
# is absent. A size change in the profile is applied with `kubectl patch` or by deleting the pool first.
export POOL_NAME=ousast-pool POOL_REPLICAS="$(profile pools.default.replicas)" POOL_CPU="$(profile pools.default.cpu)" POOL_MEMORY="$(profile pools.default.memory)"
export WORKER_IMAGE="ko://github.com/agent-substrate/substrate/cmd/ateom-gvisor"
SUBSTRATE_VERSION="$(kubectl --context "$CTX" get nodes -o jsonpath='{.items[0].metadata.labels.ate\.dev/substrate-version}')"
export SUBSTRATE_VERSION
envsubst < "$(dirname "$0")/workerpool.yaml.tmpl" > "$SRC/workerpool.yaml"
if kubectl --context "$CTX" -n ax-system get workerpool "$POOL_NAME" >/dev/null 2>&1; then
  echo "pool $POOL_NAME exists ($(kubectl --context "$CTX" -n ax-system get workerpool "$POOL_NAME" -o jsonpath='{.status.readyReplicas}/{.spec.replicas}') ready); kept"
else
  (cd "$SRC/substrate" && KO_DOCKER_REPO="$KO_DOCKER_REPO" ko apply -f "$SRC/workerpool.yaml")
fi
kubectl --context "$CTX" -n ax-system wait --for=condition=Ready pod -l "ate.dev/worker-pool=$POOL_NAME" --timeout=600s \
  || kubectl --context "$CTX" -n ax-system get pods

step "runner image $KO_DOCKER_REPO/ousast-runner"
docker build -q -f "$REPO_ROOT/plane/Dockerfile.runner" -t "$KO_DOCKER_REPO/ousast-runner:dev" "$REPO_ROOT"
docker push -q "$KO_DOCKER_REPO/ousast-runner:dev"
RUNNER_IMAGE="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$KO_DOCKER_REPO/ousast-runner:dev" | grep "^$KO_DOCKER_REPO/ousast-runner@" | head -1)"
[ -n "$RUNNER_IMAGE" ] || { echo "no digest for the runner image" >&2; exit 2; }
export RUNNER_IMAGE
printf '{\n  "runner": "%s"\n}\n' "$RUNNER_IMAGE" > "$IMAGES_FILE"   # the profile's images file: commit it with the templates
echo "runner image $RUNNER_IMAGE -> $IMAGES_FILE"
echo "re-pin the templates with: ousast plane workspaces ... --runner-image $IMAGES_FILE (or ousast plane repin, task 4.3)"

step "ax CLI from the deployed checkout (a release CLI skews from the server)"
if [ -x "$HOME/go/bin/ax" ] && [ "$HOME/go/bin/ax" -nt "$SRC/ax/.git/HEAD" ]; then echo "ax CLI newer than the checkout; kept"; else
  (cd "$SRC/ax" && go install ./cmd/ax)
fi

step "smoke task"
ax delete task ousast-smoke >/dev/null 2>&1 || true
envsubst < "$(dirname "$0")/smoke-task.yaml.tmpl" > "$SRC/smoke-task.yaml"
ax apply -f "$SRC/smoke-task.yaml"
for i in 1 2 3 4 5 6; do ax resume task ousast-smoke && break; sleep 20; done   # first resume may time out while the golden snapshot builds
ax get tasks

step "footprint"
free -m | sed -n 1,2p
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' | grep -Ei 'kind|registry' || true
