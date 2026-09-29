#!/usr/bin/env bash
# Render the end-to-end smoke Run with the current runner digest and execute it through the reconciler on ax.
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"
RUNNER_IMAGE="$(cat "$SRC/runner-image")"; export RUNNER_IMAGE
# Actors reach the receiver by its Service name through the egress gateway (ops/ax/receiver-service.yaml.tmpl,
# applied by up.sh, endpoint this host at OUSAST_ARTIFACT_PORT): the runner dials the Service's ClusterIP on port
# 80 with that name as Host; the reconciler looks the ClusterIP up unless OUSAST_ARTIFACT_DIAL is set.
export OUSAST_ARTIFACT_PORT="${OUSAST_ARTIFACT_PORT:-18090}"
envsubst < "$(dirname "$0")/smoke-run.yaml.tmpl" > "$SRC/smoke-run.yaml"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
"$REPO/.venv/bin/ousast" plane run "$SRC/smoke-run.yaml" "$@"
"$REPO/.venv/bin/ousast" plane status ax-e2e-smoke
