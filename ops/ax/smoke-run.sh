#!/usr/bin/env bash
# Render the end-to-end smoke Run with the current runner digest and execute it through the reconciler on ax.
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"
RUNNER_IMAGE="$(cat "$SRC/runner-image")"; export RUNNER_IMAGE
KIND_GW="$(docker network inspect kind --format '{{range .IPAM.Config}}{{if .Gateway}}{{.Gateway}} {{end}}{{end}}' | tr ' ' '\n' | grep -m1 '\.')"
export OUSAST_ARTIFACT_HOST="${OUSAST_ARTIFACT_HOST:-$KIND_GW}"   # sandboxes reach the host via the kind gateway
envsubst < "$(dirname "$0")/smoke-run.yaml.tmpl" > "$SRC/smoke-run.yaml"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
"$REPO/.venv/bin/ousast" plane run "$SRC/smoke-run.yaml" "$@"
"$REPO/.venv/bin/ousast" plane status ax-e2e-smoke
