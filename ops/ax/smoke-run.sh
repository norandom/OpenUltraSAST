#!/usr/bin/env bash
# Render the end-to-end smoke Run with the profile's runner digest and execute it through the reconciler on ax.
# The profile (OUSAST_PLANE_PROFILE, default kind; ops/k8s/profiles/) names the images file up.sh wrote.
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${OUSAST_PYTHON:-$REPO/.venv/bin/python}"
RUNNER_IMAGE="$(PYTHONPATH="$REPO/src" "$PY" -m openultrasast.plane.profile --profile "${OUSAST_PLANE_PROFILE:-kind}" --print images.runner)"
export RUNNER_IMAGE
# Actors reach the receiver by its Service name through the egress gateway (ops/ax/receiver-service.yaml.tmpl,
# applied by up.sh, endpoint this host at OUSAST_ARTIFACT_PORT): the runner dials the Service's ClusterIP on port
# 80 with that name as Host; the reconciler looks the ClusterIP up unless OUSAST_ARTIFACT_DIAL is set.
export OUSAST_ARTIFACT_PORT="${OUSAST_ARTIFACT_PORT:-18090}"
envsubst < "$(dirname "$0")/smoke-run.yaml.tmpl" > "$SRC/smoke-run.yaml"
ousast() { PYTHONPATH="$REPO/src" "$PY" -m openultrasast.cli "$@"; }   # this checkout's code, whatever python runs it
ousast plane run "$SRC/smoke-run.yaml" "$@"
ousast plane status ax-e2e-smoke
