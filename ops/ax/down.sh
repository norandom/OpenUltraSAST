#!/usr/bin/env bash
# Tear down the local ax: the kind cluster and its registry container. Source checkouts stay in the cache.
set -euo pipefail
export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"
export KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ousast}"
SRC="${OUSAST_AX_SRC:-$HOME/.cache/ousast/ax-src}"
(cd "$SRC/substrate" && hack/delete-kind-cluster.sh)
