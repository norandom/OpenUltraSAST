# Engine workers on k3s

Build the new **Engine image** workflow on main (or dispatch it), then copy its
`ghcr.io/<owner>/openultrasast@sha256:...` job-summary value. The old September
image does not include boto3 or this service. The release workflow still builds
version tags. The Dockerfile copies the worker and parser under `/app/benchmarks/learn`
and installs `.[semantic,s3]`; no analyzer tarball is sent by the dispatcher.

Use two schedulable nodes with at least 3 GiB available each. Required hostname
anti-affinity places one worker on each node. Updates use Recreate so a third
worker does not wait forever for a third node. Local scratch uses the container's
filesystem, with no host mount or Kubernetes API access.

Create a **new scoped account** using the policy in `docs/rustfs.md`. Export its
`S3_ENDPOINT`, `S3_BUCKET=sast-memory`, `AWS_ACCESS_KEY_ID`, and
`AWS_SECRET_ACCESS_KEY` in the coordinator shell. Do not use the memory-store
account. The following commands are for the coordinator; they were not run by the
implementation agent.

```sh
export ENGINE_IMAGE='ghcr.io/<owner>/openultrasast@sha256:<digest-from-workflow>'
# From the repository root, edit the digest parameter without changing the template:
export ENGINE_OVERLAY="$(mktemp -d /tmp/ousast-engine.XXXXXX)"
cp ops/k8s/engine/{namespace,deployment,kustomization}.yaml "$ENGINE_OVERLAY/"
python - <<'PY'
import os
from pathlib import Path
image, digest = os.environ['ENGINE_IMAGE'].split('@', 1)
p = Path(os.environ['ENGINE_OVERLAY']) / 'kustomization.yaml'
p.write_text(p.read_text().replace('ghcr.io/OWNER/openultrasast', image)
             .replace('sha256:REPLACE_WITH_ENGINE_IMAGE_DIGEST', digest))
PY
kubectl apply -f ops/k8s/engine/namespace.yaml
kubectl -n ousast-engine create secret generic ousast-engine-s3 \
  --from-literal=S3_ENDPOINT="$S3_ENDPOINT" \
  --from-literal=S3_BUCKET="$S3_BUCKET" \
  --from-literal=AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
kubectl apply -k "$ENGINE_OVERLAY"
kubectl -n ousast-engine rollout status deployment/ousast-engine-worker
kubectl -n ousast-engine get pods -o wide

export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH="$PWD/src"
python benchmarks/learn/engine_trace.py --queue-status
python benchmarks/learn/engine_trace.py --executor queue \
  --image "$ENGINE_IMAGE" --parallel 2 --deadline 900 --queue-timeout 3600 \
  --units plane/experiments/exp-005-graph-slice.units.jsonl \
  --out "$HOME/ousast-results/plane/engine-trace-queue"
```

The dispatcher uses the existing local memory examples by default. Add
`--examples /path/to/examples.jsonl` for a frozen example snapshot. Materialization
uses locally cached source pins, just as the Docker executor does. `--executor
k8s-jobs` preserves the old Job lane (`k8s` is its legacy alias); `queue` requires
no kubectl access. Resume skips completed local units and retries failed or timed
out units. `progress.json`, `STOP`, filtering, and `--summary` retain their existing
meaning. Each invocation uses a new run ID, so an old remote result cannot satisfy
a new retry. The dispatcher records worker and pod identity in each pin JSON.

Tasks contain the pin, units, prepared questions, source object key, and deadlines.
Results live at `engine-results/<run>/<pin-id>.json`; inputs are removed after
publication. The Docker lane retains JSON and a log, not a result tar, so the queue
also returns JSON. Queue timeout records timeout locally and removes pending;
an already claimed task finishes remotely and cleans its input. Orphaned inputs
from a failed submission can be removed under `engine-queue/inputs/` after checking
that no pending task or claim references them.

Claims use per-worker choosing markers followed by ordered tickets. A worker waits
for choosing peers and every lower ticket before removing pending and starting.
This requires strongly consistent GET/PUT/LIST from RustFS, including paginated
LIST, and synchronized node clocks with skew below 30 seconds. Half of the 60-second lease margin is reserved for clock
skew; the remaining execution budget is checked again after claiming.
It does not require conditional writes, object tags, S3 Select, or bucket-admin
permissions. A dead worker's task is recovered from its expired claim. Execution
runs in a child process. Linux subreaping and a frozen descendant walk kill its
entire tree, including Joern's separate sessions, at the task deadline before the
lease expires. As with any unfenced lease, a node suspended beyond its lease must be
terminated before it rejoins; the protocol cannot guarantee exclusivity against
arbitrary process suspension or an inconsistent object store.

SIGTERM stops new claims and lets the current task finish. The 900-second
termination grace matches the maximum task deadline. Keep these values aligned
if changing the deployment. `/healthz` serves both probes and becomes unready on
shutdown. Errors omit SDK exception text to avoid exposing credentials.
