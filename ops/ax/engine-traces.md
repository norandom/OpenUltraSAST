# Engine traces on kube-ax

`benchmarks/learn/engine_trace.py --executor ax` submits AX v0.3.1 Tasks with
`ax apply -f -` and removes them with `ax delete task NAME`. The operator supplies
kubeconfig and AX access; the dispatcher creates no Kubernetes resources or secrets.
The `ousast-engine-task` GHCR package **must be made Public once** in its package
settings so the actors can pull it without registry credentials.

The task image contains the current engine and worker code. Rebuild it after code
changes and pass its digest with `--image`; no analyzer download is needed. The host
prepares each pin as usual and uploads source and prepared questions under
`engine-queue/<run>/<pin>/`. Only object-scoped presigned URLs and deadline parameters
enter Task env. Credentials stay on the coordinator. Configure `OUSAST_MEMORY=s3://<bucket>`
and the store credentials in the coordinator's `.env` or environment, with
`S3_ENDPOINT=https://files.because-security.com`. Presigned links expire after the
pin deadline plus ten minutes. IP and HTTP endpoints are rejected: the operator's
actor EgressPolicy must allow files.because-security.com:443.

The result object marks completion, even while AX reports Running. Failed phases and
host deadlines produce explicit failure/timeout rows. Task and staging-object cleanup
runs on success and failure; cleanup failure stops further dispatch. Per-pin files,
`--rerun-status`, resume and `progress.json` retain the existing trace-runner behavior.
AX results include `executor: "ax"`, `worker_ip`, and the image digest. Placement is
random; `--parallel` defaults to two AX tasks and cannot exceed two.

AX workers use `--heap-profile cluster` with
`-Xms1700m -Xmx1700m -XX:MaxMetaspaceSize=256m -XX:ReservedCodeCacheSize=128m -XX:MaxDirectMemorySize=256m -Xss512k -XX:ActiveProcessorCount=1 -XX:+UseG1GC`
on every frontend/query JVM; instruments record the flags. A `JVM out of memory`
result is automatically re-queued to one local Docker lane with `--heap-profile vm`
(2560m), recording `fallback: "vm-oom"` and the AX attempt. `mixed-ax` also uses this
one Docker lane for overflow, prioritizing pending OOM fallbacks. Thus a mixed run has
up to two AX tasks plus one Docker container. Use `--docker-image` for the locally
available VM image; Docker never pulls it implicitly. A STOP file prevents new
launches; interrupted fallback queues are recovered on resume.

Coordinator commands, from this worktree (the AX binary and kubeconfig remain
configurable). Build the image of the Docker lane, then set `TASK_IMAGE` to the
`ousast-engine-task` reference the Engine image workflow printed:

```bash
cd /home/mc/Source/OpenUltraSAST/.claude/worktrees/engine-ax
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH="$PWD/src"
OUSAST_VERSION=engine-ax docker compose build
# The ousast-engine-task reference the Engine image workflow printed, in its log and its summary:
export TASK_IMAGE="ghcr.io/norandom/ousast-engine-task@sha256:<digest>"
```

`docker compose build` takes the base from the defaults in `docker-compose.yml`,
which a test keeps equal to `plane/task-base.digest`; `OUSAST_VERSION` sets the tag
of the image, here `openultrasast:engine-ax`. The Engine image workflow also
builds/pushes both images and prints each digest; CI needs the changes published
before dispatch. When the workflow runs is the rebuild policy in `ops/ax/README.md`,
under "Image layers, publication and node cache budget". The Docker lane runs the local
image, committed or not; the AX lanes run the task image of the revision the workflow
built.

With `KUBECONFIG` pointing to the operator's kube-ax config and store settings in
`.env`, run a one-pin smoke using the default experiment units and local example
memory (or add `--examples /path/to/frozen-examples.jsonl`). Use the `ax` binary at
`$HOME/go/bin/ax`. `$HOME/.local/ax-v0.3.1/ax` hits the AX-lane dispatch blocker:

```bash
: "${KUBECONFIG:?Set KUBECONFIG to the operator kube-ax configuration}"
python benchmarks/learn/engine_trace.py --executor ax \
  --ax-bin "$HOME/go/bin/ax" --kubeconfig "$KUBECONFIG" \
  --atespace default --image "$TASK_IMAGE" --docker-image openultrasast:engine-ax \
  --parallel 1 --limit 1 --deadline 900 \
  --out "$HOME/ousast-results/plane/engine-ax-smoke"
```

Then run the mixed lanes (repeat to resume; defaults re-run failed/timeout pins):

```bash
python benchmarks/learn/engine_trace.py --executor mixed-ax \
  --ax-bin "$HOME/go/bin/ax" --kubeconfig "$KUBECONFIG" \
  --atespace default --image "$TASK_IMAGE" --docker-image openultrasast:engine-ax \
  --parallel 2 --deadline 900 --rerun-status failed,timeout \
  --out "$HOME/ousast-results/plane/engine-ax-mixed"
```
