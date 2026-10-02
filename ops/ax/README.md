# ax on this host

The service plane (`.kiro/specs/ai-service-plane/`) runs every task on google/ax over Agent Substrate in a
single-node kind cluster. ax is the only executor; `ousast plane run` submits, resumes, starts and collects.

## Bring-up

    ops/ax/up.sh          # idempotent: kind + registry, Substrate, ax, gVisor worker pool, egress gateway,
                          # receiver Service, runner image (digest pinned), ax CLI, smoke Task
    ousast plane doctor   # kind, Substrate, ax controller, runner image
    ops/ax/smoke-run.sh   # end to end: repo-facts on ax, artifacts back on the host, attribution table
    ops/ax/down.sh        # deletes the cluster and its registry

Tools live in `~/go/bin` (kind, ax, ko, kubectl-ate) and `~/.local/bin` (kubectl); sources and rendered files
in `~/.cache/ousast/ax-src/` (the runner digest pin is `runner-image` there).

## How a Run executes

A Run (`plane/runs/*.yaml`, kind `openultrasast.io/v1alpha1 Run`) is a DAG of steps; each step names an ax Task
(`plane/tasks/`), its inputs and outputs, and its own `budget: {usd, calls}`. Every Task binds its Workspaces
(`plane/workspaces/`) and one ax Model (`plane/models/`): `deepseek-flash` for chat, `openrouter-embedding`
(OpenAI `text-embedding-3-small` through OpenRouter) for embeddings. `ousast plane run` (`plane/reconciler.py`)
applies Workspaces before the Tasks that bind them, resumes each Task, sends its start signal, collects its
artifacts and records state under `$OUSAST_RESULTS/plane/<run>/` (default `~/ousast-results/plane/`); a rerun
skips tasks already done, and `--workers` bounds the tasks in flight.

**Runner contract** (`plane/runner.py`, PID 1 of the runner image). ax hands the Task in `AX_TASK_YAML` and the
Workspaces in `AX_WORKSPACES_YAML`; the runner serves `/healthz` and `/readyz` (503 until every workspace is
materialised). Agent Substrate boots each template once as a golden actor to snapshot it, so the command never
starts by itself: it waits for `POST /ousast/v1/start` with `{run, task, credentials}`, which the reconciler sends
through Substrate's `atenet-router` to that actor only (`plane/router.py`). **The provider key exists only in that
request**: the runner keeps it in memory, passes it to the command's environment, redacts it from echoed stderr
and never writes it. The reconciler reads the variable the Model's `secretKey.key` names from the operator's
environment or `.env` (which never overrides an exported variable). After the command exits, the runner posts
`OUSAST_OUTPUT_DIR` as a tar to the receiver; that delivery is the task's completion, and a completion marker
stops a resumed actor from repeating billed work.

**Budgets.** The metered client refuses the next call once a task's `usd` or `calls` ceiling is reached; the task
ends `unfinished` and resumes on a rerun with a larger budget. An account or authentication error ends it
`failed`. Model-free tasks run with `{usd: 0, calls: 0}`, so a stray call fails loudly.

**Egress** (`plane/egress.py`). One EgressPolicy per actor through the `atenet-egress` gateway, deny by default,
hostnames only: plain HTTP to the artifact receiver, TLS passthrough to the source hosts of the bound Workspaces
and to the hosts the bound Model declares (`openultrasast.io/egress-hosts`). The policy is deleted with the actor.

**Token attribution.** `ousast plane status <run>` prints per task its status and `calls`, `prompt`,
`cache_hit` and `output` tokens and `usd` from the tasks' `summary.json`, and writes `<run dir>/attribution.json`;
`--units` adds per-unit rows.

## Tasks

| Task | Model | Does |
|---|---|---|
| `repo-facts` | none | functions per product file, and each candidate's call sites in other files |
| `verify` (passes a, b, c) | `deepseek-flash` | batched tool hunt per file over the candidates, with their known callers |
| `agree` | none | a and b agreed or disputed; after pass c on the disputed, 2-of-3 (the step `final`) |
| `features` | none | one feature record per candidate for the decision engine |
| `remember` | none | the case's artifacts as memory rows (`facts`, `verdict`, `unit_cost`, `alert`, `coverage`, `features`) |
| `alerts` | none | the quick scan on the vulnerable and fixed pins (loop Runs) |
| `loop` | none | the steps `snapshot`, `measure`, `propose`, `improve`: the improvement loop as a Run |
| `roles` | `deepseek-flash` | per-repository source, sink and sanitizer roles without a vocabulary (decision-engine harvest) |

Generators: `ousast plane workspaces <population> --validation-set ...` writes the per-case chain
(`facts -> va, vb -> agree -> vc -> final -> features -> remember`, plus `alerts` and the loop with `--loop`);
`ousast plane harvest --labels ... --plane DIR` writes the decision engine's harvest Runs; `ousast plane
alerts-engine` produces a Run's `alerts` from the Joern engine image on the host, for PHP and other languages
quick mode does not cover.

## Memory store

`plane/memory.py`. One store keyed by repository and pin holds what runs learned: `index.jsonl`, `facts/` by
content hash, `repos/<host>__<owner>__<name>/<pin>.jsonl` rows, and content-addressed blobs (excerpts, embeddings,
cached model responses, compiled programs). `ousast plane remember <run>` ingests a run's rows; a repeated ingest
is skipped by the index. A facts entry is reused for the same repository, pin, candidates and runner image.

`OUSAST_MEMORY` selects the backend:

- `file:///path` (`FileStore`), default `$OUSAST_RESULTS/plane/memory`; it refuses to write below 1 GiB free;
- `minio://<bucket>[/<prefix>]` (`MinioStore`, the `minio` extra), used on the maintainer's MinIO. Endpoint and
  credentials come from `.env` or the environment (`MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`,
  `MINIO_SECURE`), never from a manifest, and are never printed.

`ousast improve --memory [STORE]` and the `ousast learn` commands (`--memory`) read the same store.

## Measured footprint (2026-09-29, idle, two workers)

| Item | Value |
|---|---|
| kind node container memory | 1.7 GiB (27% of the 7.7 GiB host) |
| registry container memory | 34 MiB |
| node volume (images, containerd) | 4.9 GB on disk |
| worker pool | 2 gVisor workers, 1 CPU / 1.5 GiB limit each |

Disk is the binding constraint: the Substrate install and `ko` builds need several GB of Go caches. Clear them
afterwards (`go clean -cache -modcache`); rerunning the full Substrate install on a near-full disk fails in
`ko resolve`.

## What this host taught (each one cost a failed live run)

- Substrate installs no WorkerPool ("no free workers") -> `workerpool.yaml.tmpl`.
- Actor images must be pinned by digest; ax's default runner image on gcr.io needs credentials.
- A release `ax` CLI skews from the server; build it from the deployed checkout.
- ax's API rejects unknown fields; metadata is `name` + `atespace`; Git entries have no `commit`.
- `ax apply` leaves a Task Suspended until `ax resume`; the first resume may time out while Substrate builds the
  template's golden snapshot. ax has no Completed phase: completion is our artifact delivery.
- Substrate boots each template once as a golden actor with the task's env, so the runner waits for a start
  request sent through `atenet-router`; the provider key travels only in that request.
- Actor egress goes through the `atenet-egress` gateway, deny by default, one EgressPolicy per actor, hostnames
  only; the gateway dials the address the actor connected to, so the receiver is a Service dialled by ClusterIP
  with its name as Host. The Envoy gateway needs a Rust build; the agentgateway variant needs none.
- Apply a Task after the Workspaces it binds; ax copies them at create time.
- Every Task is its own actor template with a golden actor (~24 MB under `/var/lib/ate/actors` on the node). Deleting
  them failed while the snapshot bucket ax's templates name (`dberkov-gke-dev3`, from `AX_SNAPSHOTS_BUCKET`) did not
  exist in rustfs: golden actors piled up in `DELETING` and filled the disk during a 600-task harvest (2026-10-01).
  Create that bucket in rustfs (an aws-cli pod with the `rustfs-bucket-init` env); even then a deleted actor's
  directory stays on the node, so long Runs need a janitor that removes directories no live actor owns.
- A Workspace's `files` reach the actor inline in one environment variable: above ~20 KB of content the template
  fails with "actor template not found" (an 86 KB and a 31 KB excerpt did; 7 KB ran).

## Moving to a separate Kubernetes cluster (planned)

The maintainer will deploy the plane to its own Kubernetes environment. The manifests under `plane/` move as they
are; these parts assume this laptop and must change first (checked 2026-09-30):

| Assumption | Where | Needed in a real cluster |
|---|---|---|
| Artifact receiver runs on the developer host, reached through the `ousast-receiver` Service with an EndpointSlice to the kind gateway `172.19.0.1:18090` | `egress.py`, `receiver-service.yaml.tmpl` | the receiver as an in-cluster Deployment (or object storage, e.g. Substrate's S3-compatible store), with the reconciler reading from it |
| Registry `localhost:5001`, rewritten by Substrate for kind | `up.sh`, `doctor.py:45`, runner digest pin | a registry the workers can pull from; keep digest pins (Substrate rejects tags) |
| kubectl context `kind-$KIND_CLUSTER_NAME` | `doctor.py:39`, `egress.py`, `router.py` | one configurable context (for example `OUSAST_KUBE_CONTEXT`) |
| ax's snapshot bucket: `AX_SNAPSHOTS_BUCKET` in ax's `deploy/ax-server.yaml` points at the ax authors' GCS bucket | ax deploy manifest | your own bucket, set before deploying ax |
| Egress gateway applied by hand (agentgateway variant, no Rust build) | this README | the Substrate-installed gateway; per-task EgressPolicies work unchanged |
| Worker pool of 2 x 1 CPU / 1.5 GiB for the 7 GB host | `workerpool.yaml.tmpl` | sized to the cluster; `--workers` to match |
| Plane memory store and results under `~/ousast-results/` on the host | `reconciler.py` (`OUSAST_RESULTS`), `memory.py` (`OUSAST_MEMORY`) | a persistent volume or bucket shared by the reconciler; the `minio://` store already works against any reachable MinIO |

The provider key already travels only in the start request through `atenet-router`, which works the same through
a port-forward to any cluster.

## What a larger ax deployment needs

A Kubernetes cluster with Agent Substrate (and its egress gateway), the ax control plane, a registry the workers
can pull from, the runner image pinned by digest, the receiver reachable as a Service, and the provider host
allowed per task. The manifests under `plane/` move unchanged; only `OUSAST_ARTIFACT_*` and the context change.
