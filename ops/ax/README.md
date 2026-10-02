# ax on this host

The service plane (`.kiro/specs/ai-service-plane/`) runs every task on google/ax over Agent Substrate in a
single-node kind cluster. ax is the only executor; `ousast plane run` submits, resumes, starts and collects.

## Bring-up

    ops/ax/up.sh          # idempotent: kind + registry, Substrate, ax, gVisor worker pool, egress gateway,
                          # receiver Service, runner image (digest pinned), ax CLI, smoke Task
    ousast plane doctor   # the profile's cluster (ops/k8s/profiles/kind.toml), Substrate, ax, runner image, memory store
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
- `s3://<bucket>[/<prefix>]` (`S3Store`, the `s3` extra: boto3 against any S3-compatible server; RustFS is the
  tested one). Endpoint and credentials come from `.env` or the environment (`S3_ENDPOINT`, `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`), never from a manifest, and are never printed.

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

## Memory store on S3 (RustFS is the tested server)

`OUSAST_MEMORY=s3://<bucket>[/<prefix>]` (or `s3://` for the bucket in `S3_BUCKET`) puts the plane's memory store
(`plane/memory.py`) in an S3-compatible bucket through boto3 (the `s3` extra). Any store with versioning,
lifecycle rules, object tags and S3 Select works; RustFS is what the contract tests run against. Endpoint and
credentials come from `.env` (`S3_ENDPOINT` as a full URL, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional
`AWS_SESSION_TOKEN` and `S3_REGION`, which avoids a GetBucketLocation call) and are never printed.

**The store never configures its bucket.** An admin sets it up once. Each time an `S3Store` is opened it
checks the setup (`S3Store.verify_bucket`), using reads plus one small probe object at
`<prefix>/_probe/select.jsonl`. If anything is missing, it refuses to start with a `MemoryStoreError` that lists
each missing piece and the admin command that fixes it. Nothing is skipped quietly. The store needs:

- **versioning `Enabled`**, because provenance cites object version ids;
- **an enabled lifecycle rule expiring `<prefix>/runs/`** (raw run outputs) after a number of days, 30 by
  default. The rule must be a plain prefix filter, and no rule may expire the whole store (`repos/`, `facts/`,
  `index.jsonl` and the blobs are kept);
- **S3 Select** (`SelectObjectContent` over JSON Lines). Every filtered read is pushed down to the server, and
  there is no fetch-and-filter fallback. A server without Select is refused;
- **object tags readable**, because rows are filtered by their `kind` tag.

One-time admin setup (admin credentials, bucket `sast-memory`, store at the bucket root):

    aws s3api put-bucket-versioning --endpoint-url "$S3_ENDPOINT" --bucket sast-memory \
        --versioning-configuration Status=Enabled
    aws s3api put-bucket-lifecycle-configuration --endpoint-url "$S3_ENDPOINT" --bucket sast-memory \
        --lifecycle-configuration '{"Rules":[{"ID":"ousast-runs-expiry","Status":"Enabled",
          "Filter":{"Prefix":"runs/"},"Expiration":{"Days":30}}]}'

`put-bucket-lifecycle-configuration` replaces every rule on the bucket, so merge this rule with any rules
already there. The agent account's policy can read the bucket's configuration but not change it. It reads and
writes objects and their tags, and it gets no `Put*` on versioning or lifecycle:

    {"Version": "2012-10-17", "Statement": [
      {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning",
                                     "s3:GetLifecycleConfiguration"],
       "Resource": ["arn:aws:s3:::sast-memory"]},
      {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject",
                                     "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:GetObjectVersionTagging"],
       "Resource": ["arn:aws:s3:::sast-memory/*"]}]}

Measured state on 2026-10-02 (agent `sast-memory-agent`): versioning was `Enabled` and a 30-day rule on `runs/`
was in place. `verify_bucket` first refused because `GetObjectTagging` returned AccessDenied for the agent; with
the three tagging permissions above (`s3:GetObjectTagging`, `s3:PutObjectTagging`, `s3:GetObjectVersionTagging`)
the real-server contract tests pass.

**Fixed schema: every row carries every queryable field.** RustFS's Select infers an object's JSON schema from its
first 1000 rows (measured 2026-10-02). Two failures follow:

- a `where` field missing from those rows, even if row 5000 has it, fails with `EvaluatorBindingDoesNotExist`;
- a column that is `null` in all of those rows and set in a later one fails the whole object with
  `JSONParsingError`, whatever the `where` names (999 leading nulls answer, 1000 fail). A column holding two JSON
  types (a string, then a number) fails the same way at any size.

So `plane/memory.py` declares per kind the fields a `where` may name (`QUERY_FIELDS`, besides the fields every
row has). They are strings, and the store writes all of them on every row at write time, `""` where one does not
apply (never `null`). `rows()` refuses an unknown kind, a `where` on a field no kind declares, and `where` = null,
before any read: a new query declares its field first. Rows written before the rule are rewritten once with
`ousast plane memory-normalise [--store URL] [--dry-run]`, which is idempotent and prints its counts; on a bucket
it writes new object versions, and versioning keeps the old ones. Run it when a store moves to RustFS. The store
never answers "no rows" for a failed Select; it raises a `MemoryStoreError` naming the object and the cause.

The real-server contract tests (`OUSAST_MEMORY_TEST_S3=1`, bucket `OUSAST_MEMORY_TEST_BUCKET`, else
`S3_BUCKET`) verify the bucket at its root and write only under a fresh `contract-<id>/` prefix. They never
configure the bucket.

## Moving to a separate Kubernetes cluster (planned, not done)

No deployment outside this host's kind cluster has been made. The step-by-step guidance, with what is implemented
and what is planned, is `docs/deployment.md` (the site page "Deployment"). The Model and Workspace manifests under
`plane/` move as they are and the Task templates need their image reference re-pinned to your registry; these parts
assume this laptop and must change first (checked 2026-10-02):

| Assumption | Where | Needed in a real cluster |
|---|---|---|
| Artifact receiver runs on the developer host, reached through the `ousast-receiver` Service with an EndpointSlice to the kind network's gateway address on `OUSAST_ARTIFACT_PORT` | `egress.py`, `receiver-service.yaml.tmpl` | the receiver as an in-cluster Deployment (or object storage, e.g. Substrate's S3-compatible store), with the reconciler reading from it |
| The kind-local registry (`registry` in `ops/k8s/profiles/kind.toml`), rewritten by Substrate for kind | `up.sh` (`KO_DOCKER_REPO`), the profile's images file, the `image` of every template under `plane/tasks/` | the `k3s` profile's registry; keep digest pins (Substrate rejects tags); `--runner-image FILE` re-pins generated Tasks |
| kubectl context | `kube_context` in the profile, read by `doctor.py`, `egress.py`, `router.py` (plane-on-kubernetes 1.2); `up.sh` reads the same profile | the `k3s` profile's context; nothing else changes |
| ax's snapshot bucket: `AX_SNAPSHOTS_BUCKET` in ax's `deploy/ax-server.yaml` points at the ax authors' GCS bucket | ax deploy manifest | your own bucket, set before deploying ax |
| Egress gateway applied by hand (agentgateway variant, no Rust build) | this README | the Substrate-installed gateway; per-task EgressPolicies work unchanged |
| Worker pool of 2 x 1 CPU / 1.5 GiB for the 7 GB host | `workerpool.yaml.tmpl` | sized to the cluster; `--workers` to match |
| Plane memory store and results under `~/ousast-results/` on the host | `reconciler.py` (`OUSAST_RESULTS`), `memory.py` (`OUSAST_MEMORY`) | a persistent volume or bucket shared by the reconciler; the `s3://` store already works against any reachable S3-compatible server |

The provider key already travels only in the start request through `atenet-router`, which works the same through
the kube-context tunnel to any cluster.

## What a larger ax deployment needs

A Kubernetes cluster with Agent Substrate (and its egress gateway), the ax control plane with `AX_SNAPSHOTS_BUCKET`
pointing at your own bucket, a registry the workers can pull from, the runner image pinned by digest, the receiver
reachable as a Service, and the provider host allowed per task (which each task's EgressPolicy already does). The
Model and Workspace manifests under `plane/` move unchanged; the Task templates get a new image reference; the kube
context and `doctor`'s registry check are not configurable yet (the table above). Step by step: `docs/deployment.md`.
