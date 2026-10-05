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
in `~/.cache/ousast/ax-src/`. The cluster's context, registry and pool sizes come from the kind profile
(`ops/k8s/profiles/kind.toml`); `up.sh` writes the runner's digest pin to that profile's images file
(`ops/k8s/profiles/kind-images.json`), which the templates are re-pinned from and which is committed with them.
`up.sh` and `smoke-run.sh` run the checkout's code with `OUSAST_PYTHON` (default `.venv/bin/python`).

The kind profile runs on a 7.7 GB server VM. Observability is off by default
(`kind_observability = false` in `ops/k8s/profiles/kind.toml`). This saves the measured
930 MiB used by `otel-system`, about 40% of the cluster's 2.3 GB. The smoke Run still
completes with those deployments stopped. To enable the stack, run
`OUSAST_KIND_OBSERVABILITY=1 ops/ax/up.sh` or set `kind_observability = true` in the profile.

`up.sh` stages copied Substrate manifests in a temporary checkout view and installs through
`hack/install-ate-kind.sh`. The local `ops/ax/substrate-kind-lean/` overlay removes the collector,
Prometheus, Jaeger and their supporting resources before installation. This preserves the
installer's secret, CRD and image setup. The upstream checkout is unchanged. The shared
`ate-otel-config` disables trace, metric and log export and the OTEL SDK; it removes the old
collector endpoint and metric timing keys. On an existing cluster, `up.sh` scales the three
observability deployments to zero, replaces the ConfigMap data and rolls its consumers when
the configuration changes. Opting in restores the upstream ConfigMap and observability manifests.

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
assume this server VM and must change first (checked 2026-10-02):

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

## Search executor and verifier task contract (operator verified 2026-10-05)

There are two workers and no queue. `no free workers available` is capacity
back-pressure: the dispatcher retries the same apply with 15–30 seconds of jitter,
up to the workload deadline. It does not retry a sandbox execution or route to the VM
because of this response. A shared reservation limits all AX workloads in one host
process to two tasks; separate host processes coordinate through AX's rejection.

Search executors build on the disk-backed `/workspace`, export a single archive, and
are deleted before verifier repetitions start. The archive contains `checkout/`,
`products/`, and `spec.json` with a `none` build recipe. A verifier receives only
`VERIFY_INPUT_URL` and `RESULT_URL`; it never installs dependencies or fetches source.
The executor's host-scoped `PREPARED_PUT_URL` carries the built output. The host checks
its SHA-256 before passing it to fresh verifier tasks. Each side has three fresh runs.

Verifier egress to `files.because-security.com:443` is requested but **pending**.
Until the operator enables it, live verifier input/output is blocked. The first input
download tolerates up to 60 seconds of delayed policy activation.

`/` and `/tmp` consume the worker's 3 GiB RAM; `/workspace` has about 2 GiB usable disk.
Entrypoints set `TMPDIR=/workspace/tmp`, `npm_config_cache=/workspace/.npm`,
`MAVEN_OPTS=-Dmaven.repo.local=/workspace/.m2`, `COMPOSER_HOME=/workspace/.composer`,
`PIP_CACHE_DIR=/workspace/.pip`, and `GRADLE_USER_HOME=/workspace/.gradle`.
`OUSAST_SCRATCH_BYTES` overrides the default 2147483648-byte workspace guard. The guard
includes caches and open output logs, checks running children and completed writes,
and reports `could_not_build` / `scratch limit`. It is a monitored guard, not a hard
filesystem quota; programs that hardcode `/tmp` still consume the worker's RAM.

Repository clones must use HTTPS `git clone https://github.com/...git` or codeload
archives, never `api.github.com`: tasks share one public IP. Search task inputs are
presigned checkout archives, so these entrypoints do not clone repositories themselves.

## Image layers, publication and node cache budget

The task family has one shared runtime base, `ousast-task-base`, built from the
public AX runner v0.3.1. `base-browser` adds Chromium to that exact published base
(by digest); engine and replay do not carry Chromium. The VM/kind `openultrasast`
image uses the same base and Joern recipe. Replay inherits the published engine
digest in CI, so even a cold build cannot accidentally duplicate its Joern layers.

Java is **Temurin 21 JDK**, copied from `eclipse-temurin:21-jdk-jammy`.
`ops/frontend-retention/install.py` explicitly requires Java 21 and invokes
`java -cp ... dotty.tools.dotc.Main` using Joern's bundled Scala compiler.
The shared JDK also provides `javac` for Maven/Gradle project builds.
Curl/unzip and retention build scratch stay in a discarded Joern build stage.
Joern stays above the base in the engine image (also used by replay and the VM
lane); its compiler jars and retention provenance must not be blindly pruned.
Runtime dependencies from `pyproject.toml` (core plus semantic/s3 for the VM lane)
precede project code. Package installation uses `--no-deps --no-cache-dir`;
its isolated packaging backend is temporary.

The base retains upstream Python 3.12 with venv/pip. Its explicit apt package list
is `nodejs npm node-typescript php-cli composer maven sqlite3 bubblewrap util-linux
git ca-certificates libstdc++6 zlib1g`. Composer is the trixie apt package.
Chromium is installed only in `base-browser`. Apt caches/lists and docs/man/info
are cleaned; dpkg excludes new docs/man/info. Files already in inherited AX
layers still occupy space even if deleted.

Executor preparation supports pip, npm, Composer, Maven and Gradle builds.
There is **no installed Gradle binary**: the executor invokes the selected project's
`gradlew` through `/bin/sh`, including for wrappers without executable permissions.
Gradle-wrapper distribution downloads and dependency downloads go through
**public HTTPS from the executor**, subject to its egress policy and deadline.
The verifier receives prepared products and performs no dependency downloads.

Rebuild policy:

- Dependency/toolchain changes: run **Task base image** (also triggered by changes
  to `plane/Dockerfile.base`, `pyproject.toml`, or `uv.lock`). It publishes
  `base-<short sha>` and `base-content-<input hash>` tags, plus their `-browser`
  variants, and prints immutable digest references. Content tags identify build
  inputs; they do not claim reproducible upstream apt/PyPI resolution. The lockfile
  triggers refreshes but pip installs the declared runtime constraints, not a uv
  frozen environment. Deliberate upstream refreshes use manual dispatch.
- After both targets publish, ensure `ousast-task-base` is **public** in GHCR's
  package settings. Copy the workflow summary's JSON into `plane/task-base.digest`
  and submit that pin update for normal review. CI does not commit on your behalf.
  The initial null pins mean **unpublished**, not a usable bootstrap image.
- A pin update or `plane/Dockerfile.*`/root Dockerfile change on main runs **Engine
  image**. For source, entrypoint or retention-installer changes, dispatch it once
  for the desired revision, or push a `v*` release tag. Source-only merges no longer
  publish images automatically. Never rebuild per task/run. All builds use scoped
  GHA caches; pin checks precede builds and require anonymous access plus identical
  base-layer ancestry for the browser variant.
- Final package names must also be public in GHCR. Publication checks anonymous
  access after logout and fails if the package is private. Set visibility on first
  publication and rerun as needed. Deploy only the reported `image@sha256:...`
  references in the cluster profile/Task manifests, never `main` or a release tag.
  Publication does not automatically change deployed Task pins.

For a local task build, pass `TASK_BASE_TAG` and `TASK_BASE_DIGEST` from the base
pin; search instead takes `TASK_BROWSER_TAG` and `TASK_BROWSER_DIGEST`. Replay's
`ENGINE_REF` defaults to its local engine stage; set it to the published engine
reference to reuse exactly those layers. When building `base-browser` locally,
pass `TASK_BASE_REF=<full base tag@digest>` for the same ancestry as CI.

The operator's capacity rule is **all images in rotation, unpacked, together
at most approximately 9 GiB**, including rollback revisions. Working builds take
priority over minimizing an individual executor image; its previous 2.13 GB
unpacked (~1.98 GiB) was acceptable. Retire unused Task templates and image
revisions before rotating a large base/Joern generation. Shared layers occupy
storage once where the runtime deduplicates them, but do not assume that turns
a sum above 9 GiB into an acceptable rotation. Record both the sum of unpacked
image sizes and actual unique-layer storage. Never prune images used by live tasks.

Expected footprint (planning estimates only; no images built for this change):

| Image | Expected unpacked size | Basis / uncertainty |
| --- | --- | --- |
| Shared base | about 1.3–1.9 GiB | ~454 MB inherited AX layers + ~281 MB JDK baseline + npm/Composer/Maven, language runtimes and venv/extras; apt dependency closure unmeasured |
| Browser base | about 1.65–2.45 GiB | Shared base + roughly 350–550 MB Chromium/dependencies |
| Search executor/verifier | about 1.7–2.5 GiB | Browser base + application; previous 2.13 GB unpacked is a baseline, not a ceiling |
| Engine | roughly 3.5–6 GiB | Restored shared base + Joern; the supplied 2.16 GB compressed engine cannot establish its unpacked size |
| Replay | engine + a few KiB | Same engine digest plus replay entrypoint |
| VM/kind openultrasast | roughly 3.5–6 GiB plus benchmark assets | Same base/Joern, runtime extras shared, benchmark payload retained |

An engine + search rotation therefore sums to about **5.2–8.5 GiB** before
rollback images. Adding replay as another unpacked image brings the sum to about
**8.7–14.5 GiB**; this rotation is not demonstrated to fit 9 GiB. Engine/replay
share almost all layers, but the operator must confirm the accounting and measured
footprint before selecting a rotation. Extra revisions and the VM image add to
the budget if retained there.

The previous search history included a 1.37 GB apt layer and 281 MB JDK; no
per-package apt breakdown is available. Removing system Gradle and docs/caches
may save space, while retained build tools and shared Python extras cost space.
These ranges are not measured savings or a capacity guarantee. After publication,
measure unpacked images and unique layers for the entire intended rotation, and
verify build recipes, PHP/JavaScript retention, runner startup and Chromium before
rollout. There is no separate <1.5 GiB executor gate.
