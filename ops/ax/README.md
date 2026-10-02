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

## Memory store on S3 (MinIO or RustFS)

`OUSAST_MEMORY=minio://<bucket>[/<prefix>]` puts the plane's memory store (`plane/memory.py`) in an
S3-compatible bucket. MinIO and RustFS both work; the maintainer's server is RustFS. Endpoint and credentials
come from `.env` (`MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE`, optional
`MINIO_REGION`, which avoids a GetBucketLocation call) and are never printed.

**The store never configures its bucket.** An admin sets it up once. Each time a `MinioStore` is opened it
checks the setup (`MinioStore.verify_bucket`), using reads plus one small probe object at
`<prefix>/_probe/select.jsonl`. If anything is missing, it refuses to start with a `MemoryStoreError` that lists
each missing piece and the admin command that fixes it. Nothing is skipped quietly. The store needs:

- **versioning `Enabled`**, because provenance cites object version ids;
- **an enabled lifecycle rule expiring `<prefix>/runs/`** (raw run outputs) after a number of days, 30 by
  default. The rule must be a plain prefix filter, and no rule may expire the whole store (`repos/`, `facts/`,
  `index.jsonl` and the blobs are kept);
- **S3 Select** (`SelectObjectContent` over JSON Lines). Every filtered read is pushed down to the server, and
  there is no fetch-and-filter fallback. A server without Select (some MinIO releases removed it) is refused;
- **object tags readable**, because rows are filtered by their `kind` tag.

One-time admin setup (admin credentials, bucket `sast-memory`, store at the bucket root):

    aws s3api put-bucket-versioning --endpoint-url "$MINIO_ENDPOINT" --bucket sast-memory \
        --versioning-configuration Status=Enabled
    aws s3api put-bucket-lifecycle-configuration --endpoint-url "$MINIO_ENDPOINT" --bucket sast-memory \
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
                                     "s3:GetObjectTagging", "s3:PutObjectTagging"],
       "Resource": ["arn:aws:s3:::sast-memory/*"]}]}

Measured state on 2026-10-02 (agent `sast-memory-agent`): versioning was `Enabled` and a 30-day rule on `runs/`
was in place. `verify_bucket` still refused, because `GetObjectTagging` returned AccessDenied for the agent.

Known RustFS limit (measured 2026-10-02): Select infers an object's JSON schema from its leading rows. A
`where` field that is missing there, even if row 5000 has it, fails with `EvaluatorBindingDoesNotExist` instead
of matching. The store raises a `MemoryStoreError` that names the field. It does not answer "no rows", since
that answer could silently drop matches.

The real-server contract tests (`OUSAST_MEMORY_TEST_MINIO=1`, bucket `OUSAST_MEMORY_TEST_BUCKET`, else
`MINIO_BUCKET`) verify the bucket at its root and write only under a fresh `contract-<id>/` prefix. They never
configure the bucket.

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
| Plane memory store and results under `~/ousast-results/` on the host | reconciler, memory layer (harnessx-removal Req 6) | a persistent volume or bucket shared by the reconciler |

The provider key already travels only in the start request through `atenet-router`, which works the same through
a port-forward to any cluster.

## What a larger ax deployment needs

A Kubernetes cluster with Agent Substrate (and its egress gateway), the ax control plane, a registry the workers
can pull from, the runner image pinned by digest, the receiver reachable as a Service, and the provider host
allowed per task. The manifests under `plane/` move unchanged; only `OUSAST_ARTIFACT_*` and the context change.
