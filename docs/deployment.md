# Deployment

This page covers two things. First, how the agentic plane is deployed today. Second, what moving it to a
separate Kubernetes cluster would take. It describes the state as of 2026-10-02 (v2.0.0).

A scan needs none of this. `ousast scan` and `ousast pre-push` run from the Python package. Joern runs
from the Docker image (see [Engine and pre-push](ops/README.md)). The plane is the maintainers' tool for
model work over whole repositories. `ousast plane` drives it.

This page uses two words strictly:

- **Implemented** means the code on `main` does it, and it has run on the maintainer's host.
- **Planned** means it has not been done. The guidance comes from the code and from what the host taught
  us. Each code change it needs is named with its file path.

**No deployment of the plane to a cluster other than the maintainer's single-node kind cluster has
been made.** Section B is guidance, not a record. (kind runs a Kubernetes cluster inside Docker
containers on one machine.)

## What runs where today (implemented)

```mermaid
flowchart LR
    subgraph host ["Operator's host"]
        rec["Reconciler: ousast plane run"]
        rcv["Artifact receiver: in-process HTTP server, port 18090"]
        env[".env or exported variables: provider keys, S3 settings"]
    end
    subgraph cluster ["kind cluster on the same host"]
        ax["ax control plane (ax-system)"]
        sub["Agent Substrate (ate-system): atenet-router, atenet-egress"]
        act["Task actors in gVisor workers (WorkerPool ousast-pool)"]
        svc["Service ousast-receiver + EndpointSlice to the host"]
        reg["Registry localhost:5001: runner image by digest"]
    end
    mem[("Memory store: file store on the host, or an S3 bucket (RustFS tested)")]
    rec -- "ax apply, resume, get, delete" --> ax
    rec -- "EgressPolicy per actor; start request via port-forward" --> sub
    sub --> act
    act -- "HTTP by Service name through the gateway" --> svc
    svc --> rcv
    rec --> mem
    reg -. "pull by digest" .-> act
```

| Part | Where it runs | Code or manifest |
| --- | --- | --- |
| Reconciler (`ousast plane run`, `status`, `remember`) | the operator's host | `src/openultrasast/plane/reconciler.py` |
| Artifact receiver | an HTTP server inside the reconciler process, on the host, port `OUSAST_ARTIFACT_PORT` (18090) | `src/openultrasast/plane/egress.py` (`Receiver`, `RECEIVER_PORT`) |
| How actors reach the receiver | the Service `ousast-receiver.ax-system` (port 80) with a selector-less EndpointSlice whose endpoint is the kind network's gateway address on the host; the runner dials the ClusterIP with the Service name as `Host`, which the egress gateway allows by hostname | `ops/ax/receiver-service.yaml.tmpl`, rendered by `up.sh` |
| ax control plane, Agent Substrate, egress gateway, router | the kind cluster (`ax-system`, `ate-system`) | installed by `ops/ax/up.sh` from the upstream checkouts under `~/.cache/ousast/ax-src/` |
| Tasks | one actor per Task in a gVisor worker; two warm workers of 1 CPU / 1.5 GiB | `ops/ax/workerpool.yaml.tmpl` |
| Runner image | the kind-local registry `localhost:5001`, pinned by digest (`~/.cache/ousast/ax-src/runner-image`) | `plane/Dockerfile.runner`; the `image` of every template under `plane/tasks/` |
| Provider keys | read from the operator's environment or `.env` (which never overrides an exported variable), sent only in the start request through a `kubectl port-forward` to `svc/atenet-router` | `src/openultrasast/plane/router.py` |
| Memory store | `OUSAST_MEMORY`: a file store under `~/ousast-results/plane/memory` by default, or `s3://<bucket>[/<prefix>]` on any reachable S3-compatible server (RustFS is the tested one) | `src/openultrasast/plane/memory.py`, [Memory](memory.md), [RustFS setup](rustfs.md) |
| Run state and artifacts | `$OUSAST_RESULTS/plane/<run>/` on the host (default `~/ousast-results/plane/`) | `reconciler.py` (`run_dir`) |

Terms in the table:

- **ax** is Google's controller that runs agent tasks on Kubernetes.
- **Agent Substrate** is the layer below ax that owns the machines and runs sandboxes.
- **gVisor** is a sandbox runtime that isolates each actor from the node's kernel.
- An **actor** is one running Task inside a sandbox.

Only the reconciler talks to the memory store. A sandboxed task cannot read it. So the reconciler seeds
the loop's `memory-snapshot` before the Run starts ([The plane on ax](plane.md)).

## A. This host: the local setup (implemented)

`ops/ax/up.sh` needs these tools on the PATH: `docker`, `go`, `kubectl`, `kind`, `ko` and `ax`. It
refuses to start when one is missing. Tools live in `~/go/bin` and `~/.local/bin`. Sources and rendered
files live in `~/.cache/ousast/ax-src/` (`OUSAST_AX_SRC`).

1. **Bring up the cluster and the plane.**

    ```bash
    ops/ax/up.sh
    ```

    The script is idempotent: it skips each step that is already done. In order, it:

    - creates the kind cluster (`KIND_CLUSTER_NAME`, default `ousast`) with its registry
      (`KO_DOCKER_REPO`, default `localhost:5001`);
    - installs Agent Substrate;
    - applies the egress gateway if the install left it out (the agentgateway variant, one prebuilt image);
    - deploys the ax control plane;
    - applies the receiver Service, with the host's kind-gateway address as its endpoint;
    - applies the gVisor worker pool;
    - builds and pushes the runner image, and writes its digest pin to `~/.cache/ousast/ax-src/runner-image`;
    - installs the `ax` CLI from the deployed checkout (a release CLI does not match the server version);
    - runs one smoke Task.

    At the end it prints the host's memory and the kind containers' usage.

2. **Check it.**

    ```bash
    uv run ousast plane doctor
    ```

    It runs four checks:

    - the kind context is reachable;
    - every pod in `ate-system` is ready;
    - every pod in `ax-system` is ready;
    - the registry at `localhost:5001` holds `ousast-runner`.

    Each failing line names `ops/ax/up.sh` as the fix. `doctor` is informational only.
    `ousast plane run` does not call it.

3. **Run the end-to-end smoke Run.**

    ```bash
    ops/ax/smoke-run.sh
    ```

    It renders `ops/ax/smoke-run.yaml.tmpl` with the current runner digest. It then submits the Run
    `ax-e2e-smoke` through the reconciler. The Run has one model-free `repo-facts` Task (`budget: {usd: 0,
    calls: 0}`) over a files-only Workspace, resumed, started through the router, its `facts.json`
    and `summary.json` delivered to the host. Then `ousast plane status ax-e2e-smoke`
    prints the attribution table. The script calls the repository's `.venv/bin/ousast`, so run `uv sync`
    first.

4. **Keys and the store.**

    - Put `DEEPSEEK_API_KEY` (chat) and `OPENROUTER_API_KEY` (embeddings) in `.env`, or export them.
    - A Task's Model names the variable (`secretKey.key`). The key travels only in that Task's start
      request.
    - For the S3 store, set `OUSAST_MEMORY=s3://<bucket>` with `S3_ENDPOINT`, `AWS_ACCESS_KEY_ID` and
      `AWS_SECRET_ACCESS_KEY`. `S3_REGION` and `S3_BUCKET` are optional.
    - An admin must set up the bucket once, as [RustFS setup](rustfs.md) describes. The store verifies
      it at every start.

5. **Run a real Run**, as in [Examples](examples.md#7-running-the-agentic-plane): `ousast plane run
    plane/runs/validation-46.yaml`, then `status` and `remember`.

6. **Tear down** with `ops/ax/down.sh`. It deletes the cluster and its registry.

**Footprint** (measured 2026-09-29, idle, two workers; [ax on this host](ops/ax/README.md#measured-footprint-2026-09-29-idle-two-workers)):

| Item | Value |
| --- | --- |
| kind node container memory | 1.7 GiB (27% of the 7.7 GiB host) |
| registry container memory | 34 MiB |
| node volume (images, containerd) | 4.9 GB on disk |
| worker pool | 2 gVisor workers, 1 CPU / 1.5 GiB limit each |

Disk is the tightest limit, for two reasons:

- The Substrate install and the `ko` builds need several GB of Go caches. Run `go clean -cache -modcache`
  afterwards.
- Every Task is its own actor template with a golden actor (a saved snapshot the actor boots from). Each
  takes about 24 MB under `/var/lib/ate/actors` on the node.

[ax on this host](ops/ax/README.md#what-this-host-taught-each-one-cost-a-failed-live-run) lists the
failures the host produced and what each one taught.

## B. A separate Kubernetes cluster (planned)

The target cluster would do four things:

- run Agent Substrate with its egress gateway and the ax control plane;
- pull the runner image from a registry of yours;
- receive task artifacts without a developer laptop in the path;
- keep its memory in your S3 bucket.

The provider key already travels only in the start request through `atenet-router`. That works the same
through a port-forward to any cluster. Everything else below is either a step you take or a code change
that is not made yet.

### B.1 Cluster with Agent Substrate, its egress gateway and ax

- Install Agent Substrate on the cluster with its own instructions. `ops/ax/up.sh` uses Substrate's kind
  helpers (`hack/create-kind-cluster.sh`, `hack/install-ate-kind.sh`). These do not apply to another
  cluster.
- Apply the egress gateway. On this host it is the agentgateway variant
  (`manifests/ate-install/agentgateway-egress` in the Substrate checkout). It is applied with
  `kubectl kustomize --load-restrictor=LoadRestrictionsNone`. It needs no Rust build; the Envoy variant
  does.
- Without the gateway an actor has no network at all.
- The reconciler writes one EgressPolicy per task (`src/openultrasast/plane/egress.py`). These work
  unchanged against the gateway that Substrate installs. The rules are:
    - deny by default;
    - hostnames only;
    - plain HTTP to the receiver;
    - TLS passthrough to the Workspaces' Git hosts and the Model's declared hosts.
- Deploy ax (`make deploy AX_IMAGE_REPO=<your registry>` in the ax checkout) **after** B.2.
- Apply a WorkerPool (B.6). Substrate installs none by itself ("no free workers").

### B.2 ax's snapshot bucket: `AX_SNAPSHOTS_BUCKET`

Point `AX_SNAPSHOTS_BUCKET` at **your own bucket before deploying ax**. ax's deploy manifest
(`deploy/ax-server.yaml` in the ax checkout) sets it to the ax authors' own bucket. In the checkout used
here that is `gs://dberkov-gke-dev3/ate-env/`.

This host shows what goes wrong otherwise (2026-10-01):

1. The bucket named there did not exist in the S3 server.
2. Deleted golden actors piled up in `DELETING`.
3. They filled the disk during a 600-task harvest.

Creating the bucket let deletes complete. Even then, a deleted actor's directory stays on the node. So
long Runs need a janitor that removes directories no live actor owns.

### B.3 A registry the workers can pull from, the runner image pinned by digest

- Build the runner from the repository root and push it to your registry:

    ```bash
    docker build -f plane/Dockerfile.runner -t <registry>/ousast-runner:dev .
    docker push <registry>/ousast-runner:dev
    docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' <registry>/ousast-runner:dev
    ```

- Substrate rejects tags. Every Task's `image` must be the `<registry>/ousast-runner@sha256:...`
  reference.
- Write that reference into a file. On this host the file is `~/.cache/ousast/ax-src/runner-image`.
- Pass `--runner-image FILE` to `ousast plane workspaces` and `ousast plane harvest`. They re-pin the
  Tasks they generate.
- The committed templates under `plane/tasks/` and the generated `plane/tasks/validation-46.yaml` carry
  `localhost:5001/ousast-runner@sha256:...`. They need the same re-pin before they run elsewhere.
  Regenerate them, or replace the reference.
- Workers must be able to pull from the registry. Credentials, if any, are the cluster's concern. ax's
  default runner image on `gcr.io` needs credentials and is not used here.
- **Not yet configurable:** `ousast plane doctor` checks the registry at `localhost:5001` by name
  (`src/openultrasast/plane/doctor.py:45`). So its fourth check fails on another cluster, even when the
  image is in place. `doctor` is informational; `plane run` does not depend on it.

### B.4 One configurable kube context

The reconciler, the egress client and the router port-forward all use one kube context. Its name is
`kind-$KIND_CLUSTER_NAME` (`kind-ousast` by default).

**Not yet configurable**: the prefix `kind-` is hard-coded in these places:

- `src/openultrasast/plane/doctor.py:39`;
- `src/openultrasast/plane/egress.py:115` and `:148`;
- `src/openultrasast/plane/router.py:145`;
- `ops/ax/up.sh:24` builds the same name.

The planned change is one variable read in those three modules, for example `OUSAST_KUBE_CONTEXT`.

Until then, there is one workaround to drive another cluster with the unchanged code. Rename its
kubeconfig context to that form: `kubectl config rename-context <ctx> kind-<name>` and
`KIND_CLUSTER_NAME=<name>`. This is a workaround, not a supported configuration.

The egress client also needs `kubectl-ate` (or the executable `OUSAST_KUBECTL_ATE` names). It must be
able to use that context.

### B.5 The receiver: in-cluster instead of on the host

Today the receiver is a thread inside the reconciler process (`egress.py`, `Receiver`). The reconciler
learns that a task finished by watching that object's `delivered` set in memory (`reconciler.py`).
Actors reach it through the Service `ousast-receiver.ax-system`. That Service's EndpointSlice points at
the host.

There are three paths, from least to most effort:

1. **Interim, works with the unchanged code:** keep the host receiver.
   Render `ops/ax/receiver-service.yaml.tmpl` with an endpoint address the egress gateway pod can reach.
   In the template, `KIND_GATEWAY` is just an IPv4 address and `OUSAST_ARTIFACT_PORT` is the port.
   The cluster must be able to reach the reconciler's host, through a VPN or a routed address.
   The gateway dials the address the actor connected to. So the Service's ClusterIP must still map to it.
2. **Planned: the receiver as an in-cluster Deployment** behind the same Service name.
   The reconciler would read deliveries from it and serve inputs from it, instead of from its own thread.
   This needs code. The receiver and its `delivered`/`inputs` state are in-process today.
   The same process serves the runner's `GET /inputs/<producer>/<artifact>`.
3. **Follow-on: presigned-URL delivery to the S3 store.** (A presigned URL grants one upload or download
   without credentials.)
   The runner would `PUT` its output tar to a presigned URL on the memory store's bucket.
   It would fetch inputs the same way, and the reconciler would read from the bucket.
   None of this exists. The EgressPolicy would then have to allow the store's hostname for the task.

### B.6 Worker pool sizing

`ops/ax/workerpool.yaml.tmpl` declares two warm gVisor workers for the 7 GB host. Each has 1 CPU /
1.5 GiB (requests 250m / 1.5 GiB). They are placed on nodes by `ate.dev/substrate-version`.

An actor occupies a whole worker. So the pool size is the number of tasks that can run at once. Set
`--workers` on `ousast plane run` to match.

Size the workers above the largest Task's limits. For `verify` these are requests 250m / 384Mi and
limits 1 CPU / 1 GiB. `roles` and the others are in `plane/tasks/`. Also keep the golden-actor storage
on the node in mind (B.2).

### B.7 The S3 memory store reachable from where the reconciler runs

The `s3://` store already works against any reachable S3-compatible server. The server must support:

- versioning;
- lifecycle rules;
- object tags;
- S3 Select (a server-side query over JSON objects).

RustFS is the tested server. The bucket setup and the agent policy are on [RustFS setup](rustfs.md).

Only the reconciler reads and writes the store. So today the operator's host must reach it. If the
reconciler moves into the cluster, its pod must reach it.

No Task talks to the store directly. If one ever does (B.5, path 3), its EgressPolicy must allow the
store's hostname. The policies allow hostnames only, never addresses. A Model already declares its hosts
this way today, through `openultrasast.io/egress-hosts`.

### B.8 Secrets in Kubernetes Secrets, injected into the reconciler's environment

The reconciler reads these variables from its own environment or `.env`:

- the variable a Model's `secretKey.key` names (`DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`);
- the store's `S3_ENDPOINT`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`;
- optionally `AWS_SESSION_TOKEN`, `S3_REGION` and `S3_BUCKET`.

When the reconciler runs in the cluster, keep these in Kubernetes Secrets. Inject them into **the
reconciler's** pod environment. Use `envFrom` with `secretRef`, or `valueFrom.secretKeyRef` per variable.

Never put a value into a manifest. The key stays out of every manifest:

- the Model manifests name a variable;
- the rendered Task carries no key;
- the key reaches an actor only in the start request;
- the runner keeps it in memory and redacts it from echoed stderr.

The `secretKey.name` values in `plane/models/` (`deepseek`, `openrouter`) are the names such Secrets
would carry.

Running the reconciler in-cluster is itself planned. Today it is a host process. Its state directory
(`OUSAST_RESULTS`) would need a persistent volume.

### What is implemented and what is planned

| Item | Status |
| --- | --- |
| ax as the only executor; `plane run|status|doctor|remember|memory-normalise|workspaces|harvest|alerts-engine` | implemented, run on this host |
| Per-task EgressPolicy, credentials only in the start request, per-task budgets and attribution | implemented |
| S3 memory store against any reachable S3-compatible server, verified at startup | implemented (RustFS tested) |
| Local bring-up, doctor, smoke Run (`ops/ax/`) | implemented |
| Re-pinning generated Tasks to another registry (`--runner-image`) | implemented; the committed templates still name `localhost:5001` |
| Deployment to a cluster other than this host's kind cluster | **not done** |
| One configurable kube context | **planned**; `kind-` hard-coded in `doctor.py`, `egress.py`, `router.py` |
| `doctor` registry check against a configurable registry | **planned**; `localhost:5001` hard-coded in `doctor.py:45` |
| Receiver as an in-cluster Deployment | **planned** (code change) |
| Presigned-URL delivery to the S3 store | **follow-on**, not started |
| Reconciler running in-cluster with Secrets injected into its environment | **planned** |
| `AX_SNAPSHOTS_BUCKET` on your own bucket, worker pool sized to the cluster | your deployment's setting; documented, nothing to change in this repository |

## Production topology: ax on a Kubernetes cluster

This section answers the maintainer's questions from the code and the upstream checkouts under
`~/.cache/ousast/ax-src/`:

- How is it hosted in ax?
- Is there one container?
- How does ax relate to Kubernetes?
- What would scaling the pre-push hook take?

The decisions of 2026-10-02 set the target: **two profiles of one code base**.

- `kind` is this laptop. It stays a first-class local execution mode. Every change is proven here first.
- `k3s` is production. (k3s is a small Kubernetes distribution.)

Everything marked **planned** is not built. The rest is what runs on this host today.

```mermaid
flowchart LR
    subgraph dev ["Laptop or CI job"]
        hook["ousast pre-push: local, 30 s deadline"]
        cli["ousast plane run, remote mode (planned)"]
    end
    subgraph k3s ["k3s cluster (the kind profile is the same picture on one laptop)"]
        subgraph axns ["Namespace ax-system"]
            axs["ax-server Deployment + Redis"]
        end
        subgraph atens ["Namespace ate-system: Agent Substrate"]
            ctl["ate-api-server, ate-controller, atelet"]
            rt["atenet-router"]
            eg["atenet-egress gateway"]
            wp["WorkerPool: gVisor workers, runsc RuntimeClass, HPA (planned)"]
            ewp["Engine WorkerPool: Joern as a task (planned)"]
        end
    end
    ghcr["GHCR: runner and engine images by digest (planned)"]
    s3[("S3 memory store: memory rows, task artifacts (planned)")]
    llm["Model provider"]
    hook -. "calls the CLI in remote mode (planned)" .-> cli
    cli -- "ax apply, resume, delete: ingress or kubeconfig" --> axs
    axs -- "ActorTemplate per Task" --> ctl
    ctl --> wp
    ctl --> ewp
    cli -- "start request" --> rt
    rt --> wp
    wp -- "PUT artifacts, presigned" --> eg
    eg --> s3
    eg -- "TLS passthrough" --> llm
    ghcr -. "pull by digest" .-> wp
    cli -- "polls: status, attribution" --> s3
```

This picture has no inbound path:

- the CLI reaches ax-server and the router from outside;
- the tasks push their artifacts to the store through the egress gateway;
- the CLI reads the store.

Today's EndpointSlice back to a laptop (`ops/ax/receiver-service.yaml.tmpl`) belongs to the kind
profile only. It does not appear in production.

### ax, Kubernetes and Agent Substrate in three sentences

**ax is a Kubernetes application.**

- It is a Deployment `ax-server` with a Redis beside it, in the namespace `ax-system`
  (`ax/deploy/ax-server.yaml` in the ax checkout).
- Its controller runs with `--template=default-template --template-atespace=ax-system`.
- The `ax` CLI reaches it through a `kubectl port-forward` to `svc/ax-server`
  (`ax/internal/tunnel/tunnel.go`).
- So `ousast plane run` needs a kube context or an ingress, not a public endpoint.

**ax does not run containers itself.**

- It turns every Task into an ActorTemplate on Agent Substrate (`ax/internal/substrate/client.go`,
  `CreateActorTemplate`).
- The ActorTemplate is built from the Task's image and environment.
- The image must be pinned by digest. Substrate's `SandboxConfig` validation rejects tags: "All images
  must include a digest".

**Agent Substrate is the layer that owns the machines.**

- In the namespace `ate-system` it runs `ate-api-server`, `ate-controller`, the `atelet` DaemonSet,
  `atenet-router`, the `atenet-egress` gateway, a Postgres and a RustFS
  (`substrate/manifests/ate-install/`).
- It defines three CRDs (custom Kubernetes resource types) under `ate.dev/v1alpha1`: `WorkerPool`,
  `SandboxConfig` and `CSIDriverConfig`.
- A `WorkerPool` keeps warm worker pods (`ko://.../cmd/ateom-gvisor`).
- An actor is one gVisor sandbox inside one of those workers.
- The actor boots from the golden snapshot that [The plane on ax](plane.md) describes. The controller
  suspends and resumes it.
- Names are limited to 63 bytes (`MaxNameLength` in `ax/pkg/apis/v1alpha1/types.go`). That is why the
  generated Task names are short.

**What k3s changes** (planned; nothing has been applied to a k3s cluster):

- k3s runs containerd with no Docker socket. So the host-Docker path of `ousast plane alerts-engine`
  does not exist there. The engine must become a task (below).
- Substrate's gVisor workers need `runsc` and a `RuntimeClass` on the nodes they run on.
- k3s ships Traefik and local-path storage. Traefik is an ingress the CLI can use instead of a kubeconfig.
- GitHub Actions builds the images from tagged commits. They are published to GitHub Container Registry
  and digest-pinned in the manifests.
- A private package needs an `imagePullSecret` on the worker ServiceAccount.
- Substrate's and ax's own images are built with `ko` from their checkouts. They are pushed to the same
  registry.
- The kind profile keeps `localhost:5001` and `ops/ax/up.sh`.

### One image, and what concurrency equals

There is **one container image** for every Task: `plane/Dockerfile.runner`. It is `python:3.12-slim`
plus this package. PID 1 is `/usr/local/bin/ax-task-runner`, which is `openultrasast.plane.runner`.

Each Task manifest under `plane/tasks/` names the same image by digest. The pin is kept in
`~/.cache/ousast/ax-src/runner-image`. The manifest picks its work with `spec.command`. The runner
starts `python -m openultrasast.plane.tasks.<command[0]>` (`runner.py`, `task_module`).

`repo-facts`, `verify`, `agree`, `features`, `remember`, `alerts`, `loop` and `roles` are modules in
that image. They are not images of their own. The engine would be the second image (planned).

So the production answer to "how many containers" is:

- one image;
- one actor per Task;
- **an actor occupies a whole worker**. Its limits are the ActorTemplate's, and the worker holds one
  actor at a time.

Concurrency is therefore the number of workers in the `WorkerPool`, nothing else.
`ops/ax/workerpool.yaml.tmpl` declares `replicas: 2` of 1 CPU / 1.5 GiB. So at most two Tasks run at
once on this host. `ousast plane run --workers` must not exceed the pool.

Substrate ships two scaling aids:

- **An autoscaled pool** (`substrate/demos/autoscaled-workerpool/README.md`). An HPA (Horizontal Pod
  Autoscaler) reads the external metric `ate_workerpool_workers{state=at_capacity}` through
  prometheus-adapter. It writes `WorkerPool.spec.replicas`. Its README says the demo is kind-only today.
- **Request parking** (`substrate/demos/parking/`). The router holds a resume until a worker frees up.

`ops/ax/up.sh` applies neither. The production profile's pool manifests and autoscaling rule are
**planned**.

### The three components that are bound to the host today

| Component | Today (the kind profile) | Production (the k3s profile, planned) |
| --- | --- | --- |
| Reconciler (`ousast plane run`, `src/openultrasast/plane/reconciler.py`) | a process on the operator's host; calls `ax` and `kubectl` against `kind-ousast`, holds the Run's state under `OUSAST_RESULTS` | **the reconciler stays the CLI.** An execution mode `local` or `remote`: in `remote`, the same `ousast plane run` from a laptop or a CI job submits the Run to ax-server in k3s (over the cluster's ingress or a kubeconfig), sends the start requests, then polls the store and prints the same `status` and attribution table. Credentials come from the caller's environment as today (CI secrets in a job; B.8's rule, no value in a manifest). An unattended in-cluster reconciler (a Deployment with a submit API, or a Job per Run) is a **later option**, not the first step |
| Artifact receiver (`plane/egress.py`, the `Receiver` thread inside the reconciler) | reached through the Service `ousast-receiver.ax-system` whose EndpointSlice points at the kind gateway address on the host (`ops/ax/receiver-service.yaml.tmpl`) | **no receiver in remote mode.** Tasks deliver their artifacts and fetch their inputs through presigned URLs on the S3 memory store (B.5, path 3; the store's hostname enters each Task's EgressPolicy, B.7), and the CLI reads completion from the store. The kind profile keeps the receiver thread; an in-cluster receiver Deployment (B.5, path 2) is not the chosen direction |
| Joern engine (`plane/engine_alerts.py`, the host's `openultrasast:dev` container, run with `--memory 3g`) | `ousast plane alerts-engine` runs it on the host, one container at a time, and marks the Run's `alerts` tasks done | **an `engine` task on a second, larger `WorkerPool`** (the engine does not fit a 1.5 GiB worker, and k3s has no Docker socket), from an engine image digest-pinned in GHCR, emitting the same `alerts.jsonl` rows and coverage; `alerts-engine` on the host stays as the development path |

The S3 memory store (RustFS tested) is already external. In remote mode it is also the artifact path.
So the CLI's host must reach it, and the workers must reach it through the egress gateway.

### Scaling the pre-push hook in production

**Today** `ousast pre-push` is a local, deterministic check. It does four things:

1. materialises base and head;
2. finds the changed regions;
3. runs the evidence ranker and arbiter on head;
4. compares the result with base.

All of this runs within `--deadline` (30 s by default). It runs in `--mode advisory` unless you opt
into blocking. See [Pre-push: the delta check](scanning.md#pre-push-the-delta-check-experimental),
`src/openultrasast/push/` and [Engine and pre-push](ops/README.md#experimental-pre-push-integration).

**The plane is not in that path.**

- No hook submits a Run.
- No model is called without an explicit `--model-config`.
- Nothing leaves the developer's machine.

**The production shape** (planned, none of it built) splits the work by latency:

1. **Blocking, inside the hook's deadline**: what runs today, the quick rules and the delta engine on
   the changed regions. It stays local and deterministic. So the push never waits for a model or a
   cluster.
2. **Asynchronous, on the plane**: the hook or the CI job calls the CLI in remote mode with a *delta
   Run*.
    - The Run's candidates are the functions the push changed.
    - The Run is the per-case chain of [The plane on ax](plane.md#per-case): `facts`, `verify` a and b,
      `agree`, `verify` c on the disputed only, `final`.
    - The caller can wait, with its own deadline, for the CLI to print the status and attribution table.
    - Or the caller returns at once, and a later `ousast plane status <run>` reports from the store.
    - A commit status check or a review comment would be built on that.
    - The worker pool is sized to the push rate, or autoscaled on `at_capacity` workers.
    - An unattended in-cluster reconciler that accepts submissions without a CLI session is the later
      option named above.

**Cost per push, estimated from measured rates.** Two measured per-candidate rates exist for one model
verdict:

- `$0.003215` (`spend.cost_per_candidate_evaluate_usd` in
  `benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json`);
- `$0.0021` (exp-002 arm A, `overall.usd_per_candidate.A` in
  `benchmarks/measurements/2026-10-02-exp-002/record.json`).

A push that changes five functions needs two verify passes per candidate. That gives 5 x 2 x $0.0021 =
$0.021, or 5 x 2 x $0.003215 = $0.032 at the higher rate. A third pass runs on the disputed candidates
only. That is where "about two cents per push" comes from. It is arithmetic over the decision engine's
measured rates, not a measurement of a push Run. `ousast plane status` would print the real figure per
Task.

**What is not built** (each is a named gap, not a configuration):

- The delta-Run command. `ousast plane scan <repo> --base <commit> --head <commit>` **does not
  exist**. `ousast plane` has `run`, `status`, `doctor`, `remember`, `memory-normalise`,
  `workspaces`, `harvest` and `alerts-engine` (`src/openultrasast/cli.py`).
- A candidates task for an arbitrary repository. `repo-facts` takes its candidates from a
  population's validation set. No step derives them from a diff yet.
- Workspace generation from a URL and a commit outside a population. `plane/generate.py` is
  population-driven: `read_cases` reads a validation set and a population TOML. So a Run for a
  repository that is not in a population cannot be generated today.
- The remote execution mode itself:
    - the `local`/`remote` switch;
    - a configurable cluster context and ax-server and router addresses (the `kind-` prefix is
      hard-coded, B.4);
    - presigned delivery from the runner to the store;
    - the CLI reading completion and `summary.json` from the store instead of its receiver thread.
- The engine task and its WorkerPool, the GHCR build, the production pool and autoscaling
  manifests, and the k3s runbook and checklist.
- The check or comment that carries the asynchronous verdict back to the push.

### Sizing

The worker is the unit. Every Task's `limits` fit the 1 CPU / 1.5 GiB worker of
`ops/ax/workerpool.yaml.tmpl`. The requests are what the Task declares. The worker is what it occupies.

| Task (`plane/tasks/*.yaml`) | Requests | Limits | Per push |
| --- | --- | --- | --- |
| `repo-facts` | 250m / 512Mi | 1 CPU / 1280Mi | 1 (`facts`) |
| `verify` | 250m / 384Mi | 1 CPU / 1Gi | 2 (`va`, `vb`), plus 1 (`vc`) on disputed candidates |
| `agree` | 100m / 256Mi | 1 CPU / 512Mi | 1 (`agree`; `final` reuses it after `vc`) |
| `features`, `remember` | 250m / 512Mi; 100m / 256Mi | 1 CPU / 1Gi; 1 CPU / 512Mi | optional, for the decision engine and the memory |
| `alerts`, `loop` | 250m / 512Mi | 1 CPU / 1280Mi | not in a push Run (loop Runs only) |
| `roles` | 250m / 384Mi | 1 CPU / 1Gi | not in a push Run (harvest Runs only) |
| `engine` (planned) | from a measured run | above 3 GiB (the host run uses `--memory 3g`) | its own pool, not the default one |

- **Actors per push**: 4 (`facts`, `va`, `vb`, `agree`), or 6 with a tie-break (`vc`, `final`).
  `features` and `remember` add two more when the verdict is to be kept.
- **Critical path**: `facts`, then `va` and `vb` side by side, then `agree`, then sometimes `vc`
  and `final`. That is three to five Task boots in series. Each boot is a golden-snapshot restore plus
  the model calls of the verify passes.
- **One actor per worker**: `agree` asks for 256Mi but still holds a 1.5 GiB worker while it runs. The
  worker's capacity, not the Task's request, is the unit.
    - A pool of `W` workers runs at most `W/2` pushes through their verify phase at once.
    - On this host (`W = 2`) that is one push at a time.
    - Every further push waits, on the reconciler's `--workers` bound or on Substrate's request parking
      if the pool is saturated.
    - Autoscaling the pool on `at_capacity` workers is the upstream answer. It is **planned** here.

## C. The manifests under `plane/`

| Path | Moves unchanged? | What changes |
| --- | --- | --- |
| `plane/models/*.yaml` | yes | nothing: provider, prices, `secretKey` variable names and `openultrasast.io/egress-hosts` are cluster-independent |
| `plane/tasks/*.yaml` (templates) | no | only the `image` reference: `<your registry>/ousast-runner@sha256:<digest>` (B.3); resources stay unless the pool is sized differently |
| `plane/tasks/validation-46.yaml`, `plane/runs/*.yaml` | regenerate | generated by `ousast plane workspaces --validation-set ... --runner-image FILE`; the Run spec itself (steps, inputs, outputs, budgets) is cluster-independent |
| `plane/workspaces/*.yaml` | yes | nothing: Git sources at pinned commits; their hosts enter each task's EgressPolicy automatically; inline `files` stay under the ~20 KB limit the actor template tolerates |
| `plane/Dockerfile.runner` | yes | nothing; build from the repository root and push to your registry |
| `ops/ax/receiver-service.yaml.tmpl` | no | the endpoint address (B.5, path 1), or replaced by an in-cluster receiver (path 2) |
| `ops/ax/workerpool.yaml.tmpl` | no | replicas and limits (B.6) |
| `ops/ax/smoke-task.yaml.tmpl`, `smoke-run.yaml.tmpl` | yes | rendered with `RUNNER_IMAGE` from your pin file |
| `ops/ax/up.sh`, `down.sh` | no | kind-specific; they do not apply to another cluster |

The Run and Task contract does not depend on where the cluster is. That contract covers:

- `plane/runner.py` as PID 1 of the runner image;
- `AX_TASK_YAML` and `AX_WORKSPACES_YAML`;
- `/healthz` and `/readyz`;
- the start request;
- the tar delivery as completion.

See [The plane on ax](plane.md).
