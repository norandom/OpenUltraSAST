# Requirements Document

## Introduction

The plane moves from this laptop's kind cluster to a Kubernetes cluster of the maintainer's choosing without
changing what runs: the same ax manifests, runner image, memory store and credential path. Every host-bound
piece becomes a cluster resource or a configuration value, each change is proven on kind first, and the
production entry point (a delta Run for a push) is added. Context: `brief.md`, `docs/deployment.md`.

## Boundary Context

- **In scope**: two profiles of one code base, `kind` (local, kept) and `k3s` (production); a remote execution mode of the CLI; artifacts delivered to the store; configurable
  cluster context, registry and image pins; our own snapshot and memory buckets; the Joern engine as a plane task
  on a larger worker pool; worker pool sizing and autoscaling; a delta Run command and Workspaces from URL +
  commit; a deployment runbook with a proof on kind and a checklist for the target cluster.
- **Out of scope**: provisioning or operating the target cluster; modifying Agent Substrate or ax; any change to
  detection, scoring, populations or the decision engine; replacing the `ax` CLI with a bespoke client beyond what
  remote submission needs.
- **Adjacent expectations**: `ai-service-plane` requirements (one Model + budget per task, attribution,
  credentials only in the start request, egress policies, verify-at-startup memory store) keep holding;
  `harnessx-removal` Req 6 (memory on the S3 store) keeps holding; nothing is deleted before its replacement
  passes its test (the `harnessx-removal` sequencing rule).

## Target Environment (maintainer, 2026-10-02)

- **Cluster: k3s.** Consequences: containerd (no Docker socket; the engine's host-Docker path does not exist there),
  gVisor needs `runsc` and a `RuntimeClass` installed on the nodes Substrate's workers run on, k3s ships Traefik
  and local-path storage, and single-node k3s is close enough to kind that the kind proof transfers.
- **Images and source: GitHub.** Images are published to GitHub Container Registry (`ghcr.io/norandom/...`),
  built by GitHub Actions from tagged commits, digest-pinned in the manifests; private packages need an
  `imagePullSecret` on the worker ServiceAccounts and the CI principal. Substrate's and ax's own images are built with
  `ko` from their checkouts and pushed to the same registry.

## Requirements

### Requirement 1: Nothing assumes this host

**User Story:** As the maintainer, I want every host-bound assumption replaced by a cluster resource or a
configuration value, so the plane runs the same on kind and on the target cluster.

#### Acceptance Criteria

1. The kube context, the registry (GHCR in production), the ax-server address, the router address, the receiver address and the
   snapshot and memory buckets are configuration (environment or one config file), with the kind values as the
   documented defaults for development; no module names `kind-ousast`, `localhost:5001` or `172.19.0.1`.
2. `ousast plane doctor` checks the configured cluster, not kind by name, and reports each configured address.
3. A test enumerates the source tree for host-only literals and fails on any.

### Requirement 2: The reconciler stays the CLI, with a remote execution mode

**User Story:** As the maintainer, I want to trigger the checks in the cluster from the CLI and get the results
fed back, so that remote execution is a mode of the same tool, not a separate service.

#### Acceptance Criteria

1. `ousast plane run` (and the later `ousast plane scan`) takes an execution mode, `local` or `remote`, from the
   profile or a flag; `remote` submits the Run to ax-server in the target cluster (over the cluster's ingress or a
   kubeconfig), `local` is today's kind path. The manifests, the memory-key seeding, the budgets and the
   attribution table are identical in both modes.
2. In remote mode the CLI needs no inbound path: it polls the memory store for task completion and artifacts and
   prints the same status, attribution table and verdicts; `ousast plane status <run>` reports a Run started
   earlier from any machine with the store credentials.
3. Provider and store credentials come from the caller's environment (a laptop `.env`, a CI secret), travel only
   in the start request, and never appear in a manifest, an ActorTemplate or a log.
4. The principal the CLI uses against the cluster has the least privilege the ax API needs and nothing against
   Agent Substrate directly; a test compares the rendered role with the calls the CLI makes.
5. kind stays a first-class local execution mode, not a stepping stone: `ousast plane run` from a laptop
   against the kind cluster keeps working with the development profile (same code, same manifests, local
   registry), and every release is proven on it before anything is applied to k3s.
6. An unattended in-cluster reconciler (a Deployment or Job that runs without a caller) is a later option, not
   part of this spec.

### Requirement 3: Artifacts land in the store, not on a host

**User Story:** As the maintainer, I want task artifacts delivered to the memory store so that no host has to
be reachable from the cluster.

#### Acceptance Criteria

1. Tasks deliver their artifacts to the S3 memory store (presigned URLs minted by the CLI and carried in the
   start request, or a scoped delivery credential; the design chooses one and states why) and the CLI reads
   completion from the store. The receiver thread and the kind gateway EndpointSlice remain only if the design
   shows the local profile needs them; one delivery path for both profiles is preferred.
2. Egress policies grant each task exactly the hosts it needs (the store's endpoint, git hosts, the bound
   Model's host) and nothing else; a test renders the policy for every committed Task.

### Requirement 4: The engine is a plane task

**User Story:** As the maintainer, I want Joern to run where the other tasks run, on a worker sized for it.

#### Acceptance Criteria

1. A second WorkerPool sized for the engine (memory and CPU from a measured run) exists alongside the default
   pool; an `engine` task module wraps today's host engine run and emits the same `alerts.jsonl` rows and
   coverage as `alerts-engine`.
2. The engine image is digest-pinned in the registry like the runner image; its size and pull time are recorded.
3. `alerts-engine` on the host remains available for development and is marked as such.

### Requirement 5: Sizing and autoscaling

**User Story:** As the maintainer, I want the pool to follow the load of pushes without manual resizing.

#### Acceptance Criteria

1. Worker pool replicas, limits and the autoscaling rule (Substrate's assigned-worker signal) are manifests under
   `ops/k8s/` with the kind values as a small profile and a documented production profile.
2. The runbook records the measured footprint per task type and the queueing consequence of one actor per
   worker.

### Requirement 6: A delta Run for a push

**User Story:** As a user with a repository the project has never seen, I want a push checked by the plane.

#### Acceptance Criteria

1. `ousast plane scan <repo-url> --base <commit> --head <commit>` generates Workspaces from the URL and commits,
   derives candidates from the changed functions (quick rules, inferred roles, repository facts), and submits a
   Run of facts, verify a/b, tie-break and agree with per-task budgets; a whole-repository mode is secondary.
2. Results are written to the memory store under the repository and head commit and reported with the
   attribution table; the decision engine's verdict is reported only when a model is adopted, else the plane's
   agreement (ai-service-plane Req 6 and learned-decision-engine Req 6 unchanged).
3. The latency split is explicit: a blocking pre-push carries quick rules and the delta engine within its
   deadline; plane verdicts arrive asynchronously.

### Requirement 7: Proven on kind, then documented for the target

**User Story:** As the maintainer, I want each step shown working on kind before I touch the real cluster.

#### Acceptance Criteria

1. Every requirement above is exercised end to end on the kind cluster (remote mode included, with the kind cluster as the remote target), with
   a recorded run under `benchmarks/measurements/`.
2. `docs/deployment.md` becomes the runbook: prerequisites for the target cluster (Substrate, ax, registry,
   buckets, Secrets, node requirements for gVisor workers), the profile switch, and a checklist whose every item
   maps to a requirement here; planned items are labelled planned until their run is recorded.
