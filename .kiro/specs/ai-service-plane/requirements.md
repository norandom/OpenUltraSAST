# Requirements Document

## Introduction

The model-driven pipeline (classify sinks, triage, verify, judge, recheck, score) is a set of scripts run from
one long conversation, each with its own resume, budget and pass logic. Measured 2026-09-29: 90% of development
tokens are tool I/O around those scripts, and verification re-derives the same per-repository facts in every
hunt and every pass. This feature restructures the pipeline as a Kubernetes-style service plane at the model
level, in the shape of google/ax: declarative `Task`, `Workspace` and `Model` manifests, a reconciler that
executes them in isolation with resume, and a runner contract. The plane runs on ax itself: a `kind` cluster
with Agent Substrate and the ax controller on this host (maintainer decision 2026-09-29: "switch to ax
completely now"). What ax does not yet carry -- task dependencies, artifacts, token budgets (on ax's roadmap),
a DeepSeek provider -- is carried by our thin `Run` layer and dissolves into ax as ax gains it.

## Boundary Context

- **In scope**: the manifest kinds and a `Run` kind for dependencies, artifacts and budgets; bring-up of ax on
  this host (kind + Agent Substrate + ax controller) with a doctor command; an ax-backed reconciler that
  submits Tasks to ax (one engine-bearing task at a time) and is the only executor; the runner contract and a
  runner image; the first two tasks, `repo-facts` and
  `verify`, with the existing scripts as reference behaviour; measurement on the 46-candidate validation set.
- **Out of scope**: a remote or multi-node cluster; contributing providers or budgets to ax upstream (a
  follow-on once the increment is measured); changing what the model is asked (prompts, families, pass rules)
  except as required to consume `repo-facts`; the judge stage, the config-family question and population v3
  (they become tasks later, under their own specs); any change to `evaluate.py`'s protocol scoring.
- **Adjacent expectations**: the independent-population protocols and records stay as they are; `finding_dump`
  and the engine path are untouched; `vulnerabilities-over-plumbing` applies -- this is plumbing that must pay
  for itself in measured tokens and unchanged or better recall.
- **Target state (maintainer, 2026-09-29)**: this plane replaces HarnessX as the agentic plane; HarnessX is
  removed by its own spec (`harnessx-removal`) once Requirement 6's measurement shows value; the `Run` layer
  shrinks as ax gains dependencies, budgets and artifacts. No new HarnessX feature is added meanwhile.

## Requirements

### Requirement 1: Manifests are ax's kinds plus a Run kind

**User Story:** As the maintainer, I want the pipeline declared in manifests that ax would accept, so that
moving to a cluster later changes the reconciler and not the pipeline.

#### Acceptance Criteria

1. `Task`, `Workspace` and `Model` manifests use `apiVersion: ax.io/v1alpha1` and only fields ax documents
   (`spec.image`, `spec.command`, `spec.env`, `spec.resources`, `spec.workspaces`; `spec.git`, `spec.files`;
   `spec.provider`, `spec.model`, `spec.secretKey`, `spec.parameters`).
2. A `Run` manifest (our kind) lists tasks with `dependsOn`, the artifacts each task produces and consumes, and a
   per-task budget (`usd`, `calls`); it contains nothing a task needs to execute.
3. A manifest that violates its schema is rejected before anything runs, with the field named.
4. A DeepSeek model is expressed as a `Model` with a provider adapter noted in the manifest; no ax field is
   repurposed to carry it.

### Requirement 2: A task is isolated, idempotent and resumable

**User Story:** As the maintainer, I want a stopped or failed run to resume without repeating finished work and
without ever recording partial work as a result.

#### Acceptance Criteria

1. A task reads only its declared inputs and the bound workspace, and writes only its declared artifacts.
2. Work is recorded per unit (file, candidate) as it completes; a restarted task skips completed units and
   repeats unverified ones.
3. A task whose model calls fail on account or authentication errors stops at once with a distinct status;
   its artifacts are marked unfinished, never complete.
4. A task's spend is metered from the provider's usage fields and stops the task at its budget; a task with no
   priced model reports "unpriced", not zero.

### Requirement 3: An ax-backed reconciler executes a Run on this host's ax

**User Story:** As the maintainer, I want to run a whole pipeline with one command on the laptop, with every
task executed by ax on the local cluster, so that the same manifests move to a bigger cluster unchanged.

#### Acceptance Criteria

1. The reconciler submits each task to ax as a `Task` (with its bound `Workspace`s and `Model`) in dependency
   order, at most one engine-bearing task at a time, reads task outcome from ax's status plus the task's
   delivered `summary.json`, and passes artifacts between tasks by placing a producer's outputs where the
   consumer's manifest expects them. It never executes a task as a local subprocess; ax is the only executor.
2. Task status (`pending`, `running`, `suspended`, `done`, `failed`, `unfinished`) is persisted and shown by
   one status command.
3. A suspended or interrupted run resumes from persisted status (Requirement 2.2) with the same command.
4. The reconciler is under 500 lines and holds no pipeline logic: no prompts, no scoring, no model calls.
5. `ousast plane doctor` verifies the host's ax in one command: kind cluster reachable, Agent Substrate control
   API up, ax controller ready, runner image loaded; each check names what is missing and how to bring it up.
6. Bring-up on this host (kind + Agent Substrate + ax) is scripted, documented with its measured memory and
   CPU footprint, and smoke-tested with one trivial Task before any pipeline task runs.

### Requirement 4: The runner contract is ax's

**User Story:** As the maintainer, I want each task entrypoint to run unchanged inside an ax task container
later.

#### Acceptance Criteria

1. An entrypoint receives its task and workspace manifests as YAML in `AX_TASK_YAML` and `AX_WORKSPACES_YAML`
   and takes nothing else from the command line except what the manifest's `command` states.
2. The runner image serves `/healthz` and `/readyz` on port 80, `/readyz` returning 503 until workspaces are
   materialised, as ax's runner contract requires; the image contains this package and is loaded into kind.
3. One fixture test per task type runs the entrypoint against a small workspace and checks its artifacts.
4. Because ax has no artifact channel, the runner delivers the task's output directory (including
   `summary.json` and `units.jsonl`) to the reconciler's artifact endpoint named in `OUSAST_ARTIFACT_URL`
   before it reports completion; a delivery failure is reported as `failed`, never as done.
5. The command never runs in Agent Substrate's golden-snapshot boot, which executes the same image with the same
   task environment (observed on the live cluster, 2026-09-29): the runner prepares workspaces, reports ready and
   waits; the reconciler starts the command with one request to the task's actor through Substrate's router
   (`ate-target-actor: <atespace>/<task>`), which never addresses the golden actor. A second start request for
   the same task is refused.
6. Provider credentials reach a task only in that start request, held in the runner's memory and passed to the
   command's environment; they never appear in a manifest, a rendered Task, an ax template or any file.

### Requirement 5: `repo-facts` is the memory layer

**User Story:** As the maintainer, I want per-repository facts computed once and reused by every hunt and pass,
so that verification stops paying tool turns for the same lookups.

#### Acceptance Criteria

1. `repo-facts` produces, without model calls, per product file: the functions defined, and for each candidate
   function the call sites in other product files (path and line) -- from source text only, never from git.
2. The artifact is deterministic for a given workspace and is reused across tasks and passes unchanged.
3. `verify` includes each candidate's callers from `repo-facts` in its prompt and reports the number of tool
   turns per hunt.

### Requirement 6: The first increment is measured before the rest moves

**User Story:** As the maintainer, I want proof that the restructuring saves tokens without losing recall
before the remaining concerns are converted.

#### Acceptance Criteria

1. `repo-facts` + `verify` run on the 46-candidate validation set through the reconciler on ax, two passes, and
   report cost per candidate, tool turns per hunt and declared sites agreed.
2. Acceptance: declared sites agreed at least 16 of 20 (the current value) and cost per candidate below the
   current $0.022 for two passes; otherwise the increment is reported as not met and the design revisited.
3. The development transcript measure (`benchmarks/dev/token_report.py`) is run at the end of the increment and
   recorded next to the result.

### Requirement 7: Routing is a declared concern of the plane

**User Story:** As the maintainer, I want which model serves which concern to be a manifest decision with a
budget, not a prompt trick inside one conversation, so that token spend is structured by component.

#### Acceptance Criteria

1. Every `Task` in a `Run` binds exactly one `Model`; a Run may bind different Models to different tasks
   (a cheap model for reads and triage, a stronger one for verification and judgement), and the reconciler
   passes the bound Model's identity and prices to the task.
2. A task never chooses or switches its model at runtime; the Model it was bound to is recorded in its
   `summary.json`.
3. `ousast plane status <run>` prints a token attribution table: one row per task and Model binding with
   calls, input tokens, cache-hit tokens, output tokens and USD, a total row, and a per-Model subtotal; every
   number comes from the provider's usage fields recorded in the tasks' `summary.json`, never estimated. A
   `--units` flag breaks a task down per unit (file or candidate) from `units.jsonl`. The same table is
   written to `attribution.json` in the run directory so runs can be compared.
4. A task that needs a second model for a sub-step (a judge over a verifier's output) is a separate task with
   its own Model binding, never a second client inside one task.
