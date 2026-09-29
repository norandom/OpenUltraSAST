# Requirements Document

## Introduction

The model-driven pipeline (classify sinks, triage, verify, judge, recheck, score) is a set of scripts run from
one long conversation, each with its own resume, budget and pass logic. Measured 2026-09-29: 90% of development
tokens are tool I/O around those scripts, and verification re-derives the same per-repository facts in every
hunt and every pass. This feature restructures the pipeline as a Kubernetes-style service plane at the model
level, in the shape of google/ax: declarative `Task`, `Workspace` and `Model` manifests, a reconciler that
executes them in isolation with resume, and a runner contract. ax's software (Kubernetes, Agent Substrate) is a
later deployment target; its design is adopted now (`brief.md`).

## Boundary Context

- **In scope**: the manifest kinds and a `Run` kind for dependencies, artifacts and budgets; a local reconciler
  for this host (one engine container at a time); the runner contract; the first two tasks, `repo-facts` and
  `verify`, with the existing scripts as reference behaviour; measurement on the 46-candidate validation set.
- **Out of scope**: running on ax or Kubernetes; changing what the model is asked (prompts, families, pass rules)
  except as required to consume `repo-facts`; the judge stage, the config-family question and population v3
  (they become tasks later, under their own specs); any change to `evaluate.py`'s protocol scoring.
- **Adjacent expectations**: the independent-population protocols and records stay as they are; `finding_dump`
  and the engine path are untouched; `vulnerabilities-over-plumbing` applies -- this is plumbing that must pay
  for itself in measured tokens and unchanged or better recall.

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

### Requirement 3: A local reconciler executes a Run on this host

**User Story:** As the maintainer, I want to run a whole pipeline with one command on the laptop, with the same
manifests a cluster would take.

#### Acceptance Criteria

1. The reconciler executes tasks in dependency order, at most one engine-bearing task at a time, and passes
   artifacts by path.
2. Task status (`pending`, `running`, `suspended`, `done`, `failed`, `unfinished`) is persisted and shown by
   one status command.
3. A suspended or interrupted run resumes from persisted status (Requirement 2.2) with the same command.
4. The reconciler is under 500 lines and holds no pipeline logic: no prompts, no scoring, no model calls.

### Requirement 4: The runner contract is ax's

**User Story:** As the maintainer, I want each task entrypoint to run unchanged inside an ax task container
later.

#### Acceptance Criteria

1. An entrypoint receives its task and workspace manifests as YAML in `AX_TASK_YAML` and `AX_WORKSPACES_YAML`
   and takes nothing else from the command line except what the manifest's `command` states.
2. The default image serves `/healthz` and `/readyz` when run as a container; locally these may be no-ops.
3. One fixture test per task type runs the entrypoint against a small workspace and checks its artifacts.

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

1. `repo-facts` + `verify` run on the 46-candidate validation set through the reconciler, two passes, and
   report cost per candidate, tool turns per hunt and declared sites agreed.
2. Acceptance: declared sites agreed at least 16 of 20 (the current value) and cost per candidate below the
   current $0.022 for two passes; otherwise the increment is reported as not met and the design revisited.
3. The development transcript measure (`benchmarks/dev/token_report.py`) is run at the end of the increment and
   recorded next to the result.
