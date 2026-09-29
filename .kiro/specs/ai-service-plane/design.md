# Design Document

## Overview

A thin service plane under `src/openultrasast/plane/`: manifest schemas in ax's shape plus a `Run` kind, an
ax-backed reconciler that submits a Run's tasks to ax on this host's kind cluster in dependency order with
persisted status and resume, a runner that honours ax's contract and delivers artifacts, and task entrypoints.
ax (with Agent Substrate) is the only executor; there is no local subprocess path. The pipeline's logic lives only in the task entrypoints; the
reconciler and runner know nothing about prompts, models or scoring (Requirement 3.4). The first increment moves
`repo-facts` and `verify` (plus a model-free `agree` step) and measures them on the 46-candidate set
(Requirement 6); the other concerns stay as scripts until that measurement is recorded.

## Architecture

```
plane/                         manifests (YAML), checked in
  models/deepseek-flash.yaml     Model
  workspaces/<case>-<pin>.yaml   Workspace, generated from population-v2.toml by `ousast plane workspaces`
  tasks/repo-facts.yaml          Task
  tasks/verify.yaml              Task
  runs/validation-46.yaml        Run: DAG, artifacts, budgets
src/openultrasast/plane/
  manifests.py                   load + validate Task / Workspace / Model / Run (PyYAML, declared dependency)
  reconciler.py                  Run execution, status, resume  (<= 500 lines, test-enforced)
  runner.py                      ax runner contract: AX_TASK_YAML / AX_WORKSPACES_YAML -> entrypoint
  budget.py                      spend and call metering from provider usage fields
  tasks/repo_facts.py            source-only facts artifact
  tasks/verify.py                one hunt per file with facts in the prompt; per-unit resume
  tasks/agree.py                 pass agreement, no model
~/ousast-results/plane/<run>/    state.json + one directory per task with summary.json and artifacts
```

Locally the reconciler runs a task as a subprocess of the same interpreter with the ax environment set; in a
container the same module is PID 1 (`ax-task-runner`), built as a target of the root `Dockerfile` that extends
`openultrasast:dev`. Nothing in a task depends on which of the two started it.

## Components and Interfaces

### Manifests (`manifests.py`)

- `Task`, `Workspace`, `Model`: `apiVersion: ax.io/v1alpha1`, fields exactly as ax documents; unknown fields
  are rejected with the path named. `Model.spec.provider` accepts ax's `google` and `anthropic`, and `deepseek`
  only when `metadata.annotations["openultrasast.io/provider-extension"] == "true"` (Requirement 1.4): the
  deviation is declared, not hidden in another field.
- Field names are ax's verbatim (`ax.proto`; its API server decodes with `protojson`, so an unknown field fails
  `ax apply`): `metadata` is `name` and `atespace` (not `namespace`), and a Workspace `git` entry is `name`,
  `repo`, `branch`, `dir`, `depth` (no `commit`; a `commit` there is rejected with a pointer to the annotation).
  `metadata.annotations` is this project's only extension, and nothing under it reaches ax: the reconciler strips
  it and carries it to the task as env. The Model binding (`openultrasast.io/model`) becomes `OUSAST_MODEL` and
  `OUSAST_MODEL_PARAMS`. Commit pins (`openultrasast.io/git-commits: "<git name>=<40-hex sha>,..."` on a
  Workspace) become `OUSAST_GIT_PINS` = `{"<workspace>/<git name>": "<sha>"}`, which the runner checks out after
  fetching the way ax's `internal/workspace/setup.go` does, with the same `dir` and `depth` rules.
- `Run`: `apiVersion: openultrasast.io/v1alpha1`. `spec.tasks[]`: `name`, `task` (a Task manifest name),
  `dependsOn[]`, `inputs{name: "<task>/<artifact>"}`, `outputs[]`, `budget{usd, calls}`, `serialize` (a label
  for tasks that must not overlap; engine-bearing tasks carry `engine`). The reconciler passes budgets and
  artifact paths to a task as `env` entries (`OUSAST_BUDGET_USD`, `OUSAST_BUDGET_CALLS`, `OUSAST_INPUT_<NAME>`,
  `OUSAST_OUTPUT_DIR`), which is ax's own mechanism for task configuration, so a Run never adds a field to a
  Task.

### Runner (`runner.py`)

Reads `AX_TASK_YAML` and `AX_WORKSPACES_YAML`, materialises each workspace's `git` entries at the pinned commit
into the bound path (locally a `git archive` from the case cache, as `evaluate.export` does today), writes
`spec.files`, then executes `spec.command`, whose first element names a task module
(`openultrasast.plane.tasks.<name>`). With `AX_RUNNER_HTTP=1` it serves `/healthz` and `/readyz` (503 until
workspaces are ready) on port 80 in a thread; locally the flag is unset (Requirement 4.2).

### Reconciler (`reconciler.py`, ax-backed)

`ousast plane run <Run.yaml>`, `ousast plane status <run>` and `ousast plane doctor`. State: `state.json` with
per-task status in `pending | running | suspended | done | failed | unfinished`, timestamps, spend. Execution:
topological order; for each ready task the reconciler renders the Task manifest with the run's env
(`OUSAST_BUDGET_*`, `OUSAST_INPUT_*`, `OUSAST_OUTPUT_DIR`, `OUSAST_ARTIFACT_URL`), applies it and its
Workspaces through the `ax` CLI (`ax apply`, `ax get`, `ax delete`; the CLI path is injectable so tests use a
fake), and polls ax's status. Artifacts: the reconciler serves a small HTTP receiver on the host (reachable from
kind pods via the node's host gateway); the runner posts the output directory there at exit. Tasks sharing a
`serialize` label never overlap; everything else may run in parallel up to `--workers`. A task's outcome is
read from its delivered `summary.json`: `done` only when the task says every unit finished; `unfinished` on a
budget stop; `failed` on an account or authentication error, a crash, or a missing delivery. `status` prints
the token attribution table (Requirement 7.3) from the delivered summaries and writes `attribution.json`. On rerun, `done` tasks are skipped and
the others re-executed; per-unit resume is the task's own duty (Requirement 2.2). No prompts, scoring or model
calls anywhere in this module; a test counts its lines.

### Budget (`budget.py`)

Wraps a chat client: sums the provider's usage fields per call (`prompt_tokens`, `prompt_cache_hit_tokens`,
`completion_tokens`), prices them from the Model's parameters, raises `BudgetExhausted` at the ceiling and
`AccountError` on 401/402 or an "insufficient balance" body. A model without prices makes the meter report
`unpriced` and refuse to run under a `usd` budget (Requirement 2.4).

### Task contract (all tasks)

Inputs from `OUSAST_INPUT_*` paths and the bound workspace only; outputs under `OUSAST_OUTPUT_DIR`; progress in a
`units.jsonl` appended per finished unit and read back on start; `summary.json` written last with
`status`, `units_done`, `units_total`, `usd`, `calls`, `usage`. A task never writes `summary.json` with
`status: done` unless `units_done == units_total`.

### `repo-facts` (`tasks/repo_facts.py`)

Source only, no model. For every product file (the `enumerate_source_files` + product filter of
`model_sinks.py`): the functions it defines (the per-language declaration patterns of `sink_candidates.py`),
and for each function name in the candidate list (input `candidates.json`) the call sites in other product
files: `path`, `line`, the enclosing function, capped at 40 per name. Output `facts.json`, keyed by file,
sorted, deterministic for a workspace (Requirement 5.2).

### `verify` (`tasks/verify.py`)

The hunt of `verify_batched.py` (system prompt, one hunt per file, up to 6 candidates, 6 steps, candidate-
anchored sites) moved into the package, with two changes: the prompt lists each candidate's known call sites
from `facts.json` ("Known callers: a.py:12 in handler(), ..."), and each hunt records its tool turns and usage
in `units.jsonl`. `pass` is an env value from the Run, so two passes are two task instances with distinct output
directories. Candidates and triage come from the existing `independent-v2-modelsinks` and batched-check
artifacts for the increment; the `classify` and `triage` tasks are later specs.

### `agree` (`tasks/agree.py`)

Reads the pass outputs, emits `agreed.json` and `disputed.json` by the same rule as `verify_batched.agreement`,
plus the per-candidate cost, turns and the declared-site match (`evaluate.matches_v2`) for the measurement.

## Data Models

- `facts.json`: `{ "<path>": { "functions": ["name", ...], "callers": { "<fn>": [ {"path", "line", "in"} ] } } }`
- `units.jsonl` (verify): one row per file hunt: `{"path", "candidates", "flagged": [...], "turns", "usage",
  "usd"}`; rows with `"error"` are re-asked on resume.
- `summary.json`: `{"status", "units_done", "units_total", "usd", "calls", "usage", "reason"?}`
- `state.json` (run): `{"run", "started", "tasks": {"<name>": {"status", "started", "finished", "usd"}}}`

## Error Handling

- Manifest errors stop before any task starts, naming the manifest, field and rule.
- `AccountError` inside a task: the task writes `summary.json` with `status: failed` and the provider's
  message, exits 2; the reconciler marks the run `failed` and starts nothing further (Requirement 2.3).
- `BudgetExhausted`: `status: unfinished`, exit 3; dependants are not started; a rerun with a larger budget
  continues from `units.jsonl`.
- A crash: `failed`, traceback in `summary.json`; `units.jsonl` is still valid for resume.
- Two runs of the same Run name never share a directory: the reconciler refuses to start a second run while one
  is `running` (a lock file with the PID), which also keeps engine tasks to one at a time on this host.

## Testing Strategy

- `tests/test_plane_manifests.py`: valid ax manifests load; an unknown field, a bad provider without the
  annotation, and a Run with a cycle are rejected with the field named.
- `tests/test_plane_reconciler.py`: a fake `ax` CLI (a script recording `apply`/`get`/`delete` calls and
  posting scripted `summary.json` deliveries to the receiver) drives a DAG: order, `serialize` non-overlap,
  skip-on-rerun, `unfinished` and `failed` propagation, missing delivery, the lock, the attribution table; a
  test asserts the module is under 500 lines. `tests/test_plane_ax_live.py` (marker `ax`, skipped unless
  `ousast plane doctor` passes) applies one trivial Task on the real cluster.
- `tests/test_plane_runner.py`: the env contract on a fixture workspace; `/readyz` 503 then 200 with the flag.
- `tests/test_plane_repo_facts.py`: a three-file tree; callers found across files, none from tests or vendor;
  identical output on a second run.
- `tests/test_plane_verify.py`: a scripted client; the prompt carries the callers; `units.jsonl` resume asks
  only the unfinished file; a scripted 402 yields `failed`.
- Measurement (Requirement 6): `plane/runs/validation-46.yaml` executed twice (passes a and b); the result
  compared with `verifier-batched-check-2026-09-29.json` and recorded in `benchmarks/independent/`, with the
  transcript measure of the increment's development session next to it.
