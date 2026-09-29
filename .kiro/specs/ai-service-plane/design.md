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
  doctor.py                      `ousast plane doctor`: the four checks of Requirement 3.5
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
`spec.files`, then runs `spec.command` as ax's runner contract requires (ax `docs/runner.md`,
`docs/sandbox.md`): a child process `python -m openultrasast.plane.tasks.<name> <args>` in its own process group,
with the first workspace as working directory and `AX_METADATA_URL` pointing at the runner's own server. It serves
`/healthz`, `/readyz` (503 until workspaces are ready; ax probes `/readyz?check=workspace`) and ax's two metadata
paths on port 80 (Requirement 4.2). Workspaces are prepared on the first boot only; `/workspace` survives suspend
and resume. After the child exits the runner reads `summary.json` (a crash without one becomes `failed` with the
exit code and stderr tail), delivers the output directory (Requirement 4.4), writes the completion marker
`/workspace/.ousast-state/<task>.done.json` (`exit`, `status`, `delivered`) and then keeps running as PID 1 until
SIGTERM: an exiting runner stops the container, which the first live run showed as every resume timing out. A
boot that finds the marker does not rerun the command (a resumed actor must not repeat billed work); a marker
with a failed delivery retries the delivery only. SIGTERM (ax's stop and suspend) is forwarded to the command's
process group, followed by SIGKILL after `OUSAST_TERM_GRACE` (10 s), and the runner exits 0.
`AX_RUNNER_EXIT_AFTER_COMMAND=1` is a unit-test escape that exits with the task's code after delivery.

The command never starts by itself (Requirements 4.5, 4.6). Once the workspaces are ready the runner serves
`POST /ousast/v1/start` on port 80 with the body `{"run", "task", "credentials"}`: 503 before the workspaces are
ready (the reconciler retries), 409 when `run`/`task` differ from `OUSAST_RUN` and the Task's name, 409 for a
second request on the same boot, 409 with the reason when the completion marker records a delivered run, 400 for
a malformed body or a credential name outside `^[A-Z][A-Z0-9_]*$` (or under `AX_`/`OUSAST_`), and 202 once.
Only then does the command run -- or, when the marker records a failed delivery, only the delivery is retried; a
runner failure (bad manifests, a workspace that cannot be materialised) is likewise delivered only after a start,
or refused with its reason. The credentials stay in the runner's memory and are merged into the child's
environment only; they are never logged or written, and their values are redacted from the child's echoed
stderr and the stderr tail a crash summary keeps. `AX_RUNNER_AUTOSTART=1` (unit tests only; required with
`AX_RUNNER_HTTP=0`) starts without a request.

**Golden snapshot.** Agent Substrate boots every new ActorTemplate once as a temporary "golden" actor (atespace
`ate-golden`, a UUID name) to capture a snapshot. ax bakes `AX_TASK_YAML`, `AX_WORKSPACES_YAML` and `spec.env`
into the template, and inside the sandbox the hostname is always `actor` with no identity variable, so the golden
boot and the real one are indistinguishable from within (observed on the live cluster, 2026-09-29: the command
ran in both). The distinction exists only outside: Substrate's router (`svc/atenet-router` in `ate-system`)
routes on `ate-target-actor: <atespace>/<name>` to the task's actor, resuming it if suspended, and never to the
golden one. Hence the start request, and hence credentials only in it: a template, a rendered Task or an ax
manifest is visible to the golden boot and to anyone who can read the cluster's objects.

### Reconciler (`reconciler.py`, ax-backed)

`ousast plane run <Run.yaml>`, `ousast plane status <run>` and `ousast plane doctor`. State: `state.json` with
per-task status in `pending | running | suspended | done | failed | unfinished`, timestamps, spend. Execution:
topological order; for each ready task the reconciler renders the Task manifest with the run's env
(`OUSAST_BUDGET_*`, `OUSAST_INPUT_*`, `OUSAST_OUTPUT_DIR`, `OUSAST_ARTIFACT_URL`), applies it and its
Workspaces through the `ax` CLI (`ax apply`, `ax resume`, `ax get`, `ax delete`; the CLI path is injectable so
tests use a fake). ax creates a Task `Suspended`; it runs only after `ax resume task`, and the first resume of a
new image can fail with `DeadlineExceeded` while Agent Substrate builds its golden snapshot (ax then reports
`Failed`), so the reconciler retries a DeadlineExceeded/Unavailable resume with backoff for up to
`OUSAST_RESUME_TIMEOUT` (900 s). ax has no Completed phase and never reports that a command exited: completion is
the artifact delivery. `Failed` after a resume went through, or the task disappearing, before delivery fails the
task with ax's condition message; no delivery within `OUSAST_TASK_TIMEOUT` (7200 s) fails it too; `ax delete task`
follows either way. Artifacts: the reconciler serves a small HTTP receiver on the host (reachable from kind pods
via the docker bridge); the runner posts the output directory there after its command exits. Tasks sharing a
`serialize` label never overlap; everything else may run in parallel up to `--workers`. A task's outcome is
read from its delivered `summary.json`: `done` only when the task says every unit finished; `unfinished` on a
budget stop; `failed` on an account or authentication error, a crash, or a missing delivery. `status` prints
the token attribution table (Requirement 7.3) from the delivered summaries and writes `attribution.json`. On rerun, `done` tasks are skipped and
the others re-executed; per-unit resume is the task's own duty (Requirement 2.2). No prompts, scoring or model
calls anywhere in this module; a test counts its lines.

Start (Requirements 4.5, 4.6; `router.py`, kept out of the reconciler's line budget): for the whole run the
reconciler holds one `kubectl --context kind-ousast -n ate-system port-forward svc/atenet-router :80` (random local
port read from kubectl's `Forwarding from 127.0.0.1:NNNN`; the child is terminated when the run ends;
`OUSAST_ROUTER_URL` replaces it, as in the tests). When ax reports `Running` after an accepted resume -- again
after a re-resume of a suspended task, where an "already started on this boot" answer means the command
survived and still runs -- it posts the start body with `ate-target-actor: <atespace>/<task>`,
retrying 502/503/504 and connection errors with backoff up to `OUSAST_START_TIMEOUT` (300 s); a 409 or the timeout
fails the task with the response text unless it already delivered. Credentials come from the Model binding: the
bound Model's `spec.secretKey.key` names the variable (`DEEPSEEK_API_KEY` for `deepseek-flash`), read from the
reconciler's own environment (`ousast` loads `.env` at startup); a Model-bound task whose variable is unset fails
before `ax apply`, and a task without a Model gets none. The value is never rendered, logged or written.

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
The rule is reproduced in the package (`agree.matches_declared`, parity-tested against `matches_v2` on the recorded
reference outputs) and the generator writes the fix ranges it matches against into each case's `case.json`, so
the runner image carries no benchmark tree.

**Measurement.** Requirement 6.2's cost is judged on `cost_per_candidate_with_recorded_triage`: the plane's two
verify passes plus the recorded triage cost of the case, over the candidates before triage, summed across the run.
The reference's $0.022 (`verifier-batched-check-2026-09-29.json`) paid for per-file triage and the hunts while the
plane applies the recorded triage without a model call, so `cost_per_candidate` (plane spend alone) is reported but
not judged; the triage share is derived per file from the recorded spend minus the priced hunt usage (about $0.087
of the $1.01) and labelled as derived in `case.json`. Sites are judged as `declared_sites_matched_agreed` against
`declared_sites_in_set`, the reference's 16 of 20.

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
- `tests/test_plane_reconciler.py`: a fake `ax` CLI with ax's real lifecycle (apply -> `Suspended`, a first
  resume failing DeadlineExceeded, then `Running` forever, and a scripted `summary.json` delivery only after a
  resume went through) drives a DAG: order, `serialize` non-overlap, skip-on-rerun, `unfinished` and `failed`
  propagation, resume retry and timeout, `Failed` with a condition message, a vanished task, the task timeout
  without delivery, the lock, the attribution table; a
  test asserts the module is under 500 lines. `tests/test_plane_ax_live.py` (marker `ax`, skipped unless
  `ousast plane doctor` passes) applies one trivial Task on the real cluster.
- `tests/test_plane_runner.py`: the env contract on a fixture workspace; `/readyz` 503 then 200; the command as a
  child in its own group in the first workspace; the runner serving on after the command; SIGTERM reaching the
  command's group; the completion marker preventing a rerun and retrying a failed delivery alone.
- `tests/test_plane_repo_facts.py`: a three-file tree; callers found across files, none from tests or vendor;
  identical output on a second run.
- `tests/test_plane_verify.py`: a scripted client; the prompt carries the callers; `units.jsonl` resume asks
  only the unfinished file; a scripted 402 yields `failed`.
- Measurement (Requirement 6): `plane/runs/validation-46.yaml` executed twice (passes a and b); the result
  compared with `verifier-batched-check-2026-09-29.json` and recorded in `benchmarks/independent/`, with the
  transcript measure of the increment's development session next to it.
