# Implementation Plan

Order follows the dependency chain: manifests -> budget -> runner -> reconciler -> tasks -> increment run ->
measurement. Every task ships with its tests; a task is done when its tests pass in the host suite, ruff and
mypy are clean, and the commit is gated on pytest's own exit code. Script-level pipeline work stays paused.

- [ ] 1. Manifest schemas and validation
  - Add `pyyaml` as a declared dependency in `pyproject.toml`.
  - `src/openultrasast/plane/manifests.py`: dataclasses and loaders for `Task`, `Workspace`, `Model`
    (`ax.io/v1alpha1`, ax's fields only) and `Run` (`openultrasast.io/v1alpha1`: tasks, dependsOn, inputs,
    outputs, budget, serialize); reject unknown fields, a provider outside ax's two without the
    `openultrasast.io/provider-extension` annotation, and a Run with a cycle or an input naming no task.
  - `tests/test_plane_manifests.py`: valid manifests load; each rejection names the field.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [ ] 2. Budget metering
  - `src/openultrasast/plane/budget.py`: a client wrapper that sums provider usage per call, prices from the
    Model's parameters, raises `BudgetExhausted` at the ceiling and `AccountError` on 401/402 or an
    "insufficient balance" body; an unpriced model reports `unpriced` and refuses a `usd` budget.
  - Tests with a scripted client: ceiling stop, account error, unpriced refusal, cache-hit pricing.
  - _Requirements: 2.3, 2.4_

- [ ] 3. Runner contract
  - `src/openultrasast/plane/runner.py`: read `AX_TASK_YAML` / `AX_WORKSPACES_YAML`; materialise `git`
    entries at the pinned commit from the local case cache and write `spec.files`; execute `spec.command`
    by importing `openultrasast.plane.tasks.<name>`; optional `/healthz` `/readyz` server under
    `AX_RUNNER_HTTP=1`; exit codes 0 done, 2 failed, 3 unfinished.
  - `tests/test_plane_runner.py`: the env contract on a fixture workspace; readyz 503 then 200.
  - _Requirements: 4.1, 4.2, 4.3_

- [ ] 4. Local reconciler and CLI
  - `src/openultrasast/plane/reconciler.py` (under 500 lines, no pipeline logic): `state.json`, statuses,
    topological execution, `serialize` labels never overlapping, `--workers`, budgets and artifact paths
    passed as task env, outcome read from `summary.json`, skip `done` on rerun, PID lock per run.
  - `ousast plane run <Run.yaml>`, `ousast plane status <run>`, `ousast plane workspaces <population.toml>`
    (generates Workspace manifests per case pin).
  - `tests/test_plane_reconciler.py`: stub tasks in a DAG: order, non-overlap, skip-on-rerun, `unfinished`
    and `failed` propagation, the lock, and the line-count assertion.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 2.2_

- [ ] 5. `repo-facts` task
  - `src/openultrasast/plane/tasks/repo_facts.py`: product files, functions per file (per-language
    declaration patterns), call sites per candidate function across product files (path, line, enclosing
    function, cap 40), sorted and deterministic; `summary.json` per the task contract.
  - `tests/test_plane_repo_facts.py`: three-file tree; cross-file callers found, tests and vendor excluded,
    identical output on a second run.
  - _Requirements: 5.1, 5.2, 2.1_

- [ ] 6. `verify` and `agree` tasks
  - `src/openultrasast/plane/tasks/verify.py`: the batched hunt moved from `verify_batched.py` (one hunt per
    file, up to 6 candidates, 6 steps, candidate-anchored sites) with known callers from `facts.json` in the
    prompt, tool turns and usage per hunt in `units.jsonl`, per-unit resume, `pass` from env, budget wrapper
    from task 2; `summary.json` never `done` unless every unit finished.
  - `src/openultrasast/plane/tasks/agree.py`: agreement across pass outputs, per-candidate cost and turns,
    declared-site matching via `evaluate.matches_v2`.
  - `tests/test_plane_verify.py`: scripted client; prompt carries the callers; resume asks only the
    unfinished file; a scripted 402 yields `failed`; agree on two scripted passes.
  - _Requirements: 5.3, 2.1, 2.2, 2.3_

- [ ] 7. Manifests for the increment
  - `plane/models/deepseek-flash.yaml` (annotated extension, prices in parameters);
    `plane/tasks/repo-facts.yaml`, `plane/tasks/verify.yaml`, `plane/tasks/agree.yaml`;
    `plane/runs/validation-46.yaml`: repo-facts -> verify pass a, verify pass b -> agree, budgets per task,
    inputs from the recorded candidate and triage artifacts.
  - Workspaces generated for the 15 validation cases' vulnerable pins.
  - _Requirements: 1.1, 1.2, 6.1_

- [ ] 8. Measurement of the first increment
  - Run `validation-46` through the reconciler (needs DeepSeek credit); record cost per candidate, tool turns
    per hunt, declared sites agreed, against `verifier-batched-check-2026-09-29.json`.
  - Run `benchmarks/dev/token_report.py` on the increment's development session.
  - Record `benchmarks/independent/plane-increment-1.json` with the gate result (met or not met) and commit;
    if not met, revise the design before task 9.
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 9. Handover
  - `ops/README.md`: how to run a Run locally and what an ax deployment would need (Kubernetes, Agent
    Substrate, the runner image, the provider extension); memory note updated; scripts that the tasks replaced
    marked as reference-only in their docstrings.
  - _Requirements: 4.2_
