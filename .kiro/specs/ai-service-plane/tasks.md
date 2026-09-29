# Implementation Plan

Order follows the dependency chain: ax bring-up (parallel with 1-2) -> manifests -> budget -> runner ->
ax-backed reconciler -> tasks -> increment run on ax -> measurement. Every task ships with its tests; a task is done when its tests pass in the host suite, ruff and
mypy are clean, and the commit is gated on pytest's own exit code. Script-level pipeline work stays paused.

- [x] 0. ax bring-up on this host
  - Install `kind`, `kubectl`, the `ax` CLI and `ko` (user-local). `ops/ax/up.sh`: create the kind cluster and
    install Agent Substrate with its `hack/create-kind-cluster.sh` and `hack/install-ate-kind.sh
    --deploy-ate-system`, deploy the ax control plane with `ko` to the kind registry, apply one trivial Task
    and wait for it to finish; `ops/ax/down.sh` tears it down. Record the measured idle footprint (RSS, CPU)
    in `ops/ax/README.md` next to the 7 GB host constraint.
  - `ousast plane doctor` (in `reconciler.py` or a sibling `doctor.py`): the four checks of Requirement 3.5.
  - Egress: `up.sh` applies Substrate's agentgateway egress gateway (`atenet-egress`, prebuilt image, rendered
    with `kubectl kustomize`) when absent, and the receiver Service `ousast-receiver.ax-system`
    (`receiver-service.yaml.tmpl`, endpoint the kind gateway at port 18090). The reconciler writes each task's
    egress policy (`egress.py`: receiver over HTTP, Git and Model hosts as TLS passthrough) between `ax apply` and
    resume; the runner delivers to `OUSAST_ARTIFACT_DIAL` (the Service's ClusterIP, port 80) with the receiver's name as
    `Host`.
  - Stop rule: if the cluster does not come up within one working session, report the exact failure and stop;
    the decision to work around it is the maintainer's.
  - _Requirements: 3.5, 3.6_

- [x] 1. Manifest schemas and validation
  - Add `pyyaml` as a declared dependency in `pyproject.toml`.
  - `src/openultrasast/plane/manifests.py`: dataclasses and loaders for `Task`, `Workspace`, `Model`
    (`ax.io/v1alpha1`, ax's fields only) and `Run` (`openultrasast.io/v1alpha1`: tasks, dependsOn, inputs,
    outputs, budget, serialize); reject unknown fields, a provider outside ax's two without the
    `openultrasast.io/provider-extension` annotation, and a Run with a cycle or an input naming no task.
  - `tests/test_plane_manifests.py`: valid manifests load; each rejection names the field.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 2. Budget metering
  - `src/openultrasast/plane/budget.py`: a client wrapper that sums provider usage per call, prices from the
    Model's parameters, raises `BudgetExhausted` at the ceiling and `AccountError` on 401/402 or an
    "insufficient balance" body; an unpriced model reports `unpriced` and refuses a `usd` budget.
  - Tests with a scripted client: ceiling stop, account error, unpriced refusal, cache-hit pricing.
  - _Requirements: 2.3, 2.4_

- [x] 3. Runner contract
  - `src/openultrasast/plane/runner.py`: read `AX_TASK_YAML` / `AX_WORKSPACES_YAML`; materialise `git`
    entries at the pinned commit from the local case cache and write `spec.files` (first boot only); run
    `spec.command` as a child `python -m openultrasast.plane.tasks.<name>` in its own process group, cwd the
    first workspace, `AX_METADATA_URL` set; `/healthz` `/readyz` and ax's metadata paths on port 80 (503 until
    workspaces are ready; disabled only under `AX_RUNNER_HTTP=0` for unit tests); after the command exits,
    POST the output directory as a tar stream to `OUSAST_ARTIFACT_URL` (report `failed` if delivery fails),
    write `/workspace/.ousast-state/<task>.done.json`, and keep serving until SIGTERM (ax's contract for PID 1);
    a boot with the marker never reruns the command and retries only a failed delivery; SIGTERM goes to the
    command's group, SIGKILL after `OUSAST_TERM_GRACE`, exit 0. `AX_RUNNER_EXIT_AFTER_COMMAND=1` (tests only)
    exits after delivery with 0 done, 2 failed, 3 unfinished. The command never starts by itself: after the
    workspaces are ready the runner waits for `POST /ousast/v1/start` (`{run, task, credentials}`; 503 before
    ready, 409 on a run/task mismatch, a second request, or a marker recording a delivered run; 202 once),
    merges the credentials into the child's environment only and redacts them from its echoed stderr, so
    Agent Substrate's golden-snapshot boot runs nothing (Req 4.5, 4.6). `AX_RUNNER_AUTOSTART=1` (tests only)
    starts without a request. `plane/Dockerfile.runner`: this package on Python 3.12, installed to
    `/usr/local/bin/ax-task-runner`, loaded into kind by `ops/ax/up.sh`.
  - `tests/test_plane_runner.py`: the env contract on a fixture workspace; readyz 503 then 200; delivery to a
    local receiver; delivery failure yields `failed`; the child's cwd and `AX_METADATA_URL`; the runner stays
    up after the command; SIGTERM kills a long-running command's group; the marker prevents a rerun; no command
    before a start request, 409 on a wrong run/task and on a second start, the credential reaches the child
    (its hash in the artifact) and no file or log record, a crash printing it is redacted, and of two runners
    with identical env only the addressed one runs (the golden scenario).
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [x] 4. ax-backed reconciler and CLI
  - `src/openultrasast/plane/reconciler.py` (under 500 lines, no pipeline logic, no local subprocess
    executor): `state.json`, statuses, topological submission through the `ax` CLI (path injectable),
    `ax resume task` after `ax apply` (a created Task is `Suspended`), retrying DeadlineExceeded/Unavailable
    with backoff up to `OUSAST_RESUME_TIMEOUT`; completion is the artifact delivery, never an ax phase (ax has
    none for a finished command); `Failed` or a vanished task before delivery, or no delivery within
    `OUSAST_TASK_TIMEOUT`, fails the task with ax's condition message; the artifact HTTP receiver, `serialize` labels never overlapping, `--workers`, budgets and
    artifact env passed in the rendered Task manifest, outcome read from the delivered `summary.json`, skip
    `done` on rerun, PID lock per run, `ax delete` of finished Tasks. Once ax reports `Running` after a
    resume, one start request per resume through Agent Substrate's router (`src/openultrasast/plane/router.py`:
    `kubectl port-forward svc/atenet-router` for the run, or `OUSAST_ROUTER_URL`; header
    `ate-target-actor: <atespace>/<task>`; 502/503/504 and connection errors retried up to
    `OUSAST_START_TIMEOUT`, a 409 final), carrying the bound Model's `secretKey.key` variable from the
    reconciler's environment; a Model-bound task whose variable is unset fails before `ax apply`.
    Task-produced inputs travel as `OUSAST_INPUTS`, not as a rendered Workspace: the runner fetches them after
    the start from the receiver's authorised `GET /inputs/<producer>/<artifact>` (a 182 KB `facts.json` in
    `AX_WORKSPACES_YAML` exceeded Substrate's 32768-character env limit on the live cluster, 2026-09-29).
  - `ousast plane run <Run.yaml>`, `ousast plane status <run>` (token attribution table per task and Model
    from the tasks' `summary.json` usage; `--units` from `units.jsonl`; also written to `attribution.json`),
    `ousast plane workspaces <population.toml>` (generates Workspace manifests per case pin).
  - `tests/test_plane_reconciler.py`: a fake `ax` CLI with ax's real lifecycle (Suspended, a first resume
    failing DeadlineExceeded, Running without a Completed phase) drives a DAG: order, non-overlap,
    skip-on-rerun, `unfinished` and `failed` propagation, resume retry and timeout, `Failed` with a condition
    message, the task timeout without delivery, the lock, the attribution table, and the
    line-count assertion; with a fake router: one start per task after the accepted resume and before the
    delivery, the credential in the verify start only and in no file under the run or tmp dirs, a missing
    secret failing the task, a refused start failing it. `tests/test_plane_router.py`: port parsing from a
    fake kubectl and its termination on exit, retry on 503/502 then 202, 409 raised with redacted text, the
    start timeout. `tests/test_plane_ax_live.py` (marker `ax`, skipped without a live cluster): one
    trivial Task end to end.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 2.2, 4.5, 4.6, 7.1, 7.3_

- [x] 5. `repo-facts` task
  - `src/openultrasast/plane/tasks/repo_facts.py`: product files, functions per file (per-language
    declaration patterns), call sites per candidate function across product files (path, line, enclosing
    function, cap 40), sorted and deterministic; `summary.json` per the task contract.
  - `tests/test_plane_repo_facts.py`: three-file tree; cross-file callers found, tests and vendor excluded,
    identical output on a second run.
  - _Requirements: 5.1, 5.2, 2.1_

- [x] 6. `verify` and `agree` tasks
  - `src/openultrasast/plane/tasks/verify.py`: the batched hunt moved from `verify_batched.py` (one hunt per
    file, up to 6 candidates, 6 steps, candidate-anchored sites) with known callers from `facts.json` in the
    prompt, tool turns and usage per hunt in `units.jsonl`, per-unit resume, `pass` from env, budget wrapper
    from task 2; `summary.json` never `done` unless every unit finished, and records the bound Model and
    the summed usage fields (prompt, cache-hit, output tokens, calls, usd).
  - `src/openultrasast/plane/tasks/agree.py`: agreement across pass outputs, per-candidate cost and turns,
    declared-site matching via `evaluate.matches_v2`.
  - `tests/test_plane_verify.py`: scripted client; prompt carries the callers; resume asks only the
    unfinished file; a scripted 402 yields `failed`; agree on two scripted passes.
  - _Requirements: 5.3, 2.1, 2.2, 2.3, 7.2_

- [x] 7. Manifests for the increment
  - `plane/models/deepseek-flash.yaml` (annotated extension, prices in parameters);
    `plane/tasks/repo-facts.yaml`, `plane/tasks/verify.yaml`, `plane/tasks/agree.yaml`;
    `plane/runs/validation-46.yaml`: repo-facts -> verify pass a, verify pass b -> agree, budgets per task,
    inputs from the recorded candidate and triage artifacts.
  - Workspaces generated for the 15 validation cases' vulnerable pins; the runner image rebuilt and loaded.
  - _Requirements: 1.1, 1.2, 6.1_

- [ ] 8. Measurement of the first increment
  - Run `validation-46` through the reconciler on ax (needs DeepSeek credit); record cost per candidate, tool turns
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
