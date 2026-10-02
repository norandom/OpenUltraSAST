# Architecture

How a scan works, how a finding earns its place, how severity and the project score are
decided, and how the ruleset improves itself. State as of 2026-10-02; module paths are under
`src/openultrasast/`.

## The scan pipeline

The CLI is thin; `HarnessRuntime` owns the lifecycle and writes an event trace for every stage
(`trace/events.jsonl`). The stages a mode requests are `MODE_STAGES` in `stages.py`:
`quick` runs STATIC, `standard` adds MAP, `deep` adds REGRESS.

```
policy_load ─▶ ruleset_load ─▶ policy_check            (fail loud on an ungoverned CWE)
  ─▶ static_mapping (SARIF ingest) ─▶ preprocess ─▶ entry_point_mapping
  ─▶ rank ─▶ calibrate (demote previously rejected scopes)
  ─▶ findings   quick, deep: quick_findings (language-scoped pattern rules)
  │             standard: hunter_pool (the same rules, scheduled per ranked target)
  ─▶ verify ─▶ record_calibration ─▶ fusion (standard only, deterministic) ─▶ score
  ─▶ MAP (standard, deep)
  │     map          complexity map and hotspots
  │     overlay      semantic overlay over the findings (tree-sitter with the `semantic` extra)
  │     obligations  absence bugs: an obligated operation with no governing guard
  │     model        one Joern CPG per repository; taint, dominance and configuration arbiters
  │     tool hunter  only with `[models] hunter`
  ─▶ REGRESS (deep)  sandboxed regression snippets ─▶ verdicts.json, worth-fixing
  ─▶ report.md, report.sarif, manifest.json
```

**The model layer** (`model/`, `cpg/`) is the core of `standard`. It builds one code property
graph per scan with Joern (`joern-parse`, then batched `joern --script` queries from
`cpg/queries/*.sc`) and dispatches each question to the arbiter of its spec type: taint
(source to sink with no discharging sanitizer), dominance (does a guard govern the obligated
operation) and configuration (constant abstraction over a value). Taint facts ship for C,
Java, JavaScript, PHP and Python (`ruleset/semantic/*.toml`). Without Joern the layer records
`cpg_unavailable` and the scan is otherwise unchanged; the Docker image ships Joern and
`php-cli` (which the PHP frontend needs).

The model layer reports on a rung ladder:

```
execution_confirmed   a test or sandbox reproduced it
model_entailed        the graph decided: a flow with no discharge, an obligation with no
                      guard, a permissive value
model_corroborated    the graph found the shape; a judge agreed on the residual question
suspicion             proposed, nothing corroborated it
```

The LLM (`model/judge.py`) is asked only the residual question the graph cannot settle, for a
flow the graph already found; it can confirm or contradict, never create a flow. Without a
provider key only the `suspicion` band goes unasked.

**REGRESS** (`regress/`, `sandbox/`) runs only when `docker info` succeeds. Each promoted
candidate gets a small language recipe (Python, JavaScript, C) that loads the candidate's
source inside a container with no network, a read-only `/workspace`, a non-root user and the
`[sandbox]` limits. A structural deny-list rejects snippets mentioning sockets, curl, host
networking or writes under `/workspace` before anything runs.

## Evidence ladder: how a false positive is eliminated

Evidence level is a state machine, not a label a model may assign. The verifier
(`verification.py`) runs on independent context and enforces:

```
suspicion ─▶ static_corroboration ─▶ crash_reproduced ─▶ root_cause_explained
          ─▶ exploit_demonstrated ─▶ patch_validated
```

- below `static_corroboration`: `NEEDS_EVIDENCE`;
- `static_corroboration` with reachability unknown: `REJECTED`, with a tie-breaker demanding
  call-graph, route, CLI, parser or dynamic evidence;
- `static_corroboration` with function-level reachability: `ACCEPTED`.

A rejected finding becomes a **scoped false-positive learning** (`calibration.py`) with a
reason from a fixed taxonomy (`unreachable_path`, `missing_attacker_control`,
`sanitizer_disproved`, `static_rule_mismatch`, `incorrect_model_assumption`, `duplicate`,
`insufficient_impact`, `unsupported`, `contradicted`, `unverified`) and a scope. A rejection in
`auth/` demotes only `auth/...`, never the whole class
(`tests/test_calibration.py::test_scoped_false_positive_demotion_does_not_suppress_class_globally`).

## How a false negative is surfaced

Every expected vulnerability that no finding matched becomes a `BenchmarkCalibrationRecord` in
`calibration_records.json`, with a `next_improvement_candidate` (a static rule, SARIF source,
entry-point mapping, retrieval package, hunter prompt, dynamic reproducer or skill route).
Once a miss is closed the detection gate keeps it closed in CI.

## Central CWE policy and the project score

**Policy** (`policy/verycode.py`): a vendored `CWE_Score.tsv` (verycode-policies) is the single
source of truth. Each CWE carries a flaw category, a severity (0-5) and `static`/`dynamic` scope
flags. A finding's severity comes only from policy, keyed on CWE. CWEs that are not `static`
resolve to 0 and are report-only. `assert_rules_resolve` runs as the `policy_check` stage: an
enabled rule naming an ungoverned CWE aborts the scan. Verycode has no CWE-120, so the C/C++
buffer rules carry CWE-121.

**Score** (`scoring/project_score.py`): each finding's penalty is
`SEV_WEIGHT[severity] x REACH_MULT[reachability]`, and the score is `100 * e^(-total/k)` with
`k = 60`.

| Severity | Weight | | Reachability | Multiplier |
| --- | --- | --- | --- | --- |
| 5 | 50 | | `reachable` | 1.0 |
| 4 | 25 | | `inferred-file-surface` | 0.6 |
| 3 | 10 | | `unknown` | 0.4 |
| 2 / 1 / 0 | 2 / 1 / 0 | | | |

A confirmed false positive lowers a finding's reachability multiplier instead of deleting the
rule. A severity-5 reachable finding always fails the score gate; `score < min_score`
(default 80) fails it only with `[score] blocking = true`. The `score` stage writes
`score.json` and merges it into `manifest.json`.

## Self-improvement

### Scoped calibration (every scan)

```
scan ─▶ verify ─▶ non-accepted findings ─▶ scoped learnings
        (.openultrasast/calibration/false_positive_learnings.json)
next scan ─▶ rank ─▶ calibrate (demote rejected scopes) ─▶ findings
```

`record_calibration` (after `verify`) merges this run's non-accepted outcomes into the ledger,
de-duplicated by finding ID; `calibrate` (after `rank`) demotes the priority of every scope
that produced a rejection and writes `applied_calibrations.json`. Demotion is scoped and
reversible (`tests/test_pipeline_calibration.py`).

### Rule-level loop: `ousast improve`

Each round (`improve/evolve.py`): benchmark with the current ledger, per-rule signals
(`rule_signals.json`), bounded proposals, validation (`improve/validator.py`), replay smoke,
re-benchmark, and a hard gate. The levers are rule status (`enabled -> shadow` before
`disabled`) and score constants; the loop can never edit pattern text
or the authoritative CWE severity. A round is accepted only if recall >= 90%, FP < 10%, the
project score did not regress and no matched finding was lost; otherwise the ledger is not
written. With `--pair-catalog`, every round is also gated per provenance profile on the
catalog's holdout pairs (`--no-pair-gate` skips this and is not for accepted ledgers). The same
detection gate runs in CI (`python -m openultrasast.gate`).

### Proposals from plane memory

With `--memory [STORE]`, `ousast improve` also reads the rows plane runs stored per repository
and pin (`improve/memory.py`). Two deterministic rules turn them into rule-status proposals: a
rule whose alerts are repeatedly false across repositories is shadowed, and a shadow rule that
keeps hitting agreed, declared vulnerable sites is re-enabled. Rows from holdout pairs, from the
gated manifest's own cases and from any `--qualify-population` are dropped before any rule sees
them. Each proposal records the rows it came from (`memory_proposals.jsonl` next to the
journal) and goes through the same validator and gate.

### The loop as a plane Run

`ousast plane workspaces <population> --validation-set ... --loop` appends the improvement loop
to a generated Run: `alerts` per case (the quick scan on the vulnerable and fixed pins), then
the steps `snapshot` (task `memory-snapshot`), `measure`, `propose` and `improve` (`plane/tasks/loop.py`), each model-free
with a zero budget. The snapshot applies the same train-on-test guard before any row leaves the
store. A recorded live run: `benchmarks/measurements/2026-09-30-harnessx-removal-loop/`.

For PHP, which quick mode covered with zero rules when that run was made, `ousast plane
alerts-engine` produces a Run's `alerts` from the engine image on the host instead
(`benchmarks/measurements/2026-09-30-php-engine-alerts/`).
