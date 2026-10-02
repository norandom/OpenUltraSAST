# Architecture

This page covers four things:

- how a scan works;
- how a finding earns its place;
- how severity and the project score are decided;
- how the ruleset improves itself.

State as of 2026-10-02; module paths are under `src/openultrasast/`.

## The scan pipeline

The CLI is thin. `HarnessRuntime` owns the lifecycle. It writes an event trace for every stage
(`trace/events.jsonl`). `MODE_STAGES` in `stages.py` lists the stages each mode requests:

- `quick` runs STATIC;
- `standard` adds MAP;
- `deep` adds REGRESS.

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
graph (CPG: a graph of the program's syntax, control flow and data flow) per scan with Joern.
It runs `joern-parse`, then batched `joern --script` queries from `cpg/queries/*.sc`. Each
question goes to the arbiter (a checker that decides one kind of question) for its spec type:

- taint (untrusted input reaching a dangerous call): source to sink with no discharging sanitizer;
- dominance: does a guard govern the obligated operation;
- configuration: constant abstraction over a value.

Taint facts ship for C, Java, JavaScript, PHP and Python (`ruleset/semantic/*.toml`). Without
Joern, the layer records `cpg_unavailable` and the rest of the scan is unchanged. The Docker
image ships Joern and `php-cli`, which the PHP frontend needs. [Detection
techniques](detection-techniques.md) explains the representations and techniques behind each
stage.

The model layer reports on a rung ladder:

```
execution_confirmed   a test or sandbox reproduced it
model_entailed        the graph decided: a flow with no discharge, an obligation with no
                      guard, a permissive value
model_corroborated    the graph found the shape; a judge agreed on the residual question
suspicion             proposed, nothing corroborated it
```

The LLM answers only the residual question: the part the graph cannot settle
(`model/pipeline.py`, `residual_question`). It is asked only about a flow the graph already
found. It can confirm or contradict that flow, but never create one. When the graph resolved
nothing, the LLM sees the enumerator's candidates (at most `MAX_JUDGED_CANDIDATES`, 8).
Anything it affirms is reported at `suspicion`. Without a provider key, neither question is
asked. Only the graph's entailed findings are reported then.

**REGRESS** (`regress/`, `sandbox/`) runs only when `docker info` succeeds. Each promoted
candidate gets a small language recipe (Python, JavaScript, C). The recipe loads the
candidate's source inside a container with:

- no network;
- a read-only `/workspace`;
- a non-root user;
- the `[sandbox]` limits.

Before anything runs, a structural deny-list rejects snippets that mention sockets, curl, host
networking or writes under `/workspace`.

## Evidence ladder: how a false positive is eliminated

Evidence level is a state machine, not a label a model may assign. The verifier
(`verification.py`) runs on independent context and enforces it:

```
suspicion ─▶ static_corroboration ─▶ crash_reproduced ─▶ root_cause_explained
          ─▶ exploit_demonstrated ─▶ patch_validated
```

- below `static_corroboration`: `NEEDS_EVIDENCE`;
- `static_corroboration` with reachability unknown: `REJECTED`, with a tie-breaker demanding
  call-graph, route, CLI, parser or dynamic evidence;
- `static_corroboration` with function-level reachability: `ACCEPTED`.

A rejected finding becomes a **scoped false-positive learning** (`calibration.py`). It has a
scope and a reason from a fixed taxonomy: `unreachable_path`, `missing_attacker_control`,
`sanitizer_disproved`, `static_rule_mismatch`, `incorrect_model_assumption`, `duplicate`,
`insufficient_impact`, `unsupported`, `contradicted`, `unverified`. A rejection in `auth/`
demotes only `auth/...`, never the whole class
(`tests/test_calibration.py::test_scoped_false_positive_demotion_does_not_suppress_class_globally`).

## How a false negative is surfaced

An expected vulnerability that no finding matched becomes a `BenchmarkCalibrationRecord` in
`calibration_records.json`. Each record names a `next_improvement_candidate`: a static rule,
SARIF source, entry-point mapping, retrieval package, hunter prompt, dynamic reproducer or
skill route. Once a miss is closed, the detection gate keeps it closed in CI.

## Central CWE policy and the project score

**Policy** (`policy/verycode.py`): a vendored `CWE_Score.tsv` (verycode-policies) is the single
source of truth. Each CWE carries:

- a flaw category;
- a severity (0-5);
- `static`/`dynamic` scope flags.

A finding's severity comes only from policy, keyed on CWE. CWEs that are not `static` resolve
to 0 and are report-only. `assert_rules_resolve` runs as the `policy_check` stage. An enabled
rule that names an ungoverned CWE aborts the scan. Verycode has no CWE-120, so the C/C++
buffer rules carry CWE-121.

**Score** (`scoring/project_score.py`): each finding's penalty is
`SEV_WEIGHT[severity] x REACH_MULT[reachability]`. The score is `100 * e^(-total/k)` with
`k = 60`.

| Severity | Weight | | Reachability | Multiplier |
| --- | --- | --- | --- | --- |
| 5 | 50 | | `reachable` | 1.0 |
| 4 | 25 | | `inferred-file-surface` | 0.6 |
| 3 | 10 | | `unknown` | 0.4 |
| 2 / 1 / 0 | 2 / 1 / 0 | | | |

A confirmed false positive lowers a finding's reachability multiplier. The rule is not
deleted. The score gate works like this:

- a severity-5 reachable finding always fails it;
- `score < min_score` (default 80) fails it only with `[score] blocking = true`.

The `score` stage writes `score.json` and merges it into `manifest.json`.

## Self-improvement

### Scoped calibration (every scan)

```
scan ─▶ verify ─▶ non-accepted findings ─▶ scoped learnings
        (.openultrasast/calibration/false_positive_learnings.json)
next scan ─▶ rank ─▶ calibrate (demote rejected scopes) ─▶ findings
```

1. `record_calibration` runs after `verify`. It merges this run's non-accepted outcomes into
   the ledger, de-duplicated by finding ID.
2. `calibrate` runs after `rank`. It demotes the priority of every scope that produced a
   rejection and writes `applied_calibrations.json`.

Demotion is scoped and reversible (`tests/test_pipeline_calibration.py`).

### Rule-level loop: `ousast improve`

Each round (`improve/evolve.py`) runs these steps:

1. benchmark with the current ledger;
2. per-rule signals (`rule_signals.json`);
3. bounded proposals;
4. validation (`improve/validator.py`);
5. replay smoke;
6. re-benchmark;
7. a hard gate.

The levers are rule status (`enabled -> shadow` before `disabled`) and score constants. The
loop can never edit pattern text or the authoritative CWE severity. A round is accepted only if
all of these hold:

- recall >= 90%;
- FP < 10%;
- the project score did not regress;
- no matched finding was lost.

Otherwise the ledger is not written. With `--pair-catalog`, each round is also gated per
provenance profile on the catalog's holdout pairs. `--no-pair-gate` skips this check; do not
use it for accepted ledgers. The same detection gate runs in CI (`python -m openultrasast.gate`).

### Proposals from plane memory

With `--memory [STORE]`, `ousast improve` also reads the rows that plane runs stored per
repository and pin (`improve/memory.py`). Two deterministic rules turn these rows into
rule-status proposals:

- a rule whose alerts are repeatedly false across repositories is shadowed;
- a shadow rule that keeps hitting agreed, declared vulnerable sites is re-enabled.

Some rows are dropped before any rule sees them: rows from holdout pairs, from the gated
manifest's own cases and from any `--qualify-population`. Each proposal records the rows it
came from (`memory_proposals.jsonl` next to the journal). It then goes through the same
validator and gate.

### The loop as a plane Run

`ousast plane workspaces <population> --validation-set ... --loop` appends the improvement loop
to a generated Run. The Run holds `alerts` per case: the quick scan on the vulnerable and fixed
pins. Then come the steps `snapshot` (task `memory-snapshot`), `measure`, `propose` and
`improve` (`plane/tasks/loop.py`). Each step is model-free with a zero budget. The snapshot
applies the same train-on-test guard before any row leaves the store. A recorded live run:
`benchmarks/measurements/2026-09-30-harnessx-removal-loop/`.

When that run was made, quick mode covered PHP with zero rules. So for PHP, `ousast plane
alerts-engine` produces a Run's `alerts` from the engine image on the host instead
(`benchmarks/measurements/2026-09-30-php-engine-alerts/`).
