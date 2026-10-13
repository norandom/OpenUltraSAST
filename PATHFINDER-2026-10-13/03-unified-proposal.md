# Unified proposal (2026-10-13)

Written by the orchestrator from 00 to 02. One rule throughout: prefer deletion over abstraction, one path over
configurable paths, and no new layer "for flexibility". Everything here serves the four active lines in
`.kiro/steering/overview.md`: hunter-learning-loop, pre-push-safety-net, search-with-proof,
engine-change-scoped-analysis. What serves none of them is cut.

## What the map says in three sentences
The code is not rotten (14 clone findings, 13 unreferenced lines), it is wide: each spec added a package and
nothing retired one. The same five jobs are done in several places: calling a model and counting its cost
(seven client types, four cost paths), finding the enclosing function and its callers (two naming systems, two
caller indexes, one grep), running the quick rules (nine copies), running code in a sandbox for a verdict (two
runtimes, two verdict vocabularies, neither reaching the evidence ladder), and writing scan results (findings
written six times, five ledgers under one directory). And three subsystems serve no active line: the improve
lever, the deep-mode regress arm, and the HarnessX-era half of the plane executor.

## Systems to unify (S1 to S6), in the order they pay off

### S1. One source-facts module (D4 + D5): the hunter's annotation producer
Today: semantic/functions.py (tree-sitter + regex fallback, sentinel `<module>`), plane/tasks/repo_facts.py
(regex only, sentinel `<global>`, DECLARATION/KEYWORDS/product_files), learn/features.callers (own regex),
plane/tasks/verify.callers_of, learn/excerpt.function_bounds, hunter_tools.find_refs (grep), plus alias maps in
three places. This is the exact set of facts hunter-learning-loop R3 names (enclosing function, callers, entry
points, roles, def-use), so it is the first thing to own.
Unified: `src/openultrasast/source.py` with `ranges(path, text, lang)`, `enclosing(ranges, line)`,
`bounds(ranges, name)`, `call_sites(text, names)`, `product_files(root)`, `DECLARATION`, `KEYWORDS`,
`LANGUAGE_ALIASES` (beside `preprocess.LANGUAGE_BY_EXTENSION`), one sentinel, one reserved set. Entry point:
`source.facts_for(root, path, line) -> SourceFacts(function, span, callers, entry_points)`; entry points keep
coming from `mapping.analyze_entry_points`, called once per run and passed in.
Old call sites: semantic/functions.py becomes the implementation moved here (keep `function_at` as an alias
for one release); plane/tasks/repo_facts.py keeps `main()` and imports the tables from source.py; learn/labels.py:48,
learn/features.py:27, 365-395, learn/roles.py:35, learn/excerpt.py:35, 302, plane/tasks/alerts.py:108-114,
plane/tasks/verify.py:128, plane/harvest.py:46, hunter_tools.py:83, 317-323 → source.py.
Lost: the per-language DECLARATION patterns for Java/Go/Ruby/PHP must be merged into `_DECL`; re-label the pair
corpus and diff `labels-<sha>.jsonl` before switching. The Learn↔PlaneTasks cycle disappears.

### S2. One chat client, one meter, one resolver (D1 + D10 parsers and retry policy)
Unified: `model/endpoint.py` keeps the single client (today's `DeepSeekChatClient`, renamed `ChatAdapter`; usage
is a list of rows) and the single resolver `resolve_chat_client(config | None) -> (client, endpoint)` that
honours `[models]` and prices by the model that runs. `plane/budget.py` keeps one `Meter` with
`reserve(bound)` and `settle(row)`; `MeteredClient` (post-call) and the reserve-first mode replace `FillMeter`,
`SpendBudget`/`SpendReservation` and search/worker `_call`. One `cost(row, prices)`. `Caller` (learn/program.py)
stays as the cache and replay layer on top of the meter. `parse_json_content` (provider/openrouter.py:205) is
the one JSON-in-fences parser; retry policy lives on the client only.
Old call sites: tool_hunter.py:239-262 `resolve_hunter_client` → `resolve_chat_client`; `OpenRouterHunterClient`
(203) and the env-flag set (36-39) deleted; `_load_json`/`_looks_like_json` (581, 409) → `parse_json_content`;
cli.py:976 passes a metered client; push/assistance.py:103-110 uses `cost`; search/worker.py:218-270 uses the
client and the reserve-first meter; learn/fill.py:44 `FillMeter` deleted; plane/tasks/verify.py:66 `_Recording`
and model/scan.py:1628 `_CountingClient` read counts off the meter; benchmarks/valid/hunter_arm.py:56-65 shim
deleted.
Lost: unmetered OpenRouter calls; recorded hunter dollars change because the hunter prices by its real model.

### S3. One quick-rule pipeline (D3)
Unified: `findings.quick_pipeline(root, targets=None, *, ruleset, policy, floors=None, include_shadow=False)
-> QuickRun(targets, entry_points, rankings, findings)`. cli.py wraps each step in `run_stage` through a
callback argument. Old call sites: cli.py:641-687 (and the standard-mode pool at hunter.py:103-160, which keeps
its thread pool but calls the pipeline), gate.py:81-84, map_gate.py:52-54, pairs.py:794-815, plane/tasks/alerts.py:
120-122, improve/evolve.py:311-315 (deleted with S9), push/quick.py:87-92 (passes its changed-file targets),
hunter_tools.py:232 (deleted with S8), benchmarks/learn/build_features.py. Fixes the standard-mode floors bug
(cli.py:670 vs 683-684). Lost: nothing; gates pass `ruleset=PATTERN_RULES` to keep their numbers.

### S4. One sandbox verdict on the evidence ladder (D2)
Unified: `search/_sandbox.run` implements `sandbox.SandboxRunner` (its options move into `SandboxJob`);
`resolve_sandbox_runner` picks bwrap or docker; one outcome record `ExecutionOutcome(outcome ∈ confirmed |
refuted | inconclusive | unavailable, reason, runs)` that emits `Rung.EXECUTION_CONFIRMED` (model/ladder.py:33)
so push_scoring.py:84, mcp.py:98 and learn/schema.py:77 finally receive execution evidence. Two oracle
strategies stay (owned canary, exit code). regress/ is deleted (S9): the deep-mode REGRESS stage calls the
proof arm's verify path once that lands, and until then deep mode equals standard mode and says so in a
degradation. Lost: snippet-based regress in `scan --mode deep` until search-with-proof is wired to scan. This
is the one capability loss in the proposal and it is deliberate: the maintainer named proof as the block
gate and the search line owns it.

### S5. Deadline type and the CPG↔Model cycle (D6 + W3.5)
Unified: `ExecutionBudget` moves to `contracts.py` with `expired()`, `remaining()`, `cleanup_end`, `check()`;
`DeadlineExpired` and `remove_owned_tree` become public in a `deadline.py` next to it. Old call sites: the 66
budget expressions (push 47, model 13, cpg 16), cpg/backend.py:37, cpg/session.py:44, model/partitions.py:14,
cpg/artifact.py:151, push/cache.py:22. Also W4.3: one `_run` in cpg/backend.py so standard scans get partial
stdout; W4.1: one `ARBITERS` table used by scan.py and pipeline.py (and the `hook_callbacks` divergence closes).
Lost: nothing.

### S6. Scan assembly: write once, score last, one ledger (D9 + U1 bugs + W1.4 + W1.5)
Unified: `_run_scan` accumulates findings per proposer in memory and writes `findings.json` once in a
`finally`; scoring and verification move after MAP so model, overlay, obligation and hunter findings are scored
and verified (the U1 bug); `CalibrationLedger(target)` owns the five files under `.openultrasast/calibration/`;
`runtime.degrade(stage, reason, detail)` replaces 13 inline appends; `run.write_json` replaces 24 `write_*`
wrappers; `benchmark.run_benchmark` is shared by cli and mcp (W1.3). fusion.py is deleted: its decisions never
reach findings or score (U1), and harness.py loses the processor machinery nobody builds. Lost: a partial
findings.json on a crash, unless the finally write is kept (it is).

### S7. Memory store as a leaf; plane executor trimmed (U7 inversion + U8 + W8)
`plane/memory.py` loses its three lazy imports: `seed` moves to `plane/seed.py`, `results_root` to
`plane/paths.py`. The executor keeps reconciler, runner, delivery, router, egress, doctor, profile and loses
engine_alerts.py, harvest.py, workspaces.py, generate.py and receiver mode (their live helpers `declares`,
`docker_command`, `frozen_source`, `read_record`, `export_pin` move into benchmarks/learn, their only users).
One `Cli` wrapper and `error_tail` for ax and kubectl (reconciler, egress, benchmarks/ax/batch); one
`safe_extract` and one `ObjectURL` client shared by plane/runner, delivery, search/executor and verify_task
(plane extraction gains the size cap and the no-redirect rule). The two dispatch stacks stay two for now: the
search stack is on the active proof line and the plane stack is parked with plane-on-kubernetes; merging them
is a decision for when the ax lane is back.

## Cuts (S8, S9): what leaves the tree
S8, hunter unit: the four never-enabled tools and their schemas and dispatch branches (hunter_tools.py:174-290,
tool_hunter.py:94-137, 505-521), the dead `find_refs` mapping branch (hunter_tools.py:86-101, 118-164),
`OpenRouterHunterClient`, `_load_json`, `_looks_like_json`, `ScriptedChatClient` stays. The facts those tools
computed come back as annotations from S1, which is what the hunter-learning-loop spec asks for.
S9, off every active line: improve/ (1,175 lines; `ousast improve`, the `loop-improve` task at
plane/generate.py:380 and plane/tasks/loop.py, plane/memory.py:1002's snapshot guard, docs/memory.md and
README sections); regress/ (549) with the REGRESS branch cli.py:839-880; skills.py + index.py (446; the routed
ids are trajectory metadata only, hunter.py:137-139, 96, 157); model/audit.py (255) to a maintainer script or
gone; test-only functions in mapping.py (188-237), calibration.py:108, findings.py:102, verification.py:39,
rank.py:46-69, model/report.py:24-75, taxonomy.hierarchical/related, config_value.verdict, taint.verdict,
pipeline._arbitrate's dead branches, learn/roles.load_roles, learn/features.language_of and build_for_scan,
folds.leave_one_*, plane/tasks/features.recorded_case, coordinator.BatchExecutor, memory.purge/delete_version,
delivery.put_input, worker.main/verify.main/coordinator.main shims, cpg/queries/vocabulary.sc. Each goes with
its test file. push_inputs.py moves under benchmarks/push. mcp.py stays until the mcp-shift-left-agent spec is
decided (breadth.toml: parked, close date 2026-12-01). map_gate.py and pair_gate.py stay with CI for now; their
removal needs cli.py:49, ci.yml, dagger/ci.py and the gate baseline changed together.

Estimated effect (lines, rough): duplication removal 650 to 800 in src; cuts about 4,500 in src (improve 1,175,
regress 549, plane dead modules about 1,300, skills+index 446, audit 255, hunter tools and client about 450,
test-only functions about 350) and the tests that only exercised them, about 9,000. src goes from 60k toward
55k and tests from 54k toward 45k, with every remaining package on an active line or in breadth.toml as parked
with a close date.

## Order of work
1. S9 cuts and S8 (cheap, no design, unblocks everything else; one commit per package with its tests).
2. S1 source facts (the annotation producer hunter-learning-loop needs first).
3. S2 client and meter (the ablation runs need one metered client with replay).
4. S3 quick pipeline, S5 deadline type (small, mechanical).
5. S6 scan assembly (fixes the scoring-before-MAP bug; touches cli.py most).
6. S4 sandbox verdict (with search-with-proof's next increment).
7. S7 plane trim (when plane-on-kubernetes resumes or is closed).

## The proposed system
```mermaid
flowchart TD
  subgraph inputs
    SCAN[ousast scan<br/>cli.py:619] --> QP
    PUSH[pre-push runner<br/>push/runner.py:609] --> QP
    GATE[gate.py / pairs / alerts] --> QP
  end
  QP[quick_pipeline<br/>findings.py (S3)] --> FACTS
  QP --> ENGINE
  FACTS[source.facts_for<br/>source.py (S1)] --> ANN[annotation model<br/>hunter-learning-loop R3]
  ENGINE[scan_repository<br/>model/scan.py:143] --> RUNG
  ANN --> HUNT[run_tool_hunter<br/>tool_hunter.py:323]
  HUNT --> CLIENT[ChatAdapter + Meter + Caller<br/>model/endpoint.py, plane/budget.py, learn/program.py (S2)]
  CLIENT --> CLS[classify<br/>learn/program.py:473]
  CLS --> RUNG[evidence ladder Rung<br/>model/ladder.py:29]
  RUNG --> ADMIT[admit_candidates<br/>push/policy.py:889]
  RUNG --> PROOF[search verify<br/>search/verify.py:648]
  PROOF --> EXEC[ExecutionOutcome -> EXECUTION_CONFIRMED<br/>sandbox (S4)]
  EXEC --> ADMIT
  ADMIT --> REPORT[deliver_report<br/>push/report.py:423]
  ENGINE --> ASSEMBLE[write once, score last<br/>cli.py (S6)]
  HUNT --> ASSEMBLE
  ASSEMBLE --> LEDGER[CalibrationLedger<br/>(S6)]
  CLS --> STORE[(MemoryStore leaf<br/>plane/memory.py (S7))]
  LEARN[learn compile / evaluate / experiment<br/>learn/cli.py] --> CLIENT
  LEARN --> STORE
  FACTS --> LEARN
  BUDGET[ExecutionBudget + DeadlineExpired<br/>contracts.py (S5)] -.-> ENGINE
  BUDGET -.-> PUSH
```
