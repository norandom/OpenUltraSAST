# Handoff prompts (copy each into /make-plan)

Order follows 03-unified-proposal.md. Every prompt is read-only until its plan is approved. Shared guards:
work on main, no branches; one package per commit with its tests; run `ruff check` and the touched test files
before each commit; plain English in comments and commit messages; never read or echo `.env`; update
`.kiro/breadth.toml` when a capability changes status.

## P0. Cuts: packages and functions on no active line (S9 + S8)
```
Plan the removal of code that serves none of the four active lines in .kiro/steering/overview.md, using
PATHFINDER-2026-10-13/03-unified-proposal.md section "Cuts" and the per-unit "removal candidates" in
PATHFINDER-2026-10-13/01-flowcharts/*.md as the inventory. One commit per package, tests included.
Packages: src/openultrasast/improve/ (and `ousast improve` in cli.py:237-281, 433, 1106-1170; the loop-improve
task at plane/generate.py:380 and plane/tasks/loop.py:67-104, 194-224; plane/memory.py:1002's snapshot guard;
README.md:220, 314; docs/memory.md, docs/examples.md:58-85, docs/index.md:45, docs/threat-model.md:18;
ops/ax/README.md:101; tests test_improve*.py, test_cli_improve.py, test_subtraction_complete.py:67-89,
test_gate.py:135-136); src/openultrasast/regress/ with cli.py:839-880 (deep mode records a degradation
"regress retired, proof arm pending" and otherwise equals standard; tests test_regress_*.py,
test_split_sink_regress.py, test_reports.py:12); skills.py + index.py (hunter.py:137-139 stops routing; drop
`selected_skills` from the task and trajectory at hunter.py:96, 157; tests test_skills, test_index, the skills
part of test_hunter); model/audit.py (either delete with tests/test_module_audit.py and the
2026-09-08-module-audit.json reference in overview.md, or move to ops/tools/); hunter tools never enabled
(hunter_tools.py:174-290 read_definition/entry_points/flows/obligations, tool_hunter.py:94-137 schemas,
505-521 dispatch, the find_refs mapping branch hunter_tools.py:86-101, 118-164; tests
test_hunter_curated_tools.py); cpg/queries/vocabulary.sc with tests/test_cpg_queries_compile.py:32 and
benchmarks/push/ontology_gap.py:102.
Functions (each with its only test): mapping.py:188-237 five task/record functions and their record classes
(:39-56); calibration.py:108; findings.py:102; verification.py:39; rank.py:46-69 and RankerClient (:31);
fusion.py:94 and, if S6 is accepted, fusion.py entirely (cli.py:720-726, fusion.json); harness.py:41-55,
125-166 processor machinery; model/report.py:24-75; model/taxonomy.py:76, 80; model/config_value.py:90 and
model/taint.py:72 (tests move onto `verdicts()[0]`), model/pipeline.py:117-121 becomes dominance only;
learn/roles.py:539; learn/features.py:65, 467; learn/folds.py:129-157; plane/tasks/features.py:202;
search/coordinator.py:426-484 and :487, search/worker.py:530, search/verify.py:714; plane/memory.py:833-843;
plane/delivery.py:167; receiver mode plane/egress.py:128-160, 233-324, plane/runner.py:829-840,
plane/reconciler.py:409-412, ops/ax/up.sh:121-124. Move push_inputs.py to benchmarks/push/ (callers
benchmarks/push/{measure,m1a_record_vetoes,transfer_replay}.py, tests/test_push_inputs.py).
Guards: do not touch mcp.py, map_gate.py, pair_gate.py, vetoes.py (parked or CI-bound, see
.kiro/breadth.toml); confirm each deletion with `grep -rnw <name> src tests benchmarks ops docs` before
removing; keep a table in the commit message of lines removed per package; re-run `fossil-mcp dead-code src
--min-confidence certain` at the end and expect zero.
```

## P1. One source-facts module (S1)
```
Plan `src/openultrasast/source.py` as the single owner of function ranges, enclosing function, function
bounds, call sites, product-file enumeration, declaration tables and language aliases, per
PATHFINDER-2026-10-13/02-duplication-report.md D4 and D5 and the facts table in 01-flowcharts/U5-semantic.md.
Entry points: `ranges(path, text, lang)`, `enclosing(ranges, line)`, `bounds(ranges, name)`,
`call_sites(text, names)`, `product_files(root)`, `facts_for(root, path, line, *, entry_points)`.
Implementation moves from semantic/functions.py (tree-sitter with the regex fallback at :120-133, sentinel
`<module>`, RESERVED_FUNCTION_LABELS :23-51, `_DECL` :56-69 merged with repo_facts DECLARATION :48-63 and
KEYWORDS :64-88 for Java, Go, Ruby, PHP). Call sites to rewrite: plane/tasks/repo_facts.py:30-146 (keep
main() and re-export the tables), plane/tasks/alerts.py:108-114, plane/tasks/verify.py:128-141,
learn/labels.py:48, learn/features.py:27, 49, 365-395, 415, learn/roles.py:35, learn/excerpt.py:35, 302,
plane/harvest.py:46, plane/generate.py:72, plane/tasks/remember.py:44, hunter_tools.py:83, 317-323,
benchmarks/valid/hunter_arm.py (annotation producer for hunter-learning-loop R3).
Guards: one sentinel and one reserved set, no compatibility shim beyond a one-release `function_at` alias;
before switching, regenerate labels-<sha>.jsonl with the old and the new module and diff them, and record
the diff in benchmarks/measurements/; do not add a registry of "range providers", a switch on language is
enough; nothing in source.py may read labels, advisories or commit messages (hunter-learning-loop R3.2).
```

## P2. One chat client, one meter, one resolver (S2)
```
Plan the collapse of the LLM client stack described in PATHFINDER-2026-10-13/02-duplication-report.md D1 and
D10 and 01-flowcharts/U6-hunter-client.md. Target: model/endpoint.py keeps one client class (rename
DeepSeekChatClient to ChatAdapter, usage as a list of rows, retry policy including the empty-JSON re-call
lives here and nowhere else) and one resolver `resolve_chat_client(config | None) -> (client, endpoint)`
that honours [models] and prices by the running model; plane/budget.py keeps one Meter with
`reserve(bound)`/`settle(row)` and one `cost(row, prices)`; learn/program.py Caller stays as the cache and
replay layer; provider/openrouter.py parse_json_content is the only JSON-in-fences parser.
Call sites: tool_hunter.py:36-39, 163-262 (delete OpenRouterHunterClient and the env-flag sets, keep
ScriptedChatClient and the ChatClient Protocol), 409, 581; cli.py:976 (pass a metered client);
push/assistance.py:84, 103-110; search/worker.py:153-165, 188-189, 218-270 (reserve-first mode of the
Meter; StubModel stays); learn/fill.py:44 (FillMeter deleted); learn/cli.py:241, 254; plane/tasks/verify.py:
66, 181, 232-244, 267, 378; model/scan.py:1628-1640; budget.py:59-60, 154-170, 260-322; endpoint.py:39,
135-144, 262; benchmarks/valid/hunter_arm.py:55-66 (shim deleted).
Guards: no new abstraction above ChatAdapter; do not keep OpenRouterHunterClient behind a flag; the only
behaviour change allowed is "hunter dollars are priced by the configured model", record it in the commit;
error messages carry exception types, never a key; run tests/test_hunter_arm.py,
tests/test_model_endpoint.py, tests/test_plane_budget*.py, tests/test_search_worker.py.
```

## P3. One quick-rule pipeline and the deadline type (S3 + S5)
```
Plan two mechanical consolidations from PATHFINDER-2026-10-13/02-duplication-report.md D3, D6 and W3.5,
W4.1, W4.3.
(a) `findings.quick_pipeline(root, targets=None, *, ruleset, policy, floors=None, include_shadow=False)
-> QuickRun(targets, entry_points, rankings, findings)` with an optional `stage(name, fn)` callback so
cli.py can keep run_stage. Call sites: cli.py:641-687, hunter.py:103-160 (keeps its pool, calls the
pipeline per target), gate.py:81-84, map_gate.py:52-54 (pass ruleset=PATTERN_RULES explicitly), pairs.py:
794-815, plane/tasks/alerts.py:120-122 (include_shadow=True), push/quick.py:87-92 (passes changed-file
targets), benchmarks/learn/build_features.py. Fix the standard-mode floors bug (cli.py:670 vs 683-684).
(b) Move ExecutionBudget (model/contracts.py:19-33) to contracts.py with expired(), remaining(),
cleanup_end, check(exc); make DeadlineExpired and remove_owned_tree public in deadline.py; rewrite the 66
budget expressions (push 47, model 13, cpg 16: snapshot.py:635, 642, scan.py:203, 1435, backend.py:1377,
1399, report.py:160, partitions.py:117-267, regions.py:313), cpg/backend.py:37, cpg/session.py:44,
model/partitions.py:14, cpg/artifact.py:151, push/cache.py:22. Then one `_run` in cpg/backend.py (merge
1514-1555 into 1414-1484 so standard scans harvest partial stdout) and one ARBITERS table for scan.py:
1491-1506 and pipeline.py:93-121 (closing the hook_callbacks divergence at taint.py:124-127).
Guards: no behaviour change except the two named bugs; gate numbers in benchmarks/measurements/
2026-09-06-gate-baseline.txt must not move; run the gate, map_gate, pair_gate and test_push_*, test_model_*,
test_cpg_* files.
```

## P4. Scan assembly: write once, score last, one ledger (S6)
```
Plan the rewrite of `_run_scan` (cli.py:619-959) per PATHFINDER-2026-10-13/01-flowcharts/U1-scan.md
"Likely bugs" and 02-duplication-report.md D9, W1.3-W1.5: findings accumulate per proposer and are written
once in a finally; scoring (cli.py:731-746) and verification (711) move after MAP (757-835) so model,
overlay, obligation and hunter findings are scored and verified; `CalibrationLedger(target)` owns
false_positive_learnings.json, rule_policy.json, complexity_ledger.json (cli.py:94, 635-636, 765, 872,
1021-1022; plane/tasks/loop.py:43 reads the same path); `runtime.degrade(stage, reason, detail)` on
HarnessRuntime replaces the 13 inline appends (cli.py:647-1446) and stages.skip_as_degradation;
`run.write_json` and `write_records` replace the 24 write_* wrappers; `benchmark.run_benchmark` is shared
by cli.py:1076 and mcp.py:160-183 so MCP benchmark runs write artifacts; fusion.py is deleted (cli.py:720-726,
fusion.json); harness.py processor machinery is deleted (41-55, 125-166, cli.py:627-632).
Guards: keep the finally write so a crash still leaves findings.json; the manifest and SARIF formats do not
change; add one test that a model-layer finding appears in score.json and verification.json; run
tests/test_scan_pipeline_integrity.py, test_reports.py, test_scoring.py, test_mcp.py, test_benchmark.py.
```

## P5. One sandbox verdict on the ladder (S4)
```
Plan the unification in PATHFINDER-2026-10-13/02-duplication-report.md D2 and
01-flowcharts/U9-search-sandbox-regress.md: search/_sandbox.run (:105) implements sandbox.SandboxRunner
(options move into SandboxJob, sandbox/runner.py:29-45); resolve_sandbox_runner (:59) chooses bwrap or
docker; one `ExecutionOutcome(outcome in confirmed|refuted|inconclusive|unavailable, reason, runs)` that
search/verify.py:648-701 produces and that emits Rung.EXECUTION_CONFIRMED (model/ladder.py:33) into the
evidence ladder so push_scoring.py:84, mcp.py:98 and learn/schema.py:77 receive execution evidence; the
canary oracle (oracles.py:30, 307) and the exit-code oracle remain two strategies. regress/ is already gone
(P0); the deep-mode REGRESS stage (cli.py:839-880) becomes a call into search's verify path for findings
that carry a demo, else a degradation.
Guards: do not keep the regress verdict vocabulary behind a flag; the differential 3-vs-3 rule and the 0
false proofs requirement of search-with-proof Req 6.2 are unchanged; the only new rung producer is the
verify path; run tests/test_search_verify*.py, test_sandbox*.py, test_push_scoring.py.
```

## P6. Memory store as a leaf; plane executor trimmed (S7)
```
Plan, per PATHFINDER-2026-10-13/01-flowcharts/U7-learn-memory-tasks.md "Memory→Plane inversion",
U8-plane-executor.md "Removal candidates" and 02-duplication-report.md W8.1-W8.5: move `seed`
(plane/memory.py:984-1020) to plane/seed.py and `results_root` to plane/paths.py so memory.py has no plane
import; delete plane/engine_alerts.py, harvest.py, workspaces.py, generate.py and their cli.py subcommands
(1570-1611, 1667-1700) after moving `declares` (harvest.py:116), `docker_command`, `frozen_source`,
`read_record`, `export_pin` (engine_alerts.py) into benchmarks/learn/, their only users; one
`Cli(executable, base_args, env, timeout).run(*args)` and `error_tail(proc)` in plane/ for
reconciler.py:185-228, egress.py:174-216, benchmarks/ax/batch.py:221-262; one `safe_extract(data, dest, *,
max_bytes, max_files)` for delivery.py:134-140, runner.py:500-504, search/executor.py:658-690,
search/verify_task.py:161-215; one `ObjectURL` client (no proxy, no redirect, bounded read, backoff) for
runner.py:719-790, search/executor.py:508-541, verify_task.py:240-270; redaction.py takes `values=` and
`urls=True` so router.redact (:50), task_storage.diagnostic (:100-120) and runner.safe_url (:713) are thin.
Guards: the two dispatch stacks stay two (decision deferred to plane-on-kubernetes); credentials still travel
only in the start POST body; nothing logs a URL with a query string; run tests/test_plane_*.py,
test_search_executor*.py, test_ax_batch.py.
```
