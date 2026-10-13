# Duplication report (2026-10-13)

Every claim was checked against the source by the phase-2 agents, not taken from the flowcharts. Paths are
relative to `src/openultrasast/` unless they start with `benchmarks/`. "First" dates are from
`git log --diff-filter=A` and give rough order only.

Verdict in one line: of ten candidate concerns, seven are real duplication (D1 to D5, D7, D10), two are one
owner missing (D8, D9), one is a misplaced type (D6). The three that matter most: D1 (LLM call and cost),
D4+D5 (enclosing function, callers, declaration tables), D3 (the quick-rule pipeline).

## Part A: concerns duplicated across features

### D1. Chat client, resolver and cost metering (accidental, highest value)
Where: `ChatClient` Protocol `.complete` (tool_hunter.py:163); `RankerClient.complete_json` (rank.py:31, tests
only). Clients: `ScriptedChatClient` (tool_hunter.py:176); `OpenRouterHunterClient` (203) drops `json_object`,
calls `complete_chat`, records no usage (222-223); `DeepSeekChatClient` (model/endpoint.py:91) uses
`complete_chat_raw`, keeps `usage` as a list (98), has its own retry on empty JSON (135-144);
`OpenRouterChatClient` (provider/openrouter.py:56, 69, 84). Wrappers: `MeteredClient` (plane/budget.py:68,
`usage` is a dict 95); `FillMeter(MeteredClient)` (learn/fill.py:44) reserves before each call; `Caller`
(learn/program.py:369) caches and replays, diffs `client.usage` as a dict (404-406); `_Recording`
(plane/tasks/verify.py:66); `_CountingClient` (model/scan.py:1628). Two resolvers: `resolve_hunter_client`
(tool_hunter.py:239) ignores config and prices against `DEFAULT_DETECTOR_MODEL` whatever model runs (258);
`resolve_chat_endpoint(config)` (endpoint.py:192) honours `[models]`; their OpenRouter branches build different
wrappers (tool_hunter.py:262 unmetered vs endpoint.py:221 metered). Duplicate env-flag sets tool_hunter.py:36-39
and endpoint.py:39. Four cost paths: `ChatEndpoint.cost` (endpoint.py:70-80; `cost_usd` 147; push/assistance.py:
103-110 inline); `cost_of` (budget.py:59, docstring: "the arithmetic of ChatEndpoint.cost") used by
`_absorb_rows` (158-167), `Caller.usd` (program.py:420-423), `verify._sum_usage` (232-244); `SpendBudget`/
`SpendReservation` (budget.py:260-322) with search/worker.py:218-270 repeating the DeepSeek `extra_body`;
`_CountingClient.cost_usd` (scan.py:1639). `_tokens` copied (budget.py:170, endpoint.py:262). Fallout: the
list-vs-dict `usage` mismatch needs the shim in benchmarks/valid/hunter_arm.py:56-65 ("made every live
classification fail while stubbed tests passed"); the CLI hunt passes the bare client (cli.py:976) so the
shipped scan's hunter spend is never metered.
Why: tool_hunter 09-03, endpoint 09-08, budget 09-29, program 10-01, fill 10-03, worker 10-05; each consumer
added the wrapper it needed (tool_hunter.py:240-244, 257; budget.py:263-266 "existing MeteredClient callers
retain their historical post-call metering").
Legitimate parts: the worker's hard reservation (fail-closed, `max_attempts=1` worker.py:188-189); `Caller`'s
replay cache; `ScriptedChatClient` as a test double. Accidental: two resolvers, two adapters, four cost
formulas, two usage shapes.
Unification: one `resolve_chat_client(config|None) -> (client, endpoint)`; one client class (today's
`DeepSeekChatClient`, renamed) with `usage: list[row]`; one `Meter` with `reserve(bound)`/`settle(row)` so
`MeteredClient`, `FillMeter` and the worker's `_call` are configurations (post-call vs reserve-first); one
`cost(row, prices)`; `Caller` stays as the cache layer; `_CountingClient`, `_Recording` become counters read
off the meter. Lost: calling OpenRouter unmetered; the hunter prices by its configured model (recorded dollars change).

### D2. Sandboxed execution for a verdict (runtime split legitimate, verdict split not)
Shared `SandboxJob`/`SandboxResult` (sandbox/runner.py:29-45; search/_sandbox.py:24; regress/candidate.py:15).
Runners: `DockerCliRunner.run` (sandbox/runner.py:67, 107-137) implements `SandboxRunner` (24);
`search/_sandbox.run` (105) is bwrap+seccomp with extra keyword-only args and does not satisfy the Protocol.
Probes: `resolve_sandbox_probe` (`docker info`, sandbox/probe.py:22-49) vs `_sandbox.isolation_check` (68).
Verdicts: regress `triggerable/not_triggerable/already_covered/inconclusive` + 14 reasons (regress/verdict.py:
10-26); search `demonstrated/inconclusive/no_oracle/could_not_run/could_not_build`, no negative
(search/verify.py:350-701); learn `vulnerable/not_vulnerable/unsure` (program.py:43, classification). Gap:
neither path produces `Rung.EXECUTION_CONFIRMED` (model/ladder.py:33; consumers push_scoring.py:84, mcp.py:98,
learn/schema.py:77), so the evidence ladder never receives execution evidence.
Why: regress/sandbox 09-03; _sandbox.py 10-05 for AX pods without Docker (docstring :1-8).
Unification: make `_sandbox.run` a `SandboxRunner` (options into `SandboxJob`) selected by
`resolve_sandbox_runner`; one outcome record `{outcome ∈ confirmed|refuted|inconclusive|unavailable, reason}`
that emits `Rung.EXECUTION_CONFIRMED`; keep two oracle strategies. Lost: nothing.

### D3. The quick-rule pipeline, re-implemented by each caller (accidental)
Each site runs preprocess → `analyze_entry_points` → `attach_reachability_hints` → `rank_targets` →
`quick_scan_findings` itself:

| Site | Ruleset | Shadow findings | Emit floors |
|---|---|---|---|
| cli.py:643-687 | `load_ruleset` + target ledger (634-638) | filtered (691) | quick/deep only; the standard pool skips them (670 vs 683-684) |
| gate.py:81-84 | None → `PATTERN_RULES` | not filtered here | no |
| map_gate.py:52-54 | `PATTERN_RULES` | not filtered | no |
| pairs.py:794-801, 815 | param | filtered | no |
| plane/tasks/alerts.py:120-122 | `PATTERN_RULES` | kept on purpose (docstring :5) | no |
| improve/evolve.py:311-315 | param | filtered | no |
| push/quick.py:87-92 | `PATTERN_RULES` | filtered; no preprocess, targets from changed files | no |
| hunter_tools.py:232 (`flows`) | None | filtered | no; re-runs preprocess per tool call (307), uncached |
| hunter.py:151 | pool | per task | no |

Plus benchmarks/learn/build_features.py and benchmarks/measurements/2026-09-30-php-quick-rules/measure_php_quick.py.
Legitimate differences: push's changed-files target set; alerts keeping shadow findings. The divergent ledger
and floors mean a gate measures different rules from what `ousast scan` ships.
Unification: one `quick_pipeline(root, targets=None, *, ruleset, policy, floors, include_shadow=False) ->
(targets, entries, rankings, findings)`; cli wraps steps in `run_stage` through a callback. Lost: nothing;
gates pass `ruleset=PATTERN_RULES` explicitly to keep today's numbers.

### D4. Enclosing function, function spans and callers (two naming systems, accidental)
Tree-sitter path: semantic/functions.py `_DECL` (56-69), `RESERVED_FUNCTION_LABELS` (23-51), sentinel
`<module>` (20), `function_at` (136); docstring (1-9): "the single source of that naming. Every consumer must
therefore name ranges the same way, or function-scoped matching silently fails". Used by hunter_tools
`_named_span` (317-323), overlay, pairs, model/candidates. Regex path: plane/tasks/repo_facts.py `DECLARATION`
(48-63), `KEYWORDS` (64-88), sentinel `<global>` (34), `enclosing` (131), `declared_functions` (118),
`call_sites` (154); used by plane/tasks/alerts.`function_at` (108-114); learn/features
`FeatureContext.function_at` (365-370), line-for-line the same as the alerts copy; learn/excerpt
`function_bounds` (302) with its own brace matcher; learn/labels.py:48, learn/roles.py:35, plane/harvest.py:46.
Two caller indexes: `repo_facts.call_sites` (154) written to facts.json (301), read by `verify.callers_of` (128)
accepting two facts shapes (131-141); `learn/features.callers()` (372-395) with a separate `_CALL` regex (49).
`hunter_tools.find_refs` (83) is a plain `\bsymbol\b` grep. `mapping.analyze_entry_points` (123) is the single
source for entry points, recomputed per caller (nine D3 sites plus learn/features.py:415, push/runner.py:123).
Why: functions.py 09-05 for the pair scorer; repo_facts.py 09-29 as a pod task avoiding tree-sitter, so learn
imported it. functions.py already has a regex fallback (120-133). Two sentinels and two keyword sets mean labels
(`<global>`) and scorer ranges (`<module>`) can name the same function differently, the exact failure
functions.py:6-8 warns about.
Unification: one `functions` module with `ranges(path, text, lang)` (tree-sitter, regex fallback),
`enclosing(line)`, `bounds(name)`, `call_sites(names)`, one sentinel, one reserved set; `repo_facts` re-exports
it so the runner still finds the task by name. Lost: Java/Go/Ruby/PHP patterns in DECLARATION must merge into
`_DECL` or labels change; re-label and diff before switching.

### D5. Declaration tables, product-file filter, language detection (accidental)
Product-file filters: `repo_facts.product_files` (96-115, rglob, own `_EXCLUDED_DIRS`/`_NOT_PRODUCT` 36-43,
`LANGUAGES` 33) vs `preprocess.enumerate_source_files` (96-100, 240, `git ls-files`); excluded-dir lists also at
preprocess.py:9 and model/partitions.py:194. Language detection: `preprocess.detect_language`/
`LANGUAGE_BY_EXTENSION` (11, 130) is the one extension map (push/runner.py:219-226, regress/candidate.py:14);
`learn/excerpt.resolve_language` (200) sniffs; alias maps at semantic/facts.py:18, semantic/obligations/facts.py:21,
model/candidates.py:49; language enumerations at learn/schema.py:54, repo_facts.py:33. The tables are imported
by learn/labels, features, roles, excerpt; plane/harvest, generate (`_digest` 72), remember (44); plane/tasks/
alerts, features: this is the Learn↔PlaneTasks cycle.
Unification: move `DECLARATION`/`KEYWORDS`/`product_files`/`_digest` into a neutral `source.py` or D4's module;
one `LANGUAGE_ALIASES` beside `LANGUAGE_BY_EXTENSION`. Lost: nothing; the cycle goes away.

### D6. Contracts and the CPG↔Model cycle (layered by design, one type misplaced)
contracts.py:1-93 generic `Contract`; model/contracts.py 12 classes (19-205); push/contracts.py 9 classes
(18-161) building on `QuestionIdentity`/`ScopeDecision` (14). Layered, not duplicated. The cycle is
`ExecutionBudget` only (model/contracts.py:19-33; cpg/backend.py:37, cpg/session.py:44); reverse direction
private names `_DeadlineExpired`/`_remove_owned_tree` (cpg/backend.py:1554) imported by model/partitions.py:14,
cpg/artifact.py:151 (lazy) and push/cache.py:22 (missed by the flowcharts). Budget types `ScanBudget`
(scan.py:79), `HunterBudget` (hunter.py:19), `SearchBudget` (search/budget.py:8), `SpendBudget` (budget.py:260),
manifest `Budget` (plane/manifests.py:185) cover different quantities: legitimate.
Unification: move `ExecutionBudget` and public `DeadlineExpired`/`remove_owned_tree` into contracts.py or a
`deadline.py`. Lost: nothing.

### D7. Reachability multipliers and severity (accidental constants, legitimate severity split)
Same dict at scoring/project_score.py:15 `REACH_MULT` and calibration.py:255 `_BASE_REACH_MULT` (both
06-17/22). The set `{"reachable","inferred-file-surface"}` at regress/verdict.py:28 and complexity/ledger.py:23;
produced once at findings.py:164. Severity: policy-derived via `SEVERITY_LABEL` (findings.py:39) for quick rules
(132) and overlay (overlay.py:134); hard-coded "medium" for model-layer findings (cli.py:1373); LLM's own or
"medium" for the hunter (tool_hunter.py:35, 619); sensitivity-mapped for obligations (check.py:162).
Unification: calibration imports `REACH_MULT`; one `REACHABLE_STATUSES`; `resolve_severity` whenever a family
maps to a CWE. Lost: nothing.

### D8. Hotspot construction for the hunter (legitimate inputs, no constructor)
`Hotspot` (complexity/map.py:20-28, `band` documented "high | medium | low") built by `_hotspot_from_signals`
(62-102), plane/tasks/verify.py:180-186 with `band="candidate"` (outside the vocabulary), and
benchmarks/valid/hunter_arm.py:233-242 with `band="low"`. Unification: `Hotspot.for_file(path, function=None,
rationale, band="low")` or let `run_tool_hunter` take `(path, function)` targets. Lost: nothing.

### D9. Result and record writers (accidental sequencing, one owner missing)
`findings.json` written at cli.py:708, 788, 801, 814, 877, 1005 after each proposer; merge-by-id dedup repeated
(784-787, 989-1000). Writes into the scanned repo all come from `CALIBRATION_DIR` (cli.py:94):
`false_positive_learnings.json` (635, 1021-1022), `rule_policy.json` (636; improve 1137),
`complexity_ledger.json` (765, 872), `rule_signals.json` (improve/evolve.py:173-174), `improve_journal.json`
(1141-1144); plane/tasks/loop.py:43 re-declares the path. The plane `MemoryStore` (memory.py:267) is a separate
store that knows nothing of these. Unification: accumulate findings per proposer, write once in a `finally`
(and move scoring after the merge, fixing the U1 bug); one `CalibrationLedger(target)` owns the five files.
Lost: partial findings.json on a crash unless the finally write stays.

### D10. Other
- JSON-in-fences parsers: provider/openrouter.py:205 `parse_json_content` (raises; used by program.py:326,
  compile.py:264, worker.py:329); tool_hunter.py:581 `_load_json` (returns None); tool_hunter.py:409
  `_looks_like_json`. `cpg/backend.extract_payload` (203) is not a duplicate (Joern BEGIN/END markers, partial
  bodies). Fix: tool_hunter wraps `parse_json_content`.
- Retry: one helper `call_with_retry` (openrouter.py:34, used 115, 168); the duplication is in policy:
  DeepSeek's empty-JSON re-call (endpoint.py:135-144) makes up to 2×3 attempts; `bounded()` (103-113) and the
  worker (worker.py:188) force one attempt. One policy on the client.
- `resolve_*` factories (tool_hunter.py:239, endpoint.py:192, sandbox/runner.py:59, sandbox/probe.py:49,
  cpg/backend.py:1813): legitimate pattern; only the first two overlap (D1).
- Two evidence vocabularies on one record: `StaticFinding.evidence_level` (findings.py:139, overlay.py:115,
  tool_hunter.py:621, check.py:164) and `rung` (findings.py:34-35: "the older overlay pipeline's word"). Fold into `rung`.
- Excerpt helpers `hunter_tools.read_definition` (174) and `learn/excerpt.function_bounds` (302): covered by D4.

Confidence: high on D1, D3, D4, D6, D7, D9; medium-high on D2, D5, D8. Unverified: whether
`evaluate_benchmark` filters shadow findings for the gates; `MeteredEmbeddingClient`/`UnmeteredUsage`
(budget.py) as a fifth metering path; callers of `resolve_chat_endpoint` beyond push/assistance.py:84 and
learn/cli.py:254.

## Part B: repetition inside the big units (22 items, about 650 to 800 lines; four are correctness risks)

Correctness risks first: an unbounded Joern path drops partial answers on timeout (W4.3); plane uploads follow
redirects while search uploads refuse them (W8.2); the advisory engine findings are deduplicated differently in
the background summary and the terminal report (W3.3); evaluate builds folds differently from experiments (W7.2).

### U3 push/
- **W3.1 Git command prefix twice.** `["git","-c","protocol.allow=never","-c","core.hooksPath=…","-C",repo,*args]` at snapshot.py:94 (`_git`, subprocess.run, 10 s) and :570 (`_bounded_git`, Popen+selector); `_git` already routes through `_bounded_git` when a budget exists (83-91) and `_repository_path` (74-79) fakes a 10 s budget. Fix: one argv constant, then always `_bounded_git`. ~20 lines.
- **W3.2 Two forked-child helpers.** `_prepare` (runner.py:56-115: os.pipe, selector, pickle, 32 MiB cap) vs `_save`/`_write_artifact` (report.py:120-199: multiprocessing.Pipe); identical finally blocks (runner.py:107-115, report.py:190-199). Fix: `run_forked(fn, *, until, output_cap)`. ~35 lines.
- **W3.3 Advisory engine filter twice, different dedup keys.** `background._summary` (background.py:113-145) dedups on (family, path, line); `report._advisory_engine_lines` (report.py:241-265) on `defect_id`. Counts can differ for one push. Fix: `is_advisory(disposition)` + one key. ~15 lines.
- **W3.4 Two "scan complete" checks that disagree.** `report._completed_scan` (108-117) vs `policy.compare_evidence.complete` (policy.py:502-512; allows tier_zero deferrals); push/contracts.py:64 a third partial copy. Fix: one `scan_complete(scan, *, allow_tier_zero)`. ~15 lines.
- **W3.5 Budget arithmetic written out 66 times** across 14 files (push 47, model 13, cpg 16); `ExecutionBudget` (model/contracts.py:19-32) has no methods. Existing copies: snapshot.py:635, 642; scan.py:1435; backend.py:1377, 1399; report.py:160; partitions.py:117, 183, 188, 205, 253, 267; regions.py:313; scan.py:203. Fix: `expired()`, `remaining()`, `cleanup_end`, `check()` on `ExecutionBudget`, landing with the D6 move. ~40 lines.
- Unreachable: none at def level. vetoes.py (533 lines) only under `--experimental-record-vetoes` in replay; callers runner.py:49, benchmarks/push/m1a_record_vetoes.py:32, transfer_replay.py:37, tests. `GraphLease` Protocol (cpg/artifact.py:70) only tests/test_push_contracts.py.

### U4 model/ + cpg/
- **W4.1 Arbiter chosen by spec type three times**: `scan._grouped` (scan.py:1491-1506), `pipeline._arbitrate_all` (93-98), `pipeline._arbitrate` (117-121); identical `request_params(spec, *, function, file)` in taint.py:22, dominance.py:30, config_value.py:22; three row normalisers (taint._flows 178, dominance._operations 144, config_value._settings 125) and three `_location` builders (taint.py:297, dominance.py:124, config_value.py:96). Fix: `ARBITERS = {TaintSpec: Arbiter(...)}` table + shared `_rows`, `_site`. ~45 lines. Divergence: `_grouped` passes `hook_callbacks`, `field_parameter_sources` (1498-1505) but `taint.verdicts` (taint.py:124-127) does not, so the single-query fallback (scan.py:519) asks a different question from the batch.
- **W4.2 Three build routes in `_build_impl`** (backend.py:573-664): "frontend → None ⇒ dispose; `_apply_overlays`" twice (630-638, 648-653); unparsed warning twice (618-619, 654-655); `CpgResult(...)` twice (622-630, 656-664). Fix: `_frontend_or_none()`, `_result(paths, unparsed, dispose)`. ~30 lines. Bug candidate: the joern-parse retry (648) calls `_build_with_frontend` without `exclude`, so vendored trees are included on retry.
- **W4.3 `_run` vs `_run_bounded`** (backend.py:1514-1555 vs 1414-1484): same Popen/`_jvm_env`/communicate/group kill; the unbounded `_run` returns None on timeout and never calls `_partial_stdout`, so the partial-answer harvest at `_batch_once` (1247) works only under a budget. Fix: one `_run(command, timeout, cwd)` with deadline `min(timeout, budget.remaining())`. ~35 lines.
- **W4.4 `query` (1285-1316) vs `_batch_once` (1193-1281)**: same script check, session-or-`joern --script`, `_run`, `_engine_failure`, `extract_payload`, `_time_available`. Fix: `_invoke(cpg_path, query, params, *, harvest)`. ~25 lines.
- **W4.5 Shard merges** `query_across` (933) / `query_batch_across` (951). ~8 lines.
- Unreachable, new: `pipeline._arbitrate` config and taint branches (119-121; only caller 96 is inside `isinstance(spec, DominanceSpec)`), so `config_value.verdict` (90) and `taint.verdict` (72) are test-only; `taxonomy.hierarchical` (76) no caller at all; `taxonomy.related` (80) tests only. Confirmed: model/report.py `SliceRow`, `overfitting_gap`, `render_findings` tests only; model/audit.py no src importer.

### U7 learn/
- **W7.1 Repository-cluster bootstrap four times**: `evaluate.cluster_bootstrap` (318-337), `experiments._group_bootstrap_precision` (1107-1122), `experiments.paired_bootstrap` (673-706), `calibrate.check` (198-213); percentile rule inconsistent (`int(q*(n-1))` thrice vs `round` in calibrate._percentile 192). Fix: `cluster_resample(groups, rng)` + `percentile_ci(values, alpha)`. ~45 lines, one quantile rule.
- **W7.2 Compile split and folds three times**: learn/cli.py:312-313, compile.py:367-370, experiments.program_folds (458-463); cli and compile ignore a configured `k`, only compile calls `assert_disjoint`, experiments reads `k`. Fix: `folds.evaluation_folds(memory, cfg) -> (split, folds, digest)`. ~10 lines, closes an evaluate/experiment mismatch.
- **W7.3 JSONL readers five times**: `examples.read_jsonl` (333), plane/tasks/features._jsonl (188), remember._jsonl (156) byte-identical; loop.py:227 inline; typed `experiments.read_units` (440), `memory.read_memory` (956). Fix: one `read_jsonl`. ~15 lines.
- **W7.4 `run` (899-996) vs `run_rule` (1035-1096)**: `_checked_units` copied at 921-930 vs 1021-1032; summary `put_row` duplicated 989-995 vs 1088-1094; the row header repeated at 393, 521, 862-866, 990, 1093, 1305-1309. Fix: call `_checked_units`; `_experiment_row(manifest, pin, task, **extra)`. ~35 lines.
- **W7.5 SourceGuard vs improve.memory.Guard: not duplicates** (path allowlist vs row exclusion).
- Unreachable: `roles.load_roles` (539) no caller; `features.language_of` (65) no caller (new); `folds.leave_one_*` (129, 138) only tests/test_learn_retrieve.py:169-170; `features.build_for_scan` (467) only tests/test_learn_roles.py:180; `plane/tasks/features.recorded_case` (202) tests only. `program.prepare_ensemble` is live (program.py:521).

### U8 + U9 plane/, search/, benchmarks/ax
- **W8.1 Safe tar extraction five times**: `delivery.collect` (delivery.py:134-140) and `egress.Receiver.accept` (egress.py:278-284) byte-identical; `runner._export` (runner.py:500-504, `filter="data"`); `executor.unpack_checkout` (executor.py:658-690, size/count/.git caps); `verify_task.extract_checkout` (161-215, gzip cap). The plane copies have no size cap and no `filter="data"`. Fix: one `safe_extract(data, dest, *, max_bytes, max_files, allow_dirs)`. ~50 lines.
- **W8.2 Presigned PUT/GET with different redirect handling**: plane `runner.deliver`/`fetch` (719-790) follow redirects; `search/executor.URLTransport` (508-535) no proxy + NoRedirect; `verify_task.upload` (262-270) its own `_NoRedirect`. Fix: one `ObjectURL` client (no proxy, no redirect, bounded read, backoff). ~60 lines.
- **W8.3 Presigning: one store API, two layouts**: `Delivery.body` (delivery.py:95-111, `runs/<run>/<task>/`) vs batch.py:289-304, 716-723 (`engine-queue/...`). Part of W8.4.
- **W8.4 Two task-dispatch stacks**: plane (reconciler `Ax` 185-228 → Router POST → plane/runner 1,037 lines → tar PUT → `Delivery.collect`) vs search (batch.py `lane.ax` 241-262 → `SearchExecutorTask` 675-800 → `search/executor.serve` 622 → part PUTs). Four CLI wrappers: `reconciler.Ax._run` (188; no timeout, no KUBECONFIG, no `--atespace`), `batch.ax` (241-262), `egress.Egress._run` (174), `batch.check_cluster_health` (221); three error tails. First step: one `Cli(executable, base_args, env, timeout).run(*args)` + `error_tail(proc)` in plane/ (~40 lines). Merging the stacks is a phase-3 decision.
- **W8.5 Redaction three ways**: `router.redact` (router.py:50, exact values), `redaction.redact_secrets` (redaction.py:38, patterns, `***REDACTED***`), `search/task_storage.diagnostic` (100-120, own `sk-`/`gh*_`/`Bearer` regexes, `[redacted]`); `runner.safe_url` (713) URL-only. runner.py:621 imports `router.redact` (not a copy). Fix: `redaction.py` takes `values=`, `urls=True`. ~20 lines.
- Unreachable: receiver delivery mode (reconciler.py:409-412, egress.py:233-324, runner.py:829-840; `OUSAST_DELIVERY` set by no script, ops/ax/up.sh:121-124 still creates the Service); `delivery.put_input` (167) tests only; `coordinator.BatchExecutor` (426) tests only; `memory.purge` (836) + `delete_version` (833) tests only; `memory.drop_rows` (399) used by benchmarks/learn/build_features.py.

### U1 + U2 cli.py and core
- **W1.1 Argument plumbing**: `_main` (cli.py:426-470) unpacks the namespace for `_scan` (4), `_benchmark` (3), `_improve` (14, 432-447), `_pairs` (6), `_repos` (4). Fix: `set_defaults(func=…)`, handlers take `args`. ~45 lines.
- **W1.2 "Is a file" guards** at 1077-1078, 1123-1124, 1128, 1184-1185. Fix: `type=existing_file`. ~10 lines.
- **W1.3 `_benchmark` vs `mcp._benchmark`** (mcp.py:160-183): the MCP copy skips `runtime_seconds`, `baseline_findings`, `write_benchmark_artifacts`, so MCP benchmark runs leave no artifacts. Fix: `benchmark.run_benchmark(manifest, config, mode)` used by both; inline `_load_scan_findings` (1499). ~20 lines.
- **W1.4 Degradation recording 13 times** (cli.py:647, 698, 773, 817, 843, 996, 1312, 1330, 1343-1344, 1411, 1427, 1445-1446), mixing raw dicts and `stages.skip_as_degradation` (stages.py:32). Fix: `runtime.degrade(stage, reason, detail)`. ~15 lines.
- **W1.5 `write_*` wrappers of one json.dumps** (24 sites in 19 files: findings.py:113, verification.py:121, mapping.py:240, 245, config.py:256, rank.py:72, calibration.py:185, 190, overlay.py:126, preprocess.py:90, regress/candidate.py:222, complexity/map.py:57; inline cli.py:726, 746, 1713; `_write_json` in reconciler.py:76 and repo_facts.py:211). Fix: `run.write_json`, `write_records`. ~35 lines.
- **W1.6 Run-dir creators** run.py:18-26 vs benchmark.py:185-190 (~6 lines). **W1.7 findings.json six writes** (~5 lines).
- Unreachable, each only one test file: `calibration.compute_ranking_metrics`, `findings.build_quick_hunter_prompt`, `verification.validate_evidence_transition`, `fusion.should_fuse`, `harness.ProcessorSpec` (+ `_run_processor`, `_contract_violation` with no reference at all), `rank.rank_targets_with_model`, mapping's five task/record functions.

Confidence: high for W3.2-W3.4, W4.1-W4.4, W7.1-W7.4, W8.1, W8.2, W8.5, W1.1-W1.5 and the unreachable
list (name greps across src, tests, benchmarks, ops; dispatch-table or getattr calls would be missed); medium
for W8.4 and the line estimates. The `hook_callbacks` divergence, the missing `exclude` on retry, the redirect
handling and the plane tar limits come from reading, not from running anything.
