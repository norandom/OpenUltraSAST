# Feature inventory, src/openultrasast (2026-10-13)

199 Python files, 51,860 lines (ast count; `wc -l` with blank lines says 60k). Discovery used an ast import
resolver over every module (about 690 internal edges). The four active lines come from
`.kiro/steering/overview.md`, section 2026-10-13: hunter-learning-loop, pre-push-safety-net,
search-with-proof, engine-change-scoped-analysis.

## Map units (what the flowcharts cover)

| Unit | Features | Purpose | Entry points | Core files | Lines | Active line |
|---|---|---|---|---|---|---|
| U1 Scan and reports | F1 | `ousast scan` quick/standard/deep, run artifacts, SARIF and markdown | cli.py:226 parser, cli.py:613 `_scan`, cli.py:619 `_run_scan`; mcp.py:62 | cli.py (613-1075), stages.py, run.py, harness.py, verification.py, fusion.py, reports.py, scoring/, calibration.py, provenance.py, profiling.py | ~2,000 + part of cli.py | none directly (feeds the pre-push quick tier) |
| U2 Shared core | F2 | file enumeration, regex quick rules, CWE policy, ranking, config, contracts, mapping | quick-rule pool `run_hunter_pool` cli.py:670 | config.py, contracts.py, redaction.py, preprocess.py, findings.py, rank.py, policy/, ruleset/, mapping.py, hunter.py (regex pool, not the LLM hunter) | ~3,030 | all, indirectly |
| U3 Pre-push hook | F3, F3b | advisory head-vs-base check on pushed commits; evaluation instruments | cli.py:143 parser, cli.py:523 `_hook_main`, cli.py:529 `_pre_push`; push/install.py; push_inputs.py:143, push_scoring.py:280 | push/*.py, push_inputs.py, push_scoring.py | 5,536 | pre-push-safety-net |
| U4 Engine (CPG + model layer) | F4, F6 | Joern graph build and session; arbitration of detector claims (taint, dominance, config, evidence ladder) | `ousast model candidates` cli.py:306; cli.py:1286 `_run_model_layer`; cli.py:1304 lazy | cpg/*.py, model/*.py (minus endpoint.py) | 7,764 | engine-change-scoped-analysis, pre-push-safety-net |
| U5 Semantic layer | F5, F13 | tree-sitter CST/IR, fact tables, overlay, taint, obligations; complexity hotspots for MAP | cli.py:82, 90, 1403-1442 (lazy) | semantic/*.py, semantic/obligations/*.py, complexity/*.py | 4,301 | engine-change-scoped-analysis |
| U6 LLM hunter and model client | F7 (+ model/endpoint.py, plane/budget.py) | tool-calling LLM hunter over hotspots, its tools, the chat client, metering | cli.py:962 `_attach_tool_hunter`, cli.py:982; plane/tasks/verify.py:29; benchmarks/valid/hunter_arm.py:245 | tool_hunter.py, hunter_tools.py, provider/openrouter.py, model/endpoint.py, plane/budget.py | ~1,700 | hunter-learning-loop |
| U7 Learn harness, memory store, plane fact tasks | F8, F10, F9b | labels, examples, features, roles, compile, evaluate, experiments, leak audit; the row/blob store; fact-producing tasks | learn/cli.py:18-89; cli.py:315 `learn labels`; plane/tasks/*.py `__main__` | learn/*.py, plane/memory.py, plane/tasks/*.py | 11,350 | hunter-learning-loop |
| U8 Plane executor | F9 | run manifests on the ax cluster: reconciler, router, runner, egress, harvest | cli.py:326-379 `plane ...`, cli.py:1530; plane/runner.py:989 (container PID 1); plane/profile.py:257 | plane/reconciler.py, runner.py, generate.py, manifests.py, harvest.py, egress.py, delivery.py, router.py, doctor.py, profile.py, engine_alerts.py, workspaces.py | 4,885 | hunter-learning-loop (runs its tasks) |
| U9 Search with proof, sandbox, regress | F11, F12 | coordinator, worker, executor, differential verification in a sandbox; deep-mode regress verdicts | `__main__` in search/coordinator.py:487, worker.py:530, executor.py:691, verify.py:714; benchmarks/search/pilot_run.py:39-47; cli.py:66, 80 | search/*.py, sandbox/*.py, regress/*.py | 5,352 | search-with-proof |
| U10 Periphery | F14, F15, F16, F17 | improve lever; pair corpus, benchmark manifests, pinned repos; CI gates; MCP server and skill router | `ousast improve` cli.py:237; `benchmark`/`pairs`/`repos` cli.py:232/283/296; gate.py:184, map_gate.py:118, pair_gate.py:80; `ousast mcp` cli.py:305 | improve/*.py, pairs.py, benchmark.py, repos.py, gate.py, map_gate.py, pair_gate.py, mcp.py, skills.py, index.py | 4,429 | pairs feed hunter-learning-loop labels; the rest none |

## Edges that matter (feature → feature, heaviest sites)

- Pre-push → Model: push/policy.py:18-23, push/runner.py:23-27, push/vetoes.py:24-25. Pre-push → CPG: push/runner.py:20-21, push/cache.py:21-22. Pre-push → LLM client: push/assistance.py:18.
- Model → CPG: model/scan.py:30, model/pipeline.py:30, model/taint.py:17. **CPG → Model (cycle)**: cpg/backend.py:37, cpg/session.py:44 import `model.contracts`.
- Core → Model (cycle, lazy): findings.py:86 → model.partitions; preprocess.py:255 → model.layout.
- Learn → Memory and budget: learn/compile.py:39-40, learn/program.py:35-36. Learn → plane tasks: learn/features.py:27, learn/labels.py:48, learn/roles.py:35. **Plane tasks → Learn (cycle)**: plane/tasks/features.py:34, plane/tasks/roles.py:33-34, plane/tasks/remember.py:42.
- **Memory → Plane (layering inversion, lazy)**: plane/memory.py:933, 989, 1002 import the reconciler and tasks.loop.
- Search → Memory and budget: search/coordinator.py:22-23, search/board.py:18, search/worker.py:17. Search → sandbox: search/_sandbox.py:24, search/executor.py:32.
- Improve → Memory: improve/memory.py:49, 464. Improve → pairs: improve/evolve.py:21, 71.
- MCP → scan: mcp.py:63, 164 (lazy import of cli). skills.py is imported only by hunter.py:139 (lazy).

## Ambiguous ownership (discovery's findings, kept for phase 3)

1. model/contracts.py is shared by cpg, push and model and causes the CPG↔Model cycle; contracts.py and push/contracts.py are siblings.
2. model/endpoint.py is an LLM client that imports tool_hunter; used by learn, plane/budget, search/worker, push/assistance.
3. plane/budget.py is metering used by learn, search and plane tasks.
4. plane/memory.py is a shared store that imports the plane reconciler and loop lazily.
5. plane/tasks/{repo_facts,roles,features,alerts}.py are fact producers that learn imports and that import learn.
6. mapping.py (1,087 lines) serves scan, push, gates, pairs, hunter_tools, learn and model.
7. Name collisions: hunter.py (regex pool) vs tool_hunter.py (LLM); harness.py (scan trace config) vs the learn harness; calibration.py (scan feedback) vs learn/calibrate.py.
8. push_scoring.py and push_inputs.py sit at top level but belong to pre-push evaluation.
9. regress/ (deep mode) and search/ (proof arm) both run code in the sandbox for a triggerable verdict.

## Standalone modules (no internal importer except cli.py or tests)

No importer at all: model/audit.py, push_inputs.py, map_gate.py, plane/runner.py (container entry), plane/tasks/agree.py, plane/tasks/features.py, search/worker.py, search/probe.py (driven by benchmarks/search/pilot_run.py:43, 47).
Only via package `__init__`: policy/verycode.py, semantic/prove_filter.py, scoring/project_score.py, regress/candidate.py, sandbox/probe.py.
Imported only by cli.py: calibration, fusion, harness, hunter, improve, learn.cli, mcp, model/report, pair_gate, plane/engine_alerts, plane/harvest, plane/tasks/remember, plane/workspaces, profiling, provenance, regress, reports, stages, semantic/obligations/intent.

## Gaps

Discovery did not read tests or the spec directories; cli.py line ranges per feature are approximate; where the
measured "LLM hunter" runs in the plane (likely plane/tasks/verify.py:29) is unconfirmed.
