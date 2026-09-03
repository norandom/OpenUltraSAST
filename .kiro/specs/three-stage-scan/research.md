# Research & Design Decisions

---
**Purpose**: Capture discovery findings and architectural investigation behind the `three-stage-scan` spec. `design.md` carries the committed architecture; this file carries evidence and rejected alternatives.
---

## Summary
- **Feature**: `three-stage-scan`
- **Discovery Scope**: Extension of the existing scan harness (brownfield), with one new runtime prerequisite (Docker CLI for stage 3) and one new evaluation contract (split-sink / mutation corpora).
- **Key Findings**:
  - Stage 1 already exists as `quick` mode: preprocess, mapping, rank, `quick_scan_findings`, structural verify, score, SARIF. Do not rebuild it.
  - Stage 2 is not a hunter dump and is not `RankingScore`. Ranking is per-file attention. A complexity map is per-file-and-function hotspot attention plus test-gap hints. Existing signals (tags, loc, reachability hints, finding density, `has_fuzz_entry_point`) are enough for a heuristic map; the tool-using hunter refines it.
  - Stage 3 has config and a threat-model table, but `cli.py` exits on `--mode deep`. No container is ever started. The first execution of untrusted code must be Docker CLI with the documented isolation flags, not a Python SDK and not host `subprocess` of target code.
  - The previous HarnessX spec locked LLM use behind an optional extra that CI does not install. This spec uses the existing stdlib OpenRouter client so stage 2 can be evolutionary without that extra. HarnessX remains an optional runtime, not a prerequisite.
  - Cheat-sheet fixtures cannot gate stages 2–3. The Python fixture already documents a split-sink miss (`query` built on the prior line). That class of case becomes the quality bar.

## Research Log

### Existing scan pipeline and mode mapping
- **Context**: Whether to add `--stage` or reuse `--mode quick|standard|deep`.
- **Sources Consulted**: `src/openultrasast/cli.py` (`_run_scan`, mode choices), `README.md` maturity legend, `.kiro/specs/openrouter-sast-harness/requirements.md` (hunter pool, docker sandbox, dynamic analysis), `.kiro/specs/harnessx-self-improving-rulesets/design.md`.
- **Findings**:
  - `quick` is implemented and deterministic. `standard` schedules a hunter pool that calls `quick_scan_findings` unless HarnessX extra + hunter model are set. `deep` raises `SystemExit`.
  - OpenRouter spec already defined: quick = static + bounded LLM review; standard = sandboxed tool-calling hunters; deep = harness/fuzz/dynamic. Implementation never reached that.
  - Existing CI and README teach `--mode`. A parallel `--stage` flag would fork the contract.
- **Implications**: Map modes onto stages 1 / 1+2 / 1+2+3. Record `stages_requested` and `stages_completed` in the manifest so the three questions are explicit even if the flag names stay.

### Ranking vs complexity map
- **Context**: `rank.py` already scores files. Is stage 2 just ranking?
- **Sources Consulted**: `src/openultrasast/rank.py` (`heuristic_rank`, `composite_priority` = surface 0.5 + influence 0.2 + reachability 0.3), `preprocess.py` (`FileTarget` tags, loc, `has_fuzz_entry_point`), `mapping.py` (`analyze_entry_points`).
- **Findings**:
  - Ranking is file-level and exists to budget the hunter. It does not name functions, test gaps, or "tune your tests."
  - Tags already encode likely problem classes (`memory_unsafe`, `parser`, `network_entry`, `syscall_entry`). Loc ≥ 500 boosts influence. No nesting/branch signal. No test-file presence.
  - A hotspot that stage 1 missed (split-sink) can still rank high if the file is a reachable parser. That is the point of stage 2.
- **Implications**: Keep `RankingScore`. Add `ComplexityMap` / `Hotspot` with function identity when recoverable, test-gap hints, and a ledger overlay. Ranking still feeds hunter budgets; the map feeds humans and stage 3.

### Hunter: regex, HarnessX dump, or tools
- **Context**: Previous spec adopted HarnessX "at the hunter loop" but the default hunter is regex and the HarnessX path dumps source into a prompt.
- **Sources Consulted**: `hunter.py` (`_run_hunter_task` → `quick_scan_findings`), `hunter_harness.py` (`_describe`, `_extract_findings`), `provider/openrouter.py` (`OpenRouterChatClient.complete_json`, stdlib `urllib`), `harness_ext.py` (optional extra).
- **Findings**:
  - OpenRouter client is already zero-extra (stdlib). It is used for optional ranking, not for hunting.
  - HarnessX extra is SHA-pinned, heavy, absent in CI. Requiring it repeats the last spec's failure mode.
  - Clearwing hunters use `read_source_file`, `grep_source`, `find_callers` with path clamping. That is the evolutionary piece, not MetaAgent regex-status flips.
- **Implications**: Stage 2/3 hunter is a bounded tool loop over the OpenRouter client (or HarnessX if already wired). Tools are stdlib (read, Python grep, caller search from mapping + text). Path clamp at repo root. Hunter output evidence = `suspicion`.

### Docker sandbox: CLI vs SDK vs skip
- **Context**: Threat model already lists sandbox limits. Need a runner that does not invert zero-dep posture.
- **Sources Consulted**: `docs/threat-model.md` (sandbox table), `config.py` `SandboxConfig`, Clearwing `hunter_sandbox.py` (image build + spawn, Docker SDK), Docker isolation guidance (`docker run --network none --read-only --tmpfs --memory --pids-limit --cap-drop ALL --security-opt no-new-privileges`), initrunner docker-sandbox docs (CLI `docker run --rm --init`, optional `runsc`).
- **Findings**:
  - Python `docker` SDK would be a new core or extra dependency. The operator already has the Docker CLI if they can run containers.
  - Subprocess `docker run --rm --init` with bind-mount of the repo read-only and a tmpfs/scratch write area matches the threat model and keeps `dependencies = []`.
  - Unit tests must not require a daemon: inject a `SandboxRunner` protocol, ship a fake. Integration tests skip when `docker info` fails.
  - Full sanitizer-image builds (Clearwing) are out of scope for this spec. Stage 3 runs language-specific commands on a small pinned image per language family, or `inconclusive` if the recipe is missing.
- **Implications**: `SandboxProbe` + `DockerCliRunner`. No SDK. gVisor/`runsc` is optional `security-opt` when `docker info` reports it; not required.

### Evaluation corpora
- **Context**: User rejected cheat-sheet fixtures. Current gate is ≥90% recall on those fixtures.
- **Sources Consulted**: `benchmarks/fixtures/python-vulnerable/app.py` (line 77 split-sink comment), `javascript-vulnerable/src/app.js` (prototype pollution comment), `tests/test_detection_benchmarks.py`, `gate.py`.
- **Findings**:
  - Stage 1 smoke fixtures are still useful as unit tests. They must not be the stage 2/3 merge gate.
  - A split-sink corpus is small and owned: source and sink on different lines; mutations through wrappers/variables. Success = map ranks the true function in the top band; stage 3 triggers at least one stage-1 miss when Docker is present.
  - Comparing map ranking to "sort by pattern-hit count" is an anti-cheat-sheet test: if regex density is the map, the gate fails.
- **Implications**: New `benchmarks/fixtures/split-sink-*` and a stage-2 ranking gate. Keep existing `openultrasast.gate` for stage 1 only.

### Seams that already exist and must not be confused
- **Context**: Brownfield traps for a spec named "map" that also adds Docker.
- **Sources Consulted**: `skills.py` (`STAGES = ("map", "hunt", "verify", "fix")`), `mcp.py:68` (rejects `deep`), `reports.py:115` (`scan_exit_code`), `mapping.py` (no Java/Groovy AST), `config.py` (`SandboxConfig` parsed, never consumed by `_run_scan`), `rank.py` (`rank_targets_with_model` unused by CLI).
- **Findings**:
  - Trail of Bits skill routing already uses a stage named `map` (mapping-discipline skills: Semgrep/CodeQL/sharp-edge). That is not the complexity map. `stages.py` must not reuse `skills.STAGES`.
  - MCP scan tools reject `deep` and forbid docker/shell. This spec does not widen the MCP surface; deep is CLI/CI only.
  - `--fail-on` is implemented in `scan_exit_code`, not only argparse. `worth-fixing` must be added there.
  - Java/Groovy entry points are tag-only (`line=None` → `inferred-file-surface`). Hotspot `function_name` will often be empty on Java; the map must still rank the file.
  - `[sandbox]`, `[dynamic]`, `[evidence]`, and `[models].ranker` are loaded into resolved config and then ignored. Stage 3 consumes `SandboxConfig`; it does not invent a parallel sandbox TOML.
- **Implications**: Naming, MCP, fail-on, and Java identity are integration constraints, not new products.

### Evidence ladder honesty
- **Context**: HarnessX hunter stamped LLM JSON as `static_corroboration`. Original spec forbids reporting LLM-only claims as verified.
- **Sources Consulted**: `verification.py` (`verify_finding` accepts when reachability is not `unknown`), `hunter_harness.py` evidence_level assignment, openrouter requirements Evidence Ladder / Verification.
- **Findings**:
  - Pattern hits as `static_corroboration` is consistent with the ladder. LLM hits as `suspicion` is the missing rule.
  - `--fail-on verified` today means reachable + static corroboration. That remains the cheap PR gate. `--fail-on worth-fixing` is the rugged gate.
- **Implications**: Do not change CWE policy. Change hunter evidence. Add fail-on value. Report sections: Inventory, Complexity map, Worth fixing.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Map-then-prove on existing modes | `quick`/`standard`/`deep` = stages 1 / 1+2 / 1+2+3 | Smallest CLI blast radius; matches threat-model "deep executes in sandbox"; reuses preprocess/rank/findings | Two vocabularies (mode vs stage) until the manifest lists both | **Selected** |
| New `--stage` command family | Parallel CLI, leave modes as-is | Clearer naming | Forks CI; `deep` still a stub | Rejected |
| Clearwing-shaped full sourcehunt | Tool hunters + sanitizer images + PoC + patch | Highest detection efficiency | Fork in all but name; out of original non-goals | Rejected as this spec; remains the oracle |
| HarnessX-required agent loop | Stage 2/3 only run with the extra | Reuses last spec's seam | CI never installs it; last spec's failure | Rejected as a requirement; optional runtime only |

## Design Decisions

### Decision D1: Modes map to stages
- **Context**: Need a three-question scan without breaking CI that already passes `--mode`.
- **Selected Approach**: `quick`→stage 1, `standard`→1+2, `deep`→1+2+3. Manifest records both.
- **Rationale**: Evolutionary adoption of the CLI the project already shipped.
- **Trade-offs**: Operators must learn that `standard` now means "map" not "regex hunter pool." README must say so.

### Decision D2: Docker CLI subprocess, no SDK
- **Context**: Zero-dep core vs isolated execution.
- **Selected Approach**: `docker` binary via `subprocess`; probe with `docker info`; fake runner in unit tests.
- **Rationale**: Operator runtime, not a Python dependency. Matches threat-model flags.
- **Trade-offs**: Windows/macOS Docker Desktop variance; integration tests skip without a daemon.

### Decision D3: OpenRouter client for the tool hunter; HarnessX optional
- **Context**: Last spec hid the LLM behind an extra CI does not install.
- **Selected Approach**: Tool loop calls `OpenRouterChatClient` (or any `RankerClient`-shaped chat client) when `[models].hunter` is set. If HarnessX extra is present, `HxScanOrchestrator` may host the same tools; it is not required.
- **Rationale**: Evolutionary use of code already in tree. Stdlib HTTP.
- **Trade-offs**: Two possible runtimes until HarnessX is either used or ignored; tests mock the client.

### Decision D4: Complexity map is a new artifact
- **Context**: Ranking already exists.
- **Selected Approach**: `ComplexityMap` with `Hotspot` records. Ranking remains the hunter budget. Map is what humans and stage 3 consume.
- **Rationale**: Different question (where to look / how to test vs which file to hunt first).

### Decision D5: Worth-fixing is a gate, not an evidence level
- **Context**: Evidence ladder is already six rungs. Do not invent a seventh for CI.
- **Selected Approach**: Verdicts `triggerable|not_triggerable|already_covered|inconclusive` → `worth_fixing|not_worth_fixing`. Evidence levels unchanged. Hunter stays at `suspicion`.
- **Rationale**: CI owners need a fail-on that means "we proved it," without collapsing the ladder.

### Decision D6: Split-sink / mutation gate for stages 2–3
- **Context**: 90% recall on cheat sheets is circular.
- **Selected Approach**: New corpus + "beats pattern-hit ranking" test. Stage 1 smoke gate stays.
- **Rationale**: Directly answers the user's evaluation complaint.

### Decision D7: Ledger overlays hotspot scores, not patterns
- **Context**: Evolutionary feedback without repeating "loop must not edit patterns."
- **Selected Approach**: `.openultrasast/calibration/complexity_ledger.json` keyed by `repo_fingerprint + path + function`. Triggerable boosts, not_triggerable demotes. Cannot hide reachable severity-5 inventory from worth-fixing consideration.
- **Rationale**: Same overlay pattern as `rule_policy.json`, different object.

### Decision D8: Language recipes, not a universal executor
- **Context**: Running untrusted Python vs C vs Java is different.
- **Selected Approach**: Small recipe registry (Python and JavaScript required for MVP; C compile+run when a compiler exists in the image; Java `inconclusive` until a recipe ships). Missing recipe → `inconclusive`, not a crash.
- **Rationale**: Simplification. Do not build Clearwing's sanitizer image matrix in this spec.

## Synthesis

- **Generalization**: Inventory → attention → proof is one pipeline with a `StagePlan`. Map, hints, and regress are processors on that plan, not three products.
- **Build vs adopt**: Adopt Docker CLI and the in-tree OpenRouter client. Build the map, ledger, recipes, and split-sink corpus. Do not adopt Clearwing, docker SDK, or a cyclomatic-complexity library (nesting depth from indentation/braces is enough).
- **Simplification**: No `--stage` flag, no HarnessX requirement, no fuzz campaign, no patch oracle, no Python Docker extra.

## Risks & Mitigations
- Docker-in-Docker / rootless CI — probe, skip stage 3, degrade; do not fail stage 1.
- Hunter cost on large repos — hotspot cap + existing `[harnessx] max_cost_usd` / hardening `max_findings` / new `max_regress_candidates`.
- Untrusted snippet execution — structural deny (network, writes outside scratch, curl, docker socket mount). Never mount `/var/run/docker.sock`.
- Stage 2 still heuristic without a model — allowed; gate is ranking quality on split-sink, which heuristics can pass if tags+reachability work.
- Breaking `deep` from "exits" to "runs" — intended; document in README.

## References
- OpenUltraSAST threat model — `docs/threat-model.md`
- OpenRouter SAST harness requirements — Docker sandbox, hunter pool, evidence ladder
- HarnessX self-improving rulesets — adjacent governance; do not reopen
- Docker run isolation flags — `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`
- Clearwing sourcehunt hunter tools and sandbox — implementation oracle, not a dependency
