# Research & Design Decisions

## Summary

- **Feature**: `pair-corpus-honesty`
- **Discovery Scope**: Extension of the pair catalog, scorer, and harvest; supersedes `real-world-vfc-slice`
- **Key Findings**:
  - The overlay scorer ignores `coverage`. The Java sqli vuln file already produces a coverage record on `prepareCall` from a servlet source; the scorer reports MISS.
  - The overlay column equals the inventory column on all 176 vfc pairs because C facts have no memory sink, so every proposal is `flow_incomplete` and the scorer falls back to inventory. The dashboard cannot show engine progress until the scorer reports parser and adjudication loss explicitly.
  - Harvest anchors on the first textual occurrence of the function name. For curl that is the doc comment mention (`Curl_follow()`), so 25 pairs start mid-comment and fail to parse.
  - 129 of 176 vfc expected rows have `sink = "unknown"`; 4 have a rule id. Matching degrades to CWE equality.
  - Real-Vuln-Benchmark (Apache-2.0) ships 66 pinned Python web repos, 40 of them LLM-generated, with file, line range, function, primary and acceptable CWEs, severity, authorship, and 120 false-positive traps. It is the only released corpus with an authorship column.
  - SecBench.js ships 600 npm vulnerabilities with `fixCommit`, `fixedVersion`, and `sinkLocation`, but no license file. Pointer plus harvest from upstream repos only.
  - GitHub commit search for a Claude co-author trailer plus "fix IDOR" returns over twenty thousand commits; a sampled June 2026 FastAPI repository with `AGENTS.md` had a 12-line fix moving identity from the request body to the auth context. Agent-authored vuln-to-fix pairs are harvestable.
  - VibeApps/VibeVulns (arXiv 2606.23130) is not released, but its identification method is: `.claude/` directory, Lovable meta tag, Claude trailers, and an 85% AI-authored threshold.

## Research Log

### Scorer blind spots

- **Context**: Why the sast overlay number did not move after the tree-sitter extra.
- **Sources Consulted**: `src/openultrasast/pairs.py` (`_evaluate_overlay_pair`, `_overlay_matches_expected`, `_overlay_leaks`), `semantic/overlay.py`, direct runs of `adjudicate` on the sast files.
- **Findings**: only `promote` is counted; `coverage` is excluded on both sides. `_overlay_matches_expected` accepts a CWE-only match. `ExpectedFinding` already has `function` and `line`, and `benchmark._matches_expected` honors them, but the overlay path does not. `OverlayRecord` has no function field; `FunctionIR` has line ranges.
- **Implications**: count coverage symmetrically; add optional `function` to `OverlayRecord`; require function or sink or rule id for a match when present; flag CWE-only rows.

### Harvest anchor defect

- **Context**: 50 vfc files `parse_failed`.
- **Sources Consulted**: `benchmarks/pairs/vfc/harvest.py` `extract_function`; tree-sitter ERROR nodes on `curl-cve-2022-27774/vuln.c` and `curl-cve-2023-38545-do_socks5/vuln.c`.
- **Findings**: the name search accepts a match followed by `(` even inside a comment, and the brace search then finds the real body. A second, smaller class is `#if`-split `else if` chains, which tree-sitter cannot attach; that is an engine tolerance question, not harvest.
- **Implications**: skip comment and string regions before searching; anchor on a line that starts a declarator; add line-range and hunk modes so Python and JS/TS are covered; report parse loss on the dashboard so the engine spec can measure its tolerance work.

### Candidate corpora

- **Context**: User asked for vibe-coded and Node/TypeScript/Python web corpora.
- **Sources Consulted**: Real-Vuln-Benchmark repo and paper; SecBench.js repo and ICSE 2023 paper; AIDev dataset card and paper; BaxBench site, repo, and paper; SecurityEval, CodeSecEval, CWEval; CyberSecEval benchmarks README; VibeApps paper; TS-VulBench page; SecureVibeBench repo; GitHub commit search via `gh api search/commits`.
- **Findings**:
  | Corpus | Languages | Labels | Fixed twin | License | Verdict |
  |---|---|---|---|---|---|
  | Real-Vuln-Benchmark | Python web | file, line range, function, CWEs, authorship, FP traps | traps | Apache-2.0 | `vibe-py` |
  | SecBench.js | Node | sinkLocation, fixCommit, class | yes | none stated | `vfc-js` via upstream |
  | AIDev + GitHub search | multi | provenance only | via fix commit | per repo | `agent-vfc` source |
  | BaxBench | Express, Flask, FastAPI, Django, Nest, more | exploit outcome per generated sample | by generation | MIT | later, needs deep mode |
  | SecurityEval, CodeSecEval, CWEval | Python, some C/JS | CWE per prompt, some tests | partial | check per repo | pointers |
  | CyberSecEval ICD | 8 languages | defined by its own rules | no | MIT | pointer, circular |
  | VibeApps/VibeVulns | TS, JS, React | not released | no | n/a | method only |
  | TS-VulBench | TS synthetic | paywalled | no | unknown | skip |
  | SecureVibeBench | C/C++ | agent tasks | n/a | MIT | skip for web |
- **Implications**: three slices now; BaxBench after deep mode is stable; CyberSecEval never as recall ground truth.

### Classification and branching

- **Context**: User expects tuning to split into branches per corpus class.
- **Sources Consulted**: `improve/evolve.py` accept gate; `ruleset/store.py` ledger; `calibration.py` scope; `preprocess.detect_tags`; `build_pair_signals`.
- **Findings**: the accept gate already ANDs four clauses and reverts byte-for-byte. Pair signals carry pair name but no profile. Ledger is one file per target. Preprocess tags are deterministic and per file.
- **Implications**: classify on two axes (provenance for gating, mechanism for reporting). Branch the acceptance decision, not the ledger format: reject a change if any profile's holdout regresses. Profile-specific facts and thresholds are deferred to the engine specs where those data live.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Reopen `real-world-vfc-slice` | Add tasks to the closed spec | One place | Mixes closed seed work with scorer redesign; roadmap says do not reopen | Rejected |
| New superseding spec, corpus plane only | Scorer, labels, harvest, slices, provenance, profile gate | Measurable before engine work; engine specs stay pure | Two engine specs still needed | **Selected** |
| One big spec including engine | Corpus plus walker plus guards | Fewer specs | Unreviewable size; engine changes would be measured by a lossy scorer | Rejected |
| Profile as ledger fork | One `rule_policy.<profile>.json` per profile | Full branching | Changes ledger format owned by another spec; overfits per slice | Deferred |

## Design Decisions

### Decision: Count coverage-with-flow as detection and as leak

- **Context**: Sink aliases will always land as coverage.
- **Alternatives Considered**: promote coverage to `promote` in the engine; count coverage only on the vulnerable side.
- **Selected Approach**: scorer treats `coverage` with a non-empty source the same as `promote` on both sides.
- **Rationale**: `propose-adjudicate-prove` already states coverage enters the same state machine. Asymmetry would inflate recall.
- **Trade-offs**: some pairs move from MISS to LEAK; that is the honest reading.

### Decision: Function-scoped matching with weak-label flagging

- **Context**: CWE-only matching over-counts.
- **Selected Approach**: expected rows carry `function`; match requires the record inside that function's lines; rows with no function, sink, or rule id are `weak_label` and never match by CWE alone.
- **Trade-offs**: vfc recall may drop on first run; the drop is real.

### Decision: Provenance is deterministic and closed

- **Context**: No LLM in classification.
- **Selected Approach**: signals from `.claude/`, `CLAUDE.md`, `AGENTS.md`, `.cursor/`, `.github/copilot-instructions.md`, Lovable meta tag, "Generated with Claude Code", and co-author trailers for Claude, Codex, Copilot, Cursor, Devin, Jules when a git log is readable. Threshold for `agent` on a git tree: at least 85% of commits or lines in the last N commits carry a signal, following the VibeApps method; otherwise `mixed` when any signal exists; `human` when none; `synthetic` only from catalog declaration.
- **Trade-offs**: repos that scrub trailers read as human. Acceptable; the label is a profile, not a verdict.

### Decision: Branch the accept decision, not the data

- **Context**: Overfitting risk with per-slice tuning.
- **Selected Approach**: `run_improvement` evaluates holdout pairs per profile; any profile regression beyond tolerance rejects. Profiles capped at four. Minimum holdout size reported.
- **Follow-up**: profile-keyed facts land with the engine specs, gated by this clause.

## Risks & Mitigations

- Recall numbers drop after function-scoped matching and weak-label flags — expected; record before and after in the roadmap.
- SecBench.js has no license — never vendor its files; harvest from upstream package repos and record each package license.
- Agent-authored commits may be false labels (a "fix" that was not a vuln) — human review required; keep `agent-vfc` small.
- Real-Vuln-Benchmark apps are educational and CTF style — say so in the slice README; do not treat `vibe-py` as production.
- Held-out halves are small on day one — report minimum-size warnings; do not gate on a profile under the minimum.

## References

- [Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark) — Apache-2.0, manifest with pinned SHAs, ground-truth schema
- [RealVuln paper](https://arxiv.org/abs/2604.13764) — 26 human plus 40 LLM-generated Python repos, FP traps
- [SecBench.js](https://github.com/cristianstaicu/SecBench.js) — 600 npm vulns, `fixCommit`, `sinkLocation`
- [SecBench.js paper](https://software-lab.org/publications/icse2023_SecBenchJS.pdf)
- [AIDev dataset](https://huggingface.co/datasets/hao-li/AIDev) — agent-authored PRs, CC-BY-4.0 index
- [BaxBench](https://github.com/logic-star-ai/baxbench) — MIT, scenarios and exploits, generation by CLI
- [SecurityEval](https://github.com/s2e-lab/SecurityEval), [CodeSecEval](https://arxiv.org/pdf/2407.02395), [CWEval](https://github.com/Co1lin/CWEval)
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) — labels defined by ICD rules
- [VibeApps paper](https://arxiv.org/html/2606.23130v1) — identification method
- `.kiro/specs/real-world-vfc-slice/` — superseded corpus spec
- Memory note `overlay-gaps-diagnosis-2026-09` — measured state and engine gaps
