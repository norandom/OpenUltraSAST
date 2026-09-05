# Research & Design Decisions

## Summary

- **Feature**: `reachability-flow-model`
- **Discovery Scope**: Complex Integration across semantic, mapping, rank, complexity, hunter, regress, improve
- **Key Findings**:
  - `FunctionIR` already carries every call site per function for Python, JS, TS, C, and Java when the extra is present. A name-resolved call graph is a few hundred lines over data that exists.
  - Reachability today is "line inside an entry-point handler" (`mapping.attach_reachability_hints`); `rank` bumps an integer from tags and hints; `worth_fixing` needs `reachable` or `inferred-file-surface`. No call edge exists anywhere.
  - Sandbox candidates come only from hotspots filtered to overlay-promoted inventory ids (`cli.py:404`, `prove_filter.filter_promoted_hotspots`); a hunter snippet is used only for an already promoted hotspot (`candidate.py:199`). The LLM plane cannot create a candidate.
  - Evidence is stamped by origin: regex hit `static_corroboration` (`findings.py:110`), hunter `suspicion` (`tool_hunter.py:408`).
  - Improve levers are `rule` and `policy` only (`improve/validator.py`); facts are not a lever. `propose-adjudicate-prove` excluded auto-authored facts.
  - Code shape: detection logic 1,910 lines of 12,128; harness plumbing 2,885; governance and benchmarks 3,178.
  - Clearwing fills reachability from a tree-sitter callgraph and lets taint paths boost surface; the embeddings retrieve mechanisms, not decide taint. That split is the reference.
  - Literature: RealVuln shows LLM-based scanners at 51.7 to 73 F3 on real Python web code versus Semgrep at 17.7; CVE-Bench shows agents exploit at most 13 percent of real web CVEs. Recall on real code comes from models with tools; precision and reproducibility come from static checks and execution.

## Research Log

### Where a call graph can come from

- **Context**: Avoid a new parser or a whole-program engine.
- **Sources Consulted**: `semantic/ir.py`, `semantic/cst.py`, `mapping.py`, `preprocess.py`, `hunter_tools.find_refs`.
- **Findings**: `FileIR.functions[*].calls[*].name` is the callee text. Python stdlib parse yields the same records. Imports are not in the IR; the walker can add an `imports` tuple per file cheaply. `find_refs` is a word-boundary regex over files and is the only cross-file lookup today.
- **Implications**: `semantic/callgraph.py` consumes `FileIR` plus an additive `imports` field. Resolution order: same-file definition, imported module definition, any definition with that name (ambiguous edges). Method calls resolve by trailing name. C resolves by bare name across the tree.

### Summaries versus whole-program taint

- **Context**: `propose-adjudicate-prove` deferred inter-file taint as too large and risky for false demotes.
- **Sources Consulted**: `semantic/taint.py` (`_analyze_function` seeds parameters as tainted, tracks names, emits `TaintPath` and `Demotion`), overlay invariants.
- **Findings**: Because parameters are already seeded tainted, a per-function run already answers "which parameter reaches which sink." Adding "which parameter reaches the return" is a small extension. Composition is then a graph walk with a depth bound. Nothing needs alias analysis to produce a useful path; anything unresolved stays `flow_incomplete`.
- **Implications**: Summaries are a pure function of `FunctionIR` plus facts, cacheable by file hash. Composition never demotes; it only adds paths or marks incompleteness.

### Hunter to candidate

- **Context**: The LLM plane is the recall lever the field data supports, but it is walled off from prove.
- **Sources Consulted**: `tool_hunter.py`, `regress/candidate.py`, `three-stage-scan` design (hunter snippets run only in the sandbox after safety check), `verification.py`.
- **Findings**: The safety check and sandbox are origin-agnostic. The wall is `filter_promoted_hotspots` and the candidate selector's reliance on inventory ids. A hunter finding with a locatable sink line can be given a synthetic hotspot the same way `_hotspot_from_forced_finding` already does for severity-5 inventory.
- **Implications**: Add eligibility for hunter findings that name a sink line resolvable to a path record or an overlay sink. Evidence stays suspicion until sandbox trigger or path agreement.

### Facts from a model, safely

- **Context**: The engine lacks callee knowledge: nullable returns (`tls1_lookup_sigalg`), bounded arguments, transformer set/get (`ConfigParser`), macro out-params (`n2s`).
- **Sources Consulted**: `semantic/facts.py` loader, `improve/validator.py`, `improve/journal.py`, `calibration.py` ledger patterns, `redaction.py`.
- **Findings**: Facts are versioned TOML loaded by `load_facts`. The loader can merge a second directory at lower precedence. The improve loop has a strict validator and byte-for-byte revert. Redaction exists for prompts.
- **Implications**: Model answers are candidate facts in `.openultrasast/calibration/candidate_facts.toml`; accepted facts in `accepted_facts.toml`; loader precedence hand-written > accepted > none. The `facts` lever moves rows between candidate and accepted under the same gate. No pattern text is ever model-authored; question kinds are closed.

### Fix points

- **Context**: The principle is risk reduced per fix, not findings per file.
- **Sources Consulted**: `complexity/map.py`, `complexity/ledger.py`, `regress/verdict.py`, `scoring/project_score.py`.
- **Findings**: The path graph is small (functions, not statements). Dominators over a DAG of entry-to-sink paths are cheap. Severity is available per CWE from policy.
- **Implications**: `risk/fixpoints.py` computes dominator sets per sink path and aggregates risk removed. It is a report and artifact, not a gate; it cannot hide severity-5 reachable findings.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Joern CPG as required engine | Full inter-procedural dataflow | Real dataflow | Scala runtime, not zero-dep, slow on PRs | Rejected; stays optional sidecar |
| CodeQL databases | Strong inter-procedural | Mature | Build step, license limits, heavy | Rejected as required; SARIF ingest remains |
| Whole-program taint in Python | Own engine | Full control | Months of work, alias analysis, false demotes | Rejected |
| Name-resolved call graph plus composed summaries | Graph over existing IR; summaries from existing taint | Days to build; over-approximate by design; feeds hunter and fix points | Ambiguous names, dynamic dispatch | **Selected** |
| LLM as reachability oracle | Ask the model who calls what | No code | Unverifiable, expensive per scan | Rejected; model answers closed callee questions only |

## Design Decisions

### Decision: Over-approximate edges, never infer safety

- **Context**: Missing edges silently hide risk; false edges cost hunter budget.
- **Selected Approach**: Ambiguous names produce edges to every definition, flagged. Unresolved calls produce an unresolved edge. Distance is infinite only within the depth bound and is reported as `unknown`.
- **Rationale**: Consistent with the fail-closed rule in the overlay.
- **Trade-offs**: More hunter work on large trees; bounded by existing hotspot caps.

### Decision: Summaries are pure and cached

- **Context**: Cost on large repos.
- **Selected Approach**: Summary keyed by file hash plus facts version; recomputed only when either changes.
- **Trade-offs**: Cache invalidation on facts version bump; acceptable.

### Decision: Evidence rises on checks, not on origin

- **Context**: Regex stamped corroboration, hunter stamped suspicion.
- **Selected Approach**: This spec does not change existing stamps. It adds the checks that raise hunter evidence: composed path agreement or sandbox trigger. A follow-up may lower regex-only hits to inventory; recorded as a revalidation trigger for `propose-adjudicate-prove`.
- **Rationale**: Keep this spec additive; changing existing stamps changes gate baselines.

### Decision: Closed question kinds, gated acceptance

- **Context**: Auto-facts were excluded for good reason: unbounded model-authored patterns.
- **Selected Approach**: Five question kinds, structured answers, candidate cache with provenance, acceptance only via the `facts` lever under the per-profile holdout gate.
- **Trade-offs**: Slower than trusting answers directly; the gate is the point.

### Decision: Fix points are dominators, reported not gated

- **Context**: Do not add a seventh evidence rung or a new CI condition.
- **Selected Approach**: Compute and report; the severity-5 reachable invariant from `three-stage-scan` stays.

## Risks & Mitigations

- Dynamic dispatch and callbacks in JS and Python produce unresolved edges — report unresolved counts; hunter `find_refs` remains available as a fallback.
- Graph blow-up on large trees — depth and fan-out bounds in config; hotspot caps unchanged.
- Model answers wrong — never used unless accepted by the gate; provenance recorded; hand facts win.
- Hunter candidates increase sandbox load — existing `max_candidates` cap; hunter candidates ranked after overlay promotions unless a path agrees.
- Fix-point estimates misread as guarantees — label as estimates; show witness paths.

## References

- Clearwing sourcehunt callgraph, taint, ranker (reference architecture; not a dependency)
- [RealVuln](https://arxiv.org/abs/2604.13764) — rule-based versus LLM scanners on real Python web code
- [CVE-Bench](https://arxiv.org/abs/2503.17332) — agent exploitation ceiling on real web CVEs
- `.kiro/specs/three-stage-scan/design.md` — hunter tools, candidate selection, worth-fixing
- `.kiro/specs/propose-adjudicate-prove/design.md` — facts as data, dispositions, evidence honesty
- `.kiro/specs/harnessx-self-improving-rulesets/design.md` — bounded levers, accept gate, revert
- `.kiro/specs/pair-corpus-honesty/` — per-profile holdout gate, hunter scorer
- Memory note `overlay-gaps-diagnosis-2026-09`
