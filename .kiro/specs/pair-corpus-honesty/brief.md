# Brief: pair-corpus-honesty

Supersedes `real-world-vfc-slice` for the corpus and scorer plane. That spec is closed: all tasks done, 17 tests green, three seed projects plus curl landed. Its residuals are corpus quality and scorer fidelity, not seed coverage, so they get a new spec instead of reopening.

## Problem

The pair scoreboard cannot tell us whether the overlay engine improved, because the scoreboard itself is lossy:

- Overlay scoring counts only `promote`. Coverage records with a real flow (the Java sqli vuln is already found that way) count as nothing. Every future sink alias lands as coverage, so the scorer will hide the work.
- 129 of 176 vfc labels say `sink = "unknown"` and only 4 carry a rule id. Matching falls through to CWE-string equality, and CWE-119 is a catch-all. Any memcpy promotion anywhere in the file counts as a hit.
- 25 curl pairs (50 files) are `parse_failed`. The harvester anchors on the first mention of the function name, which is usually the doc comment above it, so excerpts start mid-comment.
- Two sast pairs cannot be labeled as vendored: the Juliet strcpy vuln and fixed bodies are byte-identical (buffer declarations lost), and the OWASP Java hash pair needs `benchmark.properties`.
- There is no vibe-coded or web corpus at all. Node, TypeScript, and modern Python web frameworks are where operators are writing code now, and where AI-authored code concentrates.
- Overlay-versus-inventory is only reported for vfc, and there is no per-mechanism or per-provenance view, so a change that helps C guards and hurts Python injection is invisible.

Measured 2026-09-04 (extra on): sast 5/11 recall, 4/11 pair-correct, Youden +27%; vfc 6/176 recall, 0 pair-correct, Youden −14%; overlay column identical to inventory on vfc.

## Desired Outcome

A scoreboard that is honest per slice, per mechanism, and per provenance, on corpora that include real Node/TypeScript/Python web code and agent-authored code, so the two engine specs that follow (`overlay-ir-completeness`, `guard-dominance-regime`) can be measured and the improve loop can be branched by profile without overfitting one slice.

## Approach

Fix the scorer and labels first (no engine change). Anchor harvest at the declarator and add line-range and hunk extraction so Python and JS/TS functions can be harvested. Add a closed mechanism vocabulary and a closed provenance set to every pair. Add three slices: `vibe-py` (Real-Vuln-Benchmark, 40 LLM-generated plus 26 human Python web repos with false-positive traps), `vfc-js` (SecBench.js fix commits and sink locations), `agent-vfc` (agent-trailer security-fix commits, human reviewed). Add a deterministic provenance fingerprint at scan time. Report per-profile metrics and make the improve loop accept only when no profile regresses.

## Scope

- **In**: scorer fidelity; label schema; harvest anchor and modes; corpus hygiene for sast; three new slices; dataset pointers; provenance fingerprint; per-profile and per-mechanism dashboard; per-profile improve-loop gate; offline tests.
- **Out**: any change to taint, facts, CST walker, or dispositions (engine specs); tolerating tree-sitter ERROR nodes (engine); BaxBench generation and exploit-labelled slices (needs deep mode; later); profile-specific fact tables; making any dashboard a merge gate; vendoring SecBench.js test files (no license).

## Boundary Candidates

- Scorer and label schema (`pairs.py`, catalog loaders) vs engine records (`OverlayRecord` gains one additive field)
- Harvest tooling vs vendored excerpts
- Provenance fingerprint (preprocess/manifest) vs improve-loop gate

## Out of Boundary

- Overlay dispositions, taint, CST walker (`propose-adjudicate-prove`, `tree-sitter-overlay-extra`, and the two follow-up engine specs)
- Rule policy internals and CWE severity (`harnessx-self-improving-rulesets`)
- Stage plan, sandbox, hunter (`three-stage-scan`)

## Upstream / Downstream

- **Upstream**: pair catalog schema; overlay eval path; `build_pair_signals`; `run_improvement` accept gate; preprocess tags.
- **Downstream**: `overlay-ir-completeness` and `guard-dominance-regime` measure against these slices and vocabularies; later `baxgen` slice reuses provenance and mechanism fields.

## Existing Spec Touchpoints

- **Supersedes**: `real-world-vfc-slice` (corpus/scorer plane). Its seed pairs, harvest script, and dual scoreboard are kept and extended.
- **Extends**: roadmap direct candidate "record inventory vs overlay Youden side-by-side in sast JSON".
- **Adjacent**: `propose-adjudicate-prove` (one additive field on `OverlayRecord`), `harnessx-self-improving-rulesets` (accept gate grows a per-profile clause, ledger format unchanged).

## Constraints

Core `dependencies = []`. Harvest never runs in CI. Every vendored file carries license and provenance. No LLM in classification. Youden on any non-local slice is never a merge gate. Held-out halves are declared in the catalog, not chosen at run time.
