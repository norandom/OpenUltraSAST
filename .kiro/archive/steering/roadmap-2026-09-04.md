# Roadmap

## Overview

OpenUltraSAST can propose sinks with regex and prove a few of them in a sandbox, but adjudication is still Python-`ast` plus a tree-sitter CLI stub. Textbook SAST pairs (OWASP/Juliet) did not improve after the overlay: Youden went from **+9.09% inventory to 0% overlay** on the same 11-pair slice. Real operator trees and browser/C/C++ history are not in the catalog. The next work is to put a real tree-sitter extra under the existing overlay, then grow an offline function-level vuln-vs-fix slice from public VFC datasets (including Firefox/gecko-dev where commits exist) without vendoring whole megarepos.

## Direction (2026-09-04)

Detection logic is ~16% of the source; harness plumbing, governance, and ranking are the rest. Recall on real code comes from the model with tools plus proof; precision and silence come from static checks. Shift: grow the corpus past the license and review walls (pointer slices, review tiers), turn every reviewed pair into a searchable mechanism (Clearwing's variant loop), then build the path model (call graph, summaries, fix points), put the hunter on paths, let model answers become gated facts, and stop adding harness plumbing until the detector exists. Recall first under a false-positive ceiling, per profile. Youden on non-local slices stays off the merge gate.

## Approach Decision

- **Chosen**: Optional tree-sitter extra first, then a harvested VFC slice scored like `github` (honesty dashboard, not smoke gate). Isolated functions only. Firefox is one project filter among Chromium, OpenSSL, curl — not a special-case full mozilla-central clone.
- **Why**: The overlay already has dispositions, facts, and taint. JS/C/Java stay `language_unsupported` because we refused a parser library. Textbook Youden is the wrong north star; large-project VFCs are the right one. Adopting tree-sitter deletes the need to hand-write language parsers.
- **Rejected alternatives**:
  - Whole Firefox tree in CI — multi-GB, memory-safety heavy, security-bug commit messages are deliberately scrubbed.
  - FixFox dataset — embargoed until 2030.
  - Joern-as-required or inter-file taint in this phase — deferred by `propose-adjudicate-prove`.
  - Chasing OWASP Youden with more regex — leaks on goodG2B/false files.

## Scope

- **In**: tree-sitter + grammars as `openultrasast[semantic]`; CST walker into existing FileIR/taint; harvested function-level pairs from CVEfixes/MoreFixes/CWE-Bench-Java/SVEN with provenance; overlay scoring on that slice; keep `quick` zero-dep.
- **Out**: Cloning mozilla-central/Chromium into the repo; making overlay Youden a merge gate; buffer-size/CWE-121 semantics; inter-file taint; auto-facts from improve; LLM as parser.

## Measured 2026-09-04 (extra on, before pair-corpus-honesty)

| Slice | Vuln recall | Silent on fix | Pair-correct | Youden |
|-------|-------------|---------------|--------------|--------|
| sast (11) | 45.5% | 81.8% | 4/11 | +27.3% |
| vfc (176) | 3.4% | 82.4% | 0/176 | −14.2% |

Overlay column equals inventory on vfc (no C memory sink fact). 25 curl pairs parse_failed (harvest anchored on a comment mention).

## Measured 2026-09-04 (after pair-corpus-honesty scorer: coverage counted, function-scoped matching)

| Slice | Vuln recall | Silent on fix | Pair-correct | Youden | Achievable | Loss |
|-------|-------------|---------------|--------------|--------|------------|------|
| sast (11) | 54.5% | 72.7% | 4/11 | +27.3% | 4/10 (java-hash known_limit) | 4 unadjudicated |
| vfc (176) | 0.0% | 81.8% | 0/176 | −18.2% | 0/176 | 50 parse_failed files, 128 unadjudicated |

New slices (pair-corpus-honesty, 2026-09-05, after the debug round: shared declarator naming, containment matching, sink-location labels): vibe-py (35, human, Real-Vuln licensed repos) 13/35 pair-correct, Youden +37.1% overlay vs 7/35 inventory; vfc-js (17) 5/17, Youden +23.5%; agent-vfc (29, agent, tier `title`) 0/29, Youden 0.0: no excerpt carries a rule-known sink and the overlay has no TypeScript grammar (18 rows); the unreviewed-tier baseline, never a gate. vfc parse-failed files 50 → 36 after the harvest fix.

Leave-one-out (corpus-seeded-mechanisms, 2026-09-05; the corpus as a teacher, never a gate). Each pair is held out once, a store is seeded from the other `seeded`/`reviewed` pairs, both excerpts are searched for structural variants:

| slice | pairs | detected | silent | Youden | teaching pairs | note |
|---|---|---|---|---|---|---|
| vibe-py (vendored) | 35 | 11 | 21 | −0.086 | 16 | `execute/1 parameter` shape taught by 7 pairs; 14 leaks on trap twins |
| local | 3 | 0 | 3 | 0.000 | 0 | reviewed, but labels name no sink call site |
| sast | 10 | 0 | 10 | 0.000 | 0 | advisory tier never teaches (known_limit pair skipped) |
| github | 6 | 0 | 6 | 0.000 | 0 | advisory tier |
| vfc-js | 17 | 0 | 17 | 0.000 | 0 | advisory tier |

The loop is closed: `ousast mechanisms export` writes candidates, `ousast improve --pair-catalog` admits the ones that recover a holdout pair without leaking (per-profile clause over variant search; `mechanism_leak`/`mechanism_no_gain` revert byte for byte), the scan searches the admitted store and reports name the mechanism and its known fix. Measured 2026-09-05 on the `python-vulnerable` benchmark target with the vibe-py candidates: 4 records admitted in round 1 (`execute/1 parameter` taught by 7 pairs among them), superseded by the learning-harness section below: that number was measured with holdout pairs teaching (see `benchmarks/measurements/2026-09-06-mechanism-lever-split.json`).

Measured 2026-09-05 after review tiers (Req 9) and pointer slices (Req 10): vibe-py 115 = 35 vendored human (13/35, Youden +37.1%) + 80 `agent` pointer pairs over the 40 LLM-generated Real-Vuln repositories (0/80, Youden 0.0; the LLM-repo baseline, scored by the nightly `pairs --slice vibe-py --pointers` only, never in tests or gates); agent-vfc 59 = 29 vendored + 30 pointer, tier `title`, 1/59, Youden 0.0, 2 unresolved labels; sast, vfc-js, vfc unchanged; detection/map/local-pair gate outputs byte-identical to the pre-spec commit. Only `seeded`/`reviewed` pairs gate the improve loop. Carry-forwards: `language_unsupported` loss counter and multi-line C/C++ declarator rescue (overlay-ir-completeness), `profiles_ungated` reporting and an offline test for the agent-vfc pointer builder (corpus-seeded-mechanisms).

sast: java-sqli moved MISS→LEAK (coverage counted on both sides; the fixed twin leaks via parameter-as-source). vfc: recall fell to zero because every label now names a function and no C detection lands inside it; that is the honest baseline the engine specs measure against.

## Constraints

- Core `dependencies = []`. Parser wheels live only in an extra.
- Pair fixtures stay out of `LANGUAGE_MANIFESTS`.
- Do not vendor 16 GB VFC dumps. Pointers in `datasets.toml`; a small reviewed catalog of isolated functions is what CI runs.
- DiverseVul-style auto labels (~60% accurate) are not ground truth without review.

## Boundary Strategy

- **Why this split**: Engine (how we parse) is independent of corpus (what we score). The extra can ship without any new pairs; the corpus can score inventory-only until the extra lands, then overlay.
- **Shared seams to watch**: `FileIR` / `parse_file`; pair catalog `slice` values; overlay vs inventory scoring in `pairs.py`.

## Existing Spec Updates

- [x] propose-adjudicate-prove -- overlay roles, facts, prove-budget, sast overlay scoring (landed). Residual: tree-sitter path returns no IR.
- [ ] propose-adjudicate-prove -- do not reopen for parsers or corpora; those are the new specs below.

## Direct Implementation Candidates

- [x] Record inventory vs overlay Youden side-by-side in `ousast pairs --slice sast` JSON -- folded into pair-corpus-honesty task 2.3. Done (`scorers` block, 2026-09-05).
- [x] Add Firefox/gecko-dev, Chromium, OpenSSL pointers to `benchmarks/pairs/datasets.toml`.

## Specs (dependency order)

- [x] tree-sitter-overlay-extra -- Optional extra: tree-sitter + grammars, one CST walker, `quick` stays zero-dep. Dependencies: none
- [x] real-world-vfc-slice -- Harvest reviewed function-level vuln/fix pairs from large projects (Firefox/gecko-dev, Chromium, OpenSSL, …) as an honesty slice. Seed is testable (`ousast pairs --slice vfc`). Dependencies: none. **Closed 2026-09-04, superseded by pair-corpus-honesty on the corpus/scorer plane.**
- [x] pair-corpus-honesty -- Scorer counts coverage and matches by function; labels carry mechanism/provenance/split/known_limit; harvest anchors at the declarator with line-range and hunk modes; sast hygiene; new slices `vibe-py` (Real-Vuln-Benchmark), `vfc-js` (SecBench.js fix commits), `agent-vfc` (agent-trailer fixes); deterministic provenance fingerprint; per-profile improve acceptance; review tiers and pointer slices (amendment). Dependencies: none (supersedes real-world-vfc-slice). **Completed 2026-09-05 (11 review rounds).**
- [x] corpus-seeded-mechanisms -- Every seeded or reviewed pair becomes a mechanism record (source shape, sink shape, guard the fix added); structural variant search over the scanned tree proposes matches as `variant` findings that the overlay and sandbox verify; leave-one-out recall on the pair corpus is the corpus's own detection rate; the improve loop gains a recall-raising `mechanisms` lever under the per-profile holdout gate. Principle: recall first under a false-positive ceiling, per profile. Dependencies: pair-corpus-honesty (tiers, pointer slices). **Completed 2026-09-05 (6 review rounds).**
- [ ] reachability-flow-model -- Name-resolved call graph over `FunctionIR`; per-function taint summaries composed along the graph into path records; graph reachability drives rank, map, worth-fixing; hunter gets `path_context` and hunter findings with a locatable sink become sandbox candidates; closed-kind fact oracle with candidate cache; `facts` improve lever under the per-profile gate; fix points ranked by reachable risk removed. Dependencies: pair-corpus-honesty **Critical path: two consumers wait on it (guard-dominance-regime and authorization-obligations).**
- [ ] overlay-ir-completeness -- Shared CST walker completeness (C `init_declarator`, lvalue paths for field stores, per-grammar literal kinds, local ERROR-node tolerance, multi-line C/C++ declarators the walker names `<anon>` and `functions.py`'s one-line rescue cannot name: `chromium-cve-2022-2162`, `openssl-cve-2025-69421`; a Scorer-side multi-line-aware rescue is the cheaper alternative) plus Python parity with stdlib ast (f-string constness, augmented assignment, kwargs); injection-regime facts: container/transformer taint, `weak_literals` consulted, parameter sources off for injection. Measured on sast and vibe-py. Dependencies: pair-corpus-honesty
- [ ] authorization-obligations -- Absence bugs as obligations, not flows: obligated operations (protected read/write, privileged action, security setting) and discharger kinds (path guard, identity constraint from authenticated context, ownership check, non-permissive value) as closed facts; obligation shapes learned from trusted pairs; the application's policy recovered from sibling-handler consistency and an optional declared, versioned policy file; violations evaluated on the path (function-local degraded mode without it) with `consistency_violation` / `declared_policy_violation` rungs below proof; `obligations` improve lever under the holdout gate; the hunter adjudicates intent only. Measured leave-one-out on the vibe-py and agent-vfc absence pairs (today 0 detected; 15 of 29 agent-vfc rows). Dependencies: reachability-flow-model, guard-dominance-regime, corpus-seeded-mechanisms. **Requirements drafted 2026-09-05, unapproved.**
- [ ] guard-dominance-regime -- Guard and Use IR records; guard dominance by nesting or early exit; memory sinks (memcpy/malloc/deref) with operand roles, nullable callees, out-param transformers, fixed-array capacity; same regime applied to web absence bugs (route auth guard, identity from auth context). Consumes path records. Measured on vfc, vfc-js, agent-vfc. Dependencies: reachability-flow-model, overlay-ir-completeness

<!-- learning-harness:begin -->

## Classified detector numbers

Generated by `uv run ousast learning publish` from the artifacts committed beside these numbers.

| model | slice | family | scorable | unscorable | recall | silence | Youden | at fixed FPR | noise floor | cost per correct pair |
|---|---|---|---|---|---|---|---|---|---|---|
| deepseek-v4-flash | agent-vfc | access_control | 4 (taxonomy 1) | known_limit:client_side_caller: 1, unresolved_label: 1 | 0.000 | 1.000 | 0.000 | 0.000 | budget 4 | - |
| deepseek-v4-flash | agent-vfc | config_secrets | 6 (taxonomy 1) | none | 0.333 | 0.833 | 0.167 | 0.000 | budget 2 | 0.95 |
| deepseek-v4-flash | agent-vfc | injection | 2 (taxonomy 1) | none | 0.500 | 0.500 | 0.000 | 0.000 | budget 1 | - |
| deepseek-v4-flash | agent-vfc | path | 3 (taxonomy 1) | none | 1.000 | 0.667 | 0.667 | 0.000 | budget 3 | 0.48 |
| deepseek-v4-flash | agent-vfc | prototype | 7 (taxonomy 1) | none | 0.429 | 1.000 | 0.429 | 0.429 | budget 5 | 0.32 |
| deepseek-v4-flash | agent-vfc | untrusted_destination | 5 (taxonomy 1) | none | 0.600 | 0.600 | 0.200 | 0.000 | budget 3 | 0.95 |
| deepseek-v4-flash | vibe-py | access_control | 3 (taxonomy 1) | identical_twin: 1 | 1.000 | 1.000 | 1.000 | 1.000 | budget 3 | 0.23 |
| deepseek-v4-flash | vibe-py | config_secrets | 3 (taxonomy 1) | none | 1.000 | 1.000 | 1.000 | 1.000 | budget 1 | 0.23 |
| deepseek-v4-flash | vibe-py | deserialization | 2 (taxonomy 1) | identical_twin: 1 | 1.000 | 1.000 | 1.000 | 1.000 | budget 0 | 0.34 |
| deepseek-v4-flash | vibe-py | injection | 20 (taxonomy 1) | identical_twin: 2 | 0.750 | 0.900 | 0.650 | 0.750 | budget 11 | 0.05 |
| deepseek-v4-flash | vibe-py | output_encoding | 1 (taxonomy 1) | identical_twin: 1 | 1.000 | 1.000 | 1.000 | 1.000 | budget 1 | 0.69 |
| deepseek-v4-flash | vibe-py | path | 1 (taxonomy 1) | none | 1.000 | 1.000 | 1.000 | 1.000 | budget 1 | 0.69 |
| deepseek-v4-pro | vibe-py | access_control | 3 (taxonomy 1) | identical_twin: 1 | 0.000 | 1.000 | 0.000 | 0.000 | budget 2 | - |
| deepseek-v4-pro | vibe-py | config_secrets | 3 (taxonomy 1) | none | 1.000 | 1.000 | 1.000 | 1.000 | budget 2 | 0.16 |
| deepseek-v4-pro | vibe-py | deserialization | 2 (taxonomy 1) | identical_twin: 1 | 1.000 | 1.000 | 1.000 | 1.000 | budget 1 | 0.24 |
| deepseek-v4-pro | vibe-py | injection | 20 (taxonomy 1) | identical_twin: 2 | 0.350 | 0.900 | 0.250 | 0.350 | budget 14 | 0.09 |
| deepseek-v4-pro | vibe-py | output_encoding | 1 (taxonomy 1) | identical_twin: 1 | 1.000 | 1.000 | 1.000 | 1.000 | budget 0 | 0.47 |
| deepseek-v4-pro | vibe-py | path | 1 (taxonomy 1) | none | 1.000 | 1.000 | 1.000 | 1.000 | budget 0 | 0.47 |

No family in this taxonomy declares a parent, so hierarchical partial credit could not apply to any figure above.

No detector cutoff is configured, so no post-cutoff slice is reported; every figure above is over the whole corpus.

Mechanism lever on the vibe-py holdout: detected 5 of 17 at Youden -0.0588 once only train-split pairs teach, against detected 7 at Youden 0.0588 when every pair taught. The difference is what holdout pairs stopped teaching.

<!-- learning-harness:end -->
