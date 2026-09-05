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
- [ ] corpus-seeded-mechanisms -- Every seeded or reviewed pair becomes a mechanism record (source shape, sink shape, guard the fix added); structural variant search over the scanned tree proposes matches as `variant` findings that the overlay and sandbox verify; leave-one-out recall on the pair corpus is the corpus's own detection rate; the improve loop gains a recall-raising `mechanisms` lever under the per-profile holdout gate. Principle: recall first under a false-positive ceiling, per profile. Dependencies: pair-corpus-honesty (tiers, pointer slices)
- [ ] reachability-flow-model -- Name-resolved call graph over `FunctionIR`; per-function taint summaries composed along the graph into path records; graph reachability drives rank, map, worth-fixing; hunter gets `path_context` and hunter findings with a locatable sink become sandbox candidates; closed-kind fact oracle with candidate cache; `facts` improve lever under the per-profile gate; fix points ranked by reachable risk removed. Dependencies: pair-corpus-honesty
- [ ] overlay-ir-completeness -- Shared CST walker completeness (C `init_declarator`, lvalue paths for field stores, per-grammar literal kinds, local ERROR-node tolerance, multi-line C/C++ declarators the walker names `<anon>` and `functions.py`'s one-line rescue cannot name: `chromium-cve-2022-2162`, `openssl-cve-2025-69421`; a Scorer-side multi-line-aware rescue is the cheaper alternative) plus Python parity with stdlib ast (f-string constness, augmented assignment, kwargs); injection-regime facts: container/transformer taint, `weak_literals` consulted, parameter sources off for injection. Measured on sast and vibe-py. Dependencies: pair-corpus-honesty
- [ ] guard-dominance-regime -- Guard and Use IR records; guard dominance by nesting or early exit; memory sinks (memcpy/malloc/deref) with operand roles, nullable callees, out-param transformers, fixed-array capacity; same regime applied to web absence bugs (route auth guard, identity from auth context). Consumes path records. Measured on vfc, vfc-js, agent-vfc. Dependencies: reachability-flow-model, overlay-ir-completeness
