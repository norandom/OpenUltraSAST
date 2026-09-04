# Roadmap

## Overview

OpenUltraSAST can propose sinks with regex and prove a few of them in a sandbox, but adjudication is still Python-`ast` plus a tree-sitter CLI stub. Textbook SAST pairs (OWASP/Juliet) did not improve after the overlay: Youden went from **+9.09% inventory to 0% overlay** on the same 11-pair slice. Real operator trees and browser/C/C++ history are not in the catalog. The next work is to put a real tree-sitter extra under the existing overlay, then grow an offline function-level vuln-vs-fix slice from public VFC datasets (including Firefox/gecko-dev where commits exist) without vendoring whole megarepos.

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

- [ ] Record inventory vs overlay Youden side-by-side in `ousast pairs --slice sast` JSON (small report field, not a new spec).
- [ ] Add Firefox/gecko-dev, Chromium, OpenSSL pointers to `benchmarks/pairs/datasets.toml`.

## Specs (dependency order)

- [ ] tree-sitter-overlay-extra -- Optional extra: tree-sitter + grammars, one CST walker, `quick` stays zero-dep. Dependencies: none
- [ ] real-world-vfc-slice -- Harvest reviewed function-level vuln/fix pairs from large projects (Firefox/gecko-dev, Chromium, OpenSSL, …) as an honesty slice. Dependencies: none
