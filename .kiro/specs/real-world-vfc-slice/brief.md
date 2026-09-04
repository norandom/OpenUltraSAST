# Brief: real-world-vfc-slice

## Problem

Operators care whether the harness fires on a real buggy snapshot and stays quiet after the patch — Firefox, Chromium, OpenSSL — not whether OWASP BenchmarkTest00074 is a TP. The labeled SAST slice is 11 textbook files. Overlay Youden there is **worse** than inventory (+9.09% → 0%). We cannot tell if the tool got better on messy product code.

## Current State

Slices today: `local` (CI 100%), `github` (6 vendored functions: SVEN, hutool, node-serialize), `sast` (OWASP/Juliet). `datasets.toml` already points at CVEfixes, MoreFixes, CWE-Bench-Java, Vul4J. Nothing is harvested from gecko-dev / Firefox. Whole mozilla-central is not in-tree (and should not be). FixFox (Zenodo) is embargoed until 2030. Firefox security commit messages are often scrubbed of “security” words, so grep-the-log is a bad miner.

Measured on the current 11-pair **sast** slice (2026-09-04):

| Scorer | pair_correct | vuln recall | silent-on-fix | Youden |
|--------|--------------|-------------|---------------|--------|
| Inventory (regex) | 2/11 (18%) | 54.5% | 54.5% | **+9.09%** |
| Overlay (current) | 2/11 (18%) | 45.5% | 54.5% | **0%** |

The only overlay change vs inventory on that slice: `owasp-python-codeinj` went from LEAK (regex hit both sides) to MISS (ConfigParser heap → `flow_incomplete`, no promote). C/Java Juliet goodG2B still leak because those languages are unadjudicated and scoring falls back to inventory.

## Desired Outcome

A new pair slice (e.g. `vfc`) of **reviewed, isolated function pairs** from large projects, including Firefox/gecko-dev when a public fix commit exists in CVEfixes/MoreFixes. Offline CI. Honesty dashboard like `github`, not a 90% smoke gate. Overlay scoring once tree-sitter can parse C/JS/Java; inventory scoring until then. Provenance on every file (repo, commit, CVE, license).

## Approach

Do not clone Firefox. Filter public VFC databases for `gecko-dev` / `mozilla-firefox/firefox`, `chromium`, `openssl`, `curl`, plus existing CWE-Bench-Java. Extract the changed function before/after. Human-review labels (DiverseVul ~60% is not ground truth). Cap the runnable catalog (tens of pairs, not thousands). Prefer injection/XSS/path CWEs the overlay can talk about; keep UAF/buffer overflows as known inventory-only leaks until a later memory-safety spec.

## Scope

- **In**: harvest script or documented procedure; catalog slice; provenance headers; overlay-vs-inventory scoreboard on that slice; dataset.toml pointers for Firefox/Chromium.
- **Out**: Vendoring mozilla-central; live Bugzilla scraping; making Youden a merge gate; buffer-size semantics; tree-sitter packaging (owned by `tree-sitter-overlay-extra`).

## Boundary Candidates

- Catalog schema / slice name vs pair eval scoring
- Harvest tooling vs vendored excerpts

## Out of Boundary

- Parser extra, Joern, improve-loop auto-facts, `LANGUAGE_MANIFESTS`

## Upstream / Downstream

- **Upstream**: `pairs.py` catalog format; `propose-adjudicate-prove` overlay scoring
- **Downstream**: improve-loop signals from real misses; later memory-safety spec can reuse the same slice

## Existing Spec Touchpoints

- **Extends**: pair catalog only (new slice). Does not change smoke gate.
- **Adjacent**: `tree-sitter-overlay-extra` (C/Java overlay on this slice once the extra exists)

## Constraints

Isolated functions, same `relpath` vuln/fixed. License in the header. No 16 GB dumps in git. Firefox pairs only when a public git commit pair exists — MFSA text without a commit is not a pair.
