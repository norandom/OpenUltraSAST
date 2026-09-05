# Vuln vs fixed pair corpus

This corpus measures harness **efficiency**, not cheat-sheet recall.

The stage-1 smoke gate (`python -m openultrasast.gate`) scans one tree that
already contains the planted sinks. A pair eval instead scans **two isolated
trees**:

1. **vuln** — only the vulnerable file. The harness should fire (true positive).
2. **fixed** — only the patched file, same relative path. The harness should stay
   silent on that CWE (true negative).

`pair_correct` = detected on vuln **and** silent on the fix. That is the signal
the improvement loop consumes (`miss` on the vuln side, `fp` on the fix side).

## Layout

| Path | Role |
| --- | --- |
| `catalog.toml` | Runnable offline pairs (local fixtures + vendored GitHub functions) |
| `datasets.toml` | Pointers to public VFC datasets — do not vendor the dumps |
| `datasets/cwe-bench-java-project_info.csv` | 120 vetted Java CVE buggy/fix commits |
| `github/` | Isolated function excerpts with provenance headers |

Pairs in this directory **must not** join `LANGUAGE_MANIFESTS`.

## Slices

- **local** — in-tree fixture counterparts (`app.py` vs `safe.py`, …). CI gate:
  every local pair must pass (`python -m openultrasast.pair_gate`).
- **github** — real commit/function pairs (SVEN, CWE-Bench-Java, NVD patterns).
  Measured, not a 90% smoke gate. Misses here are the honesty / evolve-the-harness
  dashboard.
- **sast** — OWASP Benchmark Java/Python true-vs-false files and Juliet
  bad-vs-good sinks (`benchmarks/pairs/sast/`). Score is Youden (TPR − FPR).
  Honesty dashboard, not a CI fail.
- **vfc** — reviewed isolated functions from OpenSSL, Firefox, Chromium, and
  curl (`benchmarks/pairs/vfc/`). Overlay vs inventory scoreboard. Honesty
  dashboard, not a CI fail. Training labels (vuln vs fixed) are
  `vfc/training/manifest.jsonl` (vuln vs fixed, one snapshot per line).
  Grow with a blobless `git log --grep=CVE-202` mine plus `vfc/harvest.py`,
  then `vfc/generate_catalog.py` (maintainer, not CI).
- **vibe-py** — Real-Vuln-Benchmark functions (`benchmarks/pairs/vibe-py/`):
  Python web repos pinned by commit, one vulnerable function per pair with a
  false-positive trap from the same repo as the fixed twin. Today only the 15
  licensed human-authored repos are vendored (`provenance = "human"`); the 40
  LLM-generated repos carry no license file and are excluded until one is
  stated upstream. Educational/CTF apps, not production. Honesty dashboard.
- **vfc-js** — server-side JavaScript function pairs harvested from the upstream
  fix commits that SecBench.js records (`benchmarks/pairs/vfc-js/`). Command
  injection, path traversal, and code injection first; prototype pollution and
  ReDoS carry their mechanism and may be `known_limit`. No SecBench.js file is
  vendored. Honesty dashboard.
- **agent-vfc** — security-fix commits carrying an AI agent co-author trailer or
  generation marker, in JavaScript, TypeScript, or Python
  (`benchmarks/pairs/agent-vfc/`). `provenance = "agent"`. Rows with
  `reviewer = "pending"` load at `review_tier = "title"` (the review queue) and
  never gate the improve loop (task 8.2); a human sets `reviewer` to promote a row to `reviewed`. Honesty dashboard.

## Review tiers

Every pair carries `review_tier` (Req 9): `seeded` (ground truth reviewed by the
upstream benchmark), `advisory` (public CVE or GHSA with a fix commit), `title`
(mechanism inferred from a commit message, unreviewed), `reviewed` (a named
`reviewer` in this repository; the loader rejects `reviewed` without one).
Defaults per slice: local `reviewed`, vibe-py `seeded`, sast/vfc/vfc-js/github
`advisory`, agent-vfc `title`. `pairs --json` reports `per_tier`; `evolve.evaluate_profiles` scores only `seeded`
and `reviewed` pairs, so `advisory` and `title` pairs never gate the improve loop (task 8.2).

## Pointer pairs (not vendored)

A row with `vendored = false` carries its harvest recipe (`repo`, `parent`, `commit`,
`path`, `mode`, `line`/`fix_path`/`fix_line`, ...) and no excerpt files (Req 10). The
repository never redistributes that code: `pairs --pointers` (or
`OPENULTRASAST_PAIRS_NETWORK=1`) harvests both sides into
`OPENULTRASAST_PAIR_CACHE` (default `~/.cache/openultrasast/pairs/<slice>/<name>/`,
git-ignored) and scores them exactly like a vendored pair; without network the pair is
skipped with a `pointer_pair_skipped` degradation and a failed fetch is
`pointer_pair_fetch_failed`, never an error. The default `pytest` run and every gate
score vendored pairs only (`select_vendored`); the pointer run is the nightly command.

## Labels, profiles, and mechanisms

Every `[[pair.expected]]` row names a `mechanism` from the closed vocabulary in
`benchmarks/pairs/mechanisms.toml`; every pair carries `provenance`
(`human|agent|mixed|synthetic`), a declared `split` (`train|holdout`), and an
optional `known_limit` reason. The scorer counts overlay `coverage` records with
a source as detections and as leaks, matches by function when a label names one,
never matches a CWE-only row (`weak_label`), and reports `per_profile`,
`per_mechanism`, `achievable` (known-limit pairs excluded), and `loss`
(parse-failed files, unadjudicated proposals). `ousast pairs --profile agent
--split holdout --json` filters; `--hunter` adds the LLM hunter as a third scorer
when a hunter model is configured. The improve loop rejects a change that
regresses any profile on the holdout split.

Harvest for every slice goes through `benchmarks/pairs/harvest.py --slice <name>`
(modes `name`, `line_range`, `hunk`, `enclosing`; comment and string mentions
never anchor) and `benchmarks/pairs/catalog_gen.py --slice <name>` regenerates
the catalog from `recipes.toml`. Maintainer only; CI never fetches.

## Commands

```bash
uv run ousast pairs
uv run ousast pairs --slice github --json
uv run ousast pairs --slice vfc --json
uv run python -m openultrasast.pair_gate
```

## Growing the corpus

Prefer function-level before/after from a reviewed source (SVEN jsonl, a
CWE-Bench-Java `fix_info.csv` row, a GHSA with a tiny patch). Isolate the
changed function into `vuln` / `fixed` files with the same `relpath`. Leave
whole-repo clones to `--fetch` later; CI stays offline.
