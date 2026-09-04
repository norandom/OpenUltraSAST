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
