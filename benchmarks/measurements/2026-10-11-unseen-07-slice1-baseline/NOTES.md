# Record 07 — slice-1 unseen-repo baseline (G0 exit)

Measured 2026-10-11. Commit: e716e3beab8b01f63ac59dd49586b5904231e2a4
Image: ghcr.io/norandom/ousast-replay-task@sha256:a24fd03c6ccac0852d495e8a1931e630fffc866ca9e82dd81011533da413f783
Pool: benchmarks/unseen/pool-p1.toml (100 frozen never-seen repos, freeze_digest 3371c67d…), slice 1, 1300 changes.
Ledger: benchmarks/unseen/usage-p1.jsonl — one `baseline` row (this is G0's exit).

## Headline (DEFAULT arm, docker lane)
- catch (recall): 3/92 = 3.3% (Wilson95 1.1%–9.2%)
- false alarm: 3.1% (cluster95 1.6%–5.4%, icc 0.25 — repo clustering real)
- alerts_only: 0/1154 = 0% (no hard alerts; catches are advisory/quick stream)
- coverage: quick_only 1246, engine_covered 0, unanalysable 0, instrument_failure 54 (4.2%, < 5% guard)
- by family (catch): deserialization 1/4, injection 2/20, all others 0
- unseen gate: not_run (no paired production arm; baseline only)

## Caveats (read before citing)
- **Machine-label**: labels are SZZ-derived from fix commits, 100 unchecked by a human. Catch/FP are vs machine labels.
- **Regex-only floor**: model="disabled", max_model_calls=0, cost_usd=0 — NO LLM; and engine_covered=0 — the Joern
  engine never completed within the 30s default budget (the ~200s fixed-overhead wall, see
  .kiro/specs/engine-change-scoped-analysis/brief.md). So this is the quick pattern-rule tier ALONE, the floor,
  not the product. It is NOT the ≥90%/<10% gate and must not be read as release-grade detection.
- **Docker lane, local** (not the AX/kube lane; the AX completion path is operator-owned).
- **Sizing**: 100 vulns is ~±10% for one overall catch number; per-family (deser=4, config=10) is far too thin for
  family-level decisions — needs slices 2+.
- Raw per-change records streamed to the RustFS store; local subdirs pruned-as-we-go (records + inputs.json kept).
