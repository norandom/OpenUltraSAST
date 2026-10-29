# Breadth Map (2026-10-29)

One screen: every feature's lane, its state today, and its next move. Aligns `.kiro/steering/roadmap.md`
(goals, gates) with the tree (what exists). Update a row when its state changes, not on every commit.

| lane | state today | next move | owner |
|---|---|---|---|
| Engine: obligation checker + dominance | Stable; target-agnostic; checker owns verdicts | All-kind caller-hop re-judgement (task 8.2, opt-in keyword) | access-control-prover |
| Engine: resolution | Designed (class table + receiver/signature-qualified calls); code not started | Task 7.2 `obligations/resolution.py` | access-control-prover |
| Engine: paths / CFG / trace | Stable; `PathRecord` shape kept by design | No change; resolution plugs in before them | access-control-prover |
| Prover integration | `hunt/prover.py` proves changes; caller join is name-keyed | Receiver-qualified target join + down-depth budget (task 11.1) | access-control-prover |
| Runner | `prover_arm.py` metrics, coverage, zero-byte refusal; gate 1 = 65.2% recall, 15.0 FA/100 | Stale-anchor refusal (task 12.2); re-measure after 7-12 (task 13) | access-control-prover |
| Judge (zero-shot over traces) | `judge_pass.py`; gate 2 measured: safe but inert (keeps 15/15 TPs, drops 5/69 FAs) | No tuning; revisit only if trace facts change the FA mix | roadmap (measured 2026-10-28) |
| Recogniser registry | Designed (Strategy+Registry, `mapping/` package); code not started | Task 9.1 registry + registration-sites strategy; 9.2 migrates Stapler as the proof | access-control-prover |
| mapping.py monolith | All framework families inline (1,200+ lines); WordPress/Python registration blocks included | Migrate family by family after Stapler: jetty, symfony, livewire, remix, tornado, then PHP/Python registration tables | breadth (this map) |
| Obligation facts (ruleset TOMLs) | Closed rows, hand-authored; header discipline enforced by loader | Extraction into acquirable structures via fact-init (task 10.1) | access-control-prover |
| Fact initialization job | Designed (`tools/fact_init.py`: extract + propose -> gate -> promote); code not started | Task 10.1 build; 10.2 first run for pool families as data rows | access-control-prover |
| Fact-proposal lane (standing) | Roadmap-level: LLM proposes, engine verifies, repetition promotes | Stays deferred to injection-spec track (roadmap gate 5) | roadmap |
| Injection-family object | Brief only (`engine-change-scoped-analysis`); taint flow + banks MVP exist as evidence | Spec after post-fix pilot holds recall | roadmap |
| Complexity gate | Caps in `code-standards.md`, review-time only | Wire ruff C901 / xenon into CI; threshold per steering | breadth (this map) |
| Idiomatic naming | Rule active for new/amended code; legacy debt un inventoried | Record rename inventory during family migrations; no drive-by renames | breadth (this map) |
| Training pool | pool-train 23 repos / 483 changes frozen 2026-10-14 | Pre-2019 negatives re-audit before any future run (3/12 sampled carry real missing-check bugs) | valid-detection-benchmark |
| Pre-push safety net | Implementation 67/79; wiring unchanged by this work | Unaffected until prover recall/FA hold at pilot | pre-push-safety-net |

Migration order for mapping.py families is deliberate: Stapler first (task 9.2 proves the registry path on
the family the pool exercises most), then one family per migration, each deleting its legacy block from
`mapping.py` in the same change.
