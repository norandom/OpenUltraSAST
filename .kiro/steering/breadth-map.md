# Breadth Map (2026-10-29)

One screen: every feature's lane, its state today, and its next move. Aligns `.kiro/steering/roadmap.md`
(goals, gates) with the tree (what exists). Update a row when its state changes, not on every commit.

| lane | state today | next move | owner |
|---|---|---|---|
| Engine: obligation checker + dominance | Baseline checker stable; amended three-way judgment and strict CFG relation designed | Abstract domain + strict opt-in judgment (tasks 7, 10); legacy defaults unchanged | access-control-prover |
| Engine: resolution | Stable-symbol and finite-candidate design approved; code not started | IR/symbol/call resolution tasks 8.1-8.4 | access-control-prover |
| Engine: summaries / paths / trace | Baseline concrete paths and traces stable; uncertainty is not yet first-class | Monotone summaries + exact path materialization (task 9), abstract trace fields (7.4) | access-control-prover |
| Prover integration | `hunt/prover.py` proves changes with name-keyed joins and binary outcomes | Three-way finding/trace/coverage integration (task 10.6) | access-control-prover |
| Runner | Baseline arm: 65.2% recall, 15.0 flagged ordinary pushes/100; max runtime exceeded the amended 120s hard budget, so it is development evidence, not an eligible arm | Bundle/funnel/gate/four-arm work (task 12), then development and admission runs (task 13) | access-control-prover |
| Judge (zero-shot over traces) | `judge_pass.py`; gate 2 measured: safe but inert (keeps 15/15 TPs, drops 5/69 FAs) | No tuning; revisit only if trace facts change the FA mix | roadmap (measured 2026-10-28) |
| Recogniser registry | Strategy+Registry approved; code not started | Registry + registration adapter + one-family migration (tasks 11.1, 11.2, 11.6) | access-control-prover |
| mapping.py monolith | All framework families inline (1,200+ lines); WordPress/Python registration blocks included | Migrate family by family after Stapler: jetty, symfony, livewire, remix, tornado, then PHP/Python registration tables | breadth (this map) |
| Obligation facts (ruleset TOMLs) | Closed rows, hand-authored; resource/authority algebra designed but not implemented | Resource/authority fields (tasks 7.2-7.3), label-blind development acquisition (11.7) | access-control-prover |
| Fact initialization job | Label-blind extraction/proposal/verification/promotion and acquisition record approved; code not started | Tasks 11.3-11.5 | access-control-prover |
| Fact-proposal lane (standing) | Roadmap-level: LLM proposes, engine verifies, repetition promotes | Stays deferred to injection-spec track (roadmap gate 5) | roadmap |
| Injection-family object | Brief only (`engine-change-scoped-analysis`); taint flow + banks MVP exist as evidence | Spec after post-fix pilot holds recall | roadmap |
| Complexity gate | Caps in `code-standards.md`, review-time only | Wire ruff C901 / xenon into CI; threshold per steering | breadth (this map) |
| Idiomatic naming | Rule active for new/amended code; legacy debt un inventoried | Record rename inventory during family migrations; no drive-by renames | breadth (this map) |
| Development pool | pool-train 23 repos / 483 changes frozen 2026-10-14; explicitly not admission evidence | Four-arm regression only after tasks 7-12; pre-2019 negatives still require review | access-control-prover |
| Admission population | Not yet supplied; current pool is spent for development | `valid-detection-benchmark` prepares a reviewed untouched manifest; access-control-prover only consumes it (task 13.4) | valid-detection-benchmark |
| Pre-push safety net | Implementation 67/79; wiring unchanged by this work | Unaffected until prover recall/FA hold at pilot | pre-push-safety-net |

Migration order for mapping.py families is deliberate: Stapler first (task 11.6 proves the registry path on
the family the pool exercises most), then one family per migration, each deleting its legacy block from
`mapping.py` in the same change.
