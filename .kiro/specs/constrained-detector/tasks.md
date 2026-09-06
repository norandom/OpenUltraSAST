# Implementation Plan

- [x] 1. The ceiling, offline: what a candidate detector could possibly find
- [x] 1.1 Candidate enumeration from the semantic IR, shaped by family
  - `learning/candidates.py`: `Candidate` (path, line, kind, name, text, argument texts and names, the binding chain the IR resolved, the guards in scope, the enclosing function, and an `id` of `path:line:name`); `CandidateKind` of call, bind, operation, config; `FAMILY_SHAPE` mapping each family to the kinds that can carry its bug; `enumerate_candidates` returning a `CandidateSet` with the candidates, the count discarded past the bound, and a reason of empty, `unsupported_language` or `no_candidate`.
  - Call and bind candidates come from `FunctionIR.calls` and `.binds`; operation candidates for access control come from the obligations facts with the decorators and in-body guards in scope; config candidates are bindings whose value is a literal in a configuration position. The pattern ruleset is never the generator.
  - Ordering is `(path, line, name)` and the bound is a constant, so the batches a later task forms are determined by the input alone.
  - Observable: on the shared obligations fixture every family shape yields the sites its docstring names; a file the IR cannot parse yields `unsupported_language` and no candidates; a labeled function with no calls or binds yields `no_candidate`; enumerating twice returns an identical sequence.
  - _Requirements: 1.1, 1.2, 1.4, 1.5, 1.6_

- [x] 1.2 The ceiling report and the `learning candidates` command
  - `candidates.ceiling(cases, taxonomy)` returns, per family and per slice, the number of labeled functions for which at least one candidate was enumerated, the sites-per-function distribution, and the rows that yielded nothing with their reason; `ousast learning candidates --catalog --slice --json` prints it and writes the artifact. No model is called at any point.
  - Observable: the command runs offline with no endpoint configured; the artifact reproduces the recorded web-slice figures (ruleset 12.1%, IR 96.6%, median 10 sites) and adds the deciding slices; running it twice produces a byte-identical artifact.
  - _Requirements: 1.3, 3.5_
  - _Depends: 1.1_

- [x] 1.3 The stop-or-go reading of the ceiling
  - The artifact states, per deciding slice, the ceiling against that slice's recorded detection rate from round zero, and names the comparison as the condition on which this design continues. The reading is written into the spec's Implementation Notes with the numbers, whichever way it goes.
  - Observable: the artifact carries agent-vfc, vfc-js, vfc and github ceilings beside 44.4% and the other recorded rates, and the notes state whether any deciding slice fails the condition.
  - _Requirements: 1.3, 3.5, 3.7_
  - _Depends: 1.2_

- [ ] 2. One definition of the checks, used to constrain and to score
- [ ] 2.1 (P) Predicates extracted from the scorer without changing it
  - `learning/predicates.py`: `Violation`, the named predicates `line_in_parsed_function`, `sink_at_line`, `family_in_taxonomy` and `source_in_function`, and `check_claim`; `scoring._hits`, `_others` and `_fabricated` delegate to them.
  - Observable: the scorer's unit tests pass unchanged, and a test reproduces the recorded round-zero numbers for vibe-py and agent-vfc from the committed artifacts exactly, so the refactor's observable effect is none.
  - _Requirements: 4.1, 4.4, 6.1_

- [ ] 2.2 The unscorable vocabulary gains `no_candidate`
  - `no_candidate` joins the reasons `unscorable_reason` can return, distinct from `unresolved_label` (the corpus named a function nothing parses) and from `unsupported_language` (the tooling could not parse at all); it leaves every denominator and is listed by reason.
  - Observable: a pair whose labeled function has no call or bind is reported unscorable with `no_candidate` and appears in the per-family unscorable tally, not as a miss.
  - _Requirements: 1.5, 6.1_
  - _Depends: 1.1, 2.1_

- [ ] 3. The detector
- [ ] 3.1 Typed judgment, one bounded question per candidate, no tools
  - `learning/judgments.py`: `Judgment` (candidate id, verdict, source expression, guard or empty, family, rationale) and `judge_candidates(candidates, config, client, model, taxonomy, violation=None)` making one call per fixed-size batch with `tools=[]` and JSON-object mode, the family's prompt and checklist as the system message, and the batch rendered as data. An answer naming a candidate id absent from the batch is dropped before any predicate runs.
  - Observable: a scripted client shows one call per batch and no tool schema offered; a reply with a fabricated candidate id yields no judgment and increments the `fabricated_candidate` tally; a reply that is prose yields no judgment rather than a parsed guess.
  - _Requirements: 2.1, 2.2, 2.3_
  - _Depends: 1.1_

- [ ] 3.2 `run_constrained_detector`, with the predicates enforced and one retry
  - `detectors.run_constrained_detector` enumerates, batches, judges, checks each judgment with `check_claim`, retries a violating batch exactly once with the violation injected, discards what still violates, and returns `StaticFinding`s tagged `family:`, `detector:` and `candidate:<id>`. `run_family_detector` is untouched and stays selectable.
  - Observable: a judgment naming a line outside the parsed function is retried once and then discarded, and the discard is counted by predicate name; every finding carries the candidate id it came from; the unconstrained hunter still runs from the same configuration.
  - _Requirements: 2.5, 4.1, 4.2, 4.3, 6.5_
  - _Depends: 2.1, 3.1_

- [ ] 3.3 Two runs make the same calls
  - A recording client captures the full sequence of `(model, messages, tools)` for a run; two runs over the same region and configuration produce an identical sequence.
  - Observable: the test fails if candidate ordering, batching or the retry condition becomes input-dependent in a way the input does not determine; it is run repeatedly in the suite to catch order instability.
  - _Requirements: 2.4_
  - _Depends: 3.2_

- [ ] 3.4 Selecting the detector, and its degradations
  - `[learning] detector = "hunter" | "constrained"` defaulting to `hunter`; `--detector` on `learning score` and `learning baseline`; without the semantic extra the constrained detector reports `unsupported_language` and scores nothing; without an endpoint it records `learning_endpoint_unavailable`; its spend goes through the client meter and stops at the cap.
  - Observable: both detectors run from the same command over the same catalog; the extra-free matrix reports the recorded reason rather than failing; a run with no endpoint still writes its artifact.
  - _Requirements: 7.1, 7.2, 7.4, 7.5_
  - _Depends: 3.2_

- [ ] 4. Real-world code decides
- [ ] 4.1 (P) Deciding and development slices, and the overfitting gap
  - `learning/slices.py`: `DECIDING_SLICES` of agent-vfc, vfc-js, vfc and github; `DEVELOPMENT_SLICES` of vibe-py; `overfitting_gap` over per-slice metrics; `cross_slice_verdict(before, after)` rejecting by name any change that improves a development slice and regresses a deciding one; `teachable(slice, cases)` false while every row of a slice sits below a gating tier.
  - Observable: a change that improves vibe-py and regresses agent-vfc is rejected with agent-vfc named; the gap over the recorded baseline reads 83.3% against 44.4%; `teachable("agent-vfc", …)` is false today and the reason is the tier.
  - _Requirements: 3.2, 3.3, 3.4, 3.6_

- [ ] 4.2 Per-slice publication, and memory kept out of the web aggregate
  - `publish` prints a per-slice table, the overfitting gap beside every headline number, the statement that the deciding slices teach nothing today, and the memory family separately from any figure a reader would take as web-taxonomy performance; no aggregate is printed without its per-slice rows.
  - Observable: the published section carries a row per slice and refuses to print a cross-slice aggregate alone; the 176 vfc rows appear under their own heading; the regenerated roadmap section is byte-identical on a second run.
  - _Requirements: 3.1, 3.4, 3.6, 3.7_
  - _Depends: 4.1_

- [ ] 5. The comparison, and what it retires
- [ ] 5.1 Constrained against unconstrained, per slice
  - Both detectors scored by the same scorer over the same catalog at the same K, on every slice; detection, leak and pair-correct rates published against the recorded 64.9%, 12.3% and 52.6%, with cost per correct pair against $0.030 and $0.136. If the constrained detector is behind on any deciding slice, that is the headline of the artifact.
  - Observable: one artifact holds both detectors' numbers per slice with the deltas, and its summary line names the deciding-slice result rather than the aggregate.
  - _Requirements: 6.2, 6.3, 6.4_
  - _Depends: 3.4, 4.2_

- [ ] 5.2 The trajectory and the floor, re-measured
  - The trajectory experiment re-run against the constrained detector, publishing distinct trajectories per pair; the per-family noise floor re-measured at the same K as the baseline and published beside it; every published K-run number labelled as repeated measurements or as an ensemble of distinct procedures.
  - Observable: the artifact reports the distinct-trajectory count per pair for both detectors on the same twelve pairs, and the floors side by side.
  - _Requirements: 5.1, 5.2, 5.4_
  - _Depends: 5.1_

- [ ] 5.3 What the floor retires, named
  - If a family's re-measured floor is zero, the artifact states that its K-run requirement and its regression budget are unnecessary and names the `learning-harness` requirements that would be amended — 3.5, 8.2 and 9.5 — without amending them here.
  - Observable: the artifact carries the per-family verdict and the named requirements, and the spec's Implementation Notes record the escalation to the maintainer.
  - _Requirements: 5.3_
  - _Depends: 5.2_

- [ ] 5.4 Gates, matrices and the boundary
  - Detection, map and local pair gate outputs byte-identical to the committed baseline; both test matrices green; the core install still resolving with no dependencies; every prompt and persisted trajectory redacted.
  - Observable: the committed gate-baseline test passes in both matrices, and a planted key in a judgment prompt does not survive into the artifact.
  - _Requirements: 7.3, 7.4, 7.5_
  - _Depends: 5.1_

## Task-plan review notes

- Phase 1 is deliberately able to end the feature. Tasks 1.1 to 1.3 call no model, so the condition in 1.3 — a deciding slice whose ceiling is below its recorded detection rate — is reachable before any budget is spent. The ruleset variant of this design would have failed that condition at 12.1% against 64.9%.
- Task 2.1 is the only task that touches `scoring.py`, and its observable is that nothing changes. The recorded round-zero artifacts are the pin; if they cannot be reproduced exactly, the refactor is wrong and not the numbers.
- `(P)` marks the two tasks with no dependency on a model call: 2.1 and 4.1 can be built and reviewed while phase 1 runs.
- Task 3.3 is the one that would have caught the defect this whole spec exists for. It belongs in the suite, run repeatedly, not in a one-off measurement.

## Implementation Notes

- Task 1.1 (2026-09-06, RED first: 13 failing tests in `tests/test_candidate_enumeration.py`; then green). `learning/candidates.py`. Two things the fixtures taught: the IR emits a chained call twice at one line, once bare and once carrying the keyword arguments, so deduplication keeps the richest — a bare `filter_by` and `filter_by(user_id=owner)` are the same site and only one of them says what the constraint was. And `leaky` and `constrained` in the shared obligations fixture **both** discharge through `filter_by`; what separates them is that one binding chain ends at `request.args.get('owner')` and the other at `request.user.id`. The test asserts that contrast, which is the judgement the model is being narrowed to.
- Task 1.2 (2026-09-06, RED first: 3 failing tests; then green). `candidates.ceiling(cases, taxonomy, generator="ir"|"ruleset")` and `ousast learning candidates`. The `ruleset` arm exists so the comparison that rejected it stays a measurement rather than a remembered number. The command calls no model and its artifact is byte-identical on a second run.
- Task 1.3 (2026-09-06). **Verdict: go.** Measured offline across every slice, `benchmarks/measurements/2026-09-06-candidate-ceiling-all-slices.json`:

  | slice | ceiling | round-zero detection | headroom |
  |---|---|---|---|
  | agent-vfc (deciding) | **89.7%** | 44.4% | +45.3 |
  | vfc (deciding, non-gating) | 84.7% | pending | — |
  | vfc-js (deciding) | 52.9% | none recorded | see below |
  | github (deciding) | 100.0% | none recorded | — |
  | vibe-py (development) | 100.0% | 83.3% | +16.7 |

  The margin is largest on agent-vfc, which is the slice that matters most and the one the tool is actually for. Per family: config_secrets, deserialization, output_encoding and untrusted_destination 100%; access_control 90%; path 87.5%; memory 86.4%; injection 84.6%; prototype 71.4%; `unknown` 0% of two rows, which is what abstention looks like.

  - **A shape correction the measurement forced, before the detector existed.** `config_secrets` first read 63.6% with a bind-and-literal shape. A permissive default is as often an argument to a call — `cors({origin: '*'})`, `app.use(session({secure: false}))` — as it is a binding; adding call sites to that family's shape took it to 100% and recovered `new-erp-final-app-6e9644`, `zoonk-origin-bfbf67`, `melodix-playerprovider-089931` and `registry-proxy-worker-426847`.
  - **Carry-forward, and it is not this feature's to fix.** vfc-js sits at 52.9% because eight of seventeen rows label a function the JavaScript CST names `<anon>`: `module.exports.publish = function () {}` and its relatives. The gap is in function *naming*, not in candidate generation, and it caps the existing hunter on that slice exactly as much. Same class as the `_declarator_start` defects found during learning-harness task 4.1.
  - vfc's 21 `unsupported_language` rows are C and C++ files the IR declines; they are the non-gating memory slice and are already excluded from every web number.
