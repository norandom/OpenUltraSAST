# Implementation Plan

This plan splits the fused regex layer into three governed owners (rules detect, CWE policy decides severity/scope, project score is the optimization target) and adopts HarnessX behind an optional extra. Tasks are grouped into four phases. Each phase is independently shippable and keeps the ≥90% recall / <10% FP detection gate green. Phases 1-2 (Foundation) and the early Core work stay zero-dependency and byte-identical by default; the HarnessX execution and self-improvement work (Integration) lives behind a lazy, SHA-pinned extra; Validation locks the cross-cutting gates and the dependency-weight decision.

## Phase 1 — Foundation: Governance & Scoring Planes (zero-dep)

- [x] 1. Stand up the central CWE policy authority
- [x] 1.1 Vendor the verycode CWE severity data and build the Policy Store loader
  - Vendor the verycode CWE-to-severity dataset into the governance plane and parse it with the standard library only, tolerating the trailing-space severity column header.
  - Expose, per CWE, an authoritative 0-5 severity, a static scope flag, and a dynamic scope flag; mark dynamic-only CWEs as report-only.
  - Observable completion: loading the policy yields the full set of CWE policy entries with correct static/dynamic flags and zero third-party imports, verified by a unit test.
  - _Requirements: 2.6, 2.9_
  - _Boundary: PolicyStore_

- [x] 1.2 Expose policy-governed severity resolution
  - Resolve a finding's severity exclusively from the Policy Store keyed on the rule's CWE, discarding any severity string carried in legacy rule data.
  - Guarantee that two findings whose rules map to the same CWE receive identical severity.
  - Observable completion: a resolution call returns the policy severity (never a legacy string) and is identical for two rules sharing a CWE, proven by a unit test.
  - _Requirements: 2.2, 2.3_
  - _Boundary: PolicyStore_

- [x] 1.3 Enforce the fail-loud startup CWE-resolution invariant
  - Assert at startup that every enabled rule's CWE resolves in the Policy Store; abort the scan loudly before any work when an enabled rule's CWE is unmapped.
  - Observable completion: an enabled rule with an unmapped CWE aborts the scan with a loud error and no findings are produced, proven by an integration test.
  - _Requirements: 2.7_
  - _Boundary: PolicyStore_
  - _Depends: 1.1_

- [x] 2. Build the project Score Model and CI gates (zero-dep)
- [x] 2.1 Compute the 0-100 policy-weighted, reachability-adjusted project score
  - Compute a single 0-100 project score from policy-governed severity weights multiplied by a reachability multiplier over reported findings, using the standard library only.
  - Key the reachability multipliers exactly on the three emitted reachability values (`reachable`, `inferred-file-surface`, `unknown`) without redefining the vocabulary.
  - Assign a zero score penalty to findings whose CWE is dynamic-only or unmapped, reporting them as out-of-scope or unmapped instead of scoring them.
  - Observable completion: a no-penalty corpus scores 100, a single severity-5 reachable finding scores roughly 43, and dynamic-only/unmapped findings contribute zero penalty, proven by boundary unit tests.
  - _Requirements: 5.1, 5.2, 5.3, 5.9_
  - _Boundary: ScoreModel_
  - _Depends: 1.1_

- [x] 2.2 Emit the scan-level score artifact and manifest score block
  - Emit a score artifact containing the project score, the maximum severity, the total penalty, a by-category breakdown, the out-of-scope dynamic-only count, the unmapped-CWE list, and the gate verdict; include the score block in the scan manifest.
  - Observable completion: a scan writes a score artifact with every required field and merges the score block into the manifest, verified against the documented artifact schema.
  - _Requirements: 5.5_
  - _Boundary: ScoreModel_
  - _Depends: 2.1_

- [x] 2.3 Implement the two-condition CI score gate (advisory-first)
  - Fail the build when any reported finding maps to policy severity 5 and has reachability `reachable`.
  - When configured as blocking, fail the build when the project score is below the minimum; until the score constants are calibrated against the corpus, compute and report the score advisory-first without blocking.
  - Observable completion: the hard gate fails on a severity-5 reachable finding while the score gate reports advisory-only by default, proven by gate tests.
  - _Requirements: 5.7, 5.8, 5.9_
  - _Boundary: CI Score Gate_
  - _Depends: 2.1_

- [x] 2.4 Centralize ruleset/policy/score configuration
  - Add configuration entries for the ruleset, policy, and score data locations plus the gate thresholds and emission floors used by later phases.
  - Observable completion: the scan reads the score constants and emission thresholds from configuration rather than hardcoded literals, confirmed by a config-driven test.
  - _Requirements: 5.8_
  - _Boundary: Packaging Configuration, ScoreModel_

## Phase 2 — Core: Rules-as-Data and Benchmark Signals (zero-dep, byte-identical)

- [x] 3. Convert detection rules into versioned, governed data
- [x] 3.1 Externalize detection patterns into a versioned Ruleset Store
  - Load detection rules from versioned data files in which each rule declares a pattern, a CWE, tags, and a loop-controlled status, carrying no rule-local severity field.
  - Remove the rule-local severity field from the in-memory rule model so severity can only come from policy.
  - Observable completion: the existing pattern rules load from versioned data files with no severity attribute present, proven by a unit test asserting the absence of the field.
  - _Requirements: 2.1, 2.9_
  - _Boundary: RulesetStore_

- [x] 3.2 Implement the three-status volume control
  - Support exactly three rule statuses — `enabled`, `shadow`, `disabled` — where enabled fires/scores/reports, shadow fires and records outcomes but is excluded from report and score, and disabled does not fire.
  - Exclude shadow-status findings from the reported set and from the score input while still recording their outcome for precision tracking.
  - Observable completion: an enabled rule appears in report and score, a shadow rule is excluded from both yet records an outcome, and a disabled rule never fires, proven by a unit test across all three statuses.
  - _Requirements: 2.4, 2.5, 5.4_
  - _Boundary: RulesetStore, ScoreModel_
  - _Depends: 3.1, 2.1_

- [x] 3.3 Remap the unmapped C/C++ buffer rules to a scored CWE
  - Remap the C/C++ buffer-handling rules that reference the unmapped CWE-120 to CWE-121 so they resolve in policy and contribute a nonzero penalty.
  - Observable completion: the remapped buffer rules resolve to a severity-5 policy entry and produce a nonzero score penalty, verified by a unit test.
  - _Requirements: 2.8_
  - _Boundary: RulesetStore_
  - _Depends: 3.1, 1.1_

- [x] 3.4 Wire findings and severity resolution through the governance plane
  - Pass the loaded ruleset into the finding-detection stage instead of reading an implicit module-level rule list, and resolve every finding's severity through the Policy Store.
  - Apply emission thresholds so not every regex match becomes a reported finding, replacing the old "rule is its own volume control" behavior.
  - Observable completion: a scan produces findings with policy-resolved severity and shadow findings filtered out, while the default ruleset keeps benchmark output byte-identical to the pre-feature baseline.
  - _Requirements: 2.2, 2.3, 2.5, 6.2_
  - _Boundary: PolicyScoringProcessor, RulesetStore, PolicyStore_
  - _Depends: 3.1, 3.2, 1.2_

- [x] 4. Make benchmark output an actionable per-rule signal
- [x] 4.1 Attribute misses and false positives to rules
  - Attribute every recorded miss and every recorded false positive to a rule identifier and aggregate per-rule precision and recall in the benchmark metrics.
  - Observable completion: a benchmark run reports per-rule precision/recall and every miss and false positive carries a rule identifier, verified by a metrics test.
  - _Requirements: 4.1_
  - _Boundary: Benchmark Harness_
  - _Depends: 3.1_

- [x] 4.2 Emit a per-rule recommendation delta artifact
  - Replace the inert improvement-candidate stub with a per-rule recommendation artifact recommending enable, disable, shadow, threshold, or evidence-floor changes per rule.
  - Observable completion: a benchmark run writes a recommendation artifact with per-rule suggested actions alongside its records, verified against the documented delta schema.
  - _Requirements: 4.2_
  - _Boundary: Benchmark Harness_
  - _Depends: 4.1_

- [x] 4.3 Introduce the loop-owned ledger and re-key calibration to rules
  - Add the loop-owned overlay ledger that records per-rule status, evidence floor, threshold, and precision, applied over the ruleset at load time.
  - Re-key calibration from the first-tag key to the rule identifier and write status flips into the ledger rather than only demoting ranking.
  - Observable completion: an empty ledger leaves behavior byte-identical to the prior phase while a ledger entry overlays a rule's status at load, proven by an integration test.
  - _Requirements: 2.4, 5.6, 6.2_
  - _Boundary: RulesetStore, Calibration subsystem_
  - _Depends: 3.1, 3.2_

- [x] 4.4 Convert false-positive confirmation into a reachability knob
  - When confirming a false positive, lower the finding's effective reachability multiplier rather than delete the rule, so recall stays high while the score stops over-penalizing.
  - Observable completion: confirming a false positive lowers the finding's effective reachability multiplier and the rule still fires, proven by a calibration test.
  - _Requirements: 5.6_
  - _Boundary: Calibration subsystem, ScoreModel_
  - _Depends: 4.3, 2.1_

## Phase 3 — Integration: HarnessX Execution & Self-Improvement (optional extra)

- [x] 5. Gate and package the HarnessX dependency-weight decision
- [x] 5.1 Run the dependency dry-run audit and record the transitive graph
  - Before adopting the HarnessX execution stages, run a dependency dry-run audit and record the realized transitive dependency graph.
  - If the audited graph pulls a browser-binary, container-SDK, or web-server stack as a mandatory dependency and it is judged unacceptable, select the pre-specified vendored lean subset under the same extra name with the heavy subtrees removed.
  - Observable completion: the audit produces a recorded transitive-dependency graph and a documented accept-extra-or-vendor-subset decision before any HarnessX execution code is wired in.
  - _Requirements: 7.3, 7.4, 7.7_
  - _Boundary: Packaging Configuration_

- [x] 5.2 Configure HarnessX as a SHA-pinned optional extra with a capability guard
  - Keep the core dependency list empty and expose HarnessX only as an optional extra pinned to a specific commit revision; initialize any submodule non-recursively so the large RL fork subtree is not pulled.
  - Guard every HarnessX import behind a capability check and import it lazily so heavy code paths stay cold in the default install.
  - Observable completion: the default install resolves with an empty core dependency list and HarnessX symbols are only imported after the capability check passes, verified by an import-cold test.
  - _Requirements: 7.1, 7.2, 7.6_
  - _Boundary: Packaging Configuration_
  - _Depends: 5.1_

- [ ] 6. Adopt HarnessX at the hunter loop and verifier
- [x] 6.1 Run the hunter pool stage on a real HarnessX agent loop
  - Run the hunter pool stage on a real HarnessX run loop with the control, tool, and observability processors registered in the hunter sub-harness, invoked from the existing hunter-pool stage callback.
  - Confine all asynchronous execution to this single stage so the deterministic stages remain synchronous.
  - Observable completion: with the extra installed, the hunter pool produces per-target trajectories from a real agent loop while all other stages stay synchronous, verified by an integration test.
  - _Requirements: 1.1, 1.4_
  - _Boundary: HxScanOrchestrator_
  - _Depends: 5.2_

- [x] 6.2 Map stage events and identifiers onto HarnessX hooks
  - Map the existing stage-start/stage-end events to the HarnessX step-level hooks and the scan identifier to the HarnessX run identifier without losing trace continuity.
  - Observable completion: a HarnessX-backed run preserves trace continuity with stage events mapped to step hooks and the scan id mapped to the run id, verified by inspecting the emitted trace.
  - _Requirements: 1.7_
  - _Boundary: HxScanOrchestrator_
  - _Depends: 6.1_

- [ ] 6.3 (P) Run deterministic stages as model-disabled HarnessX processors with slot contracts
  - Run each deterministic stage under HarnessX with model invocation disabled so no deterministic stage incurs a model call.
  - Preserve each stage's declared read/write slot allow-list and validate slot access on every lifecycle hook.
  - Observable completion: deterministic stages execute under HarnessX with no model calls and a slot-contract violation is raised on undeclared slot access, proven by a slot-contract test.
  - _Requirements: 1.5, 1.6_
  - _Boundary: HxScanOrchestrator_
  - _Depends: 6.1_

- [x] 6.4 (P) Add the LLM-judge verifier with a structural fallback
  - Produce verification verdicts using the HarnessX llm-judge helpers when the extra is present, mapping the strict-JSON verdict to a verification result.
  - Retain the existing structural verifier (which rejects on unknown reachability) verbatim as the zero-dependency fallback.
  - Observable completion: with the extra present the judge produces verdicts and with it absent the structural verifier produces equivalent verdicts, proven by a paired verifier test.
  - _Requirements: 1.2_
  - _Boundary: VerifyProcessor_
  - _Depends: 5.2_

- [x] 6.5 Fall back gracefully when a HarnessX capability is unavailable
  - When a HarnessX-backed stage is enabled but its capability is unavailable at runtime, fall back to the existing equivalent stage and record the degradation in the scan manifest.
  - Observable completion: requesting a HarnessX stage whose capability is missing runs the existing equivalent and records a degradation entry in the manifest, proven by a fallback test.
  - _Requirements: 1.8_
  - _Boundary: HxScanOrchestrator_
  - _Depends: 6.1, 6.4_

- [x] 7. Stand up the bounded self-improvement loop
- [x] 7.1 Add the two bounded edit levers
  - Expose exactly two new edit levers: a rule lever covering rule status, evidence floor, and threshold, and a policy lever covering evidence floor, scope, and the score constants.
  - Observable completion: the loop's valid-lever set includes exactly the rule and policy levers and rejects any edit outside their declared fields, verified by a lever test.
  - _Requirements: 3.1_
  - _Boundary: EvolveValidator, improve/evolve.py_
  - _Depends: 5.2_

- [x] 7.2 Enforce the rule/policy edit safety bounds in the validator
  - Reject any loop edit that modifies detection pattern text and any edit that modifies the authoritative 0-5 CWE severity.
  - Reject moving a rule directly from enabled to disabled, requiring shadow as a mandatory intermediate staging state.
  - Assert that each edit parses, that status is one of the three literals, that threshold/evidence-floor changes stay within configured bounds, that an added rule does not duplicate an existing identifier, and that every referenced CWE resolves in policy; raise a rule-change validation error and reject the whole round on any failure.
  - Observable completion: each prohibited edit (pattern change, severity change, enabled-to-disabled jump, duplicate identifier, unmapped CWE, out-of-bounds threshold) is rejected and rejects the round, proven by validator unit tests.
  - _Requirements: 3.2, 3.3, 3.4, 3.5, 3.8_
  - _Boundary: EvolveValidator_
  - _Depends: 7.1, 1.1_

- [x] 7.3 Add the novelty, replay, and journal gates
  - Block re-proposing a previously reverted edit that lacks a retry rationale via the novelty gate.
  - Run a replay smoke gate before any benchmark re-run proving the edited ruleset and policy still load and boot.
  - Record each rule and policy edit, its lever, and its outcome in the journal so every change is attributable and reversible.
  - Observable completion: a reverted re-proposal without rationale is blocked, a non-booting edited ruleset is rejected before re-benchmark, and every edit appears in the journal with its lever and outcome, proven by gate tests.
  - _Requirements: 3.6, 3.7, 3.9_
  - _Boundary: EvolveValidator, improve/evolve.py_
  - _Depends: 7.2_

- [x] 7.4 Convert benchmark deltas into loop signals
  - Convert the per-rule recommendation delta and false-positive learnings into a loop signal file, writing recall-side items as miss signals and precision-side items as verifier-reject or false-positive signals.
  - Observable completion: a benchmark run produces a signal file whose recall-side entries are miss signals and precision-side entries are verifier-reject/false-positive signals, verified against the documented signal schema.
  - _Requirements: 4.3_
  - _Boundary: improve/evolve.py_
  - _Depends: 4.2, 7.1_

- [x] 7.5 Implement the hard acceptance gate with byte-for-byte revert
  - After the meta-agent edits rules or policy, re-run the benchmark and accept the round only if aggregate recall is at least 90% AND false-positive rate is under 10% AND the project score did not regress on the held set AND no unpredicted regression occurred.
  - On any failed acceptance condition, revert the round and restore the rule and policy configuration byte-for-byte.
  - Observable completion: a round that regresses recall is reverted and the configuration is restored byte-for-byte, while a compliant round is accepted and persisted, proven by a self-improvement integration test.
  - _Requirements: 4.4, 4.5, 6.3_
  - _Boundary: improve/evolve.py_
  - _Depends: 7.3, 7.4, 4.1_

- [x] 7.6 Auto-shadow precision-draggers, nominate coverage gaps, and separate the objective
  - Auto-shadow a rule that drags aggregate precision below the gate rather than delete it, preserving recall while removing the false-positive cost.
  - Nominate a new or loosened rule through the signal file when a coverage gap surfaces as a persistent miss, leaving pattern authoring to a human pull request.
  - Treat maximizing the project score as the optimization objective and the recall/FP gate as a separate hard feasibility constraint that is never folded into the score reward.
  - Observable completion: a deliberately noisy rule is auto-shadowed (not deleted) when it drags precision, a persistent miss emits a rule nomination, and the loop cannot raise the score by shadowing rules that breach the gate, proven by integration tests.
  - _Requirements: 4.6, 4.7, 4.8_
  - _Boundary: improve/evolve.py_
  - _Depends: 7.5_

## Phase 4 — Validation: Cross-Cutting Gates & Non-Regression

- [x] 8. Lock the detection-gate non-regression checks into CI
- [x] 8.1 Enforce the per-merge recall/FP detection gate
  - Evaluate aggregate recall and aggregate false-positive rate on the benchmark corpus on every merge and fail the merge if recall is below 90% or the false-positive rate is at or above 10%.
  - Treat the recall/FP gate as a hard constraint that is never folded into the project-score reward, blocking any change that breaches the gate regardless of score improvement.
  - Observable completion: a CI run fails the merge when recall drops below 90% or false-positive rate reaches 10%, and a score improvement cannot unblock a gate-breaching change, proven by pipeline tests.
  - _Requirements: 6.1, 6.5, 6.6_
  - _Boundary: CI Pipeline_
  - _Depends: 4.1_

- [x] 8.2 (P) Assert byte-identical benchmark baseline for the zero-dep phases
  - With the default ruleset and an empty loop ledger, assert the benchmark output is byte-identical to the pre-feature baseline for the governance and rules-as-data phases.
  - Observable completion: a golden-diff test confirms byte-identical benchmark output with the default ruleset and empty ledger.
  - _Requirements: 6.2_
  - _Boundary: Benchmark Harness, CI Pipeline_
  - _Depends: 3.4, 4.3_

- [x] 8.3 (P) Confirm HarnessX-backed stages stay within detection tolerance
  - When a HarnessX-backed stage is enabled, confirm recall and false-positive rate stay within the configured tolerance of the equivalent zero-dependency baseline.
  - Observable completion: a CI run with a HarnessX-backed stage enabled keeps recall/FP within the configured tolerance of the baseline, proven by a tolerance test.
  - _Requirements: 6.4_
  - _Boundary: CI Pipeline, HxScanOrchestrator_
  - _Depends: 6.1, 8.1_

- [x] 8.4 (P) Add the zero-dependency guard test
  - Run a guard test confirming that with HarnessX absent the governance, scoring, and benchmark planes operate and CI gating runs in the default install.
  - Observable completion: the guard test passes with HarnessX uninstalled and fails if any governance/scoring/benchmark path imports HarnessX.
  - _Requirements: 7.5_
  - _Boundary: CI Pipeline_
  - _Depends: 8.1_

- [x] 9. Validate scan-pipeline integrity and serialization
- [x] 9.1 (P) Verify capability fallback and unchanged sync-driver behavior
  - Confirm that with the extra absent, quick and standard scans execute through the existing sync driver with behavior unchanged from the pre-adoption baseline, and that a requested-but-unavailable HarnessX stage records a degradation.
  - Observable completion: an extra-absent scan matches the pre-adoption baseline and a missing-capability request records a manifest degradation, proven by an end-to-end fallback test.
  - _Requirements: 1.3, 1.8_
  - _Boundary: HxScanOrchestrator, CI Pipeline_
  - _Depends: 6.5_

- [x] 9.2 (P) Verify slot serialization round-trips on resume
  - Confirm each scan slot type serializes and restores without loss after a resume, guarding against non-serializable slots restoring as empty.
  - Observable completion: a per-slot-type round-trip test passes for every scan slot after a resume cycle.
  - Done for the current artifact-persistence model (findings/ranking/file-target/verification/score round-trip + the real findings.json reload path in `tests/test_scan_pipeline_integrity.py`). The HarnessX processor slot-contract serialization variant remains deferred with task 6.3.
  - _Requirements: 1.5_
  - _Boundary: HxScanOrchestrator_
  - _Depends: 6.3_
