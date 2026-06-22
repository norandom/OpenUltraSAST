# Requirements Document

## Introduction

OpenUltraSAST today fuses three responsibilities into one regex layer: detection patterns also carry their own severity strings and act as the sole volume control, so a noisy rule can dominate scan output, set its own criticality, and fire forever with no central governance. This feature splits those responsibilities into three governed owners — rules detect, a central CWE policy decides severity and scope, and a single project score becomes the optimization target — and adopts the HarnessX runtime exactly where it pays off: the LLM hunter loop, the LLM-judge verifier, and a meta-harness self-improvement loop that adapts rules and policy gates under hard bounds.

The work spans five user asks. First, OpenUltraSAST shall adopt HarnessX directly at the hunter loop and migrate the existing scan flow stage-by-stage onto HarnessX processors. Second, detection rules shall become versioned data governed centrally, with severity sourced from the verycode CWE policy rather than from the rule itself. Third, the HarnessX meta-harness shall adapt rules and policy gates within bounded levers. Fourth, benchmark results shall drive that adaptation as actionable signals with a hard acceptance gate. Fifth, a Veracode-style project score shall be computed from policy-weighted, reachability-adjusted findings and gated in CI.

Two cross-cutting constraints govern every part of this feature. The existing detection gate of at least 90% recall and under 10% false-positive rate on the benchmark corpus must never regress, at any phase, for any change. And the HarnessX runtime must be adopted in a way that preserves the project's zero-dependency posture for the governance and scoring planes, so an explicit dependency-weight decision controls whether HarnessX ships as an optional extra or as a vendored lean subset.

## Boundary Context

- **In scope**: detection rules as versioned data; a central CWE-to-severity policy with static/dynamic scope; a single project score (0-100) with a two-condition CI gate; HarnessX adoption at the hunter loop, the verifier, and the self-improvement meta-harness; benchmark-to-signal conversion with per-rule attribution; bounded loop authority over rule status, evidence floors, thresholds, and score constants; a dependency-weight audit and decision; preservation of the recall/FP detection gate.
- **Out of scope**: authoring new detection pattern text by the loop (human pull-request only); editing the authoritative 0-5 CWE severity by the loop (verycode-upstream authority); a full single-step HarnessX rewrite of all deterministic stages and weight-level reinforcement learning (deferred, optional, later phase); changing the reachability vocabulary, which remains exactly `reachable | inferred-file-surface | unknown`; dynamic/DAST scoring, which is report-only for a static tool.
- **Adjacent expectations**: the governance and scoring planes shall run with no HarnessX present and `dependencies = []`; CI gating (score plus benchmark) shall run in the zero-dependency default install; HarnessX, when present, shall be confined behind a capability check and lazy imports so heavy code paths stay cold in the default install.

## Requirements

### Requirement 1: HarnessX Direct Adoption and Scan-Flow Migration

**Objective:** As an OpenUltraSAST maintainer, I want the scan flow to adopt the HarnessX runtime directly at the LLM hunter loop and migrate the existing stages onto HarnessX processors in a staged way, so that the project gains the HarnessX agent loop, journal, and trajectory machinery without a high-risk big-bang rewrite.

#### Acceptance Criteria
1. Where the HarnessX extra is installed, the Scan Orchestrator shall run the hunter pool stage on a real HarnessX `Harness.run()` loop with the HarnessX control, tool, and observability processors registered in the hunter sub-harness.
2. Where the HarnessX extra is installed, the Verify Processor shall produce verification verdicts using the HarnessX llm-judge helpers and shall retain the structural verifier as a zero-dependency fallback.
3. While the HarnessX extra is absent, the Scan Runtime shall execute `quick` and `standard` scans through the existing sync driver with behavior unchanged from the pre-adoption baseline.
4. When the hunter pool stage runs under HarnessX, the Scan Orchestrator shall confine all asynchronous execution to that single stage so that the deterministic stages remain synchronous.
5. The Scan Runtime shall preserve each stage's declared read and write slot allow-list and shall validate slot access on every lifecycle hook, so that the existing provenance and audit discipline is retained under the HarnessX runtime.
6. Where a deterministic stage runs under HarnessX, the Scan Runtime shall execute it with model invocation disabled so that no deterministic stage incurs a model call.
7. When migrating event names, the Scan Runtime shall map the existing `stage_start`/`stage_end` to the HarnessX step-level hooks and `scan_id` to the HarnessX run identifier without losing trace continuity.
8. If a HarnessX-backed stage is enabled and the corresponding HarnessX capability is unavailable at runtime, then the Scan Runtime shall fall back to the existing equivalent stage and shall record the degradation in the scan manifest.

### Requirement 2: Central Security-Affine Ruleset Governance

**Objective:** As a security policy owner, I want detection rules to be versioned data whose severity and scope come from a central CWE policy rather than from the rule itself, so that one CWE maps to one governed severity and no rule can be too influential by setting its own criticality or volume.

#### Acceptance Criteria
1. The Ruleset Store shall load detection rules from versioned data files in which each rule declares a pattern, a CWE, tags, and a loop-controlled `status`, and shall not carry any rule-local severity field.
2. When resolving the severity of a finding, the Policy Scoring Processor shall read severity exclusively from the Policy Store keyed on the rule's CWE and shall discard any severity string carried in legacy rule data.
3. While two enabled rules map to the same CWE, the Policy Scoring Processor shall assign both findings the identical policy-governed severity so that two rules for one CWE can no longer disagree.
4. The Ruleset Store shall support exactly three rule statuses — `enabled`, `shadow`, and `disabled` — where `enabled` fires and scores and reports, `shadow` fires and records outcomes but is excluded from the report and the score, and `disabled` does not fire.
5. When a finding's rule status is `shadow`, the Policy Scoring Processor shall exclude that finding from the reported findings and from the project-score input while still recording its outcome for precision tracking.
6. The Policy Store shall expose, per CWE, an authoritative 0-5 severity plus a static scope flag and a dynamic scope flag, and shall mark dynamic-only CWEs as report-only and never scored by the static tool.
7. If an enabled rule's CWE does not resolve in the Policy Store at startup, then the Scan Runtime shall fail loud and shall not proceed with the scan.
8. The Ruleset Store shall remap the C/C++ buffer-handling rules that reference the unmapped CWE-120 to CWE-121 (severity 5) so that those rules contribute a nonzero penalty to the project score.
9. The Ruleset Store and the Policy Store shall be loaded with the standard library only and shall require no third-party dependency.

### Requirement 3: Bounded Rule and Policy Adaptation in the Self-Improvement Loop

**Objective:** As an OpenUltraSAST maintainer, I want the HarnessX meta-harness to adapt rules and policy gates only through two bounded levers, so that the loop can suppress, stage, or raise the bar on noisy rules without ever inventing detectors or rewriting the severity authority.

#### Acceptance Criteria
1. The Self-Improvement Loop shall expose exactly two new edit levers: a `rule` lever covering rule status, evidence floor, and threshold, and a `policy` lever covering evidence floor, scope, and the score constants `K` and `MIN_SCORE`.
2. The Rule Edit Validator shall reject any loop edit that modifies detection pattern text, so that pattern authoring remains human-pull-request only.
3. The Policy Edit Validator shall reject any loop edit that modifies the authoritative 0-5 CWE severity, so that the severity authority remains upstream-governed.
4. If the loop proposes moving a rule directly from `enabled` to `disabled`, then the Rule Edit Validator shall reject the edit and require `shadow` as a mandatory intermediate staging state.
5. When validating a proposed edit, the Rule Edit Validator shall assert that the edit parses, that `status` is one of `enabled`/`shadow`/`disabled`, that any threshold or evidence-floor tightening or loosening stays within configured bounds, that an added rule does not duplicate an existing rule identifier, and that every referenced CWE resolves in the Policy Store.
6. If the loop re-proposes an edit that was previously reverted without supplying a retry rationale, then the Self-Improvement Loop shall block the re-proposal via the novelty gate.
7. Before accepting any round, the Self-Improvement Loop shall run a replay smoke gate that proves the edited ruleset and policy still load and boot.
8. When any loop edit is rejected during validation, the Self-Improvement Loop shall raise a rule-change validation error and reject the entire round.
9. The Self-Improvement Loop shall record each rule and policy edit, its lever, and its outcome in the journal so that every change is attributable and reversible.

### Requirement 4: Benchmark-Driven Iteration with a Hard Acceptance Gate

**Objective:** As an OpenUltraSAST maintainer, I want benchmark results to become actionable per-rule signals that drive the self-improvement loop under a hard acceptance gate, so that detection quality improves automatically while regressions are reverted byte-for-byte.

#### Acceptance Criteria
1. The Benchmark Harness shall attribute every recorded miss and every recorded false positive to a `rule_id` and shall aggregate per-rule precision and recall in its metrics.
2. The Benchmark Harness shall emit a per-rule recommendation artifact alongside its records, recommending enable, disable, shadow, threshold, or evidence-floor changes per rule.
3. When the orchestrator converts benchmark output to loop input, it shall write recall-side items as miss signals and precision-side items as verifier-reject or false-positive signals into the loop's signal file.
4. After the meta-agent edits rules or policy, the Self-Improvement Loop shall re-run the benchmark and shall accept the round only if aggregate recall is at least 90% AND aggregate false-positive rate is under 10% AND the project score did not regress on the held set AND no unpredicted regression occurred.
5. If a re-run round fails any acceptance condition, then the Self-Improvement Loop shall revert the round and restore the rule and policy configuration byte-for-byte.
6. If a rule drags aggregate precision below the gate, then the Self-Improvement Loop shall auto-shadow that rule rather than delete it, so that recall is preserved while the false-positive cost is removed.
7. When a coverage gap surfaces as a persistent miss, the Self-Improvement Loop shall nominate a new or loosened rule through the signal file while leaving pattern authoring to a human pull request.
8. The Self-Improvement Loop shall treat maximizing the project score as the optimization objective and the recall/FP gate as a separate hard feasibility constraint, so that the loop cannot improve the score by shadowing rules in a way that harms real security.

### Requirement 5: Project Scores via verycode Policies

**Objective:** As a security reviewer, I want a single 0-100 project score computed from policy-weighted, reachability-adjusted findings and gated in CI, so that a scan produces a bounded AppSec quality signal alongside its findings.

#### Acceptance Criteria
1. The Score Model shall compute a single 0-100 project score from policy-governed severity weights multiplied by a reachability multiplier over the reported findings, using the standard library only.
2. The Score Model shall use reachability multipliers keyed exactly on the three emitted reachability values `reachable`, `inferred-file-surface`, and `unknown`.
3. When a finding maps to a CWE that is dynamic-only or unmapped in the Policy Store, the Score Model shall assign that finding a zero score penalty and shall report it as out-of-scope or unmapped rather than scoring it.
4. The Score Model shall exclude findings whose rule status is `shadow` from the score input before computing the project score.
5. The Score Model shall emit a scan-level score artifact containing the project score, the maximum severity, the total penalty, a by-category breakdown, the out-of-scope dynamic-only count, the unmapped CWE list, and the gate verdict, and shall include the score block in the scan manifest.
6. When confirming a false positive, the Calibration subsystem shall lower the finding's effective reachability multiplier rather than delete the rule, so that recall stays high while the score stops over-penalizing.
7. If any reported finding maps to policy severity 5 AND has `reachability_status` equal to `reachable`, then the CI Score Gate shall fail the build.
8. Where the score gate is configured as blocking, the CI Score Gate shall fail the build when the project score is below `MIN_SCORE`; until the score constants are calibrated against the corpus, the CI Score Gate shall compute and report the score advisory-first without blocking.
9. The Score Model and the CI Score Gate shall run in the zero-dependency default install with no HarnessX present.

### Requirement 6: Detection Gate Non-Regression

**Objective:** As an OpenUltraSAST maintainer, I want the existing detection gate of at least 90% recall and under 10% false positives on the benchmark corpus to hold across every phase and every change, so that no governance, scoring, runtime, or self-improvement change can silently degrade detection quality.

#### Acceptance Criteria
1. The CI Pipeline shall evaluate aggregate recall and aggregate false-positive rate on the benchmark corpus on every merge and shall fail the merge if recall is below 90% or the false-positive rate is at or above 10%.
2. While the default ruleset and an empty loop ledger are in effect, the Benchmark Harness shall produce results byte-identical to the pre-feature baseline for the governance and rules-as-data phases.
3. When the self-improvement loop proposes any rule or policy change, the Self-Improvement Loop shall require the recall/FP gate to pass on the re-benchmarked candidate before the change can be accepted.
4. If a HarnessX-backed stage is enabled, then the CI Pipeline shall confirm recall and false-positive rate stay within the configured tolerance of the equivalent zero-dependency baseline.
5. The CI Pipeline shall treat the recall/FP gate as a hard constraint that is never folded into the project-score reward, so that improving the score can never substitute for meeting the detection gate.
6. If any change would reduce recall below 90% or raise the false-positive rate to 10% or above, then the CI Pipeline shall block the change regardless of any project-score improvement.

### Requirement 7: HarnessX Dependency-Weight Decision

**Objective:** As an OpenUltraSAST maintainer, I want an explicit dependency-weight decision that keeps the core install zero-dependency and chooses between an optional HarnessX extra and a vendored lean subset based on an audited dependency graph, so that a supply-chain auditing tool never silently inherits an unacceptable transitive dependency footprint.

#### Acceptance Criteria
1. The Packaging Configuration shall keep the core `dependencies` list empty and shall expose HarnessX only as an optional extra pinned to a specific commit revision.
2. The Runtime shall guard every HarnessX import behind a capability check and shall import HarnessX lazily so that heavy code paths stay cold in the default install.
3. Before adopting the HarnessX execution stages, the maintainer shall run a dependency dry-run audit and shall record the realized transitive dependency graph.
4. If the audited transitive graph pulls a browser-binary, container-SDK, or web-server stack as a mandatory dependency and the maintainers judge it unacceptable for a supply-chain auditing tool, then the Packaging Configuration shall switch to a vendored lean subset of HarnessX under the same extra name with the heavy subtrees removed.
5. While HarnessX is absent, the CI Pipeline shall run a zero-dependency guard test confirming the governance, scoring, and benchmark planes operate with no HarnessX present.
6. Where the project is developed via a submodule, the Runtime setup shall initialize HarnessX non-recursively so that the large reinforcement-learning fork subtree is not pulled.
7. The Packaging Configuration shall keep the vendored lean subset pre-specified so that switching from the optional extra to the vendored subset is a packaging change and not a redesign.
