# Group 4 implementation and verification

Date: 2026-09-13. The maintainer authorized group 4 as a whole. Scope is tasks
4.1–4.3: targeted novelty comparison, actionability admission and compact reporting.
Groups 1–3 are verified at `6ba2b06`; full transaction replay remains task 5.1.

Status: tasks 4.1–4.3 are VERIFIED (TASK scope), bringing the spec to 14/27 tasks.
Tasks 4.1 and 4.2 passed independent review. Task 4.3 used the Kiro manual review
fallback after the agent service rejected further dispatch. No production capability
is enabled for normal hook alerts; actual admission still requires task 8.3 evaluation.

## Verification boundary

Exercise production policy functions with immutable Git snapshots and actual engine
answers, plus deterministic error-path and equivalent-origin controls. Prove source
bytes were read before interpreting empty answers. Synthetic evaluated capabilities
exercise admission mechanics only and never establish real capability eligibility.
The established gates protect detector regressions; these controls do not establish
production hook latency, broad alert precision or feature-level readiness.

## Task 4.1 verification

VERIFIED (TASK scope), independent review APPROVED. Full suite: 1,167 passed,
nine skipped in 122.44 seconds; global Ruff/format (233 files), mypy (110 source
files), all three regression gates and diff checks passed. The first OFF control
failed on novelty behavior. Review regressions reproduced false NEW classifications
from wrong-mechanism base rows and non-string operations; both now stay unknown.

`benchmarks/measurements/2026-09-13-delta-comparison-smoke.json` records actual
JavaScript guard removal as worsened, unchanged backlog moved by comments as
unchanged, and a PHP source newly connected to a mapped unchanged sink as new.
All inputs were read and both sides' questions completed. Current reviewed policy
was independently rechecked against captured actual answers after the schema-only
repair; the artifact preserves exact source hashes and that narrower provenance.
Concurrent lab costs were 214.81, 214.52 and 291.01 seconds respectively under
900-second budgets. These are not hook latency measurements.

Automatic dominance-only change-context projection remains an explicit upstream
limitation for the later replay integration. These controls use declared questions
and Git context directly; no missing-coverage result was erased. Ambiguous source
and identifier changes remain unknown. Task 4.1 brings progress to 12/27 tasks;
admission and rendering remain pending within this authorized group.

## Task 4.2 verification

VERIFIED (TASK scope), independent review APPROVED. Full suite: 1,207 passed,
nine skipped in 99.04 seconds; global Ruff/format (235 files), mypy (110 source
files), detection/map/pair gates and diff checks passed. OFF admission controls
failed before implementation. Review reproduced a SQL witness acquiring shell advice
through a broad injection-family key; evaluated operation-symbol restrictions now
reject that mismatch, missing bindings, receiver changes and embedded-name matches.

Deltas bind exact base/head and semantics; unbound legacy records cannot be admitted.
Evaluation declarations retain calibration and untouched-population provenance and
must supply positive controls and reviewed alerts. Every disposition preserves its
evidence and matching declarations. Deduplication retains witnesses, locations,
refs and exact comparisons; unchanged debt on one comparison cannot erase a new
claim on another. Advisory and blocking share admission; coverage policy is separate.

`benchmarks/measurements/2026-09-13-admission-policy-smoke.json` records current
policy against captured actual engine answers: all remain diagnostic with the empty
default registry. Explicitly synthetic PHP/WordPress and JavaScript/Express controls
receive equivalent admission and enforcement behavior. They do not qualify any
real capability; task 8.3 still owns actual eligibility. Task 4.2 brings progress to
13/27 tasks. Compact reporting remains in this authorized group.

## Task 4.3 verification

The agent service rejected the task 4.3 dispatch with `agent thread limit reached`.
The [kiro-impl skill](../../../.opencode/skills/kiro-impl/SKILL.md) explicitly provides:
“If multi-agent is not available, fall back to manual mode execution for all tasks.”
Implementation, review and completion checks therefore ran in the main context.
This is a manual review record, not an independent-review claim.

OFF controls produced seven relevant failures; ON and unflagged reporting tests
passed. Manual review found and repaired an invalid artifact path escaping the
notice path and a complete comparison carrying failed base evidence. A writer
exiting zero without a receipt is rejected. Stalled-writer tests prove cancellation,
preservation of an existing artifact and no surviving child. Other controls cover
all candidate/scan preservation, five defects with only three displayed, separate
coverage/enforcement, escaping and bounded long text, and immutable provenance.

## Review Verdict
- VERDICT: APPROVED
- TASK: 4.3
- REVIEW_MODE: Kiro manual fallback; agent dispatch unavailable.
- MECHANICAL_RESULTS: final full suite 1,222 passed, nine skipped in 102.39 seconds;
  Ruff and format (238 files), mypy (111 source files), compileall, diff checks and
  detection/map/pair gates PASS. No new placeholders or hardcoded secrets.
- FINDINGS: Invalid destination and failed-base completeness issues repaired and
  verified with failing controls followed by passing tests. No outstanding task finding.
- BOUNDARY: Reporting consumes existing admission and engine records; no new
  detector, ranker, graph mutation, provider or installed hook.

The image build and CLI boot passed. The packaged integration control rechecked
captured actual PHP/JavaScript answers through current comparison/admission/reporting,
preserving complete scan payloads and default diagnostic-only output. Five explicitly
synthetic admitted defects retain all five records, display three summaries and keep
the block decision. Artifact write failure also retains that decision. Packaged
policy/reporter hashes match the workspace. See
`benchmarks/measurements/2026-09-13-compact-report-smoke.json`.

Publication is atomic from mode-0600 temporary files. A separate Linux process
bounds serialization and filesystem work by the remaining transaction/report
allowance. Hard cancellation can leave a private unpublished partial file; it is
never presented as the completed artifact. Caller-supplied stage timings are
preserved, and the delivery receipt measures publication/rendering separately.
Observed packaged delivery costs (about 0.02–0.04 seconds for these controls) do not
establish whole-hook latency.

## Group integration validation

- DECISION: GO
- VALIDATION_SCOPE: Tasks 4.1–4.3 only; no full-feature or release admission.
- CROSS_TASK_CONTRACTS: Actual captured engine evidence → bound delta → empty-registry
  diagnostics → compact report and complete artifact PASS. Explicitly synthetic
  calibrated controls → admission → advisory/blocking → capped rendering PASS.
- REQUIREMENTS: Group-owned portions of 2.4, 3.1–3.5, 4.1, 5.1–5.5, 7.3 and 8.1 are
  covered by the implementation and controls above. Full transaction wiring and
  representative capability/latency evaluation remain later tasks.
- DESIGN_ALIGNMENT: Existing arbiters and ranker retained; policy and report live
  in their planned push-adapter boundary. No orphaned module or upstream detector change.
- BLOCKED_TASKS: None in group 4. Automatic dominance change-context projection is
  a documented upstream integration limit, not erased by these declared controls.
- NEXT: Group 5 full replay and first bounded experiment. Complete that experiment
  before persistent graph reuse in group 6. Groups 5–8 remain pending.
