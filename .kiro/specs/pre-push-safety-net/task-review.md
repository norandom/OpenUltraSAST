# Task-plan review: pre-push-safety-net

Date: 2026-09-12. Scope: design readiness and implementation task graph, not runtime validation.

## Authorization and phase

After the amended requirements/design and JavaScript transfer plan were presented, the maintainer
said **"ok, next kiro phase"**. This was applied as approval of those concrete documents for task
generation. Requirements/design are approved; generated tasks remain unapproved and implementation
has not begun. The initial acceptance profile is an evaluation target, not a demonstrated SLA.

## Design readiness assessment

**GO for task generation.** The design retains the existing ranker as scope owner, excludes vendor
code from targets/graphs, preserves language-agnostic evidence contracts, and separates graph
claims from actionable change-related alerts. Boundaries, integration paths and all 35 numeric
requirements have concrete design counterparts. No fundamental design gap was found in this review.

Three material risks are explicit work and release gates, not assumed solved:

1. Whole/changed-unit graph cost may not meet the hook deadline: measure the uncached baseline
   before cache work, then realistic warm edits rather than identical-tip hits alone (5.2, 8.2).
2. Frontend/framework or sanitizer semantics may prevent an actionable claim: retain the gap,
   keep the affected capability experimental, and route new engine work to its owning spec (3.3, 8.3).
3. Repeatedly inspected examples do not prove transfer: freeze the core and retain untouched
   evidence per language/framework/family, with noise/recall/coverage gates together (1.2, 8.3).

## Independent task-graph sanity review

Reviewer received the draft task plan and paths to requirements, design, evaluation and task rules,
without a parent-generated coverage summary. The first verdict was **NEEDS_FIXES**:

- Cache reuse can complete more work within the same deadline. Task 6.4 must require evidence/
  admission equality for the same completed questions; complete-scope equality belongs to a controlled
  sufficient-budget comparison, not every deadline-limited run.
- Requirement 8.1 needs explicit paired normalized PHP/JavaScript contract tests, including equivalent
  capability eligibility and an unsupported-origin negative control (3.2, 4.2).
- A Node holdout cannot admit PHP or Python capabilities. Untouched evaluation is required for each
  language/framework/family; missing evidence leaves that capability experimental (1.2, 8.3).

All three were repaired once. The same independent reviewer read the repaired draft and returned
**PASS**, with no remaining important task-graph issue. No return to design was required.

## Mechanical and scope checks

- Eight major groups and 27 executable subtasks; one parallel candidate (3.1), otherwise sequential
  because the work shares backend, ranker, cache and integration contracts.
- All 35 requirement IDs mapped; every executable subtask has an observable completion condition,
  responsibility boundary, and valid explicit dependencies where needed.
- No task is checked off; no acceptance-critical tests are optional. No deployment is included.
- The initial experiment is 5.2; persistent caching follows it. Normal alert eligibility is gated
  at 8.3, so experimental diagnostics do not become noisy advisory output during development.
- Final file/metadata validation and `git diff --check` are the fresh document checks. No runtime
  code or tests changed, and no graph/performance measurements were rerun during task generation.

Next phase: human task approval, then implementation starting with group 1.
