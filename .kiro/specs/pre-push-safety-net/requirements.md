# Requirements: pre-push-safety-net

Status: approved for task generation on 2026-09-12 following the maintainer's "ok, next kiro phase". The acceptance profile defines evaluation targets, not measured achievements.

## Introduction and Boundary

OpenUltraSAST helps developers catch concrete security regressions in the resulting commits they
push. Advisory findings must be actionable; nonblocking speculation is still noise. The hook owns
the push transaction and its report, using the existing analysis engine. It does not certify the
repository, scan every intermediate commit, add new detector semantics, or automatically fix code.

## Requirement 1: Analyze the code being pushed

1.1 When a push contains ref updates, the Safety Net shall analyze each distinct resulting commit
snapshot and retain its association with every supplied ref update.

1.2 While analysis runs, the Safety Net shall leave the working tree, index, refs, and existing hook
behavior unchanged and shall exclude uncommitted content from the analyzed snapshot.

1.3 If an update deletes a ref, targets an unsupported object, or lacks a usable comparison base,
the Safety Net shall record that disposition without presenting an empty comparison as a successful check.

1.4 When a new branch, merge, force-push, rename, or deletion changes the comparison, the Safety Net
shall record the exact compared revisions and the rule used to choose them.

## Requirement 2: Analyze affected security behavior

2.1 When code changes, the Safety Net shall supply changed sites and affected first-party caller,
callee, data, guard, dispatch, and configuration context to the ranker, which shall remain the
mechanism selecting the regions and questions to analyze.

2.2 If a dependency cannot be resolved or included within the budget, the Safety Net shall identify
the affected checks as incomplete rather than treating omitted context as safe.

2.3 When constructing analysis targets or graphs, the Safety Net shall exclude third-party vendor
code and record those boundaries, along with any test, generated-file, submodule, or language exclusions
and their effect on supported coverage; missing vendor semantics shall require an explicit summary
or an unresolved result rather than reintroducing vendor code.

2.4 When a guard or sanitizer is removed, the Safety Net shall evaluate affected unchanged operations
where supported rather than requiring the vulnerable operation itself to occur on an added line.

## Requirement 3: Produce actionable security alerts

3.1 When the Safety Net emits a normal hook alert, it shall include a supported security consequence,
an exact location, a witness connecting the relevant input or obligation to the operation, a supported
relationship to the proposed change, and a concrete repair direction.

3.2 If a candidate is only suspicion, unsupported intent inference, a style concern, or an
uncalibrated capability result, the Safety Net shall omit it from normal hook alerts and retain its
disposition in an opt-in diagnostic artifact.

3.3 When multiple regions identify the same defect, the Safety Net shall emit one defect summary
with its relevant locations rather than repeated warnings.

3.4 If an existing defect is unchanged by the push, the Safety Net shall omit it from normal hook
alerts; if evidence cannot establish whether a defect is new or worsened, it shall report that
comparison gap as coverage information without claiming a new vulnerability.

3.5 Where a model assists ranking or explanation, the Safety Net shall require the same alert
admission evidence as in a run without that model.

## Requirement 4: Bound cost and reuse valid work

4.1 When a check begins, the Safety Net shall apply one configurable elapsed-time budget across
all ref updates and stages, including preparation, retries, analysis, optional services, and reporting.

4.2 If the deadline expires, the Safety Net shall cancel outstanding work, persist completed
evidence and incomplete coverage, and return within a separately measured cancellation allowance.

4.3 When reusing an analysis result, the Safety Net shall verify that its input, relevant context,
engine, facts, query semantics, scope, and policy remain compatible with the requested check.

4.4 If a cached artifact is partial, corrupt, incompatible, or unavailable, the Safety Net shall
recompute within the remaining budget or return incomplete coverage without reusing a clean verdict.

## Requirement 5: Keep the push experience proportionate

5.1 When no actionable defect is found in the completed supported checks, the Safety Net shall
emit at most one compact status line that describes the checked scope without calling the repository secure.

5.2 If analysis is incomplete or unavailable, the Safety Net shall emit a separate compact operational
notice with one concrete next action and a detailed artifact reference, without a per-file warning flood.

5.3 Where advisory mode is selected, the Safety Net shall allow the push while applying the full
actionability requirements to every displayed finding.

5.4 Where blocking mode is explicitly enabled, the Safety Net shall block for admitted new or
worsened defects; an incomplete scan shall follow a separately declared coverage policy.

5.5 When producing a result, the Safety Net shall preserve separate finding, coverage, and push
disposition fields so allowing a push cannot be interpreted as complete analysis.

## Requirement 6: Earn admission through evaluation

6.1 When evaluating admission of a detector capability to the hook, the project shall evaluate its language,
framework, and family on labeled vulnerable/fixed changes and benign pushes, including a repository
not used to develop or tune that capability.

6.2 When reporting hook quality, the project shall report actionable-alert precision, recall on
supported labeled changes, fixed-side silence, benign-push interruption rate, coverage completion,
and cold/warm latency with sample counts, uncertainty, and all unresolved cases.

6.3 If a target cannot be located, a query is unanswered, or a transitive path is unproven, the
evaluation shall retain that case in the declared population and identify the unresolved result.

6.4 When comparing rankers, the evaluation shall hold scope, engine, facts, workload, and budget
constant, record the actual deployed ranking mode, and evaluate completed detections as well as rank.

6.5 When evaluating release readiness of the hook, the project shall require passing predeclared precision, recall,
coverage, and latency gates together; a policy that achieves silence by examining or alerting on nothing
shall fail that evaluation.

## Requirement 7: Preserve local control and reproducibility

7.1 When running the default hook, the Safety Net shall use locally available analysis without
requiring a model endpoint, downloading an engine, fetching source, or running project build scripts.

7.2 Where an external model is explicitly configured, the Safety Net shall apply the existing
redaction policy, record model/prompt provenance, and include its cost and latency in the budget.

7.3 When saving an artifact, the Safety Net shall record input identities, scope and exclusions,
engine/fact/query/policy versions, exact selected and deferred questions, outcomes, and timings.

7.4 When installing or removing the hook explicitly, the Safety Net shall preserve existing hooks
and document the integration and removal steps.

## Requirement 8: Transfer the core analysis across languages

8.1 When equivalent source, sink, guard, obligation and carried-value evidence is supplied from
different languages or frameworks, the Safety Net shall apply the same core scope, ranking and
admission rules without repository-specific or language-specific priority exceptions.

8.2 When a frontend or framework cannot supply evidence needed for a supported check, the Safety Net
shall identify that capability gap rather than interpreting missing evidence as a safe program.

8.3 When evaluating a core optimization developed on PMPro, the project shall freeze the core
ranking features, weights and decision rules and evaluate transfer on a JavaScript Node API workload
with Express-style routes and middleware, including vulnerable, fixed and benign changes.

8.4 When publishing cross-language results, the project shall distinguish unchanged-core transfer,
frontend/framework adaptations and new abstract capabilities, and shall report C/C++ envelope or
unsupported-property results separately from demonstrated vulnerability detection.

## Accepted experimental acceptance profile

These values are the initial implementation/evaluation profile accepted for task generation, not
measured achievements or a demonstrated SLA. Freeze them before evaluating a candidate; report
failures without lowering the bar after inspecting holdout results.

- Advisory first; blocking opt-in; incomplete coverage allows the push with one notice by default.
- Warm latency p95 <= 30 seconds, cancellation/report allowance <= 2 seconds; cold latency reported separately.
- >= 95% completed supported checks on the declared representative push workload.
- >= 95% observed actionable-alert precision with counts and confidence interval; zero known false
  alerts on the fixed/benign regression suite. Small samples do not establish broad precision.
- >= 90% recall on the predeclared supported security-change suite; unsupported classes remain in
  coverage reporting, not reclassified after a miss. Publish per-capability results, not only an aggregate.
- No capability is admitted with zero positive controls, zero reviewed emitted alerts, or no untouched
  evaluation repository. Failed profiles remain experimental and silent in the normal hook.
