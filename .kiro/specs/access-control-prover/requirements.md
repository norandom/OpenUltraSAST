# Requirements Document

## Project Description (Input)
An access-control prover: a deterministic check that a protected operation is reachable from an attacker-facing
entry point without a required authorization check governing that path. The prover consumes acquired entry,
operation and enforcement facts, resolves calls and resources conservatively, emits an ordered trace for every
examined pair, and is measured separately on development and admission populations.

## Introduction
The security object for access control is not the shape of a changed function. It is an ordered path from an
attacker-facing entry to a protected operation, together with the authorization evidence that governs every
relevant control-flow and call-flow step. The 2026-10-28 development measurement established a useful baseline:
15 of 23 fix changes detected, 15.0 flagged ordinary pushes per 100, and no instrument failures. The subsequent
ablation showed that unresolved calls, over-broad resource matching, missing registration facts and silent
fallbacks account for both missed detections and false alarms.

This amendment makes uncertainty part of the result rather than a side counter. A pair is `unguarded`,
`discharged`, or `indeterminate`; degraded resolution, missing control-flow semantics, incomplete facts and
budget cutoffs cannot create a final security verdict. It also separates label-blind fact acquisition and
development regression from admission measurement on untouched repositories.

Concrete frameworks and repositories are benchmark evidence, not acceptance-criteria inventories. Target
vocabulary is acquired as reviewed data or recogniser strategies and is verified before promotion. The abstract
interpretation engine remains target-agnostic.

## Boundary Context
- **In scope**: acquired entry, operation and enforcement knowledge; exact and conservative call resolution;
  resource- and authority-sensitive witness matching; bounded interprocedural summaries and concrete evidence
  paths; control-flow-sensitive dominance; three-way pair judgments; failure-visible coverage; development and
  admission runners.
- **Out of scope**: taint flow; the Joern engine; model calls inside the prover; vulnerability families other than
  access control; client-side presentation gating; pre-push hook wiring; proof execution; hand-tuning vocabulary
  from evaluation labels.
- **Adjacent expectations**: `authorization-obligations` supplies the existing checker and fact contracts;
  `valid-detection-benchmark` supplies reviewed populations; `search-with-proof` consumes unguarded traces;
  `pre-push-safety-net` may consume the arm only after admission passes.

## Requirements

### Requirement 1: Acquired attacker-facing entry points
**Objective:** As a maintainer, I want entry recognition to consume verified target knowledge, so that new targets
can be covered without adding target vocabulary to the analysis engine.

#### Acceptance Criteria
1. When verified target knowledge describes a declarative entry shape, the mapper shall record every matching
   repository-defined handler as an entry with its source range, trust boundary and recognition evidence.
2. When verified target knowledge describes a call-site registration, the mapper shall resolve the registered
   repository-defined handler and record its request methods as entries with the registration site and resolved
   handler identity as evidence.
3. If a registration target cannot be resolved to repository-defined code, the mapper shall emit no entry for it
   and shall record `registration_unresolved` coverage.
4. When acquired knowledge proves that an entry is intentionally public, the mapper shall record access `public`;
   otherwise, the mapper shall record access `unknown` rather than infer public access.
5. The mapper shall preserve the promoted fact or strategy identifier and the concrete source evidence on every
   entry record.
6. If no promoted entry knowledge covers a file, the prover shall record `framework_unrecognised` and shall not
   interpret the absence of entries as a clean result.
7. When target entry knowledge is added or updated, the system shall apply it through data or a registered
   recognition strategy without changing target-agnostic analysis modules.

### Requirement 2: Acquired protected operations and enforcement evidence
**Objective:** As a maintainer, I want operations and authorization evidence represented as verified knowledge,
so that the prover compares the correct action, resource and authority.

#### Acceptance Criteria
1. When promoted operation knowledge matches a call or recognised handler, the prover shall record the protected
   operation, its required authorization kinds, its resource identity and any required authority.
2. When promoted enforcement knowledge matches a statement, decorator, route, policy decision or equivalent
   construct, the prover shall record a witness with its scope, resource identity, authority and provenance.
3. When a handler name itself denotes a protected action, the prover shall apply that operation only to an entry
   recognised for the same promoted target knowledge.
4. When a route or declared policy marks an entry public, the prover shall waive only a request-level path guard
   and shall preserve resource, ownership and authority obligations.
5. When a witness binds a different resource or an insufficient authority, the prover shall not use that witness
   to discharge the operation.
6. When a witness is request-global, the prover shall use it without resource equality only when the operation
   fact explicitly declares that witness kind sufficient at request scope.
7. If resource identity or authority compatibility cannot be decided, the prover shall treat the witness match as
   unknown rather than matching it broadly or rejecting it as definitely unrelated.
8. When one authority implies another, the prover shall apply that implication only from promoted target
   knowledge and shall record the implication used in the trace.
9. When target knowledge is extracted or proposed, the acquisition workflow shall verify its source, version,
   region and match evidence before promoting it to closed data or an enabled strategy.
10. If proposed target knowledge contradicts the inspected source or lacks verification evidence, the acquisition
    workflow shall reject it with a reason and shall not modify promoted knowledge.

### Requirement 3: Conservative interprocedural reachability
**Objective:** As a maintainer, I want calls resolved to stable program identities and paths carried through
helpers, so that unrelated same-name code neither creates nor suppresses findings.

#### Acceptance Criteria
1. When a touched function or reachable helper contains a protected operation, the prover shall construct caller
   chains from recognised entries to that operation within the configured work budget.
2. When a call target can be identified by module, enclosing type, method and signature, the prover shall keep
   that identity distinct from every other same-name target.
3. When more than one call target remains feasible, the prover shall preserve the finite candidate set and shall
   mark the call incomplete rather than merge the candidates under a bare name.
4. If no bounded candidate set can be established, the prover shall mark the call unresolved and shall not use it
   to create a final discharged or unguarded judgment.
5. When an operation or entry is declared on a base type, the prover shall attach it only to repository-defined
   concrete descendants whose resolved identities support that attachment.
6. When a helper calls another helper that contains an operation or governing authorization evidence, the prover
   shall continue the analysis through that call while budget remains.
7. When recursion is present, the prover shall terminate and shall preserve the accumulated operations,
   authorization effects and incompleteness reasons for the recursive component.
8. If depth, fan-out, time or another work bound truncates exploration, the prover shall record the exact cutoff
   reason and shall treat affected pairs as incomplete.
9. When a complete chain is materialised, the prover shall emit its hops from entry to operation with the call
   site of every transition.
10. When multiple complete chains reach the same operation, the prover shall evaluate each chain independently so
    that a guarded chain cannot hide an unguarded chain.

### Requirement 4: Access-control verdicts
**Objective:** As a developer about to push, I want a finding only for a demonstrated unguarded path, so that every
alarm names a concrete security obligation and repair location.

#### Acceptance Criteria
1. When a complete path reaches a protected operation, at least one required authorization kind is proven absent,
   and every other required kind is proven either governing or absent, the prover shall judge the pair
   `unguarded` and shall report each absent kind.
2. When every required authorization kind is proven to govern the operation on a complete path, the prover shall
   judge the pair `discharged`.
3. If the evidence is insufficient for either final judgment, the prover shall judge the pair `indeterminate`.
4. When a pair is `unguarded`, the prover shall emit one finding per operation and missing authorization kind with
   family `access_control`, exact source anchor, entry, hops and evidence.
5. When a pair is `discharged` or `indeterminate`, the prover shall emit no vulnerability finding for that pair.
6. The prover shall apply the recognised-entry-is-protected premise only in its explicit opt-in mode and shall
   identify that premise in the evidence.
7. The prover shall make no model call and shall return findings in the existing hunt-defect contract.

### Requirement 5: Development measurement
**Objective:** As a maintainer, I want repeatable development measurements, so that changes to facts and analysis
can be attributed without being mistaken for admission evidence.

#### Acceptance Criteria
1. When a development population is run, the runner shall write one resumable record per change with analyzer,
   fact-set, population and input digests.
2. When development records are summarised, the runner shall report recall on fix changes and verified locations,
   flagged ordinary pushes per 100, precision, vulnerable/fixed pair correctness, instrument failures and runtime
   distributions with uncertainty intervals where defined.
3. The runner shall report a stage funnel from entry recognition through call resolution, operation discovery,
   control-flow evaluation, witness matching and pair judgment.
4. The runner shall report per-target-family and per-repository coverage without disclosing reserved repository
   identities in shared records.
5. When comparing an amended analyzer and amended facts, the runner shall support the four registered arms formed
   by old/new analyzer crossed with old/new fact set.
6. If any record reads zero bytes for a file present in the analysed tree or anchors a finding outside files read,
   the runner shall mark an instrument failure and shall refuse the summary.
7. The runner shall label results from populations used to choose facts or analyzer behavior as development or
   regression evidence and shall not present them as admission evidence.

### Requirement 6: Pre-push budget
**Objective:** As a developer, I want the prover to finish inside the pre-push window, so that eligible detection
can run on every push.

#### Acceptance Criteria
1. When a measured change exceeds 120 seconds, the runner shall fail the budget gate and shall identify the
   change, stage and elapsed time.
2. The prover shall reuse per-change file, text, syntax, call, entry, symbol and summary caches and shall not read
   the product tree more than once per change.
3. If analysis stops because of a deadline, the prover shall return incomplete coverage and indeterminate affected
   pairs rather than a partial clean verdict.

### Requirement 7: Failure-visible coverage
**Objective:** As a developer, I want the tool to state what it could not decide, so that silence never reads as a
clean bill of health.

#### Acceptance Criteria
1. The prover shall report files by language, recognised entry families, entries, reached and unreached targets,
   operations, discharged pairs, unguarded pairs and indeterminate pairs.
2. The prover shall count unchecked or incomplete work by specific reason, including parse failure, unsupported
   language, unrecognised target, absent facts, unresolved registration, ambiguous or unresolved call, exploration
   cutoff, unavailable control flow, unknown resource, unknown authority and analysis exception.
3. If no target family is recognised for a repository, the runner shall mark the repository `uncovered` and shall
   report its recall separately from covered recall.
4. When a recognition, resolution, summary or judgment pass raises an exception, the prover shall record the
   exception class at that stage and shall not fold it into a quiet coverage reason.
5. When the same pair has multiple incompleteness reasons, the prover shall preserve every reason in the trace and
   aggregate each reason in coverage.
6. The runner shall report the indeterminate rate separately and shall not include indeterminate pairs in either
   clean or discharged counts.

### Requirement 8: Proof-arm feed
**Objective:** As the proof arm, I want each unguarded finding to carry a complete analysis witness, so that a
demonstration can be attempted without re-deriving the decision.

#### Acceptance Criteria
1. When a finding is emitted, it shall carry the entry record, exact hop list, operation, missing authorization
   kind, resource and authority relations, pair judgment, trace identifier and completeness evidence.
2. The finding identifier shall remain stable for the same operation, source anchor and missing authorization
   kind across deterministic replays.
3. If the pair is indeterminate, the prover shall expose its trace only as diagnostic coverage and shall not send
   it to the proof arm as a vulnerability finding.

### Requirement 9: Ordered traces for every examined pair
**Objective:** As a maintainer, I want every examined pair represented by the same deterministic trace, so that
decisions and degradations can be inspected and compared.

#### Acceptance Criteria
1. When the prover examines an entry-operation path, it shall emit one trace containing the entry, ordered hops,
   operation, authorization witnesses, resource and authority relations, control-flow relations, completeness
   state and pair judgment.
2. The prover shall emit traces for unguarded, discharged and indeterminate pairs alike.
3. When an argument or resource is forwarded through a call, the trace shall preserve its origin through the
   resolved hop; if origin cannot be followed, the trace shall record `unknown`.
4. The trace shall carry target knowledge identifiers and source evidence needed to reproduce the judgment but
   shall omit repository identity, file-size and repository-size features from decision input.
5. The trace shall serialise to one deterministic canonical text form and one deterministic canonical JSON form.
6. When a work bound or fallback would have been required, the trace shall record the cutoff or unavailable
   semantic fact rather than silently substituting a weaker analysis.
7. The runner shall persist traces and their analyzer, fact-set and input digests with the corresponding record.

### Requirement 10: Control-flow-sensitive dominance
**Objective:** As a maintainer, I want authorization evidence to count only when control flow guarantees it governs
the operation, so that avoidable or ignored checks do not discharge obligations.

#### Acceptance Criteria
1. When authorization evidence appears before an operation, the prover shall determine whether every feasible
   path to the operation passes that evidence.
2. When a guard's failing branch terminates or the operation exists only in the passing branch, the prover shall
   record the guard effect and may treat it as governing the operation when resource and authority also match.
3. When a predicate result is ignored or appears only on some paths, the prover shall not treat it as a governing
   authorization check.
4. When an operation is inside a loop, exception region or conditional branch, the trace shall record that control
   context and any exception handling that can bypass the guard.
5. When route- or declaration-scoped authorization evidence covers the whole handler, the prover shall preserve
   that declared scope without inventing a statement location.
6. If control-flow semantics or source-to-control-flow correspondence is unavailable, the prover shall mark the
   affected relation unknown and the pair indeterminate rather than decide it by textual order.
7. The existing order-based checker mode shall remain available to callers that do not opt into prover semantics.

### Requirement 11: Three-way abstract judgment
**Objective:** As a maintainer, I want uncertainty to propagate monotonically through the analysis, so that losing
precision cannot manufacture a vulnerability or a discharge.

#### Acceptance Criteria
1. The prover shall represent call resolution, path completeness, resource compatibility, authority compatibility
   and dominance with values that distinguish definite, possible, absent and unknown evidence.
2. When all required evidence on a complete path is definite and at least one required obligation has no governing
   witness, the prover shall produce `unguarded` and shall report every such obligation, including when other
   required obligations are definitely governed.
3. When every required obligation has a definite governing witness on a complete path, the prover shall produce
   `discharged` for that path.
4. If any required relation is possible or unknown, or path enumeration is incomplete, the prover shall produce
   `indeterminate` unless another complete path already proves `unguarded`.
5. When multiple paths reach one operation, the prover shall aggregate them as `unguarded` if any complete path
   is unguarded, `discharged` only if enumeration is complete and every path is discharged, and `indeterminate`
   otherwise.
6. When analysis precision is reduced by adding an unresolved candidate or removing semantic information, a final
   judgment shall remain unchanged or move to `indeterminate`; it shall not switch directly between `unguarded`
   and `discharged`.
7. The prover shall keep abstract-domain operations deterministic and independent of target names.
8. The runner shall expose judgment counts and transitions between compared arms so that precision loss cannot be
   hidden inside aggregate recall or false-alarm metrics.

### Requirement 12: Label-isolated admission workflow
**Objective:** As a maintainer, I want admission measured on untouched, reviewed evidence after the analyzer and
facts are frozen, so that a better development score is not mistaken for generalisation.

#### Acceptance Criteria
1. When an admission run is prepared, the workflow shall freeze the analyzer revision, promoted fact-set digest,
   acquisition record, configuration and population manifest before opening admission labels.
2. While acquiring target knowledge for an admission repository, the workflow shall use repository source and
   approved documentation without vulnerability, fix-location or ordinary-change labels.
3. If acquisition observes evaluation labels or is changed in response to an admission result, the workflow shall
   mark that population spent and shall not use it for admission.
4. When ordinary changes are prepared for a false-alarm denominator, the benchmark workflow shall review and
   remove or relabel changes that contain real missing-authorization defects before scoring.
5. When a vulnerable case has a fixed twin, the admission run shall require the expected unguarded trace on the
   vulnerable side and quiet or discharged behavior at the corresponding fixed operation.
6. When an amended prover is considered for the G1 arm, the workflow shall measure it on untouched repositories
   that were not used to choose facts, recognition strategies, abstract-domain behavior or thresholds.
7. The admission report shall include recall, verified-location recall, flagged ordinary pushes per 100,
   precision, paired vulnerable/fixed correctness, indeterminate rate, coverage, runtime and instrument failures
   with sample counts and uncertainty intervals.
8. If the budget gate, instrument gate or pre-registered quality criteria fail, the workflow shall return NO-GO
   and shall not enable the arm in pre-push admission.
9. The workflow shall retain the current 23-repository population as development regression evidence and shall
   require a separate untouched population for admission claims.
