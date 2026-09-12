# Implementation Plan: pre-push-safety-net

Status: task plan approved by the maintainer's "approve." on 2026-09-12. Implementation has
started with group 1 (tasks 1.1–1.4); each task remains pending until independent review and fresh verification pass.

## Execution contract

- Preserve the ranker as the scope mechanism and vendor exclusion from targets AND graphs.
- Use PMPro for core development and a JavaScript/Express workload for transfer. Keep the core
  frozen for the first Node measurement; separate adapter repairs from core changes.
- Each executable subtask is a bounded work unit targeting 1–3 hours of engineering, excluding
  unattended measurement time. If a new abstract capability is needed, record the gap and return
  it to the owning engine/ranking spec; do not hide that implementation in an integration task.
- Cross-spec engine changes below are explicit integrations of the accepted push contracts.
  They do not approve unrelated contributor/ranker backlog or automatically complete its tasks.
- Development runs retain experimental candidate/admission diagnostics without enabling normal
  hook alerts. A capability becomes eligible for normal alerts only after task 8.3 passes its gates.
- The first end-to-end milestone is 5.2, before persistent caching and hook installation polish.
  Negative performance evidence there informs caching; a broken instrument or absent supported
  positive control requires predecessor remediation before claiming that milestone successful.
- Sequential order is the default. Only 3.1 may run alongside group 2 after its explicit prerequisite;
  shared backend/driver, cache and report edits otherwise remain serial. No optional acceptance tests.

- [ ] 1. Establish the runtime, evaluation inputs and shared contracts
- [x] 1.1 Reproduce the evaluated engine environment
  - Align the shipped image, Compose and host-install defaults with Joern 4.0.625; preserve version override and checksum verification.
  - Exercise PHP with the native interpreter and the installed JavaScript frontend; open a source and the frontend parser where applicable, recording byte counts and graph census.
  - Done when a local image smoke produces valid small PHP and JavaScript graph/query payloads with recorded versions, and an unreadable source fails explicitly. This builds locally; it does not deploy.
  - _Boundary: Cache and Engine Boundary, packaging integration_
  - _Requirements: 7.1, 7.3, 8.2_
  - _Verified 2026-09-12:_ independent review APPROVED; 888 tests passed, 9 skipped. Actual local image PHP/JavaScript graph census and source witnesses passed, unreadable PHP explicitly refused. Parent verified current provenance hashes, image identity, non-root user and CLI/frontend liveness. Evidence: `benchmarks/measurements/2026-09-12-engine-runtime-smoke.json`. Runtime readiness only; no hook latency/detection claim. Existing mypy errors in `model/scan.py` at 299/302/310 remain unchanged.
- [ ] 1.2 Prepare labeled development and reserved evaluation changes
  - Pin a readable PMPro change/fix and a supported Node/Express change/fix, plus benign controls; verify license and source bytes before accepting recipes.
  - Use NodeGoat only if its selected mechanism fits a current arbiter; label authored repairs as authored. Reserve an independently selected Node API repository with modern module/async context and reviewable history before tuning on transfer results.
  - Keep Python regression and libpng envelope recipes, explicit supported/unsupported populations, ref identities and development/holdout roles in machine-readable evaluation inputs.
  - Reserve untouched evaluation for each language/framework/family intended for admission; the Node holdout cannot qualify PHP or Python. Missing per-capability evaluation leaves it experimental and does not delay the initial PMPro/Node diagnostic experiment.
  - Done when recipe validation resolves immutable inputs and labels or names an explicit missing prerequisite; no favorable scanner result is required to select a recipe.
  - _Boundary: Evaluation harness_
  - _Requirements: 6.1, 6.3, 8.3, 8.4_
- [ ] 1.3 Make the baseline and push scorer fail honestly
  - Retain unmatched targets and unanswered queries in the declared population; require a queried witness before labeling a target transitively detected.
  - Emit actual vulnerable/fixed outcomes beside rank, selected mode, engine/facts/scope and elapsed stage costs. Freeze a versioned workload/profile before measuring.
  - Done when a deliberately missing target and failed query cannot improve reported recall, while a verified transitive positive is counted with its witness.
  - _Boundary: Evaluation harness, repository benchmark integration_
  - _Requirements: 6.2, 6.3, 6.4, 6.5, 7.3_
- [ ] 1.4 Establish typed push and engine integration contracts
  - Add importable push components and validated configuration for comparison base, shared deadline/cancellation allowance, local cache limit, advisory/blocking and separate coverage policy.
  - Define ownership of update/comparison, change context, selected/deferred scope, graph identity/lease and separate finding/coverage/push statuses as described in design.
  - Keep generic engine contracts outside the push package; leave ordinary scan defaults compatible and capabilities experimental until evaluated.
  - Done when contract/config round trips preserve all identities/statuses, invalid values are rejected, and the engine has no dependency on the push package.
  - _Boundary: Push runner, Cache and Engine Boundary, CLI/config integration_
  - _Requirements: 4.1, 4.3, 5.3, 5.4, 5.5, 7.1, 7.3_

- [ ] 2. Resolve immutable pushed content
- [ ] 2.1 Resolve every supplied ref update and comparison
  - Parse Git's complete update input using object-format-aware validation; resolve existing tips, new-branch configured bases, force-pushes, merges, peeled tags, deleted refs and unsupported objects.
  - Deduplicate equal targets without merging different base comparisons; retain every ref association. Do not silently substitute HEAD or fetch missing objects.
  - Done when multi-ref and missing-base fixtures produce exact comparison identities and explicit dispositions, including deletion-only no-analysis results.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.1, 1.3, 1.4, 7.1_
- [ ] 2.2 Materialize isolated object snapshots
  - Read immutable tracked blobs into bounded scratch storage using machine-readable paths; do not checkout into the live tree or run filters, project scripts or network requests.
  - Preserve path identity and report symlinks, gitlinks, unavailable LFS blobs and unsupported content; never follow source outside the snapshot.
  - Done when non-HEAD pushes from a dirty checkout read only the intended object bytes and leave index, files and refs byte-identical after success, cancellation and failure.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.1, 1.2, 1.3, 2.3, 7.1, 7.3_
- [ ] 2.3 Attach changed spans and deletion/rename context
  - Compare recorded base/head objects using NUL-safe path handling; retain removed spans, renamed identities and declaration/config changes.
  - Supply change context to the shared ranker contract rather than selecting an independent changed-files-only scope.
  - Done when renamed functions retain correspondence and a removed guard remains an impact seed for an unchanged operation, with missing correspondence explicitly unresolved.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.4, 2.1, 2.4, 3.4_

- [ ] 3. Integrate bounded execution and ranker scope with the existing engine
- [ ] 3.1 (P) Enforce one remaining-time budget in the backend
  - Thread the absolute deadline through readability probes, frontend builds, overlays, census, query batches, fallbacks and retries; no phase gets a fresh full budget.
  - Bound process-group termination and lease/scratch cleanup by the cancellation allowance, replacing any longer fixed cleanup waits on the push path.
  - Done when controlled hanging subprocesses at build/overlay/query stages terminate without orphan children inside the declared allowance, while ordinary scans preserve their prior behavior.
  - _Boundary: Cache and Engine Boundary, generic driver integration_
  - _Depends: 1.4_
  - _Requirements: 4.1, 4.2, 7.3_
- [ ] 3.2 Return the ranker's exact selected and deferred work
  - Integrate the existing ranker through explicit mode selection and shared question identity; record selected/deferred IDs, evidence and reasons directly from the final order.
  - Preserve unanswered evidence as unknown rather than tier zero; report per-family coverage so taint ranking cannot masquerade as authorization/configuration coverage.
  - Add paired PHP/JavaScript normalized-evidence contract tests asserting identical tier/score and selection decisions for equivalent input and budgets, without repository/language priority exceptions.
  - Done when changing order produces matching execution and manifest IDs, with no reconstruction from an earlier list, and normalized cross-language equivalence tests pass.
  - _Boundary: Ranker Scope Contract, generic driver integration_
  - _Requirements: 2.1, 2.2, 6.4, 7.3, 8.1, 8.2_
- [ ] 3.3 Connect change context to supported first-party relationships
  - Use existing entry/callee, field, hook and guard relationships to supply affected context to ranked questions, including unchanged sinks after source/guard changes.
  - Preserve current abstract semantics; absent dynamic or external relationships remain unresolved rather than guessed safe. A required new feature or fact is reported to its owning spec.
  - Done when controlled cross-file and removed-guard cases reach the relevant question/witness, while an unresolved boundary cannot produce a complete negative.
  - _Boundary: Ranker Scope Contract, Snapshot Adapter integration_
  - _Depends: 2.3, 3.2_
  - _Requirements: 2.1, 2.2, 2.4, 8.1, 8.2_
- [ ] 3.4 Apply vendor exclusion and explicit language partitions
  - Reuse declared layout exclusions before target enumeration and graph build; retain unshipped first-party tests and separate browser/server or language capability coverage.
  - Build supported frontend partitions explicitly; preserve unknown cross-language and vendor semantics without restoring excluded sources.
  - Done when PHP and Node graphs/targets contain no declared vendor code, first-party callers remain visible, and unsupported partitions appear as coverage limits rather than clean results.
  - _Boundary: Ranker Scope Contract, Cache and Engine Boundary integration_
  - _Requirements: 2.2, 2.3, 7.3, 8.2, 8.4_

- [ ] 4. Implement change attribution and actionable output
- [ ] 4.1 Compare targeted base/head evidence for defect novelty
  - Establish stable mechanism/operation identity with rename/span mapping and collect comparable base evidence under the same semantics and remaining deadline.
  - Distinguish new, worsened, unchanged and unknown; an absent finding from a failed/truncated base is unknown. Support removed guards and new source connections at unchanged sinks.
  - Done when benign movement and unchanged backlog do not become new defects, while a supported removed-guard case has a concrete change-to-witness relationship.
  - _Boundary: Delta and Actionability Policy, engine comparison integration_
  - _Depends: 2.3, 3.3, 3.4_
  - _Requirements: 2.4, 3.1, 3.4, 4.1_
- [ ] 4.2 Enforce capability and actionability admission
  - Require evaluated capability provenance, applicable semantics, a sufficient rung, exact witness/location, supported change attribution and a concrete repair direction.
  - Keep experimental, suspicious, wrongly sanitized and unknown-novelty candidates in diagnostic records; do not let model confidence, a sanitizer name or printed-before state admit/dismiss a defect.
  - Deduplicate by defect while retaining relevant witnesses and refs; distinguish experimental evaluation from normal hook eligibility.
  - Add equivalent PHP/JavaScript normalized claims with equally eligible capabilities and assert equal admission; add an unsupported-origin control whose coverage/eligibility differs without changing core scores.
  - Done when the policy rejects an entailed but unsupported claim and admits fully supported synthetic controls equivalently across origins and advisory/blocking modes; real capabilities remain disabled pending 8.3.
  - _Boundary: Delta and Actionability Policy_
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4, 8.1_
- [ ] 4.3 Render compact results and preserve complete artifacts
  - Render up to three actionable summaries plus remaining count; emit at most one no-finding status and one aggregated incomplete notice with a useful next action.
  - Persist all defects, candidate dispositions, exact scope, identities, capability/ranker provenance and timings with separate finding/coverage/push status.
  - Done when the display cap does not change the push decision, incomplete analysis cannot read as secure, and artifact-write failure produces a bounded notice while retaining the real decision.
  - _Boundary: Result and Hook Adapter_
  - _Requirements: 3.1, 3.2, 3.3, 5.1, 5.2, 5.5, 7.3_

- [ ] 5. Prove the first end-to-end experiment before cache optimization
- [ ] 5.1 Wire explicit base/head replay through the full transaction
  - Connect immutable snapshots, ranker decisions, existing arbiter, targeted comparison, admission diagnostics and compact artifacts through an explicit local replay command.
  - Apply the shared budget to preparation and both revisions; no model/service or installed hook is required. All runtime errors preserve coverage state.
  - Done when a controlled security change and fixed twin traverse the production runner through the existing ranker and produce replayable results with truthful deadlines.
  - _Boundary: Push runner, CLI, Snapshot Adapter, engine and policy integration_
  - _Depends: 1.3, 3.1, 3.4, 4.3_
  - _Requirements: 1.1, 2.1, 3.1, 3.4, 4.1, 4.2, 5.5, 7.1, 7.3_
- [ ] 5.2 Measure PMPro and frozen-core Node transfer
  - Replay each prepared security/fixed/benign case, first using the declared hook deadline; record timeouts and stage costs. A separately named extended lab run may obtain witnesses but cannot satisfy the hook latency gate.
  - Freeze the core after PMPro, run Node with existing facts, and classify instrument, mapping, fact, scope and domain gaps without tuning on an untouched holdout.
  - Done when one joint artifact reports actual evidence and outcomes for both workloads, with unresolved cases retained and an explicit feasibility decision; no normal capability is enabled here.
  - _Boundary: Evaluation harness, full-run integration_
  - _Depends: 1.2, 1.3, 5.1_
  - _Requirements: 6.2, 6.3, 6.4, 6.5, 8.1, 8.2, 8.3, 8.4_

- [ ] 6. Reuse valid graphs and results without stale conclusions
- [ ] 6.1 Validate graph artifact identity and leases
  - Have the backend own source/declaration/exclusion digests, frontend/engine/overlay options, graph census and complete/partial identity.
  - Permit validated graph leases in the generic driver while preserving the fresh-build path; isolate potentially mutating loads and retain bounded cleanup.
  - Done when identical valid inputs can reuse a graph while any changed graph input or failed census rejects the lease; original cached artifacts survive query loading unchanged.
  - _Boundary: Cache and Engine Boundary, generic driver integration_
  - _Requirements: 4.2, 4.3, 4.4, 7.3_
- [ ] 6.2 Publish and evict local artifacts safely
  - Add private temporary publication, per-key bounded locking, atomic completed manifests, cache size enforcement and unleased eviction.
  - Retain partial records only as diagnostics; never interpret a directory or failed write as a complete result. Do not rebuild graphs incrementally by mutating old node identities.
  - Done when concurrent writers, corrupt entries and interrupted publication yield either a validated complete artifact or an explicit miss without exceeding the remaining lock budget.
  - _Boundary: Cache and Engine Boundary, push cache integration_
  - _Depends: 6.1_
  - _Requirements: 4.1, 4.3, 4.4, 7.3_
- [ ] 6.3 Key query and comparison results by all relevant semantics
  - Include graph identity, question/context/depth, facts/sanitizers/query versions and configuration; include ranking/admission/model provenance for final results and both revision identities for comparisons.
  - Keep incomplete query/comparison results out of complete lookups; preserve current eligibility checks after reuse.
  - Done when source, context, fact, query, mode, policy and optional model changes invalidate the appropriate layer, while an identical compatible request returns the same evidence and provenance.
  - _Boundary: Push cache, policy integration_
  - _Requirements: 3.4, 4.3, 4.4, 6.4, 7.2, 7.3_
- [ ] 6.4 Integrate cache reuse into the shared push deadline
  - Reuse identical snapshots/unchanged declared units across refs without merging different comparisons; changed units rebuild and stale graph relationships remain hints only.
  - Account for lookup, lock wait, lease, build/query and result persistence in the same deadline; preserve completed outcomes on cancellation.
  - Done when cached and uncached replay produce equal evidence/admission for the same completed questions under compatible semantics, with full equivalence under a sufficiently large controlled budget. Under the hook deadline, verify truthful extra completion/deferred scope from cache reuse rather than requiring identical scope; no stale answer survives a dependency/configuration edit.
  - _Boundary: Push runner, cache and engine integration_
  - _Depends: 5.1, 6.2, 6.3_
  - _Requirements: 1.1, 2.2, 4.1, 4.2, 4.3, 4.4, 7.3_

- [ ] 7. Connect the real push interface without adding noise
- [ ] 7.1 Execute Git's full push input and enforcement policy
  - Extend the replay command to consume all update lines and remote arguments, aggregating per-ref comparisons under one deadline and preserving independent coverage and finding statuses.
  - Apply advisory, opt-in blocking and separate incomplete-coverage policy; keep external services disabled by default and normal alerts limited to admitted capabilities.
  - Done when controlled multi-ref push invocations exercise all allow/block/status combinations, including deletion-only, missing-base and no-work cases, without resetting budgets.
  - _Boundary: CLI/config, Push runner and Result and Hook Adapter integration_
  - _Depends: 2.1, 4.2, 4.3, 6.4_
  - _Requirements: 1.1, 1.3, 1.4, 4.1, 5.1, 5.2, 5.3, 5.4, 5.5, 7.1_
- [ ] 7.2 Provide non-destructive hook integration and removal
  - Supply an executable integration snippet/installation path with explicit invocation, preserving existing hooks, hook path configuration, remote arguments and stdin for other consumers.
  - Refuse automatic overwrite; retain an existing hook's nonzero result even when the Safety Net runs advisory. Include concrete integration/removal instructions with the delivered hook interface.
  - Done when a disposable Git remote accepts/rejects pushes correctly with an existing stdin-reading hook, and removal restores the preceding behavior without touching source or refs.
  - _Boundary: Result and Hook Adapter, CLI integration_
  - _Requirements: 1.2, 5.3, 5.4, 7.4_
- [ ] 7.3 Keep optional model assistance within existing evidence rules
  - Reuse explicit endpoint configuration and redaction only when enabled; propagate the remaining deadline to model calls and record model/prompt/cost provenance.
  - Restrict explanations to existing witnesses and preserve deterministic no-model behavior; do not implement a new learned ranker or prompt optimizer in this task.
  - Done when a delayed or misleading model cannot extend the push budget, leak unredacted input in the tested path, raise a rung or bypass actionability admission.
  - _Boundary: Push runner, existing model and policy integration_
  - _Requirements: 3.5, 4.1, 4.2, 7.1, 7.2, 7.3_

- [ ] 8. Validate usefulness, runtime and cross-language admission
- [ ] 8.1 Exercise complete push failure and regression paths
  - Combine dirty/non-HEAD/multi-ref/new-branch/force/tag/deletion pushes with unusual paths, external content boundaries, failed census, missing comparisons and interrupted persistence.
  - Verify no orphan children, no overwritten live state, no vendor code in graphs, exact scope reports and no false clean result from skipped work.
  - Done when the integration suite covers the critical flows through the real CLI/backend seams and preserves ordinary scan behavior.
  - _Boundary: Push runner integration tests_
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.2, 2.3, 4.2, 4.4, 5.2, 5.5, 7.1, 7.4, 8.2_
- [ ] 8.2 Measure realistic cache and deadline feasibility
  - Measure identical-tip reuse, a warm one-function edit, dependency/configuration edits, cold starts, repository growth and multi-ref workloads on declared hardware.
  - Publish p50/p95, timeouts, cancellation allowance, completed/deferred population and stage costs; the denominator is fixed before ranker selection.
  - Done when the versioned scorecard evaluates the accepted latency/coverage gates without hiding timeouts or calling repeated-identical-tip hits representative warm edits; a failed gate remains NO-GO for rollout.
  - _Boundary: Evaluation harness, runtime integration_
  - _Requirements: 4.1, 4.2, 6.2, 6.3, 6.5, 7.3_
- [ ] 8.3 Evaluate independent transfer and admit only passing capabilities
  - Run the frozen candidate on reserved Node changes and benign/fixed controls; preserve PHP/Python regressions, including a verified VAmPI transitive target, and report libpng envelope/unsupported bounds separately.
  - Score actual actionable alerts, reviewed precision with counts/intervals, supported recall, benign interruptions and fixed-side silence alongside latency and coverage. Record adapter changes separately; a core retune requires a new untouched evaluation.
  - Generate versioned capability eligibility only when all predeclared gates pass; no positive controls, no reviewed alerts, no untouched workload, wrong family semantics or unsupported properties prevent admission.
  - Require untouched evaluation for the particular language/framework/family being admitted. Node results cannot qualify PHP/WordPress or Python; capabilities without their own untouched evidence remain experimental with an explicit disposition.
  - Done when the policy consumes a reproducible PASS/NO-GO capability artifact tied to exact semantics and rejects stale eligibility; a NO-GO result never silently enables advisory alerts.
  - _Boundary: Evaluation harness, Delta and Actionability Policy integration_
  - _Depends: 1.2, 1.3, 5.2, 7.3, 8.2_
  - _Requirements: 3.1, 3.2, 6.1, 6.2, 6.3, 6.4, 6.5, 8.1, 8.2, 8.3, 8.4_
- [ ] 8.4 Verify the packaged end-to-end outcome and acceptance coverage
  - Run the required regression checks and a local packaged smoke over supported security/fixed/benign pushes; verify no-model startup, preservation of hook behavior and truthful partial results.
  - Reconcile every acceptance criterion with fresh evidence and record unresolved capability/performance blockers separately from completed plumbing.
  - Done when a reproducible validation artifact states GO only with all mandatory integration and joint quality/latency gates satisfied; otherwise it names the remaining NO-GO conditions without marking the feature complete.
  - _Boundary: Packaged runtime, full feature validation integration_
  - _Requirements: 3.1, 3.4, 5.1, 5.2, 5.3, 5.4, 5.5, 6.5, 7.1, 7.3, 7.4, 8.3, 8.4_
