# Implementation Plan: pre-push-safety-net

Status: the existing task plan remains approved. Groups 1–7 and tasks 8.1, 8.2 and 8.4
are verified (28/29 executable subtasks, including group 9); task 8.3 and rollout remain NO-GO. Later work
used the documented manual review fallback where agent dispatch reached its limit.

The accepted [release milestone spec](release-milestones.md) now orders remaining work:
M1a diagnose → M1b repair → M2 speed → M3 shared-language transfer → M4 independent
qualification → M5 narrow advisory rollout. All milestones remain unverified.
Milestones are release outcomes, not checked implementation tasks. Group 9 below is the
bounded owner amendment M1a requires; it adds the task-local recorded-veto evaluation and
its three-revision development run. It enables no capability and changes no gate.
Preserve all completed task evidence below.

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

- [x] 1. Establish the runtime, evaluation inputs and shared contracts
- [x] 1.1 Reproduce the evaluated engine environment
  - Align the shipped image, Compose and host-install defaults with Joern 4.0.625; preserve version override and checksum verification.
  - Exercise PHP with the native interpreter and the installed JavaScript frontend; open a source and the frontend parser where applicable, recording byte counts and graph census.
  - Done when a local image smoke produces valid small PHP and JavaScript graph/query payloads with recorded versions, and an unreadable source fails explicitly. This builds locally; it does not deploy.
  - _Boundary: Cache and Engine Boundary, packaging integration_
  - _Requirements: 7.1, 7.3, 8.2_
  - _Verified 2026-09-12:_ independent review APPROVED; 888 tests passed, 9 skipped. Actual local image PHP/JavaScript graph census and source witnesses passed, unreadable PHP explicitly refused. Parent verified current provenance hashes, image identity, non-root user and CLI/frontend liveness. Evidence: `benchmarks/measurements/2026-09-12-engine-runtime-smoke.json`. Runtime readiness only; no hook latency/detection claim. Existing mypy errors in `model/scan.py` at 299/302/310 remain unchanged.
- [x] 1.2 Prepare labeled development and reserved evaluation changes
  - Pin a readable PMPro change/fix and a supported Node/Express change/fix, plus benign controls; verify license and source bytes before accepting recipes.
  - Use NodeGoat only if its selected mechanism fits a current arbiter; label authored repairs as authored. Reserve an independently selected Node API repository with modern module/async context and reviewable history before tuning on transfer results.
  - Keep Python regression and libpng envelope recipes, explicit supported/unsupported populations, ref identities and development/holdout roles in machine-readable evaluation inputs.
  - Reserve untouched evaluation for each language/framework/family intended for admission; the Node holdout cannot qualify PHP or Python. Missing per-capability evaluation leaves it experimental and does not delay the initial PMPro/Node diagnostic experiment.
  - Done when recipe validation resolves immutable inputs and labels or names an explicit missing prerequisite; no favorable scanner result is required to select a recipe.
  - _Boundary: Evaluation harness_
  - _Requirements: 6.1, 6.3, 8.3, 8.4_
  - _Verified 2026-09-12:_ independent review APPROVED; 902 tests passed, 9 skipped, then 34 focused tests passed after a diagnostic-only correction. Fresh offline validation opened 506,502 bytes and retained all 11 cases/9 snapshots: 7 cases input-ready, 4 with named missing prerequisites. See `benchmarks/push/inputs.json` and `input-validation.json`. Ghost checkout/reviewed labels and independent per-capability PHP/Python populations remain missing; every capability stays experimental. No detector run or admission claim.
- [x] 1.3 Make the baseline and push scorer fail honestly
  - Retain unmatched targets and unanswered queries in the declared population; require a queried witness before labeling a target transitively detected.
  - Emit actual vulnerable/fixed outcomes beside rank, selected mode, engine/facts/scope and elapsed stage costs. Freeze a versioned workload/profile before measuring.
  - Done when a deliberately missing target and failed query cannot improve reported recall, while a verified transitive positive is counted with its witness.
  - _Boundary: Evaluation harness, repository benchmark integration_
  - _Requirements: 6.2, 6.3, 6.4, 6.5, 7.3_
  - _Verified 2026-09-12:_ independent review APPROVED; 925 tests passed, 9 skipped. Parent reproduced the frozen profile and actual VAmPI static rerun (15,942 pinned bytes, all 3 targets retained, SQLI unmatched, no transitive/detection claim, exit 1). Empty-run scoring retains 11 unresolved cases and explicitly reports unmeasured/0 recorded cases. Historical baselines remain unchanged with a caveat; new scorer consumes associated execution/review evidence and does not implement replay or admission.
- [x] 1.4 Establish typed push and engine integration contracts
  - Add importable push components and validated configuration for comparison base, shared deadline/cancellation allowance, local cache limit, advisory/blocking and separate coverage policy.
  - Define ownership of update/comparison, change context, selected/deferred scope, graph identity/lease and separate finding/coverage/push statuses as described in design.
  - Keep generic engine contracts outside the push package; leave ordinary scan defaults compatible and capabilities experimental until evaluated.
  - Done when contract/config round trips preserve all identities/statuses, invalid values are rejected, and the engine has no dependency on the push package.
  - _Boundary: Push runner, Cache and Engine Boundary, CLI/config integration_
  - _Requirements: 4.1, 4.3, 5.3, 5.4, 5.5, 7.1, 7.3_
  - _Verified 2026-09-12:_ independent review APPROVED; 965 tests passed, 9 skipped; touched-source Ruff/mypy passed. Parent rebuilt the local image and verified non-root, network-disabled CLI startup, all contract imports, an 83-byte configuration round trip and invalid-budget rejection. Comparison-owned completion preserves different bases for a shared head. Contracts are structural; runtime snapshot/cache/runner/admission implementations remain in later tasks.

- [x] 2. Resolve immutable pushed content
- [x] 2.1 Resolve every supplied ref update and comparison
  - Parse Git's complete update input using object-format-aware validation; resolve existing tips, new-branch configured bases, force-pushes, merges, peeled tags, deleted refs and unsupported objects.
  - Deduplicate equal targets without merging different base comparisons; retain every ref association. Do not silently substitute HEAD or fetch missing objects.
  - Done when multi-ref and missing-base fixtures produce exact comparison identities and explicit dispositions, including deletion-only no-analysis results.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.1, 1.3, 1.4, 7.1_
  - _Verified 2026-09-12:_ independent review APPROVED after Unicode-ref repair; 997 tests passed, 9 skipped; focused 76 passed and touched Ruff/mypy passed. Real SHA-1/SHA-256 fixtures cover exact comparisons, tags, deletion, missing/ambiguous bases, replacement/graft suppression and blocked promisor fetch. Parent read 2,547 pinned source bytes and verified real-repository comparison/ref identity with dirty state and index preserved. ASCII protocol framing retains valid Unicode ref names.
- [x] 2.2 Materialize isolated object snapshots
  - Read immutable tracked blobs into bounded scratch storage using machine-readable paths; do not checkout into the live tree or run filters, project scripts or network requests.
  - Preserve path identity and report symlinks, gitlinks, unavailable LFS blobs and unsupported content; never follow source outside the snapshot.
  - Done when non-HEAD pushes from a dirty checkout read only the intended object bytes and leave index, files and refs byte-identical after success, cancellation and failure.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.1, 1.2, 1.3, 2.3, 7.1, 7.3_
  - _Verified 2026-09-12:_ independent review APPROVED; 1,037 tests passed, 9 skipped; focused 116 passed; touched Ruff/mypy passed. Real SHA-1/SHA-256 fixtures verify binary-safe paths, exact blobs, no filters, explicit symlink/gitlink/LFS limits, cancellation and unchanged live state. Independent hanging-child cleanup took 0.202 s. Parent reopened and checked all 1,157 materialized repository files (8,737,198 bytes), with scratch removed and live state preserved; evidence `benchmarks/measurements/2026-09-12-snapshot-materialization.json` records a 5.783 s preparation-only lab run, not end-to-end hook latency.
- [x] 2.3 Attach changed spans and deletion/rename context
  - Compare recorded base/head objects using NUL-safe path handling; retain removed spans, renamed identities and declaration/config changes.
  - Supply change context to the shared ranker contract rather than selecting an independent changed-files-only scope.
  - Done when renamed functions retain correspondence and a removed guard remains an impact seed for an unchanged operation, with missing correspondence explicitly unresolved.
  - _Boundary: Snapshot Adapter_
  - _Requirements: 1.4, 2.1, 2.4, 3.4_
  - _Verified 2026-09-12:_ independent review APPROVED; fresh final suite 1,069 passed, 9 skipped; focused 148 passed. Global Ruff/format, touched mypy and regression gates passed. PHP/JavaScript fixtures retain removed spans and unchanged-operation anchors across declaration renames; uncertain moves, repeated lines, binary and unavailable inputs remain unresolved. Forty independent real-Git comparisons checked exact spans/anchors. Network-disabled image smoke preserved committed PHP/JavaScript bytes and dirty non-HEAD state, with cleanup verified; see `implementation-group-2.md`. Lexical anchors do not establish semantic impact or novelty.

- [x] 3. Integrate bounded execution and ranker scope with the existing engine
- [x] 3.1 (P) Enforce one remaining-time budget in the backend
  - Thread the absolute deadline through readability probes, frontend builds, overlays, census, query batches, fallbacks and retries; no phase gets a fresh full budget.
  - Bound process-group termination and lease/scratch cleanup by the cancellation allowance, replacing any longer fixed cleanup waits on the push path.
  - Done when controlled hanging subprocesses at build/overlay/query stages terminate without orphan children inside the declared allowance, while ordinary scans preserve their prior behavior.
  - _Boundary: Cache and Engine Boundary, generic driver integration_
  - _Depends: 1.4_
  - _Requirements: 4.1, 4.2, 7.3_
  - _Verified 2026-09-13:_ independent review APPROVED; fresh suite 1,089 passed, nine skipped; global Ruff/format and mypy (108 files) passed. Real hanging probe/frontend/overlay/census/query processes obey the shared deadline and cancellation allowance; retries do not reset it. Non-root packaged PHP/JavaScript graph/query smoke passed with matching source hashes under one 900-second lab budget. See `implementation-group-3.md` and `benchmarks/measurements/2026-09-13-engine-budget-smoke.json`. Runtime readiness only; no hook latency claim. Former three mypy errors resolved by a behavior-preserving variable rename.
- [x] 3.2 Return the ranker's exact selected and deferred work
  - Integrate the existing ranker through explicit mode selection and shared question identity; record selected/deferred IDs, evidence and reasons directly from the final order.
  - Preserve unanswered evidence as unknown rather than tier zero; report per-family coverage so taint ranking cannot masquerade as authorization/configuration coverage.
  - Add paired PHP/JavaScript normalized-evidence contract tests asserting identical tier/score and selection decisions for equivalent input and budgets, without repository/language priority exceptions.
  - Done when changing order produces matching execution and manifest IDs, with no reconstruction from an earlier list, and normalized cross-language equivalence tests pass.
  - _Boundary: Ranker Scope Contract, generic driver integration_
  - _Requirements: 2.1, 2.2, 6.4, 7.3, 8.1, 8.2_
  - _Verified 2026-09-13:_ independent review APPROVED; 1,105 passed, nine skipped; global Ruff/format/mypy passed. Twenty-four independent order/budget/missing-family combinations retained all question identities. Packaged PHP/JavaScript smoke selected the same controlled risky operation at tier 4/score 2.5, with exact execution/outcome IDs and reconciled family coverage. Missing evidence, partial graphs and interrupted arbitration remain explicit; CLI consumes authoritative scope. Evidence: `benchmarks/measurements/2026-09-13-ranker-scope-smoke.json`. No new ranking weights or hook admission claim.
- [x] 3.3 Connect change context to supported first-party relationships
  - Use existing entry/callee, field, hook and guard relationships to supply affected context to ranked questions, including unchanged sinks after source/guard changes.
  - Preserve current abstract semantics; absent dynamic or external relationships remain unresolved rather than guessed safe. A required new feature or fact is reported to its owning spec.
  - Done when controlled cross-file and removed-guard cases reach the relevant question/witness, while an unresolved boundary cannot produce a complete negative.
  - _Boundary: Ranker Scope Contract, Snapshot Adapter integration_
  - _Depends: 2.3, 3.2_
  - _Requirements: 2.1, 2.2, 2.4, 8.1, 8.2_
  - _Verified 2026-09-13:_ independent review APPROVED after an unknown-call boundary repair; fresh suite 1,128 passed, nine skipped; global Ruff/format/mypy passed. Real PHP/JavaScript Git guard-removal snapshots reached unchanged helper-file witnesses with local dirty state preserved. Production negative regression reproduced then fixed unknown(req.body) being pruned as tier zero: modeled arguments no longer summarize unknown consumers. Existing ranking and detector semantics unchanged; unsupported projections remain explicit. Evidence: `benchmarks/measurements/2026-09-13-change-context-smoke.json`. Lexical attribution is not semantic novelty or alert admission.
- [x] 3.4 Apply vendor exclusion and explicit language partitions
  - _Prerequisite resolved 2026-09-13:_ contributor-scan 2.18 independently approved and verified at `51fabef`; both JavaScript test filters repaired by explicit versioned input policy. Task 3.4 subsequently passed its own independent review.
  - Reuse declared layout exclusions before target enumeration and graph build; retain unshipped first-party tests and separate browser/server or language capability coverage.
  - Build supported frontend partitions explicitly; preserve unknown cross-language and vendor semantics without restoring excluded sources.
  - Done when PHP and Node graphs/targets contain no declared vendor code, first-party callers remain visible, and unsupported partitions appear as coverage limits rather than clean results.
  - _Boundary: Ranker Scope Contract, Cache and Engine Boundary integration_
  - _Requirements: 2.2, 2.3, 7.3, 8.2, 8.4_
  - _Verified 2026-09-13:_ independent review APPROVED; 1,151 passed, nine skipped; Ruff/format/mypy pass. Real PHP/JavaScript graphs retain tests/browser source, omit vendor nodes and share one ranker limit. Named census survives PHP aggregation; missing source names and unreadable discovery inputs remain explicit. Python exercises all three batch census schemas. Evidence: `benchmarks/measurements/2026-09-13-partition-scope-smoke.json`. No hook capability or latency claim.

- [x] 4. Implement change attribution and actionable output
- [x] 4.1 Compare targeted base/head evidence for defect novelty
  - Establish stable mechanism/operation identity with rename/span mapping and collect comparable base evidence under the same semantics and remaining deadline.
  - Distinguish new, worsened, unchanged and unknown; an absent finding from a failed/truncated base is unknown. Support removed guards and new source connections at unchanged sinks.
  - Done when benign movement and unchanged backlog do not become new defects, while a supported removed-guard case has a concrete change-to-witness relationship.
  - _Verified 2026-09-13:_ independent review APPROVED; 1,167 tests passed, nine skipped; real JavaScript guard/movement and PHP connection controls passed. Final policy rechecked against captured actual answers after malformed-schema repair. See `implementation-group-4.md`.
  - _Boundary: Delta and Actionability Policy, engine comparison integration_
  - _Depends: 2.3, 3.3, 3.4_
  - _Requirements: 2.4, 3.1, 3.4, 4.1_
- [x] 4.2 Enforce capability and actionability admission
  - Require evaluated capability provenance, applicable semantics, a sufficient rung, exact witness/location, supported change attribution and a concrete repair direction.
  - Keep experimental, suspicious, wrongly sanitized and unknown-novelty candidates in diagnostic records; do not let model confidence, a sanitizer name or printed-before state admit/dismiss a defect.
  - Deduplicate by defect while retaining relevant witnesses and refs; distinguish experimental evaluation from normal hook eligibility.
  - Add equivalent PHP/JavaScript normalized claims with equally eligible capabilities and assert equal admission; add an unsupported-origin control whose coverage/eligibility differs without changing core scores.
  - Done when the policy rejects an entailed but unsupported claim and admits fully supported synthetic controls equivalently across origins and advisory/blocking modes; real capabilities remain disabled pending 8.3.
  - _Verified 2026-09-13:_ independent review APPROVED after operation/context-binding repair; 1,207 tests passed, nine skipped; default real-evidence controls remain diagnostic and synthetic PHP/JavaScript admission is equivalent. See `implementation-group-4.md`.
  - _Boundary: Delta and Actionability Policy_
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 5.3, 5.4, 8.1_
- [x] 4.3 Render compact results and preserve complete artifacts
  - Render up to three actionable summaries plus remaining count; emit at most one no-finding status and one aggregated incomplete notice with a useful next action.
  - Persist all defects, candidate dispositions, exact scope, identities, capability/ranker provenance and timings with separate finding/coverage/push status.
  - Done when the display cap does not change the push decision, incomplete analysis cannot read as secure, and artifact-write failure produces a bounded notice while retaining the real decision.
  - _Verified 2026-09-13:_ manual Kiro review fallback APPROVED after dispatch thread limit; 1,222 tests passed, nine skipped. Packaged comparison/admission/report smoke and CLI boot passed; full records retained with bounded output/write failure handling. See `implementation-group-4.md`.
  - _Boundary: Result and Hook Adapter_
  - _Requirements: 3.1, 3.2, 3.3, 5.1, 5.2, 5.5, 7.3_

- [x] 5. Prove the first end-to-end experiment before cache optimization
- [x] 5.1 Wire explicit base/head replay through the full transaction
  - Connect immutable snapshots, ranker decisions, existing arbiter, targeted comparison, admission diagnostics and compact artifacts through an explicit local replay command.
  - Apply the shared budget to preparation and both revisions; no model/service or installed hook is required. All runtime errors preserve coverage state.
  - Done when a controlled security change and fixed twin traverse the production runner through the existing ranker and produce replayable results with truthful deadlines.
  - _Verified 2026-09-13:_ manual Kiro fallback review APPROVED; 1,236 tests passed, nine skipped; final packaged security replay and fixed/deadline controls verified. See `implementation-group-5.md`.
  - _Boundary: Push runner, CLI, Snapshot Adapter, engine and policy integration_
  - _Depends: 1.3, 3.1, 3.4, 4.3_
  - _Requirements: 1.1, 2.1, 3.1, 3.4, 4.1, 4.2, 5.5, 7.1, 7.3_
- [x] 5.2 Measure PMPro and frozen-core Node transfer
  - _Prerequisite repaired 2026-09-13:_ 3.1/5.1 deadline regression verified in the packaged Node replay; re-freeze the experiment after this core identity change.
  - Replay each prepared security/fixed/benign case, first using the declared hook deadline; record timeouts and stage costs. A separately named extended lab run may obtain witnesses but cannot satisfy the hook latency gate.
  - Freeze the core after PMPro, run Node with existing facts, and classify instrument, mapping, fact, scope and domain gaps without tuning on an untouched holdout.
  - Done when one joint artifact reports actual evidence and outcomes for both workloads, with unresolved cases retained and an explicit feasibility decision; no normal capability is enabled here.
  - _Verified 2026-09-13:_ manual Kiro review APPROVED; six final CLI cases measured under unchanged core, all timed out in 30.55–30.64 seconds with artifacts retained. Full 11-case population retained; feasibility NO-GO, no eligibility enabled. 1,242 tests passed, nine skipped. See `implementation-group-5.md`.
  - _Boundary: Evaluation harness, full-run integration_
  - _Depends: 1.2, 1.3, 5.1_
  - _Requirements: 6.2, 6.3, 6.4, 6.5, 8.1, 8.2, 8.3, 8.4_

- [x] 6. Reuse valid graphs and results without stale conclusions
- [x] 6.1 Validate graph artifact identity and leases
  - Have the backend own source/declaration/exclusion digests, frontend/engine/overlay options, graph census and complete/partial identity.
  - Permit validated graph leases in the generic driver while preserving the fresh-build path; isolate potentially mutating loads and retain bounded cleanup.
  - Done when identical valid inputs can reuse a graph while any changed graph input or failed census rejects the lease; original cached artifacts survive query loading unchanged.
  - _Boundary: Cache and Engine Boundary, generic driver integration_
  - _Requirements: 4.2, 4.3, 4.4, 7.3_
- [x] 6.2 Publish and evict local artifacts safely
  - Add private temporary publication, per-key bounded locking, atomic completed manifests, cache size enforcement and unleased eviction.
  - Retain partial records only as diagnostics; never interpret a directory or failed write as a complete result. Do not rebuild graphs incrementally by mutating old node identities.
  - Done when concurrent writers, corrupt entries and interrupted publication yield either a validated complete artifact or an explicit miss without exceeding the remaining lock budget.
  - _Boundary: Cache and Engine Boundary, push cache integration_
  - _Depends: 6.1_
  - _Requirements: 4.1, 4.3, 4.4, 7.3_
- [x] 6.3 Key query and comparison results by all relevant semantics
  - Include graph identity, question/context/depth, facts/sanitizers/query versions and configuration; include ranking/admission/model provenance for final results and both revision identities for comparisons.
  - Keep incomplete query/comparison results out of complete lookups; preserve current eligibility checks after reuse.
  - Done when source, context, fact, query, mode, policy and optional model changes invalidate the appropriate layer, while an identical compatible request returns the same evidence and provenance.
  - _Boundary: Push cache, policy integration_
  - _Requirements: 3.4, 4.3, 4.4, 6.4, 7.2, 7.3_
- [x] 6.4 Integrate cache reuse into the shared push deadline
  - Reuse complete preparation/discovery by immutable tree and discovery/fact/configuration identity, retaining readable snapshot and declaration/boundary records; measure its costs and hits separately from graph/query reuse.
  - Reuse identical snapshots/unchanged declared units across refs without merging different comparisons; changed units rebuild and stale graph relationships remain hints only.
  - Account for lookup, lock wait, lease, build/query and result persistence in the same deadline; preserve completed outcomes on cancellation.
  - Done when cached and uncached replay produce equal evidence/admission for the same completed questions under compatible semantics, with full equivalence under a sufficiently large controlled budget. Under the hook deadline, verify truthful extra completion/deferred scope from cache reuse rather than requiring identical scope; no stale answer survives a dependency/configuration edit.
  - _Boundary: Push runner, cache and engine integration_
  - _Depends: 5.1, 6.2, 6.3_
  - _Requirements: 1.1, 2.2, 4.1, 4.2, 4.3, 4.4, 7.3_

- [x] 7. Connect the real push interface without adding noise
- [x] 7.1 Execute Git's full push input and enforcement policy
  - Extend the replay command to consume all update lines and remote arguments, aggregating per-ref comparisons under one deadline and preserving independent coverage and finding statuses.
  - Apply advisory, opt-in blocking and separate incomplete-coverage policy; keep external services disabled by default and normal alerts limited to admitted capabilities.
  - Done when controlled multi-ref push invocations exercise all allow/block/status combinations, including deletion-only, missing-base and no-work cases, without resetting budgets.
  - _Boundary: CLI/config, Push runner and Result and Hook Adapter integration_
  - _Depends: 2.1, 4.2, 4.3, 6.4_
  - _Requirements: 1.1, 1.3, 1.4, 4.1, 5.1, 5.2, 5.3, 5.4, 5.5, 7.1_
- [x] 7.2 Provide non-destructive hook integration and removal
  - Supply an executable integration snippet/installation path with explicit invocation, preserving existing hooks, hook path configuration, remote arguments and stdin for other consumers.
  - Refuse automatic overwrite; retain an existing hook's nonzero result even when the Safety Net runs advisory. Include concrete integration/removal instructions with the delivered hook interface.
  - Done when a disposable Git remote accepts/rejects pushes correctly with an existing stdin-reading hook, and removal restores the preceding behavior without touching source or refs.
  - _Boundary: Result and Hook Adapter, CLI integration_
  - _Requirements: 1.2, 5.3, 5.4, 7.4_
- [x] 7.3 Keep optional model assistance within existing evidence rules
  - Reuse explicit endpoint configuration and redaction only when enabled; propagate the remaining deadline to model calls and record model/prompt/cost provenance.
  - Restrict explanations to existing witnesses and preserve deterministic no-model behavior; do not implement a new learned ranker or prompt optimizer in this task.
  - Done when a delayed or misleading model cannot extend the push budget, leak unredacted input in the tested path, raise a rung or bypass actionability admission.
  - _Boundary: Push runner, existing model and policy integration_
  - _Requirements: 3.5, 4.1, 4.2, 7.1, 7.2, 7.3_

- [ ] 8. Validate usefulness, runtime and cross-language admission
- [x] 8.1 Exercise complete push failure and regression paths
  - Combine dirty/non-HEAD/multi-ref/new-branch/force/tag/deletion pushes with unusual paths, external content boundaries, failed census, missing comparisons and interrupted persistence.
  - Verify no orphan children, no overwritten live state, no vendor code in graphs, exact scope reports and no false clean result from skipped work.
  - Done when the integration suite covers the critical flows through the real CLI/backend seams and preserves ordinary scan behavior.
  - _Boundary: Push runner integration tests_
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.2, 2.3, 4.2, 4.4, 5.2, 5.5, 7.1, 7.4, 8.2_
- [x] 8.2 Measure realistic cache and deadline feasibility
  - Measure identical-tip reuse, a warm one-function edit, dependency/configuration edits, cold starts, repository growth and multi-ref workloads on declared hardware.
  - If reuse correctness passes but changed-code checks time out, identify preparation, frontend/overlay/census and query costs separately and route the remaining optimization to its owning boundary before rollout GO. Preserve the declared gates and do not substitute identical-tip latency.
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
  - _Blocked 2026-09-13:_ Eligibility implementation and reproducible NO-GO artifact delivered; independent reviewed Node/PHP/Python populations and verified VAmPI transitive witness remain missing. Runtime/coverage gates fail. See `implementation-group-8.md` and contributor-scan owner follow-up.
- [x] 8.4 Verify the packaged end-to-end outcome and acceptance coverage
  - Run the required regression checks and a local packaged smoke over supported security/fixed/benign pushes; verify no-model startup, preservation of hook behavior and truthful partial results.
  - Reconcile every acceptance criterion with fresh evidence and record unresolved capability/performance blockers separately from completed plumbing.
  - Done when a reproducible validation artifact states GO only with all mandatory integration and joint quality/latency gates satisfied; otherwise it names the remaining NO-GO conditions without marking the feature complete.
  - _Boundary: Packaged runtime, full feature validation integration_
  - _Requirements: 3.1, 3.4, 5.1, 5.2, 5.3, 5.4, 5.5, 6.5, 7.1, 7.3, 7.4, 8.3, 8.4_


- [x] 9. Diagnose the first useful detection with vetoes recorded (release milestone M1a)
- [x] 9.1 Add the task-local recorded-veto evaluation flag
  - Add an explicit experimental evaluation path that **records** each comparison and admission veto per raw finding instead of applying it. Keep it task-local, off by default, and available only on explicit `--base`/`--head` replay; refuse it on the Git stdin path so it can never become a hook capability.
  - Lift only recognized completeness vetoes over a copy of the evidence: answered-then-demoted question outcomes, the vendor exclusion completion veto, and the diagnosed context/correspondence boundary kinds. Never lift failures: deadline exhaustion, unanswered questions, unreadable input, empty graphs and unparsed files stay applied, because silence from failure is not a quiet fixed twin.
  - Retain the production novelty, reason and admission reasons beside the recorded ones for every finding, plus the query-to-witness identity difference, base-only findings and readable census receipts. Every payload carries an explicit experimental label; the recorded path admits no defect and enables no capability.
  - Done when the flag is off by default, produces a labeled artifact section and terminal line under explicit replay, is refused in Git stdin mode, and unit controls prove recognized vetoes are recorded while failures and unrecognized boundaries remain applied.
  - _Boundary: Delta and Actionability Policy, Push runner, Result and Hook Adapter, CLI integration_
  - _Requirements: 3.1, 3.4, 5.5, 6.3, 7.3_
  - _Verified 2026-09-16:_ 1,330 tests passed, nine skipped; global Ruff/format and touched mypy passed. Flag off by default, refused in Git stdin mode, labeled artifact section and terminal line under explicit replay. Controls prove recognized vetoes are recorded while deadline exhaustion, unanswered questions, empty graphs and unrecognized boundaries stay applied, and that the recorded path emits no defect even when a lifted candidate would otherwise admit. Regenerated the committed module audit for the added module.
- [x] 9.2 Run the three NodeGoat revisions and produce the per-finding veto list
  - Record exact base/head revisions, expected operation and expected outcome before running. Exercise the shipped replay path, existing ranker and physically vendor-free graph; do not substitute a hand-selected slice or hard-coded target function.
  - Replay the pinned vulnerable, fixed and unchanged revisions under the flag with an explicitly named development budget. That budget cannot satisfy or measure the hook latency gate.
  - Deliverable: the raw finding on the vulnerable revision with location and witness, the fixed twin genuinely analyzed and quiet, the unchanged revision not reported as a new regression, and for every finding the exact list of vetoes that fired and why, with source and census receipts.
  - Done when one replayable three-revision record states each expectation against its observed outcome and names the vetoes that actually fired. A fixed twin that timed out or was not analyzed fails M1a and blocks M1b until diagnosed.
  - _Boundary: Evaluation harness, full-run integration_
  - _Depends: 9.1_
  - _Requirements: 1.1, 2.1, 2.4, 3.4, 6.3, 7.1, 7.3_
  - _Verified 2026-09-16:_ all three pinned revisions replayed through the production CLI under a named 900-second development budget; expectations frozen on disk first. Raw `<lambda>2` witnesses present at lines 32–34; fixed twin analyzed and quiet (target question answered with zero rows, no deadline reason, three base-only findings); unchanged revision analyzed and recorded `unchanged`. Five vetoes fired and were recorded; the remaining blocker is `operation_correspondence_unresolved` for an operation on a changed line. Zero admitted defects. Evidence: [M1a record](m1a-recorded-vetoes.md) and `benchmarks/measurements/2026-09-16-nodegoat-m1a-recorded-vetoes.json`. Diagnosis only; no capability enabled and no latency claim.

- [x] 10. Repair only the vetoes M1a recorded (release milestone M1b)
- [x] 10.1 Establish operation correspondence for an operation on a changed line
  - M1a measured this as the blocker that survives every other repair: a newly introduced operation sits on a changed line, has no base line anchor, and therefore cannot be classified even when every completeness veto is lifted.
  - Bind the required base/head correspondence to the specific operation identity rather than to a line anchor. A complete base answer for the counterpart question that contains no operation with the same operation and source establishes absence; a matching operation elsewhere in that answer is movement, not novelty.
  - Keep the existing conservative rules: an incomplete or failed base stays unknown, benign movement and renames stay unchanged, and lexical alignment is never semantic proof.
  - Add absent, renamed, removed-guard, moved-operation and repeated-identical-operation controls. Done when a newly introduced operation on a changed line is classified new, while movement, renames and an incomplete base remain unchanged or unknown.
  - _Boundary: Delta and Actionability Policy_
  - _Requirements: 2.4, 3.1, 3.4_
  - _Verified 2026-09-16:_ 1,337 tests passed, nine skipped; Ruff/format/mypy passed. Correspondence now reports `anchored`, `ambiguous`, `changed_line`, `unmapped` or `unchanged_path`, and only `changed_line` supports an introduced operation. Movement keys on the operation spelling, which the existing benign-rename control proved necessary. One superseded control was updated with its reason; movement, ambiguity, unmapped operations, discharged or unentailed claims and an incomplete base all remain unknown.
- [x] 10.2 Establish the required comparison scope explicitly
  - Comparison currently requires every selected base question to complete with no base degradation and no non-tier-zero deferred question, so one unsupported family anywhere prevents an otherwise complete target comparison. The owner research names this and requires the amendment to state the required scope rather than relax the bar.
  - Define the comparison's required scope as the counterpart question plus the questions its evidence actually depends on, and require completeness over exactly that scope. Retain every other gap in aggregate coverage; a question outside the required scope stays reported and unresolved, never silently discharged.
  - A missing raw finding in an incomplete base still cannot establish novelty. Unknown dependency remains inside the required scope.
  - Done when an unrelated unsupported family no longer prevents a complete target comparison, while an incomplete counterpart, an incomplete dependency of it, or unknown dependency ownership still yields unknown.
  - _Boundary: Delta and Actionability Policy_
  - _Depends: 10.1_
  - _Requirements: 2.2, 2.4, 3.4, 6.4_
  - _Verified 2026-09-16:_ 1,342 tests passed, nine skipped; Ruff/format/mypy passed. Completeness is now demanded over the counterpart plus its recorded dependencies. Controls prove an unrelated unsupported family no longer blocks a complete target comparison, while an incomplete counterpart, an incomplete recorded dependency, an unknown-ownership boundary and a truncated base scan all still yield unknown. Every other gap stays in aggregate coverage.
- [x] 10.3 Scope correspondence ambiguity to the operations it actually affects
  - `ambiguous_line_correspondence` is recorded file-wide and inherited by every question, so repeated unchanged lines invalidate distinct, uniquely mapped operations elsewhere.
  - Retain ambiguous mappings as unavailable and record which regions are ambiguous, so only an operation whose required correspondence needs an ambiguous line is vetoed. Do not delete the ambiguity check.
  - Done when a uniquely mapped operation is comparable in a file that also contains repeated unchanged lines, while an operation needing an ambiguous line stays unresolved.
  - _Boundary: Snapshot Adapter, Delta and Actionability Policy_
  - _Depends: 10.2_
  - _Requirements: 2.4, 3.4_
  - _Verified 2026-09-16:_ 1,347 tests passed, nine skipped; Ruff/format/mypy passed. Ambiguity is no longer inherited as a context gap by every question, and no longer blocks the transaction comparison; it is decided per operation by the correspondence classifier. Controls prove a uniquely mapped or newly introduced operation stays comparable in a file with repeated unchanged lines, an operation needing an ambiguous anchor stays unresolved, and any other transaction gap still blocks. The mapping is still withheld and still reported in aggregate coverage.
- [x] 10.4 Export the enumerated operation inventory so absence is provable
  - **Prerequisite discovered 2026-09-16, not in the original plan.** The 10.1-10.3 rerun showed the remaining two vetoes cannot be scoped or relaxed soundly as written. A taint answer reports flows, so an absent row means either that the operation does not exist in the base or that no traced flow reached it. `dynamic_external_or_depth_context_unresolved` exists precisely to stop the second being read as the first, and on a real Express application it is always true, because ordinary framework and dependency calls have unresolved destinations. It therefore carries no discrimination and can never be discharged, while removing it would make an unreached operation look absent.
  - Export the operations the query actually enumerated in the question's scope, separately from the flows it traced, so absence of an operation is established by the inventory rather than by the absence of a flow. Sanitizer and source facts are unchanged; this adds no detector, alias resolver or second IR.
  - Done when a base answer distinguishes "this operation does not exist here" from "no traced flow reached it", with an unenumerated scope remaining explicitly unresolved.
  - _Boundary: contributor-scan query/evidence contract, Delta and Actionability Policy_
  - _Depends: 10.1_
  - _Requirements: 2.1, 2.2, 3.4, 8.1, 8.2_
  - _Verified 2026-09-16:_ 1,354 tests passed, nine skipped; Ruff/format/mypy passed. The taint query exports one row per enumerated operation plus a completion marker, which is what makes an empty inventory meaningful. Comparison now separates three outcomes: operation present in the base without a traced flow, operation absent from an enumerated base, and a base scope never enumerated, which stays explicitly unresolved along with any malformed inventory. The arbiter skips every row carrying a kind, so an inventory row cannot become a flow with an empty source. Real-engine smoke on an authored two-revision JavaScript control confirmed emission, the zero-operation marker and unchanged answer integrity: `benchmarks/measurements/2026-09-16-operation-inventory-smoke.json`. Pre-inventory fixtures were given an enumerated base, since an unenumerated one can no longer establish absence.
- [x] 10.5 Make the external and dynamic context boundary question-owned
  - M1a recorded `dynamic_external_or_depth_context_unresolved` on the target's own question. The flag is computed over every in-scope method, so one unresolved call anywhere vetoes every question.
  - With 10.4 supplying inventory evidence, bind the boundary to what it actually limits: reachability, not enumeration. A question establishing absence from the inventory no longer needs complete reachability; a question asserting a traced flow still does. Unknown ownership remains a blocker; absent evidence of independence is not proof of independence.
  - Done when an absence established from the inventory survives an unrelated unresolved destination, while a reachability claim under a bounded scope stays unresolved.
  - _Boundary: contributor-scan query/context evidence, Ranker Scope Contract_
  - _Depends: 10.4_
  - _Requirements: 2.1, 2.2, 8.1, 8.2_
  - _Verified 2026-09-16:_ 1,362 tests passed, nine skipped; Ruff/format/mypy passed. The boundary is now bound to what it limits. At scan level it is recorded against its owning question without demoting that question's answer, while an unavailable projection, an empty scope and an unreadable extent still demote. In comparison it no longer blocks the head's own traced flow, and no longer blocks an absence read off a structural enumeration, but still blocks every claim resting on a flow not having been traced. The query declares its enumeration basis, because a scope followed through the call graph can be shrunk by the same unresolved destination; such an inventory cannot establish absence while reachability is bounded. Controls cover both directions and both bases; every other gap kind still blocks.
- [x] 10.6 Stop vendor exclusion acting as a global completion veto
  - `vendor_semantics_unresolved` degrades every otherwise complete outcome to `graph_incomplete`, including on a complete 44-file first-party census with successful query receipts.
  - Keep the exclusion physical and keep the coverage note. Let the inventory and reachability evidence from 10.4 and 10.5 carry whether a specific answer needed excluded semantics; a recorded dependency on an excluded path still blocks that question.
  - Done when an unrelated vendor exclusion no longer invalidates a first-party answer, while a question with evidence of dependency on excluded code remains unresolved and the exclusion stays out of targets and graphs.
  - _Boundary: contributor-scan graph/scope evidence, Cache and Engine Boundary_
  - _Depends: 10.5_
  - _Requirements: 2.2, 2.3, 8.2, 8.4_
  - _Verified 2026-09-16:_ 1,365 tests passed, nine skipped; Ruff/format/mypy passed. Graph boundaries are split into integrity failures, which still demote a completed answer, and declared exclusions, which do not. Whether a particular answer needed the excluded semantics is carried by that question's own unresolved call destinations from 10.5, not assumed for every answer. Controls exercise the real partition logic rather than an injected reason: a vendored directory leaves the answer completed with the exclusion still reported, an unresolved symlink still demotes, and the two together still demote. The exclusion stays physical and out of targets and graphs. The NodeGoat rerun showed the same distinction was still missing inside comparison, where any degradation and any boundary blocked: comparison now filters declared exclusions and correspondence ambiguity on both sides, keeping integrity degradations and every other boundary blocking.
- [x] 10.7 Bind candidate dependency gaps to the candidate
  - **Discovered 2026-09-16 in the M1b production rerun.** The runner passes every coverage reason as every candidate's `dependency_gaps`, so admission always answers `dependency_unresolved`. That is not "an unresolved dependency that undermines the claim"; it is every gap anywhere in the transaction.
  - Supply the gaps that pertain to this candidate's required comparison scope, the same scope 10.2 established. Unknown ownership still counts against the candidate.
  - Not an M1b exit blocker, since eligibility stays disabled and no alert is emitted either way. It would prevent admission from ever passing after qualification, so it belongs before M4.
  - Done when an unrelated transaction gap no longer appears as this candidate's unresolved dependency, while a gap in its required scope still does.
  - _Boundary: Push runner, Delta and Actionability Policy_
  - _Depends: 10.2_
  - _Requirements: 3.1, 3.3, 3.4_
  - _Verified 2026-09-16:_ 1,371 tests passed, nine skipped; Ruff/format/mypy passed. Gaps are now attributed: a boundary carrying a question id counts only when that question is in this candidate's required scope, an unattributed gap always counts because unknown ownership is not evidence of independence, and integrity degradations count. A declared exclusion, correspondence ambiguity and bounded reachability do not, because each was already weighed against this specific claim. The runner no longer hands every candidate the whole transaction's reason list, which had included other candidates' comparison outcomes.
- [x] 10.8 Carry query-to-operation provenance into the reported evidence
  - The target is selected through a file-fallback question with `function=None` while rows report method `<lambda>2`. M1a showed this did not block the comparison once the question completed, so it is provenance quality rather than the blocker.
  - Record verified query-to-operation provenance on the evidence; do not inject benchmark function names into regions or count coincident sites.
  - Done when a reported operation names the question that produced it and the method the engine reported, with unresolved provenance explicit.
  - _Boundary: Delta and Actionability Policy, contributor-scan normalization_
  - _Requirements: 3.1, 3.4, 6.3_
  - _Verified 2026-09-16:_ 1,371 tests passed, nine skipped; Ruff/format/mypy passed. Evidence now carries the method the engine reported beside the question that produced it, so the link is inspectable rather than inferred or dug out of a detail blob. Provenance is recorded as `exact`, `file_scope` when the question named no function and the engine supplied one, `unresolved` when the two disagree, and `method_unreported` when the engine named none. Controls cover all four. No region is renamed, no benchmark function name is injected and no coincident site is counted; the state is recorded, not applied.
- [x] 10.9 Rerun the three revisions through the production rules
  - Replay the same pinned vulnerable, fixed and unchanged revisions **without** the recorded-veto flag under the named development budget. Demonstrate a developer-readable evaluation finding with a supported consequence, exact location, witness, change attribution and repair direction.
  - Verify the fixed twin is analyzed and produces no actionable defect and the unchanged revision is not reported as a new regression. Keep qualification eligibility disabled; experimental evaluation output cannot advertise an unqualified hook alert.
  - Done when one replayable record states which vetoes were repaired and which remain, with completed required checks and readable source and census receipts.
  - _Boundary: Evaluation harness, full-run integration_
  - _Depends: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8_
  - _Requirements: 1.1, 2.1, 2.4, 3.1, 3.4, 6.3, 7.1, 7.3_
  - _Verified 2026-09-16 with one named exception:_ all three revisions replayed through the production rules with exact pins and reopened source receipts. Vulnerable: three sites new with `operation_absent_from_comparable_base`, admission rejecting on `capability_unavailable` alone. Fixed twin: analyzed and quiet with three base-only findings. Unchanged: three sites `unchanged` with base locations resolved to the same lines. Every finding carries its question, the engine-reported method and its witness; the head census is the complete 44 files; all 436 base questions complete. Zero admitted defects. The repaired and remaining veto lists are in [the M1b record](m1a-recorded-vetoes.md). **Exception:** the supported security consequence and concrete repair direction are not demonstrated, because both are owned by an evaluated capability declaration and the registry is deliberately empty. M1b's comparison half is verified; its explanation half waits on M4.

- [x] 10.10 Render the experimental evaluation finding with its consequence and repair
  - **The remaining half of M1b's exit, named by the 10.9 run.** The comparison is verified, but the milestone also asks for a developer-readable finding carrying a supported security consequence and a concrete repair direction. Both come from an evaluated capability declaration and the registry is deliberately empty, so nothing renders them.
  - Generate an explicitly unreviewed, experimental declaration for this capability with the existing registry tool, and render the finding through the same grounded-template path the admitted case uses. Keep eligibility disabled: an experimental declaration is not enabled and not PASS, so admission must still reject it and no normal hook alert may be advertised.
  - Do not write consequence or repair text that no declaration supports. Refusing generic advice without a supported context and operation is the rule admission exists to enforce, and the experimental path must not become a way around it.
  - Done when the experimental output shows family, exact location, witness, change attribution, consequence and repair direction for the vulnerable revision, is labeled experimental throughout, and the production result still reports no actionable defect with zero admitted defects.
  - _Boundary: Result and Hook Adapter, Delta and Actionability Policy, Evaluation harness_
  - _Depends: 10.9_
  - _Requirements: 3.1, 3.2, 3.3, 5.1, 5.5, 6.3_
  - _Verified 2026-09-16:_ 1,386 tests passed, nine skipped; Ruff/format/mypy passed. Three evaluation findings rendered on the vulnerable revision with exact location, witness, change attribution, provenance, consequence and repair, all from the declaration's templates through the grounded-template path. The declaration reports verdict experimental and enabled false, the production result still reports no actionable defect, and all three artifacts carry zero admitted defects. Controls prove an ungrounded template is refused, an uncovered operation symbol is stated, no matching declaration leaves both sentences absent with the reason, and a declaration claiming PASS still admits nothing because the rendering path is outside admission. Evidence: `benchmarks/measurements/2026-09-16-nodegoat-m1b-explained.json`.


- [x] 11. Fit the same useful analysis into the push budget (release milestone M2)
- [x] 11.1 Give the backend a transaction-owned engine session
  - The measured cost is JVM startup, not analysis. In the M1b runs each disposable `joern --script` invocation cost 13 to 23 seconds while the work itself took under a second, and the 2026-09-14 lifecycle probe measured one session at 12.8 s to start, 3.6 s to load a graph and 0.22 to 0.47 s per warm request.
  - Own the session inside the existing backend for the length of one transaction: loopback only on an ephemeral port with no published port, a private working directory, one shared deadline, serialized requests, explicit graph identity and epoch, and kill-and-reap of the whole process group on cancellation, failure or exit.
  - An HTTP status is not an answer contract. Require a per-request receipt written to a fresh private file and verified before the answer is accepted, the way the probe's repaired instrument did after its first attempt read an empty stdout as a census.
  - Poison the session on any crash or malformed response so a failed session can never answer a later request, and fall back to the disposable path rather than reporting a zero.
  - Done when a controlled hanging in-session request is cancelled inside the allowance with no surviving process group, a crashed session answers nothing afterwards, and the disposable path still works unchanged.
  - _Boundary: contributor-scan runtime, Cache and Engine Boundary_
  - _Requirements: 4.1, 4.2, 7.3_
  - _Verified 2026-09-16:_ 1,391 tests passed, nine skipped; Ruff/format/mypy passed. Sixteen session tests drive a real fake-server process: receipt verified before an answer is accepted, a mismatched receipt or crash poisons the session so nothing answers afterwards, an empty body with its receipt is a valid empty answer, a hanging request is cancelled and the process group is gone inside the allowance, and a launch failure is recorded rather than raised. The probe took four iterations, each failing loudly: `runScript` is absent from the server REPL; the server answers success even for a compile error, so the receipt is the only proof; a shipped `@main` script cannot be nested in a block, so definitions go to the top level unwrapped; and the REPL shadows `Console`, so capture must qualify `scala.Console.withOut`. Evidence: `benchmarks/measurements/2026-09-16-session-script-execution.json`.
- [x] 11.2 Prove every shipped query kind answers identically through both transports
  - Run taint, dominance, configuration and census over the same graph through the session and through the disposable path and require identical payloads, including empty answers and the distinction between an empty answer and an unavailable one.
  - Cover a malformed or absent response, a switched graph, a second graph loaded in the same session, and a request arriving after cancellation. Equivalence on a census alone does not establish equivalence for security queries.
  - Done when every shipped query kind matches byte for byte on a real graph, and every failure shape is reported as unavailable rather than empty.
  - _Boundary: contributor-scan runtime, engine integration tests_
  - _Depends: 11.1_
  - _Requirements: 4.1, 4.2, 6.4, 7.3_
  - _Verified 2026-09-16:_ taint, dominance and configuration all return byte-identical payloads through both transports on a real NodeGoat graph, with parameters built by each arbiter's own request function through the driver's family lookup. Failure shapes are correct: an empty answer stays present and distinguishable from an unavailable one, an unknown query and an absent graph are both unavailable, and two graphs in one session each answer about the graph the request names. Amortized over five taint requests the session took 22.48 s against 71.96 s disposable, all answered and identical; a single request per session is its worst case and is recorded as such. Evidence: `benchmarks/measurements/2026-09-16-session-transport-equivalence.json`.
- [ ] 11.3 Route the batch path through the session behind an explicit setting
  - Consume the session from the existing batch and census paths, keeping the disposable path as the default and as the fallback. No capability, ranking decision or evidence semantics changes; only the transport does.
  - Account for session startup, load, requests and teardown inside the one shared deadline, and record them as separate stage costs so the next decision is made on measurements rather than estimates.
  - Done when a replay produces the same evidence and admission through either transport under a sufficient budget, with per-stage costs recorded for both.
  - _Boundary: Cache and Engine Boundary, Push runner_
  - _Depends: 11.2_
  - _Requirements: 4.1, 4.3, 6.4, 7.3_
- [x] 11.4 Remove the startup cost from the critical path where the measurement says it pays
  - With 11.3's stage costs in hand, decide what else to change. The candidates the M1b runs point at are the overlay pass, 15.8 s in a separate invocation, and session startup, 12.8 s, which may overlap the frontend build rather than follow it.
  - Change only what the measurement implicates, and keep each change's correctness evidence separate from its timing evidence. Do not substitute a faster census for a completed security check.
  - Done when the recorded stage costs after the change are compared against the same profile before it, with any regression in completed checks reported rather than traded away.
  - _Boundary: contributor-scan runtime_
  - _Depends: 11.3_
  - _Requirements: 4.1, 4.2, 6.2, 6.5_
  - _Verified 2026-09-17:_ 1,399 tests passed, nine skipped; Ruff/format/mypy passed. The overlay, the last fixed cost bypassing the session, now runs in-session and the saved graph is verified rather than assumed. The first session-enabled replay then showed correct detections and no speedup, and a targeted probe disproved the sequence hypothesis before finding the real defect: a build runs on a copy of the backend, so the session it started was never closed, leaking a JVM holding the configured heap, twice per transaction, enough to exhaust the container. With that fixed the session stays alive for the whole transaction and no `session_query_failed` appears. Measured on the same pins and budget, the vulnerable revision went from 326.4 s to 243.3 s, head query time from 63.6 s to 32.0 s and base from 85.1 s to 51.2 s, with dominance and configuration each falling from about 14 s to about 4 s. Detections unchanged. Evidence: `benchmarks/measurements/2026-09-17-nodegoat-session-transport.json`.
- [x] 11.5 Rerun the frozen seven-class runtime profile and decide
  - Rerun the unchanged seven-class profile: identical-tip, function edit, dependency edit, configuration edit, cold, growth and multi-ref, three samples each, retaining every timeout and unresolved check. Identical-tip reuse cannot substitute for warm changed-code work.
  - Verify the M1 outcome still holds on the same three revisions through the production rules, so speed is not bought with a lost detection.
  - Apply the existing gates without alteration: representative warm changed-code p95 at most 30 s, cancellation and reporting at most 2 s, supported-check completion at least 95%. A failed gate stays NO-GO and names the dominant remaining cost.
  - Done when one versioned scorecard reports p50 and p95 with sample counts beside the M1 correctness outcome, and states GO or NO-GO against the unchanged gates.
  - _Boundary: Evaluation harness, runtime integration_
  - _Depends: 11.4_
  - _Requirements: 4.1, 4.2, 6.2, 6.3, 6.5, 7.3_
  - _Measured 2026-09-17, verdict NO-GO:_ the unchanged seven-class profile, three samples each, session enabled. Every changed-code workload still times out at the 30-second deadline, and identical-tip got worse, p50 rising from 18.5 s to 24.2 s. The cause is recorded in the artifacts rather than inferred: 13 transactions report `session_unavailable:session_startup_timeout`, so under the real deadline the session usually never starts and everything falls back. Startup is 9 to 13 seconds, about a third of the whole budget, spent before any analysis. Where a session did start, on cached-graph transactions with little remaining work, it cost more than it saved. Correctness is unchanged: the same three revisions through the production rules with the session on reproduce the M1 verdict. Evidence: `benchmarks/measurements/2026-09-17-session-runtime-profile.json`. **Dominant remaining cost: engine startup itself, which a transaction-owned session relocates but cannot remove.**

- [x] 12. Security capability work found during M1a and M1b
  - Group 11 established that M2 needs graph reuse rather than more runtime tuning, and that decision is recorded there. This group returns to what the tool can actually establish about a codebase, which is where the remaining release risk sits: two of the three shipped families cannot complete their change context at all, and admission rejects genuine findings on a mis-extracted operation symbol.
- [x] 12.1 Extract the operation symbol from the operation, not from the statement
  - **Found 2026-09-16 in the M1b explanation run.** Admission takes the text before the first parenthesis as the operation symbol, so `const preTax = eval(req.body.preTax)` yields `const preTax = eval`. The demonstration declaration had to enumerate each assignment spelling for its coverage check to pass.
  - A qualified declaration cannot enumerate every assignment a codebase might write, so admission would reject genuine findings on `operation_semantics_mismatch`. Take the symbol from the called operation the engine reported, preserving receiver spelling, and leave an unresolved or dynamic spelling ineligible as it is today.
  - Done when the symbol for an assigned call is the call's own name, a receiver-qualified call keeps its receiver, a dynamic spelling stays ineligible, and a declaration naming the plain symbol covers the assigned form.
  - _Boundary: Delta and Actionability Policy_
  - _Requirements: 3.1, 3.2, 3.4_
  - _Verified 2026-09-17:_ 1,403 tests passed, nine skipped; Ruff/format/mypy passed. The symbol is now the trailing qualified callee rather than everything before the first parenthesis, so `const preTax = eval(...)` yields `eval` and a declaration naming the call covers the assigned form. Receiver spelling is preserved, so `$wpdb->prepare` and `prepare` remain different operations. A spelling that is not a qualified name, such as a dynamic `handlers[name](x)`, yields the statement text, matches no declaration and stays ineligible exactly as before. The recorded-veto report reads the same helper rather than repeating the extraction.
- [x] 12.2 Supply per-family context producers for dominance and configuration
  - The M1b exit run left 231 of 436 head questions reporting `change_context_incomplete` from `context_projection_unavailable` and `context_scope_empty`, because those families' queries export no context. They did not block the Node injection case, so M1b correctly left them alone, but their families stay experimental until they can answer.
  - Give dominance and configuration their own context producers describing the actual scope of the query they accompany. Do not copy taint context into them: dominance evaluates sibling operations across a file and configuration has different scope and obligations.
  - Done when a dominance and a configuration question complete their change context on a real repository, with missing extents and unsupported reasoning still explicit.
  - _Boundary: contributor-scan query/context evidence_
  - _Requirements: 2.1, 2.2, 8.1, 8.2_
  - _Verified 2026-09-17:_ 1,405 tests passed, nine skipped; Ruff/format/mypy passed. The gap was larger than a missing query block: the evidence pass dispatches taint only, because only taint has an evidence vector, so these families were never asked for context at all. Each query now describes its own scope, dominance the file's methods labelled operation, guard or sibling because its claim is about a file contradicting itself, and configuration the file's methods labelled setting or sibling. Neither copies taint's reachability projection, which would describe work they never do, and both report an empty scope explicitly. A new context pass asks each family with the flag set; a family whose query answers nothing keeps no context and stays unresolved, which a control asserts so no family can complete on another's context. Confirmed on a real NodeGoat graph: both produce a context summary and seven scoped methods. Evidence: `benchmarks/measurements/2026-09-17-per-family-context.json`.

- [x] 11.6 Decide what to do about engine startup, which the session cannot remove
  - **Named by the 11.5 measurement.** A transaction-owned session amortizes engine startup across the invocations inside one transaction, and a warm changed-code push does not have enough of them: startup is 9 to 13 seconds of a 30-second budget, so the session either fails to start or costs more than it saves. Group 11 as designed cannot reach the gate.
  - The options are a decision for the maintainer, not an implementation detail, because two of them change the product's shape. A session shared across transactions is a resident local service, which the accepted milestone spec explicitly does not imply. A smaller budget for what a push analyses is a scope change, not a speed change. A faster cold path would mean attacking the frontend and overlay costs directly, which the session does not touch.
  - Record the measured cost of each candidate before choosing, and keep the 30-second and 2-second gates unchanged; a gate met by analysing less is not the same result.
  - Done when one record states the candidates, their measured or estimated costs, their effect on the product's shape, and the maintainer's choice.
  - _Boundary: contributor-scan runtime, release direction_
  - _Depends: 11.5_
  - _Requirements: 4.1, 4.2, 6.5_
  - _Decided 2026-09-17 by the maintainer: do not rebuild a whole graph per push._ Both startup attacks were measured and neither reaches the gate. The session helps a long transaction, 326 s to 243 s, and cannot help a 30-second one: startup is 9 to 13 seconds of the budget, so it usually declines. Removing JavaScript's second engine start is real, 11.0 s against 21.0 s on identical graphs, but its census gate was asymmetric and it was reverted after costing two engine starts on 12 profile transactions. What the profile names is not startup at all: a changed-code transaction reaches its deadline during the build, head build 25.2 s of 30 s with query time 0.0 s. The remaining cost is building a fresh whole-repository graph for every pushed revision. **Direction: reuse the graph across revisions instead of rebuilding it, rather than further optimising the rebuild.** Not scheduled here; M2 stays unmet and the 30-second and 2-second gates stay unchanged.

- [x] 12.3 Resolve function-scoped questions whose function the query cannot locate
  - **Named by the 12.2 measurement.** With per-family context in place, head completion rose from 205 to 298 of 436 and `context_projection_unavailable` fell to zero. Every remaining unresolved question reports `context_scope_empty`, and they sit in three files: `app/routes/index.js` (114), `app/routes/tutorial.js` (12) and `server.js` (12). None is access control.
  - These are function-scoped questions whose named function the query cannot locate in the graph, so the scope it describes is honestly empty. It is the same query-to-operation identity problem M1a recorded at the witness end, appearing at the scope end.
  - Carry verified provenance from the region's declared function to the method the engine actually holds, and leave an unresolvable name explicit. Do not widen a question to the whole file to make it complete, and do not inject a declared name into a region.
  - Done when a question whose function the graph holds completes, a question whose function it does not hold stays unresolved with the name recorded, and no question completes by widening its scope.
  - _Boundary: contributor-scan query/context evidence, Ranker Scope Contract_
  - _Depends: 12.2_
  - _Requirements: 2.1, 2.2, 6.3, 8.1_
  - _Verified 2026-09-17:_ 1,406 tests passed, nine skipped; Ruff/format/mypy passed. The cause is recorded rather than guessed: `app/routes/index.js` requires seven handler modules and defines none of them, so a question naming `handleContributionsUpdate` there names a function that file genuinely does not hold and the empty scope is correct. Taint and configuration now separate the two causes, reporting `context_function_unresolved` with the name when a question names a function the file does not define, and `context_scope_empty` only when the file has no methods at all. The driver no longer adds its generic empty-scope gap on top of a query that already explained itself, and the new gap is question-owned so it cannot block another question's comparison. Completion is unchanged by design: a question whose function the graph does not hold stays unresolved, and nothing completes by widening its scope to the whole file.

- [x] 12.4 Attribute a region to the file that defines its handler
  - **The region-attribution half of 12.3.** A route-registration module registers handlers other modules define. `app/routes/index.js` requires seven handler modules and defines none, yet regions there were scoped to `handleContributionsUpdate` and its siblings, so the graph rightly held no such method and every question in those regions was unresolvable: 138 across six families.
  - The entry record still names the handler, because the authorization question is which middleware guards which handler and that is cross-file by nature. It now also records whether the file defines what it names, and a region built from an entry that does not is scoped to the file rather than to a method the file lacks.
  - _Verified 2026-09-17:_ 1,407 tests passed, nine skipped; Ruff/format/mypy passed. A first attempt changed the mapper to stop naming cross-file handlers and was reverted: an existing control proved the name carries the authorization attribution, so the fix belongs in region construction, not in the mapper. Controls assert the registering file asks about itself with no function-scoped region, while the defining module keeps its function-scoped region.
  - _Boundary: Ranker Scope Contract, contributor-scan entry mapping_
  - _Depends: 12.3_
  - _Requirements: 2.1, 2.2, 8.1_


- [ ] 13. Show the shared design transfers across languages (release milestone M3)
  - Status 2026-09-17: Python established, PHP blocked by runtime on a large repository. M3 is not met. Its exit asks for Node, PHP and Python together, and two of the three are in hand.
- [x] 13.1 Replay the declared Python family through the shared core
  - Generalize the replay instrument so a case family is an argument rather than a hard-coded target: a harness that only knows one language cannot say whether the design transfers. Targets, pins and expectations come from the committed inputs.
  - VAmPI is a regression snapshot with the same revision on both sides, so it can establish detection and completion but never novelty. The mode asserts that too: with nothing changed, a target reported new would be a comparison defect rather than a finding.
  - _Verified 2026-09-17:_ all three declared targets detected at their declared lines with their questions answered, 35 of 35 questions complete on every case, nothing reported new, zero admitted defects. The SQL injection at `models/user_model.py:73` is the evidence the milestone names as previously unresolved. Two of the three are access control, the family that could not complete a question anywhere before group 12, so this is the first time broken object-level authorization has been asked on Python. Evidence: `benchmarks/measurements/2026-09-17-m3-python-transfer.json`.
  - _Limits:_ identical revisions establish detection, not novelty; VAmPI is inspected teaching data and cannot qualify production Python support.
  - _Boundary: Evaluation harness, full-run integration_
  - _Requirements: 6.2, 6.3, 8.1, 8.2_
- [ ] 13.2 Replay the declared PHP pair through the shared core
  - PMPro 2.9.7 against 2.9.8 with its upstream prepare fix, plus a comment-only benign variant. A different language, a different mechanism and a fix this project did not author.
  - The first attempt selected one case of three, because the manifest labels a case by what it is while the case id says what the comparison does; the harness now maps label to role explicitly. That run also exhausted a 900-second budget on the single case it ran.
  - Done when all three comparisons complete with their declared target evidence recorded, or the budget they need is stated as a finding rather than reported as a pass.
  - _Measured 2026-09-17, PHP transfer NOT established._ All three comparisons exhausted a 3000-second deadline with a 1200-second query ceiling and produced no artifact, so there is no target evidence at all. The engine reports `cpg batch taint failed` twice per case on the 1,274-file PMPro tree: first an exception whose trace runs through ujson array transformation, then a timeout on the retry. Budgets tried: 900 s, 1200 s and 3000 s deadlines against 300 s and 1200 s query ceilings. Pins, source receipts and the declared target are all correct, so the question was asked properly and the engine could not answer it. This is a runtime blocker on a large repository, not evidence about whether the design transfers to PHP. Evidence: `benchmarks/measurements/2026-09-17-m3-php-transfer.json`.
  - _Two harness defects found and fixed on the way, each of which had made an earlier run look like a transfer failure:_ the manifest labels a case by what it is while the id says what the comparison does, and filtering on one while keying expectations by the other ran a single case; and the per-query ceiling is taken as the minimum with the remaining transaction time, so raising only the deadline could never have helped.
  - _Retried 2026-09-18 with batch splitting, still not established._ A batch that fails whole is now retried in eight parts, which a probe made look promising: the evidence pass answers all 4,425 PMPro regions in one batch in 29.7 s with a 681 KB response, and cost is fixed rather than per request, so neither count nor size is near a limit. That probe sent `evidenceOnly=true` and therefore measured the structural pass, not the failing one; recorded because those numbers would otherwise read as evidence that PMPro's taint work is cheap. With a 4500-second deadline and a 900-second query ceiling the run was stopped after 26 minutes with no case completed. Splitting also makes an unrecoverable batch slower to abandon, since each part burns its own share of the ceiling.
  - **Blocker still unidentified; investigation paused 2026-09-19 to return to vulnerability work.** Six hypotheses were measured and eliminated: batch size (17,700 requests answer in 44 s with a 2.6 MB response), dataflow cost (50 execution requests in 24 s), call depth 3 with parameter sources (24.7 s for 20), argument length (a 16 KB hook table against a 128 KB cap), hook callback resolution (1 s difference with 233 hooks), and build or sharding (79 s, no shards). Preparation measures 273.5 s. Every reproduction of the failing 22,125-request batch outside the push path answers in under a minute, and the difference from the production invocation is not known. The exception has never been read, because the backend logged a stack trace's tail and the corrected extractor reports its head, which on this engine is JVM startup noise. Evidence: `benchmarks/measurements/2026-09-19-php-blocker-open.json`.
  - _Boundary: Evaluation harness, full-run integration_
  - _Depends: 13.1_
  - _Requirements: 6.2, 6.3, 8.1, 8.2_

## Implementation Notes

- Task5.2 measured PMPro timing out after both snapshots were materialized but before change context/graph analysis. Group6 must account for compatible snapshot/discovery reuse as well as graph reuse; identical-tip hits cannot substitute for the later representative changed-code latency gate. No new detector, scope heuristic or incremental CPG mutation is implied.
- Cancellation must cover semantic planning and reporting, not only engine subprocesses: `_collect` and `_scope_work` now consume the shared deadline, and replay instantiates the budget-aware backend once. Preserve the 400-question failure-census and real Node artifact-retention regressions.

- Group 9 (M1a) corrected the owner diagnosis: all four named vetoes fire on the NodeGoat case, and a fifth, `operation_correspondence_unresolved`, is the actual remaining blocker because a newly introduced operation sits on a changed line and has no base anchor. The unchanged revision resolves its base location on the same lines and is classified `unchanged`, which isolates correspondence as the mechanism. M1b repairs context producers, question-owned vendor relevance, operation correspondence, file-wide ambiguity scope and query-to-operation provenance; vetoes that did not fire stay unchanged.

- Group 6: complete discovery/graph/query reuse is explicit via `--cache-dir`; source/declaration edits invalidate affected units. Installed frontend/adaptation bytes now bind graph and admission provenance. A valid cached census cannot qualify a fresh answer that omitted its own census. Identical-revision timing is not the changed-code rollout gate.
