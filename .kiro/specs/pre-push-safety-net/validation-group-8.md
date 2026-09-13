# Packaged acceptance validation — group 8

## Validation Report
- DECISION: NO-GO
- FEATURE_COMPLETE: false
- BLOCKED_TASKS: 8.3 — independent reviewed populations and verified VAmPI transitive evidence are missing; useful completion and runtime gates fail.
- OWNERSHIP: UPSTREAM for engine/census/context prerequisites; LOCAL for evaluation population and capability qualification.
- UPSTREAM_SPEC: contributor-scan; see `pre-push-runtime-followup.md` there.

This report distinguishes implemented safety contracts from demonstrated useful detection.
All 35 criteria below are mapped. A contract test does not qualify a language or framework,
and this report makes no rollout or production-readiness claim. Task 8.4 permits this
explicit NO-GO outcome; task 8.3 and the feature remain incomplete.

## Acceptance coverage

Paths in the evidence column refer to `tests/` unless otherwise indicated. Current
full-suite evidence covers the code at the group 8.3 implementation commit. Packaged
receipts below exercise the built release with its installed NO-GO registry.

| Criterion | Evidence | Assessment |
|---|---|---|
| 1.1 | `test_push_snapshot.py`, `test_push_interface.py`, `test_push_regression_integration.py` | Exact immutable comparisons/ref associations verified by controls. |
| 1.2 | Snapshot/integration tests; packaged disposable-hook smoke | Working source/index/refs and preceding hook preserved. |
| 1.3 | Snapshot and multi-ref tests | Delete/missing-base/unsupported dispositions remain explicit. |
| 1.4 | Snapshot/context tests | Comparison rules, force/new-branch/tag/rename identities retained. |
| 2.1 | Context/scope integration tests; real Node/VAmPI artifacts | Ranker owns selection; useful context incomplete on real workloads. |
| 2.2 | Scope, runner and failed-census controls | Omitted context is an explicit gap; real dynamic dependencies remain unresolved. |
| 2.3 | `test_push_regression_integration.py`, partition/backend tests | Physical first-party filtering verified; external semantics remain unresolved. |
| 2.4 | Removed-guard context/admission tests | Contract verified; real dominance context projection remains unqualified. |
| 3.1 | `test_push_admission.py`, `test_push_report.py`, `test_push_eligibility.py` | Actionability admission enforced; zero qualified real capabilities. |
| 3.2 | Admission/eligibility tests; installed NO-GO registry | Unreviewed/unsupported candidates do not become normal alerts. |
| 3.3 | Admission/report tests | Duplicate witness paths produce one defect summary. |
| 3.4 | Delta/admission/report tests; real same-snapshot VAmPI | Unchanged or unknown novelty cannot create a new-defect alert. |
| 3.5 | Model-assistance tests | Model selection cannot create evidence or change admission. |
| 4.1 | Execution-budget and multi-ref tests; real timeout receipts | Single absolute budget retained; useful completion gate fails. |
| 4.2 | Cancellation/publication controls and 21-case runtime profile | Partial artifacts retained; measured cancellation/report allowance below 2s. |
| 4.3 | Cache invalidation/reuse tests and packaged group 6 control | Exact input/context/semantic compatibility required. |
| 4.4 | Corrupt/partial/cache-failure controls | No partial or stale clean verdict reused. |
| 5.1 | Report/CLI tests and packaged output | Compact supported-scope status; no repository-security claim. |
| 5.2 | Timeout artifacts and report tests | Compact operational notice with next action/artifact, no per-file warning flood. |
| 5.3 | CLI/admission tests; packaged advisory/prior-hook smoke | Advisory permits push, preserves preceding rejection, same evidence bar. |
| 5.4 | Multi-ref/CLI policy tests | Blocking and incomplete-coverage policies separate; real blocking qualification absent. |
| 5.5 | Result contracts, artifact tests and real timeout artifacts | Finding/coverage/push disposition remain separate. |
| 6.1 | Input validator and frozen profiles | BLOCKED: independent Node/PHP/Python reviewed populations missing. |
| 6.2 | Versioned runtime/qualification scorecards | Counts, intervals, undefined precision, unresolved cases and latency retained; gates fail. |
| 6.3 | Scorer controls and real VAmPI replay | Missing target/question/transitive proof remains unresolved in denominator. |
| 6.4 | Frozen provenance receipts, deployed evidence ranking mode | No comparative ranker retune claimed; fixed core preserved across PHP/Node. |
| 6.5 | Eligibility recomputation and NO-GO decisions | Joint gates enforced; no runtime/quality qualification earned. |
| 7.1 | Packaged network-disabled no-model runs | No endpoint, engine download, source fetch or project build required by hook. |
| 7.2 | Explicit/delayed/misleading-model controls | Redaction, model provenance and shared budget verified on controlled path. |
| 7.3 | Full raw bundles, graph/query cache identity tests | Input, selected/deferred questions, outcomes, exclusions and stage identities retained. |
| 7.4 | Hook tests; packaged installer/refusal/removal smoke | Explicit integration preserves hooks and configuration. |
| 8.1 | Equivalent-normalized-evidence ranking/admission controls | Shared core rules; no PHP/Node priority exceptions introduced. |
| 8.2 | Runtime smoke and missing-census controls; real Node/VAmPI gaps | Missing frontend/context evidence is not interpreted as safe. |
| 8.3 | Frozen six-case packaged PHP/Node profiles | Transfer attempted unchanged; all 30s cases time out. Useful transfer unproven. |
| 8.4 | Separate development/regression/envelope profiles | No core/fact/adapter retune; libpng arithmetic/bounds unsupported; no C++ detection claim. |

## Integration and boundary assessment

The implemented route remains Snapshot Adapter → ranker-owned scope → existing scan
engine/cache → delta/actionability admission → report/hook. Persistent eligibility
is a trusted installed input to the actionability boundary. It recomputes the existing
evaluation scorer and checks exact semantics; repository configuration and optional
models cannot supply eligibility. Immutable graph leases and answer compatibility are
kept separate from change attribution. No incremental graph mutation, second engine,
new IR, rank boost or downstream detector workaround was introduced in group 8.

Concrete remaining gaps are engine lifecycle/census completeness and context/witness
projection, not evidence that a new ranker would solve the measured failure. Shared
scan changes belong to contributor-scan and must trigger downstream replay revalidation.
The file structure extends the approved evaluation/admission boundary with
`push/eligibility.py` and its installed JSON resource. Ordinary scan behavior remains
covered by the full suite and canonical detector/map/pair gates.

## Required next work

1. In contributor-scan, reconcile named readable first-party files with the Node graph
   census, then measure/amortize frontend, overlay, census and query process startup.
   Preserve vendor exclusion and complete/corrupt cache distinctions.
2. Resolve supported first-party context and retain actual query-origin/path witnesses.
   Reproduce the three VAmPI targets with exact question accounting; a raw SQLI finding
   does not establish transitive reachability or push attribution.
3. Freeze independently reviewed Node API vulnerable/fixed/benign cases with the required
   middleware/module/async shapes; obtain separate PHP/Python qualification populations.
   Do not tune on reserved Ghost before its population is fixed.
4. Refreeze the candidate after owner fixes and rerun all seven runtime workload classes,
   cross-language regressions and independent actionable-alert review. Require the
   unchanged 30s warm p95, 2s cancellation allowance, 95% completion/observed precision,
   90% supported recall and zero known fixed/benign false alerts together.
5. Regenerate eligibility only for exact passing language/framework/family semantics,
   then rerun packaged validation. Keep normal capabilities disabled until then.

## Fresh verification evidence

- Full suite: `pytest -q`, **1317 passed, 9 skipped**, 115.80s, exit 0. No production
  source changed after this run; subsequent edits are validation tooling and records.
- Ruff check and formatting pass (262 files); mypy passes (116 source files);
  compileall exits 0. No new placeholder markers or concrete secrets in reviewed code.
- Detection regression gate: 44/47 recall, 0/44 false positives, PASS. Map gate: PASS.
  Local pair gate: 3/3 pair-correct, 28/28 labeled recall, no fixed-side leaks, PASS.
  These corpus controls do not qualify real pre-push language/framework capabilities.
- Docker build exits 0, image
  `4cca6d20c5c9bfdbfa60c4e8fc991e096bc9b2f35096bb92cc92440e99f946d4`.
- Packaged offline smoke exits 0 as UID 1000. Installed registry recomputes as NO-GO,
  zero enabled capabilities. Both real disposable hook acceptance/rejection and removal
  controls pass; exact stdin/remote args and prior state are verified.
- Final packaged six-case PHP/Node replay completes its instrument with exit 1 and
  an explicit NO-GO decision. All underlying advisory CLI invocations exit 0 and save
  partial artifacts; all six time out in 30.560–30.614s. Every snapshot has positive
  byte receipts. No target check or real actionable alert is qualified. Preparation
  timeout provenance remains unavailable where it was not measured.
- Versioned record: `benchmarks/measurements/2026-09-13-push-packaged-validation.json`.
  Its 38-file raw bundle is 827,483 bytes, SHA-256
  `ad1bc15791636868a65a5cbb93b84d1a08dc6c94be0eb2f8f03890936720cc79`.
  Decompression matches every retained original. Full logs, smoke artifacts, profile,
  replay pins, scorecard and six complete partial-result artifacts are included.

## Verification Result
- STATUS: NOT_VERIFIED
- CLAIM_TYPE: FEATURE_GO
- CLAIM: Pre-push safety net ready for rollout.
- EVIDENCE: Passing integration controls coexist with measured runtime/completion failures and missing quality prerequisites.
- GAPS: Task 8.3 qualification; real independent positive/fixed/benign evidence; verified VAmPI transitive witness; useful changed-code latency and coverage.
- NOTES: Keep the feature in implementation and capabilities disabled. Follow owner remediation above, then rerun qualification and packaged validation.
