# Product direction: a security safety net before push

Updated 2026-09-12 from the maintainer's explicit direction. This direction supersedes the
WordPress-first release framing in older steering; historical measurements remain historical.

## Purpose

AI accelerates code production. OpenUltraSAST should help developers catch concrete security
regressions before pushing, with enough evidence to understand and repair them. It is also a
teaching system for understanding what abstract analysis can establish and where it stops.

The maintainer's acceptance criterion is an actionable safety net, not a code nag. Advisory mode
does not lower the evidence bar. A nonblocking stream of speculative findings still fails the product.

## Product principles

- Make new or worsened security defects visible; do not repeatedly present unrelated backlog.
- Every normal hook alert needs a supported security claim, a connection to the proposed change,
  an exact location, and a concrete repair direction. A confidence label alone is insufficient.
- Keep suspicion and uncalibrated detector output in opt-in diagnostic artifacts.
- Separate finding disposition from coverage. An incomplete scan gets a concise operational notice,
  not a fabricated vulnerability or a clean verdict. Silence is bounded by the recorded scope.
- The ranker is the scope mechanism: it selects and orders the regions/questions receiving analysis.
  Change information supplies its context; there is no second heuristic scope selector in the hook.
  Ranking never establishes a defect or earns permission to alert.
- Third-party vendor code is excluded from both analysis targets and graphs. This is an explicit
  product boundary. Flows requiring its internals need declared summaries or remain unresolved;
  context expansion must not silently reintroduce vendor sources.
- Preserve vulnerability-family semantics: escaping for one context does not discharge another.
- Reuse results only when code, context, analysis semantics, and scope still match.
- A push deadline covers all work, including snapshot preparation, graph construction, retries,
  queries, optional model calls, and reporting. A region count is not a runtime bound.

## Scope and evidence

PMPro remains the primary worked example for core optimization. JavaScript/Node APIs, especially
Express routing and middleware, are a required transfer workload alongside Python; they must not
be deferred until a PHP-specific implementation has hardened. Polyglot repositories and common
injection, path, authorization, and configuration scenarios belong in the evaluation according to
demonstrated capabilities. Parsing a language does not imply support for its security properties.
C/C++ supplies an additional shared-machinery and abstraction-limit workload; C bounds/arithmetic
reasoning remains a separate abstraction question.

Language-agnostic analysis is an architectural requirement: frontends and versioned framework facts
map concrete code to shared sources, sinks, carried values, guards/obligations, configuration values
and evidence. Core ranking, scope selection and arbitration consume those contracts. No PMPro paths,
WordPress API names, Express method names or language-specific score boosts belong in core ranking.
Equivalent normalized evidence must produce equivalent core tier/score decisions. This is a contract
to verify, not an assumption that every frontend already produces equally complete graphs.

Optimize on PMPro, freeze the core, and measure transfer to Node/Express before further tuning.
Report changes needed in framework facts separately from core changes. Once an example informs a
change it becomes development/regression data; keep a separate untouched repository for evaluation.

Measure precision and actionability of alerts, recall on labeled security changes, fixed-side
silence, benign-push interruption rate, completed coverage, and cold/warm latency. Report sample
counts and uncertainty. More findings or a better rank position is not product success.

Keep the repeatedly inspected plugins as regression workloads. Evaluate new ranking or alert
policies on untouched repositories and benign changes as well. A policy that suppresses all alerts
does not pass: useful recall and coverage are required alongside low noise.

## Specification boundaries

- `pre-push-safety-net`: immutable pushed snapshots, ranker integration, reusable results, total budget,
  change attribution, actionability admission, and concise hook behavior.
- `contributor-scan`: reusable scan driver/backend, family correctness, packaging, repository validation.
- `flow-aware-ranking`: reusable scheduling of questions and honest ranking experiments.
- `zero-with-a-reason`: broader pipeline diagnostics; the hook consumes concrete coverage information.
- `finding-feedback-loop`: review ledger, dismissals, and later feedback-driven evolution.

The hook does not require an LLM ranker or an optimizer. Start with the existing detector, earn
alert admission per capability, and add scheduling sophistication only when it improves the measured
developer outcome. Do not rebuild a custom IR, add a second engine, or assume incremental Joern
updates as a shortcut to an unmeasured latency promise.

## Approval state

The product direction above is user-requested. The amended requirements, design and initial
evaluation profile in `pre-push-safety-net` were approved for task generation on 2026-09-12
("ok, next kiro phase"). The maintainer then approved the task plan and starting group 1
("approve.") and then group 2 ("ok, next kiro phase, approved"). Groups 1–7 are now
implemented, reviewed and verified (23/27), including the frontend-retention prerequisite
and the deadline regression exposed by full Node replay. Tasks 4.3 and groups 5–7 used the
explicit Kiro manual review fallback after the agent thread limit.

The first newly frozen PMPro/Node experiment is measured **NO-GO**: all six cold cases
timed out without completed supported target checks, while retaining all 11 declared cases.
The repaired CLI saved all artifacts and returned in 30.55–30.64 seconds. PMPro exhausted
the deadline in preparation/discovery before graph analysis, so compatible preparation
reuse matters alongside graph persistence. Group 6 now provides compatible local reuse; warm changed-code performance
and useful coverage remain mandatory later gates. No ranking/fact adaptation or holdout
inspection occurred in the final transfer run. Real capability eligibility and automatic
dominance context projection remain unproven; the installed capability registry is NO-GO with no enabled capabilities.

Group 6 verified equal cached/uncached evidence and current admission in a packaged authored
JavaScript control. Source/declaration edits invalidate affected units. Identical-revision
latency does not qualify representative changed-code performance. Requirements and rollout
thresholds remain unchanged; independent capability admission remains blocked in group 8. Group 7 adds exact multi-ref
transactions, explicit non-overwriting hook integration and bounded optional witness
selection. No model output can create evidence, raise a rung or bypass admission.


Group 8 validation (2026-09-13) is **NO-GO**. Tasks 8.1, 8.2 and 8.4 are verified;
26/27 tasks are complete. Task 8.3 remains blocked despite delivered eligibility
implementation and a reproducible installed NO-GO resource. All 21 representative
Node runtime transactions timed out (0/24 declared target checks complete); final
packaged PHP/Node security/fixed/benign replays likewise time out. VAmPI preserves
raw known findings and valid identical-comparison reuse, but exact target question
context/transitive evidence remains unresolved. Independent reviewed Node/PHP/Python
populations are missing; libpng arithmetic/bounds remains unsupported. No real capability
is enabled. Engine/census/context prerequisites route to contributor-scan before another
frozen qualification attempt. See `pre-push-safety-net/validation-group-8.md`.


On 2026-09-14, contributor-scan task 2.19 repaired the confirmed Gruntfile frontend
omission (real Node census 43/44 → 44/44) and the misleading empty-graph diagnostic.
Incomplete or unavailable census retains explicit coverage gaps and cannot complete
questions. Native PHP/JavaScript partition smoke and 1321 tests pass. Runtime/core
identity changed, so prior eligibility is stale and remains disabled. This repairs one
shared prerequisite; pre-push 8.3, runtime amortization, VAmPI context/transitive
evidence and independent qualification remain open. No ranker retune or rollout GO.

The 2026-09-14 post-census profile now verifies identical-tip reuse (18.521–18.874s,
two graph hits and 1,512 query hits per repeat), while all 18 other transactions time
out and 0/24 target checks complete. The separate local-session census experiment is
promising but does not qualify security queries or hook latency. The contributor-scan
`release-remediation-research.md` records missing family context producers, global
vendor/correspondence completeness vetoes, and query-to-operation identity as the next
shared-contract work. Resolving a boundary requires evidence of its relevance and scope;
do not simply drop completeness checks to increase admissions. Rollout remains NO-GO.
