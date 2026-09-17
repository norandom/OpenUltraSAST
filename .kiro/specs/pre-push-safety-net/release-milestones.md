# Release milestones: prove usefulness, then speed and transfer

Accepted direction: 2026-09-14. The maintainer agreed to the five-step path and asked
for it to be recorded in the roadmap as a spec. This amendment defines the order and
observable exit criteria for the remaining release work within pre-push-safety-net.
It preserves the approved requirements, completed tasks and existing owner boundaries.
It does not approve an unreviewed implementation design or enable any capability.

## Current position

**Next milestone: M1b. M1a is met; none of M1–M5 is verified yet.** The 28/29 completed
executable tasks measure implementation progress, not release readiness. Task 8.3 remains blocked.
The published `v1.2.0-alpha.1` is an experimental implementation release, not a qualified
advisory rollout. See [current status](status.md) for measured evidence and limitations.

The immediate goal is one real changed-code defect, a defensible explanation, and a
fixed twin that stays quiet. M1a first shows the raw detection with every admission veto
recorded rather than applied; M1b repairs only the vetoes that fired. A longer, explicitly
named development budget is acceptable for M1; it cannot satisfy the hook's latency gate.
Runtime optimization is the next milestone after this useful result is demonstrated.

## M1 — One real security change works end to end

Status: **NEXT — not verified**. Dependencies: existing immutable replay and scan machinery.
M1 is split into M1a (diagnose with vetoes recorded, not applied) and M1b (repair only
the vetoes M1a showed to matter). M1 is verified only when M1b passes.

Why the split: the detector already reports the NodeGoat contribution injection. The
2026-09-14 post-census bundle carries the raw `<lambda>2` witness at contributions.js
lines 32–34, and the same bundle carries thousands of `context_incomplete`,
`graph_incomplete`, `vendor_semantics_unresolved` and `ambiguous_line_correspondence`
reasons that discard it before any developer sees it. Four independent admission vetoes
are known: no context producer for dominance/config families, vendor exclusion acting as
a global completion veto, line ambiguity inherited by every question, and query identity
differing from witness identity. Requiring all four repaired before the first visible
result is a full production pass, not one detection.

### M1a — Show the detection with every veto recorded

Status: **MET 2026-09-16**, inside its one-week box. Evidence:
[M1a record](m1a-recorded-vetoes.md) and
[measurement](../../../benchmarks/measurements/2026-09-16-nodegoat-m1a-recorded-vetoes.json).
Raw witnesses present at contributions.js lines 32–34; fixed twin analyzed and quiet with
zero rows and no deadline reason; unchanged revision analyzed and recorded `unchanged`. The
kill criterion did not trigger. Five vetoes fired and were recorded, and M1a corrected the
diagnosis: with all five lifted the detection stops at `operation_correspondence_unresolved`,
a fifth veto that was not previously named. No defect was admitted and no capability enabled.

- Use the pinned NodeGoat contribution injection case, its fixed twin and an unchanged
  vulnerable revision as development data. Record exact base/head revisions, expected
  operation and outcome before running. Exercise the shipped replay path, existing ranker
  and physically vendor-free graph; do not substitute a hand-selected slice or hard-coded
  target function.
- Run all three revisions under an explicit experimental evaluation flag that **records**
  each admission and comparison veto per finding instead of applying it. The flag is
  task-local, off by default, cannot enable any hook capability, and every output it
  produces is labeled experimental. A longer, explicitly named development budget applies;
  it cannot satisfy the hook's latency gate.
- Deliverable: the raw finding on the vulnerable revision with location and witness, the
  fixed twin genuinely analyzed and quiet, the unchanged revision not reported as a new
  regression, and for every finding the exact list of vetoes that fired and why. Silence
  from failure is not a pass; a fixed twin that timed out or was not analyzed fails M1a.

**Exit evidence:** a replayable three-revision record under the experimental flag with
exact revision, question and operation provenance, the per-finding veto list, and readable
source and census receipts. **Kill criterion:** if the fixed twin is not quiet under the
recorded-veto run, M1 has a detector problem, and M1b does not start until that is
diagnosed and recorded.

### M1b — Repair only the vetoes M1a showed to matter

Status: **NEXT — not verified**. M1a supplied the veto list: per-family change context,
question-owned vendor relevance, operation correspondence for an operation on a changed line,
file-wide correspondence ambiguity scope, and query-to-operation provenance. The owner
diagnosis expected the first and the last two; operation correspondence is the addition M1a
measured and is the blocker that survives every other repair.

- From the M1a veto list, repair only the context/family/identity contracts this case
  actually needs. The owner diagnosis expects query-to-operation provenance and question-
  owned vendor relevance to be the two that fire here; M1a confirms or corrects that.
  Vetoes that did not fire on this case stay as they are and their families stay
  experimental. Resolve vendor and correspondence boundaries through evidence of dependency
  and ownership; unknown relevance remains unresolved.
- Rerun the three revisions **without** the recorded-veto flag through the production
  evidence and comparison rules. Demonstrate a developer-readable evaluation finding with a
  supported security consequence, exact location, witness, change attribution and concrete
  repair direction. Verify the fixed twin is analyzed and produces no actionable defect, and
  the unchanged vulnerable revision is not reported as a new regression.
- Keep qualification eligibility disabled. The demonstration uses explicit experimental
  evaluation output; it cannot advertise an unqualified normal hook alert.

**Exit evidence:** a replayable vulnerable/fixed/unchanged comparison record through the
production rules, exact question and operation provenance, completed required checks,
reviewed explanation, readable source and census receipts, task-local regression
verification, and a list of which vetoes were repaired and which remain. Raw findings, rank
positions, synthetic-only controls and screenshots alone do not satisfy M1b.

Owners: contributor-scan for query/operation/context evidence; pre-push-safety-net for
comparison, admission, the recorded-veto flag and reporting. Requirements: 1.1–1.4,
2.1–2.4, 3.1–3.5, 6.3, 7.1–7.3.

## M2 — The same useful analysis fits the push budget

Status: **MEASURED AND UNMET, 2026-09-17.** Two attacks on engine startup were measured and
neither reaches the gate. A transaction-owned session is implemented and proven equivalent for
every shipped query kind, and it amortizes startup only across a long transaction: 326 s to 243 s
under a development budget, while under the 30-second deadline its own 9 to 13 second startup
means it usually declines to start. Removing JavaScript's redundant second engine start is a real
11.0 s against 21.0 s on identical graphs, but the attempt was reverted for an asymmetric census
gate that made 12 profile transactions pay two engine starts.

The profile names the actual cost: a changed-code transaction reaches its deadline inside the
build, head build 25.2 s of 30 s with query time 0.0 s. It is building a fresh whole-repository
graph for every pushed revision.

**Direction accepted 2026-09-17: do not rebuild a whole graph per push. Reuse the graph across
revisions instead of further optimising the rebuild.** The 30-second and 2-second gates are
unchanged; this milestone is not met, and the work is not scheduled here.

- Use the successful M1 case as a correctness baseline for a transaction-owned Joern
  session within the existing backend. The measured census probe supports investigating
  this design; it does not establish full-query equivalence or production readiness.
- Verify equivalent taint, dominance and configuration answers under matching semantics,
  fresh request receipts, isolated graph identities, cache invalidation, crash handling
  and process-group cancellation. Keep one deadline across the complete transaction.
- Rerun the frozen seven-class runtime profile with changed-code cases, cold starts,
  dependency/configuration edits, growth and multi-ref transactions. Retain all timeouts
  and unresolved checks. Identical-tip reuse cannot substitute for warm changed-code work.

**Exit evidence:** the M1 outcome remains correct; representative warm changed-code p95
is at most 30 seconds, cancellation/reporting at most two seconds, and supported-check
completion at least 95%, under the predeclared profile. A fast census alone does not pass.

Owner: contributor-scan runtime, with pre-push-safety-net deadline/cache integration.
Requirements: 4.1–4.4, 6.2–6.5, 7.3.

## M3 — The shared design transfers across languages

Status: **PARTIAL, 2026-09-17. Not met.** Python is established and PHP is blocked by runtime.

Python: all three declared VAmPI targets detected at their declared lines with their questions
answered, 35 of 35 questions complete on every case, nothing reported new on identical revisions,
zero admitted defects. That includes the SQL injection this spec names as previously unresolved,
and both broken-object-level-authorization targets, which is the first time access control has
answered on Python at all.

PHP: not established. All three PMPro comparisons exhausted a 3000-second deadline with a
1200-second query ceiling and produced no artifact, so there is no target evidence. The taint
batch fails on the 1,274-file tree, first with an engine exception and then by timeout. The pins,
receipts and declared target are correct, so this is a runtime blocker on a large repository
rather than evidence about whether the design transfers.

The exit asks for Node, PHP and Python together. Two of three are in hand.

- Repeat the useful vulnerable/fixed comparisons with PMPro/PHP and VAmPI/Python,
  including the previously unresolved VAmPI SQLI query/path evidence. Preserve explicit
  limits for authorization and other families whose evidence is still unsupported.
- Keep framework knowledge in frontends/adapters and versioned facts. Equivalent normalized
  evidence must retain the same core ranking, scope and admission behavior.
- Record core and adapter changes separately. Any PMPro-driven core change must be frozen
  and replayed on Node/Express before claiming transfer; the initial Node-first repair
  does not remove that existing requirement.

**Exit evidence:** reviewed development/regression results for Node, PHP and Python,
including positive, fixed and unchanged controls, exact provenance, coverage and runtime.
Do not label these repeatedly inspected projects independent qualification. C/C++ bounds
remain a separate unsupported abstraction; adding a new engine is not a prerequisite here.

Owners: contributor-scan shared evidence and framework adapters; pre-push-safety-net evaluation.
Requirements: 6.2–6.4, 8.1–8.4.

## M4 — Independent examples establish useful detection and low noise

Status: **PENDING M3**. Population preparation may proceed earlier, but evaluation follows
the frozen candidate. Reserve untouched cases before examining their scan results.

- Freeze reviewed vulnerable, fixed and benign changes from projects not used to develop
  or tune the particular language/framework/family. Ghost remains reserved until its
  actual reviewed population exists. Node evidence cannot qualify PHP or Python.
- Measure actual actionable alerts, supported recall, fixed-side silence, benign interruptions,
  completed coverage and runtime together, with counts and uncertainty. Keep unlocated
  targets, unanswered queries and unsupported cases visible in their declared populations.
- Apply the existing acceptance profile: at least 95% observed actionable precision,
  at least 90% supported recall, at least 95% supported-check completion, the 30s/2s runtime
  gates, nonzero reviewed emitted alerts and positive controls, and zero known fixed/benign
  false alerts. Silence on everything fails. A core retune requires new untouched evaluation.

**Exit evidence:** reproducible, reviewed per-capability qualification with every mandatory
gate passing together. Report failures honestly and leave those capabilities experimental;
do not require every possible language or family to become eligible for a narrow release.

Owner: pre-push-safety-net task 8.3, consuming verified contributor-scan semantics.
Requirements: 6.1–6.5, 8.1–8.4 and the accepted experimental acceptance profile.

## M5 — Enable a narrow advisory rollout

Status: **PENDING M4**.

- Generate eligibility bound to the exact passing runtime, query, fact, ranking and policy
  identities. Enable only independently qualified capabilities; stale or missing evidence
  enables none. Advisory retains the same evidence bar as blocking.
- Revalidate the packaged vulnerable/fixed/benign push experience, compact reporting,
  truthful incomplete coverage, local no-model operation and preservation/removal of hooks.
- Publish the supported scope, limitations and evidence with the advisory release.
  Expand capabilities only when they earn qualification. Blocking deployment is a later,
  explicit decision, even though opt-in blocking plumbing already exists.

**Exit evidence:** passing packaged acceptance validation and exact eligibility for the
declared advisory scope, with the release decision recorded. Only then mark task 8.3
and release readiness complete if their mandatory criteria are satisfied.

Owner: pre-push-safety-net admission, packaging and release validation.
Requirements: 3.1–3.5, 5.1–5.5, 6.5, 7.1–7.4.

## Execution and reporting contract

Use M1a → M1b → M2 → M3 → M4 → M5 as the critical path. Preparation may overlap, but later
milestones cannot substitute for missing earlier evidence. Necessary runtime repairs
that make M1 executable are allowed; a standalone speed benchmark cannot close M1.
Keep ranker-owned scope, vendor exclusion, language-agnostic core behavior and all
acceptance thresholds unchanged. No new source IR, second detector, differential graph
mutation, learned ranker or unrelated backlog is introduced by this amendment.

Before production edits, make the required owner design/task amendment concrete and
apply the existing Kiro approval, review and verification workflow. Prior authorizations
remain valid within their scope; this milestone record does not reset them.

Progress updates shall lead with the current milestone, observed developer outcome,
remaining blocker and next concrete action. Report implementation task counts separately.
Change a milestone to verified only with linked evidence; do not infer progress from
elapsed effort or a completed experimental release tag.

Immediate next action (M1b): repair the five vetoes M1a recorded, smallest first, starting
with operation correspondence for an operation on a changed line, since that one survives
every other repair. Then rerun the same three revisions without the flag through the
production evidence and comparison rules. Use
[M1a evidence](m1a-recorded-vetoes.md) and
[remediation research](../contributor-scan/release-remediation-research.md) as the starting
record; do not begin another broad timing campaign before the M1 outcome exists.
