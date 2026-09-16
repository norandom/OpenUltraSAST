# M1a evidence: the NodeGoat detection with every veto recorded

Run date 2026-09-16. Milestone **M1a** of [release-milestones.md](release-milestones.md).
Instrument `benchmarks/push/m1a_record_vetoes.py`; flag `--experimental-record-vetoes`.
Evidence: [summary](../../../benchmarks/measurements/2026-09-16-nodegoat-m1a-recorded-vetoes.json)
and its 11-file [bundle](../../../benchmarks/measurements/2026-09-16-nodegoat-m1a-recorded-vetoes.json.gz).

This record diagnoses. It admits no defect, enables no capability, qualifies no language and
makes no latency claim. All three artifacts report `finding_status: none` with zero admitted
defects; every recorded section carries its experimental label.

## What was declared before running

Expected base/head pins, expected operation and expected outcome for all three comparisons
were written to `m1a-record.json` before the first scan. The declared target is
`app/routes/contributions.js`, `handleContributionsUpdate`, family `injection`, lines 32–34.

| Case | Base | Head | Declared expectation |
|---|---|---|---|
| nodegoat-introduce | fixed `0b453d5a` | vulnerable `c5cb68a7` | raw finding at the three eval lines, recorded novelty new |
| nodegoat-repair | vulnerable `c5cb68a7` | fixed `0b453d5a` | fixed twin analyzed and quiet; three base-only findings |
| nodegoat-benign | vulnerable `c5cb68a7` | benign `f772c59e` | backlog unchanged; never new or worsened |

Each revision's target file was reopened before the run: 2,485, 2,491 and 2,498 bytes with
recorded SHA-256 digests. Each head scan reported a complete 44-file JavaScript census.
Installed engine, facts, query, policy, core and semantics provenance matched the frozen
values in all three artifacts.

## Observed outcome

| Case | Elapsed | Target findings | Target question answered | Deadline reached |
|---|---:|---:|---|---|
| nodegoat-introduce | 349.8 s | 3 | yes, 9 rows | no |
| nodegoat-repair | 153.8 s | 0 | yes, 0 rows | no |
| nodegoat-benign | 261.4 s | 3 | yes | no |

All three ran under an explicitly named 900-second development budget. These durations are
development measurements and cannot satisfy or measure the 30-second hook latency gate.

Verdict recorded by the instrument: raw witness present, fixed twin quiet, unchanged revision
not reported as a new regression, recorded evaluation produced for all three. The milestone's
**kill criterion did not trigger**: the fixed twin was genuinely analyzed, answering its target
question with zero rows and no deadline reason, while the same three findings appear on its
base side as base-only findings. Silence from failure was not accepted as a pass.

## The vetoes that actually fired

Identical for each of the three `eval` witnesses on the vulnerable revision. Five recognized
vetoes fired and were recorded rather than applied:

| Stage | Veto | Evidence |
|---|---|---|
| head question | `change_context_incomplete` | the answered target question carried 9 rows and was then demoted |
| head scan | `dynamic_external_or_depth_context_unresolved` | on the target's own question identity, not an unrelated one |
| head scan | `vendor_semantics_unresolved` | recorded both as a degradation and as a scope boundary |
| base scan | `graph_incomplete` | the base question answered with 0 rows and was then demoted |
| change context | `ambiguous_line_correspondence` | file-level, on the target file |

The earlier owner diagnosis named four independent vetoes and expected query-to-operation
provenance and question-owned vendor relevance to be the two that mattered. Both fired. The
run also confirms the third and fourth, so all four named vetoes are real on this case.

## What M1a corrected in the diagnosis

**A fifth veto is the actual remaining blocker.** With all five recognized vetoes lifted, the
detection does not become new. Its reason advances from `witness_identity_unresolved` to
`operation_correspondence_unresolved`, because the head operation sits on a changed line and
therefore has no base line anchor. The comparison can classify an operation only when it maps
to a base location.

The unchanged revision proves this is the mechanism rather than a coincidence. Its comment-only
edit leaves lines 32–34 unchanged, the base location resolves to the same lines, and the
recorded novelty becomes `unchanged` / `same_supported_mechanism`. Same evidence, same policy,
opposite correspondence outcome:

| Revision | Operation line | Base location | Recorded novelty |
|---|---|---|---|
| vulnerable | changed | unresolved | unknown, `operation_correspondence_unresolved` |
| unchanged | unchanged | resolved to the same line | unchanged, `same_supported_mechanism` |

**Query identity differs from witness identity, as predicted.** The target is selected through a
file-fallback question with `function=None`, while the rows report method `<lambda>2` at lines
32–34. The declared benchmark function is `handleContributionsUpdate`. This is recorded, not
applied: it is why production reported `witness_identity_unresolved` before any lifting, since
an unresolved question yields no comparable operation at all.

**Admission reasons that no flag can remove.** `capability_unavailable` remains on every
candidate because the registry is empty and this flag cannot enable a capability.
`dependency_unresolved` remains because unlifted coverage reasons still reach admission.

## What M1b must repair, ordered by this evidence

1. **Authentic per-family change context.** `change_context_incomplete` demoted every answered
   question in all three cases. Dominance and configuration questions need their own context
   producers describing their actual query scope; taint context must not be copied into them.
2. **Question-owned vendor relevance.** `vendor_semantics_unresolved` turned an otherwise
   complete 44-file first-party census into `graph_incomplete` on every base question. Keep the
   exclusion physical; establish which question actually requires excluded semantics.
3. **Operation correspondence for changed lines.** The blocker M1a surfaced. Bind the required
   base/head correspondence to the specific operation rather than to a line anchor, with absent,
   renamed, removed-guard and ambiguous-operation controls. Do not delete the ambiguity check
   and do not treat lexical alignment as semantic proof.
4. **Correspondence ambiguity scoped to its file region.** `ambiguous_line_correspondence` is
   recorded file-wide and inherited by every question, including uniquely mapped operations.
5. **Query-to-operation provenance.** Carry verified provenance from the selected question to the
   reported operation. Do not inject benchmark function names into regions.

Vetoes that did not fire on this case stay as they are and their families stay experimental.

## Limits

Three comparisons on one inspected teaching repository. NodeGoat is development and transfer
data; it cannot qualify production Node support, and Node evidence cannot qualify PHP or Python.
The lifted view is a diagnostic reconstruction, not a comparison result: it shows what the
existing evidence would support if those vetoes were repaired, and no repair has been made.
Runtime, independent qualification and rollout all remain NO-GO.

## M1b step 1: what the first three repairs changed

Rerun 2026-09-16 after tasks 10.1–10.3, same instrument, same pins, same budget.
Evidence: [summary](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-step1.json)
and its [bundle](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-step1.json.gz).

The recorded view now classifies the case correctly. The vulnerable revision reaches
`new` / `operation_absent_from_comparable_base`, and the unchanged revision reaches
`unchanged` / `same_supported_mechanism` with its base location resolved to the same lines.
Before the repairs both stopped at `operation_correspondence_unresolved` and
`witness_identity_unresolved`.

| Revision | Before 10.1–10.3 | After 10.1–10.3 |
|---|---|---|
| vulnerable | unknown, `operation_correspondence_unresolved` | new, `operation_absent_from_comparable_base` |
| unchanged | unknown, `witness_identity_unresolved` | unchanged, `same_supported_mechanism` |

The rerun also caught a defect in the repair itself: the new novelty reason was missing from
the admission allowlist, so admission rejected the candidate as `change_unsupported`. Fixed
with a control.

The production path is unchanged so far, because two vetoes still demote the target
questions: `change_context_incomplete` on the head from the question's own
`dynamic_external_or_depth_context_unresolved`, and `graph_incomplete` on the base from the
vendor exclusion.

## Why the last two vetoes need new query evidence

Neither remaining veto can be scoped or relaxed soundly as the plan originally described,
and the rerun is what showed it.

A taint answer reports traced flows. An absent row therefore means either that the operation
does not exist in the base, or that it exists and no traced flow reached it.
`dynamic_external_or_depth_context_unresolved` exists precisely to stop the second being read
as the first. Removing or narrowing it would let an unreached operation look absent, which
turns a wrong absence into a wrong new finding: the false-positive direction this project
cannot afford.

At the same time the flag carries no discrimination. It is computed over every in-scope
method, and on any real Express application ordinary framework and dependency calls have
unresolved destinations, so it is always true and can never be discharged. A veto that is
always on and can never be lifted is why the tool reports nothing on real projects.

The resolution is neither to keep it nor to drop it, but to supply the evidence that makes
absence provable independently of reachability: export the operations the query actually
enumerated in the question's scope, separately from the flows it traced. Absence is then
established from the inventory, while a traced-flow claim still requires complete
reachability. Vendor exclusion can then stop acting as a global completion veto for the same
reason, since dependency on excluded code becomes visible in the evidence rather than assumed.

That prerequisite is now task 10.4, ahead of the two vetoes it unblocks. It adds no detector,
alias resolver or second source IR.

## M1b outcome: the same case through the production rules

Rerun 2026-09-16 after tasks 10.1 to 10.6, same instrument, same pins, same budget.
Evidence: [summary](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-production.json)
and its [bundle](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-production.json.gz).

The production comparison now classifies all three revisions without any lifting, and its
verdicts match the recorded view exactly. That match is the point: the vetoes M1a recorded
were repaired rather than bypassed.

| Revision | Production verdict | Recorded verdict |
|---|---|---|
| vulnerable | new, `operation_absent_from_comparable_base` | identical |
| fixed twin | quiet, analyzed, three base-only findings | identical |
| unchanged | unchanged, `same_supported_mechanism` | identical |

Compared with M1a, where production reported `witness_identity_unresolved` on every finding
and every one of the 436 questions was demoted on both sides.

The head target questions now complete, the base scan completes all 436 questions, and the
three `eval` witnesses at contributions.js lines 32 to 34 are attributed to the change that
introduced them. Timings were 325.7 s, 158.9 s and 260.3 s under the named 900-second
development budget, which measures nothing about the hook gate.

All three artifacts still report `finding_status: none` with zero admitted defects. Admission
rejects on `capability_unavailable`, which is the deliberate eligibility gate, and on
`dependency_unresolved`, which is a coarse plumbing defect recorded as its own task: the runner
passes every coverage reason as every candidate's dependency gaps rather than the gaps that
pertain to that candidate. Neither is a comparison failure.

### What each repair contributed, measured

1. **10.1 operation correspondence.** Moved the vulnerable revision from
   `operation_correspondence_unresolved` to a classifiable operation.
2. **10.2 required comparison scope.** Stopped unrelated unsupported families from blocking a
   complete target comparison.
3. **10.3 ambiguity scoping.** Stopped one file's repeated unchanged lines invalidating every
   question in the repository.
4. **10.4 operation inventory.** Made absence provable from enumeration rather than from the
   absence of a traced flow, which is what let 10.5 and 10.6 be done soundly.
5. **10.5 reachability binding.** Let the head questions complete, since bounded reachability
   cannot invalidate a flow that was traced.
6. **10.6 declared exclusion.** Let the base scan's 436 answers stand, since excluding
   dependencies is a scope choice rather than a failed read.

A seventh change was needed after the first rerun: the same exclusion and ambiguity distinction
was still missing inside the comparison's own degradation and boundary checks, so the verdict
stayed at `head_context_incomplete` even once both scans completed. The rerun is what surfaced
it, not the unit suite.

### Limits

Three comparisons on one inspected teaching repository, under a development budget. NodeGoat is
development and transfer data: it cannot qualify production Node support, and Node evidence
cannot qualify PHP or Python. No capability is enabled, no defect is admitted, no alert is
emitted, and no latency claim is made. Runtime, independent qualification and rollout all
remain NO-GO.

## M1b exit run (tasks 10.1 to 10.8)

Rerun 2026-09-16 after every repair, same instrument, same pins, same 900-second development
budget. Evidence: [summary](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-exit.json)
and its [bundle](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-exit.json.gz).

| Revision | Verdict | Admission | Elapsed |
|---|---|---|---:|
| vulnerable | all three sites new, `operation_absent_from_comparable_base` | `capability_unavailable` only | 326.4 s |
| fixed twin | analyzed and quiet, three base-only findings | none to admit | 157.8 s |
| unchanged | all three sites `unchanged`, `same_supported_mechanism` | `capability_unavailable`, `unchanged` | 256.8 s |

The vulnerable revision's only remaining admission reason is the deliberate eligibility gate.
`dependency_unresolved` is gone, which verifies task 10.7 on real data: those gaps belonged to
unrelated questions.

Each finding now carries its provenance explicitly: question function `None`, engine method
`<lambda>2`, witness `eval(req.body.preTax) -> const preTax = eval(req.body.preTax)` at
contributions.js line 32, and likewise for lines 33 and 34. The unchanged revision resolves each
base location to the same line, which is why it reads `unchanged` rather than new.

Source receipts were reopened before the run, and the head census is the complete 44 files.

### Which vetoes were repaired and which remain

All five vetoes M1a recorded are repaired, plus two the repairs exposed:

| Veto | State |
|---|---|
| `change_context_incomplete` on the target question | repaired, question completes |
| `graph_incomplete` on the base from vendor exclusion | repaired, all 436 base questions complete |
| `ambiguous_line_correspondence` inherited repository-wide | repaired, decided per operation |
| `dynamic_external_or_depth_context_unresolved` as a blanket veto | repaired, bound to reachability claims |
| `operation_correspondence_unresolved` on a changed line | repaired via the enumerated inventory |
| comparison's own degradation and boundary checks | repaired after the first rerun exposed them |
| `dependency_unresolved` on every candidate | repaired, gaps attributed per candidate |

What remains, recorded rather than repaired, because each is outside this case or a later
milestone:

- 231 of 436 head questions still report `change_context_incomplete`, from
  `context_projection_unavailable` and `context_scope_empty` on families whose queries export no
  context. Those are dominance and configuration questions. They did not block this case and
  their families stay experimental, so per the milestone they stay as they are.
- The vendor exclusion and the file's correspondence ambiguity remain reported in coverage. That
  is intended: they are recorded limits, not repaired absences.

### What M1b has not yet demonstrated

The milestone also asks for a developer-readable evaluation finding carrying a supported
security consequence and a concrete repair direction. Those two come from an evaluated
capability declaration, and the registry is deliberately empty, so nothing renders them today.
Writing that text without a declaration is precisely what admission exists to prevent, so it is
not something to work around here. The comparison half of M1b is verified; the explanation half
waits on a declaration, which is M4's subject.

### Limits

Three comparisons on one inspected teaching repository under a development budget. NodeGoat is
development and transfer data: it cannot qualify production Node support, and Node evidence
cannot qualify PHP or Python. No capability is enabled, no defect is admitted, no alert is
emitted and no latency claim is made. Runtime, independent qualification and rollout all remain
NO-GO.

## M1b explanation: the finding as a developer would read it

Run 2026-09-16 after task 10.10, same pins and budget, with an unreviewed experimental
declaration generated by the instrument and bound to the run's own analysis semantics.
Evidence: [summary](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-explained.json)
and its [bundle](../../../benchmarks/measurements/2026-09-16-nodegoat-m1b-explained.json.gz).

Three evaluation findings were rendered on the vulnerable revision, one per eval site. For
line 32:

- **Location** app/routes/contributions.js:32, family injection, novelty new with
  `operation_absent_from_comparable_base`.
- **Witness** `eval(req.body.preTax) -> const preTax = eval(req.body.preTax)`.
- **Change attribution** `base:app/routes/contributions.js:32-34`.
- **Provenance** `file_scope`: the question named no function, the engine reported `<lambda>2`.
- **Consequence** "A request field reaches const preTax = eval(req.body.preTax), where it is
  evaluated as JavaScript, so an attacker controlling that field can execute arbitrary code in
  the server process."
- **Repair** "Replace the evaluation at const preTax = eval(req.body.preTax) with a numeric
  conversion such as Number(...) or parseInt(...), then validate the result before use."

Both sentences come from the declaration's templates through the grounded-template path, not from
generated prose. The declaration reports verdict `experimental` and `enabled: false`, the
production result still reports `finding_status: none`, and all three artifacts carry zero
admitted defects. The rendering path never reaches admission, so no supplied declaration can
change that.

### A defect this surfaced, recorded not repaired

The operation symbol admission extracts is the text before the first parenthesis, which for
`const preTax = eval(req.body.preTax)` is `const preTax = eval`, not `eval`. The demonstration
declaration had to enumerate each assignment spelling for its coverage check to pass. A real
qualified declaration cannot enumerate every assignment a codebase might write, so admission
would reject genuine findings on `operation_semantics_mismatch`. That is recorded as its own task
ahead of M4; it is not worked around here.

M1b is met: the comparison classifies all three revisions through the production rules, and the
finding reads as a developer would need it to, with every claim traceable to its evidence.
