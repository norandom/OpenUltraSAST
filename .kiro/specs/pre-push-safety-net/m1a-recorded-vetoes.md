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
