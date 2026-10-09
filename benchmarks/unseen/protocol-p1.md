# Pool p1: frozen scoring protocol

This protocol fixes the scoring, uncertainty estimates and adoption gate before any
p1 replay. Its authority is the approved
[unseen-repo-evaluation design](../../.kiro/specs/unseen-repo-evaluation/design.md),
sections 3, 4 and 7 (including decisions 4.0, 4.0a and 7.3). The freeze record binds
these exact UTF-8 file bytes by `protocol_digest`. Corrections require a new pool;
neither p1 nor this protocol is revised in response to results.

## Population, slices and use

Design section 3 fixes three seeded, ecosystem- and `post_cutoff`-stratified slices
of 100 repositories: one vulnerability change and 12 ordinary changes per
repository, 100 + 1,200 = 1,300 changes per slice, 300 repositories and 3,900 changes
overall. Guard-rejected candidates are dropped before freezing; actual retained
counts are reported, with no replacement or silent claim that reduced slices meet
the planned precision. Frozen slices are never resized.

Slice 1 supplies the baseline and G1 arms table. Slices 2 and 3 qualify the first
two adoption decisions. Once spent, p2 is drawn by the same code and excludes p1.
Every use is appended to `usage-p1.jsonl` with slice, decision or experiment id,
purpose (`baseline`, `exploratory`, `informed`, `qualifies`), date, result digest and
freeze digest. A slice that informed a change cannot qualify that change (3.1).

The label check reads every third `introducing` change before freezing, marking
`confirmed`, `refactor` or `unclear`; report the confirmed share and catch on the
confirmed subset. Report catch separately for `introducing` (the headline) and
`last_touch` (a lower bound). The former inherits SZZ last-writer/refactor noise;
the latter may already contain the flaw in base, making novelty-based silence
correct even though scoring counts a miss (design 2.1).

## Replay arms

The default hook replay uses `--deadline 30 --engine inline --max-regions 500
--mode advisory` (section 4). Retain the artifact and full text output, including
every `Skipped:` line.

Decision 4.0 registers a second slice-1 arm with `--deadline 300` and every other
flag unchanged. Commit its experiment manifest with
`unseen: {pool: p1, slice: 1}` before its first replay. Report both arms to
distinguish deadline misses from engine misses. This arm is a measurement;
adopting a longer default deadline is a separate decision under section 7.2.

Decision 4.0a calibrates cluster overhead against native Docker runc. Use a
deterministic paired sample of 20 changes by default, or all of a smaller proof
manifest, at a 600-second calibration deadline. Record per-change stage times and
median cluster/native slowdown with bootstrap 95% intervals separately for time
through quick, engine build and engine queries. Incomplete timings or degraded
scans invalidate calibration. Cluster arm deadlines are the 30/300-second
deadlines multiplied by the median paired slowdown through quick, rounded to
integer seconds; native deadlines stay at 30/300 seconds. Report applied
deadlines and factors.

A deterministic native sample accompanies the cluster slice. Compare whether
each push flags anything and report a Wilson 95% agreement interval. If its lower
bound is below 95%, or any sample pair is missing or failed, flag the run and
exclude cluster results from the baseline. Identify disagreements by opaque
change IDs only. Calibration records contain counts, times and opaque digests.
Docker checks its data-root free space against the unpacked image size upper
bound plus 1 GiB before explicitly pulling; retain sanitized stderr tails and
exit codes on failure (4.0a).

## Catch and false alarm

A vulnerability change is caught only if a finding matches its labelled family
and head location (4.1). Engine findings carry the family; quick-rule CWEs map
through the project's family CWE table. Match locations in the corresponding
file using the following rules:

| Family | Required head location |
| --- | --- |
| `injection`, `path`, `deserialization`, `output_encoding`, `untrusted_destination` | Sink line in the vulnerable function, or within 10 lines of the head-side changed hunks |
| `access_control` | The vulnerable function itself (the handler lacking the check), or within 10 lines of the head-side changed hunks |
| `config_secrets` | The changed file and head-side changed lines ±10, at file scope (`<global>`) |

All three user-visible streams count: admitted defects, advisory engine findings
and quick-rule matches. Record the stream responsible for each catch. A matching
family at the wrong location does not count.

An ordinary change is a false alarm if **any** of those three streams contains at
least one finding, of any family, anywhere (4.2). Report the admitted-defects-only
alerts rate beside it. An ordinary change may contain an unknown vulnerability;
adjudication does not change this definition. Adjudicate all flagged ordinary
changes if there are 30 or fewer, otherwise every third, against the standard
of protocol v2, and report the adjudicated share separately (design 2.2).

## Coverage and degradation

Assign exactly one state to every change (4.3):

| State | Definition |
| --- | --- |
| `instrument_failure` | No record, failed fetch, head commit not verified, or zero bytes of changed files read; also the `suspect_fast` failure path |
| `unanalysable` | No changed file uses a language the hook covers (`language_not_covered`) |
| `quick_only` | Quick read the changed files but no engine question completed on them |
| `engine_covered` | At least one engine question completed on a changed file |

Prove input access: record checkout files and bytes, bytes of each changed file,
JVM wall time and hook exit code. A replay faster than JVM startup is
`suspect_fast`, never a clean zero. Failed fetches, missing commits and hook
crashes yield failure records, never empty successes. Re-run an instrument
failure once, then report it; it never counts as quiet or missed. Refuse to score
a slice with more than 5% instrument failures after re-runs (design Error
Handling). Preserve skipped/degraded coverage rather than interpreting silence
as analysis. Report catch and false alarm overall and by coverage state, with
failure counts explicit and failures excluded from outcome denominators.

## Intervals and planned precision

Use Wilson 95% intervals with z = 1.96 (section 3). For observed proportion p and
denominator n, the centre is `(p + z²/(2n)) / (1 + z²/n)` and the half width is
`z * sqrt(p*(1-p)/n + z²/(4n²)) / (1 + z²/n)`. The precision bar uses the larger
distance from p to either bound, not just the interval's half width.

The design's exact minimum sample sizes are:

| Rate | Assumed p | Maximum distance | Required n |
| --- | --- | --- | --- |
| False alarm | 0.05 | 3 percentage points | 315 |
| False alarm | 0.10 | 3 percentage points | 483 |
| False alarm | 0.20 | 3 percentage points | 756 |
| Catch | 0.10 | 10 percentage points | 62 |
| Catch | 0.25 | 10 percentage points | 88 |
| Catch | 0.40 | 10 percentage points | 97 |

At n = 100 and catch p = 0.4 the Wilson interval is [0.309, 0.498], within
10 points. One vulnerability change per repository keeps those observations
independent. The 12 ordinary changes within a repository are correlated. With
m = 12 and assumed ICC = 0.05 the design effect `1 + (m - 1)*ICC` is 1.55;
1,200 ordinary changes give effective n ≈774 ≥756. At p = 0.2 their plain Wilson
interval is about ±2.3 points.

Report a repository-cluster bootstrap 95% interval beside the ordinary-change
Wilson interval: resample whole repositories, retaining their within-repository
changes. Measure and record ICC on slice 1. If ICC exceeds 0.05, increase the next
pool's size, never the frozen slice's. Per-family intervals are reported but not
sized; splitting 100 changes over seven families gives roughly ±20–25 points.
The design leaves per-family BLOCK sizing to a later decision.

Report counts, denominators, rates and intervals overall and per family, method,
post-cutoff group, stream, coverage state and confirmed subset (sections 3 and 7).
Use actual observed counts, not planned sample sizes, for intervals.

## Fixed budgets and adoption gate

For score-bearing arms, report catch at false-alarm budgets of 1%, 5% and 10%
(7.1). Choose the lowest score threshold whose ordinary-change false-alarm rate
stays within the budget; report catch with its Wilson interval and realised
false-alarm rate. A threshold selected on the same slice is `exploratory`. For
qualification, fix it beforehand on an earlier slice or held-out folds and
apply it unchanged. A binary arm has one operating point; report which budgets
it meets. Do not substitute AUC for these operating points.

Registered experiments identify `unseen: {pool, slice}`. Write the unseen
estimates beside held-out fold estimates, including each arm's catch at each
budget and paired difference B − A with an exact McNemar test on the paired
vulnerability changes (planned n = 100; 7.2). Record use in the ledger.

Adopt candidate B over production A only when both the existing fold rule and
the untouched-slice gate pass (7.3):

1. At the 5% budget with B's threshold fixed beforehand, B's catch is not
   significantly lower than A's: exact two-sided McNemar on paired vulnerability
   changes, alpha 0.05.
2. For a binary arm, B's false-alarm rate is not significantly higher than A's:
   exact two-sided McNemar on paired ordinary changes, alpha 0.05. Report the
   repository-cluster bootstrap interval for the false-alarm difference beside
   the test because those changes are clustered.

Write `unseen.gate: pass | regression | not_run`. No slice, a slice already
`informed` for this change, or more than 5% instrument failures yields `not_run`;
it blocks adoption just as `regression` does. Decision 4.0a also excludes flagged
cluster/native agreement runs from baseline use. Failure to detect a significant
regression is the specified gate, not evidence that the arms are equivalent.

Raw per-change artifacts remain outside the repository. Committed measurement
records contain counts, rates, intervals and digests, never repository names or
URLs. Public p1 names stay only in the permissive pool manifest; private entries
remain in the gitignored private manifest and are bound through opaque pointers
(design 1.4 and 6).
