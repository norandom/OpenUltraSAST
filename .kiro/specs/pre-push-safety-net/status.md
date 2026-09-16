# Pre-push safety net status — v1.2.0-alpha.1

Updated 2026-09-16. Phase: **implementation**. Requirements, design and tasks are
approved. **28/29 executable tasks complete; task 8.3 remains blocked.**
Rollout: **NO-GO**. The alpha tag publishes experimental implementation and evidence;
it does not approve normal hook capabilities or production enforcement.

## Next release milestone

**M1a is met and the M1b comparison now works through the production rules.** The other four
milestones remain unverified, and rollout remains NO-GO.

Every veto M1a recorded has been repaired. On 2026-09-16 the production comparison classified
the pinned NodeGoat revisions without any lifting: the vulnerable revision is `new` with the
three `eval` witnesses attributed to the change that introduced them, the fixed twin is
analyzed and quiet, and the unchanged revision is `unchanged`. Production and the recorded view
agree exactly, which is how we know the vetoes were repaired rather than bypassed. No capability
is enabled, no defect is admitted and no alert is emitted. See
[M1a and M1b evidence](m1a-recorded-vetoes.md).

Two tasks remain before M1b is verified: binding candidate dependency gaps to the candidate,
which the rerun exposed as coarse plumbing that would block admission forever after
qualification, and carrying query-to-operation provenance. Then the run is repeated and
recorded as the milestone's exit evidence.

M1a ran on 2026-09-16 within its one-week box. The raw `<lambda>2` witnesses are present at
contributions.js lines 32–34, the fixed twin was genuinely analyzed and quiet, and the
unchanged revision was not reported as a new regression, so the kill criterion did not
trigger. Five vetoes fired and were recorded; with all five lifted the detection still stops
at `operation_correspondence_unresolved`, because a newly introduced operation sits on a
changed line and has no base anchor. That fifth veto was not in the earlier diagnosis and is
now M1b's central repair. See [M1a evidence](m1a-recorded-vetoes.md).

The 28/29 task count is implementation progress, not proximity to rollout. Follow the
accepted [release milestone spec](release-milestones.md): usefulness → speed → shared
PHP/Python transfer → independent qualification → narrow advisory rollout.

## Verified

Immutable pushed snapshots, shared multi-ref deadlines, ranker-owned scope, physical
vendor exclusion, compatible immutable graph/result reuse, actionability admission,
compact truthful reporting and non-destructive hook integration are implemented.
Advisory and blocking share the same evidence bar; optional model output cannot bypass it.

Contributor-scan task 2.19 is verified: the pinned frontend now retains the original
Gruntfile, bringing the real NodeGoat census from 43/44 to 44/44 files. Partial, absent
and malformed census no longer masquerade as a complete result or a falsely empty graph.
The final code verification recorded 1321 passed tests, nine skipped, passing canonical
gates and a packaged native PHP/JavaScript partition smoke. See
[owner verification](../contributor-scan/census-repair-verification.md).

## Rollout blockers

1. **Useful checks within the deadline are unproven.** The fresh post-census profile
   completed all 21 measurements: all 18 changed/cold/growth/multi-ref transactions timed
   out; the three identical-tip replays took 18.521–18.874s with valid graph/query reuse.
   Still 0/24 declared target checks completed. Maximum observed cancellation/report
   overrun was 0.874s, below the two-second allowance. After M1 establishes the useful
   comparison, amortize engine startup/loading and rerun the frozen seven-class profile; require warm p95 <=30s and >=95% completed supported checks.
2. **Target and change-context evidence remains incomplete.** M1a measured exactly which
   contracts fail on the Node case: per-family change context, question-owned vendor
   relevance, operation correspondence for changed lines, file-wide correspondence ambiguity
   and query-to-operation provenance. VAmPI preserves raw findings
   at all three known sites, but the exact SQLI function question/transitive witness and
   supported authorization context are unresolved. Raw findings or rank positions cannot
   establish an actionable new regression. Repair this in the shared scan boundary and
   verify the actual associated query/path evidence.
3. **Independent quality qualification is missing.** Freeze and review untouched Node API
   vulnerable/fixed/benign cases, including middleware/module/async context. Ghost remains
   reserved with missing reviewed inputs. PHP and Python need their own independent
   language/framework/family populations; Node results cannot qualify them. Require >=95%
   observed actionable precision with counts/intervals, >=90% supported recall, nonzero
   reviewed emitted alerts/positive controls and zero known fixed/benign false alerts.
4. **No current capability is eligible.** The earlier registry is NO-GO and becomes stale
   under the repaired runtime/core identities. Loading it enables zero capabilities.
   After the preceding evidence passes together, regenerate exact-semantic eligibility
   and rerun packaged acceptance validation. Do not relabel old measurements as current.

C/libpng arithmetic and bounds remain explicitly unsupported; this is not a C/C++
detection qualification. Advisory rollout cannot be justified by silence from an
unqualified registry.

## Ownership and revalidation

Engine lifecycle, source/census and context/witness normalization belong to
`contributor-scan`. The hook consumes those contracts; no second engine, source IR,
ranker priority exceptions or differential graph mutation is introduced here. Graph
mutation would need a separate cold-equivalence experiment.

After owner fixes, refreeze identities and rerun ordinary scan gates, Python regressions,
PHP-to-Node transfer, the representative cache/deadline profile, independent per-capability
quality evaluation and packaged hook validation. Keep task 8.3 unchecked and the feature
in implementation until those mandatory results are established.

Evidence: [group 8 validation](validation-group-8.md),
[post-census runtime scorecard](../../../benchmarks/measurements/2026-09-14-nodegoat-post-census-feasibility.json),
[census repair](../../../benchmarks/measurements/2026-09-14-node-census-repair.json).

The owner investigation now distinguishes missing family context producers, globally
propagated vendor/correspondence gaps, and query-to-operation identity. See
[remediation research](../contributor-scan/release-remediation-research.md). These are
next implementation prerequisites, not completed fixes or changed acceptance gates.

An isolated Joern session probe matched the full Node census with four warm requests in
0.221–0.467s and verified cancellation/reaping in 0.043s. It identifies a promising engine
lifecycle change; full-query equivalence and changed-code performance remain unverified.
