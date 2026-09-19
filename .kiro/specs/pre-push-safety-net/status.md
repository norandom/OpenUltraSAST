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

The exit run is recorded. Every veto M1a listed is repaired, plus two the repairs exposed: the
comparison's own degradation and boundary checks, and the runner handing every candidate the
whole transaction's gaps. On the vulnerable revision admission now rejects on
`capability_unavailable` alone.

One half of M1b remains. The milestone also asks for a developer-readable finding carrying a
supported security consequence and a concrete repair direction. Both are owned by an evaluated
capability declaration and the registry is deliberately empty, so nothing renders them. Writing
that text without a declaration is what admission exists to prevent, so it is not worked around.
Task 10.10 renders it through an explicitly experimental declaration with eligibility still
disabled.

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

## Security capability, 2026-09-17

Group 12 closed three defects that limited what the tool can establish, each measured on the
pinned NodeGoat revisions with detections unchanged throughout.

- **Access control could not answer anywhere.** Dominance and configuration were never asked for
  change context, because the evidence pass dispatches taint only. Each family now describes its
  own scope. Head completion rose from 205 to 298 of 436, `context_projection_unavailable` fell to
  zero, and access control went from 0 to 52 completed questions.
- **Admission rejected genuine findings.** The operation symbol was the text before the first
  parenthesis, so `const preTax = eval(...)` was the operation `const preTax = eval`, which no
  qualified declaration could ever name. It is now the trailing qualified callee, with receiver
  spelling preserved.
- **Unresolved questions said why, and then there were none.** The remaining 138 each named a
  function its file does not define. A route-registration module registers handlers other modules
  define, and regions were scoped to methods those files do not hold. The entry record keeps the
  handler name, because the authorization question is cross-file by nature, and the region is now
  scoped to the file instead. **Every question the scan asks now completes on both revisions,
  299 of 299**, with detections unchanged.

Evidence: [group 12 final](../../../benchmarks/measurements/2026-09-17-group-12-final.json) and
[region attribution](../../../benchmarks/measurements/2026-09-17-region-attribution.json).

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

## Family detection census, 2026-09-19

Four of seven declared families establish findings on the two development subjects:
injection, access_control, config_secrets and untrusted_destination. Output encoding, path,
prototype and deserialization have established nothing anywhere. Every question completed on
both subjects, 299 of 299 on NodeGoat and 35 of 35 on VAmPI, so the silences are answers
rather than failures — but three of them are diagnosed gaps rather than clean code:
NodeGoat's documented SSRF is invisible because `needle.get` is not in the sink vocabulary,
its XSS is invisible because output encoding declares only DOM sinks, and its two
access-control defects raise no obligation because the modelled data operations live in DAO
files while the family's scope is the handler's own file.

The census also found and fixed one false positive: NodeGoat's only prototype report was
the word `set` in a code comment, matched because the sink text clause searched a whole
assignment node. Nothing about this changes the release gates. No capability is qualified by
these subjects.

The first of the three gaps is closed. The untrusted-destination vocabulary now holds the
client surface a Node server actually calls, and NodeGoat's SSRF is reported at
`app/routes/research.js:16` with a witness naming the call. One data change, no query change,
every other family unchanged. Output encoding and access control remain open as tasks 14.3
and 14.4.

Evidence: [family detection census](../../../benchmarks/measurements/2026-09-19-family-detection-census.json),
[untrusted destination vocabulary](../../../benchmarks/measurements/2026-09-19-untrusted-destination-vocabulary.json).
