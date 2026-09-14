# Pre-push safety net status — v1.2.0-alpha.1

Updated 2026-09-14. Phase: **implementation**. Requirements, design and tasks are
approved. **26/27 executable tasks complete; task 8.3 remains blocked.**
Rollout: **NO-GO**. The alpha tag publishes experimental implementation and evidence;
it does not approve normal hook capabilities or production enforcement.

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

1. **Useful checks within the deadline are unproven.** The last full representative
   runtime profile timed out on all 21 Node transactions, completing 0/24 declared target
   checks. Cancellation/reporting stayed below the two-second allowance. The subsequent
   census repair is verified, but the full changed-code runtime/coverage profile has not
   passed under its new identities. Amortize engine startup/loading work and rerun the
   frozen seven-class profile; require warm p95 <=30s and >=95% completed supported checks.
2. **Target and change-context evidence remains incomplete.** VAmPI preserves raw findings
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
[runtime scorecard](../../../benchmarks/measurements/2026-09-13-nodegoat-feasibility.json),
[census repair](../../../benchmarks/measurements/2026-09-14-node-census-repair.json).
