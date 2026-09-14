# Task 2.19 — measured input retention and census completeness

The maintainer accepted the proposed contributor-scan follow-up after the pre-push
NO-GO report. The Kiro root-cause-first workflow identified a concrete shared-boundary
repair; no new detector, ranking policy or rollout threshold is introduced.

## Debug Report
- ROOT_CAUSE: Joern 4.0.625's default filename filter excludes Gruntfile.js. A fresh read-verified NodeGoat input has 44 files/95,411 bytes but its raw graph census contains 43 files, 564 methods and 3,750 calls. The partition adapter substitutes zero counts for this incomplete census, incorrectly producing cpg_empty.
- CATEGORY: CONFIG_GAP
- FIX_PLAN: Retain the original Gruntfile under an explicit versioned frontend policy; preserve actual census counts and named omissions while keeping incomplete questions unresolved.
- VERIFICATION: Exact pinned Node input/census before and after; packaged native PHP/JavaScript partition smoke; malformed/missing census controls; full regression suite and canonical gates.
- NEXT_ACTION: RETRY_TASK
- CONFIDENCE: HIGH
- NOTES: Independent quality evidence, VAmPI context/transitive witness and runtime amortization remain separate blockers. The debug timing is not a representative hook latency profile.

## Implementation and review

`JoernBackend.include_build_configs` explicitly sets the frontend environment option,
overriding inherited ambient values. Runtime and graph identity include the option.
The pinned adaptation exempts only the `Gruntfile.js` basename from the known default
filter when enabled. Paths, bytes and graph connectivity are preserved; no configuration
is executed. Existing test retention and vendor exclusion remain intact.

Partition census rejection now carries actual counts plus a named completeness reason
and the missing filenames when available. Scan scope and outcomes consume that reason
in both evidence and arbitration passes. A nonempty graph is no longer reported empty.
Empty, absent or malformed census payloads produce an explicit unavailable marker,
with no invented observed counts. Review found this latter gap in the first correction;
three failing controls reproduced it before repair. A missing-file marker survives
aggregation with another valid partition; existing sharded/empty graph limits remain.

RED evidence: `/tmp/owner-retention-red.log` and `owner-retention-off.log` fail the new
explicit policy assertion. Default ON passes; the supported opt-out remains a real input
policy. Census diagnostics: `owner-census-diagnostic-red.log` and `-off.log` fail three
new expectations; ON passes and the temporary switch was removed. Additional empty,
malformed and absent census controls fail before repair (`owner-census-empty-red.log`).
The final focused suite passes 20 tests, including the combined push regression controls.

The raw Node check after retention finds all 44 files and 579 methods, with no missing
or extra source names. Both runs use exactly 95,411 readable source bytes. Diagnostic
build/census costs remain tens of seconds and cannot qualify the 30-second hook gate.
The before/after checks use packaged images; final partition smoke also exercises the
updated scan completeness path. Existing eligibility becomes stale after runtime/core
identity changes and admits nothing; no old measurement is relabeled as current PASS.


Review also checked regression fixtures that intentionally exercise complete graph evidence.
Those backends now provide a named census for the readable files they are given, matching
the production contract. Their ranking, pruning and comparison assertions are unchanged.
A genuinely empty graph retains `cpg_empty`; only unavailable/partial evidence uses the
new explicit census reasons. Counts and missing filenames are carried into the saved
scan degradations. The final focused scan/scope/partition/policy suite passes 74 tests.

The final offline image's mixed native PHP/JavaScript partition smoke passes, including
original Gruntfile method/file nodes, test directories/suffixes, first-party source byte
receipts and absence of vendor nodes. No language-specific ranking change was made.

## Status Report
- STATUS: READY_FOR_REVIEW
- TASK: 2.19
- RED_PHASE_OUTPUT: Explicit policy OFF and census preservation OFF failures recorded above; three additional missing/malformed census failures reproduced before repair. Temporary diagnostic switch removed.
- TESTS_RUN: Final full suite 1321 passed, 9 skipped in 120.96s, exit 0; 74 focused controls pass; ruff/format/mypy/compileall and detector/map/pair gates pass. Final image builds, native mixed partition smoke exits 0, installed builder identity and stale eligibility rejection verified.

## Review Verdict
- VERDICT: APPROVED
- TASK: 2.19
- MECHANICAL_RESULTS: Actual diff reviewed; full regression and packaged checks pass. Existing ordinary-scan test backends now supply named readable-file censuses while retaining their original assertions. No new placeholders, secrets, rank heuristics or vendor restoration.
- FINDINGS: Actual empty graphs retain cpg_empty. Nonempty partial graphs retain counts and missing names; absent/empty/malformed census cannot authorize completion or tier-zero pruning. Runtime/cache identity binds the retention option and installed adaptation. Main-context Kiro fallback; no independent review claimed.
- SUMMARY: Targeted shared input/census repair verified without a latency, transitive-detection or rollout claim.

## Verification Result
- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Task 2.19 repairs the measured Gruntfile omission and honest census-completeness handling.
- EVIDENCE: `benchmarks/measurements/2026-09-14-node-census-repair.json` preserves all source receipts, raw before/after census, reproducer, build/smoke logs, packaged identity and final test/gate results. Node census 43/44 → 44/44, methods 564 → 579. Final image `898789cb6cc88507a9fa67276fd442ee4ef9e9f1135b333bafda511fb0532b25` passes mixed native PHP/JavaScript smoke, including the original build/test methods and vendor absence.
- GAPS: Representative runtime/coverage gates, VAmPI change context/transitive evidence and independent qualification remain unresolved. Pre-push task 8.3 and rollout remain NO-GO. Old eligibility is stale and enables no capabilities.
