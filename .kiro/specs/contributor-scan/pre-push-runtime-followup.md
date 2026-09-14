# Runtime follow-up from pre-push-safety-net task 8.2

Status: frozen measurement complete, runtime NO-GO; investigation routed to the existing engine/runtime
owner. This note does not change contributor-scan task approvals or detector semantics.
Final scorecard and exact instrument identities are linked below.

The NodeGoat production transaction uses the existing evidence ranker and full tracked
first-party graph. Initial packaged process receipts show approximately 5 seconds for
the JavaScript frontend, 14 seconds for overlays and 12 seconds for census before the
first query. Each query invokes another JVM. Both comparison sides retain independent
graph/answer identities. These are observed single-stage costs, not p95 estimates.

The existing engine boundary owns frontend execution, overlays, graph census, queries,
process cancellation and validated graph leases. Investigate batching census and query
work into an engine session, amortizing JVM startup, and reusing complete immutable
base-side artifacts. Measure the additional costs of graph parsing, overlay work and
loading separately. A long-lived local engine would need request deadlines, isolated
leases, reliable cancellation/recovery and resource limits before it can replace the
current disposable subprocess lifecycle.

Any proposed change must preserve named source/census receipts, actual selected/deferred
question identities, first-party-only graph contents, exact base/head comparisons and
fresh-answer census validation. Compare evidence against cold execution. Keep the
30-second warm p95 and 2-second cancellation/report gates unchanged. Differential graph
mutation remains a separate experiment requiring cold-equivalence evidence. Ranker
retuning or shrinking the evaluation population cannot repair fixed engine startup cost.

The initial long-budget NodeGoat priming transaction finished in 224.47 seconds with
incomplete coverage. Its head partition records 44 input paths and 95,411 source bytes,
but the scan reports `cpg_empty` and `partition_file_census_incomplete`; the declared
contributions handler remains an unresolved file-level question. No qualified graph
or answer hit is established for the following identical comparison. This is a named
instrument/coverage gap, not evidence that the target is safe or that the ranker missed
a proven candidate. Reconcile raw frontend/census filenames with the 44 input paths,
including the explicit test-retention policy, before attributing this to cache identity
or detector semantics. Keep this investigation separate from JVM startup optimization.

Final task 8.2 receipts: `benchmarks/measurements/2026-09-13-nodegoat-feasibility.json`
and its compressed full evidence bundle. All 21 deadline-bound transactions timed out,
0/24 declared target checks completed, observed workload p95 30.631–30.912 seconds.
Every measured artifact matches the frozen installed semantics. No source, engine,
query, fact or ranking change was made during this run. The follow-up remains necessary
before rollout; the evaluation task does not authorize weakening its gates.

## VAmPI qualification follow-up, 2026-09-13

Task 8.3's packaged frozen regression (139,164 total snapshot bytes read per replay)
retains raw findings at `models/user_model.py:73:get_user`,
`api_views/users.py:187:update_password`, and `api_views/books.py:51:get_by_title`.
The SQLI target has no selected exact function question; the two authorization target
questions are selected at positions 93 and 63 but have `change_context_incomplete`.
Head scope retains 138 selected and 20 deferred questions. Raw findings do not prove
completed target questions or a transitive source-to-target witness.

The first lab run took 112.415s; same-snapshot cached replays took 6.816s and 6.684s,
all incomplete. This is diagnostic reuse, not changed-code performance qualification.
The 600-second budget is distinct from the hook acceptance profile. Full artifacts are
in `2026-09-13-push-qualification.json.gz` under the regression population.

Reconcile evidence normalization and the unsupported context projection at the shared
scan boundary before downstream admission: retain the actual query-origin/path witness
when available, resolve supported first-party context, and keep unresolved dynamic/vendor
boundaries explicit. Do not fabricate transitivity from a raw finding at the target.
Revalidate ordinary VAmPI scan, exact question accounting, push regressions and independent
qualification after an approved owner fix. This note records the prerequisite; it does
not silently approve an upstream implementation or change detector semantics.

## 2026-09-14 census diagnosis and targeted retention repair

The maintainer accepted the proposed contributor-scan follow-up with "ok" after
group 8's NO-GO report. This authorizes the targeted shared-boundary fixes and their
validation; independent qualification and rollout still require their existing gates.

A fresh offline packaged probe copied and reopened all 44 exact NodeGoat first-party
JavaScript inputs (95,411 bytes), built a graph and inspected its raw named census.
Result: 43 files, 564 methods, 3,750 calls; only `Gruntfile.js` was missing. Build took
21.708s and census 14.990s. Tests were retained. The pinned frontend's
`IgnoredFilesRegex` explicitly drops `Gruntfile.js`; the partition adapter then replaced
the partial census with zero counts, producing the misleading `cpg_empty` diagnosis.

The first repair narrowly extends the existing versioned frontend adaptation to retain
`Gruntfile.js` under explicit `OUSAST_INCLUDE_BUILD_CONFIGS=1`. It changes neither its
path nor bytes and leaves all other defaults, vendor exclusion and test retention
intact. The backend owns the option and binds it to graph/runtime identity, so old
artifacts cannot silently qualify under the new retention policy. It does not execute
the build configuration. This format-level input repair is not NodeGoat-specific scope
selection or a claim that every possible JavaScript configuration file is now supported.
The partial-census correction now preserves actual counts and missing filenames,
with missing/empty/malformed census still preventing completed questions. Runtime amortization and VAmPI context/witness evidence remain open.

Source: [Joern 4.0.625 AstGenRunner](https://raw.githubusercontent.com/joernio/joern/v4.0.625/joern-cli/frontends/jssrc2cpg/src/main/scala/io/joern/jssrc2cpg/utils/AstGenRunner.scala).
