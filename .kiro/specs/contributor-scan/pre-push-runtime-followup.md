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
