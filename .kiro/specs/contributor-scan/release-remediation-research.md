# Release remediation research — 2026-09-14

Status: investigation under the maintainer's instruction to continue towards release.
This record does not approve rollout, replace the existing design, or mark a production
remediation complete. The published candidate is `v1.2.0-alpha.1`, commit `04f8880`.

## Summary

Two independent constraints remain after task 2.19 restored Node's complete named census:
engine lifecycle cost and the scope of completeness evidence. A faster engine cannot
repair missing context; suppressing completeness gaps cannot prove useful detection.
Both belong in the existing contributor-scan boundary, with comparison/admission changes
owned by pre-push-safety-net. The ranker continues to select all analysis work.

## Engine lifecycle investigation

The earlier task 2.3 decision rejected server mode on the measured large C workload:
evaluation dominated its elapsed time. That decision remains valid for that measurement.
It does not establish the best lifecycle for small, frequently changed API repositories.

The fresh Node priming transaction reopened the declared inputs and completed in 338.157s.
Its two frontends took 5.536s and 5.451s; overlays 15.779s and 15.239s; standalone census
13.716s and 13.708s. Each of eight query invocations took another 13.264–22.783s. These
are individual process receipts, not estimates of exclusive JVM startup time. The remaining
transaction time includes Python orchestration, cache publication and other work and must
not be attributed to the JVM without a separate measurement.

The first identical-tip replay took 18.874s with two graph hits, 1,512 query hits, and no
engine subprocesses. Thus compatible persistence now works on this workload. Every head
question still has incomplete change context; base questions have `graph_incomplete` from
the vendor boundary described below. Identical-tip timing is not changed-code qualification.

Joern documents a local interpreter server with synchronous and asynchronous query APIs:
[official server contract](https://docs.joern.io/server/). This supplies a candidate transport,
not a sandbox. Before adopting it, probe the actual pinned 4.0.625 image in a disposable,
network-disabled container with no published ports, a private graph copy and process-group
cleanup. Compare an actual named census against disposable script execution, record startup,
load and repeated request times separately, and test cancellation of an in-flight request.
A census microbenchmark cannot establish security-query equivalence or hook p95.

### Completed lifecycle probe

[Full receipts and all three instruments](../../../benchmarks/measurements/2026-09-14-joern-session-lifecycle.json)
retain the failed first attempt as well as both successful file-receipt attempts.
The first attempt received HTTP `success=true` with an empty stdout for the census;
the `println` payload went to the process log. It failed rather than interpreting that
response as a zero. The repaired instrument writes a fresh private result file per
request and checks a unique receipt before accepting its census.

The final attempt reopened all 44 source files (95,411 bytes), verified the cached graph
digest, loaded a private copy, and matched names, counts and overlays against disposable
execution. It confirmed entry into a deliberately hanging operation before cancellation,
then verified the entire process group disappeared. The cached graph remained unchanged.

| Final attempt phase | Observed seconds |
|---|---:|
| Disposable census invocation | 14.292 |
| Server startup through usable request | 12.805 |
| Graph load | 3.636 |
| First census request | 1.402 |
| Four warm census requests | 0.339, 0.467, 0.353, 0.221 |
| Kill and process-group reaping | 0.043 |

Decision: a transaction-owned local session is a promising candidate for the owner
implementation. The adapter needs explicit request receipts; HTTP status alone is not
an answer contract. This probe does not cover full taint/dominance/config equivalence,
multiple graph epochs, concurrent transactions, overlays in-session or production
failure recovery. It neither overturns the large-C evaluation result nor proves 30s p95.

### Completed full runtime profile

The [post-census scorecard](../../../benchmarks/measurements/2026-09-14-nodegoat-post-census-feasibility.json)
and its compressed 115-file evidence bundle retain all 21 planned transactions plus
priming, raw scans, process traces, CLI output and exact instruments. All 22 scan artifacts
match the frozen runtime/core provenance; recomputing the scorecard reproduced its result.
There were no missing cases or instrument failures. Eighteen transactions timed out;
the three identical-tip cases took 18.521–18.874s. Completion remains 0/24 target checks;
maximum observed cancellation/report overrun was 0.8732s. Runtime and rollout remain NO-GO.

Verification: seven runtime-scorecard tests pass; JSON/bundle round-trip, hashes, population,
provenance and scorecard recomputation pass. Production source is unchanged from the
released alpha; this is evidence validation, not a new full implementation verification.

## Completeness diagnosis

### Missing family context producer

`model/scan.py:_evidence_pass` dispatches only taint queries and records their context by
the exact family-specific question identity. `affected_context` requires `context_summary`
and readable method extents for every question. Neither `dominance.sc` nor `config.sc`
exports that contract. Consequently access-control and configuration questions cannot
complete change context through the production path. This is deterministic missing
integration, not evidence that the ranker selected the wrong region.

Do not copy taint context into other families: dominance deliberately evaluates sibling
operations across a file; configuration has different scope; source, sink and guard
summaries have different obligations. A producer must describe the actual scope of the
query it accompanies. Missing extents, unresolved external calls and unsupported reasoning
remain explicit. Context relationships alone never prove an exploitable flow or guard loss.

### Exclusion is currently a global completion veto

`model/partitions.py` records `vendor_semantics_unresolved` when it excludes any vendor
path. `model/scan.py` includes that reason in `graph_gaps`, changing every otherwise
completed outcome to `graph_incomplete`. In the fresh Node prime, this is the only base
degradation, despite a complete 44-file first-party census and successful query receipts.

Vendor exclusion must remain physical. The missing contract is which question actually
requires excluded semantics. Distinguish input-integrity failures, which invalidate the
affected graph, from an excluded dependency whose relevance needs query evidence. Only
an explicit, complete dependency proof or versioned summary can discharge that question's
boundary; lack of a recorded dependency is not such proof.

### Line ambiguity propagates beyond the affected correspondence

`push/snapshot.py` conservatively omits non-unique unchanged lines and records a file-level
`ambiguous_line_correspondence`. `model/regions.py:affected_context` inherits any existing
boundary into every question. `push/policy.py:compare_evidence` also rejects a candidate
when any transaction context boundary exists. Repeated unchanged lines can therefore
invalidate an otherwise distinct, uniquely mapped operation elsewhere.

Retain ambiguous mappings as unavailable. A future repair must bind the required base/head
correspondence to the specific operation and dependency context, with absent, renamed,
removed-guard and ambiguous-operation controls. Aggregate coverage must retain every gap.
Do not delete the ambiguity check or treat lexical alignment as a semantic proof.

Comparison currently also requires all selected base questions to complete, no base
degradations, and no non-tier-zero deferred question. That prevents a complete target
comparison from surviving an unrelated unsupported family. Any amendment must establish
the complete base counterpart and its required scope explicitly; a missing raw finding
in an incomplete base scan cannot establish novelty. This change belongs to the push
comparison policy, consuming evidence ownership supplied by the shared scan contract.

### Query identity and witness identity differ

The Node contribution target is selected through a file-fallback injection question
(`function=None`), while raw rows report `<lambda>2` at lines 32–34. The declared benchmark
target is `handleContributionsUpdate`. VAmPI similarly has a raw SQLI site without an exact
function target question. The benchmark correctly refuses exact-target completion today.
Production normalization must carry verified query-to-operation provenance; do not inject
benchmark function names into regions or change the denominator to count coincident sites.

## Bounded remediation sequence

1. Finish and preserve the unchanged seven-class runtime profile, including all failures.
   Run the isolated lifecycle probe afterwards so the experiments do not contend for CPU.
2. Use those results to choose one engine lifecycle amendment. If a session is promising,
   keep it transaction-owned inside the existing backend: one deadline, serialized requests,
   explicit graph identity/epoch, private leases, failure poisoning, kill-and-reap cancellation,
   and fresh census on each answer. No resident laptop service is implied. Compare every
   shipped query kind with the disposable path before any production switch.
3. Specify question-owned completeness across scan and comparison boundaries. First add
   authentic family context producers, then dependency/correspondence ownership, with paired
   PHP/JavaScript normalized controls and VAmPI regressions. Unknown ownership remains a
   blocker. A family that cannot provide this evidence stays experimental.
4. Refreeze runtime and semantic identities. Rerun changed-code latency/completion and the
   independent reviewed vulnerable/fixed/benign populations together. Regenerate eligibility
   only after the existing joint gates pass; then repeat packaged acceptance validation.

This sequence separates runtime transport from evidence semantics. It adds no detector,
second IR, language-specific rank boost, vendor graph expansion or differential CPG mutation.

## Verification needed for implementation

| Boundary | Required evidence |
|---|---|
| `cpg/backend.py`, candidate local session transport | Actual pinned launch/API; full query equivalence; malformed/absent response; switched graph isolation; concurrent transactions; deadline, crash and orphan cleanup |
| `cpg/queries/{taint,dominance,config}.sc`, `model/scan.py` | Context from actual query scope; authentic per-family methods; answered-empty distinct from unavailable; unchanged rank decisions |
| `model/contracts.py`, `model/regions.py`, `model/partitions.py` | Explicit gap ownership; first-party input failures remain blocking; dependent vendor/unknown paths unresolved; unrelated exclusion never silently proves completeness |
| `push/snapshot.py`, `push/policy.py` | Exact operation correspondence; guard deletion; same-named and ambiguous operations; incomplete base cannot establish novelty; aggregate partial coverage retained |
| Evaluation and eligibility | Frozen identities and populations; unchanged 30s/2s and precision/recall/completion gates; no capability enabled by a microbenchmark |

Production changes require task-local review and fresh ordinary scan gates, runtime smoke,
and downstream acceptance evidence. This research record is not that verification.
