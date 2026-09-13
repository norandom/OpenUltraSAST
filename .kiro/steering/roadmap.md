# Roadmap

## Current direction and next review — 2026-09-12

The product is an **actionable pre-push security safety net for AI-accelerated development**, across
supported languages/frameworks. WordPress is one regression workload. Advisory must be useful and
low noise; moving speculative SAST output into a nonblocking hook does not meet the goal. See
`safety-net.md` for current steering. The earlier narrative below is retained as dated history and
does not override this direction or the latest measurements.

### Approach decision

Keep the existing ranker as the scope mechanism. Supply it with pushed-change and affected
first-party context. Third-party vendor code remains outside both targets and graphs. Reuse
compatible graph/results artifacts and apply a total deadline; treat unknown external semantics
as a coverage boundary. Require change attribution, witness and repair direction before a finding
earns normal hook visibility. A second heuristic scope selector and an assumed incremental Joern
engine are out of scope.

### Current evidence and limitations

- Whole-PMPro analysis has completed with its known CVE; the earlier "does not finish" diagnosis
  is superseded. The recorded 72-minute scan is not a pre-push performance result.
- Historical Joern 4.0.625 + layout position budgets are PMPro 82, WP Statistics 91, MW WP Form 54.
  `<50` remains unmet. VAmPI's old 16 omitted SQLI; the corrected instrument retains the unmatched
  target and reports no full-target budget or detection recall without the required evidence.
- Equal-score tie-breaking alone cannot bring PMPro or WP Statistics under 50. The existing
  ranker is useful, but its measured ordering is not enabled by the ordinary CLI caller.
- Docker/Compose/ops now default to 4.0.625; task 1.1 passed local PHP/JavaScript image smoke and independent review. No host deployment or hook latency claim follows from that runtime evidence.
- `contributor-scan` has 25/41 checked tasks, including the approved and verified frontend-retention prerequisite 2.18.
  `flow-aware-ranking` is still an unapproved brief despite implementation history.

## Existing Spec Updates

- [ ] `contributor-scan` — review the draft driver/backend integration amendment; reconcile packaging
  pins, family-specific sanitizer task 5.6, exact scope reporting and repository baseline honesty.
  Preserve previously approved work; the new amendment is not implicitly approved.
- [ ] `flow-aware-ranking` — review the amended experiment contract: ranker owns scope, vendor
  boundary preserved, missing targets stay unresolved, actual detection and cost accompany rank,
  untouched evaluation and exploration precede learned-ranking claims.
- [ ] `zero-with-a-reason` — reconcile the broader funnel proposal with the hook's consumed coverage
  contract; it is adjacent work, not a requirement to finish every diagnostics mechanism first.

## Specs (dependency order)

- [ ] pre-push-safety-net — Immutable pushed tips, existing-ranker integration, compatible artifact
  reuse, total deadline, change attribution, actionability admission and compact hook behavior.
  Dependencies: contributor-scan. Requirements/design approved 2026-09-12; tasks generated
  (8 groups, 27 executable subtasks), independently reviewed and approved; groups 1–6 are implemented and verified (20/27 tasks), including the resolved frontend-retention prerequisite.

### Next concrete step

Groups 1–5 now connect immutable replay to the existing ranker, detector, comparison,
admission and compact artifacts. The first frozen PMPro/Node experiment is **NO-GO**:
all six cold security/fixed/benign cases timed out without completed target checks.
After repairing post-deadline semantic planning and a repeated availability probe,
every final CLI run saved its artifact and returned in 30.55–30.64 seconds. PMPro spent
its deadline in preparation/discovery after materializing both trees; Node reached the
driver but did not complete checks. The exact 11-case population remains unresolved.
No normal capability is enabled and these six cold samples establish no warm p95 claim.

Group 6 now provides complete preparation/discovery, graph and query reuse through explicit
`--cache-dir`, bounded publication and isolated graph leases. A packaged authored JavaScript
control preserved the same evidence/admission as an uncached run; its identical-revision
replay took 2.00s. Source/declaration changes invalidate affected units. This correctness
control does not establish representative changed-code p95, independent alert precision or
eligibility. Rollout remains NO-GO and normal capabilities remain disabled.

Group 7 is next for the real multi-ref push interface and opt-in hook integration. Group 8
must still pass the joint gates on declared populations. Keep the existing thresholds and
profile preparation, graph construction and queries separately when investigating misses;
do not substitute identical-tip hits for warm changed-code performance.

Tasks 4.3 and groups 5–6 used the documented Kiro manual review fallback after the agent
thread limit; this is not independent review. See `pre-push-safety-net/implementation-group-5.md`
and `benchmarks/measurements/2026-09-13-first-replay-experiment.json` for provenance,
initial instrument failures, their repairs and the newly frozen final trial. The NodeGoat
teaching workload did not cause a framework/fact adaptation or ranking retune. Ghost remains
untouched; independent PHP/Python eligibility populations and C/C++ property support remain
separate gaps. Automatic dominance-only context projection is still an upstream limit.

## Historical roadmap narrative — September 9–11

The sections below preserve prior plans and measurements. Statements about the current bottleneck,
PHP coverage, rollout order or feature readiness are superseded by the current section above.

**Rewritten 2026-09-09.** The previous version (kept as `roadmap-2026-09-04.md`) described a pre-Joern world —
"adjudication is still Python-`ast` plus a tree-sitter CLI stub", "Joern-as-required deferred". Joern was
adopted, the model layer was built, wired and measured, and two repositories have been scanned. See
`overview.md` for what is true today; this is what happens next and in what order.

## The target: a first release for small projects

> "a first release that is ready for smaller projects like libpng or wordpress"

Those two are, today, exactly the cases that do not work — and they fail for **different** reasons, which is
what makes them a good pair of targets rather than one.

| target | why it fails now | what a release needs |
| --- | --- | --- |
| **WordPress** (php) | `taint_specs(language="php")` returns **zero families**. Joern's `php2cpg` parses it; we say nothing. | Fact tables and entry-point mapping. The engine is right for this: PHP web bugs are the classic taint families, which is what the taint arbiter already decides well. |
| **libpng** (c) | `c/memory` models string functions; libpng overflows through *arithmetic*, and its library never calls a sink we model. | Either a second abstraction (size arithmetic — a constraint problem) or an honest, stated limit. |

So "ready for" has to mean two different things, and the release criteria say which applies where:

* For a project whose bug class a family **can** decide (WordPress, vibe-code): find the known vulnerability.
* For one it **cannot** (libpng today): run inside its envelope, report nothing false, and *state the limit*
  rather than returning a quiet clean bill of health.

The second is not a consolation. A tool that says "I do not model this class" is usable; one that silently
finds nothing is the thing that teaches developers to distrust SAST.

### Release criteria (v0.1)

1. Runs unattended on a pinned checkout of each target within a stated time and memory envelope.
2. **Zero known-false entailed findings** on every pinned checkout.
3. Finds the known vulnerability wherever a family can decide it in principle (Req 4.6).
4. States what each family cannot decide, in the report (Req 5.6).
5. The report is proportionate — no rule repeating itself past a stated count (Req 5.5).
6. Installs and runs without the user having Joern, a JVM, or a PHP interpreter (docker compose + wrapper).
7. A committed regression baseline per target, so the next change is measurable rather than argued about.

### What that reorders

PHP moves **up**: it is the shortest path from here to a target the maintainer named, and it is the case the
existing arbiter is best suited to. The C decision moves up with it, because criterion 4 needs `c/memory`
either earning its place or being scoped — and scoping it is cheap.

## The one test everything is ordered by

> "it must find the bugs, otherwise it's SAST noise. most devs know codeql / semgrep have dataflow
> capabilities but never use it"

So the ordering principle is: **make the output worth reading, then make it find more.** A better arbiter
behind an unreadable report changes nothing, and a second language before the report is fixed just doubles the
noise.

## Now — make a repository scan finish at all

The output work this section used to hold is done, and PHP went considerably further than it planned: three
CVEs on real WordPress plugins, entailed by the graph with no model in the loop, each dropping on its fixed
side. The detector is not the problem any more. **Finishing is.**

A 637-file plugin builds in 76 seconds and then the taint query does not complete. Everything below is
ordered by one question: what is the shortest path to a scan of a real plugin that reports its CVE?

1. **5.14 — stop asking questions that cannot have an answer.** 53% of taint requests are put to a family
   whose sinks do not appear in scope; every one of PMPro's 487 `deserialization` requests is asked of a
   repository that never calls `unserialize`. Arithmetic, not judgement, and it cannot lose a finding.
   4.6 hours → 2.2. Do this first because it makes every later measurement cheaper to run.
2. **5.12 — rank, because 84% of regions currently share one rank ordered alphabetically.** Two thirds of the
   budget is spent arbitrarily. Fifty well-chosen regions beat five hundred; combined with (1) that is the
   difference between hours and minutes. The ranker is an LLM job, and it is safe as one because ranking
   cannot manufacture a finding -- it decides what is looked at, never what is reported.
   **The loop is closed and that is a design requirement, not a caveat:** a region the ranker excludes is
   never arbitrated, so it never produces a label, so the ranker never learns it was wrong. An exploration
   slice and a small fully-labelled corpus are what make the signal unbiased.
3. **5.13 — the 6.63 s/request itself**, if (1) and (2) are not enough. `callDepth=3` over 7,061 methods is
   the term that makes a request cost seconds; the two-stage joins are NOT the cost (measured: 22%, and they
   found two of the three CVEs).

Only after a scan finishes is there any point tuning what it finds.

## Next — the families that cannot be asked

4. **5.9 — PHP obligation facts.** `dominance_specs(language="php")` is empty, so missing-capability checks
   are not asked on any WordPress scan. Not a miss; nothing was measured.
5. **5.6 — a sanitizer cleanses the family it cleanses.** The list is flat, so `esc_sql` reads as sufficient
   for XSS and `esc_html` as insufficient for SQL. Wrong in both directions, so no `output_encoding` verdict
   currently means anything.
6. **File the php2cpg defect upstream.** A `global` inside a closure yields a CPG Joern's own dataflow
   overlay rejects, bisected to four lines. Worked around here (0.2% of files, detected and excluded and
   reported), but it costs the WHOLE graph rather than the file, and other users will hit it.

## Then — close the deferred engine questions

8. **2.14 — control dependence.** Absent from both CPGs, so every guard question runs on CFG dominance. Find
   out whether Joern's CDG pass can be applied from the query script and what it costs. If it cannot, that is
   a real bound on what this engine can reason about and should be recorded as one.
9. **2.13 — a destination allocated to size.** Deliberately blocked on 6, so the rule can be measured for what
   it *silences* as well as what it clears.
10. **Group 3–4 — ship it.** Contributor output, the Docker image, the memory-family decision, retiring
    `evidence_level` now that the rung carries the meaning.

## Alongside — keep the codebase from growing into the problem

> "we should make sure our code base here doesn't explode. for example we have a custom IR."

`.kiro/specs/ir-consolidation/` (brief, unapproved) separates two questions with opposite answers:

* **The source IR is already carried, not about to be added.** `semantic/` is 3,218 lines — 16% of the
  codebase — holding a hand-written IR and flat taint engine measured at **2.2% entailment against the CPG's
  41.3%**, still running as a proposer. Vine and Ghidra P-Code are *binary* IRs and do not help here; the
  work is subtraction. A candidate ~1,000-line deletion with a number attached.
* **The missing abstraction is C arithmetic**, and there an existing IR is exactly right. GhidraPAL's
  three-valued-logic abstract interpreter over P-Code decides "can this index exceed this allocation", which
  is the class `c/memory` cannot see and every libpng overflow is. Vine is dormant since 2009 and is not the
  candidate.

The ordering constraint is the point: **question 1 lands before question 2 starts**, or adopting an IR makes
the growth problem worse rather than better.

## After — the feedback loop

11. **`finding-feedback-loop`** (design generated, awaiting approval). Its ledger and dismissals are useful
    immediately; its *evolution* should not be trusted until step 5 or 6 lands a second true-positive
    checkout. The boundary is fixed: an optimiser may evolve the **question**, never the **facts**.

## Not now, and why

- **`authorization-obligations`** (24 open tasks, approved) — the dominance arbiter delivered its substance by
  another route. It should be reconciled or retired rather than worked, and carrying it as "approved, not
  started" misrepresents both.
- **`reachability-flow-model`** (23 open, nothing approved) — largely delivered by adopting Joern. Same
  treatment.
- **`constrained-detector`** (4 of 20, tasks unapproved) — parked.
- **More corpus volume.** 198 of 238 OWASP pairs were left unvendored deliberately: volume without
  readability makes every number worse, and the corpus is not the binding constraint. Reachability is.
- **A second CPG engine, a server mode, an execution rung.** Server mode was measured and declined (6% of a
  scan). The other two have no evidence calling for them yet.

## How to know it is working

The scoreboard in `overview.md`, and one question: **can a developer run this on a repository they did not
write and get something they act on?** Today that is true for one Python application and false for one C
library, and the specs above are ordered by what changes that.

A release is ready when that question is answered **yes for WordPress and honestly for libpng** — found for
the one whose class we decide, and a stated limit for the one we do not. Both are release criteria; only one
of them is a detection claim.
