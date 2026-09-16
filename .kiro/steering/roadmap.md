# Roadmap

## Current release path — 2026-09-14

Build an actionable pre-push security safety net for AI-accelerated development.
The maintainer accepted the following order: **prove one useful detection, make it
fast, prove cross-language transfer, qualify independently, then enable narrow advisory
rollout**. The executable outcome contract lives in the existing
[pre-push-safety-net release milestone spec](../specs/pre-push-safety-net/release-milestones.md).

**We are at M1b. M1a is met; no other release milestone is verified yet.** The published
`v1.2.0-alpha.1` and 28/29 completed implementation tasks describe delivered machinery,
not a demonstrated useful safety net. Task 8.3 and rollout remain NO-GO.

| Order | Milestone | Observable exit | Current state |
|---|---|---|---|
| M1a | Show the NodeGoat detection with every admission veto recorded, not applied | Raw finding with witness on the vulnerable revision; analyzed fixed twin and unchanged control quiet; per-finding veto list. One-week time box | MET 2026-09-16 |
| M1b | Repair only the vetoes M1a showed to matter | Supported evaluation finding through production rules, exact change/base evidence and repair direction; fixed twin and unchanged control stay quiet | IN PROGRESS: every recorded veto repaired and the production comparison classifies all three revisions; 10.7-10.9 remain |
| M2 | Make that same analysis fast | Equivalent evidence; representative warm changed-code p95 <=30s, cancellation/report <=2s, >=95% supported completion | Pending M1 |
| M3 | Prove the shared design transfers | PMPro/PHP and VAmPI/Python vulnerable/fixed evidence; unchanged core rules; Node replay after any PMPro core change | Pending M2 |
| M4 | Qualify on independent cases | Reviewed untouched vulnerable/fixed/benign populations pass joint quality, coverage and latency gates per capability | Pending M3 |
| M5 | Enable a narrow advisory rollout | Exact passing eligibility and packaged acceptance; only qualified capabilities enabled | Pending M4 |

### Immediate next action

Finish M1b: bind candidate dependency gaps to the candidate (10.7), carry query-to-operation
provenance (10.8), then rerun and record the three NodeGoat revisions as the milestone's exit
evidence (10.9). Every veto M1a recorded is repaired and the production comparison already
classifies all three revisions correctly, with production and the recorded view agreeing. The
dependency-gap defect is coarse plumbing rather than a comparison failure, but it would block
admission forever once capabilities qualify, so it belongs before M4. Normal hook eligibility
stays disabled and no capability is enabled by any of this.
Do not start another broad speed campaign before this outcome exists. See the
[M1a evidence](../specs/pre-push-safety-net/m1a-recorded-vetoes.md) and the
[owner diagnosis](../specs/contributor-scan/release-remediation-research.md).

### Approach and boundaries

The existing ranker owns scope. Vendor code stays out of targets and graphs. Framework
facts and frontends supply evidence to a language-agnostic core. Unknown dependencies
remain explicit; removing global completeness vetoes requires question-owned evidence,
not dropped safety checks. Advisory and blocking share the same actionability bar.

Graph persistence now works: identical-tip replays take 18.5–18.9s. All 18 other measured
transactions still time out and 0/24 target checks complete. A local Joern session census
probe is promising, but full-query equivalence and hook performance are unverified.
These findings inform M2; they do not complete M1. No second IR/engine, new heuristic
scope selector, differential graph mutation or unrelated backlog is part of this path.

## Existing Spec Updates

- [ ] pre-push-safety-net — Execute the accepted M1–M5 release milestone amendment.
  Owns immutable replay, comparison, admission, evaluation and reporting. Preserve the
  existing completed tasks; task 8.3 remains blocked until qualification passes.
- [ ] contributor-scan — Supply the required query/operation/context fixes for M1,
  followed by equivalent bounded session execution for M2 and shared transfer evidence.
  Frontend retention 2.18 and named census repair 2.19 are already verified.
- [ ] flow-aware-ranking — Preserve ranker-owned scope and normalized cross-language
  behavior. New ranking research is not a prerequisite for the first useful comparison.
- [ ] zero-with-a-reason — Adjacent diagnostics work; finishing its whole backlog is
  not required before M1.

## Specs (dependency order)

- [ ] pre-push-safety-net — Existing approved implementation, dependent on contributor-scan.
  Groups 1–7 and tasks 8.1, 8.2, 8.4 are verified; 26/27 executable tasks complete.
  Remaining release work follows [M1–M5](../specs/pre-push-safety-net/release-milestones.md).
  This amendment creates no duplicate implementation spec and resets no prior approvals.

### Progress reporting

Lead with the current milestone, the demonstrated developer outcome, the blocker and
the next action. Keep implementation counts separate from release readiness. Preserve
prior evidence and review limits in the [implementation records](../specs/pre-push-safety-net/status.md).
The earlier PHP-first and runtime-first narrative below is historical and does not
supersede this accepted sequence. Blocking deployment follows a later explicit decision.

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
