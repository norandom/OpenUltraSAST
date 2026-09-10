# Roadmap

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
