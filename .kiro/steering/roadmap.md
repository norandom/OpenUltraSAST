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

## Now — make the output worth reading

Everything here is in `contributor-scan`, group 2, and all of it is measurable on the two checkouts that exist.

1. **2.17 — the model's own suspicion band.** vampi emits 61 sections for 520 lines; 38 are a candidate the
   graph could not decide with a judge's opinion attached. Expected: 61 → ~23. Measure what it hides.
2. **2.9 — one defect is one finding.** 26 identical rows for one site. Dedupe on the site, keep the strongest
   rung, record `reached_from`.
3. **2.16 — say what a family cannot decide.** Req 5.6. This is the anti-quiet-failure fix, and it matters
   most for the teaching goal: an LLM handed a silent C scan will fluently explain why the code is fine.
4. **2.8 — a declared-public endpoint carries no obligation.** Removes both remaining vampi false positives.
   Needs the access level's *provenance*, because for decorator frameworks "public" means "no decorator
   found", which is the bug itself.

## Next — reach the named targets

5. **5.1 — PHP fact tables, then a WordPress checkout.** The shortest path to a target the maintainer named,
   and the case this arbiter suits best. Sources, sinks and sanitizers for PHP; entry points for WordPress's
   registration model (`add_action`, `add_filter`, admin-ajax, REST routes) which the mapper already handles
   in principle. **Validate on pairs before pointing it at WordPress** — tables first, corpus second, because
   the other order produces a confident silence.
6. **2.15 / 2.16 — settle `c/memory`.** Either a C checkout whose CVE runs through a sink we model, giving the
   family its first true positive, or the family's scope narrowed and stated. Release criterion 4 needs one
   or the other, and the second is cheap. libpng cannot answer the first; no version of it can.
7. **5.2 — a pinned vibe-code repository.** Still the cheapest *second* true-positive checkout, and the guard
   against tuning everything on vampi. Below PHP now only because it is not a named release target.

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
