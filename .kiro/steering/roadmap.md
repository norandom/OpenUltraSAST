# Roadmap

**Rewritten 2026-09-09.** The previous version (kept as `roadmap-2026-09-04.md`) described a pre-Joern world —
"adjudication is still Python-`ast` plus a tree-sitter CLI stub", "Joern-as-required deferred". Joern was
adopted, the model layer was built, wired and measured, and two repositories have been scanned. See
`overview.md` for what is true today; this is what happens next and in what order.

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

## Next — make it find more, in the cheapest order

5. **5.2 — a pinned vibe-code repository.** The cheapest route to a *second* checkout that can produce a true
   positive, because Python and JavaScript are the two languages whose fact tables are complete. Everything
   downstream is tuned on two repositories until this lands.
6. **2.15 — a C checkout whose CVE goes through a sink we model.** Decides whether `c/memory` earns its place
   or gets scoped (2.16). libpng cannot answer this; no version of it can.
7. **5.1 — PHP fact tables, then WordPress.** `php2cpg` exists; our PHP families are empty. Tables first,
   corpus second — the other order produces a confident silence.

## Then — close the deferred engine questions

8. **2.14 — control dependence.** Absent from both CPGs, so every guard question runs on CFG dominance. Find
   out whether Joern's CDG pass can be applied from the query script and what it costs. If it cannot, that is
   a real bound on what this engine can reason about and should be recorded as one.
9. **2.13 — a destination allocated to size.** Deliberately blocked on 6, so the rule can be measured for what
   it *silences* as well as what it clears.
10. **Group 3–4 — ship it.** Contributor output, the Docker image, the memory-family decision, retiring
    `evidence_level` now that the rung carries the meaning.

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
