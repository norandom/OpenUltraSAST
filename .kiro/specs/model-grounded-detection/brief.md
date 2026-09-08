# Corrective brief: model-grounded detection

> **Renamed from `model-grounded-detection` after the maintainer's correction (2026-09-08):** "execution
> isn't possible for all types of projects. I'd see a model layer instead, which can be built up from code.
> given that we are in a SAST project. I see dynamic testing later, but only if it's needed." Execution is one
> arbiter, and the easy one only for memory-safety-in-C. This project's arbiter is a **program model built
> deterministically from code**; execution is a later, conditional tier. The correction is integrated below.

**Status:** course-setting. Supersedes `learning-harness` and `constrained-detector`. Not a requirements
document — a decision about what to build, what to delete, and what to adopt, written after the
learning-harness line produced numbers its own measurements say to discard.

## 1. The premise we got wrong

OpenUltraSAST was built on an unstated assumption: that an LLM is a *noisy oracle* whose judgement must be
averaged (K runs), floored (per-family noise budget), gated (sign test), and slowly improved (evolve loop).
Every mechanism in `learning-harness` follows from that assumption. This session measured all of it and it
does not hold:

- Five evolve rounds, $2.17, **zero decisions distinguishable from chance** — because the acceptance rule
  compares two ensemble votes over a detector that never runs the same investigation twice.
- 120 runs of one detector produced **120 distinct trajectories**. The variance is the loop's freedom to
  search, not the model's uncertainty about an answer.
- The noise floor a regression budget is derived from measures *how often an unconstrained search happens
  to reach the sink* — so the worse the search wanders, the more collateral damage a round is licensed to do.

The assumption is also empirically false as a claim about LLMs, and the evidence is now overwhelming:

- **Google Big Sleep** (Nov 2024): the first LLM-discovered zero-day in widely-used real-world software — a
  stack buffer underflow in SQLite — found by *variant analysis*, a sandboxed test case, and an
  auto-generated root-cause report. Not pattern-matching; reproduction.
- **DARPA AIxCC finals** (DEF CON 33, Aug 2025): seven autonomous systems processed 54M lines of code,
  patched 43 of 54 synthetic vulnerabilities and **uncovered 18 previously-unknown real 0-days**. Buttercup
  (Trail of Bits, 2nd place) found **28 vulnerabilities across 20 CWEs at 90% accuracy, $181 per point,
  using non-reasoning LLMs only**, ~$152 per task, 45 minutes each.

The lever in every one of those systems is **architecture, not prompt optimization**. Buttercup won with
non-reasoning models. Nobody evolved a prompt with a genetic loop. The question "can LLMs find security
bugs" was answered *yes* by 2024; we spent this project answering a question the field had closed, with the
wrong architecture.

## 2. What the successful systems share, and Clearwing is the open one

Big Sleep, Atlantis (AIxCC 1st), Buttercup (2nd), and **Clearwing** (`/home/mc/Source/clearwing`,
Lazarus-AI, MIT, an open reproduction of Anthropic's Glasswing) share one shape:

> **The LLM is a judgement layer on top of a deterministic substrate that arbitrates its claims. Truth comes
> from that substrate, not from a score against a labeled corpus.**

In the memory-safety systems above the substrate is *execution* — a crash is the arbiter. But execution is
only the arbiter you reach for when the target builds in isolation and the bug crashes, which is the C world,
not ours. The general form of the substrate is a **program model built from the code**: a deterministic
abstraction rich enough to *check* a claim — does the source actually reach the sink through resolved
dataflow; is there a guard on the path or isn't there; is the entry point attacker-reachable. Execution is one
way to arbitrate; a model is the way that works for a SAST project and for bugs that never crash.

Clearwing's evidence ladder is the whole thesis in one type:

```
suspicion → static_corroboration → crash_reproduced → root_cause_explained
          → exploit_demonstrated → patch_validated
```

The load-bearing gate is `poc_runner.py`: apply a candidate diff inside the sandbox, recompile, re-run the
PoC, and return a boolean for *does the crash still happen*. That single primitive replaces our entire
noise architecture. You do not average five noisy runs when a container can tell you whether the bug is
real. **We built K-runs and noise floors because we had no ground truth. They generate their own.**

## 3. What Clearwing does better, mapped to what failed here

| Our failure this session | What Clearwing does instead |
|---|---|
| K-runs / noise floor / sign test / regression budget — a statistical treatment for a structural problem | **Execution is the arbiter.** `poc_runner` reproduces or it doesn't. `stability.py` runs the PoC across N fresh containers (≥90% = stable) to kill flakiness at the source instead of averaging it. |
| Evolve loop: 5 rounds, 0 reliable decisions, $2.17 to learn nothing | **A fixed specialist roster** dispatched by file tags — `memory_safety`, `kernel_syscall`, `crypto_primitive`, `web_framework`, `logic_auth`, `general` — plus **variant analysis** (verify a bug, generate a grep+semantic pattern, find its structural twins, iterate to fixpoint). Density compounds *within a run*, no optimizer. |
| Second judge / fusion, gesturing at independence | **4-axis adversarial validator** (REAL / TRIGGERABLE / IMPACTFUL / GENERAL) that sees *only* the finding, PoC and exploit — never the discovery transcript — steel-mans both sides, and **must attempt reproduction**. |
| Corpus: 12 hand-harvested function excerpts per family, scored by text-inside-function, capped by twins/straddles/truncation defects we spent days repairing | **Corpus is real repos at vulnerable-parent commits + OSS-Fuzz** (7000 targets in `full` mode), run blind, with the fix commit used only as an *after-the-fact oracle*. Truth is generated by the sandbox, not annotated by us. `CampaignConfig` scales this to hundreds of repos with shared budget, checkpoint/resume, and diminishing-returns detection. |
| Detector chooses what to look at (555 grep calls vs 71 entry-point lookups) | **Deterministic preprocessing feeds candidates:** callgraph → intra-procedural taint (source→sink) → 3-axis ranker → hunter. The model judges; it does not search for the sink. This is exactly the `constrained-detector` design we had started — Clearwing is the mature version of it. |

## 4. The one thing OpenUltraSAST proved that Clearwing lacks

This is not a total loss, and the course is not "throw everything away." Two results here are real,
measured, and *absent from Clearwing*:

1. **IR-driven candidate enumeration with a published ceiling.** We measured that the pattern ruleset caps
   recall at 12.1% while call-sites-and-bindings from the semantic IR reach **96.6%** across the web slices,
   a median of ten sites per function. Clearwing's candidate feeder is C-first (taint tables for
   `memcpy`-shaped bugs); its `web_framework` specialist is a *single unconstrained prompt* with no
   equivalent candidate enumerator for logic/web classes.

2. **Absence-bug detection.** Our `obligations` work — an access-control bug is the *absence* of a guard
   around an operation its siblings protect — has no analogue in Clearwing, whose ladder is built around a
   *crash*. An IDOR or a missing authorization check never crashes a sandbox. Clearwing's execution
   ground-truth model does not reach these classes at all, and they are exactly the "dangerous but
   low-hanging" web bugs this project was chartered to catch.

So the gap Clearwing leaves open is **the web/logic taxonomy without a crash oracle** — which is where our
IR candidate enumerator, our family taxonomy, and our obligation checker are genuinely ahead.

## 4b. The model layer, and the evidence ladder it produces

The arbiter is a program model constructed deterministically from the code — the thing an LLM claim is
*checked against*, so that a finding's truth does not rest on the LLM that proposed it. We already hold the
first rungs of it; they were buried under a noise layer instead of being made the arbiter.

The evidence ladder is the model layer made legible. Each rung is a stronger, still-deterministic statement:

| rung | what it means | who establishes it | we have |
|---|---|---|---|
| `suspicion` | the model enumerated a candidate site; the LLM flagged it | IR enumeration + LLM | yes (candidate enumerator, 96.6% ceiling) |
| `model_corroborated` | the LLM's claim is *consistent* with the model — the source it names reaches the sink it names through a resolved binding/dataflow path; or the operation it flags lacks a discharging guard its siblings carry | model checks the LLM's assertion | partial (binding chains, obligation facts) |
| `model_entailed` | the model *itself* establishes it, independent of trusting the LLM — a concrete source→sink path with no sanitizer node; a provably-absent guard among a sibling set that carries it | model alone | to build (interprocedural dataflow + guard dominance) |
| `execution_confirmed` | a sandbox reproduced it — a crash, or a differential request the fixed twin rejects | execution substrate (deferred tier) | Clearwing, later, only where needed |

Two properties are the whole point:

- **`model_corroborated` and above are deterministic.** Run the checker twice over the same model and it
  returns the same verdict. That removes the run-to-run noise the same way a crash would — no K-runs, no
  floor, no sign test — *without needing a runnable target*. The noise this session measured was the LLM
  free-searching; a model check does not search.
- **The LLM's job shrinks to the residual the model cannot decide** — is this string genuinely
  attacker-controlled, is this guard semantically sufficient — and even that answer is checked against the
  model rather than averaged over runs. The LLM stops being the oracle and becomes a proposer the model
  audits.

**Measured, 2026-09-08 — the entailment ceiling** (`benchmarks/measurements/2026-09-08-model-entailment-ceiling.json`,
offline, no LLM):

| rung | web/logic taxonomy | for comparison |
|---|---|---|
| `model_entailed` today | **2.2%** (2/92) | — |
| `model_corroborated`, one-hop taint | **24%** (22/92) | — |
| taint reachable, multi-hop (flow families) | **35%** (26/74) | — |
| candidate site enumerable | — | **96.6%** (constrained-detector group 1) |

The gap between 96.6% (a site exists) and 2.2% (the model *decides* the vulnerability) is the gap between
enumerating and arbitrating, and it is the whole finding. The model cannot be a *pure* arbiter at v1. But it
is not a wall — the measurement diagnoses depth, not impossibility: one-hop source resolution (real taint sits
1–3 binds upstream: `q = "…" + id; execute(q)`), a closed literal sink table (misses project wrappers and the
path/xss/prototype sinks), and the function-naming gap that eats 20/50 injection pairs as `no_function`.
Deepening the taint to reuse the candidate enumerator's depth-4 chain already moved injection 24% → 48%.

So the architecture the numbers support is a **layered arbiter**, not a pure one:

- where the model **entails** — report `model_entailed`, deterministic, the LLM not needed;
- where the model **corroborates a taint path** (~35% and rising) — the LLM judges, but its claim is *checked*
  against the resolved path, so run-to-run noise is removed on this band;
- where the model can only **enumerate** (the rest, up to 96.6%) — honest `suspicion`, the LLM proposes with
  no deterministic backstop, and this is exactly the band where the deferred execution / differential tier
  earns its place.

Pure `model_entailed`-as-arbiter is the north star. The v1 is the layered arbiter, and the near-term work is
named by the measurement: fix function naming, build per-family sink/sanitizer tables, and lift the flow
model onto the multi-hop binding chain we already have.

This is the classical SAST arbiter — dataflow / abstract interpretation, the CodeQL and Infer lineage —
with the LLM supplying the semantic judgement the model is weakest at (aliasing intent, whether a value is
really untrusted, whether a guard really covers the case). It does not need soundness. A partial model that
can confirm *some* claims and honestly returns "could not confirm — stays suspicion" for the rest is already
the independent arbiter we never had.

## 4c. IL or AST, build or adopt — the substrate decision

**IL, and adopt one.** Both halves are forced by the entailment measurement.

*Why an IL, not the AST we have.* Our `semantic/ir.py` is not an IL — it is a lossy AST projection: per-function
flat lists of calls and binds, no control-flow graph, no basic blocks, no data-dependence edges. That is
*why* entailment sits at 2.2%. Real abstract interpretation is a fixpoint over a **CFG**: guard *dominance*
(is the check on every path to the operation) is a dominator-tree question, and path-sensitive taint (a
sanitizer on the taint path specifically) needs the branch structure. A flat bind list cannot express either;
it can only over-approximate taint flow-insensitively by name, which is the one-hop ceiling we measured. The
model layer wants the classical IL that merges AST + CFG + PDG + call graph into one graph — a **Code Property
Graph (CPG)** — over which taint is a reachability query (source → sink minus sanitizer) and absence is a
dominance query.

*Why adopt, not build.* Building a multi-language CFG/PDG/taint engine on top of tree-sitter is precisely
reinventing CodeQL, Semgrep and Joern — a multi-year effort, and the maximal case of the failure mode this
session logged eighteen times. **Joern** is the adoptable answer: Apache-2.0, a CPG engine for exactly our
corpus (C/C++/Java/JavaScript/Python/Kotlin/binary), a built-in taint-propagation engine, embeddable, and
there is already a published CPG-plus-LLM bridge (Codebadger, an MCP server over Joern) and an arXiv line on
CPGs as the substrate for LLM program analysis. Joern *is* "a model built up from code" as a graph — the exact
thing the maintainer described. The alternatives: CodeQL is more powerful but least adoptable (restrictive
license, query-only, GitHub-owned); Semgrep's taint engine is lighter and we already have integration
precedent through Clearwing's sidecar, but interprocedural taint is behind the paid Pro engine.

*The flow, concretely:*

```
source ──▶ Joern: compile to CPG (one IL: AST + CFG + PDG + call graph, language-agnostic)
        ──▶ taint reachability (source→sink − sanitizer)  +  CFG dominance (absence)
        ──▶ deterministic verdict: model_entailed | model_corroborated | (neither) suspicion
        ──▶ LLM judges the residual, its claim CHECKED against the CPG
```

The CPG is language-agnostic once its frontend exists, so the taint and dominance logic is written *once*, not
per language — which is the whole reason our per-language tree-sitter approach kept hitting naming and grammar
gaps.

*What stays ours, and is the contribution.* Joern is a workbench, not an opinionated web/logic detector with
an LLM judge. What we own and port onto it: the closed **family taxonomy**; the **source / sink / sanitizer /
guard models** for the web/logic CWEs — our obligation facts and closed guard vocabulary become CPG queries
and taint specifications; and the **LLM-adjudication-checked-against-the-CPG** orchestration. That security
modelling — expressed as queries over an adopted CPG — is where our work is genuinely ahead of both Joern
(no opinion on these classes) and Clearwing (crash-oracle, no arbiter for bugs that do not crash).

*The one real cost.* Joern is JVM/Scala; embedding it in a Python tool means its server mode or the MCP bridge,
not an in-process call. That is an integration cost, named, and far below the cost of building the engine.

## 5. The course

**Build the model layer up from the code as the arbiter; make the LLM a proposer the model audits; delete the
noise architecture; keep execution as a later, conditional tier.**

Concretely, superseding both prior specs:

1. **Delete, do not fix.** The K-run machinery, the per-family noise floor, the regression budget, the sign
   test, the evolve loop, the acceptance rule, the mechanism-lever optimizer. All of it existed to average an
   LLM oracle we could not otherwise trust. A deterministic model arbiter removes the need for every piece.
   `learning-harness` Req 3.5, 8.2, 9.5 and the evolve tasks are retired, not amended.

2. **Adopt a CPG engine (Joern) as the arbiter substrate; port our security models onto it.** We do not lift
   our flat IR to a CFG ourselves (§4c). The taxonomy, the source/sink/sanitizer/guard models, and the
   obligation/absence logic move from prompt context to **CPG taint specifications and dominance queries** —
   deterministic `model_corroborated` and `model_entailed` verdicts over an engine that already has the CFG
   and PDG our IR lacks. Our tree-sitter IR retains one job: cheap candidate enumeration for the `suspicion`
   band where the CPG has no verdict.

3. **The LLM proposes; the model disposes.** One bounded, typed question per candidate — the constrained
   detector we already started — but the answer is not scored against a corpus, it is *checked against the
   model*. A claim the model corroborates advances; a claim it contradicts is dropped with the contradiction
   recorded; a claim it can neither confirm nor deny stays `suspicion` and is reported as such. No K-runs, no
   evolve loop.

4. **Corpus is the model's calibration set, not the LLM's training signal.** Keep the vulnerable-parent /
   fix-commit pairs — but their role changes. The pair is ground truth for *the model's precision*: the fix
   is what the model should be able to see (a guard added, a sanitizer inserted, a bound checked), and a pair
   the model cannot distinguish is a gap in the model, named and measured, not a detector miss to average.
   Harvest more pairs at repository scale from CVE history, as Clearwing does; truth is the fix diff read by
   the model, not a label we hand-assign.

5. **Execution is a deferred, conditional tier.** For the classes a static model genuinely cannot arbitrate —
   memory-safety-in-C, where reachability and exploitability turn on runtime layout — a sandbox crash oracle
   is the right arbiter, and Clearwing already is that system. Adopt it *there*, later, only when a class
   needs it. It is the `execution_confirmed` rung, not the foundation.

6. **Reporting keeps the honesty disciplines that stand:** per-slice numbers with the real-world slice
   deciding, the overfitting gap published, and the evidence rung on every finding — now meaning a model
   verdict, not a sandbox result.

## 6. Build vs. adopt, revised

The earlier draft of this brief over-rotated to "adopt Clearwing wholesale," because the external evidence
foregrounds execution. The maintainer's correction re-centres it, and the honest split is cleaner than either
extreme:

- **The model layer is adopt-plus-contribute, not build.** The arbiter *engine* is Joern's CPG (Apache-2.0,
  our languages, taint + dominance built in); the *contribution* is our security modelling on top of it — the
  taxonomy and the source/sink/sanitizer/guard specs for the web/logic classes, plus the LLM adjudication
  checked against the CPG. The entailment measurement (2.2% on our flat IR) is what rules out building the
  engine ourselves: that number is the distance between our AST projection and a real CPG, and closing it by
  hand is reimplementing Joern.
- **The execution tier is Clearwing's to adopt**, later, for the memory-safety classes where it is strong and
  we are weak — via the fork the maintainer already maintains. We do not reimplement its sandbox lifecycle,
  container pooling, sanitizer images or PoC stability; those are exactly the parts this session proved we get
  wrong.

So neither "rebuild everything" nor "throw our work away." Build the arbiter we can build from code; adopt the
arbiter we cannot, when a class demands it.

## Open questions for the requirements phase

- **How far up the ladder can a partial model reach without soundness?** `model_corroborated` needs only a
  consistency check; `model_entailed` needs a real interprocedural dataflow/guard-dominance result. What
  fraction of our corpus can the model *entail* today, and where does it honestly fall back to `suspicion`?
  This is the first measurement to run — the model analogue of the 96.6% candidate ceiling — and it can end
  or reshape the design before any LLM cost, exactly as the ceiling did.
- **What is the model's arbiter for an absence bug?** A missing guard has no dataflow path to confirm. The
  obligation/sibling-dominance model is the candidate arbiter; does it distinguish the vulnerable-parent from
  the fixed twin across the corpus on its own, deterministically?
- **Where does the LLM's residual judgement resist checking?** Some claims — "this value is attacker-
  controlled by convention", "this guard is semantically insufficient" — the model cannot audit. How large is
  that residual, and is `suspicion` an acceptable home for it or does it need the execution tier sooner?
- **Which classes cross into execution, and when.** Memory-safety-in-C is the clear case for the deferred
  tier. Is anything in the web/logic taxonomy genuinely un-arbitrable by a model, forcing the differential
  request oracle earlier than "later, if needed"?
- **What of the existing corpus survives** as the model's calibration set, given the twin/straddle/tier
  defects the learning-harness reviews surfaced?

Sources: [Big Sleep / SQLite zero-day](https://thehackernews.com/2024/11/googles-ai-tool-big-sleep-finds-zero.html) ·
[AIxCC finals — Buttercup, 28 vulns / 20 CWEs / non-reasoning LLMs](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/) ·
[AIxCC results — 18 real 0-days, 43/54 patched](https://semiengineering.com/aixcc-2025-what-it-means-for-device-security/) ·
[Clearwing](https://github.com/Lazarus-AI/clearwing) · local: `/home/mc/Source/clearwing`, fork `norandom/deepwing`.
