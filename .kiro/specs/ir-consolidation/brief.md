# Brief: ir-consolidation — stop maintaining an IR we did not need, and adopt one we do

**Status:** brief only, unapproved.

## Why now

> "we should make sure our code base here doesn't explode. for example we have a custom IR. maybe vine
> (berkely) or another existing IR (rolf rolles had one) ... I know Ghidra has one we could steal"

Two different questions live inside that, and they have opposite answers. Keeping them apart is most of the
value of this brief.

## Question 1 — the source IR we already replaced and never retired

`semantic/` is **3,218 lines, 16% of the codebase**: a hand-written IR (`ir.py`, `cst.py`) and a flat taint
engine (`taint.py`), plus the overlay that runs them. `model-grounded-detection` measured that IR against
Joern's CPG and the result was decisive — **2.2% entailment against 41.3%** — which is why the CPG was
adopted for the model layer. The flat IR was never removed, and still runs as a proposer in every scan.

So the outgrowth is not something we are about to add. It is something already carried.

**Vine and P-Code do not help here.** Both are *binary* IRs — Vine lifts executables (BitBlaze, UC Berkeley,
GPL-2.0, last significant activity 2009), and P-Code lifts machine code. Our source languages are Python,
PHP, JavaScript and Java, and the source IR we should adopt is the one we already have. The work is
subtraction, not substitution:

- Can the CPG serve the overlay's job at equal or better recall?
- What does deleting `semantic/`'s IR and taint cost, measured on the pair corpus and both repositories?
- What has to stay? `obligations/` reads the same facts and is a different analysis.

A candidate ~1,000-line deletion with a number attached, which is the only kind worth doing.

## Question 2 — the abstraction we are missing, where an existing IR is exactly right

`c/memory` has produced **zero true positives** and three distinct classes of false one. The reason is
structural and now stated in the report (Req 5.6): it models unbounded string CALLS, while real C overflows
are *arithmetic* — an index, a pointer offset, a `memcpy` whose size is computed. Every one of libpng's is,
and its library code never calls a modelled string API at all.

"Can this expression exceed this allocation" is a value question, not a reachability one. **Rolf Rolles'
GhidraPAL carries a three-valued-logic abstract interpreter over Ghidra P-Code** — each bit definite 0,
definite 1, or unknown, with abstract transformers for `INT_ADD`, `INT_MULT`, `INT_AND`, the comparisons —
validated against concrete execution in its own tests. That is precisely the shape of analysis the C family
lacks, and it exists.

It is also the honest answer to a decision this project already took. `model-grounded-detection` chose
abstract interpretation over SMT, and chose to build the model from code because execution cannot be
assumed. A bit-level abstract interpreter over P-Code is *still abstract interpretation* and still static —
what changes is the artifact: it needs a **built** library rather than its source.

## What this brief must decide

1. Whether the source-IR subtraction is safe, measured rather than assumed.
2. Whether the C arithmetic class is worth a second pipeline at all, or whether `c/memory` stays scoped to
   string misuse and says so — which is where task 2.16 left it, deliberately.
3. If it is worth it: P-Code with a TVL domain, adapting GhidraPAL's transformers, versus writing one. Vine
   is dormant since 2009 and is not the candidate; Ghidra is maintained and P-Code has tooling.
4. What a second pipeline costs in the one currency this project has been strict about — **not lines, but
   the number of things that can silently return nothing.** This session found three separate quiet failures
   in one PHP scan. A binary pipeline adds a build step, a lifter, and a domain, each of which can produce
   an empty result that looks like a clean one.

## The constraint that governs it

Nothing here may grow the codebase without a measurement that justifies it, and the module audit
(`benchmarks/measurements/2026-09-08-module-audit.json`, currently 97 modules with no orphans) is the
instrument. A brief that ends in "adopt P-Code" and 3,000 new lines while `semantic/` still carries 3,218
has made the problem worse, not better. **Question 1 should land before Question 2 starts.**
