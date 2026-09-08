# Requirements Document: model-grounded-detection

## Introduction

This feature supersedes `learning-harness` and `constrained-detector`. It replaces the assumption that the LLM
is a noisy oracle to be averaged, floored and gated with an architecture in which a **deterministic program
model arbitrates the LLM's claims**. The arbiter is a Code Property Graph (CPG) — an intermediate language
merging AST, control-flow graph, program-dependence graph and call graph — over which taint reachability and
guard dominance produce verdicts the LLM's assertion is no longer needed for. The measurements that force this
design are committed: the candidate ceiling (96.6% of labeled functions have an enumerable site), and the
entailment ceiling (a deterministic model *decides* only 2.2% today on our flat AST-projection IR, ~24-35%
with deeper taint — the distance to a real CPG). Context: `brief.md`,
`benchmarks/measurements/2026-09-06-trajectory-divergence.json`, `2026-09-06-candidate-ceiling-all-slices.json`,
`2026-09-08-model-entailment-ceiling.json`.

The project has an outgrowth problem: 99 source modules and 832 tests, a large fraction implementing the noise
architecture this feature discards. **Subtraction comes first.** The dead layer is removed and the test suite
reduced to what protects surviving behavior before the CPG arbiter is adopted, because building on top of an
overgrown, superseded surface is how this session logged eighteen defects.

## Boundary Context

- **In scope**: removing the noise architecture and the superseded arbiter; reducing the test suite to
  surviving behavior; auditing the whole tree for orphaned modules; adopting a CPG engine (Joern) as the
  model-layer substrate behind an optional extra; the evidence ladder as the verdict type; taint + dominance
  verdicts; porting our taxonomy and source/sink/sanitizer/guard models to the CPG; the LLM as a proposer
  checked against the model; the corpus as the model's calibration set; per-slice reporting.
- **Out of scope**: building a dataflow/CFG engine by hand (the CPG is adopted, §Req 4); the execution tier
  itself (deferred to Clearwing, `execution_confirmed` rung only, Req 10); prompt optimisation, reflective
  evolution, any optimiser (deleted, not deferred); fine-tuning weights.
- **North star, not v1**: pure `model_entailed`-as-arbiter. The entailment ceiling says the model decides a
  minority today; v1 is the *layered* arbiter (entail where it can, corroborate the taint band, honest
  suspicion for the rest). This is stated so the requirements are not read as promising a soundness the
  measurement denies.

## Requirements

### Requirement 1: Subtract the noise architecture

**Objective:** As a maintainer, I want the machinery built to average and gate an LLM oracle removed entirely,
so that nothing is maintained, tested, or built upon that this feature's measurements say is the wrong shape.

#### Acceptance Criteria

1. The system shall remove the round loop, the per-family noise floor, the regression budget, the acceptance
   rule, the sign test, the evolve journal and the meta-agent proposer — concretely `learning/rounds.py`,
   `learning/acceptance.py`, `learning/proposer.py`, `learning/journal.py`, and the K-run / floor / sign-test
   machinery in `learning/scoring.py`.
2. The system shall remove the mechanism-optimisation loop — the mechanism store and lever in
   `improve/evolve.py`, and the shape-search machinery in `semantic/mechanisms.py` and the optimisation
   surface of `semantic/variants.py` — while preserving the *security models* those modules carried (the
   guard vocabulary and source/sink classification) for porting under Req 7.
2b. The system shall remove the per-family evolvable detector configuration and its canary/verifier surface
   (`learning/detectors.py` config-evolution parts, `learning/canaries.py`, `learning/verifiers.py`,
   `learning/difficulty.py`) except where a component is retained by name under Req 6, 7 or 8.
3. When a module is removed, no surviving module shall import it, and a static check shall confirm no dangling
   import remains.
4. The detection, map and local pair gate outputs shall stay byte-identical to the committed baseline after
   the removal, since the removed modules are absent from the gate path.
5. The system shall record, for every removed module, one line stating what replaced it or why nothing did.

### Requirement 2: Reduce the test suite to what protects surviving behavior

**Objective:** As a maintainer, I want the test suite to shrink with the code, so that tests stop being a
ratchet that pins deleted mechanisms and the suite is once again a description of what matters.

#### Acceptance Criteria

1. When a mechanism is removed under Req 1, the tests that existed only to pin its behavior shall be removed
   with it, in the same change, not left skipped or xfailed.
2. Every surviving test shall map to a surviving requirement — of this spec or of a still-shipping feature —
   and a test that maps to nothing shall be removed.
3. The reduced suite shall be smaller than the current 832 tests, and the change shall report the count before
   and after with the requirement each removed test cluster served.
4. The system shall keep as the non-negotiable floor: the three gate-baseline tests, the redaction tests, the
   determinism test (Req 6.4), the per-slice honesty tests, and the two ceiling measurements' regeneration
   tests.
5. A test that asserts a shape "does nothing" or greps `--help`, or that passes with its capability absent,
   shall be removed rather than kept — the session logged several; none survive.

### Requirement 3: Audit the whole tree for outgrowth

**Objective:** As a maintainer, I want every module classified, so that orphaned code from earlier phases is
found and removed rather than carried indefinitely.

#### Acceptance Criteria

1. The system shall classify every source module as one of: load-bearing for the model-grounded architecture;
   a retained standalone capability with its own users; or orphaned.
2. If a module is orphaned — no importer, no CLI entry, no gate dependency, no surviving requirement — then the
   system shall remove it and record the classification.
3. The system shall name, for the audit, the older-phase subsystems whose status is not obvious
   (`fusion.py`, `mcp.py`, `skills.py`, `harness_ext.py`, `hunter_harness.py`) and give each an explicit
   keep-or-remove decision with its reason, rather than leaving them unexamined.
4. The audit result shall be committed as a manifest that a later reader can check the tree against.

### Requirement 4: Adopt a CPG engine as the arbiter substrate

**Objective:** As a maintainer, I want the model layer built on an adopted Code Property Graph engine, not on
a hand-built dataflow engine, so that the CFG and PDG our flat IR lacks come from a mature substrate.

#### Acceptance Criteria

1. The system shall compile a target to a Code Property Graph via an adopted engine (Joern, Apache-2.0),
   producing AST, control-flow, program-dependence and call-graph relations over one queryable graph.
2. The CPG engine shall sit behind an optional extra; the core install shall remain zero-dependency
   (`dependencies = []`).
3. Without the CPG engine, the system shall degrade every model verdict to `suspicion` and record the reason,
   never crash and never fall back to the flat IR as if it were an arbiter.
4. The system shall not build a control-flow or program-dependence engine of its own; the flat tree-sitter IR
   is retained only for candidate enumeration in the `suspicion` band (Req 8.4).
5. The system shall record the named integration cost (the engine is JVM/Scala; access is via its server mode
   or an MCP bridge, not an in-process call) and isolate it behind one seam.

### Requirement 5: The evidence ladder is the verdict type

**Objective:** As a maintainer, I want every finding to carry what established it, so that a deterministic
model result is never confused with an LLM suspicion.

#### Acceptance Criteria

1. The system shall assign every finding one rung: `suspicion` (a site was enumerated / the LLM flagged it),
   `model_corroborated` (the LLM's claim is consistent with the CPG — the source it names reaches the sink
   through resolved dataflow, or a guard its siblings carry is absent), `model_entailed` (the CPG alone
   establishes it, independent of trusting the LLM), or `execution_confirmed` (a sandbox reproduced it).
2. The system shall establish `model_corroborated` and `model_entailed` from the CPG deterministically, with
   no model call in the establishing step.
3. The system shall report the rung on every finding in every output format.
4. The system shall never report a claim above `suspicion` on the strength of the LLM alone.

### Requirement 6: Deterministic verdicts from taint reachability and guard dominance

**Objective:** As a maintainer, I want the model verdicts to be reproducible, so that the run-to-run noise the
project measured is removed on the band the model covers.

#### Acceptance Criteria

1. The system shall establish a flow-family verdict by taint reachability over the CPG: a source reaching the
   labeled sink through data-dependence, minus any sanitizer node on the path.
2. The system shall establish an access-control (absence) verdict by dominance over the CFG: whether a
   discharging guard dominates the operation on every path.
3. The system shall establish a configuration verdict by constant/abstract-value evaluation of the binding.
4. When the system runs the model layer twice over the same CPG, the sequence of verdicts shall be identical,
   and a test shall assert it.
5. The system shall report, per family and per slice, the fraction of the corpus it can `model_entail` and
   `model_corroborate` — the regeneration of the committed entailment ceiling — and shall name where it falls
   back to `suspicion`.

### Requirement 7: Port the taxonomy and security models onto the CPG

**Objective:** As a maintainer, I want our security knowledge — the classes we target and how their bugs look
— expressed as queries over the adopted CPG, so that the contribution is the modelling, not the engine.

#### Acceptance Criteria

1. The system shall retain the closed family taxonomy as the routing key, unchanged in meaning.
2. The system shall express the source, sink and sanitizer models for the web/logic CWEs as CPG taint
   specifications, seeded from the models the deleted modules carried.
3. The system shall express the obligation / absence model — an operation on a protected resource, and the
   guards that discharge it — as CPG dominance queries, as the arbiter for the classes that never crash.
4. The system shall keep the verifier boundary: the models and gold labels stay outside anything an LLM or a
   future optimiser may write.

### Requirement 8: The LLM proposes; the model disposes

**Objective:** As a maintainer, I want the LLM's role reduced to the residual judgement the model cannot make,
with its claim checked against the model, so that there is no oracle to average.

#### Acceptance Criteria

1. The system shall ask the LLM one bounded, typed question per candidate, offering it no freedom to search
   for the site.
2. When the model contradicts the LLM's claim, the system shall drop the claim and record the contradiction.
3. When the model corroborates the LLM's claim, the system shall advance the finding to at least
   `model_corroborated`.
4. When the model can neither confirm nor contradict, the system shall report the claim at `suspicion`, and
   this band is where a future execution tier earns its place.
5. The system shall contain no K-run averaging, no noise floor, no acceptance rule, no evolve loop — the model
   check replaces all of them.

### Requirement 9: The corpus is the model's calibration set

**Objective:** As a maintainer, I want the corpus to measure the model's precision rather than train an LLM
vote, so that a gap is a gap in the model, named and fixable.

#### Acceptance Criteria

1. The system shall use the vulnerable-parent / fix-commit pair as ground truth for whether the model can
   distinguish the two — the fix is what the model should be able to see.
2. If the model cannot distinguish a pair's two sides, then the system shall record it as a named model gap
   with the reason, not as a detector miss to be averaged away.
3. The system shall keep the per-slice split with the real-world slices deciding, and shall not present the
   development slice as the corpus.
4. The system shall support harvesting pairs at repository scale from CVE history, with the fix diff read by
   the model as the oracle, rather than hand-assigned labels.

### Requirement 10: The execution tier is deferred and adopted, not built

**Objective:** As a maintainer, I want dynamic confirmation available for the classes a static model cannot
arbitrate, without building or requiring it at v1.

#### Acceptance Criteria

1. The system shall treat `execution_confirmed` as an optional rung reached only for classes where the model
   layer cannot decide — memory-safety in C first.
2. When execution confirmation is used, the system shall adopt it from Clearwing (the existing fork), not
   reimplement the sandbox lifecycle, container pooling, sanitizer images or PoC stability.
3. The system shall not require the execution tier for any web/logic class at v1.

### Requirement 11: Reporting and operational contract

**Objective:** As a maintainer, I want the honesty disciplines that survived and the same operational contract
as the rest of the tool.

#### Acceptance Criteria

1. The system shall report every number per slice, publish the overfitting gap beside every headline number,
   and carry the evidence rung on every finding.
2. The system shall leave the detection, map and local pair gate outputs byte-identical to the committed
   baseline.
3. The system shall keep the core install at zero dependencies; the CPG engine, the LLM endpoint and any
   execution tier are optional extras that degrade to a recorded reason without them.
4. The system shall pass every prompt and every persisted artifact through redaction.
