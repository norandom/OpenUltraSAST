# Requirements Document: contributor-scan

## Introduction

`model-grounded-detection` built an arbiter and measured it: 41.3% of the corpus reaches `model_entailed`
against the flat IR's 2.2%, and the wired pipeline scores 86.7% pair-correct at 6.7% leak against the LLM
hunter's 76.7% / 12.3%, at a fifth of the model calls. All 16 of its tasks are complete.

**And the model layer has zero production callers.** `ousast scan` does not use it. Every number above came
from a measurement harness, not from the tool. This feature closes that gap and answers the question the
maintainer actually posed: *a real world tool that helps developers when they want to contribute.*

That framing changes the work. A contributor has no labelled function and no declared weakness class — they
have a repository they are about to touch. Everything measured so far is function-level pairs, which
exercise none of the questions a whole repository asks: which regions to look at, how to rank thousands of
candidates, what to spend, and whether a CPG build on a 100k-line tree finishes at all.

Context: `brief.md`, `.kiro/specs/model-grounded-detection/`, and the committed measurements
`2026-09-08-pipeline-vibe-py.json`, `2026-09-08-model-entailment-ceiling-cpg.json`.

## Boundary Context

- **In scope**: wiring `model/pipeline` into `ousast scan`; region selection from entry points; ranking and
  budget at repository scale; the performance envelope; running against known-vulnerable checkouts;
  contributor-facing output; the packaging already built (image, compose, shell wrappers, pyinfra); the
  deferred memory-family decision; retiring `evidence_level`.
- **Out of scope**: new arbiters or families (the three forms exist); prompt optimisation of any kind;
  building a sandbox (Req 10 of the predecessor stands — adopt, never build); changing the gates.
- **Carried forward, not re-litigated**: the evidence ladder, the taxonomy, the fact tables, and the finding
  that the model supplies precision while the LLM supplies recall.

## Requirements

### Requirement 1: The model layer reaches a user

**Objective:** As a developer, I want `ousast scan` to use the model layer, so that the arbiter this project
built is something I can run rather than something a harness demonstrates.

#### Acceptance Criteria

1. When a scan runs with a CPG engine available, the system shall arbitrate its candidate findings through
   `model/pipeline` and attach a rung to each.
2. The system shall report model findings alongside the existing pattern and overlay findings, without
   removing either.
3. When no CPG engine is available, the scan shall behave exactly as it does today and record
   `cpg_unavailable` — the model layer is additive, never a precondition.
4. The detection, map and local pair gates shall remain byte-identical to the committed baseline.
5. The system shall expose the model layer's per-rung counts in the scan's own output, so a user can see how
   much of the result the model arbitrated rather than inferring it.

### Requirement 2: Regions come from the code, not from a label

**Objective:** As a developer scanning a repository, I want the tool to decide what to look at, because I
cannot tell it which function is interesting.

#### Acceptance Criteria

1. The system shall select regions from entry points and reachability rather than from a declared function
   name.
2. If a region has no resolvable entry point, then the system shall fall back to file-level regions and
   record that it did.
3. The system shall route each region to the families its shape admits, rather than attempting every family
   on every region.
4. The system shall not require a `function` label anywhere on the scan path; that label belongs to pair
   scoring alone.

### Requirement 3: Ranking and budget at repository scale

**Objective:** As a developer, I want the most useful findings first and a bounded cost, because a repository
offers thousands of candidates and my attention and budget are finite.

#### Acceptance Criteria

1. The system shall order findings by rung first, so what the model established outranks what only the LLM
   proposed.
2. The system shall apply a total budget across a scan for model calls, not merely the per-region cap of
   eight the enumerator uses today.
3. When the budget is exhausted, the system shall stop asking and report how many candidates went unjudged,
   rather than silently truncating.
4. The system shall spend the budget on the highest-ranked candidates first.
5. The system shall report cost and elapsed time for the run.

### Requirement 4: It runs on a real repository

**Objective:** As a maintainer, I want the performance envelope measured on real checkouts, because nothing
in the corpus exercises it.

#### Acceptance Criteria

1. The system shall be measured against at least one known-vulnerable repository checkout at a vulnerable
   commit, not an excerpt.
2. The measurement shall record CPG build time, scan wall-clock, peak memory, findings by rung, and cost.
3. If a repository cannot be processed within its resource envelope, then the system shall record the reason
   and the stage it failed at, rather than failing opaquely.
4. The measurement shall state whether the known vulnerability was found, and at which rung.
5. The system shall not require the whole repository to fit in one CPG if that proves infeasible; the
   fallback shall be recorded and measured rather than assumed.
6. At least one pinned checkout shall carry a known vulnerability that a family can decide in principle, so
   that a scan producing nothing is distinguishable from an engine that cannot see. *(Added 2026-09-09.
   Criterion 4.1 is satisfied by libpng, whose CVE is out of family and which no version can fix, because
   the library never calls a sink any family models: the letter was met and the intent was not.)*

### Requirement 5: Output a contributor can act on

**Objective:** As a developer, I want to know what is risky and why, in terms I can check.

#### Acceptance Criteria

1. Every finding shall carry its rung, its witness, and the file and line it concerns.
2. The system shall state plainly what a `suspicion` means — that the model could not confirm it — so a
   reader does not treat it as established.
3. The system shall write findings to the writable output location, never into the repository under analysis.
4. The system shall summarise a scan in a form readable without opening a JSON file.
5. The report shall be proportionate to the evidence behind a finding: a rule whose only evidence is a text
   match shall be summarised once it exceeds a stated number of sites, and a finding a proposer reasoned
   about shall keep its detail whatever its rung. Nothing shall be dropped from `findings.json`, which
   remains the record a baseline is compared against. *(Added 2026-09-09. libpng emitted 198 findings, 163 of
   them a pattern asserting `memcpy` and `strcpy` are PRESENT in a library that uses them correctly
   throughout, and no criterion here forbade it.)*
6. Where a family's abstraction cannot decide a weakness class, the system shall state that limit in the
   report, and no scan shall present an absence of findings as evidence of absence. *(Added 2026-09-09.
   `c/memory` scored zero true positives across 89k lines of C for a structural reason — it models string
   functions and libpng overflows through arithmetic. A silent scan reading as a clean bill of health is
   worse than noise because it is quiet, and it is the one failure mode the rung ladder does not guard.)*

### Requirement 6: Packaging is part of the product

**Objective:** As a developer with nothing installed, I want to run this, because an analyser I cannot start
is not a tool.

#### Acceptance Criteria

1. The system shall run from `docker compose` with no host dependency beyond Docker, and the image shall be
   **built and verified**, not merely defined.
2. The shell wrappers shall make the container invisible for ordinary use, and shall prefer a native install
   when one exists.
3. The repository under analysis shall be mounted read-only, and findings shall go to the one writable mount.
4. The network shall be off by default and required only for the optional LLM judge.
5. The engine version shall be pinned and checksum-verified in every install path.

### Requirement 7: Close the two deferred decisions

**Objective:** As a maintainer, I want the outstanding decisions closed rather than carried, because each one
silently caps what the corpus can tell us.

#### Acceptance Criteria

1. The system shall either reach the `memory` family through an adopted execution tier, or record explicitly
   that C memory-safety is out of scope — 173 of the 176 real-world CVE pairs currently sit idle behind a
   stub.
2. The system shall retire `evidence_level` in favour of `rung`, or record why both are kept.
3. Each decision shall be recorded with its reason where a later reader will find it.

### Requirement 8: Honesty disciplines carry forward

**Objective:** As a maintainer, I want the reporting disciplines that survived the predecessor to survive
this one, because each exists due to a specific past error.

#### Acceptance Criteria

1. The system shall report per-slice numbers with the real-world slice deciding, and refuse a bare aggregate.
2. The system shall publish the overfitting gap beside any headline number, and record it as absent rather
   than zero when a slice is missing.
3. The system shall pass every prompt and persisted artifact through redaction.
4. The core install shall remain zero-dependency, with the CPG engine, the LLM endpoint and any execution
   tier optional and degrading to a recorded reason.
5. Any new family-specific code path shall be checked for sibling paths that need the same change, before it
   is measured — five bugs in the predecessor shared exactly that shape.

### Requirement 9: Grow the corpus where the engine can use it

**Objective:** As a maintainer, I want more real-world and more vibe-code bugs, so the engine is tuned against
what developers actually contribute to rather than against 30 pairs of one slice.

#### Acceptance Criteria

1. The system shall add a **PHP/WordPress** slice covering plugin and core weaknesses. WordPress plugin CVEs
   are overwhelmingly injection, XSS and authorization bypass — the families the model layer already
   arbitrates well — and `php2cpg` works once a PHP interpreter is present, which the shipped image now
   provides.
2. The system shall add **real-world C library CVEs** beyond the existing curl and OpenSSL rows — libpng and
   the image libraries, OpenSSH, libpam, and vulnerable kernel modules were named. These are gated on Req 7.1:
   until the memory-family decision is closed they would join 173 pairs already sitting idle, so the decision
   comes first and the harvest follows it.
3. The system shall add further **vibe-code** pairs — agent-written and human-written web application bugs —
   because that slice is where the tool's stated audience actually works, and it is currently 35 pairs.
4. Before any slice is vendored at scale, the system shall verify on a sample that the model can **read** its
   pairs, and shall vendor only the categories that a measurement shows it can arbitrate. The OWASP harvest
   found 238 candidate pairs and vendored 40 for exactly this reason; the other 198 would have grown the
   corpus while making every number less interpretable.
5. Every vendored pair shall carry a stated licence, and no vendored excerpt or test shall contain a
   contiguous key-shaped literal.
6. Each new slice shall report as its own row and shall never be blended into a headline, and a synthetic
   slice shall say in its catalog that it measures breadth rather than real-world performance.
7. The system shall record, per slice, how many pairs the model can arbitrate — so corpus growth is measured
   by what it teaches rather than by how many rows it adds.

### Requirement 10: Regression tuning over a large codebase

**Objective:** As a maintainer, I want a repeatable run over a large real codebase, so changes to the fact
tables and queries can be checked for regressions that pair scoring cannot see.

#### Acceptance Criteria

1. The system shall support a repeatable scan over a pinned checkout of a large repository, recorded as a
   committed baseline.
2. When the fact tables or queries change, the system shall report the delta against that baseline —
   findings gained, findings lost, and rung movements.
3. The system shall treat an unexplained loss of a previously-entailed finding as a regression to be
   investigated, not a number to be accepted.
4. The baseline shall record the engine version, because a CPG engine change moves every verdict it produces.

---

## Amendment record — group 2 (approved 2026-09-09)

Group 2 was specified as the phase that can reshape the rest, and it did. Three amendments were drafted from
what it measured and **approved by the maintainer on 2026-09-09**; they are folded into the numbered
requirements above and marked there with the evidence that produced them.

| amendment | folded into | evidence |
| --- | --- | --- |
| A — what a report may repeat | Req 5.5 | libpng: 198 findings, 163 a pattern match; task 2.11 fixed that half |
| B — a family that cannot decide must say so | Req 5.6 | `c/memory`: 0 true positives on 89k lines of C |
| C — a checkout that can demonstrate detection | Req 4.6 | libpng satisfies 4.1 and cannot demonstrate detection |

**A is only half implemented, deliberately.** Task 2.11 made pattern matches proportionate. The same argument
applies to the model layer's own suspicion band — 38 of vampi's 60 findings — which is an enumerated
candidate the graph could not decide and an LLM affirmed: a pattern match with an opinion attached, not a
reasoned claim. Task 2.17 carries that half.

### What group 2 confirmed rather than changed

* **Req 8's overfitting warning earned its place twice.** It stopped a rule being extended until libpng was
  clean (2.13), and it forced the access-control precision work to be measured on pairs nobody tuned against
  (2.6), where the leak fell 42.9% → 0.0% with pair-correct unchanged.
* **Req 3.3's honesty counters were the load-bearing part.** `regions_unjudged` is what made a budget that
  stopped free work visible at all.
* **Req 11.2's byte-identical gates held through every one of nine defect fixes** — which says the same thing
  from the other side: the corpus could not have caught any of them.
