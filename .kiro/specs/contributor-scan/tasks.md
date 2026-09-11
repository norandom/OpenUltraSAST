# Implementation Plan: contributor-scan

## Guidance for the implementing agent

- **The predecessor's lesson, in one line.** Five bugs in `model-grounded-detection` shared one shape: a
  taint-specific assumption applied to every family, each caught by a *measurement* rather than a check.
  Before you finish any change to a routing rule, a matching rule, or a per-family question, **grep for its
  siblings and fix them in the same commit.** The most expensive instance cost a 19-minute run that returned
  an identical number, and only the identity revealed the bug.
- **Run the whole CI list before pushing**, not the parts you remember: `ruff format --check .`,
  `ruff check .`, `mypy src/openultrasast`, `pytest`, the three gates, `compileall src tests`, and
  `pytest -m semantic`. CI was red for most of a session because `ruff check` passing was taken as evidence
  that `ruff format --check` would.
- **The gate baseline is the safety net.** `benchmarks/measurements/2026-09-06-gate-baseline.txt`. Run all
  three gates before and after every task. The model layer is additive: if a gate moves, you changed
  something that was never meant to change.
- **RED first**, one commit per task, selective `git add`.
- **Zero-dependency core.** Copy the capability-probe pattern in `semantic/extra.py` and `cpg/capability.py`.
- **Do not modify `model/pipeline`, `taint`, `dominance`, `config_value`, `specs` or `candidates`.** They are
  built and measured. If a change looks necessary, it belongs in its own commit with its own measurement.

## Group 1 — Wire it (gate-protected)

- [x] 1.1 Regions from entry points
  - `model/regions.py`: `ScanRegion(path, function, families, rank, source)` and
    `regions_for(entries, targets, *, taxonomy, language_of)`. Rank from what `EntryPointRecord` already
    carries (`access_level`, `trust_boundary`) — do not invent a new signal. File-level fallback when a target
    has no entry point, with `source="file_fallback"`. Families from region shape and language, via the
    existing `taint_specs`/`dominance_specs`/`config_specs`.
  - **Sibling audit (Req 8.5):** family routing now exists in three places — `ceiling.py`'s harness,
    `pipeline._arbitrate`, and here. Check all three agree before finishing.
  - Observable: a region is produced per entry point; a target with no entry point yields a file region marked
    as such; no region carries a family whose spec is absent for its language.
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 8.5_

- [x] 1.2 The repository driver
  - `model/scan.py`: `ScanBudget`, `ModelScanResult`, `scan_repository(...)`. **One CPG per run**, reused
    across regions. Regions in rank order; budget decremented per model call and checked before each; the
    remainder counted into `regions_unjudged`. Findings ordered by rung, then rank.
  - Observable: one `backend.build` call for many regions; a budget of N yields at most N model calls and a
    non-zero `regions_unjudged`; ordering puts `model_entailed` above `suspicion`; a failed CPG build yields
    an empty result with `cpg_build_failed`, never an exception.
  - Redaction (Req 8.3) is inherited from `model/pipeline`, which redacts every prompt; a test asserts the
    driver adds no unredacted path of its own.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 8.3_
  - _Depends: 1.1_

- [x] 1.3 The MAP stage
  - Wire `scan_repository` into `cli.py` inside `Stage.MAP`, mirroring `_check_obligations`: takes
    `entry_points` and `targets`, returns findings merged **additively** beside the pattern, overlay and
    obligation findings. A `[model]` config block (enabled, budget, max regions), zero-dep, conservative
    defaults. Payload into the manifest with `by_rung`, cost and elapsed.
  - Observable: a scan on a repo with Joern present reports findings carrying rungs; the same scan with
    `OPENULTRASAST_JOERN_PROBE=off` is identical to today's output plus a `cpg_unavailable` degradation;
    **the three gates are byte-identical**.
  - The `[model]` block is capability-detected like every other optional plane (Req 8.4): core stays
    `dependencies = []`, and the engine, endpoint and execution tier each degrade to a recorded reason.
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 8.4_
  - _Depends: 1.2_

- [x] 1.4 Batch the queries — one Joern invocation per scan, not one per region and family
  - **Why this is in group 1 rather than group 2.** Wiring 1.3 exposed that the cost model in the design was
    half right. One CPG per scan was the right call, but every *query* is its own `joern --script` JVM launch
    of roughly 30 seconds, and the driver issues one per region per family. A single ten-line Python file
    admits six families and therefore takes six launches and over three minutes. At 100 regions that is ~5
    hours; at 1000, ~50. Task 2.2's go/no-go would not have been a measurement, only arithmetic.
  - Extend `cpg/backend.py` with a batched call: one invocation carrying many (region, family, spec) requests
    and returning rows keyed back to each. The `.sc` scripts already take parameter lists; they take a list of
    requests instead. `model/scan.py` collects the work first, issues one call, then arbitrates from the rows.
  - **Keep the seam.** The subprocess boundary stays the only Joern touch-point (predecessor Req 4.5). Server
    mode would keep a JVM warm but adds a process model and weakens that promise; batching needs neither.
  - **The arbiters do not change.** `taint`, `dominance`, `config_value` and `pipeline` take rows and are
    already measured; if this task needs to edit one, that is a signal the batching is leaking into them.
  - Observable: a scan over N regions issues **one** `joern --script` invocation, not N×families; the same
    fixture produces the same findings and rungs as the unbatched path, asserted against a recorded baseline;
    the ten-line scan drops from minutes to seconds.
  - _Requirements: 3.5, 4.2, 4.3_
  - _Depends: 1.3_

## Group 2 — Scale it (the phase that can reshape the rest)

- [x] 2.1 A pinned known-vulnerable checkout
  - `benchmarks/repos/<name>.toml`: url, commit, the known CVE, the file and function it lives in, licence.
    Start with one small enough to iterate on. Fetch is explicit and offline-by-default, like the pointer
    pairs.
  - Observable: the recipe resolves to a checkout; CI never fetches it.
  - _Requirements: 4.1_
  - _Depends: 1.3_

- [x] 2.2 The first repository measurement
  - Run the full scan against that checkout and commit the artifact: CPG build time, query time and total
    scan wall-clock as three separate numbers, peak memory, findings by rung, cost, `regions_unjudged`,
    and **whether the known CVE was found and at which rung**. The build/query split is separated because
    2.3 is decided on that ratio and cannot be decided on a single wall-clock figure. If the repository cannot be processed in its envelope, record the stage it failed at.
  - This is the go/no-go for the shape of the rest: if one CPG per repository is infeasible, the region and
    budget design changes and phases 3–6 should not be built on it first.
  - Observable: the artifact exists with every field; the reading states go or no-go and why.
  - _Requirements: 4.2, 4.3, 4.4, 4.5_
  - _Depends: 2.1_

- [x] 2.3 Decide on Joern server mode, on 2.2's numbers
  - Joern offers `--server` with `--server-host`, `--server-port` and basic auth: one warm JVM with the CPG
    loaded once, and queries in milliseconds after that. It would remove the three-to-four JVM starts
    (~100s) that remain per scan now that 1.4 has batched the queries.
  - **Deliberately sequenced after the measurement, because deciding it now would be optimising before
    measuring.** Batching already moved query cost from O(regions) to O(1) per scan; whether the remaining
    floor matters is a ratio 2.2 produces and nothing before it does. If a real CPG build takes ten minutes,
    a 100s query floor is noise and server mode buys nothing. If the build is thirty seconds, the floor is
    3x the build and server mode is the obvious next move.
  - Costs to weigh against that ratio: process lifecycle (start, health, shutdown, orphan reaping -- stray
    JVMs had to be killed by hand twice while building the batching); the seam weakening from "the subprocess
    is the only Joern touch-point" to "subprocess or HTTP client", which is the promise that has kept the
    backend replaceable; and that a CPGQL endpoint evaluates Scala, so it is arbitrary code execution on the
    analysis host -- acceptable inside the shipped container, which runs `network_mode: none`, and much less
    so as a port listening on a contributor's laptop.
  - Observable: a recorded decision that cites 2.2's build-time-to-query-time split. A preference does not
    close this task; a ratio does.
  - **Decided: no.** On libpng (89k lines of C) the query phase splits taint 243.3s / config 10.7s over two
    invocations, and fixed overhead measured on that CPG is ~13s per invocation. So ~26s of 250s is JVM
    startup and ~224s is CPGQL evaluation: a warm server removes 6% of a 446s scan and none of the part that
    costs. Recorded in `benchmarks/measurements/2026-09-09-repo-libpng-envelope.json`.
  - The small repository pointed the other way -- vampi's 34.3s over three kinds is roughly three startups
    and almost no evaluation -- and the ratio inverts with size. That inversion is precisely why this task
    was sequenced after a real repository instead of being decided on a 520-line file.
  - _Requirements: 4.2_
  - _Depends: 2.2_

- [x] 2.4 A region that spans the flow, not just a function
  - **2.2's finding, and the one that reshapes the phase.** VAmPI-SQLI is a request parameter reaching
    `get_by_username(username)`, passed to `User.get_user(username)` in another module, interpolated into a
    query and executed. Source and sink are in different functions, regions are per-function, and a
    repository scan does not treat parameters as untrusted -- so neither region sees both ends and the
    engine is silent on the most ordinary shape a real injection bug has.
  - The CPG already has the call graph; `reachableByFlows` is not function-bounded. What is bounded is the
    QUESTION the driver asks. So the work is in the region model and the query scope, not in the arbiter:
    a region should be able to name an entry point and admit sinks reachable from it, with the file scope
    from 2.2 kept so the answer is still attributable.
  - Watch the cost: an unbounded interprocedural question over a large repository is how this gets slow
    again. Measure it on vampi first, then on the envelope checkout.
  - Observable: VAmPI-SQLI entailed or corroborated at `models/user_model.py:get_user`, with the scan's
    wall-clock and the entailed-finding count recorded against 2.2's numbers.
  - _Requirements: 4.4, 8.1_
  - _Depends: 2.2_

- [x] 2.5 Module-level regions the engine can actually ask about
  - A setting in `if __name__ == '__main__':` belongs to a region the mapper calls `app.py:__main__`, but
    Joern names that method `<module>`. The function filter matches nothing, so module-level configuration
    is invisible. Before 2.2's file scoping it was worse, not better: the literal was reported eight times
    in eight files that do not contain it.
  - Observable: `app.py:17`'s `host='0.0.0.0'` reported exactly once, at that location.
  - _Requirements: 4.4_
  - _Depends: 2.2_

- [x] 2.6 Access control that does not entail every public endpoint
  - 7 of 9 VAmPI handlers were entailed, including `register_user` and `get_all_users`, which are meant to
    be unauthenticated. The dominance rule -- unguarded, with guarded siblings -- was calibrated on pairs
    where a guarded twin always existed. At repository scale every public endpoint has guarded siblings.
  - This is a precision question and needs a precision measurement: on a real repository, what fraction of
    entailed access-control findings are endpoints that genuinely require authorisation? Do not tune it
    against VAmPI alone; that is how the +16% overfitting gap in Req 8 happened.
  - Observable: a recorded precision figure before and after, on more than one checkout.
  - _Requirements: 8.1, 8.2_
  - _Depends: 2.2_

- [x] 2.7 A dominance witness that names its line
  - Access-control sites read `api_views/users.py:?:update_password`. Taint and config witnesses carry
    `(line N)`; dominance does not, so its findings have no line and a contributor cannot open them.
  - Observable: every entailed finding in a repository scan has an integer line.
  - _Requirements: 5.1_
  - _Depends: 2.2_

- [x] 2.8 An endpoint that declares itself public carries no obligation
  - **2.6's remainder.** Both false positives left on VAmPI are `register_user` and `login_user`, which its
    OpenAPI spec declares public with no `security` block. The arbiter cannot see that declaration, so it
    reports a missing guard on an endpoint whose contract says there is nothing to miss.
  - The mapper's `access_level` is NOT a safe substitute on its own. For an OpenAPI route it comes from the
    declared `security` block and is trustworthy; for a decorator-based framework "public" means only that
    no `@login_required` was found, which is precisely the bug this family exists to report. Suppressing on
    that would silence the primary detection case for Flask and Express.
  - So the work is to carry the PROVENANCE of the access level, not just its value: a declared contract
    removes the obligation, an absent decorator does not. `EntryPointRecord.provenance` currently only
    echoes the level, so this needs a real signal rather than a string match on evidence text.
  - Observable: `register_user` and `login_user` no longer entailed on vampi, with the pair-corpus leak rate
    unchanged at 0% on the non-VAmPI pairs -- the check that this suppressed a declaration and not a family.
  - _Requirements: 8.1, 8.2_
  - _Depends: 2.6_

- [x] 2.9 One defect is one finding, however many regions reach it
  - libpng's scan produced 26 entailed findings that are all the identical site,
    `contrib/gregbook/wpng.c:335:main`. Many regions reach one shared sink and each emits its own finding;
    nothing dedupes by site. A contributor would be shown the same defect twenty-six times.
  - Invisible at vampi scale, where regions rarely share a sink, and it appeared the moment task 2.4 let a
    region's question follow the call graph.
  - Dedupe on the reported site, keeping the strongest rung and recording how many regions reached it --
    "reached from 26 entry points" is useful information, twenty-six rows are not.
  - Observable: libpng's entailed count reflects distinct sites; the artifact records both numbers.
  - _Requirements: 5.1, 8.1_
  - _Depends: 2.4_

- [x] 2.11 The suspicion band has to be worth reading
  - libpng's scan produced 198 rows: 26 entailed (all one false positive, since fixed), 113 `c-unsafe-*`
    pattern matches that assert an API is PRESENT rather than misused, 50 overlay-coverage annotations that
    are not findings at all, and 9 model suspicions. Zero validated defects.
  - The rung is honest -- these say "needs review" and mean it -- but a contributor handed 163 rows about a
    library that uses `memcpy` correctly throughout will not read the one that matters. 82 of the 113 are in
    `contrib/`, so task 2.10 removes most of it; what remains needs a policy, not a filter invented here.
  - Observable: a stated rule for what reaches a contributor's report at `suspicion`, and libpng's row count
    under it, measured.
  - _Requirements: 5.1, 5.2_
  - _Depends: 2.10_

- [x] 2.10 Do not spend the scan on example code
  - 22 of libpng's 30 highest-ranked regions are under `contrib/` -- the sample programs shipped with the
    library rather than the library. The budget and the 243s taint query go there first.
  - The rank already comes from the entry-point mapper; what is missing is that a path can be evidence too.
    Vendored, generated, example and test trees are not what a contributor is changing. This is also the
    cheapest available reduction of the 243s.
  - Do not hardcode `contrib/`: derive it, record what was excluded and why, and measure the scan with and
    without so the exclusion is a number rather than a preference.
  - Observable: a recorded before/after on libpng -- regions, query seconds, and entailed sites.
  - _Requirements: 4.2, 8.1_
  - _Depends: 2.2_

- [x] 2.12 A C flow that a bounds check governs is not a finding
  - `c/injection` and `c/memory` carry ZERO sanitizers, so no C flow can ever be discharged. Every
    `argv -> strcpy` entails however carefully it is bounded, which is why libpng reports
    `strcpy(outname+len, ".png")` at wpng.c:374 -- guarded four dozen lines earlier by
    `if ((len = strlen(inname)) > 250)` against a `char[256]`.
  - A sanitizer list will not fix this: the discharge is not a call, it is a GUARD that dominates the sink.
    That abstraction already exists and already works -- it is what `dominance.sc` does for access control --
    and it is wired to one family only. The work is to let a taint family name a guard-shaped discharge and
    route it through the arbiter that can decide one.
  - Observable: wpng.c:374 not entailed, with the pair corpus and both repositories measured either side. Do
    not do this by adding `strlen` to a sanitizer list; that would discharge the unguarded case too.
  - _Requirements: 8.1, 8.2_
  - _Depends: 2.9_

- [ ] 2.13 A destination allocated to size is bounded too
  - 2.12's remainder, and libpng's last entailed finding: `strcpy(output + len, ".icc")` at
    contrib/examples/iccfrompng.c:124, where `output = malloc(len + 5)` and a five-byte copy lands at offset
    `len`. It fits exactly. There is no comparison anywhere, so the bound rule cannot see it -- the
    destination is ALLOCATED to size rather than bounds-checked.
  - Deliberately not done inside 2.12. Both discharge shapes were found on the same repository, and
    extending a rule until one checkout is clean is the overfitting Req 8 exists to prevent. This wants a
    second C checkout with a genuine CWE-121 first, so the change can be measured for what it silences as
    well as what it clears.
  - Observable: iccfrompng.c:124 not entailed, AND a real overflow on another checkout still entailed.
    Without the second half this task should not be closed.
  - _Requirements: 8.1, 8.2_
  - _Depends: 2.12, 5.3_

- [ ] 2.14 Control dependence is not populated, and two arbiters want it
  - Measured, not assumed: **0 of 13,184 calls in the libpng CPG and 0 of 1,152 in the vampi CPG have a
    controlling control structure.** `controlledBy` returns nothing in either, so the PDG's control half is
    simply absent from the graphs we build. The data half is present and load-bearing -- `reachableByFlows`
    is the whole taint arbiter, and `joern-parse` reports `dataflowOss` applied.
  - Everything guard-shaped we do therefore uses CFG dominance (`dominatedBy`) or syntactic conditions
    (`method.controlStructure.condition`) instead. That is why 2.12's first attempt failed: libpng's bound
    reaches its sink through an `error` flag, which is a control-dependence fact and nothing else.
  - Find out whether a CDG overlay can be enabled on `joern-parse` or in the script, what it costs on the
    envelope checkout, and whether it makes the flag-mediated guard decidable. If it cannot be enabled,
    record that -- it bounds what guard reasoning this engine can ever do.
  - Observable: a recorded answer with the build-time and query-time cost, and wpng.c:374 decided or a
    stated reason it cannot be.
  - _Requirements: 4.2, 8.1_
  - _Depends: 2.12_

- [ ] 2.15 A C checkout whose CVE goes through a sink we model
  - libpng cannot demonstrate a C true positive, and pinning an older vulnerable commit would not change
    that. **Every one of the twelve files using `strcpy`/`strcat`/`sprintf`/`gets` is under `contrib/`; the
    library itself uses none of them.** Its overflows are array and pointer arithmetic and `memcpy` sizing,
    and five buffer-overflow fixes checked (`png_set_quantize`, `png_image_finish_read`,
    `png_init_read_transformations`, `png_do_quantize`, `png_write_image_8bit`) touch no modelled sink at
    all.
  - So there are two ways forward and they are different sizes.
  - **Cheap: pin a C project whose CVE genuinely runs through a string function.** That gives the memory
    family its first true positive and tells us whether the family works at all. It does not make libpng
    decidable.
  - **Expensive, and a different engine: model how C actually overflows.** A `memcpy` whose size is
    computed, an index that is not bounded. That is *size arithmetic*, not sink matching -- "can this
    expression exceed this allocation" rather than "does tainted data reach this call". It is a constraint
    problem, which is what SMT is for and what this project deliberately did not adopt: the architecture
    decision was abstract interpretation as arbiter, taken because a model layer can be built from code
    where execution cannot be assumed. That decision was right for the flow families and it does not reach
    this one.
  - The maintainer has attacked libpng this way directly -- SMT to lay out memory, then guiding a fuzzer to
    produce the PNGs that reach it -- which is evidence about the shape of the problem, not a suggestion to
    reimplement it. It says the honest routes to C memory safety are constraint solving or execution, and
    the ladder already has a rung for the second (`execution_confirmed`, built and unreachable per the
    module audit).
  - Observable: a pinned checkout with an in-scope CVE found at a rung, OR a recorded decision that
    `c/memory` is scoped to string-function misuse and makes no claim about arithmetic overflows. Do not
    leave it implying it covers a class it cannot see.
  - _Requirements: 4.1, 4.4_
  - _Depends: 2.12_

- [x] 2.16 Say what `c/memory` actually covers, or retire it
  - Its score so far is zero true positives and every finding a false one: 26 from a substring match, 3 from
    a bound it could not see, 1 from an allocation sized to fit. Each was a real defect in the engine and
    each is now fixed, but the family has never once been right, and 2.15 explains why -- it models string
    functions in a codebase class that overflows through arithmetic.
  - This spec's predecessor threw away parts that did not carry their weight, and the same question applies
    here. The answer may well be "keep it, scoped and labelled" -- `strcpy` misuse is real in plenty of C --
    but it should be a recorded decision with a number behind it, not an assumption.
  - Observable: either a measured true positive on the 2.15 checkout, or the family's declared scope
    narrowed in the facts and the docs so no reader takes a silent C scan for a clean bill of health.
  - **Done 2026-09-09 by the second route: kept, scoped and stated.** `strcpy` misuse is real in plenty of C
    and the family earns its place for that; what it could not do was claim more. Its description said
    "bounds, lifetime, arithmetic", which is exactly what it does not decide -- the description was itself
    the quiet-failure risk. It now names the APIs it models, and a new `limits` field says what it cannot:
    an overflow expressed as an index, a pointer offset, or a memcpy whose size is computed.
  - The report renders it as **What was analysed**, for every family offered to a region whether or not it
    found anything -- a family that ran and reported nothing is the case a reader is most likely to misread.
    The counts are derived from the fact tables the arbiter used, so they cannot drift from what the engine
    really looked for; only the limit sentence is authored.
  - Retiring the family was the alternative and would have been wrong: it would remove the disclosure along
    with the coverage, leaving a C scan silent for a reason nobody could read.
  - _Requirements: 3.1, 8.2_
  - _Depends: 2.15_

- [x] 2.17 The model's own suspicion band is a pattern match with an opinion attached
  - **Req 5.5's other half.** Task 2.11 made pattern matches proportionate and left this untouched, so vampi
    still emits 61 sections for a 520-line application -- 38 of them model suspicions, roughly one per
    fourteen lines of code.
  - The epistemic case for treating them as reasoned claims does not survive inspection. A model suspicion is
    what the enumerator proposed at a site the graph could NOT decide, affirmed by a judge with no coverage
    there. That is a pattern match with an opinion attached, and it is weaker evidence than the obligations
    checker's output, which comes from a structural analysis rather than a guess.
  - So group them by family the way 2.11 groups pattern rules, and keep obligation findings and everything
    at `model_corroborated` or above in full. Expect vampi to fall from 61 sections to roughly 23.
  - Measure both repositories, and measure what it costs: if a real finding only ever appeared at model
    suspicion, this hides it, and that is the number that decides whether the rule is right.
  - _Requirements: 5.1, 5.2, 5.5_
  - _Depends: 2.11_

## Group 3 — Ship it

- [ ] 3.1 Contributor output
  - `model/report.py`: a scan summary — counts per rung, the top findings with witness and `path:line`, and a
    plain statement of what `suspicion` means (the model could not confirm it). Findings to the writable
    output only.
  - Observable: a scan produces a summary readable without opening JSON; every finding shows rung, witness
    and location; nothing is written into the analysed tree.
  - Keeps the disciplines already built into `model/report.py` (Req 8.1, 8.2): per-slice rows with the
    real-world slice deciding, a refused bare aggregate, and the overfitting gap published beside any headline
    — absent rather than zero when a slice is missing.
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 8.1, 8.2_
  - _Depends: 1.3_

- [ ] 3.2 Build and verify the image
  - `docker compose build`, then run a real scan through it and through the shell wrapper. The Dockerfile and
    compose exist and are syntax-valid; **the image has never been built**, so nothing about it is proven.
  - Observable: the image builds; `TARGET=<repo> docker compose run --rm ousast scan /target` produces the
    same findings as a native run; the target mount is read-only; the network is off by default.
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_
  - _Depends: 3.1_

## Group 4 — Close the deferred decisions

- [ ] 4.1 The memory-family decision
  - Either reach `memory` through an adopted execution tier, or record explicitly that C memory-safety is out
    of scope. 173 of the 176 real-world CVE pairs sit idle behind a stub; the decision gates Req 9.2.
  - Observable: the decision and its reason are recorded where a later reader finds them; if out of scope,
    the corpus says so per slice.
  - _Requirements: 7.1, 7.3_

- [ ] 4.2 Retire `evidence_level`
  - It duplicates `rung` in intent. Retire it, or record why both are kept. Note the legacy value
    `static_corroboration` comes from the flat-IR overlay, which Req 4.4 of the predecessor demotes to the
    suspicion band — so a straight rename would overstate it.
  - Observable: one vocabulary, or a recorded reason for two; SARIF and JSON consumers considered.
  - _Requirements: 7.2, 7.3_

## Group 5 — Grow the corpus

**What group 2 established about each of these**, so none is started on a wrong assumption:

* **PHP/WordPress**: Joern ships `php2cpg`, so the engine can parse it. The blocker is ours --
  `taint_specs(language="php")` returns **zero families**, as do ruby and go. WordPress would parse and
  produce nothing, which is the quiet failure that reads as a clean bill of health. The work is fact tables
  first, corpus second.
* **A known-vulnerable old libpng**: measured and it will not work, for a reason the version cannot fix.
  Every file using `strcpy`/`strcat`/`sprintf`/`gets` is under `contrib/`; the library uses none of them and
  overflows through arithmetic instead. See 2.15 and 2.16.
* **Vibe-code repos**: the best fit available. Python and JavaScript both have full fact tables, the pair
  corpus already carries 70 vibe-py and 17 vfc-js pairs, and vampi -- the one repository where the engine
  finds 3 of 3 -- is exactly this shape. A whole-repository vibe-code checkout is the cheapest next
  measurement that could produce a true positive.

- [ ] 5.1 PHP/WordPress slice
  - **Fact tables landed 2026-09-09** (`benchmarks/measurements/2026-09-09-php-facts.json`). Five families
    derive, and the arbiter decides a real PHP CPG 4 of 4 on a probe: SQL concat entails, its escaped twin
    drops to corroborated, `echo` XSS and `system` command injection entail. `php` added to the region
    model's languages. What remains is below.
  - Plugin and core weaknesses. `php2cpg` needs a PHP interpreter, which the image provides. **Validate on a
    sample that the model can read the pairs before vendoring** — the OWASP harvest found 238 and vendored 40
    for exactly this reason.
  - Observable: a sample measurement precedes vendoring; only categories the model can arbitrate are
    vendored; the slice reports as its own row; every pair states a licence.
  - _Requirements: 9.1, 9.4, 9.5, 9.6, 9.7_
  - _Depends: 3.2_

- [ ] 5.2 More vibe-code pairs, and at least one as a whole repository
  - The pair corpus has 70 vibe-py and 17 vfc-js pairs, all excerpts. Group 2 showed that excerpts cannot
    see the defects a repository shows: nine engine bugs this session, none of them visible to the corpus,
    the gates byte-identical through every fix.
  - So the higher-value half of this task is a **pinned vibe-code repository**, not more pairs. It is the
    cheapest measurement that could produce a second true-positive checkout, because Python and JavaScript
    are the two languages whose fact tables are complete.
  - Observable: a `benchmarks/repos/` recipe for a vibe-code checkout with in-scope known vulnerabilities,
    and a measurement saying which were found at which rung.
  - _Requirements: 9.1, 9.2, 4.1_
  - The slice where the stated audience works, currently 35 pairs. Same read-check discipline.
  - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.7_

- [ ] 5.3 Real-world C library CVEs
  - libpng and the image libraries, OpenSSH, libpam, kernel modules. **Gated on 4.1**: until the memory
    decision closes these would join 173 idle pairs.
  - _Requirements: 9.2, 9.4, 9.5, 9.6_
  - _Depends: 4.1_

- [x] 5.4 WordPress entry points, and the one-verdict-per-region limit
  - Two things stand between the PHP facts and a WordPress result, and the second was found by running the
    first.
  - **Entry points.** WordPress registers handlers with `add_action`, `add_filter`, admin-ajax and REST
    routes. Nothing maps them, so every PHP file becomes one file-level region. The mapper already handles
    registration-based entry points for other frameworks (predecessor task 2.6), so this is a new recogniser
    rather than a new mechanism.
  - **One verdict per region per family.** The taint arbiter returns a single verdict for a region and
    family, so a file-level region reports at most one injection finding however many the file holds: on the
    probe, `system` won on flow length and the SQL injection went unreported. This is the mirror of 2.9 --
    that is many regions collapsing to one site, this is many sites collapsing to one verdict -- and it bites
    hardest where PHP needs it not to.
  - Observable: the probe reports 3 of 3, and a WordPress checkout yields function-scoped regions rather than
    one region per file.
  - _Requirements: 2.1, 8.1, 9.1_
  - _Depends: 5.1_

- [x] 5.5 php2cpg emits a CPG containing one file — NOT A DEFECT, it was the shim
  - **Found by 5.4 and it blocks the WordPress target.** A CPG built over two PHP files contains only one,
    and the survivor is the last alphabetically. Reproduced twice on independent samples; both files parse
    cleanly under `php -l` and under PHP-Parser directly, and `joern-parse` reports success either way.
  - php2cpg logs `Found warning in PHP-Parser JSON output` naming the surviving file, and that warning is
    PHP-Parser's own `====> File X:` banner appearing in what php2cpg expects to be pure JSON. That is the
    thread to pull.
  - Not yet isolated: this machine has no PHP interpreter, so php2cpg was driven through a container shim.
    The banner comes from PHP-Parser rather than from the shim, which makes a shim-only cause unlikely but
    not excluded. **Rerun with the native php-cli in the shipped image first.**
  - A plugin is many files. A scan that silently covers one of them and reports success is exactly the quiet
    failure Req 5.6 was approved for.
  - Observable: a CPG over N PHP files contains N files, or a recorded reason it cannot with the version and
    the reproduction.
  - **Resolved 2026-09-09: there was no defect.** Rerun with a native php-cli (8.3.6, no shim) over the same
    two files and the CPG contains both, all eight methods, and no PHP-Parser banner warning at all. The
    shim ran each `php` invocation in its own container -- needed because this machine has no interpreter --
    and php2cpg drives PHP-Parser per file, so that isolation kept only one file's JSON.
  - **The lesson is worth more than the fix.** Two independent reproductions agreed, and both were measured
    through the same broken instrument. A consistent result is not a correct one when every measurement
    shares an apparatus, which is the same trap as a corpus that cannot see the defect it is scoring.
  - _Requirements: 4.3, 5.6, 9.1_
  - _Depends: 5.4_

- [ ] 5.6 A sanitizer cleanses the family it cleanses, not every family
  - `TaintSpec.sanitizers` is one flat list per language, and its comment states the assumption plainly:
    "a sanitizer that breaks one flow breaks it whatever the sink's family". PHP falsifies it. `esc_html`
    stops XSS and does nothing for SQL injection; `esc_sql` is the reverse; `sanitize_text_field` stops
    neither and is the most-used of the three.
  - **CVE-2023-23488 is the proof.** Its handler calls `sanitize_text_field( $params['code'] )` and then
    concatenates the result into a query. Adding WordPress's sanitizers to the flat list -- the obvious thing
    to do when writing PHP facts -- would make that CVE and its whole class invisible. Task 5.1 therefore
    carries only SQL-specific cleansers, which leaves XSS under-sanitized instead.
  - This is 2.6's finding arriving in the taint family: a discharge counts for the obligation it discharges.
    The dominance arbiter now reads `requires`/kind from the facts; the taint spec has no equivalent.
  - Observable: `esc_html` marks an output_encoding flow sanitized and leaves an injection flow entailed, on
    a pair that carries both.
  - _Requirements: 8.1, 9.1_
  - _Depends: 5.1_

- [x] 5.7 Does the PHP call graph carry a flow through an object? — NOT a call-graph question
  - **The WordPress checkout scans and does not find its CVE.** Both ends are inside the budget --
    `pmpro_rest_api_get_order` at position 290 as a recognised entry point, `getMemberOrderByCode` at 472 --
    and the taint query runs for 23 seconds. So the question is the middle.
  - The flow crosses `new MemberOrder( $code )` into a constructor and then
    `$this->getMemberOrderByCode( $code )`. Both are dynamic in PHP, and whether php2cpg resolves either into
    a CALLEE edge is unverified: two attempts to query the call graph failed on script errors and were
    abandoned rather than guessed at.
  - Answer that first. If the edges exist, the gap is elsewhere -- the source may be `$request->get_params()`
    rather than a superglobal, which `parameter_sources` should cover but has not been checked on this shape.
    If they do not, task 2.4's interprocedural region cannot bridge an object boundary and PHP needs
    something else, which is a finding worth having either way.
  - Observable: a recorded answer naming which edges exist, and either the CVE found or a stated reason it
    cannot be.
  - **Answered 2026-09-09, and it was the wrong question.** The 117k-line pmpro CPG does not LOAD -- import
    throws in a ForkJoinParallelCpgPassWithAccumulator during overlay application -- so every query against
    it returns nothing. Isolated by running the ARBITER against two prebuilt CPGs rather than writing more
    ad-hoc Scala: `get_order_by_code` on the small probe returns 1 `model_entailed` with parameter sources
    and depth 3, while `getMemberOrderByCode` on pmpro, the identical shape, returns 0 under identical
    settings. Same arbiter, same spec, same question; the CPG is the difference.
  - That clears the facts: `$wpdb` sinks work, the parameter-source rule works, and a PHP parameter reaching
    `$wpdb->get_var` through a concat is entailed. Whether php2cpg resolves `new X()` and `$this->method()`
    remains **unmeasured**, because it cannot be measured on a CPG that will not load. Recorded as 5.10.
  - _Requirements: 4.4, 8.1, 9.1_
  - _Depends: 5.1_

- [x] 5.8 WordPress's popular flaw classes, on popular plugins
  - > "in wp focus on some of their popular flaws and plugins. these are the keys to unlock practical
    > software verification."
  - One plugin is a checkout; a class is a claim. WordPress's recurring shapes are narrow and well
    documented, and each maps to a family this engine already has:
    - **Unauthenticated AJAX** — `wp_ajax_nopriv_*` reaching a `$wpdb` query. Declared-public plus injection,
      both of which the mapper and the facts now carry.
    - **Missing capability check** — a handler that acts without `current_user_can` / `check_admin_referer`.
      This is the access_control family, and PHP has NO obligation facts yet, so it cannot be asked at all.
    - **Unescaped output** — a stored option or meta value reaching `echo` without `esc_html`. Blocked on 5.6,
      because the flat sanitizer list cannot say "escapes for HTML but not for SQL".
    - **Arbitrary file operations** — a request value reaching `unlink`/`file_get_contents`. Facts exist.
  - Pick plugins by installed base rather than by convenience, and pin each at a version with a verified
    advisory the way `pmpro.toml` does -- the CVE read out of the code, not out of the advisory text.
  - Observable: a class-by-class table over several plugins, saying for each whether it was found, missed, or
    out of scope. That is the artifact worth teaching from; a single found CVE is not.
  - **Done 2026-09-09.** The table is in `benchmarks/repos/README.md`, "WordPress, class by class". Three
    plugins pinned, each CVE read out of the code, each measured against its own fixed commit:

    | class | plugin, CVE | verdict |
    |---|---|---|
    | unauthenticated injection, sink in the receiving function | `pmpro`, CVE-2023-23488 | **found**, pair separates |
    | arbitrary file operation | `mwwpform`, CVE-2023-6559 | **found**, pair separates |
    | unauthenticated injection across a WordPress hook | `wpstatistics`, CVE-2022-25148 | **missed**, structurally |
    | missing capability check | — | cannot be asked (5.9) |
    | unescaped output | — | cannot be trusted (5.6) |

    Both hits are entailed by the graph alone and both disappear on the fixed side, because both fixes are
    calls the fact tables carry. Precision is not clean and the table says so: PMPro's vulnerable side
    reports 15 entailed, 4 from a named parameter and 11 from the receiver, with one demonstrable false
    positive surviving into 2.9.8.
  - The miss is the useful half. WP Statistics' source and sink are both modelled and the fix is `esc_sql`,
    yet nothing is reported on either side, because the only edge between the two files is
    `add_filter('...', array($this, 'method'))` / `apply_filters('...')` -- both ends naming the callback with
    a **string**. No frontend can draw that edge. Most WordPress plugin data travels this way, which makes it
    the largest structural gap for PHP and not a fact-table problem. The detection strategy for it is
    5.11, which handles it and the `$this` field case with one mechanism.
  - _Requirements: 4.1, 4.4, 9.1_
  - _Depends: 5.7_

- [ ] 5.9 PHP obligation facts, so access control can be asked at all
  - `dominance_specs(language="php")` returns nothing: PHP has no obligated operations and no dischargers, so
    the access-control family is silent on every WordPress scan rather than wrong on it.
  - The vocabulary is small and conventional -- `current_user_can`, `check_admin_referer`, `wp_verify_nonce`,
    `is_user_logged_in` as dischargers; `$wpdb` writes, `update_option`, `wp_delete_post`, `wp_update_user`
    as obligated operations -- and it is the single largest missing WordPress flaw class.
  - Do it after 5.6, so a discharge counts for the obligation it discharges rather than for all of them.
  - Observable: a missing-capability finding on a plugin that has one, and silence on one that checks.
  - _Requirements: 8.1, 9.1_
  - _Depends: 5.6_

- [ ] 5.10 A PHP CPG large enough to matter that actually loads
  - `php2cpg` builds a 4.3MB CPG for a 637-file plugin with no errors, and importing it throws during
    overlay application. Every query then returns nothing.
  - Find the boundary: does it load at 100 files, 300, 600? Is one file responsible, or is it size? Joern's
    own message suggests the frontend for large codebases, which is what the fallback already does, so the
    remaining lever is whether overlays can be applied separately or the tree scoped.
  - Until this is answered, PHP detection is demonstrated only on files small enough to build cleanly, and
    no claim about WordPress can be made either way.
  - Observable: the largest PHP tree that loads and queries, measured, with the failure boundary recorded.
  - **Partly answered 2026-09-09, and it produced the first real CVE.** A two-file slice carrying both ends
    of the CVE -- `classes/class.memberorder.php` and `includes/rest-api.php`, 2885 lines -- loads, queries
    in 122 seconds, and reports **CVE-2023-23488 at class.memberorder.php:936:getMemberOrderByCode**, the
    exact verified line. 16 entailed injection findings, and the file holds 26 `$wpdb` query calls of which
    **zero** use `->prepare`, so the engine under-reports rather than over-reports. See
    `benchmarks/measurements/2026-09-09-pmpro-cve-found.json`.
  - **Root cause found 2026-09-09, and it was never a scale limit.** `php2cpg` 4.0.623 reads its PHP parser's
    stdout and stderr as one merged stream. The parser writes a `====> File <next>:` banner to stderr the
    moment it starts the next file, while the previous file's multi-megabyte JSON is still draining from a
    block-buffered stdout; the banner lands inside the JSON, ujson reports `expected json value got "="`, and
    that file is dropped. Reproducible in three commands:

        class.memberorder.php alone (1834 lines)  ->  142KB CPG, no failures
        the same file + a two-line file           ->  5.7KB CPG, BOTH dropped, exit status 0

    One oversized file empties the whole graph, and `joern-parse` propagates none of the warnings -- thirteen
    lines of output, exit 0, "Successfully wrote graph". It is also a **race**, not a threshold: five builds
    of the same two-file input gave three graphs and two empty ones.
  - **Corrected 2026-09-09, and the first diagnosis above was WRONG.** The banner-interleaving story is not
    what happens. Capturing the exact bytes php2cpg receives -- by putting a logging wrapper on `php` -- shows
    the parser's output arriving COMPLETE and VALID: two well-formed JSON documents, 5,176,594 bytes,
    byte-identical across runs. The defect is inside php2cpg's own reading of that input, and nothing outside
    it repairs a given attempt. Tried and each changed nothing: an unbuffered PHP shim, compacting the JSON
    to a fifth of its size (5,176,594 -> 943,028), and `ForkJoinPool.common.parallelism=1`.
  - What IS true and useful: the failure is **intermittent**, and `joern-parse` is both worse at it and
    silent about it. On one WordPress slice, measured:

        joern-parse   5 of 8 builds usable, and says nothing when they are not
        php2cpg      11 of 12 builds usable, and names every file it dropped

  - So php now builds through the frontend directly and retries while it reports dropped files
    (`_build_with_retries`, 4 attempts). Retrying is only sound because the failure is intermittent AND
    reported -- retrying a silent failure would be superstition. Driver-level result on the slice that
    previously needed four manual retries: **6 of 6 builds usable**, 3 entailed findings each time.
  - **Excluded files now get a CPG of their own, 2026-09-10.** A file the frontend refuses is excluded from
    the main build and put in a second graph -- the same file builds perfectly well alone, the failure being
    per-invocation -- and the queries run over both, rows concatenated per request id. The two-file PMPro
    slice that used to report `cpg_empty` and nothing at all now reports **18 entailed findings including
    CVE-2023-23488 at :936**, with `cpg_sharded` beside them.
  - What it does NOT buy is a flow that crosses the shard boundary, and that is why the split is reported
    rather than quietly served: a source in the excluded file whose sink is in the rest of the tree is
    invisible to every question asked. `reports` now renders this under "What could not be analysed", along
    with `cpg_empty`, `files_unparsed`, `query_failed` and `budget_exhausted` -- a degradation is a fact
    about coverage, not a warning to file away.
  - The excluded-file tree is symlinks at the ORIGINAL relative paths, because a region asks about
    `classes/class.memberorder.php` and the queries match a filename by suffix; a flattened copy would answer
    about a file nobody asked about.
  - **The 637-file premise was WRONG, and it was my own instrument. 2026-09-10.** This task opened with
    "`php2cpg` builds a 4.3MB CPG for a 637-file plugin ... importing it throws". It never read the plugin.
    `php` on this machine is a local shim that runs `php:8.3-cli` in docker, mounting `$HOME/joern`, `/tmp`
    and `$PWD` -- and NOT `$HOME/.cache`, which is where every pinned checkout lives. So PHP could not see a
    single file:

        php -r 'var_dump(file_exists($f));'   ->   bool(false)      # on a file plainly there
        php2cpg <637-file checkout>           ->   6,224-byte CPG, exit 0, ZERO reported failures

    Every parser batch failed with `File  does not exist.` and php2cpg wrote an empty graph. That is the
    SECOND false conclusion this shim has manufactured -- see 5.5, "NOT A DEFECT, it was the shim" -- and
    the second time a measurement here was taken through a broken instrument.
  - It is local only. The shipped image installs `php-cli` natively (`Dockerfile`), so no released path was
    ever affected, and our own honesty machinery was right the whole time: a scan over that graph reports
    `cpg_empty`. It was the hand-run `php2cpg` and the note above that drew the wrong conclusion from it.
  - **With the cache mounted, the real envelope, one frontend build of 637 files / 117k lines:**

        wall 33.0s     peak RSS 1,217 MB     CPG 1.6 MB     156 file-drops (69 distinct files)

    Affordable on a CI runner rather than a big machine, which was the open question.
  - The drops are per-BATCH, not per-file: php2cpg gives its parser ~20 files per invocation and a failed
    batch reports every file in it. Dropped file sizes run from **67 bytes to 433 KB**, so size has nothing
    to do with which files are lost -- being in an unlucky batch does. That is why retrying works, and why
    "exclude the difficult file" was the wrong mental model.
  - **The whole-repository scan was measured on 2026-09-10, and it does not work yet.** It builds, it shards,
    it reports every gap honestly -- and it decides nothing.

    | | |
    |---|---|
    | preprocess + entry-point mapping | 107s -> 673 targets, 4,412 entry points, **4,463 regions** |
    | build (driver, incl. retries + shards + census) | 255.9s |
    | query | 720.9s (taint 600.3, dominance 64.1, config 56.5) |
    | arbitrate | 19.8s |
    | total | **996.6s**, peak child RSS **1,132 MB** |
    | regions examined | **500 of 4,463 (11%)**, the default cap |
    | findings | **0** |
    | CVE-2023-23488 | **not reported** |

    The taint query dies in `ForkJoinPool` after ten minutes, and so does a bare `cpg.file.size` census, so
    the problem is the CPG itself under a 2GB heap and not the request payload. The engine says all of it:
    `files_unparsed`, `query_failed` for 2,500 regions, `cpg_sharded`. Nothing here reads as clean.
  - So the honest statement of PHP detection today: **the slices find the CVEs and the repository does
    not.** One file finds CVE-2023-23488, two files find it with a shard, and 637 files find nothing at all.
    A release claim about scanning a WordPress plugin cannot be made on this evidence.
  - Two defects the measurement exposed and fixed along the way -- both mine, both invisible at slice scale:
    `hookCallbacks` was repeated into every request (42.5MB of which 41.7MB was one string), and candidates
    were enumerated for a judge that was never going to be asked (737s -> 19.8s of arbitration).
  - **It is not a heap problem, and it is not the payload.** At 2GB *and* 4GB the CPG never finishes
    loading -- no `OutOfMemoryError`, both runs hit a 900s ceiling, and both died in the same place,
    `Braintree\Util`. What costs is Joern's dataflow overlay, recomputed on every import.
  - **Two thirds of that repository is not its own code.** Of 637 files, **429 are vendored SDKs** (Braintree
    and Stripe, each shipping its own LICENSE and README) and 31 are tests; PMPro's own code is **177 files,
    62k lines**. Auditing a plugin by scanning the payment SDK it bundles is wrong on its own terms -- those
    findings are not the plugin's bugs -- and it is what makes the graph unaffordable. This is the same idea
    `shipped.py` applies to `Makefile.am`, which PHP has no equivalent of.
  - **Scoping to authored code helps and does not fix it.** 177 files:

        regions 4,463 -> 1,324     total 996.6s -> 843.7s     peak RSS 1,132 -> 1,316 MB
        findings 0                 CVE-2023-23488 still not reported

    The taint query hits `QUERY_TIMEOUT_SECONDS` (300s) on **each** shard -- 600.3s of the 843.7s is two
    timeouts, not work. So the wall is the per-request cost of the taint query at 2,500 requests, and
    nothing about memory, the build, or the vendored code removes it.
  - The next measurement is therefore the per-request cost itself, and specifically what the two-stage joins
    cost at scale: they were 1.6x on a slice (62s -> 97s) and are plausibly the dominant term here. Until
    that is known, raising the timeout would only buy a slower way to find out.
  - **ALL OF THE ABOVE ABOUT php2cpg IS WRONG. There is no frontend defect. 2026-09-10.** Every PHP build on
    this machine ran through a local `php` shim that proxies stdio through `docker run`, and php2cpg depends
    on the INTERLEAVING of its parser's stderr banners with its stdout JSON to attribute each document to a
    file. The proxy scrambles that ordering. Measured on the same 177-file tree:

        streaming shim   drops 72-88   767KB / 969KB / 1.2MB   different every run
        buffered shim    drops 0       5,703 bytes             empty, and silent about it
        NATIVE php       drops 0       2,872,996 bytes         byte-identical across three runs

    So: no intermittent batch failure, no ~50% drop rate, no malformed CPG, no dataflow assertion, and no
    scale limit. The `AssertionError: astParent ... has two parents` was a graph the shim had corrupted.
  - **The real 637-file envelope, native php:** `drops=0`, a **4,329,471-byte CPG**, **20.0s wall**, **1.9GB
    peak RSS**. Which is what the ORIGINAL note in this task said -- "php2cpg builds a 4.3MB CPG for a
    637-file plugin with no errors" -- and it was right; everything written against it since was measured
    through a broken instrument.
  - Three of today's mechanisms were therefore built against an artifact: `_build_with_retries`, the sharded
    build with its island CPG, and the census-before-split guard. They are inert on a correct instrument (no
    drops means no retry and no split) and would still help against a genuine frontend failure, so they
    stay -- but the evidence offered for them in their commit messages was not real, and this is the record
    of that.
  - Still open, and now measurable for the first time: whether the queries survive a well-formed 637-file
    graph, what they cost, and what they find. Nothing here recovers a cross-shard flow, but on a correct
    instrument there are no shards.
  - Still open: wiring that exclusion loop, the 637-file build with it in place, and whether the REST handler
    two calls away can reach the sink -- the slice found it through a same-function flow, not across the
    object.
  - _Requirements: 4.2, 4.3, 9.1_
  - _Depends: 5.7_

- [x] 5.11 Two-stage taint with a link table — the detection strategy for both structural misses
  - "Structurally impossible" is a verdict, not a plan, and both PHP structural misses turn out to be the
    SAME shape: two halves of a path, joined by a key that is a literal in the source text.

    ```
    hook:   $_REQUEST -> ... -> return of set_current_page          [half 1]
            key: 'wp_statistics_current_page'   literal at both ends
            return of apply_filters(key) -> ... -> $wpdb->get_row   [half 2]

    field:  $_POST -> ... -> assignment to $this->attachments       [half 1]
            key: attachments                    a field name at both ends
            read of $this->attachments -> ... -> unlink             [half 2]
    ```

    Neither half is missing from the graph. Only the join is. So this is not a request to make a CPG
    frontend draw an edge it cannot draw; it is a second question asked with the query we already have.
  - **Stage 1 -- summaries.** The existing taint question, pointed at a synthetic endpoint instead of a
    modelled sink: does untrusted data reach the RETURN of a registered callback, or an ASSIGNMENT to
    `$this->F`? One extra request per endpoint, on the batch that already runs.
  - **The link table.** Built by reading literals, never by inference: every
    `add_action`/`add_filter('H', callable)` against every `apply_filters`/`do_action('H', ...)`; every
    `$this->F =` against every read of `$this->F` in the same class. The mapper already parses the first of
    those for entry points.
  - **Stage 2 -- the second half.** Again the existing query: does the `apply_filters` return, or the field
    read, reach a modelled sink?
  - **Join on the key**, and let the RUNG carry the join's uncertainty, which is what keeps this honest:
    - exactly one callback registered for the hook, string literal at both ends -> `model_entailed`;
    - several callbacks, or a computed hook name (`"save_post_" . $type`) -> `model_corroborated`, because
      the join is a match rather than a resolution, and the witness must say which.
    Refuse absolutely the approximation "any hook may reach any handler": that is a complete graph over the
    plugin and would entail everything.
  - Costs no new dependency, no CPG mutation and no IR. Both stages ride the batch that already runs, which
    is the whole reason to express this as a query-level join rather than a graph rewrite.
  - **The two compose into a precision win already measured and refused.** With the field half working,
    `_delete_files()` is reached through `$this->attachments` rather than through `$this` being tainted
    wholesale -- so the receiver can then be dropped from parameter sources, taking PMPro's 11
    receiver-sourced findings with it. The fix rejected in 5.8 becomes available once the mechanism under it
    is right, and 5.8's numbers are the before-side of that measurement.
  - Observable, and both are already-pinned pairs so the numbers move or they do not:
    - CVE-2022-25148 entailed on `wpstatistics`'s vulnerable side, absent on its fixed side;
    - CVE-2023-6559 still entailed on `mwwpform` WITH the receiver excluded, and PMPro's receiver-sourced
      count down from 11 to 0 with its CVE still found.
  - Order: the field half first. It is the smaller link table, it has a pinned pair of its own, and it is
    what unlocks the receiver change; the hook half then reuses the same two-stage machinery.
  - **Field half done 2026-09-09.** `taint.sc` gains `fieldSourceNodes`: a read of `$this->F` is a source
    when some assignment to the same literal `$this->F` in the same file is fed by an UNSANITIZED flow from
    a seed. The receiver then left `parameterNodes`, which is only sound because of it.

    |  | before | after |
    |---|---|---|
    | `mwwpform` vulnerable | 1, sourced from `this` | 1, sourced from `$this->attachments` |
    | `mwwpform` fixed | 0 | 0 |
    | `pmpro` vulnerable | 15 — 4 named, 11 receiver | 18 — all named or field, CVE still at :936 |
    | `pmpro` fixed | 1, receiver-sourced | 1 |
    | VAmPI | 4 entailed | 4 entailed, unchanged |

    Three things learned, each of which cost a measurement:
    - **A summary must carry the sanitization status of its half, not just reachability.** Without that,
      `$this->sqlQuery = "..." . esc_sql($x)` reads as tainted and PMPro's fixed side went 1 -> 13. That is
      the pair not separating, which is the only number that matters.
    - **Two-phase `reachableBy` then `reachableByFlows` is SLOWER**, not faster: 183s -> 256s. Running the
      analysis twice costs more than skipping path reconstruction saves.
    - Memoizing per **field** rather than per file took it to 97s, because only fields some region actually
      reads are worth the flow query. Roughly 1.6x the pre-field cost for that class.
  - **Hook half done 2026-09-09, and CVE-2022-25148 is found.**

    | | vulnerable | fixed |
    |---|---|---|
    | `wpstatistics` | 3 entailed, incl. `class-wp-statistics-pages.php:225:record` | 2 entailed, that one absent |
    | `mwwpform` | 1 (`$this->attachments`) | 0 |
    | `pmpro` | 18, incl. CVE at `:936` | 1 |
    | VAmPI | 4 | unchanged |

    The link table is `mapping.php_hook_callbacks`, read from the source text -- php2cpg drops a
    registration's callback argument, so the CPG holds `add_filter("wp_statistics_current_page", )` and the
    edge cannot come from the graph at any price.
  - Four things this cost, each a measurement rather than a guess:
    - **Half one must be asked per ARRAY KEY, not per callback.** "Does an unsanitized value reach this
      callback's return" is TRUE on both sides: the fix escapes `type` and `id` and leaves `search_query`
      alone. A callback-level answer flags the fixed side as readily as the vulnerable one, which is a leak.
      The key is a literal at both ends -- `"id"` in the callback, `['id']` at the sink -- so it joins the
      same way the hook name and the field name do. Third use of the one idea.
    - **The sanitizer test had to stop crediting a sibling's cleansing.** WP Statistics' query is one
      concatenation holding `esc_sql($page_uri)` AND the injectable `{$current_page['id']}`; asking whether a
      sanitizer's name appears in a path element's text marked the whole flow sanitized. An element must now
      BE the cleansing -- a call to it, or its name as a string literal, which keeps `array_map('esc_sql', ...)`
      working.
    - **Hook seeds are repository-wide where field seeds are file-scoped.** A hook registry is global by
      construction: `set_current_page` is in one file and its `apply_filters` in another. The query returned
      nothing at all until those two scopes were separated.
    - **`sourceKind` had to be reported, not inferred.** By the time a row reaches Python a hook source reads
      as `$current_page["id"]` and a parameter as `$args`. `_usable_flows` discards parameter flows whenever
      a modelled one is present, so seven sanitized `$_SERVER["REQUEST_URI"]` flows displaced the CVE. And
      that preference had to move PER SINK SITE: applied across a region it decided one site with another
      site's evidence, and PMPro's CVE at :936 vanished from a region still reporting fifteen findings.
  - Still open: array-key sensitivity is only modelled where the callback builds its result by key
    assignment; the one finding surviving on PMPro's fixed side (`saveOrder:1469 <- $this->timestamp`); and
    `verdict` now delegates to `verdicts`, so the two can no longer disagree.
  - _Requirements: 4.4, 6.1, 8.1, 9.1_
  - _Depends: 5.8_

- [x] 5.13 What a taint request actually costs — measured, and it is not the joins
  - The whole-repository scan fails on taint alone: `dominance` and `config` answer 13 requests in ~75s each
    while `taint` exceeds a 2,400s ceiling on 2,500. Four configurations over ONE verified graph (637 files,
    7,061 methods, census confirmed before timing anything) and ONE request set of 250:

    | | seconds | per request | rows |
    |---|---|---|---|
    | both joins off | 1657.5 | **6,630 ms** | 5779 |
    | field half only | 1623.0 | 6,492 ms | 5779 |
    | hook half only | 1781.0 | 7,124 ms | 5779 |
    | both on | 2026.3 | 8,105 ms | 5779 |

  - **The base query is the cost, not the joins.** 6.63s per request with both halves disabled; the field
    half is free (inside noise, and measured slightly faster), the hook half adds 7.5%, both add 22%.
    Removing them buys a fifth of the time and costs two of the three CVEs, which is not a trade worth
    making.
  - **Corrected 2026-09-10, same day: most of that 6.63 s was never dataflow.** `sinkCalls` scanned every
    call in the graph per request, and `reachableMethods` ran a call-graph BFS per request — both
    independent of the region's family, both repeated 2,500 times. Memoised across the batch (found while
    building flow-aware-ranking's evidence mode, which asks no dataflow and still took an hour), the same
    250 requests with both joins on: **2,026.3 s → 287.0 s, 8,105 → 1,148 ms per request, identical 5,779
    rows.** A 7× speedup with nothing about the analysis changed -- but "1.1 s" is an average over a set
    that was 88% tier-0 pairs answering instantly. With those pruned (flow-aware-ranking phase 1), the 339
    requests that CAN have an answer still exceed 2,400 s: **7–10 s per real request at `callDepth = 3`**.
    The memoisation was real and stays; the per-request figure to design against is that one.
  - **Worse than that, measured directly.** Forty of the 339 real requests, on their own, at `callDepth = 3`:
    **no payload after 57 minutes -- more than 85 s per request.** The 7–10 s figure above was itself an
    average diluted by cheaper pairs. At that cost the phase-1 scan's 339 requests need roughly eight hours,
    which is why 2,400 s was never close. The depth-1 and depth-0 comparison did NOT run (the harness died
    after the depth-3 timeout).
  - **Attributed, then removed.** Ten real pairs (file-scope regions with 1 to 346 sinks, and two functions),
    `callDepth = 1`, each half switched separately, hard process-group-killing timeouts, 2 GB JVM. The fixed
    cost of one Joern invocation -- boot, script compile, graph load, an EMPTY batch -- is **54 s**, and is
    subtracted below:

    | configuration | 10 requests | net per request |
    |---|---|---|
    | both halves off | 165.0 s | 11.1 s |
    | field half only | 163.4 s | 10.9 s |
    | hook half only | **timeout at 540 s** | > 49 s |
    | hook half only, seeds scoped to the callback's file | 151.5 s | 9.8 s |
    | both halves on, after the fix | 150.8 s | 9.7 s |

    The field half costs nothing measurable. The hook half was the whole difference between the cheap REST
    handlers and the real pairs, and stage timers on stderr said exactly where: the last stage to report was
    `applies=5`, and the next -- `taintedKeysOf` -- never did, inside 270 s, for a single request. Its seeds
    were `hookSeedsIn("")`: EVERY field access in EVERY one of the 7,061 methods, each put through the field
    join's `reachableByFlows`. Once per batch, memoised, and never finishing. The seeds a callback's key
    assignments can be fed by are the reads in its own body and the assignments in its own class, so the
    seeds are now computed from the callback method and its file. WP Statistics -- the case the hook half
    exists for -- has `set_current_page` and `$this->rest_hits = ...` in the same file and only `record` in
    another, so the join should be unchanged for it. **Not yet re-verified**, and the reason is its own
    finding: on the WP Statistics graph as the backend builds it today (php2cpg, one file excluded, 9.6 MB),
    `importCpg` alone -- no request at all -- does not return inside 400 s, where the pmpro graph (4.2 MB)
    loads in 54 s. The pre-change query times out on the same request too, so it is not the seed change;
    and the backend's own census had already said `cpg query census failed: timeout` during the build,
    which is the instrument reporting exactly this and being read as a warning. The suspect is the
    default-overlay pass `importCpg` runs on a raw frontend graph every time -- `joern-parse` runs it once
    and saves the result, php2cpg output does not -- and the measurement in flight is `importCpg` plus
    `save` with a 25-minute cap. **Confirmed on the first try, at the default heap:** `importCpg` plus
    `save` died of `OutOfMemoryError` inside `OssDataFlow.create` -- the reaching-definitions overlay --
    after 21 minutes. And the history closes the case: the hook half was verified at 20:42 on 09-09
    (d6908f1) from a `joern-parse` build, which applies the overlays once and saves them; at 21:11 the same
    evening (1ce7e9d) PHP builds switched to raw `php2cpg` output, which has none. Every query batch since
    has recomputed the whole dataflow layer before its first request -- that is the 54 s "fixed cost" on
    pmpro, and on WP Statistics it is the wall. The build now runs `joern-parse --overlaysonly` once after
    the frontend, so a query loads a graph that already has its layers; whether the WP Statistics pass
    completes at all with a heap the product can now actually set was the next measurement: **at 4 GB it
    did not OOM and did not finish either, killed at 25 minutes.** So it is not the heap, it is the pass:
    something in that graph makes per-method reaching definitions explode. `--max-num-def`, the
    per-method cap on that pass, did not save it either: at 1000 it skipped 11 methods and OOMed at 3 GB
    after 474 s; at 200 it skipped 110 and OOMed after 432 s, both inside `initGen`. The cap counts
    DEFINITIONS, and the culprits are two vendored browser-profile tables --
    `includes/vendor/whichbrowser/parser/data/profiles.php` (1.6 MB) and `models-android.php` (1.5 MB) --
    each a single array literal: one definition, a hundred thousand elements. They were 60% of the graph
    (9.6 MB with them, 3.6 MB without).
  - **Resolved, all three, and re-verified.**

    | | before | after |
    |---|---|---|
    | WP Statistics graph | 9.6 MB, overlay pass never finishes | 3.6 MB raw, overlays in 64 s once, **reloads in 8 s** |
    | `record` injection request, `callDepth = 3` | timeout at 520 s | **39 s including the JVM** |
    | CVE-2022-25148 at `pages.php:225` | unverifiable | **entailed, `sourceKind = hook`, unsanitized row present** |
    | pmpro, 10 real pairs, both halves on | 150.8 s (raw graph) | 123.0 s (saved overlays); same 4 evidence keys, 40 duplicate flow rows fewer on one request |

    Three changes, each named in the log rather than silent: (1) `queries/overlay.sc` runs `importCpg` +
    `save` once at build time and the saved graph replaces the raw one (`joern-parse --overlaysonly` is the
    obvious tool and NPEs in 4.0.623 -- filed as joernio/joern#6283); (2) a source file over `MAX_SOURCE_BYTES` (1 MB) is excluded from
    the build as a data table and reported in `unparsed`; (3) the hook half's seeds are the callback's own
    file. The payload diff between a raw and a saved-overlay pmpro graph was checked request by request:
    identical (sink, line, source kind, sanitized) sets, fewer repeated flow paths on the saved one.
  - **`callDepth`, finally measured.** Same ten pairs, both halves on, the saved-overlay pmpro graph; the
    fixed cost is now ~18 s (JVM plus an 8 s reload) and is included:

    | callDepth | 10 requests | per request, JVM incl. | rows |
    |---|---|---|---|
    | 0 | 107.5 s | 10.8 s | 3 |
    | 1 | 124.9 s | 12.5 s | 38 |
    | 3 | 150.5 s | 15.0 s | **3,838** |

    Depth is a 1.4× time term, not the 5× the sharding-era numbers implied -- and a 100× payload term,
    3,838 rows against 38. **How much of that was duplication, measured:** the query now emits one row per
    (sink, source kind, source, sanitized) with the shortest `length` and a `paths` count, and the same ten
    requests at depth 3 return **1,155 rows carrying 3,838 paths** -- a 3.3× collapse, exact by
    accounting, at the same time (15.9 s/request). The other 30× is depth 3 finding more distinct sources
    per sink, which is evidence, not repetition; the first write-up of this table called it "mostly the
    same evidence repeated" and that was a guess the measurement did not support.
  - **The whole-repository scan completes, 2026-09-11.** pmpro, 637 files, the product's own build path
    (overlays at build, seeds scoped, size guard), no judge, `OPENULTRASAST_CPG_QUERY_TIMEOUT=7200`:
    build 97 s, evidence 76 s, **taint 4,105 s for 348 real requests = 11.8 s each**, arbitrate 99 s,
    **total 72 minutes**, peak child RSS 2.4 GB, `tier_counts = {0: 2152, 1: 60, 2: 20, 3: 218, 4: 50}`.
    **CVE-2023-23488 found at `class.memberorder.php:936:getMemberOrderByCode`**, among 250 entailed
    findings across 40 files. First completion of this scan on this repository. The 2,400 s default is
    still too low for it and stays -- a per-push scan of 4,463 regions is the flow-aware-ranking spec's
    problem, and 250 findings is the number that spec now has to concentrate.
  - **Upstream, 2026-09-11:** joernio/joern#6281 (the `global`-inside-a-closure miscompile) is closed as
    fixed -- same root cause as #6269, fixed by #6270, released in **v4.0.625** (we run 4.0.623). The
    maintainer verified our reproducer on master: no node with two AST parents, overlays apply cleanly.
    So `_files_with_frontend_defect` and its exclusion are a workaround for two releases and should become
    version-gated: verify on 4.0.625 (the reproducer, then pmpro and WP Statistics with NO exclusions), and
    check whether #6283 (`--overlaysonly`) is also gone there. **Done, 2026-09-11:** the reproducer builds
    and loads cleanly on 4.0.625; #6283 still reproduces there (commented upstream). Through the backend,
    with the exclusion version-gated off: **pmpro 637 of 637 files in 100 s, WP Statistics 115 s with only
    the two data tables excluded by name.** One more instrument finding on the way: the second install was
    not mounted into the containerised `php`, so php2cpg 4.0.625 parsed 1 of 637 files and exited 0 --
    caught by the build census, and the interpreter precondition now probes the frontend's own parser
    script as well as the repository.
  - **Open, and the maintainer's call, not mine:** `includes/vendor/` is 207 of WP Statistics's 357 PHP
    files and is not excluded by `preprocess.IGNORED_DIRS`, so vendored third-party code is both scanned
    and in the graph. Whether a project's vendored code is in scope is policy; the size guard above is
    not, it is a tool that cannot process a lookup table and says so.
  - **Also found on the way.** `sourceNodes` was a `def` composed of four `def`s, and it was consumed once
    per SINK: a 346-sink file-scope region re-ran the repository-wide `frameworkSources` scan 346 times.
    The four are materialised once per request now. It was not the dominant term (request 4, one sink, was
    0.4 s of graph work either way) but it was pure waste.
  - **Two more instrument findings from the same afternoon.** (1) A `joern --script` run is TWO JVMs: a
    launcher, which is all `-J-Xmx` reaches (163 MB resident), and a forked worker that runs the script with
    no `-Xmx` at all (2.26 GB resident -- the JVM default of a quarter of physical memory). So
    `OPENULTRASAST_CPG_HEAP_MB` governed nothing on this 8 GB machine and would silently take 16 GB on a
    64 GB one. The backend now also sets `JAVA_TOOL_OPTIONS`, which every JVM reads, forked ones included.
    (2) The backend's own unit tests, which feed `build()` a fake engine, left fifteen `ousast-cpg-*`
    directories in `/tmp` per run -- small, but the product's stale sweep waits six hours and the
    directories looked exactly like the leak that was just fixed. `conftest.py` now points `tempfile` at
    the test's own directory.
  - **What "11 s per request" is, then.** With the hook half fixed, the real pairs cost about 10 s each at
    depth 1, of which stage timers attribute well under a second to source materialisation and the joins;
    the rest is `reachableByFlows` per sink, which is the query's actual work. So the 339 phase-1 requests
    are roughly 55 minutes at depth 1 -- affordable as a batch, still not as a per-push scan, and the depth
    question (this at `callDepth = 3`) is still the open measurement.
  - **The estimate this replaces was wrong and worth recording as wrong.** ">0.94s per request" came from
    assuming taint COMPLETED within its 2,400s ceiling. It timed out, so that was a floor presented as a
    figure. The measured cost is seven times higher.
  - Extrapolated: 2,500 requests (the current 500-region budget) is **~4.6 hours**, and all 4,463 regions
    would be about **41 hours**. Repository-scale PHP is not slow, it is the wrong shape of question asked
    thousands of times.
  - **Caveat on the rows.** All four configurations return 5,779 rows -- identical. These are the TOP 50
    regions, which are exactly the REST handlers where framework sources already exist and the joins add
    nothing. The joins earn their keep lower down: `_delete_files` at rank 0.30 and `record` in WP
    Statistics. So this measures their COST faithfully and says nothing about their VALUE, and the two must
    not be conflated when deciding what to cut.
  - The levers, in order of leverage, and none of them is the arbiter:
    - **Fewer, better regions.** 50 well-chosen beats 500 mediocre, which is 5.12 and worth ~10x on its own.
    - **Fewer families per region.** Five taint families are asked of every region regardless of whether the
      scope contains a sink of that family at all. At `callDepth=0` that is exactly checkable and the empty
      ones are free to skip; above zero it needs the reachable set.
    - **`callDepth`.** Three levels of fan-out over 7,061 methods is the term that makes each request cost
      seconds rather than milliseconds.
  - _Requirements: 4.2, 4.3, 9.1_
  - _Depends: 5.10_

- [ ] 5.14 Stop asking questions that cannot have an answer
  - Half the taint budget is spent on questions whose answer is known in advance. Measured on the 500 regions
    a PMPro scan actually examines:

    | family | asked | of those, the file holds no sink of that family |
    |---|---|---|
    | `deserialization` | 487 | **487 — every one** |
    | `untrusted_destination` | 500 | 340 |
    | `output_encoding` | 500 | 178 |
    | `injection` | 500 | 165 |
    | `path` | 500 | 140 |
    | **total** | **2,487** | **1,310 (53%)** |

    At the measured 6.63 s/request that is **4.6 hours now, 2.2 hours pruned** -- and the cut costs nothing,
    because a family with no sink in scope cannot produce a flow. This is not a heuristic.
  - Two rules, and they differ in how exact they are:
    - **Repository-level, exact at any `callDepth`.** If no file in the repository contains a sink of family
      F, never ask F. That alone removes all 487 `deserialization` requests here -- a fifth of the budget --
      and PMPro simply never calls `unserialize`.
    - **Scope-level, exact at `callDepth=0` only.** If the region's own file holds no sink of F, skip it.
      Above zero the sink may live in a reachable method in another file, so this needs the reachable set
      rather than the file, and it should be computed there or not claimed.
  - Do this BEFORE the ranker. It is arithmetic rather than judgement, it cannot lose a finding, and it makes
    every later measurement of ranking cheaper to run.
  - Observable: taint requests issued per scan, and whether the query completes at all on `pmpro`.
  - _Requirements: 4.2, 9.1_
  - _Depends: 5.13_

- [ ] 5.12 The ranker knows one framework, and everything else lands in "unknown"
  - > "the ranker hardcodes wp nodes etc. which means it's not generalizeable. I'd like the LLM to be a
    > flexible layer here to avoid hardcoded / overly specific ranker implementations"
  - **What is actually hardcoded, precisely.** The rank SCALE is generic -- `_ACCESS_RANK` maps abstract
    access levels to numbers and knows nothing about any framework. The EVIDENCE feeding it does not:
    `mapping._wordpress_hook_access` is a Python function containing the literals `wp_ajax_nopriv_` and
    `wp_ajax_`, and `_rest_route_access` contains `__return_true`. One framework, written in code.
  - **The consequence is not "slightly worse on other frameworks", it is no ordering at all.** Measured on
    Paid Memberships Pro, 4,463 regions carry **five distinct ranks**:

    | rank | regions | |
    |---|---|---|
    | 1.00 | 79 | 1.8% |
    | 0.80 | 80 | 1.8% |
    | **0.30** | **3,742** | **83.8%** -- one tier, ordered ALPHABETICALLY BY PATH |
    | 0.15 | 464 | 10.4% |
    | 0.10 | 98 | 2.2% |

    The 0.30 tier spans positions 159 to 3,900, and **341 of the 500 regions examined come from it** -- two
    thirds of the budget spent on an arbitrary alphabetical slice. A Laravel or Django codebase would have
    every region in that tier: thousands, ordered by filename.
  - **A correction that matters, because it was stated repeatedly and was wrong.** CVE-2023-23488's region
    is at position **390 of 4,463** -- INSIDE the 500-region budget, and examined. The earlier claim that it
    ranked ~1036 and was never reached came from a measurement taken before the array-callable and
    method-recogniser fixes moved it. The reason it is not reported is that the taint query TIMED OUT
    (`query_failed`, all 2,500 requests), so no region got a verdict, well ranked or not. Ranking is a real
    problem; it is not this miss.
  - **Reframed 2026-09-10, and this is the shape the whole thing should take.** Pruning impossible questions
    (5.14) is not a separate optimisation, it is TIER 0 of the ranker. The two are one mechanism at different
    resolutions, and once that is seen the unit of ranking changes:

    > **Rank (region, family) PAIRS, not regions — and rank them by evidence that a taint flow could exist.**

    Today the ranker orders regions by declared access and then asks all five families of each, so a region
    is examined for `deserialization` in a repository that never calls `unserialize`. The expensive question
    is "does a source reach a sink of family F in this scope", and it costs 6.63 seconds. Every cheap
    approximation of that question is available for free, from the fact tables and a text scan:

    | tier | evidence | what it means |
    |---|---|---|
    | **0** | no sink of F in scope | **never ask** -- provably empty, cannot lose a finding |
    | 1 | sink present, no source in scope or reachable | ask last |
    | 2 | sink and source present, a sanitizer between them | may still corroborate |
    | 3 | sink and source, no sanitizer, entry point or declared-public | ask first |

    Tier 0 must be EXACT -- it is the only tier that excludes rather than orders, so it may only hold pairs
    that provably cannot yield a flow. Everything above it is ordering, where being wrong costs position
    rather than the finding.
  - That makes the ranker a **cheap conservative approximation of the query it schedules**, which is the
    right relationship: the ranker's job is to spend an expensive budget where the cheap evidence is
    strongest, and its errors are bounded by construction because it cannot exclude anything above tier 0.
  - The three layers below then describe HOW a tier is decided, not what the unit is:
    - **Facts, not code.** Framework vocabulary moves into the semantic tables the way `[[dispatch]]` already
      did today. An `[[access]]` fact declares hook-name patterns and their access level, so
      `wp_ajax_nopriv_*` is a row rather than an `if`. Covers every framework somebody has written facts for,
      costs nothing at runtime, and is auditable.
    - **Generic features that need no framework knowledge at all.** Every region can be scored on things the
      CPG and the existing fact tables already know: how many modelled sinks its file contains, whether a
      modelled source appears in it, its call-graph distance to the nearest sink, whether it is shipped,
      whether any sink call in it lacks a sanitizer on any path. A method holding an unprepared `$wpdb`
      query one hop from a parameter should outrank an empty getter WITHOUT anyone having written a
      WordPress rule. This is the layer that would have moved CVE-2023-23488's region on its own, and it
      should be built before any model is involved -- otherwise the LLM's contribution cannot be measured
      against anything.
    - **The LLM does the ranking.** Not a tie-breaker for a residue -- the ordering job itself. It sees the
      feature vector plus a short excerpt and orders regions, because the thing being judged ("is this
      worth looking at") is a judgement about unfamiliar code, which is what a model is for and what a
      hardcoded table demonstrably is not. Layers one and two remain as CHEAP EVIDENCE for it to read and
      as the fallback when no model is configured, not as the primary ranker.
  - **Why ranking is a safe place for a model, and adjudication is not.** A ranker cannot manufacture a
    finding. It decides what is LOOKED AT, never what is reported: the arbiters still entail or stay silent,
    the three gates stay byte-identical, and a misranked region costs recall rather than producing a false
    claim. The failure is also now visible rather than silent, because `regions_truncated` reports "500 of
    4,463 examined" -- an unexamined region can no longer be mistaken for a clean one.
  - Constraints that belong in the design before any model budget is spent:
    - **Cost.** One call per region is 4,463 calls a scan and nobody runs that in CI. The model ranks a
      prefiltered candidate set in batches, or it is not shipped.
    - **Leak, and it is worse than train-on-test.** Two distinct problems, and only the first is the usual
      one:
      1. **Overfitting.** Four pinned CVEs is not a training set. This needs N projects and
         leave-one-repository-out, with the reported figure from a plugin the optimiser never saw. The
         project already has the scar -- the closed-loop finding where the improve lever learned from
         holdout pairs and inflated its own numbers.
      2. **The loop is CLOSED: the policy determines its own training data.** A region the ranker does not
         put in the budget is never arbitrated, so it never produces a label, so the ranker never learns it
         was wrong about it. The feedback is censored by the very policy being trained, and every run
         confirms the ordering it already had. Optimising on that signal makes the ranker more confident,
         not more correct.
    - **Breaking the loop is a design requirement, not a refinement.** Two mechanisms, both cheap:
      - **An exploration slice.** Reserve a fraction of the budget -- 10% is a reasonable start -- for
        regions sampled from OUTSIDE the top-K. Those are the only labels the ranker did not choose, and
        they are what makes the training signal unbiased. It also has an honest side effect: the scan reports
        that some of its budget went to exploration rather than to its own best guesses.
      - **Full labelling on a small corpus.** For repositories small enough to arbitrate EVERY region --
        VAmPI at 25 regions, a single plugin file -- the ground truth is complete and policy-independent.
        Expensive per repository and bounded in number, which is exactly the right shape for a reference set.
      If the ranking is made stochastic, inverse-propensity weighting is available too, but exploration plus
      a small fully-labelled corpus is simpler and does not require the ranker to be probabilistic.
    - **Reproducibility.** Two runs of one repository must agree, or a baseline diff means nothing. The
      ranking is recorded in the manifest so a change in what was examined is auditable rather than
      invisible.
    - **Degradation.** With no model configured the scan still runs on layers one and two, and the report
      says which ranker produced the order.
  - A model could also PROPOSE facts for an unrecognised framework -- "this codebase registers handlers with
    `Router::get(...)`" as a candidate `[[dispatch]]` row. That is a different and slower loop, and it must
    go through human approval, because a fact is policy and the standing rule is that no policy is
    LLM-authored. Ranking at runtime is not policy; a fact table is.
  - Observable: the rank position of each pinned CVE's region, before and after, on a repository the
    optimiser did not see. `getMemberOrderByCode` is at ~1036 of 4,463 today.
  - _Requirements: 4.4, 9.1_
  - _Depends: 5.8_

## Where PHP detection stands, 2026-09-10

**What works, measured on pinned checkouts with the CVE read out of the code:** three real CVEs found on real
WordPress plugins, each entailed by the graph alone with no model in the loop, each absent from its fixed
side.

| | found at | sourced from |
|---|---|---|
| CVE-2023-23488 | `class.memberorder.php:936:getMemberOrderByCode` | `$id` |
| CVE-2023-6559 | `class.mail.php:259:_delete_files` | `$this->attachments` |
| CVE-2022-25148 | `class-wp-statistics-pages.php:225:record` | `$current_page["type"]` |

Two of those needed the two-stage join (5.11) and would be invisible without it. The mechanism generalises:
one idea -- two halves of a path joined by a key that is a literal in the source -- covered a hook name, a
field name and an array key.

**What does not work: the whole repository.** A 637-file plugin builds in 76s to a 4.25MB graph, `dominance`
and `config` answer, and `taint` does not finish. Three blockers, in the order they bite:

1. **Cost.** 6.63 s per taint request (5.13). 500 regions is 4.6 hours; 53% of those requests cannot produce
   a flow at all (5.14).
2. **Ranking.** 84% of regions share one rank, ordered alphabetically (5.12), so two thirds of the budget is
   spent arbitrarily.
3. **Coverage.** `access_control` is never asked for PHP at all (5.9), and `output_encoding` cannot be
   trusted while the sanitizer list is flat (5.6).

**What is NOT a blocker, contrary to most of what this task file said this morning:** php2cpg. There is one
genuine frontend defect -- a `global` inside a closure produces a CPG Joern's own overlay rejects -- and it
affects 0.2% of files, is detected and excluded automatically, and is reported. Everything else attributed to
the frontend was a local `php` shim proxying stdio, which cost four wrong diagnoses in a day.

**Honesty machinery, which is the part that held up.** Every failure above is reported rather than silent:
`cpg_empty`, `files_unparsed`, `cpg_sharded`, `regions_truncated`, `query_failed`, and a "What could not be
analysed" section that names them in the reader's terms. A scan that decides nothing and says so is a
different artifact from one that decides nothing quietly, and only the second is dangerous.

## Group 6 — Regression baselines

- [ ] 6.1 Repository baseline and delta
  - A committed baseline per pinned checkout; a delta report on fact-table or query changes showing findings
    gained, lost and rung movements. An unexplained loss of a previously-entailed finding is a regression to
    investigate, not a number to accept. The baseline records the **engine version**, because a CPG engine
    change moves every verdict.
  - _Requirements: 10.1, 10.2, 10.3, 10.4_
  - _Depends: 2.2_

## Task-plan review notes

- Group 1 must land and pass review before group 2: measuring an unwired pipeline is what produced a
  session's worth of harness-only numbers.
- Task 1.4 was added after 1.3 was wired, when a ten-line scan took three minutes. It belongs in group 1
  because group 1's promise is a working scan, and a scan that cannot finish on a real repository is not one.
  Finding it here rather than in 2.2 is the argument for wiring before measuring.
- **Task 2.2 is a go/no-go.** If one CPG per repository is infeasible, stop and redesign the region/budget
  model rather than building groups 3–6 on an assumption.
- Group 5 is deliberately last. The corpus is not the binding constraint today — reachability is — and 198 of
  238 OWASP pairs were left unvendored precisely because volume without readability makes every number worse.

---

## Lifted out of this spec (2026-09-09)

Two groups drafted here -- a counter-example ledger, and per-repository evolutionary prompting so developers
can commit dismissals and evolve the harness -- were appended directly to this file without passing
requirements or design. That was a workflow error and they are a separate feature, not a refinement of scan
integration. They now live in `.kiro/specs/finding-feedback-loop/`, at brief, unapproved.

Three requirements amendments this group argues for are drafted at the end of `requirements.md`, also
unapproved: what a report may repeat, a family stating a class it cannot decide, and Req 4.1 requiring a
checkout that can actually demonstrate detection.
