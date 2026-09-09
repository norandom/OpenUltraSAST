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

- [ ] 2.9 One defect is one finding, however many regions reach it
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
