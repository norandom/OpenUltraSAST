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

- [ ] 2.3 Decide on Joern server mode, on 2.2's numbers
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

- [ ] 2.6 Access control that does not entail every public endpoint
  - 7 of 9 VAmPI handlers were entailed, including `register_user` and `get_all_users`, which are meant to
    be unauthenticated. The dominance rule -- unguarded, with guarded siblings -- was calibrated on pairs
    where a guarded twin always existed. At repository scale every public endpoint has guarded siblings.
  - This is a precision question and needs a precision measurement: on a real repository, what fraction of
    entailed access-control findings are endpoints that genuinely require authorisation? Do not tune it
    against VAmPI alone; that is how the +16% overfitting gap in Req 8 happened.
  - Observable: a recorded precision figure before and after, on more than one checkout.
  - _Requirements: 8.1, 8.2_
  - _Depends: 2.2_

- [ ] 2.7 A dominance witness that names its line
  - Access-control sites read `api_views/users.py:?:update_password`. Taint and config witnesses carry
    `(line N)`; dominance does not, so its findings have no line and a contributor cannot open them.
  - Observable: every entailed finding in a repository scan has an integer line.
  - _Requirements: 5.1_
  - _Depends: 2.2_

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

- [ ] 5.1 PHP/WordPress slice
  - Plugin and core weaknesses. `php2cpg` needs a PHP interpreter, which the image provides. **Validate on a
    sample that the model can read the pairs before vendoring** — the OWASP harvest found 238 and vendored 40
    for exactly this reason.
  - Observable: a sample measurement precedes vendoring; only categories the model can arbitrate are
    vendored; the slice reports as its own row; every pair states a licence.
  - _Requirements: 9.1, 9.4, 9.5, 9.6, 9.7_
  - _Depends: 3.2_

- [ ] 5.2 More vibe-code pairs
  - The slice where the stated audience works, currently 35 pairs. Same read-check discipline.
  - _Requirements: 9.3, 9.4, 9.5, 9.6, 9.7_

- [ ] 5.3 Real-world C library CVEs
  - libpng and the image libraries, OpenSSH, libpam, kernel modules. **Gated on 4.1**: until the memory
    decision closes these would join 173 idle pairs.
  - _Requirements: 9.2, 9.4, 9.5, 9.6_
  - _Depends: 4.1_

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
