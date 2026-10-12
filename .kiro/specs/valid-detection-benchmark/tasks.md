# Tasks: valid detection benchmark

Order is dependency order. Each task is small enough to review on its own. New code under
`benchmarks/valid/`. Implementation goes through Codex, gated here.

## Group 1 - positive catalog (fix-site, no SZZ)
- [x] 1.1 `benchmarks/valid/catalog.py`: given sourced advisories (reuse `source.py`/`draft.py` output),
  build candidate positive cases by fix site. Wrap `extract.fix_sites()` + `pairs/materialize.py`; read
  the pre-fix function at `parent` and the post-fix function at `commit`. Must not call `introducing` or
  `last_touch`. Emit the `[[case]]` catalog in the design schema. (R1)
- [x] 1.2 Filter to Python and JS/TS only; attach `language` and `family`/`cwe`. (scope decision)
- [x] 1.3 Offline test: a fixture commit yields one case with the correct pre/post functions and
  `method = "fix_site"`; assert SZZ methods are never invoked.

## Group 2 - LLM verification driver
- [x] 2.1 `benchmarks/valid/verify.py`: one DeepSeek call per case via the shipped provider (off-cluster).
  Confirm vulnerable-pre-fix, fix-addresses-it, reachable-in-repo; name the entry point; return
  confidence. Print bytes read per function before the call; reject a verdict on an empty read. (R3, instrument rule)
- [x] 2.2 Emit the verification record (design schema) to `verification.json`; `verdict = "accepted"`
  only when all three checks pass. Reachability here is the app-shaped filter. (R2, R3)
- [x] 2.3 Human spot-check hook: a small CLI to record accept/reject + reviewer + date per case into the
  same record. (R3)
- [x] 2.4 Offline test with a stub model: a case with all three true and a human accept becomes
  `accepted`; any false, or a human reject, does not.

## Group 3 - negatives and assembly
- [x] 3.1 `benchmarks/valid/assemble.py`: draw negatives with `extract.draw_ordinary()` from the accepted
  positives' repos, at least 20x, excluding the fix. (R4)
- [x] 3.2 Freeze accepted positives + negatives into a `pool.toml`-shaped manifest + `freeze-valid.json`
  digest; run the held-out guard via `eligibility.normalize`. (R5, R8)
- [x] 3.3 Offline test: freeze is deterministic (same source -> same digest); held-out guard drops any
  repo in the used set.

## Group 4 - metrics
- [x] 4.1 `benchmarks/valid/metrics.py`: precision (PPV) with Wilson 95% over positives+negatives. (R7)
- [x] 4.2 False alarms per 100 pushes as the presentation of `score.py`'s false-alarm rate. (R7)
- [x] 4.3 Exploit-verified rate: join flagged positives with a search-with-proof run by case `id`;
  report "not yet proved" where absent. (R7)
- [x] 4.4 Build the headline string (recall + FP/100 + precision + exploit-verified). (R7)
- [x] 4.5 Offline test on a tiny hand-made record set: all four metrics and intervals match hand calcs.

## Group 5 - pilot run (research, local)
- [ ] 5.1 Source Python/JS advisories; run `catalog.py` to ~25 candidates. (deliberate, rate-aware)
- [ ] 5.2 Run `verify.py` + human spot-check to land ~12 accepted positives.
- [ ] 5.3 `assemble.py` freezes the pilot manifest + negatives (>=20x) + held-out guard.
- [ ] 5.4 `replay.py` on the Docker lane, arm (a): the push hook as shipped (quick + engine, 300 s).
  Running overnight 2026-10-12; records under `~/ousast-results/valid/pilot/long_deadline`.
- [ ] 5.5 `score.py` + `metrics.py` on arm (a): recall, precision, FP/100, exploit-verified, intervals,
  and the headline, labelled "push hook as shipped". Freeze the run under `benchmarks/measurements/`.
- [ ] 5.6 Write up the pilot: the four numbers for (a), what they mean, the engine-covered rate, and the
  target set size from `required_n` for the full ~40-positive benchmark.

## Group 6 - hunter arm (the LLM tier required on pre-push)
- [ ] 6.1 `benchmarks/valid/hunter_arm.py`: for each change in the frozen manifest, check out `head` in
  the local clone, build `FileTarget`s scoped to the changed files, run `hunter.run_hunter_pool`
  (`src/openultrasast/hunter.py`, wiring in `cli.py` `_attach_tool_hunter`), and emit a record `score.py`
  can read (an alerts/advisory stream keyed by change id). Runs off-cluster; the model key never enters
  a replay container. Honors the instrument rule (bytes read per target, fail loudly on an empty read).
- [ ] 6.2 Combine arm (a) and arm (b) records per change id and rescore: this is the number the tool is
  held to (R6). Report (a), (a)+(b), and the difference as the pre-push product gap.
- [ ] 6.3 Offline test with a stub hunter: a flagged change joins the (a) record; a missing (b) record
  leaves (a) unchanged; duplicate ids are rejected.

## Out of this spec
- Growing beyond the pilot to the full set (follow-up, once the pipeline is proven).
- Running on kube `ax` (blocked on gVisor; Docker lane is enough here).
- Any new detection capability, including wiring the hunter into the pre-push hook. That is product
  work in `pre-push-safety-net`; this spec measures the push path with and without it.
