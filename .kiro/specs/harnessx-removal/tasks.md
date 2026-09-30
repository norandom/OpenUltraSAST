# Implementation Plan

Order follows the design's commit sequence (Requirement 5): nothing is deleted before its replacement has landed
and passed its fixture test. Every task is a commit gated on the full suite's own exit code, `ruff check`,
`ruff format --check` and `mypy`; the reconciler stays under 500 lines.

- [x] 1. Baseline without the extra
  - Equality script (design §3) with its `find_spec("harnessx")` and freeze checks; re-sync `.venv` without the
    `harnessx` extra first.
  - Record `benchmarks/measurements/<date>-harnessx-removal-baseline/`: full suite, `ousast pairs --json`, the
    `python-vulnerable` quick benchmark, one standard-mode scan, `ousast improve --dry-run`; the exclusion list
    written next to it.
  - _Requirements: 3.1, 5.1_

- [x] 2. Memory store and the `remember` task
  - `plane/memory.py`: the `MemoryStore` interface with `FileStore` and `MinioStore` (object metadata/tags,
    S3 Select JSON queries probed with a local fallback, versioned provenance, lifecycle, presign stubs;
    `OUSAST_MEMORY` selects; MinIO settings from `.env`; `minio` SDK as an optional extra); JSON rows per
    repository + pin, facts by content hash, `FileStore` ingest refuses below 1 GiB free,
    `plane/tasks/remember.py` (model-free), `reconciler.mark_done` under the run lock, seed and ingest wiring in
    `cli._plane`, generator annotations; fact reuse when repository, pin, candidate set and runner image match.
  - Fixture tests: rows from a recorded Run, reuse on an unchanged pin, recompute on a changed one, disk refusal.
  - _Requirements: 6.1, 6.4_

- [x] 3. Proposals from memory
  - `improve/memory.py` with rules M1 (demote) and M2 (promote) and the advisory disputed-family signal;
    `run_round(proposals=...)`; `ousast improve --memory` (opt-in; default output byte-identical); provenance per
    proposal in the sidecar and journal; the train-on-test guard (qualification population, gated benchmark cases,
    holdout pairs).
  - Tests: each rule on crafted rows, the guard drops excluded rows, provenance round-trips, default `improve`
    unchanged.
  - _Requirements: 6.2, 6.4_

- [ ] 4. The loop as a plane Run
  - Tasks `alerts`, `measure`, `propose`, `improve` (no Model, zero budget); `--loop` Run generation; fixed-pin
    Workspaces; the gate's verdict in `<run>/loop-improve/gate.json`; adoption stays a maintainer commit.
  - Fixture tests with the fake ax; one live loop Run on the local ax recorded (no model spend beyond the verify
    passes it reuses from memory).
  - _Requirements: 6.3_

- [ ] 5. Retire the HarnessX scan paths
  - `cli.py`, `fusion.py`, `verify_judge.py`, `stage_processors.py` changes; `RetiredConfigError` for
    `[models] verifier`, `[fusion] panel_model`/`decider_model`; one warning for a `[harnessx]` section (the only
    tagged retirement text allowed in `src`, enforced by a test); tests renamed to the behaviour they assert.
  - _Requirements: 1.1, 1.2, 1.3, 3.3_

- [ ] 6. Delete HarnessX code and packaging
  - Delete `harness_ext.py`, `hunter_harness.py`, `verify_judge.py`'s judge path, the HarnessX-only tests; remove
    the extra, the mypy override and the `uv.lock` entry; rename the conftest fixture; audit rows and manifest; the
    reference search test (Req 2.4).
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 7. Equality proof
  - Rerun the baseline script; commit the comparison record next to the baseline; any difference outside the
    exclusion list blocks the merge.
  - _Requirements: 3.2_

- [ ] 8. Documentation and specs
  - README ax-plane section pointing at `ops/ax/README.md`; `docs/examples.md` §6 and `docs/threat-model.md`
    (egress policy, budgets); dated retirement notes in the four specs and `.kiro/steering/overview.md`; release
    note naming the silent loss of the second hunter for users who set `[models] hunter`.
  - _Requirements: 4.1, 4.2, 4.3_
