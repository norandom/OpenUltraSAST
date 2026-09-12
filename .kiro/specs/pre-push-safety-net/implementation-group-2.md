# Group 2 implementation verification

Date: 2026-09-12. Scope: tasks 2.1–2.3. All three tasks received independent
APPROVED reviews after task-local verification. The specification remains in
implementation: 7/27 executable subtasks are complete, with groups 3–8 pending.

## Verification result

- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Group 2 resolves immutable pushed revisions, materializes isolated tracked
  source, and supplies bounded lexical change evidence to the shared contract.
- EVIDENCE: Fresh final `.venv/bin/pytest -q`: 1,069 passed, 9 skipped (exit 0).
  Focused snapshot/contracts/audit suite: 148 passed. Global Ruff check and format
  check passed (218 files formatted); touched-module mypy and compileall passed.
  Detection, split-sink map and local pair regression gates each passed.
- GAPS: This is not feature-level GO. Ranker integration, graph/vendor partitions,
  semantic change attribution, persistent caching and the operational hook remain
  scheduled work. No hook detection, precision or latency claim follows.

## Task evidence

| Task | Verified result |
| --- | --- |
| 2.1 | Exact supplied base/head comparisons, configured unique merge bases, tag peeling, special-update dispositions and all ref associations. SHA-1/SHA-256 tests include replacement/graft suppression and missing promisor objects without fetching. Review caught Unicode-aware protocol splitting; six regression cases now retain Git-valid Unicode refs. Full suite at completion: 997 passed, 9 skipped. Commit `05da202`. |
| 2.2 | Direct bounded blob reads with object hashes, reversible binary paths, explicit symlink/gitlink/LFS limits, and owned scratch cleanup. Dirty/non-HEAD success and failure paths preserve live files, index, refs and hooks. Independent hanging-child cancellation removed scratch in 0.202 s. Full suite: 1,037 passed, 9 skipped. Commit `97fd633`. |
| 2.3 | NUL-safe comparison metadata, both-side changed spans, declared configuration paths, renamed-path attribution and unique unchanged-line anchors. PHP/JavaScript declaration-renaming and removed-guard fixtures preserve the unchanged operation's lexical anchor. Repeated lines, unmatched/ambiguous moves, binary and unavailable inputs retain explicit uncertainty. Independent review additionally checked 40 real-Git edits with 4,880 base bytes read. |

The initial disabled implementations failed the relevant tests before implementation;
expanded tests passed after flag removal. Final normalization also fixed formatting
in the earlier push-foundation files without changing their behavior.

## Real repository and packaged checks

`benchmarks/measurements/2026-09-12-snapshot-materialization.json` records a lab
materialization of commit `05da202`: 1,157 tracked files and 8,737,198 source bytes.
Every materialized file was reopened and checked for length and SHA256; the pinned
2,547-byte `pyproject.toml` also matched its Git blob directly. Scratch removal and
unchanged live status/index were verified. Preparation took 5.783 seconds under an
explicit 120-second lab budget. This is preparation cost, not complete hook latency.
The artifact's source hashes match committed task 2.2 implementation `97fd633`.

After final source formatting, `docker compose build ousast` exited 0. Image:
`sha256:2a0dd7943ca9b9c84adc821990d38bff13a7824c7d5a9f94d07c38cb04ce333f`.
Seven packaged source-file hashes matched the workspace. The non-root,
network-disabled `ops/smoke_snapshot.py` run verified 103 JavaScript bytes and 46
PHP bytes, exact pushed comparisons, renamed/removed spans and declared configuration
context in a dirty non-HEAD checkout. Scratch was removed and live state preserved.
The packaged CLI help also exited 0. Retained evidence:
`benchmarks/measurements/2026-09-12-packaged-snapshot-smoke.json`.
Reproduction instructions are in `ops/README.md`.

## Remaining limits and next group

Full-tree `.venv/bin/mypy src/openultrasast` still exits 1 with the same three
pre-existing errors in `model/scan.py` at 299, 302 and 310, checking 108 source files.
No additional type errors were reported. The nine skipped tests remain outside
demonstrated coverage.

Snapshot completeness describes materialized source only. The snapshot contains the
tracked population; task 3.4 applies vendor exclusion and supported language partitions
before graph construction and target selection. Cleanup currently targets the shipped
Linux environment. The resolver's transaction-wide deadline integration remains pending.

Change-context structural paths use `filesystem-bytes-hex`; consumers must decode them
with `ChangeContext.decode_path` before matching canonical question paths. Declaration
paths come from the caller's project discovery; an unavailable inventory is recorded.
Lexical correspondence does not prove semantic function identity, a guard's effect,
or defect novelty. Tasks 3.3 and 4.1 own those decisions.

Next: group 3 integrates the shared execution budget, exact existing-ranker scope,
affected first-party relationships and vendor/language boundaries. The first complete
PMPro/Node experiment remains task 5.2, before persistent caching in group 6.
