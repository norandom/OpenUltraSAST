# Group 1 implementation verification

Date: 2026-09-12. Scope: tasks 1.1–1.4 only. All four tasks received independent
review with an APPROVED verdict and fresh task-local verification. Requirements,
design and tasks remain approved; implementation remains in progress (4/27 subtasks).

## Verification result

- STATUS: VERIFIED
- CLAIM_TYPE: TASK
- CLAIM: Group 1 establishes the reproducible runtime, evaluation inputs, honest
  scoring and shared push/engine contracts.
- EVIDENCE: Final independent review ran the full suite: 965 passed, 9 skipped.
  Focused contracts/configuration tests: 53 passed. Ruff and mypy passed for the
  seven touched contract/configuration modules. `git diff --check` passed.
- GAPS: This is not feature-level GO. The pre-push runtime, persistent cache and
  capability admission are not implemented. No end-to-end latency or precision
  claim follows from these tests.

## Task evidence

| Task | Result and retained evidence |
| --- | --- |
| 1.1 | Joern 4.0.625 packaged and exercised with native PHP and JavaScript. Actual source bytes, graph census and query witnesses were verified; unreadable input failed explicitly. See `benchmarks/measurements/2026-09-12-engine-runtime-smoke.json`. Suite at review: 888 passed, 9 skipped. Commit `56cfc9d`. |
| 1.2 | Pinned PMPro and NodeGoat vulnerable, repaired and benign recipes; explicit authored-repair provenance. Offline validation read 506,502 bytes: 8 snapshots ready, 1 missing; 7 cases ready, 4 missing. Missing prerequisites cause exit 1. See `benchmarks/push/input-validation.json`. Suite: 902 passed, 9 skipped. Commit `8acada0`. |
| 1.3 | Frozen evaluation identity and uncertainty-preserving scorer. VAmPI retains all three known defects; unmatched SQL injection is not silently called transitively covered. Empty runs remain unmeasured. See `benchmarks/ranking/baselines/2026-09-12-vampi-position-v2.json` and `benchmarks/push/diagnostic-profile-v1.json`. Suite: 925 passed, 9 skipped. Commit `051f3b0`. |
| 1.4 | Strict immutable configuration, budget, question, scope, graph artifact and comparison-owned result contracts. Incomplete/unexecuted work cannot become complete through serialization. Existing scan configuration remains compatible; runtime enforcement is pending. Final suite: 965 passed, 9 skipped. |

## Packaged runtime and limitations

After the final source changes, `docker compose build ousast` exited 0. Final local
image: `sha256:92d311097075a2092a2e362b5470d706734f9de35de7820c3de5eb1ad91b17d5`.
A network-disabled container imported the new contracts, read an 83-byte TOML
configuration, round-tripped its push settings, rejected a NaN deadline, and ran
`python -m openultrasast.cli --help` successfully. Runtime: UID 1000, Python 3.12.3.
The earlier graph smoke records its own image identity; the backend did not change
after that smoke. The final packaging check does not repeat or replace graph evidence.

Full-tree `.venv/bin/mypy src/openultrasast` still exits 1 with three pre-existing
errors in `model/scan.py` at lines 299, 302 and 310 (candidate redefinition and
incompatible candidate types). It checked 107 source files with no additional errors.
Skipped tests and the unavailable evaluation prerequisites remain outside demonstrated
coverage. Ghost is a reserved workload, not a scanned or admitted positive population;
independent paired/holdout evidence remains required per capability.

## Design direction and next work

The ranker remains the scope mechanism. Vendor exclusion applies to graph inputs
as well as targets. PMPro guides core development and JavaScript/Express tests
transfer; Python regressions and C-family abstraction limits remain explicit.

Persist validated immutable graphs first. Separate graph, query/evidence and ranked
result identities so ranking-only changes can reuse compatible graphs and evidence.
Differential graph mutation is a future experiment requiring equivalence to cold
rebuilds, including deletions, renames, dependent edges and overlays. No stable
Joern node-ID assumption or partial-file update is accepted as proof of correctness.

Next: group 2 immutable push snapshots and comparison resolution, then the first
complete PMPro/Node experiment at task 5.2. Persistent caching remains group 6;
normal advisory capability admission remains gated by task 8.3.
