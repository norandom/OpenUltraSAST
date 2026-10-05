# Host launcher repair and kube-ax operator constraints

2026-10-05, branch `search-with-proof`. Implemented under the maintainer's explicit
instructions. No commits or network operations. Existing uncommitted work was preserved.
This supersedes the build/transport and disk-bound statements in
`implementation-trust-domains.md` where they differ.

## Root cause and repair

The HTTP driver calls `subprocess.Popen(..., stdin=DEVNULL, stdout=DEVNULL,
stderr=DEVNULL)` inside bubblewrap. Its filesystem had no `/dev/null`; Python failed
in `_get_handles` before starting the app, binding port 18765, or applying captures.
Other probe apps do not use this nested HTTP launcher path.

A socket-free before/after reproduction read a 19-byte instrument input. Removing
`--dev /dev` reproduced exit 1 and the reported `subprocess.py:992 → _get_handles`
stack, ending with `FileNotFoundError: [Errno 2] No such file or directory: '/dev/null'`.
With the private device mount, the identical launcher exited 0 with empty stderr.
The original HTTP capture test's fixed port, token exchange, and differential
assertion remain unchanged. Reasons now retain the last 2,000 stderr characters;
executor result truncation retains stderr tails too.

## Operator contract

- Shared two-slot AX reservations cover workload lane instances and long-lived
  search executors. Capacity rejection retries the identical manifest with 15–30
  seconds of jitter until the deadline. Exhaustion is `capacity_timeout`, never
  `sandbox_failure`, and does not trigger another execution attempt or VM fallback.
  Uncertain task cleanup retains the reservation and halts dispatch.
- Task entrypoints configure temporary files and the specified package caches under
  `/workspace`. The aggregate guard defaults to 2 GiB, configurable through
  `OUSAST_SCRATCH_BYTES`. It checks workspace files, caches, and unlinked output logs
  during child execution and after exit. Exceeding it returns `could_not_build` with
  `scratch limit`; unreadable scratch is not interpreted as zero usage.
- The default AX side dispatcher first builds/packages each side in an executor,
  retrieves its digest-checked archive, and deletes the executor before verification.
  One archive contains the checkout, products, and spec. Three fresh verifier tasks
  consume that archive through `VERIFY_INPUT_URL`; results use `RESULT_URL`.
  Verifiers reject dependency builds. Git metadata is omitted from source archives;
  safe internal generated links are materialized before export.
- Search tasks receive source archives. Executor tool guidance and project/operator
  documentation require HTTPS GitHub git clone or codeload, never `api.github.com`.
  First-download retries tolerate delayed egress activation for up to 60 seconds.

## Files changed in this follow-up

Production:
- `src/openultrasast/search/_sandbox.py`
- `src/openultrasast/search/verify.py`
- `src/openultrasast/search/executor.py`
- `src/openultrasast/search/verify_task.py`
- `src/openultrasast/search/task_storage.py` (new)
- `src/openultrasast/search/worker.py`
- `benchmarks/ax/batch.py`
- `benchmarks/ax/search_verify.py`

Tests:
- `tests/test_search_isolation.py`
- `tests/test_search_verify.py`
- `tests/test_search_verify_transport.py`
- `tests/test_search_task_storage.py` (new)
- `tests/test_ax_batch.py`

Documentation/evidence:
- `.kiro/steering/kube-ax.md` (new)
- `ops/ax/README.md`
- `benchmarks/measurements/2026-09-08-module-audit.json`
- This report (new).

Other files already modified/untracked at session start remain uncommitted.

## Fresh verification

- Requested suite, with `-rs` for skip reasons:
  `/home/mc/Source/OpenUltraSAST/.venv/bin/pytest -q tests/test_search_*.py tests/test_ax_batch.py tests/test_plane_literals.py -rs`
  — **181 passed, 3 skipped, exit 0**, 24.94 seconds.
- Final executor/storage regression and module audit tests after tightening stderr
  truncation: **34 passed, exit 0**, including all **6 module audit tests**.
- Shared dispatcher consumer `tests/test_unseen_calibrate.py`: **10 passed, exit 0**.
- Module audit regenerated from the worktree using `PYTHONPATH=src`, with an explicit
  source read/byte count: **172 modules, 166 load-bearing, 6 standalone capabilities,
  0 orphaned**.
- Ruff passes across search, AX, and changed tests; strict mypy passes for the six
  changed typed implementation modules. `git diff --check` passes.

## Gaps

- Host policy prohibits Chromium network/isolation setup, SSRF localhost sockets,
  and the full HTTP capture test. These are the three skips. The exact missing-device
  failure is reproduced and repaired without sockets; full HTTP host confirmation
  remains necessary.
- No live AX tasks, image builds/pulls, registry installs, or external downloads were
  run. Mocked transport plus local real child processes establish code contracts,
  not deployed cluster readiness. Verifier egress to
  `files.because-security.com:443` is requested from the operator and still pending.
- Scratch enforcement is a polling guard, not an instantaneous filesystem quota.
  Programs that hardcode RAM-backed paths can still consume the worker memory limit.
  Archive bounds remain 64 MiB compressed / 256 MiB file contents / 20,000 entries;
  larger built projects fail explicitly and require a separately qualified envelope.
- Multi-ecosystem dependency build/runtime qualification remains open. The offline
  preparation tests cover no-build projects and controlled Python build products.
