# Declarative verification and separate execution domains

Implemented on `search-with-proof`, 2026-10-05, under the maintainer's explicit instructions.
`git merge -q main` failed because the shared Git metadata is read-only. The amended requirements
were read from the main checkout, including Requirements 3.1 and 5.2. No commits or network operations.

## Changes

- Strict, bounded JSON demonstration schema, also supplied to the model's `write_demo` tool.
  Verifier-owned recipes cover pip, npm, composer, Maven, Gradle and no build. Runtime entrypoints,
  CLI/HTTP sequences and earlier-response captures are validated; private fixtures, environment
  substitutions, canary captures and script artefacts are rejected. Injection/traversal strings remain
  legitimate request payload data, never executable verifier instructions.
- The verifier owns build, readiness and request execution. Local runs retain Bubblewrap (`userns`
  on this host). HTTP requests require an acknowledged readiness gate; incomplete observations fail
  closed. Build-generated internal symlinks are supported without accepting external or cyclic links.
- A supplied AX side dispatcher selects `task-boundary` and creates three separate fresh tasks per
  side. Failure of local isolation without a dispatcher fails closed.
- The model-holding worker delegates list/read/grep/run to an executor interface. Production uses
  presigned command/result objects; the in-process adapter is for tests. Commands have sequence
  numbers, identical-retry caching, deadlines, stop and bounded results. Uncertain outcomes prevent
  later commands from reusing that executor session.
- AX executor tasks use the `ousast-engine-search-exec-` prefix. Task entrypoints reject inherited
  credentials before reading checkout input, then use an explicit environment allowlist.

## Changed files

Production:
- `src/openultrasast/search/demo.py`
- `src/openultrasast/search/executor.py`
- `src/openultrasast/search/worker.py`
- `src/openultrasast/search/verify.py`
- `src/openultrasast/search/verify_task.py`
- `src/openultrasast/search/_sandbox.py`
- `src/openultrasast/search/oracles.py`
- `src/openultrasast/search/probe.py`
- `src/openultrasast/search/probe_apps/app.py.txt`
- `benchmarks/ax/batch.py`
- `benchmarks/ax/search_verify.py`
- `plane/Dockerfile.search-task`

Tests and audit:
- `tests/test_search_demo.py`
- `tests/test_search_executor.py`
- `tests/test_search_verify_transport.py`
- `tests/test_search_verify.py`
- `tests/test_search_worker.py`
- `tests/test_search_isolation.py`
- `tests/test_search_probe.py`
- `tests/test_ax_batch.py`
- `benchmarks/measurements/2026-09-08-module-audit.json`

This report is the additional documentation file.

## Fresh validation

`/home/mc/Source/OpenUltraSAST/.venv/bin/pytest -q tests/test_search_*.py tests/test_ax_batch.py tests/test_plane_literals.py tests/test_module_audit.py -rs`

Result: **171 passed, 3 skipped, exit 0**, in 35.46 seconds.
The three skips are Chromium isolation/network setup, SSRF localhost sockets and HTTP localhost sockets,
all prohibited by this host's policy. Host verification mode was explicitly checked: `userns`.

Ruff passes for search sources, AX changes and affected tests. Targeted strict mypy passes for the seven
changed Python search implementation modules checked. Independent review approved the implementation,
including follow-up timeout, readiness, capture, credential and generated-link regressions.

Module audit: **171 modules**, **165 load-bearing**, **6 standalone capabilities**, **0 orphaned**.
The audit read the worktree source explicitly with `PYTHONPATH=src`.

## Remaining validation gaps

- No live AX/gVisor/kind dispatch, image build/pull/publish, or paid model calls were performed.
- Actual ecosystem dependency installations remain unqualified. Python dependency loading was tested
  with a controlled offline build output and real isolated execution.
- The three socket/browser integrations need a host or task where those operations are permitted.
- Hard aggregate disk isolation in `task-boundary` mode requires an outer task storage quota. The
  executor records this requirement and additionally bounds individual files and monitors checkout
  growth; it cannot enforce a quota across every writable task path without that outer resource limit.
- AX tasks configured to inject a model credential will fail closed; executor and verifier task classes
  must be provisioned without that injection.
