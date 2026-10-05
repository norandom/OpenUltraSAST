# Implementation Plan

Scope: infrastructure probe and feasibility pilot only (Req 6.1-6.2). BLOCK qualification (6.3), the unseen-pool arm
(6.5) and delivery (6.6) are deferred until the pilot passes. Implementation via Codex in a worktree; Claude reviews,
gates, runs every networked or paid step.

- [ ] 1. Operator prerequisites (Claude, no code)
  - [ ] 1.1 Ask the operator: scoped spend-limited model key mechanism (reuse `gemini-api-secret` slot or a new
    injection), and whether a no-egress task class exists for verify runs. _Requirements: 5.1, 3.2_
  - [ ] 1.2 Record the answers in `kube-ax-cluster` memory and design.md; no key value anywhere. _Requirements: 5.2_

- [x] 2. Verifier and oracles (no model calls)
  - [x] 2.1 `src/openultrasast/search/verify.py`: fresh-sandbox runner per side; build, readiness check, read-only
    checkout and dependencies, untracked-file and runtime-patch refusal, 3 runs per side, consistency check,
    outcomes `demonstrated|inconclusive|could_not_build|could_not_run|no_oracle`. Artefact exit code ignored.
    _Requirements: 3.1-3.4_
  - [x] 2.2 Oracles owned by the verifier: SQL (database fixture + query log), path (file-access watch on a planted
    canary), XSS (headless browser execution check), SSRF (in-sandbox listener), command injection (process watch).
    Observers unreachable from the artefact. _Requirements: 3.1, 3.2, 3.5_
  - [x] 2.3 Unit tests with hand-written vulnerable/fixed toy apps per oracle, including gaming attempts (reading the
    canary, revision sniffing, patching a dependency, contacting the listener directly): each must not yield
    `demonstrated`. _Requirements: 3.2, 3.3_

- [ ] 3. Image and infrastructure probe (no model calls)
  - [ ] 3.1 `ousast-search-task` image from the AX task runner: Python, Node/TypeScript, PHP, Java toolchains, the
    oracle fixtures, headless browser; built by CI to GHCR, pinned by digest. _Requirements: 2.3_
  - [ ] 3.2 Probe: the toy apps from 2.3 verified as AX Tasks on kube-ax (gVisor) and on kind. Record image size,
    RAM peak, disk, wall time per verification and per 18-run search, oracle success per family, and that observers
    are unreachable. Record `benchmarks/measurements/2026-10-xx-search-probe/record.json`. _Requirements: 6.2_
  - [ ] 3.3 Gate: every oracle works under gVisor, or the family is marked `no_oracle` for the pilot.

- [x] 4. Board, coordinator, budgets
  - [x] 4.1 Board in the memory store as immutable versioned blobs (`plane/memory.py`); facts, intents, hints with
    writer step and task; coordinator is the only writer; tasks read and write through presigned links.
    _Requirements: 1.1-1.3_
  - [x] 4.2 Spend reservation before each model call in `plane/budget.py`, settled after; per-task memory, disk,
    cleanup caps; total wall-time and retry caps; tests that in-flight calls cannot overrun. _Requirements: 4.1, 4.2_
  - [x] 4.3 Dispatch reason, explore and verify as AX Tasks through `benchmarks/ax/batch.py` (extend its environment
    contract beyond numeric deadlines), VM lane as fallback, resume from checkpoints. _Requirements: 2.3, 2.4_

- [ ] 5. Agent worker
  - [x] 5.1 Reason step (no tools): board snapshot in, `complete` / up to 3 intents / nothing out. _Requirements: 2.1_
  - [x] 5.2 Explore step: tool loop (`list_files`, `read_file`, `grep`, `run`, `write_demo`, `finish`) via the
    existing OpenAI-compatible client; model client in a separate process and user from executed code; one fact
    or a recorded failure. _Requirements: 2.2, 5.2_
  - [ ] 5.3 Smoke test with a stub model (no spend) end to end on one toy pair on kube-ax.

- [ ] 6. Feasibility pilot (paid, after go-ahead)
  - [x] 6.1 Select 20 development-corpus pairs (never v3 or the unseen pool) in the four pool families with an owned
    oracle, across the five languages; record selection advantages. _Requirements: 6.1_
  - [ ] 6.2 Run 3 searches, measure real cost per search, ask the maintainer for the pilot ceiling. _Requirements: 4.3_
  - [ ] 6.3 Run the pilot: both sides per pair, fixed side blind to the vulnerable revision; record demonstrated
    rate, false proofs, failure-outcome rates, both coverage ceilings, spend, tasks, wall time.
    _Requirements: 6.1, 6.4_
  - [ ] 6.4 Exit decision against 6.2 and report to the maintainer; on pass, spec tasks for qualification and the
    unseen-pool arm. _Requirements: 6.2_

## Implementation Notes

- Group 2 (2026-10-05): independently reviewed; `tests/test_search_verify.py` has 32 passing tests and one
  skipped SSRF integration test because this host forbids even localhost sockets. The namespace handoff and
  listener request parsing are tested separately; the full SSRF effect still needs the task 3.2 probe before
  claiming that oracle operational. The module audit and neighbouring sandbox/regression tests pass.
- The local lane requires Linux Bubblewrap and util-linux, reuses `SandboxJob`/`SandboxResult`, and fails closed
  without isolation. Artefacts receive a batch CLI `TARGET` bridge and private scratch; HTTP apps need a trusted
  CLI adapter. Only trusted `Side.build_command` outputs can enter the app runtime (read-only `/build`);
  artefact `build.sh` writes scratch only. XSS requires a trusted browser executor, otherwise `no_oracle`.

- Tasks 3.1 (files only) and group 4 (2026-10-05): independent review approved; final offline validation:
  107 passed, 2 skipped (Chromium namespace/socket restrictions and the existing SSRF localhost restriction).
  Ruff and changed-source mypy pass; module audit: 160 load-bearing, 6 standalone, zero orphaned. No network
  actions, model calls, image builds, pushes or commits were performed. Task 3.1 remains unchecked until the
  image is built/published and a real digest is available; CI now includes `plane/Dockerfile.search-task`.
- The coordinator accepts an injected executor. `BatchExecutor` uses the repository's `benchmarks.ax.batch`
  transport with one attempt per admission; coordinator owns the global retry budget and VM fallback. It requires
  a repository checkout import path and a trusted worker command; reason/explore workers remain group 5.
  Per-task memory, disk and cleanup ceilings are passed in the worker contract; worker enforcement and gVisor
  compatibility still require group 5 and the 3.2 probe. Only trusted verification results can meet the goal.
- Board heads are immutable memory-store hashes; retain the returned head with the host run to resume. Unknown
  interrupted model calls conservatively consume their full reservation; settled failures with zero spend release
  it. Cleanup exceptions stop dispatch. Chromium uses a fresh profile in a private network namespace; injected
  script must call `alert("ousast-xss")`, while escaped/reflected payloads cannot produce the verifier DOM marker.

- Tasks 3.2 and 5.1–5.3 offline implementation (2026-10-05, explicitly authorized): packaged five-family
  toy pairs and real/two-gaming demos in `search/probe_apps/`; `python -m openultrasast.search.probe` reports
  per-side stage times, image versions, child/self peak RSS, retained scratch usage and sampled verification
  scratch peak. Generic isolation and later oracle namespace failures are instrument failures, never misses.
  Optional RESULT_URL uses an object-scoped urllib PUT. `benchmarks.ax.search_probe` reuses AX/Docker lanes
  (kind via its kubeconfig), with `ousast-engine-search-probe-` task names.
- Worker reason/explore uses the existing OpenAI-compatible client with retries disabled and SpendBudget
  reservation before each call. Repository commands run only in the scrubbed sandbox with bounded tmpfs;
  the key-absence, timeout, output limit and disk limit tests execute real isolated processes. The scripted
  model/fake coordinator executor smoke reaches `demonstrated` through the real path oracle verifier.
- Independent review APPROVED the requested offline scope. Fresh requested search/AX/plane tests plus module
  audit: 87 passed, 2 skipped, exit 0; focused new tests: 15 passed; Ruff and changed-source mypy pass.
  Audit: 162 load-bearing, 6 standalone, zero orphaned. Tasks 3.2 and 5.3 remain unchecked for their original
  live-cluster criteria; their code/local smoke is implemented. No network, paid calls, image builds, pushes
  or commits. Offline wheel build could not resolve the uncached uv-build backend, so installed-wheel and
  real AX/gVisor/kind/Docker image validation remain gaps.

- Task 6.1 and executor smoke (2026-10-05, explicitly authorized): added
  `benchmarks/search/executor_smoke.py` and `pilot_select.py`, with offline tests and usage documentation.
  The smoke drives one managed, key-free executor mailbox and records per-command timing/output measurements
  and sampled workspace peak; AX and Docker lifecycle cleanup is covered by fake-lane tests. No live task ran.
  Pilot selection read 10 development catalogs (873 rows, 904,050 bytes), retained 192 eligible pairs and selected
  20 distinct repositories: four per language and five per family. Identities live only in the gitignored local
  manifest; the aggregate record is `benchmarks/measurements/2026-10-05-search-pilot-selection/record.json`.
  All 20 selections have unknown manifest/test-suite evidence; no matching local cache or frozen unseen-pool
  metadata was present. These are feasibility inputs, not proof of buildability or qualification.
  Both task-local independent reviews approved after a reserved-cache-symlink regression was fixed.
  Fresh requested search/AX/plane tests, module audit, independent/reserved and unseen guards, and label guards:
  287 passed, four skipped, exit 0. Skips: Chromium isolation, two localhost-socket cases, and no frozen pool.
  Ruff and changed-source mypy pass; audit: 166 load-bearing, six standalone, zero orphaned.
  No network or commits. The requested main merge could not update read-only Git metadata; HEAD and main
  had identical file trees. Live AX/Docker executor smoke and oracle probes remain unmeasured.
