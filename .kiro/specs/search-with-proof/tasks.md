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

- [ ] 4. Board, coordinator, budgets
  - [ ] 4.1 Board in the memory store as immutable versioned blobs (`plane/memory.py`); facts, intents, hints with
    writer step and task; coordinator is the only writer; tasks read and write through presigned links.
    _Requirements: 1.1-1.3_
  - [ ] 4.2 Spend reservation before each model call in `plane/budget.py`, settled after; per-task memory, disk,
    cleanup caps; total wall-time and retry caps; tests that in-flight calls cannot overrun. _Requirements: 4.1, 4.2_
  - [ ] 4.3 Dispatch reason, explore and verify as AX Tasks through `benchmarks/ax/batch.py` (extend its environment
    contract beyond numeric deadlines), VM lane as fallback, resume from checkpoints. _Requirements: 2.3, 2.4_

- [ ] 5. Agent worker
  - [ ] 5.1 Reason step (no tools): board snapshot in, `complete` / up to 3 intents / nothing out. _Requirements: 2.1_
  - [ ] 5.2 Explore step: tool loop (`list_files`, `read_file`, `grep`, `run`, `write_demo`, `finish`) via the
    existing OpenAI-compatible client; model client in a separate process and user from executed code; one fact
    or a recorded failure. _Requirements: 2.2, 5.2_
  - [ ] 5.3 Smoke test with a stub model (no spend) end to end on one toy pair on kube-ax.

- [ ] 6. Feasibility pilot (paid, after go-ahead)
  - [ ] 6.1 Select 20 development-corpus pairs (never v3 or the unseen pool) in the four pool families with an owned
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
