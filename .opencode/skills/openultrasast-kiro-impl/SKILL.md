---
name: openultrasast-kiro-impl
description: OpenUltraSAST Kiro implementation steering. Use when continuing `.kiro/specs/openrouter-sast-harness/tasks.md`, choosing the next phase, updating checkboxes, or keeping implementation aligned with the spec.
---

# OpenUltraSAST Kiro Implementation

Use this skill when implementing the OpenUltraSAST Kiro spec from opencode.

## Rules

1. Read `.kiro/specs/openrouter-sast-harness/tasks.md` before choosing work.
2. Implement the next unchecked task slice unless the user names a different phase.
3. Keep each slice independently verifiable with `uv run pytest`.
4. Update task checkboxes only after implementation and tests pass.
5. Prefer minimal harness-compatible primitives over large framework imports.
6. Keep OpenUltraSAST independent of Clearwing; use Clearwing only as an oracle for design patterns.
7. Use project-local opencode skills to steer scan, triage, and fix workflows.

## Current Phase Order

- Phase 5: Harness runtime events, processors, contracts, and traces.
- Phase 5A: Static mapping disciplines for SARIF, Semgrep, CodeQL, differential review, and sharp edges.
- Phase 6: Evidence ladder verifier.
- Phase 7 and 7A: Docker sandbox and dynamic evidence.
- Phase 8 and later: Hunter pool, SARIF, deep mode, patch oracle, MCP, fusion, skill index, hardening.
