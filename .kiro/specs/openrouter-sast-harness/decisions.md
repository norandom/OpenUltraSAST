# Decisions: OpenRouter SAST Harness

## Approved Initial Slice

The first implementation slice is approved for Phase 0 and Phase 1 only:

- Python package skeleton with `ousast` CLI.
- Local configuration loading.
- Scan run directory creation under `.openultrasast/runs/<scan-id>/`.
- Repository snapshot collection.
- Source file enumeration with basic ignore handling.
- Language, LOC, and static tag heuristics.
- `preprocess/file_targets.json` artifact.

## Current Decisions

| Decision | Value | Scope |
| --- | --- | --- |
| Runtime | Python 3.11+ | Initial implementation |
| Harness dependency | Minimal HarnessX-compatible core first | Avoid direct dependency until contracts are proven |
| Vector store | Deferred to Phase 4 bakeoff | Not needed for Phase 0/1 |
| OpenRouter chat models | Deferred until ranker implementation | Not needed for Phase 0/1 |
| OpenRouter embedding model | Deferred until embeddings implementation | Not needed for Phase 0/1 |
| Fixtures | Synthetic fixture repositories first | Keeps tests deterministic |
| MCP | Defer until CLI and artifacts stabilize | Phase 12 |

## Rationale

The first milestone should prove the local artifact contract before adding model calls, embeddings, Docker, MCP, or fusion. Later decisions must be recorded here before their implementation phases begin.
