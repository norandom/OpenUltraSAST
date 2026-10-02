# Old path to new path (2026-10-02)

Committed records, specs and some docstrings name these scripts by their old path. Those files are
not rewritten. Read the old path as the new one:

| old path | new path |
|---|---|
| `benchmarks/independent/verify_batched.py` | `benchmarks/archive/verify_batched.py` |
| `benchmarks/independent/score_batched.py` | `benchmarks/archive/score_batched.py` |
| `benchmarks/independent/verify_sinks.py` | `benchmarks/archive/verify_sinks.py` |
| `benchmarks/independent/model_sinks.py` | `benchmarks/archive/model_sinks.py` |
| `benchmarks/independent/sink_candidates.py` | `benchmarks/archive/sink_candidates.py` |
| `benchmarks/independent/hunt.py` | `benchmarks/archive/hunt.py` |
| `benchmarks/harnessx_removal_equality.py` | `benchmarks/archive/harnessx_removal_equality.py` |

Files that still use the old path:

- Records: `independent/hunter-protocol-v2.md`, `independent/results-v2-model-pipeline.json`,
  `independent/selection-v2-model-sinks.json`, `independent/verifier-batched-check-2026-09-29.json`,
  `measurements/2026-09-30-harnessx-removal-equality/README`
- Specs: `.kiro/specs/ai-service-plane/`, `.kiro/specs/harnessx-removal/design.md`,
  `.kiro/specs/learned-decision-engine/`
- Docstrings: `src/openultrasast/plane/generate.py`, `plane/tasks/{verify,agree,roles,repo_facts}.py`.
  These are left for the owners of those packages.
