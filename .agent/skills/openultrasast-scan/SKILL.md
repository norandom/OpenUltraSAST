---
name: openultrasast-scan
description: OpenUltraSAST scan, index, quick, standard, deep, SARIF, and report workflows. Use when running or planning `ousast scan`, repository indexing, or evidence-gated SAST analysis from opencode.
---

# OpenUltraSAST Scan

Use this skill to steer OpenUltraSAST scan workflows from opencode.

## Workflow

1. Confirm the target is a local repository path.
2. Run commands through uv, never by activating a virtualenv manually.
3. Start with quick mode unless the task explicitly requires standard or deep analysis.
4. Treat quick findings as `static_corroboration`, not verified vulnerabilities.
5. Preserve run artifacts under `.openultrasast/runs/<scan-id>/`.
6. Report `scan_id`, `run_dir`, finding count, and the strongest available evidence level.

## Commands

```bash
uv run ousast scan <repo> --mode quick
uv run ousast index <repo>
uv run pytest
```

## Evidence Rules

- `suspicion` means a model or weak signal raised a hypothesis.
- `static_corroboration` means deterministic code evidence exists.
- `crash_reproduced` requires an artifact-backed reproducer.
- `root_cause_explained` requires independent verifier reasoning.
- `patch_validated` requires rerunning relevant checks after the patch.

Do not describe a finding as verified unless its evidence level meets the configured report threshold.
