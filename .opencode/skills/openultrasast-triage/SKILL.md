---
name: openultrasast-triage
description: OpenUltraSAST false-positive elimination, ranking calibration, evidence ladder, verifier triage, and finding adjudication. Use when reviewing findings, reducing false positives, or deciding whether evidence is enough.
---

# OpenUltraSAST Triage

Use this skill when triaging OpenUltraSAST findings from opencode.

## Triage Loop

1. Identify the finding, path, rule, severity, confidence, and evidence level.
2. Separate deterministic evidence from model assumptions.
3. Check attacker control, reachability, sanitizer behavior, duplicates, impact, and contradictory evidence.
4. If rejected or unresolved, record the false-positive reason and scope.
5. Prefer scoped demotion over deleting a vulnerability class globally.
6. Feed the outcome into ranking calibration and prompt constraints.

## False-Positive Reasons

- `unreachable_path`
- `missing_attacker_control`
- `sanitizer_disproved`
- `static_rule_mismatch`
- `incorrect_model_assumption`
- `duplicate`
- `insufficient_impact`
- `unsupported`
- `contradicted`
- `unverified`

## Decision Standard

If evidence is uncertain, mark the finding as requiring next evidence instead of escalating severity. Difficult or high-impact disagreements should trigger fusion/deeper reasoning when available.
