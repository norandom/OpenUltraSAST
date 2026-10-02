---
name: openultrasast-triage
description: OpenUltraSAST finding triage - false-positive adjudication with the fixed reason taxonomy, the evidence ladder, what a verdict may feed (labels, never rule edits), and fixing then re-scanning. Use when reviewing findings, reducing false positives, deciding whether evidence is enough, or auditing a fix for a finding.
---

# OpenUltraSAST Triage

Use this skill when triaging OpenUltraSAST findings or auditing a fix for one.

## Triage Loop

1. Identify the finding: id, path, rule, CWE and policy severity, confidence, evidence level and
   verification status (`findings.json`, `verification.json` in the run directory).
2. Separate deterministic evidence (rule match, graph entailment, attached reachability) from model
   assumptions.
3. Check attacker control, reachability, sanitizer behaviour, duplicates, impact, and contradictory
   evidence.
4. If rejected or unresolved, record the false-positive reason and its scope.
5. Prefer scoped demotion over deleting a vulnerability class globally: a rejection in `auth/`
   demotes `auth/...`, never the class (`calibration.py`).
6. Record the adjudication. Do not edit a rule because of one finding (see below).

## False-Positive Reasons

The taxonomy is `FalsePositiveReason` in `src/openultrasast/calibration.py`; use these values exactly:

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

If evidence is uncertain, mark the finding `needs_evidence` and name the next evidence instead of
escalating severity. Fusion (`fusion.json`, standard mode) is deterministic: it adjudicates between
the quick-rule and MAP panels by fixed triggers and is not a second opinion from a model. Independent
model agreement exists only in the plane's verify passes a and b, with pass c on disputes, and the
`agree` step; those verdicts arrive as features of the decision engine, never as a verification
status.

## What an Adjudication Feeds

- Recorded adjudications (a per-finding verdict with a reason) become decision-engine labels through
  the fail-closed source list `src/openultrasast/learn/sources.toml` (`[[source]] id =
  "adjudications"`). Aggregate counts label nothing; only per-finding verdicts do.
- Plane verdicts (`agreed`, `rejected`, `disputed`) are features, never labels. "Rejected by the
  plane" is not a negative.
- Rule changes go through the ledger: `ousast improve` (the validator and the detection gate, holdout
  pairs per round) or a registered experiment (`ousast learn experiment register|units|run|analyse`).
  Never a hand edit of `rules.toml` per miss or per false positive.

## Fix and Re-scan

1. Intake: restate the finding id, evidence level, affected path, and the acceptance criterion.
2. Plan: the smallest defensive change that addresses the root cause.
3. Implement: modify only the files the finding requires.
4. Adversarial review: look for bypasses, regressions, false assumptions, and unrelated edits. Use a
   differential review for changes in auth, crypto, config, parsers, and sandbox behaviour.
5. Reconcile: fix each review finding or document why it does not apply.
6. Verify: a re-scan of the checkout in the same mode, or a replay of the change with
   `ousast pre-push --base <before> --head <after> --artifact <file> <repo>`, shows the finding gone
   and no new findings. That re-scan is the evidence. Nothing in the tool records `patch_validated`;
   do not claim it.

Guardrails:

- Do not rewrite modules when a local fix is enough.
- Do not change public APIs unless the vulnerability requires it.
- Do not call a finding fixed from model reasoning alone; the re-scan or replay decides.
