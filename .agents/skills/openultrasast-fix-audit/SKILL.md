---
name: openultrasast-fix-audit
description: OpenUltraSAST patch, fix audit, differential review, adversarial review, and patch validation workflow. Use when proposing or auditing fixes for OpenUltraSAST findings from opencode.
---

# OpenUltraSAST Fix Audit

Use this skill to steer fixes for OpenUltraSAST findings.

## Fix Lifecycle

1. Intake: restate the finding ID, evidence level, affected path, and acceptance criteria.
2. Plan: choose the smallest defensive change that addresses the root cause.
3. Implement: modify only files required by the finding.
4. Adversarial review: look for bypasses, regressions, false assumptions, and unrelated edits.
5. Reconcile: either fix the review finding or document why it is not applicable.
6. Verify: rerun the reproducer or affected checks.
7. Ready: only then consider advancing to `patch_validated`.

## Guardrails

- Do not rewrite modules when a local fix is enough.
- Do not change public APIs unless the vulnerability requires it.
- Do not mark a patch validated from model reasoning alone.
- Use differential review for risky changes in auth, crypto, config, parsers, and sandbox behavior.
- Run Semgrep or CodeQL delta checks when those analyzers supplied the original evidence.
