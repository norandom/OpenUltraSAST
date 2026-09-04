# Brief: regex proposes, semantics adjudicates, sandbox proves

## Problem

OpenUltraSAST already has three scan stages (`quick` inventory, `standard` map, `deep` regression), but **only the first stage actually decides**. Pattern rules propose sinks; the map ranks files; the sandbox can run recipes. Nothing in the middle answers “does this sink receive attacker-controlled data, or is it a Juliet-style good twin / dead assignment / hardcoded command?”

Calibration corpora (cheat-sheet fixtures, OWASP Benchmark true/false files, Juliet `bad`/`good`, CVE pairs) are **nice**: one CWE per file, named sinks, labeled counterparts. Real working trees are not: mixed languages, generated code, unparseable files, framework wrappers, comments, one-hop assignments (`sql = f"…{x}"; cur.execute(sql)`), and no ground-truth labels.

Measured honesty on the labeled SAST slice is about **+9% Youden**. Widening regex to chase that number will fire on every `Runtime.exec` and leak on OWASP-false / Juliet `goodG2B`.

## Approach

Keep three roles, never collapse them:

1. **Propose** — pattern rules + optional SARIF. Stage 1. Does not decide worth-fixing.
2. **Adjudicate** — tree-sitter IR (multi-language) + taint facts; optional Joern CPG sidecar; Python stdlib parse only as last-resort fallback. Promote, demote, or **unadjudicated**.
3. **Budget** — ranker + **mechanism memory** (JSONL + OpenRouter embeddings, hard CWE/language/tag filters) **before** prove. Not a verdict. Not TF-IDF. Not raw file-slice embeddings.
4. **Prove** — sandbox only on promoted, reachable, budgeted candidates.

The primary in-scope target is a **messy working tree the operator is writing**, not a labeled benchmark. Known-vuln corpora remain calibration scoreboards (smoke 90/10, pair Youden, GitHub silent-on-fix). They do not define success on unlabeled code.

## Scope

- Semantic overlay as MAP-stage adjudication; **tree-sitter is the prio engine** (CLI/API, fail-closed). Joern optional. Embeddings tune prove order.
- Explicit `unadjudicated` when parse or flow fails — do not treat silence as safe.
- Sandbox prove only after promote.
- Pair eval scores the overlay on the sast slice; smoke gate stays inventory-only.

## Out of scope

- Replacing pattern rules.
- LLM as parse/taint engine.
- Requiring Joern or embeddings for `quick`.
- Using embedding similarity to silently drop promotions.
- Auto-writing flow facts from the improve loop.
