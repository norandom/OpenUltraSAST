# pool-p1 shape classification — application vs library (reachability in-repo) — 2026-10-12

## Why
Strategic decision (see memory evaluation-target-mismatch): the core problem is unprovable attacker-reachability —
the trust boundary lives outside the changed library code. Chosen bet: FIX THE EVALUATION TARGET FIRST. This LLM
pass (DeepSeek, reuses the label-audit cache, $0.033) classifies each of the 49 public pool vulns:
application / mixed / library, and whether the attacker→source→sink path is resolvable IN-REPO.

## Result
- shape: library 37, application 6, mixed 6. **reachability_in_repo: True 12 (24%), False 37 (76%).**
- A legitimate change-scoped pre-push catch needs BOTH a sound label AND reachability in-repo. That intersection is
  **5/49 (~10%)**: getzep/graphiti, sorlen008/desktopcommandermcp, zenitram/malla, adfinis/document-merge-service,
  punkpeye/mcp-remote. 18 more are sound-but-library (fair label, UNFAIR target — attacker source in an absent caller).
- **Shape predicts the hunter outcome:** graphiti (mixed/reach=True/sound) was CAUGHT by the hunter; bedrock
  (library/reach=False/sound) was MISSED (reachability not in-repo); banks/launch-editor/socketio (library/unsound)
  correctly quiet. The one caught pilot repo is the one app-shaped+sound target.

## Implication
record 07's floor (catch 3/92) is scored against a denominator ~90% of which is illegitimate for a change-scoped,
reachability-based hook. The near-zero catch is LARGELY a target mismatch, not pure detection failure. The fair
local eval set is the 5 app-shaped+sound public targets (expand via known-vulnerable apps: VAmPI, NodeGoat,
DjanGoat, vibe-py). Next: run the deep scan (regex/engine/hunter) on the 5 fair targets for a per-tier catch rate on
the corrected target set.

## Caveats
LLM classification (DeepSeek, general model); confidence per row in shape.jsonl. "mixed" = a library that also ships
a runnable app/CLI exercising the sink. Private 51/100 pool entries un-auditable (no code).
