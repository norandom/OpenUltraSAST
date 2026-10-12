# pool-p1 label audit (LLM corpus-honesty pass) — 2026-10-12

## Why
The engine-on pilot's banks "miss" turned out to be a **mislocated SZZ label**: the pool labelled the vuln at
`function=_load`, `head_lines=[[30],[104],[138-141]]`, but the real sink is `from_prompt_path` **line 44**
(outside the changed lines) and it **pre-exists in base** — so a change-scoped pre-push hook *correctly* stays
quiet. The pool documents this bias itself ("SZZ last-writer proxy… can misidentify"; "the flaw may already exist
in base, so a delta hook can correctly stay quiet"). We widened the check across the whole public pool to see if it
is systematic (maintainer directive 2026-10-12, "widen via LLM").

## Method
For each of the **49 public** pool vulns (the 51 private/redacted entries have no code to audit), one DeepSeek
`deepseek-flash` call given: the GHSA advisory (ground truth) + the vuln file at the head revision + the pool's
label (function, function_lines, changed head_lines). The model returns JSON: the real sink location, whether it
falls inside the changed lines (±10), introduced-vs-preexisting, and `label_sound` (fair target = sink in the
changed lines AND change-introduced). Audit cost: **$0.038 total** (~$0.001/call), ~2s/call. Raw per-repo verdicts
in `results.jsonl`; aggregate in `summary.txt`. Harness: scratchpad `label_audit.py`.

## Result
- **label_sound = 23/49 (47%)**; unsound = 26/49 (53%).
- introduced 23 / preexisting 25 / unclear 1; sink_in_changed_lines True 33 / False 16.
- **By family (sound/total):** injection 10/13, access_control 5/8, untrusted_destination 4/7, deserialization
  1/2, config_secrets 1/4, **path 1/7**, **output_encoding 1/8**. Injection labels are mostly sound; path and
  output_encoding labels mostly mislocate or pre-exist.

## Implications
1. **record 07's floor (catch 3/92) is scored against a corpus ~half of which is unfair to a change-scoped hook.**
   On the ~53% pre-existing/mislocated vulns a delta hook *should* stay quiet; counting them as required catches
   depresses the measured catch rate. The honest catchable denominator is the sound subset. record 07 should carry
   this caveat and, ideally, a sound-subset recomputation (public repos only locally; private entries un-auditable).
2. **Fair pilot re-score:** of the 5 engine-on pilot repos only **bedrock + graphiti (injection) are sound**, and
   the engine missed both — those are the *real* detection gaps to attack with the LLM-guided hunter. banks,
   launch-editor, socketio are unsound (quiet is defensible).
3. The 23 sound targets are the fair local evaluation set for the "#2 guided by #1" detection work.

## Caveats
- The audit is itself an LLM judgement; validated against the manual banks finding (matched). 5 `sound=True`
  verdicts are confidence <0.7 and warrant a human spot-check: jupyter-lsp, role-strategy-plugin,
  codeigniter-restserver, **graphiti**, mcp-remote (graphiti is a pilot target — its soundness is medium-confidence).
- Advisory line references are sometimes approximate; the model estimates the sink line.
- Private pool entries (51/100) are not audited — no code. The public-subset rate may not transfer to them.
- deepseek-flash is a general model, not security-specialised; a GEPA-style reflective-retry pass (future spec) and
  the GLM "cyber" model (future spec) would raise audit confidence.
