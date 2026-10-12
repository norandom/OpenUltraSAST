# Model hunter on the two sound pilot targets — 2026-10-12

## Why
The engine-on pilot showed the static tiers (regex + Joern dataflow) catch 0/5, and the LLM adjudication tier was
disabled in the push path. Of the 5 pilot repos, the label audit found only **bedrock + graphiti (injection)** are
sound (change-located, change-introduced) fair targets — and the static engine missed both. We ran the shipped
**model hunter** (`ousast scan --mode deep`, DeepSeek `deepseek-flash`, model layer + tool_hunter enabled,
unbounded by a push deadline, bounded to 60 model calls / 8 hotspots) on those two to test whether the LLM arm
catches what the static tiers miss.

## Result: hunter 1/2 (static engine 0/2), cheap, but both at suspicion rung
| repo | vuln | static engine | **hunter** | model calls | cost |
|---|---|---|---|---|---|
| getzep/graphiti | Cypher injection in `build_fulltext_query` | miss | **HIT (suspicion)** | 64 | $0.0071 |
| aws/bedrock-agentcore | command injection in `install_packages` | miss | **miss (suspicions on adjacent)** | 64 | $0.0076 |

- **graphiti — correct catch.** `falkordb_driver.py:207` finding, `tags:[family:cypher-injection]`, severity medium,
  confidence low, rung **suspicion**. Rationale traces it exactly: *"build_fulltext_query concatenates the sanitized
  user query into a Cypher string: full_query = group_filter + ' (' + sanitized_query + ')' (line 278)"*. Line 278
  is inside the labelled `function_lines [249,280]`; head_lines include [206],[249-251],[280] → location-matches.
  The static engine produced zero findings here.
- **bedrock — miss.** 12 findings, all suspicion; the 3 on the vuln file were adjacent concerns (network-PUBLIC
  default @114, caller client_token @188, download_file @583) — it never named the `install_packages` → `pip
  install` command injection. A prompting/targeting miss, not cost (64 calls, $0.0076) or capability.

## Reads
1. **The LLM arm lifts catch over the static tiers** — graphiti is the first unseen vuln caught that regex+dataflow
   missed. Cost is a non-issue (~$0.007/repo, 64 calls for a whole-repo deep scan).
2. **Everything stops at `suspicion`.** Neither reached corroborated/entailed/execution_confirmed — the proof arm
   (sandbox verification) did not elevate them. For release-grade BLOCK the findings must be *proven*, not just
   suspected. The proof arm + verification are the next depth to measure.
3. **bedrock motivates prompt evolution.** The hunter has the capability but its current prompts did not steer it to
   the real sink. Directive: a **DSPy**-based prompt-optimisation loop (GEPA/MIPRO; keep pluggable) whose objective
   is to learn **what hints/annotations** the model needs (bedrock: "install_packages runs pip with caller-supplied
   names → command injection") — sourced from the **framework knowledge already shipped** (`ruleset/semantic/*.toml`,
   `frameworks.toml`), no new user annotation; LLM-proposed boundaries graduate into the facts (#2 feedback loop).

## Caveats
- Whole-repo deep scan (not change-scoped), so this measures detection CAPABILITY, not pre-push latency. A
  change-scoped + proven run is the release-relevant shape.
- Only 2 sound targets here; widen to the 23 sound public targets next for a rate.
- graphiti's finding is suspicion/low-confidence; a human/proof confirmation is still needed before it is a
  release-grade catch. Findings JSON: `bedrock-findings.json`, `graphiti-findings.json`.
