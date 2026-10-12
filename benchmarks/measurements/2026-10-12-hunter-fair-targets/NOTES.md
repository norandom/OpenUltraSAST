# Deep scan (regex/engine/hunter) on the 5 app-shaped + sound "fair" targets — 2026-10-12

## Why
Strategic pivot "fix the evaluation target first". The shape classification left 5 pool targets that are BOTH
label-sound AND application-shaped (reachability in-repo) — the fair change-scoped eval set. Ran `ousast scan
--mode deep` (DeepSeek, model layer + tool_hunter, 60-call bound) on all 5 to get a per-tier catch rate on the
corrected target set (vs ~0 on the library-heavy pilot). graphiti from the earlier run; the other 4 here.

## Result: detection 3/5 on fair targets (vs ~0 library-heavy), all at suspicion rung
| target | family | detected | by | rung | model calls / cost |
|---|---|---|---|---|---|
| getzep/graphiti | injection (Cypher) | YES | hunter (family:cypher-injection, build_fulltext_query L278) | suspicion | 64 / $0.0071 |
| punkpeye/mcp-remote | injection (url-scheme) | YES | hunter (family:url-scheme-injection, sanitizeUrl L708) | suspicion | 65 / $0.0075 |
| sorlen008/desktopcommandermcp | untrusted_destination (SSRF) | YES | engine overlay ("outbound.request reached from parameter", readFileFromUrl L174) | suspicion | 60 / $0.0067 |
| zenitram/malla | output_encoding (DOM XSS) | no | — (no finding on the vuln JS file) | — | 65 / $0.0072 |
| adfinis/document-merge-service | injection (Jinja SSTI) | no | — (no finding on jinja.py get_jinja_env) | — | 64 / $0.0075 |

## Reads
1. **The target mismatch was real and material: detection 0 → 3/5 when the target is app-shaped + sound.** On
   dcmcp (an MCP server) the ENGINE's parameter-as-source mode fired (entry point present) and flagged the SSRF —
   the exact thing it could NOT do on library code. On graphiti/mcpremote the hunter caught injection with a
   family tag. The near-zero pilot catch was substantially a target artifact.
2. **The 2 misses are in families the tool DOCUMENTS as limited** — malla is DOM/template XSS (output_encoding's
   `limits` in families.toml: cannot decide template-mediated escaping) and dms is Jinja SSTI/autoescape-config.
   Expected coverage gaps, not reachability failures.
3. **Everything still stops at `suspicion`/`static_corroboration`** — none reached corroborated/entailed/
   execution_confirmed. Release-grade BLOCK needs the proof arm to elevate these.
4. Cost remains a non-issue: ~$0.007/repo, ~60-65 model calls for a whole-repo deep scan.

## Conclusion for the strategy
Fixing the evaluation target (bet #1) is validated as necessary and material but NOT sufficient: on fair targets
detection appears (3/5) but stays at suspicion. The remaining work is (a) proof-arm elevation (suspicion→proven)
for BLOCK, and (b) family coverage for the documented-limited families — and the DSPy hint loop for the misses.
This is also the honest basis to recompute record-07 on a sound+app-shaped subset / a real app corpus (VAmPI,
NodeGoat, DjanGoat, vibe-py).
