# Research & Design Decisions: learning-harness

## Summary

- **Feature**: `learning-harness`
- **Discovery Scope**: Complex Integration (extension of pairs, tool hunter, provider, regress, improve; adoption of HarnessX meta-harness; corpus repairs)
- **Key Findings**:
  - The tool hunter already beats the overlay 12/14 vs 5/14 on the class-aware, scorable vibe-py holdout; the published 0/17 was the text-token scorer.
  - Every learning path ignores the split (`evaluate_profiles`, `evaluate_mechanism_profiles`, `propose_mechanism_edits`, `evaluate_loo`, `build_pair_signals`, `export_mechanisms`); one teacher rule fixes all of them.
  - The sandbox verdict is exit-code only and snippets are compile-only templates; a canary oracle is an additive callback that respects the existing safety bans.
  - The chat and embedding clients share one base-URL variable; DeepSeek needs thinking disabled, `reasoning_content` replay, no `/v1`, `json_object` only, and offers no seed and no embeddings.
  - HarnessX 0.1.0 already provides the round primitive (`MetaAgent.evolve`, journal with `predicted_affected` and precision discounted by unpredicted regressions); the tool supplies tasks, trajectories, the evaluator and routing.
  - The field routes on coarse verifier-aligned families, gates reports on proof, and reports regression blindness in meta-agents; per-instance archives and no-regression acceptance rules are the published remedies.

## Research Log

### Codebase seams (2026-09-06, Explore subagent over `src/openultrasast`)
- **Context**: design an extension without re-reading every module.
- **Findings**: `run_tool_hunter(root, hotspots, *, client, model, max_steps)` with three curated tools and `suspicion` findings tagged `tool-hunter`; `ChatClient.complete(*, model, messages, tools, timeout_seconds)`; `OpenRouterChatClient.complete_chat` always sends `temperature: 0` and drops `reasoning_content`; `_hunter_matches_expected` is text-token based and every fixed-side finding leaks under `fix_policy = silent`; `run_regression(..., sandbox, sandbox_limits, images)` with `verdict_from_result` on exit code; `check_snippet_safety` bans sockets, curl and workspace writes; `MechanismStore` append-only JSONL with tombstones; `improve.run_round` journal has no hypothesis, attribution or cost fields and its regression check is per provenance profile; `load_dotenv` no-ops under pytest; `pyproject` semantic extra lacks TypeScript; `pair_gate` scores only vendored `local` pairs.
- **Implications**: the design adds parameters and additive fields instead of replacing modules; the family scorer is injected into the hunter path so `pairs` never imports `learning`; the oracle is an optional callback on `run_regression`; endpoint resolution takes an explicit override for tests.

### DeepSeek platform API (2026-09-06, api-docs.deepseek.com)
- **Findings**: base `https://api.deepseek.com` (no `/v1` in current docs), Anthropic-shape endpoint at `/anthropic`; models `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-v4-flash-vision-exp`; 1M context, 384K output; thinking on by default (`thinking: {"type": "disabled"}` to turn off; `temperature` ignored while thinking); tools with `tool_choice`, `reasoning_content` must be replayed on tool turns; `response_format json_object` only, occasional empty content; `logprobs`/`top_logprobs` documented, unverified in thinking mode; no `seed`, `n`, `logit_bias`; flash 0.44/1.32 USD per M in/out peak, cache hit 0.014, pro 1.32/3.96, off-peak half; concurrency 2500 flash / 500 pro; no embeddings endpoint.
- **Implications**: detectors and classifier run with thinking disabled and temperature 0; determinism is best-effort and the K-run noise floor absorbs it; the classifier's model tier uses `logprobs` averaged and falls to `unknown`; embeddings stay on OpenRouter; cost accounting reads DeepSeek's cache-hit usage fields.

### Measurement that triggered the spec (2026-09-06)
- See `brief.md` Problem section and `benchmarks/measurements/2026-09-06-*`.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Keep static machinery as the detector, add a class field | Minimal change | Cheap | Ceiling by construction; measured 5/14 vs 12/14 | Rejected |
| One generalist hunter, evolved as a whole | Single config | Simple loop | Aggregate fitness hides per-class regressions; the maintainer's oscillation observation; regression blindness in the literature | Rejected |
| Per-family detector set with auto-classifier, per-family attribution, verifier-gated reporting | This design | Matches AIxCC routing practice, GEPA per-instance archives, slice-based gating | Router error (63.8% in MoEVD); mitigated by multi-label routing plus a generalist and by measuring the router separately | **Selected** |
| Fine-tune a model per class | Weights | Potentially strong | Out of scope; label noise 25–60% in public sets; not reproducible offline | Rejected |

## Design Decisions

### Decision: families are the only routing and scoring key
- **Context**: 1.4, 3.6; text tokens and CWE ids were the proxy.
- **Alternatives**: fine CWE routing; mechanism ids as key.
- **Selected**: ten coarse families with CWE and mechanism as attributes; hierarchical relation for partial credit.
- **Rationale**: fine CWE from code is unsolved (≤14.7% top-1) and coarse families are what worked in AIxCC and MoEVD.
- **Trade-offs**: less granular reporting; compensated by attributes on findings.

### Decision: the scorer is injected into the hunter path, not imported by `pairs`
- **Context**: dependency direction; `pairs` is owned by `pair-corpus-honesty`.
- **Selected**: `_evaluate_hunter_pair` accepts a matcher/leak callable; the CLI wires `learning.scoring`.
- **Trade-offs**: one more parameter; keeps `pairs` free of `learning` and the overlay path unchanged.

### Decision: canary oracle as an optional callback on `run_regression`
- **Context**: 7.2; exit code cannot express "the vulnerability fired".
- **Alternatives**: a parallel verifier runner; parsing stderr.
- **Selected**: `oracle: Callable[[SandboxResult], bool] | None`; token in stdout.
- **Trade-offs**: minimal change to regress; templates per family live in `learning/verifiers/`.

### Decision: HarnessX proposer behind the seam, scripted proposer first
- **Context**: 9.x with core `dependencies = []`.
- **Selected**: `Proposer` protocol; `HarnessXProposer` composes `MetaAgent.evolve` with `allowed_write_roots` = the family directory; `ScriptedProposer` for tests and phase 4 start.
- **Trade-offs**: two proposers; the loop is testable offline and the extra stays optional.

### Decision: noise floor from K = 5 baseline runs is the regression budget
- **Context**: 8.2, 9.5; no public numeric negative-flip budget exists.
- **Selected**: per-family negative-flip rate between seed runs; `budget_flips = ceil(rate × scorable)`.
- **Trade-offs**: a noisy family gets a loose budget; reported beside the number so it is visible.

### Decision: DeepSeek adapter wraps the existing OpenRouter client
- **Context**: 6.6; both clients share one base URL today.
- **Selected**: `ChatEndpoint` resolution order DeepSeek → OpenRouter → scripted; adapter adds `extra_body` and `reasoning_content` replay; embeddings untouched.
- **Trade-offs**: one adapter class; no new dependency.

## Risks & Mitigations
- Router error routes a region to the wrong family → multi-label routing plus the generalist; router measured separately against random and oracle.
- No seed on DeepSeek → K runs and the reliable-change test; determinism recorded as best-effort.
- Canary templates cannot express some families (XSS, SSRF) → those report at `suspicion` only, stated in the taxonomy.
- Proposer confabulation → structured failure facts only; rejected buffer; length cap; structural levers preferred.
- Cost drift → per-stage metering, per-round cap with revert, cost per point published.
- Re-harvest needs network and licenses → maintainer step; excerpts re-redacted; failures leave the old excerpt and a recorded reason.

## References
- Codebase seams and DeepSeek facts: this file, sections above.
- External literature: the four threads below.

---

## External research (2026-09-06)

Web research conducted 2026-09-06 in four threads by research subagents; summaries are theirs, condensed, with primary sources. Speculation is marked. This section backs the "What others learned" section of `brief.md`.

## 1. Cyber reasoning systems (AIxCC finals 2025, Big Sleep, XBOW, Glasswing)

Primary cross-team source: USENIX Security '26 SoK on AIxCC, arXiv 2602.07666. 42-b3yond-6ug and Lacrosse have no first-party write-up.

| System | Decomposition / routing key | LLM vs tools |
|---|---|---|
| Atlantis (1st), arXiv 2509.14589, team-atlanta.github.io/blog/post-afc | N-version sub-CRSs by language (C, Java, Multilang) with orthogonal designs; six patch agents in parallel, no routing ("no single agent consistently outperformed"); rate limit per fuzzer×sanitizer; Java sinks keyed by Jazzer sanitizer class | Three tiers: LLM-augmented (seeds), LLM-opinionated (hints as optimizations, never correctness), LLM-driven (multi-agent call-graph, bug candidates, blobs). Fuzzers/concolic are ground truth |
| Buttercup (2nd), blog.trailofbits.com 2025-08-08/09 | Seven patch agents by role (RCA, retrieval, writer, reflection); language tooling and CWE guidance in prompts | Fuzzers discover; tree-sitter/CodeQuery program model; cheap non-reasoning LLMs only ($21k for 100k calls); >90% accuracy |
| RoboDuck (3rd), theori.io/blog/aixcc-and-roboduck-63447, /building-effective-llm-agents-63446 | Bug candidate is the anchor: Infer + LLM static analysis + crashes → logprob-scored binary classifier (~$0.001/report) → top 20% to a source-browsing agent (~$0.50) | LLM-first PoVs without fuzzing; three models race, first verified wins; Infer ~99.9% FP |
| FuzzingBrain (4th), arXiv 2509.07225 | 23 strategies keyed on mode × language × stage; per-language CWE lists aligned to sanitizers | LLM-dominant; libFuzzer only; nothing reported unless a sanitizer fires on a real build |
| ARTIPHISHELL (5th), support.shellphish.net 2025-08-22 postmortem | 53 components; multi-source voting; dual patchers | PoV submitted only after five consecutive local reproductions |
| Big Sleep / Naptime, projectzero.google 2024/06 and 2024/10 | No classifier; variant analysis seeded from recent commits | Single agent with code browser, Python, debugger, reporter; must reproduce a crash; parallel independent trajectories |
| XBOW, xbow.com/blog/top-1-how-xbow-did-it | Coordinator spawns per-vulnerability-class solvers; validators keyed by class (canary, headless browser for XSS, timing for blind SQLi) | The non-AI validator "is the only one who can decide if the agent succeeded" |
| Anthropic Glasswing, anthropic.com/research/glasswing-initial-update | Threat-model builder prioritizes targets; scanning subagents; reusable skills | 90.6% of 1,752 findings valid after human reproduction; internals unpublished |

Lessons: (1) route on mode × language × sanitizer/CWE family, never fine CWE; route to what the verifier can check. (2) Only proof survives; the accuracy multiplier (Atlantis 0.9999 vs 0.9044) decided the ranking; RoboDuck lost 16.3 points to FPs. (3) Cheap classifier → expensive agent → verifier (RoboDuck 500× cost tiering; logprob averaging for stable scores). (4) Ensembles beat selection when the winner is unpredictable; attribution per agent done by hand post hoc. (5) Dedup granularity is a scoring bug (Shadowsocks: five same-pattern bugs differing by line). (6) Validated ≠ correct: 38–46% of automatically accepted patches were semantically wrong (SoK KF4). (7) Hallucination controls are structural: forced tool calls, curated tools instead of bash, symbol resolution via Joern/LSP. (8) Stability beat cleverness: budget caps, cached container state, exit-code-0 logging, lost logs sank teams. (9) Cross-run learning nearly absent; Atlantis's only trained component (GRPO retrieval, C only) showed catastrophic forgetting across projects; daily leakage-resistant CI benchmarks instead. (10) Cost is a control: >$1,000/hour unbounded (arXiv 2603.08566); Buttercup $181/point.

## 2. Self-improving harness methods

| Method | Evolved unit | Search operator | Validation |
|---|---|---|---|
| DSPy MIPROv2 (dspy.ai) | Few-shot demos + instructions per module | Bootstrapped traces; LLM proposals; Bayesian optimization | Minibatch trials, full validation every 5 steps; ≥200 examples advised |
| GEPA, arXiv 2507.19457 | One module's prompt per iteration | Natural-language reflection on trajectories; system-aware merge | Minibatch gate → full per-instance Pareto front; candidates sampled ∝ instances led |
| TextGrad; PrefPO critique arXiv 2603.19311 | Prompt text | Textual gradients | Validation revert; 86% of TextGrad prompts hacked/brittle, 14.7× length inflation |
| OPRO 2309.03409 / EvoPrompt 2309.08532 / PromptBreeder 2309.16797 | Task prompt | Proposal / GA / self-referential mutation | Train-score selection; EvoPrompt degrades to generic prose on structured tasks |
| AlphaEvolve (DeepMind blog 2025) | Code diffs | LLM mutation over MAP-Elites program DB | Evaluator cascade; needs automatically verifiable problems |
| Darwin Gödel Machine, arXiv 2505.22954, sakana.ai/dgm | Agent code/tools | Archive sampling ∝ score, ∝ 1/(1+children) | Staged 10→60→200 tasks; held-out models/languages; faked test logs when checker visible |
| ADAS, arXiv 2408.08435 | Agent code | Meta-agent over archive | Held-out validation and domains |
| Reflexion / ExpeL 2308.10144 / AWM 2409.07429 / Voyager 2305.16291 | Reflections / insights / workflows / skills | Self-critique; contrast; induction | Mostly none |
| Self-Harness, arXiv 2606.09498 | Harness components | Weakness mining → K minimal proposals | Accept iff Δ_in ≥ 0 ∧ Δ_ho ≥ 0 ∧ one > 0 |
| SkillOpt, arXiv 2605.23904 | SKILL.md | Reflection with rejected-edit buffer | Strict improvement on held-out; ties rejected |
| AHE, arXiv 2604.25850 | Tools, middleware, memory, prompts | Evidence-driven edits with per-edit manifest (predicted fixes and at-risk regressions) | Prediction vs observed deltas; rollback |
| Meta-Harness, arXiv 2603.28052 | Harness code | Agentic proposer over prior candidates and traces | Held-out models and tasks |

Lessons: (1) per-instance/per-class tracking doubled gains vs greedy best-overall (GEPA +12.44% vs +6.05%). (2) No-regression acceptance rule; reject ties (Self-Harness, SkillOpt). (3) Regression blindness: AHE fix-prediction precision 33.7% but regression prediction 11.8%; the cross-class sweep is mandatory. (4) Two-stage evaluation is where sample efficiency comes from; most budget is validation. (5) Prompt bloat is the overfit signature (Decagon: +75% length, −2% accuracy; cap ~1,500 chars gave 4× compression at −0.8%). (6) Keep the reflector blind to validation; keep a rejected-edit buffer (arXiv 2602.22483; SkillOpt). (7) Structural edits transfer (+5.1–10.1 points across model families), system-prompt-only edits regressed −2.3 (AHE ablation). (8) Self-diagnosis confabulates: 0/121 Reflexion reflections correct; structured trajectory facts → 86% (arXiv 2605.29463). (9) Hide the checker (DGM). (10) One objective per round (arXiv 2605.26046: joint criteria −59% task focus). (11) Audit that a skill beats re-showing the failure (ContinualSkillBench arXiv 2608.03874). (12) Harness-edit quality flat across model tiers; spend on the detector (arXiv 2605.30621). Speculation: no source measures class-to-class oscillation; per-class Pareto retention plus the acceptance rule should bound it. Anthropic's Claude Code postmortem (InfoQ 2026-05: three unattributed harness changes → six-week degradation) is the cautionary tale.

## 3. Dataset pitfalls and class taxonomies

Scoring: (1) dedup by normalized body hash before splitting; split by commit, chronologically (PrimeVul arXiv 2403.18624; test-set copies 12.7–18.9% in older sets). (2) Automatic labels 25–60% correct (BigVul 25%, CVEfixes 51.7%, DiverseVul 60%; Croft et al. ICSE'23 20–71% wrong, 17–99% duplicates; CleanVul arXiv 2411.17274). (3) Pair-wise outcomes P-C/P-V/P-B/P-R, not F1 (GPT-4 CoT P-C 12.94% vs P-V 54.26%; JitVul ACL 2025: agents lose 8–9 points of pair accuracy while "winning" F1; Vul-RAG pairwise 0.21 vs plain 0.61). (4) Directional-bias index (CWE-Trace arXiv 2606.20502: −85.5 to +94.8 points at ~50% accuracy). (5) Score at fixed FPR (PrimeVul VD-S; VFC benchmark arXiv 2605.13138). (6) Match on location and class with hierarchical credit and hallucination penalty (CASTLE arXiv 2503.09433; ALPHA arXiv 2601.01320). (7) Robustness to renames/whitespace/dead code (SecLLMHolmes arXiv 2312.12575; patched-code FPs dominate). (8) CVE-date contamination checks are weak evidence, keep a post-cutoff slice anyway (thin: one paper). (9) Function-level pairs lose context: up to 54% of patched-code misclassification (arXiv 2504.13474). (10) Run-to-run consistency 8.3–81.9% by model (ALPHA).

Taxonomy: (1) fine CWE from code unsolved (top-1 ≤ 14.7% over 74 CWEs; 86.5% lateral errors; VulDetectBench arXiv 2406.07595 >80% coarse, <30% detailed). (2) From CVE text ~85–90% ceiling (arXiv 2603.14911; CweAgent arXiv 2608.21977). (3) Human/NVD disagreement 15–50%; CWE-699 families as "defensible" (Seclometry; Sonnet vs NVD 73.1% exact, 84.5% with parent–child, LLM right in 72/100 disagreements). (4) Score hierarchically. (5) Few aggregated classes: MoEVD arXiv 2501.16454 collapsed 88 → 12 families, per-class experts +12.8% F1, router 63.8% right, F1 0.18 when wrong; three-class OOB/UAF/other 87.4% (arXiv 2509.22796). (6) Specialists need hard negatives (arXiv 2408.02329: F1 0.89 in class → 0.12–0.19 on full corpus). (7) Per-class detectors work when the class fixes sources/sinks (IRIS arXiv 2405.17238: 55 vs 27 CodeQL detections, FDR 46–85%). (8) VFC typing immature (F1 0.53–0.70). Speculation: 8–12 hierarchy-derived families with partial credit beats fine CWEs for this corpus.

## 4. Routing and regression control

Router: (1) learned routers plateau 10–20 points below oracle, sometimes lose to random (RouteLLM arXiv 2406.18665; RouterBench arXiv 2403.12031; arXiv 2606.07587). (2) Evaluate router AUROC separately from expert strength (arXiv 2602.11877). (3) Small embedding classifier fine-tuned on own labels: 80.4% → 98.5% (Red Hat vLLM Semantic Router, 2026-06). (4) Cascades tolerate router error until judge error > 0.2 (FrugalGPT arXiv 2305.05176; RouterBench). (5) Multi-expert routing with balance (Expert-Choice, Google; AgentRouter arXiv 2510.05445); speculation: multi-label with `unknown` is safer than argmax for SAST.

Attribution: (6) slice everything (Oakden-Rayner arXiv 1909.12475; Slice-based learning 1909.06349; Overton 1909.05372; Model Cards 1810.03993). (7) Negative flips per item (PCT arXiv 2011.09161: 5.2% NFR at equal accuracy; MUSCLE 2407.09435: 8–49% NFR across Llama versions; arXiv 2604.27405: +1.6–2.8 point gains masked 28–39% items worse, single-shot eval missed 42% of changes → K ≥ 3 samples and a reliable-change test; UpgradeBench 2608.20918: neutral retraining breaks 1–5%). (8) Frozen per-class configurations (+20%, Progressive Prompts arXiv 2301.12314); self-feedback-only skill loops drift, external feedback does not (SkillLearnBench 2604.20087); self-revision flips correct → incorrect more often than the reverse (arXiv 2310.01798). (9) Per-instance archives over one champion (GEPA; DGM lineage logs caught faked tests). (10) Conjunctive per-slice gates with relative thresholds vs the last blessed baseline (TFMA model validations; ease.ml/ci arXiv 1903.00278; Amazon Alexa regression-free updates). No public numeric NFR budget; speculation: the measured seed-noise floor per class is the defensible budget.
