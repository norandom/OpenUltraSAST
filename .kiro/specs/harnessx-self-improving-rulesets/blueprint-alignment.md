# DocuHarnessX ↔ OpenUltraSAST — Blueprint Alignment

How OpenUltraSAST's HarnessX integration (Phase 3+) aligns with **DocuHarnessX**
(`/home/mc/Source/DocuHarnessX`), the author's other HarnessX project. Both are HarnessX
bundles steered from claude-code/opencode via Kiro spec-driven development. Goal: one shared
architecture the steering layer drives identically.

## Orientation

DocuHarnessX is **agent-first** — an 8-stage pipeline (`ingest → analyze → classify → plan →
write → review → assemble → deploy`) that *is* the agent loop. OpenUltraSAST is a
**deterministic-pipeline + agentic-plane hybrid** — a sync `HarnessRuntime` driving 13 stages,
with HarnessX confined to the one stage that is genuinely an agent loop (the hunter pool). They
converge on the same load-bearing patterns and diverge only where SAST's determinism and
supply-chain posture require it.

**What "self-improving multi-agent system" means in DocuHarnessX (important):** it does **not**
use `meta_harness` / `MetaAgent.evolve` at all (the `Train` loop is explicit future / out of
scope). Its self-improvement is realized two ways: (1) an in-product **fail-closed LLM-judge
quality firewall** (COBESY: fixed criteria, threshold-re-derived verdicts, unavailable → fail),
and (2) the **claude-code/opencode Kiro steering loop** (fresh implementer → adversarial
reviewer → debugger subagents per task). OpenUltraSAST inherits both substrates and *additionally*
builds the `MetaAgent.evolve` loop DocuHarnessX leaves unbuilt.

## Shared blueprint (the spine)

| Concern | DocuHarnessX | OpenUltraSAST | Verdict |
|---|---|---|---|
| Composition seam | `make_docgen` in `docuharnessx/bundle.py` — the only HarnessX import site; `control \| stages_builder()`; returns model-less `HarnessConfig` | `build_sast()` in `harness/build_sast.py` (mirrors `examples/coding/build_coding`), lazy behind `_has_harnessx()` | **shared** |
| Model binding | CLI `prepare_run()`: `model_config.agentic(make_docgen(...))`; model on `harness.model_config.main`, never in config | `HxScanOrchestrator`: `asyncio.run(model_config.agentic(cfg).run(ScanTask(...)))` | **shared** |
| Processor base | `NoOpStage(MultiHookProcessor)`, content-neutral on `step_end`, real module-level classes for `_target_` resolution | `MultiHookProcessor(skip_model=True)` + `SlotContractMixin`, real module-level classes | **shared** |
| Inter-stage seam | `RunContext` over append-only slot constants; frozen versioned handoff dataclasses | typed `sast.*` slots + `SlotContractMixin` (`reads_slots`/`writes_slots`) | **shared** |
| Domain / "ontology" seam | `.docuharnessx/ontology.yaml` → `Vocabulary` (Role×Subject×Intent), loaded at run start | central **CWE policy + ruleset** (`policy/CWE_Score.tsv` + `ruleset/*.toml` + `rule_policy.json`), loaded at run start | **analogous** |
| Acceptance firewall | COBESY all-of gate; judge `passed` untrusted/re-derived; unavailable → fail | `VerifyProcessor` (llm-judge + structural fallback, rejects unknown reachability, fail-closed) | **analogous** |
| Steering | Kiro SDD; `CLAUDE.md`; `.kiro/{steering,specs}`; `kiro-impl` fresh-subagent + adversarial review; `kiro-verify-completion` | same Kiro convention; `.kiro/specs/harnessx-self-improving-rulesets/*`; OpenCode steers, kiro-* maintainer-only | **shared** |
| Self-improvement (`evolve`) | **none** — future seam | `improve/evolve.py → MetaAgent.evolve`, bounded `rule`/`policy` levers, `rule_policy.json` ledger | **diverges (OUS builds it)** |
| Dependency posture | `harnessx` direct git dep + pyyaml | core zero-dep; `harnessx` optional SHA-pinned extra, lazy | **diverges (by design)** |

## Three principled divergences (and reconciliation)

1. **Agent-first vs hybrid.** OUS keeps the sync `HarnessRuntime` through Phases 0–4 and confines
   HarnessX to the hunter pool (the runtimes are "incompatible at every load-bearing point —
   bridge, do not map"). Reconcile by treating `build_sast()` as building **only the hunter
   sub-harness**, applying DocuHarnessX's `make_docgen` pattern *at the hunter-pool boundary*.
   Optional Phase 5 converges OUS toward DocuHarnessX's agent-first end-state (retire
   `HarnessRuntime`) — the divergence is temporal, and DocuHarnessX is the north star.
2. **Editable ontology vs authoritative severity.** DocuHarnessX's whole vocabulary is editable
   presets. OUS splits its domain seam into a **mutable detection vocabulary** (`ruleset/*.toml`,
   loop- and human-editable) and an **immutable severity/scope authority** (`CWE_Score.tsv`,
   verycode-upstream, the loop must never edit). Where DocuHarnessX relies on convention ("never a
   hardcoded literal"), OUS relies on a **validator** (`EvolveValidator._policy` forbids editing the
   0–5 severity) because a loop, not just a human, edits it.
3. **Firewall-as-reward vs reward/feasibility split.** DocuHarnessX's firewall *is* the signal
   (binary pass/fail). OUS must feed `MetaAgent.evolve`, so it keeps a **scalar reward**
   (`project_score`) **separate from** a **hard feasibility constraint** (≥90% recall / <10% FP),
   un-folded so the loop can't game the number. Reuse DocuHarnessX's fail-closed firewall verbatim
   at the *per-finding* `VerifyProcessor` granularity; layer the reward/feasibility split on top.

## Phase 3 blueprint for OpenUltraSAST (mirror DocuHarnessX)

- **`build_sast()` factory** = the single HarnessX composition import site (DocuHarnessX's "blast
  radius is this file" rule on `bundle.py`); `control | hunter_stages_builder()`; raised loop
  thresholds (large-repo scanning revisits shapes, like large-repo docs); model bound later in
  `HxScanOrchestrator`. OUS delta: the `_has_harnessx()` guard + raise-then-fallback to
  `run_hunter_pool()`.
- **Ontology seam** = CWE policy + ruleset as OUS's "ontology": `load_ruleset(path, ledger)` +
  `load_policy(tsv)` loaded into `sast.*` slots at run start; `resolve_severity()` is the single
  severity authority (mirrors DocuHarnessX's "every transform reads the loaded store, never a
  literal"); absent ledger → byte-identical baseline; unmapped enabled-rule CWE → fail-loud
  (stricter than DocuHarnessX, because severity is authoritative).
- **Processor set**: register HarnessX classes directly **only inside the hunter sub-harness**
  (LoopDetection, CostGuard/TokenBudget, ToolFailureGuard, ToolFilter, SelfVerify, EpisodeMetrics/
  OTel/Checkpoint); everything deterministic is a `skip_model=True` `MultiHookProcessor` over slots
  (SarifIngest/Preprocess/EntryPoint/Rank/Calibrate/QuickFindings/PolicyScoring/Verify/Score) with
  stable `make_<stage>_processor()` factories so a spec replaces exactly one stub in place.
- **`MetaAgent.evolve` loop** (Phase 4, on the same substrate): two bounded levers (`rule`,
  `policy`); reward = `project_score`; feasibility = recall/FP gate (un-folded); signal path
  benchmark per-rule precision/recall + `rule_policy_delta` → `rule_signals.json` →
  `MetaAgent.evolve`; gate = validity (canonicalize → contract → `_rules`/`_policy` → replay) →
  novelty/evidence → re-benchmark → attribution → accept or **byte-for-byte revert** (the
  structural analog of DocuHarnessX's `DEFAULT_UNAVAILABLE_VERDICT="fail"`); ledger =
  `rule_policy.json` (OUS's resume-safe analog of DocuHarnessX's markdown round journal).
- **Steering surface**: reuse DocuHarnessX's `kiro-*` skills verbatim (maintainer-only); add
  SAST-domain `.kiro/steering/` rules pinning the detection gate as a hard invariant, the zero-dep
  guard, and the `pip --dry-run` audit gate; traceable per-module docstrings citing spec Req/Decision
  numbers.

## Net

The two projects already share the spine — one composition factory, model bound in the CLI via
`ModelConfig.agentic`, content-neutral processors over typed slots, a project-loaded domain seam,
a fail-closed acceptance firewall, and the Kiro fresh-subagent steering loop. OpenUltraSAST diverges
in exactly three principled places (hybrid runtime confining HarnessX to the hunter pool; it *builds*
the `MetaAgent.evolve` loop with a reward/feasibility split + `rule_policy.json` ledger; zero-dep core
with HarnessX opt-in). Adopting DocuHarnessX's load-bearing patterns at the points above gives the
two projects one architecture that opencode/claude-code steers identically.
