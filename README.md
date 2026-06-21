# OpenUltraSAST

OpenUltraSAST is an independent OpenCode security harness. It combines
HarnessX-style harness composition, OpenUltraCode verification discipline,
OpenRouter-hosted models and embeddings, Docker-isolated code analysis, and
Trail of Bits security skills into a SAST workflow whose primary product goal is
**false-positive elimination** — turning suspicion into evidence-backed findings
and learning from rejected claims.

The full specification lives in `.kiro/specs/openrouter-sast-harness/`
(`requirements.md`, `design.md`, `tasks.md`, `assessment.md`). Clearwing is used
as an implementation oracle for proven source-hunting ideas, not as a dependency
or fork target.

> **Maturity legend** — ✅ implemented and tested · 🟡 primitive exists, not yet
> auto-wired into the scan loop · 🧭 designed, on the roadmap. The current
> verified gate is `usable_harness_mvp`.

## Install and quickstart

```bash
uv sync --group dev

# Scan a local repository (quick mode = deterministic, no model calls)
uv run ousast scan /path/to/repo --mode quick

# Build an embedding-ready chunk index
uv run ousast index /path/to/repo

# Score the detector against a benchmark manifest
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick
```

Every run writes auditable artifacts under `.openultrasast/runs/<scan-id>/`
(`manifest.json`, `findings.json`, `verification.json`, `report.md`,
`report.sarif`, `trace/events.jsonl`, ranking/preprocess/mapping JSON).
`--fail-on findings|verified` gives CI-friendly exit codes.

## How a scan works

The CLI is thin; the `HarnessRuntime` owns the lifecycle and emits an event
trace for every stage (`task_start … stage_start/stage_end … task_end`).

```
repo ──▶ preprocess (language, LOC, tags, fuzz entry points)
     ──▶ static mapping (Semgrep/CodeQL SARIF ingest, normalized hints)
     ──▶ entry-point + reachability mapping (routes, CLI, parsers, contracts)
     ──▶ rank (surface·0.5 + influence·0.2 + reachability·0.3)
     ──▶ findings  ─ quick: language-scoped pattern rules
     │             └ standard: tiered hunter pool (retrieval + skill snippets)
     ──▶ independent verifier (evidence ladder enforced)
     ──▶ report.md + report.sarif + manifest.json (shared finding IDs)
```

- **quick** ✅ — deterministic, language-scoped pattern rules + reachability +
  verification. No model calls, fully reproducible.
- **standard** ✅ scheduling / 🧭 LLM hunters — runs the tiered hunter pool
  (A/B/C budgets, retrieval context, selected Trail of Bits skill snippets,
  JSONL trajectories) and verification; language-aware LLM hunters are the next
  upgrade (today standard reuses the deterministic findings per target).
- **deep** 🧭 — sandboxed build/fuzz/dynamic reproduction (not yet implemented).

## Detection coverage

Language-scoped rule families (rules only run against matching languages, which
removes cross-language false positives):

| Language | Classes (CWE) |
| --- | --- |
| C / C++ | buffer overflow (120), format string (134), command injection (78) |
| Python | command injection (78), code injection (95), deserialization (502), SQLi (89), path traversal (22), SSRF (918), weak hash (327), SSTI (94), insecure default (489) |
| JavaScript / TS | command injection (78), code injection (95), reflected/DOM XSS (79), SQLi (89), path traversal (22), SSRF (918), weak hash (327), deserialization (502) |
| Java + Groovy templates | command injection (78), SQLi via concatenation (89), weak hash (327), deserialization (502), unescaped template XSS (79) |

## Running the benchmarks

Benchmarks wrap the same scan pipeline and score it against ground-truth
manifests in `benchmarks/manifests/`. Each manifest lists the *known*
vulnerabilities (CWE, file, line, sink, evidence) plus optional external
baselines; fixtures live in `benchmarks/fixtures/` and include safe-API files so
precision is measured honestly.

```bash
# One language
uv run ousast benchmark benchmarks/manifests/cpp-damn-vulnerable.toml --mode quick

# All in-scope corpora
for m in c-cpp-smoke cpp-damn-vulnerable \
         python-web-smoke python-vulnerable \
         javascript-node-web-smoke javascript-vulnerable \
         java-web-smoke java-spring-boot-vulnerable; do
  uv run ousast benchmark "benchmarks/manifests/$m.toml" --mode quick
done
```

Each run writes `.openultrasast/benchmarks/<id>/`:
`benchmark_result.json` (recall, precision, misses, false positives, runtime),
`calibration_records.json` (every miss as a next-improvement candidate), and
`external_baseline_deltas.json` (tool-vs-tool comparison).

### Latest results (`--mode quick`)

The corpora are modeled on Damn Vulnerable C/C++, PyGoat/DVPWA and NodeGoat,
plus the real [`kiview/damn-vulnerable-spring-boot-app`](https://github.com/kiview/damn-vulnerable-spring-boot-app)
vendored verbatim (MIT). Three vulnerabilities are deliberately left in the
ground truth that pattern matching *cannot* reach (integer overflow, second-order
SQLi, prototype pollution) so recall is not self-fulfilling.

| Language | Recall | False-positive rate |
| --- | --- | --- |
| C / C++ | 93.3% (14/15) | 0.0% |
| Python | 93.3% (14/15) | 0.0% |
| JavaScript | 92.3% (12/13) | 0.0% |
| Java | 100% (4/4) | 0.0% |
| **Overall** | **93.6% (44/47)** | **0.0%** |

The project goal — **≥90% recall and <10% false positives** per language — is
enforced as a regression gate in `tests/test_detection_benchmarks.py`, so a rule
change that drops recall or raises false positives fails CI.

## OpenCode commands, fusion, and ultra workflows

OpenUltraSAST is driven from the command line. You can call the `ousast` CLI
directly, or run [OpenCode](https://opencode.ai) in the repository and let the
agent run the harness for you — OpenCode is invoked from the command line, loads
the project skills below, and executes `ousast` plus the triage/fix workflow.

```bash
opencode run "scan this repo with ousast in quick mode and triage the findings"
# or drive the CLI yourself:
uv run ousast scan . --mode quick --fail-on verified
```

Project skills that steer the harness from OpenCode (`.opencode/skills/`):

| Skill | Purpose |
| --- | --- |
| `openultrasast-scan` ✅ | run/plan `ousast scan`, indexing, evidence-gated analysis |
| `openultrasast-triage` ✅ | false-positive elimination, ranking calibration, verifier adjudication |
| `openultrasast-fix-audit` ✅ | OpenUltraCode fix lifecycle and adversarial fix review |

**Ultra workflows (OpenUltraCode discipline)** — fixes are never a one-shot
patch prompt. `openultrasast-fix-audit` runs the bounded lifecycle
`intake → plan → minimal patch → adversarial review → reconcile → fresh
verification → ready`, and a patch can only reach `patch_validated` after
sandboxed validation passes with no accepted blocking findings.

**Fusion (deepening) 🧭** — when a finding needs more reasoning than the normal
ranker → hunter → verifier → mapping loop provides (critical/high severity,
verifier disagreement, conflicting static vs semantic evidence, risky fixes, or
an explicit high-assurance request), fusion runs two independent panels that
critique, revise, vote, and a decider issues the disposition (accepted /
rejected / mitigated / deferred / blocked) with model IDs and degradations
disclosed. The triage skill escalates to fusion *when available*; the panel
implementation is on the roadmap (Phase 13).

> The `kiro-*` skills and `AGENTS.md` in this repo are the maintainer's
> spec-driven development tooling. They are not part of using OpenUltraSAST and
> can be ignored by users.

## Evidence ladder: how a false positive is eliminated

Evidence level is a state machine, not a label a model may assign. The verifier
runs on independent context (it never sees hunter reasoning) and enforces:

```
suspicion ─▶ static_corroboration ─▶ crash_reproduced ─▶ root_cause_explained
          ─▶ exploit_demonstrated ─▶ patch_validated
```

A finding is rejected or held back unless the *artifact* for the next level
actually exists:

- below `static_corroboration` → `NEEDS_EVIDENCE` (a model/heuristic suspicion is
  never reported as verified);
- `static_corroboration` but **reachability unknown** → `REJECTED` with a
  tie-breaker demanding call-graph / route / CLI / parser / dynamic evidence
  (this is what kills "pattern matched but nothing attacker-controlled reaches
  it" findings);
- `static_corroboration` **and** function-level reachability → `ACCEPTED`.

When a finding is still rejected after review, `openultrasast-triage` records a
**scoped false-positive learning** (`calibration.py`): a reason from a fixed
taxonomy (`unreachable_path`, `missing_attacker_control`, `sanitizer_disproved`,
`static_rule_mismatch`, `incorrect_model_assumption`, `duplicate`,
`insufficient_impact`, `unsupported`, `contradicted`, `unverified`), evidence,
and a **scope**. Scoping is the safety property: a rejected `syscall_entry` claim
in `auth/` demotes only `auth/…`, never the whole vulnerability class — proven by
`tests/test_calibration.py::test_scoped_false_positive_demotion_does_not_suppress_class_globally`.
Demotion (with an audit trail) is preferred over deletion, so an analyst can
always see *why* something was downgraded.

## How a false negative is eliminated

Misses are first-class signals, surfaced by the benchmark layer rather than
hidden. Every expected vulnerability that no finding matched becomes a
`BenchmarkCalibrationRecord` in `calibration_records.json`, e.g. the integer
overflow the regex engine cannot see:

```json
{
  "cwe": "CWE-190",
  "vulnerability_class": "integer overflow",
  "path": "src/buffer.cpp",
  "failed_stage": "benchmark_ground_truth_matching",
  "next_improvement_candidate": "rules_or_language_hunter",
  "reason": "no OpenUltraSAST finding matched the expected benchmark vulnerability"
}
```

The `next_improvement_candidate` routes the gap to the stage that should close
it — a static rule, SARIF source, entry-point mapping, retrieval package,
language-aware hunter prompt, dynamic reproducer, or skill route. Once a miss is
addressed, it stays closed because the recall/precision gate runs in CI.
`external_baseline_deltas.json` additionally shows where another tool found a
vulnerability OpenUltraSAST missed (or vice-versa).

## The HarnessX self-improving cycle

Each scan is a composed harness of typed processors with read/write **state
contracts** (strict mode fails the scan on a violation; warn mode records a
degradation) and a full event trace. That trace plus the verifier and benchmark
outputs are the feedback that tunes the *next* run — and **OpenCode is the agent
that steers it**: running the triage and fix skills, it reads the harness's
signals and applies the adjustments back into config.

```
        ┌──────────────────── OpenCode steers (triage / fix skills) ─────┐
        ▼                                                                 │
  scan ──▶ traces (events.jsonl) + verifier decisions + benchmark misses  │
        │                                                                 │
        ├─ rejected findings  ─▶ scoped false-positive learnings ─────────┤
        ├─ verifier outcomes  ─▶ ranking calibration / demotion ──────────┤  applied
        ├─ benchmark misses   ─▶ calibration records (next candidate) ─────┤  back
        └─ ranking metrics    ─▶ retrieval filters · prompt constraints ───┘  into
                                  · skill routing · variant seeds             config
```

What the harness exposes today (✅): the event/trace model and processor
contracts; the evidence-ladder verifier; the scoped false-positive learning
taxonomy with ranking calibration and prompt/retrieval-filter adjustments
(`calibration.py`); ranking metrics by tier; and benchmark miss records.

**How the loop is closed today** — OpenCode is the controller. Invoked from the
command line on the repo, it runs a scan, reads the verifier decisions and
benchmark `calibration_records.json`, and via `openultrasast-triage` records the
scoped learnings and recalibrates ranking, then re-runs the benchmark gate to
confirm the change helped without regressing other findings. So the
self-improving cycle is real now with OpenCode as the steering agent; making the
harness apply that feedback **autonomously inside the pipeline** — recalibrating
on the following run without an agent in the loop — is the next milestone
(`standard_security_harness`).

## Development

```bash
uv run pytest                 # tests, incl. the 90/10 detection gate
uv run ruff check .           # lint
uv run ruff format --check .  # format
uv run mypy src/openultrasast # types
uv run python dagger/ci.py    # full containerized CI pipeline
```
