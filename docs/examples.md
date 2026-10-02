# End-to-end examples

Each example is self-contained. Artifacts land under
`<target>/.openultrasast/runs/<scan-id>/` and `.openultrasast/` is gitignored.

## 1. Quick scan a local repo (deterministic, no keys)

```bash
uv run ousast scan /path/to/code --mode quick
run=/path/to/code/.openultrasast/runs/<scan-id>
cat  "$run/report.md"       # findings + evidence (secrets redacted)
jq . "$run/score.json"      # 0–100 project score + gate verdict
"$run/report.sarif"         # SARIF for code-scanning / IDEs
```

## 2. Standard scan with the engine (Docker)

```bash
source ops/shell/ousast.sh          # once per shell; builds the image on first use
ousast scan . --mode standard       # Joern model layer, container network off: no model calls
ousast-with-judge scan . --mode standard   # network on, so the model is asked (needs DEEPSEEK_API_KEY)
```

Without a key the graph still decides; only the `suspicion` band goes unasked, and the manifest
records the degradation.

## 3. CI gate

```bash
# Fail the build on any evidence-verified finding:
uv run ousast scan . --mode quick --fail-on verified

# The hard detection gate (>=90% recall, <10% FP), score-independent:
uv run python -m openultrasast.gate
```

## 4. Benchmark a known-vulnerable corpus

```bash
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick
# -> expected / matched / missed counts + a per-rule recommendation delta
```

## 5. Vuln vs fixed pair eval (efficiency, not cheat-sheet recall)

```bash
uv run ousast pairs                              # local fixtures + vendored GitHub VFCs
uv run ousast pairs --slice github --json        # honesty dashboard as JSON
uv run ousast pairs --slice sast                 # OWASP Benchmark + Juliet Youden (TPR-FPR)
uv run ousast pairs --slice vibe-py --pointers   # nightly: pointer pairs via the local cache (network)
uv run ousast pairs --split holdout --profile human   # filter by declared split and provenance profile
uv run python -m openultrasast.pair_gate         # CI: local pairs must all pass
```

Each case is two isolated trees (vuln file vs patched file, same relative path).
`pair_correct` means the harness fired on the vuln side and stayed silent on the
fix. Misses and fix-side leaks become `miss`/`fp` signals for `ousast improve`.
The catalog and public dataset pointers live in `benchmarks/pairs/`.

## 6. Self-improve the ruleset from benchmark feedback

```bash
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run  # preview
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml            # apply
# Accepted edits land in <target>/.openultrasast/calibration/rule_policy.json,
# which the next scan/benchmark of that target loads automatically.
```

## 7. Running the agentic plane

Model work over whole repositories runs as a Run manifest on ax, one isolated actor
per task (bring-up: [ops/ax/README.md](../ops/ax/README.md)). The provider key is
read from the environment (or `.env`, which never overrides an exported variable) by
`ousast` and sent only in each task's start request.

```bash
uv run ousast plane doctor                               # kind, Agent Substrate, ax controller, runner image
uv run ousast plane run plane/runs/validation-46.yaml    # per case: repo-facts, verify a/b/c, agree, final, features, remember
uv run ousast plane status validation-46                 # per-task status and token attribution
uv run ousast plane remember validation-46               # re-ingest the run's memory rows (OUSAST_MEMORY)

# Feed the stored rows back into the ruleset loop (same validator and gate)
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run --memory
```

Each task in the Run carries its own Model and `budget: {usd, calls}`; a task that
reaches its ceiling stops as `unfinished` and resumes on a rerun with a larger
budget. `ousast plane status` prints the token attribution table: calls, prompt,
cache-hit and output tokens and USD per task.

## 8. Drive it from an MCP client (OpenCode / IDE)

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

Then: `openultrasast.scan {path}` → `run_dir` → `openultrasast.findings {run_dir}` →
`openultrasast.explain {run_dir, finding_id}`. See the README section "Agent integrations".
