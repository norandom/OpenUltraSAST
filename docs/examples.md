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

## 2. CI gate

```bash
# Fail the build on any evidence-verified finding:
uv run ousast scan . --mode quick --fail-on verified

# The hard detection gate (>=90% recall, <10% FP), score-independent:
uv run python -m openultrasast.gate
```

## 3. Benchmark a known-vulnerable corpus

```bash
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick
# -> expected / matched / missed counts + a per-rule recommendation delta
```

## 4. Self-improve the ruleset from benchmark feedback

```bash
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run  # preview
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml            # apply
# Accepted edits land in <target>/.openultrasast/calibration/rule_policy.json,
# which the next scan/benchmark of that target loads automatically.
```

## 5. Standard mode with the HarnessX agentic plane (OpenAI)

```bash
uv sync --extra harnessx
export OPENAI_API_KEY=sk-...
cat > openultrasast.toml <<'TOML'
[models]
hunter   = "gpt-4o"
verifier = "gpt-4o"
[harnessx]
provider        = "openai"
max_cost_usd    = 2.0
token_threshold = 120000
[fusion]
panel_model = "gpt-4o"   # two-panel adjudication on triggered findings
[hardening]
redact_secrets = true
max_findings   = 0
TOML
uv run ousast scan /path/to/code --mode standard --config openultrasast.toml
jq '.degradations' "$run/manifest.json"   # null = HarnessX ran; entries = it fell back
jq '.fusion'       "$run/manifest.json"   # per-finding dispositions
```

## 6. Drive it from an MCP client (OpenCode / IDE)

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

Then: `openultrasast.scan {path}` → `run_dir` → `openultrasast.findings {run_dir}` →
`openultrasast.explain {run_dir, finding_id}`. See the README "MCP server" section.
