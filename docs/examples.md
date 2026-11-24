# End-to-end examples

Each example stands on its own. A scan writes its run under
`~/.cache/openultrasast/runs/<scan-id>/`, or under `$XDG_CACHE_HOME/openultrasast/runs/` when
that variable is set to an absolute path, and prints that path. `OPENULTRASAST_RUNS_DIR`
overrides the location: an absolute path is used as given, and a relative one is resolved against
the current working directory, never against the target. Once a scan has written its run to the
default location, with no `OPENULTRASAST_RUNS_DIR` set, the runs there that are older than 30 days
are removed, and `ousast` prints one `notice:` line when it removes any;
`OPENULTRASAST_RUNS_RETENTION_DAYS` sets the number of days (`0` keeps every run), and nothing is
ever removed from a location chosen with `OPENULTRASAST_RUNS_DIR`.

A scan that rejects or holds a finding writes one file into the scanned tree, and only when that
file's content would change:
`<target>/.openultrasast/calibration/false_positive_learnings.json` (`.openultrasast/` is
gitignored in this repository, not in one of your own); on a read-only tree the scan records
`ledger_not_written` instead and keeps the learnings in the run directory.

## 1. Quick scan a local repo (deterministic, no keys)

```bash
uv run ousast scan /path/to/code --mode quick
# the scan prints: run_dir=/home/you/.cache/openultrasast/runs/<scan-id>
run=/home/you/.cache/openultrasast/runs/<scan-id>
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

Without a key, the graph still decides. Its entailed findings are reported. The LLM's residual
and suspicion questions go unasked.

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

Each case is two isolated trees: the vuln file and the patched file, at the same relative path.

- `pair_correct` means the harness fired on the vuln side and stayed silent on the fix.
- Misses become `miss` signals and fix-side leaks become `fp` signals in the pair report.
- The catalog and public dataset pointers live in `benchmarks/pairs/`.

## 6. Running the agentic plane

Model work over whole repositories runs as a Run manifest on ax. Each task gets one isolated
actor. Bring-up is in [ops/ax/README.md](ops/ax/README.md).

`ousast` reads the provider key from the environment, or from `.env`. `.env` never overrides an
exported variable. The key is sent only in each task's start request.

```bash
uv run ousast plane doctor                               # kind, Agent Substrate, ax controller, runner image
uv run ousast plane run plane/runs/validation-46.yaml    # per case: repo-facts, verify a/b/c, agree, final, features, remember
uv run ousast plane status validation-46                 # per-task status and token attribution
uv run ousast plane remember validation-46               # re-ingest the run's memory rows (OUSAST_MEMORY)
```

Each task in the Run carries its own Model and `budget: {usd, calls}`.

- A task that reaches its ceiling stops as `unfinished`. It resumes on a rerun with a larger
  budget.
- `ousast plane status` prints the token attribution table. It shows calls, prompt, cache-hit and
  output tokens, and USD per task.

## 7. Drive it from an MCP client (OpenCode / IDE)

MCP (Model Context Protocol) lets an editor or agent call the tool's functions.

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

Then call the tools in this order:

1. `openultrasast.scan {path}` returns a `run_dir`.
2. `openultrasast.findings {run_dir}` lists the findings.
3. `openultrasast.explain {run_dir, finding_id}` explains one.

See the README section "Agent integrations".
