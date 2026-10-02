# OpenUltraSAST

**v2.0.0 (Python package `2.0.0`), state as of 2026-10-02.** An experimental static
security analyser. The pre-push safety net is **NO-GO** for rollout: no hook capability is
enabled and no independent population has passed the qualification gates (see
[docs/evaluation.md](docs/evaluation.md)). See the [release notes](RELEASE_NOTES.md).

OpenUltraSAST separates what it can prove from what it merely suspects, and says which is which.
A scan combines language-scoped pattern rules, a semantic overlay, a Joern-based taint engine
and optional model calls; every finding carries the evidence that earned its place, and a scan
that could not look at something records that as a degradation instead of reporting a clean
result.

`ousast` is the interface. Model-driven work over whole repositories runs on a separate
agentic plane (google/ax), and a learned decision engine that weighs all the signals is in
development; neither is needed for a scan.

## Install and quickstart

```bash
uv sync --group dev

# Deterministic scan, no model calls
uv run ousast scan /path/to/repo --mode quick

# CI: exit 1 on any evidence-verified finding
uv run ousast scan . --mode quick --fail-on verified
```

The core install depends only on PyYAML. Optional extras (`pyproject.toml`): `semantic`
(tree-sitter grammars for the overlay), `s3` (boto3, for the plane's memory store on an
S3-compatible bucket) and `docs` (MkDocs with the Material theme, for the documentation site);
install one with `uv sync --extra s3`.

For `standard` and `deep` scans, use the Docker image, which ships Joern (with `php-cli` for
the PHP frontend) next to the tool. Source the shell wrapper once and `ousast` runs in the
container with your directory mounted read-only:

```bash
source /path/to/OpenUltraSAST/ops/shell/ousast.sh   # PowerShell: ops/shell/ousast.ps1
ousast scan . --mode standard
```

Details, including a pinned host install of Joern, are in [ops/README.md](ops/README.md).

Every run writes auditable artifacts under `<target>/.openultrasast/runs/<scan-id>/`:
`manifest.json`, `findings.json`, `verification.json`, `score.json`, `report.md`,
`report.sarif` and `trace/events.jsonl`, plus the stage artifacts of the mode.

## Scan modes

| Mode | What runs | Needs |
| --- | --- | --- |
| `quick` | Language-scoped pattern rules, entry-point reachability hints, ranking, verification, scoring. Deterministic and reproducible. | nothing |
| `standard` | `quick` plus the MAP stage: complexity map, semantic overlay, authorization obligations, and the model layer, which builds one Joern code property graph per repository and decides taint, guard-dominance and configuration questions on it. An LLM is asked only the residual question the graph cannot settle (a `suspicion`); `[models] hunter` adds the tool hunter. | Joern for the model layer (else a `cpg_unavailable` degradation); a provider key for the LLM parts (else they are skipped and only the graph's entailed findings are reported) |
| `deep` | The MAP stage of `standard` plus REGRESS: promoted candidates are loaded by a small snippet inside a Docker sandbox (no network, read-only source, non-root, memory/pid/time limits) and get a `triggerable` / `not_triggerable` / ... verdict. | a working `docker` (else a `sandbox_unavailable` degradation) |

`--fail-on never|findings|verified|worth-fixing` sets the exit code: `findings` fails on any
reported finding, `verified` on any evidence-verified one, `worth-fixing` on a deep-mode
verdict that is worth fixing. `--config openultrasast.toml` loads settings.

## Detection coverage (quick rules)

Rules run only against files of their language. The bundled ruleset lives in
`src/openultrasast/ruleset/<language>/rules.toml`:

| Language | Classes (CWE) |
| --- | --- |
| C / C++ | stack buffer overflow (121), format string (134), command injection (78) |
| Python | command injection (78), code injection (95), SSTI (94), deserialization (502), SQLi (89), path traversal (22), SSRF (918), weak hash (327), insecure default (489) |
| JavaScript / TS | command injection (78), code injection (95), XSS (79), SQLi (89), path traversal (22), SSRF (918), weak hash (327), deserialization (502) |
| Java + Groovy templates | command injection (78), SQLi (89), weak hash (327), deserialization (502), unescaped template XSS (79) |
| PHP | SQLi (89), command injection (78), file inclusion (98), path (22), open redirect (601), SSRF (918); code eval (95), unserialize (502) and echo XSS (79) ship as `shadow` rules |

The detection gate (`uv run python -m openultrasast.gate`, also `tests/test_detection_benchmarks.py`)
enforces the project goal of **at least 90% recall and under 10% false positives** per language
on the bundled corpora in `benchmarks/manifests/`. Its output on this tree:

| Language | Recall | False-positive rate |
| --- | --- | --- |
| C / C++ | 93.3% (14/15) | 0.0% |
| Python | 93.3% (14/15) | 0.0% |
| JavaScript | 92.3% (12/13) | 0.0% |
| Java | 100% (4/4) | 0.0% |
| **Overall** | **93.6% (44/47)** | **0.0%** |

These corpora are cheat-sheet fixtures modelled on deliberately vulnerable applications. They
show that a rule change did not break a known detection; they are not a recall estimate on
real code. Real-code results are in [docs/evaluation.md](docs/evaluation.md).

**PHP is not in the gate, and its numbers are in-sample only.** The PHP rules were written and
tightened while looking at the development corpus they were measured on
(`benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json`): 13 of 14 expected
findings on the `php-vulnerable` fixture with no false positive, 2 false positives on
`php-benign`, and per-rule precision lower bounds from 0.03 to 1.0 on the real pins. Treat
them as development numbers, not as a holdout result.

**Framework knowledge is optional.** Rule and taint-fact entries that know a framework or
library (WordPress, Flask, Django, Express, Spring, ...) carry a `framework` or `library` tag
naming a row of `src/openultrasast/ruleset/frameworks.toml`. The loaders take `priors=`
(`"all"`, the default and today's behaviour; `"off"`, language-level knowledge only; or a set
of ids), so their contribution can be measured and switched off.

## Pre-push checks (experimental)

`ousast pre-push` analyses the commits a `git push` would publish, or an explicit
`--base`/`--head` pair, and compares the head against its base so that only new or worsened
defects are candidates. `--mode advisory` (the default) never blocks; `--mode blocking` and
`--incomplete-coverage block` opt into enforcement. The artifact must be written outside the
analysed repository.

```bash
uv run ousast pre-push /path/to/repo --base BASE --head HEAD \
  --artifact /outside/the/repo/result.json
```

The default capability registry is empty, so no normal alert is emitted today; every
candidate stays diagnostic in the artifact. Installation into a repository's hooks
(`ops/install-pre-push`), caching and the optional witness model are documented in
[ops/README.md](ops/README.md).

## Model providers and keys

Keys and store settings live in `.env` in the working directory (gitignored, never committed;
`.env.example` lists the names):

```bash
DEEPSEEK_API_KEY=...              # every LLM call: model layer, tool hunter, plane tasks, decision engine
OPENROUTER_API_KEY=...            # embeddings only
OPENROUTER_EMBEDDING_MODEL=openai/text-embedding-3-small

# Plane memory store (maintainers). Unset: a local file store under ~/ousast-results/plane/memory.
OUSAST_MEMORY=s3://<bucket>       # or s3://<bucket>/<prefix>; needs the s3 extra
S3_ENDPOINT=https://host[:port]   # the full URL
S3_REGION=us-east-1               # optional; spares a GetBucketLocation call
S3_BUCKET=<bucket>                # the bucket `OUSAST_MEMORY=s3://` alone names
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

The project uses DeepSeek (`deepseek-flash`) for LLM calls and OpenRouter only for embeddings.
Set `DEEPSEEK_API_KEY`: without it, chat calls fall back to OpenRouter when that key is set
(`tool_hunter.resolve_hunter_client`). The S3 bucket is set up once by an admin and verified
by the store at every start ([docs/rustfs.md](docs/rustfs.md)). `ousast pre-push` does not read
`.env`; it takes credentials from the Git process environment.

**`.env` never overrides a variable already exported in your shell.** A stale
`export DEEPSEEK_API_KEY=...` in your profile wins over the `.env` file silently; `unset` it
when a key change in `.env` seems to have no effect.

## Benchmarks and pair evaluation

```bash
# Score the scan against a ground-truth manifest
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick

# Vulnerable-vs-fixed pairs: fire on the vulnerable side, stay silent on the fix
uv run ousast pairs
uv run ousast pairs --slice sast       # OWASP Benchmark + Juliet
uv run ousast pairs --slice vibe-py --pointers   # also fetch non-vendored pointer pairs (network)
uv run python -m openultrasast.pair_gate         # CI: local pairs must all pass
```

Each benchmark run writes `.openultrasast/benchmarks/<id>/` (`benchmark_result.json`,
`calibration_records.json` with every miss, `external_baseline_deltas.json`). The pair
catalogs live in `benchmarks/pairs/`.

## Self-improvement

`ousast improve` runs a bounded loop over the governed ruleset: benchmark, propose edits to
rule status and score constants only, validate, re-benchmark, and accept a round only if
recall stays at least 90%, false positives under 10%, the project score does not regress and
no matched finding is lost. Accepted rounds land in
`<target>/.openultrasast/calibration/rule_policy.json`, which the next scan of that target loads.

```bash
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run --memory
```

With `--memory`, proposals also come from the rows plane runs stored (see below), through the
same validator and gate; rows from holdout pairs, from the gated manifest's own cases and from
any `--qualify-population` are dropped first. Details:
[docs/architecture.md](docs/architecture.md#self-improvement).

## The agentic plane (maintainers)

Model work over whole repositories runs as a Run manifest on [google/ax](ops/ax/README.md)
over Agent Substrate, one isolated actor per task. ax is the only agentic executor: there is
no local subprocess path, and a scan needs none of it. Each task binds its own Model and its
own `usd`/`calls` budget; egress is deny-by-default per task (one EgressPolicy per actor,
hostnames only: the artifact receiver, the Workspaces' Git hosts, the Model's declared host);
and the provider key travels only in the task's start request, sent through Substrate's
`atenet-router` to that task's actor, never in a manifest or an image.

What runs where today: the reconciler (`ousast plane run`) and the artifact receiver run on
the operator's host; the tasks run in gVisor sandboxes on Agent Substrate in a single-node kind
cluster on the maintainer's host; the memory store is a local file store or an S3-compatible
bucket (`OUSAST_MEMORY=s3://<bucket>`; RustFS is the tested server).

```bash
uv run ousast plane doctor                               # kind, Agent Substrate, ax controller, runner image
uv run ousast plane run plane/runs/validation-46.yaml    # a rerun skips tasks already done; --workers bounds tasks in flight
uv run ousast plane status validation-46                 # per-task status and the token attribution table (--units per unit)
uv run ousast plane remember validation-46               # ingest the run's rows into the memory store
uv run ousast plane memory-normalise --dry-run           # count the stored rows a rewrite to the fixed schema would touch
```

`ousast plane workspaces`, `harvest` and `alerts-engine` generate Runs and their inputs.
Bring-up, the task catalogue, the memory store (`OUSAST_MEMORY`) and the host's lessons are in
[ops/ax/README.md](ops/ax/README.md); what runs where, this host's setup and the guidance for a
separate Kubernetes cluster (planned, not done) are in [docs/deployment.md](docs/deployment.md).

> HarnessX, the earlier optional agentic extra, was retired 2026-09-30, and a leftover
> `[harnessx]` section (retired 2026-09-30) is ignored with one warning. `[models] verifier`,
> `[fusion] panel_model` and `[fusion] decider_model` fail with a message naming the plane
> replacement. The LLM judge and the LLM fusion panels were retired with it; fusion is
> deterministic. See [RELEASE_NOTES.md](RELEASE_NOTES.md).

## Decision engine (in development, not adopted)

A learned decision engine is being built to replace hand-tuned detection edits: each
instrument (quick rules, the Joern engine, model sink classification, verify passes, repository
facts) produces signals, never verdicts, and a compiled AI classifier with local memory turns
them into a calibrated probability per candidate with BLOCK and ADVISORY operating points.
No scan, pre-push or report uses it yet, and it is not adopted. Measured so far out of
repository (slice 2, 2026-10-02, six families): pooled AUC 0.77 to 0.96 per family, within-pair
AUC 0.72 to 0.93, BLOCK offered for no family, re-run agreement below 0.9 for three of the six
(`benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`). Status and the
numbers: [docs/decision-engine.md](docs/decision-engine.md).

## Agent integrations

An agent that can run shell commands needs nothing but the CLI. For
[OpenCode](https://opencode.ai) there are optional project skills in `.opencode/skills/`:
`openultrasast-scan`, `openultrasast-triage` and `openultrasast-fix-audit`.

`ousast mcp` runs a narrow MCP server over stdio (newline-delimited JSON-RPC) with ten tools:
`openultrasast.scan`, `status`, `findings`, `get_finding`, `evidence`, `artifacts`,
`benchmark`, `explain`, `propose_patch` (degrades visibly) and `export_report`. No tool runs a
shell, Docker or a free-form command.

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

> The `kiro-*` skills, `AGENTS.md` and `.kiro/` are the maintainer's development tooling and
> can be ignored by users.

## Further reading

Documentation site with flow diagrams (`docs/`, `mkdocs.yml`): `uv sync --extra docs && uv run mkdocs serve`.

- [docs/architecture.md](docs/architecture.md): the scan pipeline, evidence ladder, CWE policy
  and project score, and the self-improving loops.
- [docs/evaluation.md](docs/evaluation.md): independent populations, the qualification gates,
  pair corpora and the plane increment results.
- [docs/deployment.md](docs/deployment.md): the plane on this host, and the guidance for a
  separate Kubernetes cluster (planned) with what is implemented and what is not.
- [docs/decision-engine.md](docs/decision-engine.md): the learned decision engine.
- [docs/threat-model.md](docs/threat-model.md): trust boundaries, sandbox and hardening.
- [docs/token-ergonomics.md](docs/token-ergonomics.md): model spend at runtime (budgets, reuse,
  measured costs) and in coding sessions.
- [docs/examples.md](docs/examples.md): end-to-end walkthroughs.

## Development

```bash
uv run pytest                 # tests, incl. the 90/10 detection gate
uv run ruff check .           # lint
uv run ruff format --check .  # format
uv run mypy src/openultrasast # types
uv run python -m openultrasast.gate       # standalone detection gate
uv run python -m openultrasast.pair_gate  # local vuln-vs-fix pairs
uv run python dagger/ci.py    # containerized CI pipeline
```

Maintainer commands not covered above: `ousast repos` (pinned known-vulnerable checkouts),
`ousast index` (chunk a repository for embedding-index construction), `ousast model candidates`
(what the candidate enumerator can reach) and `ousast learn` (the decision engine's data; see
[docs/decision-engine.md](docs/decision-engine.md)).
