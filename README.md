# OpenUltraSAST

OpenUltraSAST is an experimental static security analyser meant to work as a safety net on
repositories it has never seen: it scans a checkout, or the commits a `git push` would publish,
and separates what it can prove from what it merely suspects. A scan combines language-scoped
pattern rules, a tree-sitter overlay, a Joern code property graph and, optionally, a model that is
asked only the question the graph cannot settle; every finding carries the evidence that earned
its place. A scan that could not look at something records a degradation instead of reporting a
clean result. `ousast` is the interface; model work over whole repositories runs on a separate
agentic plane (google/ax), and a learned decision engine is in development. Neither is needed
for a scan.

This file is the front door; each section links to its page of the documentation site (`docs/`,
`mkdocs.yml`; `uv sync --extra docs && uv run mkdocs serve`).

## Status

**v2.0.0, state as of 2026-10-02.** The pre-push safety net is **NO-GO** against every M4 gate:
no hook capability is enabled, and the two independent populations spent so far gave engine recall
1 of 11 and then 0 of 17. The learned decision engine ranks but may not block: BLOCK is offered for
no family. The project has stopped trying to reach the gates by hand; every detection change now
has to win a controlled measurement on held-out repositories. The one page that states all of this
with the record behind each figure is [docs/where-we-stand.md](docs/where-we-stand.md); the
release history is in [RELEASE_NOTES.md](RELEASE_NOTES.md).

## Install and first scan

Which tier you need: a deterministic scan of a checkout or a CI gate is tier 1; the Joern engine
(`standard`, `deep`) is tier 2; running model work over whole repositories on the plane is tier 3,
for maintainers; tier 4 does not exist yet.

### Tier 1: quick scan, no Docker

The core install depends only on PyYAML. From a checkout, `uv sync` (or `pip install .`) installs
the `ousast` entry point; `uv sync --group dev` adds the test and lint tools.

```bash
uv sync
uv run ousast scan /path/to/repo --mode quick
uv run ousast scan . --mode quick --fail-on verified   # CI: exit 1 on any evidence-verified finding
```

This runs the language-scoped pattern rules, entry-point reachability hints, ranking,
verification and scoring: deterministic, reproducible, no network, no keys. What it cannot do:
there is no engine, so nothing follows a value across statements or files, and the PHP quick rules
are a low-precision, in-sample development set (per-rule precision lower bounds from 0.03 to 1.0 on
the real pins, `benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json`). The optional
`semantic` extra (`uv sync --extra semantic`) installs the tree-sitter grammars for the overlay.

### Tier 2: standard and deep scans (Docker)

`standard` and `deep` need Joern. The Docker image `openultrasast:dev` ships the tool, Joern
v4.0.625 and `php-cli` (needed by the PHP frontend) in one image; it is built locally from the
`Dockerfile` (no published image yet), and it is big: a JRE plus about 2 GB of Joern. The shell
wrapper builds it on first use and then runs `ousast` in the container with your directory mounted
read-only and the container network off:

```bash
source /path/to/OpenUltraSAST/ops/shell/ousast.sh   # PowerShell: ops/shell/ousast.ps1
ousast scan . --mode standard                       # the graph decides; no model is asked
ousast-with-judge scan . --mode standard            # network on, the model is asked (DEEPSEEK_API_KEY)
```

`docker compose build` and `TARGET=/path/to/repo docker compose run --rm ousast scan /target` do
the same without the wrapper. `deep` adds REGRESS, which runs each reproduction snippet with
`docker run` from wherever the scan runs; the engine container has no Docker socket, so run `deep`
from a host install with Joern on the PATH (`pyinfra @local ops/joern.py`, pinned and checksum-
verified) and a working `docker`, or accept the recorded `sandbox_unavailable` degradation.
Details, including the host install, are in [ops/README.md](ops/README.md).

Keys and store settings live in `.env` in the working directory (gitignored; `.env.example` lists
the names). `DEEPSEEK_API_KEY` serves every LLM call; `OPENROUTER_API_KEY` is used for embeddings
only (`ousast learn memory embed`). `.env` never overrides a variable already exported in your
shell, so `unset` a stale export when a key change seems to have no effect. The plane's memory
store defaults to a local file store under `~/ousast-results/plane/memory`; an S3-compatible bucket
is optional (`uv sync --extra s3`, then `OUSAST_MEMORY=s3://<bucket>` with `S3_ENDPOINT` and the
AWS credentials in `.env`). Nothing in a scan needs it.

### Tier 3: the plane on ax (maintainers)

None of this is needed for tier 1 or 2. Today's profile is a single-node kind cluster on the
maintainer's host. `ops/ax/up.sh` needs `docker`, `go`, `kubectl`, `kind`, `ko` and `ax` on the
PATH (it refuses to start when one is missing) and builds Agent Substrate and ax from their
checkouts under `~/.cache/ousast/ax-src/`. Measured idle footprint with two workers: the kind node
takes 1.7 GiB of memory (27% of the 7.7 GiB host) and 4.9 GB of disk for images, with several GB
more of Go caches during the build; the worker pool is sized for that 7 GB host. The verify and
roles tasks need `DEEPSEEK_API_KEY`, and memory lives in the local file store or the S3 store
(RustFS is the tested server). Bring-up, doctor and the smoke Run: [ops/ax/README.md](ops/ax/README.md).

### Tier 4: Kubernetes (k3s), planned

No deployment to any cluster other than that kind cluster has been made. The target is two
profiles of one code base, `kind` locally and `k3s` in production, where the same `ousast plane run`
submits a Run in a remote execution mode: it needs a kubeconfig context or the cluster's ingress
(and an `imagePullSecret` on the worker ServiceAccount for a private package), runner and engine
images published to GHCR and pinned by digest, and the S3 store as the artifact path, with no
receiver on a laptop. The plan, and the code changes it needs with file paths, are in
[docs/deployment.md](docs/deployment.md#production-topology-ax-on-a-kubernetes-cluster).

## Scan modes

`quick` runs the pattern rules, hints, ranking, verification and score and needs nothing.
`standard` adds the MAP stage: complexity map, semantic overlay, authorization obligations and the
Joern model layer, which builds one code property graph per repository and decides taint,
guard-dominance and configuration questions on it; a model is asked only the residual question
(without a key it is skipped and only the graph's entailed findings are reported). `deep` adds
REGRESS: promoted candidates are loaded by a small snippet in a Docker sandbox and get a
`triggerable` or `not_triggerable` verdict. A missing engine is a recorded degradation
(`cpg_unavailable`, `sandbox_unavailable`), never a clean result.

`--fail-on never|findings|verified|worth-fixing` sets the exit code and `--config openultrasast.toml`
loads settings. Every run writes `manifest.json`, `findings.json`, `verification.json`,
`score.json`, `report.md`, `report.sarif` and `trace/events.jsonl` under
`<target>/.openultrasast/runs/<scan-id>/`. `ousast pre-push` (experimental) analyses the commits a
push would publish against their base so that only new or worsened defects are candidates; it is
advisory by default and its capability registry is empty, so no normal alert is emitted today.
Flows and the per-language rule table: [docs/scanning.md](docs/scanning.md).

## How detection works

Three representations, from cheap to expensive: text (regex quick rules, one statement at a time),
tree (the tree-sitter CST and an IR per function, for the overlay and the obligations) and graph
(the Joern CPG, the only one that follows a value across statements, calls and files). Taint runs
as fact tables, queries and verdicts on the graph; absence bugs (an operation that should have
been guarded) are found as obligations, dominance and configuration census; a model answers only
the residual question. [docs/detection-techniques.md](docs/detection-techniques.md) explains each
technique with the code it comes from and what it misses;
[docs/architecture.md](docs/architecture.md) gives the stage order, the evidence ladder (a state
machine, not a label a model may assign), the central CWE policy and the project score, and the
self-improving loops (`ousast improve`, with `--memory` for proposals from plane rows).

Quick rules cover C/C++, Python, JavaScript/TypeScript, Java with Groovy templates, and PHP, and
run only against files of their language. The detection gate (`uv run python -m openultrasast.gate`)
enforces at least 90% recall and under 10% false positives per language on the bundled cheat-sheet
corpora; on this tree it reports 93.62% recall (44/47) and 0.0% false positives. Those corpora show
that a rule change did not break a known detection; they are not a recall estimate on real code,
and PHP is not in the gate. Framework knowledge (WordPress, Flask, Django, Express, Spring) is
tagged as an optional prior in `src/openultrasast/ruleset/frameworks.toml`, so its contribution can
be measured and switched off.

## The plane on ax

Model-driven work over whole repositories runs as a Run manifest, a DAG of ax Tasks, each in its
own gVisor actor on Agent Substrate. ax is the only agentic executor; there is no local
subprocess path. Each Task binds at most one Model and its own `usd`/`calls` budget, egress is
deny-by-default per Task (hostnames only), and the provider key travels only in the Task's start
request, never in a manifest or an image. Measured on the first increment: the plane agreed on 16
of 20 declared sites at $0.0205 per candidate.

```bash
uv run ousast plane doctor                               # kind, Agent Substrate, ax controller, runner image
uv run ousast plane run plane/runs/validation-46.yaml    # a rerun skips tasks already done; --workers bounds tasks in flight
uv run ousast plane status validation-46                 # per-task status and the token attribution table
uv run ousast plane remember validation-46               # ingest the run's rows into the memory store
```

`workspaces`, `harvest`, `alerts-engine` and `memory-normalise` generate Runs, their inputs and
the store's rewrites. The flow and the task catalogue: [docs/plane.md](docs/plane.md); what runs
where today and what a separate cluster would take: [docs/deployment.md](docs/deployment.md).

HarnessX, the earlier agentic extra, was retired on 2026-09-30: a `[harnessx]` section is ignored
with one warning, and `[models] verifier`, `[fusion] panel_model` and `[fusion] decider_model` fail
naming the plane replacement, as do config keys nothing ever read. Fusion is deterministic.

## Memory

One store, keyed by repository and pin, holds what plane runs and the decision engine learned:
rows (facts, verdicts, unit costs, alerts, coverage, feature records) and content-addressed blobs
(excerpts, embeddings, cached responses, compiled programs). `OUSAST_MEMORY` selects the backend:
a local file store, or `s3://<bucket>` on any S3-compatible server with versioning, lifecycle
rules, object tags and S3 Select; RustFS is the tested server. An admin sets the bucket up once;
the store verifies it at every start and refuses to run, naming each missing piece, rather than
fall back. Layout and the read and write paths: [docs/memory.md](docs/memory.md); the bucket
policy and admin steps: [docs/rustfs.md](docs/rustfs.md); how stored rows are meant to turn into
better decisions: [docs/memory-and-detection.md](docs/memory-and-detection.md).

## Decision engine and evaluation

A learned decision engine is being built to replace hand-tuned detection edits: every instrument
produces signals, never verdicts; labels come from ground truth only; a compiled AI classifier with
local memory turns retrieved similar cases and the candidate's signals into a calibrated
probability with BLOCK and ADVISORY operating points. It is **in development, not adopted**: no
scan, pre-push check or report uses it. Measured on six families, on repositories the compiled
program was not shown, the pooled AUC of its score runs from 0.77 (injection) to 0.96 (access
control); the stricter within-pair AUC is 0.72 to 0.93; BLOCK is offered for no family
(`benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`). Maintainer surface:
`ousast learn labels|memory|compile|evaluate|curve|experiment|audit-leaks`. Design, slices and
the A/B protocol: [docs/decision-engine.md](docs/decision-engine.md).

How anything is measured on code the tool was not tuned on, the pair corpora, the independent
populations and the M4 gates, and the fold discipline that keeps learned decisions out of their
own training data: [docs/evaluation.md](docs/evaluation.md). Population v3 (PHP, 15 cases) is
frozen as the one-time final check and nothing in the tree may read it.

```bash
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick
uv run ousast pairs --slice sast                     # fire on the vulnerable side, stay silent on the fix
uv run python -m openultrasast.pair_gate             # CI: local pairs must all pass
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run --memory
```

## Token economics

Model tokens are the one running cost. At runtime the plane routes them: one Model and one budget
per Task, a metered client that refuses the next call at the ceiling, repository facts computed
model-free and reused, blobs replayed at $0, triage before the hunt and a tie-break only on
disputed candidates. In development, 85.5% of the maintainers' coding-session tokens were tool
input and output rather than reasoning (down from 90%), and the remedies in `benchmarks/dev/`
target that. Mechanisms,
the measured costs and the before-and-after table: [docs/token-ergonomics.md](docs/token-ergonomics.md).

## Examples, threat model

End-to-end walkthroughs, from a quick scan to an MCP client: [docs/examples.md](docs/examples.md).
What the tool trusts and what it does not (scanned code is untrusted input, secret redaction,
per-task egress, budgets, the `deep` sandbox): [docs/threat-model.md](docs/threat-model.md).

## Contributing and maintainer tooling

```bash
uv run pytest                 # tests, incl. the 90/10 detection gate
uv run ruff check .           # lint
uv run ruff format --check .  # format
uv run mypy src/openultrasast # types
uv run python -m openultrasast.gate       # standalone detection gate
uv run python -m openultrasast.pair_gate  # local vuln-vs-fix pairs
uv run python dagger/ci.py    # containerized CI pipeline
```

An agent that can run shell commands needs nothing but the CLI. For [OpenCode](https://opencode.ai)
there are two project skills in `.agents/skills/`: `openultrasast-scan` (modes and their
prerequisites, `--fail-on`, the evidence ladder, recorded degradations, run artifacts) and
`openultrasast-triage` (false-positive reasons, what an adjudication may feed, fixing and
re-scanning). `ousast mcp` runs a narrow MCP server over stdio with ten tools (`openultrasast.scan`,
`status`, `findings`, `get_finding`, `evidence`, `artifacts`, `benchmark`, `explain`,
`propose_patch`, `export_report`); no tool runs a shell, Docker or a free-form command:

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

The `kiro-*` skills, `AGENTS.md` and the Kiro-style specifications under `.kiro/` are the
maintainer's development tooling and can be ignored by users. Other maintainer commands:
`ousast repos` (pinned known-vulnerable checkouts) and `ousast model candidates` (what the
candidate enumerator can reach).

## Licence

The repository carries no licence file yet (checked 2026-10-02: no `LICENSE` at the root and no
`license` field in `pyproject.toml`), so until one is added, treat the code as all rights reserved
and ask the maintainer before reusing it. Third-party material keeps its own terms: Joern is
downloaded at image build time under its own licence, the tree-sitter wheels of the `semantic`
extra are MIT, and the published benchmark cases were licence-checked one by one (v1's OpenCVE
case is BUSL-1.1, see [RELEASE_NOTES.md](RELEASE_NOTES.md)).
