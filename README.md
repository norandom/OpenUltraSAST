# OpenUltraSAST

OpenUltraSAST is an experimental static security analyser. It is meant to be a safety net on
repositories it has never seen. It scans a checkout, or the commits a `git push` would publish. It
keeps what it can prove apart from what it only suspects.

A scan combines up to four parts:

- language-scoped pattern rules;
- a tree-sitter overlay (a syntax tree of each file, built by the tree-sitter parser);
- a Joern code property graph (a graph of the program's syntax, control flow and data flow);
- optionally, a model. It is asked only the question the graph cannot settle.

Every finding carries the evidence that earned its place. When a scan could not look at
something, it records a degradation. It does not report a clean result.

`ousast` is the interface. Model work over whole repositories runs on a separate agentic plane
(google/ax). A learned decision engine is in development. A scan needs neither of them.

This file is the front door. Each section links to its page of the documentation site (`docs/`,
`mkdocs.yml`; `uv sync --extra docs && uv run mkdocs serve`).

## Status

**v2.0.0, state as of 2026-10-02.** The pre-push safety net is **NO-GO** against every M4 gate.

- No hook capability is enabled.
- Two independent populations (case sets frozen before any scan) have been spent so far. Engine
  recall was 1 of 11 and then 0 of 17.
- The learned decision engine ranks but may not block. BLOCK is offered for no family.

The project has stopped trying to reach the gates by hand. Every detection change now has to win
a controlled measurement on held-out repositories. One page states all of this, with the record
behind each figure: [docs/where-we-stand.md](docs/where-we-stand.md). The release history is in
[RELEASE_NOTES.md](RELEASE_NOTES.md).

## Install and first scan

Pick the tier you need:

1. Tier 1: a deterministic scan of a checkout, or a CI gate.
2. Tier 2: the Joern engine (`standard`, `deep`).
3. Tier 3, for maintainers: model work over whole repositories on the plane.
4. Tier 4 does not exist yet.

### Tier 1: quick scan, no Docker

The core install depends only on PyYAML. From a checkout, `uv sync` (or `pip install .`) installs
the `ousast` entry point. `uv sync --group dev` adds the test and lint tools.

```bash
uv sync
uv run ousast scan /path/to/repo --mode quick
uv run ousast scan . --mode quick --fail-on verified   # CI: exit 1 on any evidence-verified finding
```

This runs the language-scoped pattern rules, entry-point reachability hints, ranking,
verification and scoring. It is deterministic and reproducible. It needs no network and no keys.

What it cannot do:

- There is no engine. Nothing follows a value across statements or files.
- The PHP quick rules are a low-precision, in-sample development set. Per-rule precision lower
  bounds run from 0.03 to 1.0 on the real pins
  (`benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json`).

The optional `semantic` extra (`uv sync --extra semantic`) installs the tree-sitter grammars for
the overlay.

### Tier 2: standard and deep scans (Docker)

`standard` and `deep` need Joern. The Docker image `openultrasast:dev` ships three things in one
image: the tool, Joern v4.0.625 and `php-cli` (the PHP frontend needs it). You build it locally
from the `Dockerfile`; there is no published image yet. It is big: a JRE plus about 2 GB of Joern.

The shell wrapper builds the image on first use. Then it runs `ousast` in the container. Your
directory is mounted read-only and the container network is off.

```bash
source /path/to/OpenUltraSAST/ops/shell/ousast.sh   # PowerShell: ops/shell/ousast.ps1
ousast scan . --mode standard                       # the graph decides; no model is asked
ousast-with-judge scan . --mode standard            # network on, the model is asked (DEEPSEEK_API_KEY)
```

`docker compose build` and `TARGET=/path/to/repo docker compose run --rm ousast scan /target` do
the same without the wrapper.

`deep` adds REGRESS. REGRESS runs each reproduction snippet with `docker run` from wherever the
scan runs. The engine container has no Docker socket. So run `deep` in one of two ways:

- from a host install with Joern on the PATH (`pyinfra @local ops/joern.py`, pinned and checksum-
  verified) and a working `docker`;
- or accept the recorded `sandbox_unavailable` degradation.

Details, including the host install, are in [ops/README.md](ops/README.md).

Keys and store settings live in `.env` in the working directory. The file is gitignored;
`.env.example` lists the names.

- `DEEPSEEK_API_KEY` serves every LLM call.
- `OPENROUTER_API_KEY` is used for embeddings only (`ousast learn memory embed`).
- `.env` never overrides a variable already exported in your shell. If a key change seems to have
  no effect, `unset` the stale export.
- The plane's memory store defaults to a local file store under `~/ousast-results/plane/memory`.
- An S3-compatible bucket is optional: `uv sync --extra s3`, then `OUSAST_MEMORY=s3://<bucket>`
  with `S3_ENDPOINT` and the AWS credentials in `.env`. Nothing in a scan needs it.

### Tier 3: the plane on ax (maintainers)

Tier 1 and 2 need none of this. Today's profile is a single-node kind cluster on the maintainer's
host.

- `ops/ax/up.sh` needs `docker`, `go`, `kubectl`, `kind`, `ko` and `ax` on the PATH. It refuses to
  start when one is missing.
- It builds Agent Substrate and ax from their checkouts under `~/.cache/ousast/ax-src/`.
- Measured idle footprint with two workers: the kind node takes 1.7 GiB of memory (27% of the
  7.7 GiB host) and 4.9 GB of disk for images. The build uses several GB more for Go caches.
- The worker pool is sized for that 7 GB host.
- The verify and roles tasks need `DEEPSEEK_API_KEY`.
- Memory lives in the local file store or the S3 store. RustFS is the tested server.

Bring-up, doctor and the smoke Run: [ops/ax/README.md](ops/ax/README.md).

### Tier 4: Kubernetes (k3s), planned

Nothing has been deployed to any cluster other than that kind cluster. The target is two profiles
of one code base: `kind` locally and `k3s` in production. The same `ousast plane run` would
submit a Run in a remote execution mode. It needs:

- a kubeconfig context or the cluster's ingress (and an `imagePullSecret` on the worker
  ServiceAccount for a private package);
- runner and engine images published to GHCR and pinned by digest;
- the S3 store as the artifact path, with no receiver on a laptop.

The plan, and the code changes it needs with file paths, are in
[docs/deployment.md](docs/deployment.md#production-topology-ax-on-a-kubernetes-cluster).

## Scan modes

There are three modes. Each adds to the one before.

- `quick` runs the pattern rules, hints, ranking, verification and score. It needs nothing.
- `standard` adds the MAP stage: complexity map, semantic overlay, authorization obligations and
  the Joern model layer. The model layer builds one code property graph per repository. It decides
  taint, guard-dominance and configuration questions on that graph. A model is asked only the
  residual question. Without a key, that question is skipped and only the graph's entailed
  findings are reported.
- `deep` adds REGRESS. Promoted candidates are loaded by a small snippet in a Docker sandbox. Each
  gets a `triggerable` or `not_triggerable` verdict.

A missing engine is a recorded degradation (`cpg_unavailable`, `sandbox_unavailable`), never a
clean result.

`--fail-on never|findings|verified|worth-fixing` sets the exit code. `--config openultrasast.toml`
loads settings. Every run writes these files under `<target>/.openultrasast/runs/<scan-id>/`:
`manifest.json`, `findings.json`, `verification.json`, `score.json`, `report.md`, `report.sarif`
and `trace/events.jsonl`.

`ousast pre-push` (experimental) analyses the commits a push would publish against their base.
Only new or worsened defects become candidates. It is advisory by default. Its capability registry
is empty, so it emits no normal alert today.

Flows and the per-language rule table: [docs/scanning.md](docs/scanning.md).

## How detection works

The tool uses three representations of code, from cheap to expensive:

1. Text: regex quick rules, one statement at a time.
2. Tree: the tree-sitter CST (concrete syntax tree) and an IR (intermediate representation) per
   function. The overlay and the obligations use it.
3. Graph: the Joern CPG. It is the only one that follows a value across statements, calls and
   files.

Taint runs as fact tables, queries and verdicts on the graph. Absence bugs are operations that
should have been guarded. They are found as obligations, dominance and configuration census. A
model answers only the residual question.

- [docs/detection-techniques.md](docs/detection-techniques.md) explains each technique, with the
  code it comes from and what it misses.
- [docs/architecture.md](docs/architecture.md) gives the stage order and the evidence ladder (a
  state machine, not a label a model may assign). It also covers the central CWE policy, the
  project score and the self-improving loops (`ousast improve`, with `--memory` for proposals from
  plane rows).

Quick rules cover C/C++, Python, JavaScript/TypeScript, Java with Groovy templates, and PHP. Each
rule runs only against files of its language.

The detection gate (`uv run python -m openultrasast.gate`) enforces at least 90% recall and under
10% false positives per language on the bundled cheat-sheet corpora. On this tree it reports
93.62% recall (44/47) and 0.0% false positives. Those corpora show that a rule change did not
break a known detection. They are not a recall estimate on real code, and PHP is not in the gate.

Framework knowledge (WordPress, Flask, Django, Express, Spring) is tagged as an optional prior in
`src/openultrasast/ruleset/frameworks.toml`. So its contribution can be measured and switched off.

## The plane on ax

Model-driven work over whole repositories runs as a Run manifest. A Run is a DAG of ax Tasks. Each
Task runs in its own gVisor actor (an isolated sandbox) on Agent Substrate. ax is the only agentic
executor; there is no local subprocess path.

- Each Task binds at most one Model and its own `usd`/`calls` budget.
- Egress is deny-by-default per Task, by hostname only.
- The provider key travels only in the Task's start request, never in a manifest or an image.

Measured on the first increment: the plane agreed on 16 of 20 declared sites at $0.0205 per
candidate.

```bash
uv run ousast plane doctor                               # kind, Agent Substrate, ax controller, runner image
uv run ousast plane run plane/runs/validation-46.yaml    # a rerun skips tasks already done; --workers bounds tasks in flight
uv run ousast plane status validation-46                 # per-task status and the token attribution table
uv run ousast plane remember validation-46               # ingest the run's rows into the memory store
```

`workspaces`, `harvest`, `alerts-engine` and `memory-normalise` generate Runs, their inputs and
the store's rewrites. The flow and the task catalogue: [docs/plane.md](docs/plane.md). What runs
where today, and what a separate cluster would take: [docs/deployment.md](docs/deployment.md).

HarnessX, the earlier agentic extra, was retired 2026-09-30. A `[harnessx]` section is ignored
with one warning. `[models] verifier`, `[fusion] panel_model` and `[fusion] decider_model` fail and
name the plane replacement. Config keys that nothing ever read fail the same way. Fusion is
deterministic.

## Memory

One store holds what plane runs and the decision engine learned. It is keyed by repository and pin.
It holds two kinds of data:

- rows: facts, verdicts, unit costs, alerts, coverage and feature records;
- content-addressed blobs: excerpts, embeddings, cached responses and compiled programs.

`OUSAST_MEMORY` selects the backend. It is either a local file store or `s3://<bucket>` on any
S3-compatible server. The S3 server must support versioning, lifecycle rules, object tags and S3
Select. RustFS is the tested server.

An admin sets the bucket up once. The store verifies it at every start. If anything is missing, it
refuses to run and names each missing piece. It does not fall back.

- Layout and the read and write paths: [docs/memory.md](docs/memory.md).
- The bucket policy and admin steps: [docs/rustfs.md](docs/rustfs.md).
- How stored rows are meant to turn into better decisions:
  [docs/memory-and-detection.md](docs/memory-and-detection.md).

## Decision engine and evaluation

A learned decision engine is being built. It is meant to replace hand-tuned detection edits. It
follows three rules:

- Every instrument produces signals, never verdicts.
- Labels come from ground truth only.
- A compiled AI classifier with local memory turns retrieved similar cases and the candidate's
  signals into a calibrated probability. It has BLOCK and ADVISORY operating points.

It is **in development, not adopted**. No scan, pre-push check or report uses it.

It was measured on six families, on repositories the compiled program was not shown:

- The pooled AUC (area under the ROC curve) of its score runs from 0.77 (injection) to 0.96
  (access control).
- The stricter within-pair AUC is 0.72 to 0.93 across the same families.
- BLOCK is offered for no family
  (`benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`).

Maintainer surface: `ousast learn labels|memory|compile|evaluate|curve|experiment|audit-leaks`.
Design, slices and the A/B protocol: [docs/decision-engine.md](docs/decision-engine.md).

[docs/evaluation.md](docs/evaluation.md) explains how anything is measured on code the tool was not
tuned on. It covers the pair corpora, the independent populations and the M4 gates. It also covers
the fold discipline that keeps learned decisions out of their own training data. Population v3
(PHP, 15 cases) is frozen as the one-time final check. Nothing in the tree may read it.

```bash
uv run ousast benchmark benchmarks/manifests/python-vulnerable.toml --mode quick
uv run ousast pairs --slice sast                     # fire on the vulnerable side, stay silent on the fix
uv run python -m openultrasast.pair_gate             # CI: local pairs must all pass
uv run ousast improve benchmarks/manifests/java-spring-boot-vulnerable.toml --dry-run --memory
```

## Token economics

Model tokens are the one running cost. At runtime the plane routes them:

- one Model and one budget per Task;
- a metered client that refuses the next call at the ceiling;
- repository facts computed without a model and reused;
- blobs replayed at $0, with no new model call;
- triage before the hunt;
- a tie-break only on disputed candidates.

In development, 85.5% of the maintainers' coding-session tokens were tool input and output rather
than reasoning. That is down from 90%. The remedies in `benchmarks/dev/` target that share.
Mechanisms, the measured costs and the before-and-after table:
[docs/token-ergonomics.md](docs/token-ergonomics.md).

## Examples, threat model

- End-to-end walkthroughs, from a quick scan to an MCP client: [docs/examples.md](docs/examples.md).
- What the tool trusts and what it does not: [docs/threat-model.md](docs/threat-model.md). This
  covers scanned code as untrusted input, secret redaction, per-task egress, budgets and the
  `deep` sandbox.

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
there are two project skills in `.agents/skills/`:

- `openultrasast-scan`: modes and their prerequisites, `--fail-on`, the evidence ladder, recorded
  degradations and run artifacts.
- `openultrasast-triage`: false-positive reasons, what an adjudication may feed, and fixing and
  re-scanning.

`ousast mcp` runs a narrow MCP (Model Context Protocol) server over stdio. It has ten tools:
`openultrasast.scan`, `status`, `findings`, `get_finding`, `evidence`, `artifacts`, `benchmark`,
`explain`, `propose_patch` and `export_report`. No tool runs a shell, Docker or a free-form
command.

```jsonc
{ "command": "uv", "args": ["run", "ousast", "mcp"] }
```

The `kiro-*` skills, `AGENTS.md` and the Kiro-style specifications under `.kiro/` are the
maintainer's development tooling. Users can ignore them. Other maintainer commands:

- `ousast repos`: pinned known-vulnerable checkouts.
- `ousast model candidates`: what the candidate enumerator can reach.

## Licence

OpenUltraSAST is licensed under the [Apache License 2.0](LICENSE). Third-party material keeps its
own terms:

- Joern (Apache-2.0) is downloaded at image build time.
- The tree-sitter wheels of the `semantic` extra are MIT.
- The published benchmark cases were licence-checked one by one. v1's OpenCVE case is BUSL-1.1, see [RELEASE_NOTES.md](RELEASE_NOTES.md).
