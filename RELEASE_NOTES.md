# v2.0.1 (2026-10-02)

v2.0.0 was tagged but never published: its release job stopped at the format check (see below). v2.0.1 is
the first published 2.x release and carries everything listed under v2.0.0 plus the following.

- **Licence: Apache-2.0.** `LICENSE` added; `pyproject.toml` declares `license = "Apache-2.0"`; both images
  carry the `org.opencontainers.image.licenses` label.
- **Container images on GHCR.** Each version tag pushes `ghcr.io/norandom/openultrasast` (the scan image:
  Joern and php-cli) and `ghcr.io/norandom/openultrasast-runner` (the plane's task runner), tagged with the
  version and, for full releases, `latest`. The digests are in the release job's summary; pin by digest
  (Agent Substrate rejects tags).
- **CI green again.** CI and the release job check formatting and lint over the whole repository; eight
  benchmark scripts had drifted. They were reformatted (two `noqa` comments, one renamed loop variable; no
  script computes anything differently), and the local gate now runs the same whole-tree commands.
- **Front-door README.** Install in four tiers (quick scan without Docker; standard and deep with the scan
  image; the plane on kind; Kubernetes on k3s, planned), every claim checked against the CLI, and links to
  every documentation page.

## Also in this release (previously listed as Unreleased)

- **Documentation audited against v2.0.0** (no behaviour change). New `docs/deployment.md`: where the plane runs
  today, this host's setup, and step-by-step guidance for a separate Kubernetes cluster with what is implemented
  and what is planned; no cluster deployment has been made, and the kube context (`kind-$KIND_CLUSTER_NAME`) and
  `doctor`'s registry check (`localhost:5001`) are still hard-coded. The decision-engine pages state slice 2
  (six families, `benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json`: pooled AUC 0.77-0.96,
  within-pair 0.72-0.93, BLOCK offered nowhere, canary below 0.9 for three families) and that the engine is not
  adopted. The model layer's residual question is documented at `model/pipeline.py` (`model/judge.py` was
  deleted); a missing provider key is described as it behaves (no question asked, entailed findings reported),
  not as a recorded degradation. The `.env` reference lists the memory-store variables; `ousast plane memory-normalise` is listed.
- **Removed: the unused vector index, `ousast index` and `[embeddings]`** (legacy cleanup, 2026-10-02). `index.py`
  keeps only the text chunker the skill router uses; the `VectorIndex` half had no caller, and nothing read the
  `chunks.json` the subcommand wrote. `[embeddings] model`/`store` fail to load with the reason, like the other
  retired keys; `OPENROUTER_EMBEDDING_MODEL` is no longer read (`ousast learn memory embed --model` names the model).
- **Retired three config keys nothing read** (2026-10-02): `[sandbox] network`, `[sandbox] workspace_readonly` and
  `[complexity] top_k` now fail to load naming why. The sandbox always ran with `--network none` and a read-only
  workspace regardless of the first two; no stage read `top_k`. `memory_mb`, `timeout_seconds`, `pids_limit` and
  `max_hunter_hotspots` are read and stay.

# v2.0.0 (2026-10-02)

A new major release: the agentic plane runs on google/ax, HarnessX is gone, detection decisions move
toward a trained-by-memory AI classifier, and the plane memory lives in an S3-compatible store.

- **Agentic plane on ax** (`ousast plane run|status|doctor|workspaces|remember|alerts-engine|harvest`): tasks
  run in gVisor sandboxes on Agent Substrate; one Model and one budget per task; token attribution per task
  and model; credentials only in the start request; per-task egress policies. First increment measured:
  16/20 declared sites agreed at $0.0205 per candidate (`benchmarks/independent/plane-increment-2.json`).
- **HarnessX removed.** Retired config keys fail with a reason; `[harnessx]` warns. Deterministic outputs
  proven byte-identical (`benchmarks/measurements/2026-09-30-harnessx-removal-equality/`).
- **Memory store** (`OUSAST_MEMORY`): local files or any S3-compatible store with versioning, lifecycle,
  tags and S3 Select; RustFS is the tested server (`docs/rustfs.md`). The store verifies its bucket at
  startup and never falls back; every row carries its kind's queryable fields. New extra `s3` (boto3).
- **Decision engine (in development, not adopted):** an in-house DSPy-style AI classifier with local
  memory; labels from ground truth; repository-grouped evaluation. Slice 2 on six families: out-of-repo
  AUC 0.77-0.96 (within-pair 0.72-0.93); BLOCK not offered anywhere; see
  `benchmarks/measurements/2026-10-02-decision-engine-slice-2/record.json` and `docs/memory-and-detection.md`.
- **Improvement from memory:** `ousast improve --memory`; the loop as a plane Run.
- **PHP quick-mode rules** (in-sample measurement only) beside the Joern engine; framework knowledge
  tagged as optional priors (`ruleset/frameworks.toml`).
- **Populations:** v3 (PHP, 15 cases) frozen and untouched as the one-time final check; 97 advisory-fix
  pairs added for negatives; licences of published cases verified (v1's OpenCVE case is BUSL-1.1).
- **Removed legacy:** dead modules (`model.judge`, `model.execution`, `model.calibrate`,
  `stage_processors`, `slot_contract`); unread config keys `[dynamic]`, `[evidence]`, `[variants]`,
  `[models] patcher` retired (`resolved_config.json` loses those sections); reference-only scripts under
  `benchmarks/archive/`; the module audit now classifies by real imports.
- **Docs:** MkDocs site (`mkdocs serve`), including token ergonomics and the RustFS setup.

Detailed notes for this release follow.

## PHP quick-mode rules (2026-09-30)

`ruleset/php/rules.toml` adds 18 PHP rules (SQL injection, command injection, file inclusion,
path, open redirect, SSRF; code eval, unserialize and echo XSS as `shadow`). They were written
on the development corpus, so their numbers are in-sample only
(`benchmarks/measurements/2026-09-30-php-quick-rules/measurement.json`); PHP is not part of
the detection gate. `ousast plane alerts-engine` produces a Run's `alerts` for PHP from the
Joern engine image on the host.

## Framework knowledge as optional priors (2026-09-30)

Rule and taint-fact entries that know a framework or library carry a `framework`/`library`
tag naming a row of `ruleset/frameworks.toml`; the loaders take `priors` (`"all"` by default,
unchanged behaviour; `"off"`; or a set of ids). Scan output is unchanged.

## Decision engine, in development (2026-10-01)

The learned decision engine (signals from every instrument, labels from ground truth, an AI
classifier with local memory compiled in house) is in development and **not adopted**: no scan,
pre-push check or report uses it. New maintainer commands: `ousast learn labels|memory|compile|
evaluate|curve|audit-leaks` and `ousast plane harvest`; new plane tasks `features` and `roles`;
the `advisory-fixes` pair source (97 advisory fix commits). First slice (injection, 110
out-of-repository candidates): ADVISORY recall 0.90, precision 0.54, BLOCK not offered
(`benchmarks/measurements/2026-10-01-decision-engine-injection-slice/record.json`;
[docs/decision-engine.md](docs/decision-engine.md)).

## Documentation (2026-10-02)

The README is reduced to user-facing material; scan internals moved to
[docs/architecture.md](docs/architecture.md) and measured results to
[docs/evaluation.md](docs/evaluation.md). Removed references to commands that no longer exist
(`ousast mechanisms export`, `ousast pairs --loo`) and corrected the description of `deep`
mode, which runs sandboxed regression snippets when Docker is available.
## Unread config keys retired (2026-10-02)
These keys loaded but nothing ever read them. They now fail with `RetiredConfigError` (the
CLI prints it and exits 2), naming why. Remove them from your config:
- `[models] patcher`: no patching stage calls a model.
- `[dynamic] enabled`, `[dynamic] network_scope`: no dynamic or deep tier exists yet.
- `[evidence] minimum_report_verified`, `minimum_exploit`, `minimum_patch`: evidence tiers
  come from the program model's ladder, not from configuration.
- `[variants] enabled`, `[variants] max_mechanisms`: the variant search they configured was
  deleted earlier.
**Output shape.** `resolved_config.json` no longer has the `dynamic`, `evidence` and
`variants` sections or `models.patcher`. `harness.json` keeps its shape:
`model_roles.patcher` is always `null`, like `model_roles.verifier`.

## HarnessX removed; the ax plane is the agentic path (2026-09-30)

HarnessX, the optional agentic extra (`openultrasast[harnessx]`), is removed with its code,
packaging extra and lock entries (retired 2026-09-30). Agentic work runs on the ax plane:
`ousast plane run|status|doctor|remember`, with one Model and one `usd`/`calls` budget per
task, deny-by-default egress per task, and the provider key sent only in the task's start
request. See [ops/ax/README.md](ops/ax/README.md). Deterministic outputs (pair replay,
quick benchmark, standard scan, `improve --dry-run`) are byte-identical before and after.

Retired config keys (retired 2026-09-30):

- `[models] verifier` fails with `RetiredConfigError` (the CLI prints it and exits 2): LLM
  verification runs on the plane (`verify` + `agree`). Remove the key.
- `[fusion] panel_model` and `[fusion] decider_model` fail the same way: fusion is
  deterministic; independent LLM agreement is the plane's `agree` task. Remove the keys.
- A `[harnessx]` section (retired 2026-09-30) loads with one warning naming the plane and is
  otherwise ignored.

**Silent change for `[models] hunter`.** If you set `[models] hunter` and had the extra
installed, a standard scan ran two LLM hunters: the MAP-stage tool hunter and the
HarnessX hunter pool (findings with ids `hx-hunter:<path>:<line>`). The key is still
valid and still enables the tool hunter, so nothing fails and nothing warns, but the
second hunter's findings no longer appear. Repository-wide LLM hunting runs on the plane
(`verify` passes and `agree`).

The LLM judge, the LLM fusion panels and the in-loop hosting of deterministic stages are
retired without a local replacement. `ousast improve --memory` now proposes rule-status
edits from the plane memory, through the unchanged validator and gate.

# v1.2.0-alpha.1

Experimental pre-push security safety net for AI-accelerated development. Python package
version: `1.2.0a1`. This alpha is **not a rollout GO**; no real hook capability is enabled.

- Analyze immutable pushed commits across refs without changing the working tree or
  replacing existing hooks. Share one deadline across preparation, analysis and reporting.
- Keep the existing ranker responsible for scope and physically exclude vendor code from
  graph inputs. Reuse only compatible, complete immutable graph and answer artifacts.
- Gate advisory and blocking alerts on the same actionable change/witness/repair evidence.
  Preserve explicit incomplete coverage; optional model assistance cannot create evidence.
- Add frozen runtime and PHP/Node/Python evaluation records with honest populations,
  missing-target accounting and versioned eligibility that rejects stale evidence.
- Repair the pinned JavaScript frontend's Gruntfile omission and incomplete-census handling.
  The real NodeGoat input now retains 44/44 files; native PHP/JavaScript smoke passes.

Implementation verification: 1321 tests passed, nine skipped; detector/map/local-pair
gates and packaged partition smoke passed. These checks verify implementation contracts,
not useful hook precision, recall or latency.

Rollout remains blocked by representative changed-code latency/completion, VAmPI
query/context/transitive evidence and independent reviewed per-capability populations.
The earlier eligibility artifact is stale under the repaired identities and enables
nothing. See [current spec status](https://github.com/norandom/OpenUltraSAST/blob/v1.2.0-alpha.1/.kiro/specs/pre-push-safety-net/status.md) for the
owners, unchanged thresholds and required revalidation. Pre-push implementation stands
at 26/27 tasks; task 8.3 remains blocked. C arithmetic/bounds detection is unsupported.
