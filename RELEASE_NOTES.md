# Unreleased

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
