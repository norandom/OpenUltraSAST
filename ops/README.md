# ops

Infrastructure for the optional engines. Nothing here is a project dependency: the core install is
`dependencies = []` and every engine below degrades to a recorded reason when it is absent.

## Use it as a command

Source the wrapper once and Docker stops being something you think about:

```bash
# ~/.bashrc or ~/.zshrc
source /path/to/OpenUltraSAST/ops/shell/ousast.sh
```

```powershell
# $PROFILE
. C:\path\to\OpenUltraSAST\ops\shell\ousast.ps1
```

Then, from any directory:

```bash
ousast scan .
ousast scan src/api
ousast-with-judge scan .     # opt into the LLM judge: needs network and a key
```

The wrapper rewrites paths under your working directory to their mounted equivalents, so `src/api` means what
you expect. Anything outside the mount is passed through unchanged with a warning rather than silently
rewritten into a path the container cannot see. Your directory is mounted **read-only**; findings go to
`./.ousast`, the one writable mount. The image builds itself on first use and says so.

If `joern-parse` is already on your PATH and a local venv exists, the wrapper uses those instead — someone who
installed the engine deliberately should not be quietly routed through a container. Set
`OUSAST_PREFER_NATIVE=0` to always containerise.

## Two ways to get the engine

**Docker (recommended for contributors).** The tool and Joern ship in one image, so nothing is installed on
the host and there is no container-to-container call, no docker socket, and no host/container path
translation:

```bash
docker compose build
TARGET=/path/to/repo docker compose run --rm ousast scan /target
```

The target is mounted read-only; `/work` is a tmpfs so CPG scratch never outlives the run. The LLM endpoint
is optional and passed through the environment, never baked into a layer — without it the model layer still
entails and only the `suspicion` band goes unasked. `network_mode` defaults to `none`; set it to `bridge`
only when you want the judge.

**pyinfra (for a persistent host install).** Same engine, same pin, same checksum, but on the machine:

```bash
uv pip install pyinfra              # tooling only
pyinfra @local ops/joern.py         # this machine
```

Pin the version and its checksum in an inventory rather than editing the deploy:

```python
# inventory.py
hosts = [("@local", {"joern_version": "v4.0.625", "joern_prefix": "/opt/joern"})]
```

The checksum needs no inventory entry: the deploy fetches the `.sha512` upstream publishes beside the
archive and runs `sha512sum -c` against it, before unpacking. (pyinfra's `files.download` offers
sha384/sha256/sha1/md5 but not sha512, which is what Joern publishes — so verification is an explicit
shell step rather than a download argument.)
The upstream checksum's `target/` path prefix is removed to match the local download path;
the digest remains unchanged and a mismatch still stops installation.

Verify an image locally after building it (no model endpoint or network is needed for the smoke):

```bash
docker run --rm --network none --memory 3g --entrypoint python \
  -v "$PWD/ops/smoke_engine.py:/smoke_engine.py:ro" \
  openultrasast:dev /smoke_engine.py > engine-smoke.json
```

This checks native PHP source/parser readability, installed PHP and JavaScript frontends, saved
dataflow overlays, graph census and exact source-node witnesses, and explicit refusal of an unreadable
PHP file. It prints JSON only after all checks pass; a failed build/query raises an error with a nonzero
exit. Versions, source hashes/byte counts and timings describe this small runtime smoke, not detection
quality or a pre-push latency guarantee. Keep the image's default non-root user for the permission test.

To exercise the same smoke through one shared backend deadline, add
`-e OUSAST_ENGINE_SMOKE_BUDGET_SECONDS=900` to the Docker command. Both language builds and
all census/witness queries consume that same budget. The generous smoke allowance verifies
runtime integration; it does not represent the hook's target latency.

`ops/smoke_scope.py` exercises the generic driver with real PHP and JavaScript graphs,
explicit evidence ranking and two declared entry regions per language. Run it with the
same Docker command, substituting `smoke_scope.py` for `smoke_engine.py`. It verifies
that the lower static-ranked risky function is selected, that the harmless function is
recorded as deferred, and that selected IDs match completed query outcomes and per-family
coverage. It uses one 900-second lab budget; it is not a mapper or hook-quality evaluation.

`ops/smoke_context.py` uses the same invocation with its own filename. It creates local
PHP/JavaScript Git histories with a removed caller guard and an unchanged helper-file sink, then feeds
immutable snapshot change evidence into the real driver. It checks affected-question
relationships, a controlled witness and preservation of the dirty checkout. Its lexical
change attribution does not prove that the removed guard enforced security or that the
finding is new; comparison and admission are separate stages.

`ops/smoke_context_boundaries.py` is the production-query negative regression using
the same invocation. Unknown consumers of a framework source, nested sink, or sanitizer
name must retain unresolved context rather than become tier-zero exclusions. Direct
modeled sink and sanitizer calls remain positive controls for the boundary projection.

Why this exists: Joern was first installed here by hand with `curl` and `unzip`, which is fine once and
unreproducible thereafter. The engine decides whether a finding is a `suspicion` or a `model_entailed`, and
every ceiling number in `benchmarks/measurements` is only comparable against a fixed version — so the version
is pinned, the download is checksum-verified, and a re-run with a matching stamp is a no-op.

It installs an engine; it does not become one. No sandbox, no container, no service. `openultrasast.cpg.backend`
reaches Joern by subprocess and this changes nothing about that.

## What we actually use from Joern

A small, deliberately narrow surface — worth stating, because it is what determines whether a given Joern
version works for us:

| entry point | use |
|---|---|
| `joern-parse <src> --output cpg.bin` | build the CPG |
| `joern --script q.sc --param k=v` | run a shipped CPGQL query, JSON fenced on stdout |

CPGQL steps, all of them in `src/openultrasast/cpg/queries/*.sc`:

| step | why |
|---|---|
| `cpg.call` / `cpg.method` / `cpg.identifier` | locate sinks, operations, sources |
| `.reachableByFlows` | the interprocedural dataflow the flat IR could not do |
| `.argument`, `.argumentIndexGt(0)` | arity and the safe-shape test — index 0 is the receiver, named args are −1 |
| `.ast.isLiteral` | constant abstraction; a keyword argument is assignment-shaped so the literal sits in its subtree |
| `.dominatedBy`, `.controlledBy` | guard dominance for absence bugs; `controlledBy` is what catches a check that runs *after* the fetch |
| `.controlStructure.condition` | identity branches |
| `.method.filename` / `.lineNumber` / `.lineNumberEnd` | closure scoping by line-range containment |
| `.methodFullName` | resolved sink matching |
| `ujson` | the fenced JSON payload |

No Joern server mode, no workspace/project management, no `joern-scan`, no overlays beyond the defaults.

## Languages

Joern ships frontends for C/C++, Java (source and bytecode), JavaScript/TypeScript, Python, Kotlin, Go, C#,
PHP, ABAP and Ghidra binaries. We currently model **python, javascript, java, c**.

**PHP works but needs a PHP interpreter**: `php2cpg` drives PHP-Parser and shells out to `php`, so on a host
without it a PHP tree fails to build with an opaque "Process exited with code 1". Set `php_frontend: True` in
the inventory to install `php-cli` alongside the JVM.

## Snapshot preparation smoke

After building the image, exercise immutable Git comparisons and isolated source
materialization without network access:

```bash
docker run --rm -i --network none --entrypoint python openultrasast:dev - < ops/smoke_snapshot.py
```

The smoke reads committed PHP/JavaScript bytes from a dirty, non-HEAD checkout,
checks rename/deletion and declared configuration context, and verifies scratch
cleanup and unchanged live state. Its JSON reports snapshot preparation only;
it does not run the detector, install a hook, or establish hook latency.

## Vendor and frontend partition smoke

After rebuilding the image, inspect real PHP and JavaScript graphs from one mixed
source tree:

```bash
docker run --rm -i --network none --entrypoint python openultrasast:dev - < ops/smoke_partitions.py
```

The script reads each fixture before measurement, then checks graph file and method
nodes: declared vendor code is absent, first-party source and tests remain, and an
unsupported Go partition is reported explicitly. One ranker decision and one region
limit cover both supported frontends. The shared 900-second budget is a lab allowance;
this check establishes neither production hook latency nor framework admission.

Stock Joern 4.0.625 fails the retention check: the projected test file is readable
but absent from the graph. The approved source adaptation fixes both test filters;
see `frontend-retention/README.md` for build pins and inclusion policy, and
`benchmarks/measurements/2026-09-13-frontend-retention-smoke.json` for passing
foundation verification. The earlier failing evidence remains in
`benchmarks/measurements/2026-09-13-partition-retention-blocker.json`.

Setting `OUSAST_SMOKE_INCLUDE_TESTS=0` in the container explicitly disables the
backend inclusion policy; that negative control must fail the retention assertion.
The expanded task 3.4 smoke also verifies first-party browser-path retention and
unshipped test-path records. Runtime origin remains unspecified without declarations.

`ops/smoke_partition_census.py`, using the same container invocation, builds a small
readable Python graph and exercises the production taint, dominance and configuration
batch queries. Each must return the actual source filename in its census. This
checks query compilation and census transport, not security-property coverage.

## Targeted novelty comparison smoke

After rebuilding the image, run a declared JavaScript guard-removal comparison:

```bash
docker run --rm -i --network none --entrypoint python openultrasast:dev - --case guard < ops/smoke_delta.py
```

Use `--case movement` for unchanged JavaScript backlog shifted by comments, or
`--case connection` for a PHP input newly reaching an unchanged operation. Every
case verifies immutable base/head bytes, runs the existing driver and targeted
comparison under one 900-second lab budget, and checks that dirty checkout/index
state survives. Output contains an evidence JSON object followed by a completion
JSON object; success requires exit zero and `verified: true` in that final object.
These declared regions exercise comparison mechanics; full replay, normal alert
admission and hook latency are separate evaluation work.

`python ops/smoke_admission.py` reads the committed comparison measurement and
rechecks its actual engine answers through the current policy. With no evaluated
capabilities supplied, every candidate stays diagnostic and the result separates
`none` findings, `incomplete` coverage and `allow` disposition. This offline control
executes no new graph query and does not qualify any capability for normal alerts.

## Compact reporting integration

After rebuilding the image, exercise comparison → admission → artifact/report
using captured actual engine answers and explicitly synthetic eligibility controls:

```bash
docker run --rm -i --network none --entrypoint python openultrasast:dev - < ops/smoke_report.py
```

The control verifies full scan-record preservation, default diagnostic-only behavior,
a three-summary display cap that retains all five synthetic defects, and a write
failure that preserves blocking. It runs no new Joern query and admits no real
capability. The receipt records reporting duration separately from the captured
analysis timings.

Artifacts publish atomically from mode-0600 temporary files. The Linux writer runs
in a separate process bounded by the transaction deadline and its remaining report
allowance; a stalled writer is killed. A hard cancellation can leave a private
`.partial-` file, which is never the published artifact and cannot establish a
completed result. Serialization/write failure emits one notice without replacing
the finding, coverage or push decision.

## Explicit local replay

Task 5.1 adds `ousast pre-push REPOSITORY --base BASE --head HEAD --artifact OUTSIDE_REPOSITORY.json`.
Both revisions must already exist locally. The command records their resolved commit identities,
materializes tracked object bytes in private scratch storage, discovers regions through the existing
mapper, and runs the existing evidence ranker, arbiter, targeted base comparison and admission policy.
It installs no hook and requires no model endpoint. All real capabilities remain experimental and
ineligible for normal alerts until task 8.3; diagnostic candidates remain in the JSON artifact.

`--deadline` defaults to 30 seconds, `--cancellation-allowance` to 2 seconds, and `--max-regions`
to 500. Preparation, both revisions and reporting share that elapsed budget. `--mode blocking`
and `--incomplete-coverage block` explicitly select enforcement; default advisory exit zero means
allow, never complete analysis. This initial replay interface requires the artifact outside the
analyzed repository, including resolved symlink destinations, to preserve the live source and index.
Artifact failure cannot change the actual allow/block decision.

`ops/smoke_replay.py --case security|fixed` exercises a real controlled PHP change through this
production runner, without supplying hand-selected regions. Its default 900-second budget is a
separately labeled runtime laboratory check, not hook latency. `--deadline 30` exercises cancellation;
it does not demand a positive after an interrupted query. Run with the network-disabled packaged
image, mounting the smoke script read-only as for the other smoke scripts. Snapshot manifests
record verified immutable source bytes; full scan records retain exact selected/deferred questions,
raw answers, per-question gaps, change context and candidate dispositions.

Experimental replay can reuse compatible local preparation, graphs and query evidence:

```sh
ousast pre-push /path/to/repo --base BASE --head HEAD \
  --artifact /path/outside/repo/result.json \
  --cache-dir /path/outside/repo/private-cache
```

Omit `--cache-dir` for a cold control. The cache directory must be owned by the current
user, private (0700), and outside the analyzed repository. Its default payload/manifest
budget is 2 GiB (`PushConfig.cache_max_bytes` for API callers). Cache permission to reuse
is separate from alert eligibility: current admission is always applied. No hook is installed
by replay. Artifact timings record discovery, graph and query hits; identical-tip hits do
not establish representative changed-code latency. Corrupt, partial or incompatible entries
are misses, with remaining work constrained by the same push deadline.

### Experimental pre-push integration

The default capability registry is empty pending independent qualification. Installing
this interface does not make the project rollout-ready. Advisory is the default;
blocking and strict incomplete-coverage handling are separate explicit choices.

Put the installed `ousast` executable on the Git process's PATH. From this tool's
checkout, explicitly install into the desired repository:

```sh
ops/install-pre-push /absolute/path/to/repository
```

The installer resolves Git's effective hook directory (including `core.hooksPath`),
leaves that configuration untouched, and refuses to overwrite any existing hook.
For an existing hook, inspect it and explicitly move it aside **before** installation:

```sh
hook_dir=$(git -C /absolute/path/to/repository rev-parse --path-format=absolute --git-path hooks)
hook="$hook_dir/pre-push"
test ! -e "$hook.before-ousast" && test ! -L "$hook.before-ousast" && mv -- "$hook" "$hook.before-ousast"
ops/install-pre-push /absolute/path/to/repository
```

The wrapper chains that sibling hook with the exact remote arguments and original
stdin bytes, even when analysis blocks. A prior rejection always remains a rejection.
Only an explicitly chained hook executes project-owned hook code; analysis executes
no project code. The existing hook retains its own runtime, outside the safety-net
analysis deadline. Integration input retention is bounded to 1 MiB and the analysis
deadline; failure to retain complete input stops the integration rather than feeding
partial input to another consumer.

Artifacts default to `$XDG_CACHE_HOME/openultrasast/push` (or `~/.cache/openultrasast/push`).
Set `OUSAST_ARTIFACT_DIR` to an absolute directory outside the repository if needed.
`OUSAST_PUSH_DEADLINE` defaults to 30 seconds. `OUSAST_PUSH_MODE=blocking` opts into
blocking; `OUSAST_INCOMPLETE_COVERAGE=block` additionally blocks incomplete coverage
in that mode. These variables do not enable detector capabilities or model calls.
For a new branch, add an explicit `--comparison-base <local-ref>` to both command
branches of the installed wrapper if a suitable local base exists. Without it, a new
branch records missing-base coverage rather than silently selecting HEAD or fetching.
Direct stdin integration is `ousast pre-push . --artifact /outside/push.json
--remote "$1" "$2"`; explicit `--base` and `--head` replay remains available.

To remove, inspect the installed wrapper first. If it is unchanged, this guarded
recipe removes only the supplied wrapper and restores the previous hook:

```sh
hook_dir=$(git -C /absolute/path/to/repository rev-parse --path-format=absolute --git-path hooks)
hook="$hook_dir/pre-push"
if cmp -s ops/pre-push "$hook"; then
    rm -- "$hook"
    if test -e "$hook.before-ousast" || test -L "$hook.before-ousast"; then
        mv -n -- "$hook.before-ousast" "$hook"
    fi
else
    printf '%s\n' 'Wrapper differs: inspect and remove your integration changes manually.'
fi
```

Neither installation nor removal modifies source, the index, refs, or hook-path
configuration. Keep any prior hook backup until restoration is confirmed.
