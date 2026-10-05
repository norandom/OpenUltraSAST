# Search feasibility tools

These host-side tools make no model calls. Run them from the repository root.

## Executor smoke

```sh
python -m benchmarks.search.executor_smoke \
  --lane ax --image REGISTRY/IMAGE@sha256:DIGEST \
  --repo-url https://github.com/OWNER/REPOSITORY --commit FULL_SHA \
  --out /tmp/executor-smoke.json
```

`--lane docker` uses the same object-store mailbox and an already available local
image (`--pull never`). Both lanes need the existing batch transport's S3 store
configuration; credentials stay on the host. Running this command contacts the
store and task runner; the task fetches a shallow HTTPS checkout and installs
dependencies. Offline unit tests replace those network operations with a fake lane.

One managed executor receives clone, list, read, grep, install, trivial run, and
stop commands. Acquisition uses `git init` plus a depth-one fetch of the exact
commit, retrying initial egress failures for up to 60 seconds. Install recipes are
fixed and chosen from root pip/npm/composer/Maven manifests. Caches, temporary
files, and pip products live under `/workspace`. A repository without a recognised
manifest produces an instrument failure. If no README exists, the smoke reads
another listed file and records its size to establish that input was opened.

The JSON record holds per-command executor and round-trip wall times, exit codes
(null for file tools), observed output sizes, and sampled allocated workspace
peak, including unlinked command logs. Samples are not an instantaneous disk
quota. Output text and presigned URLs are omitted. Zero clone files, a successful
install with no output in under one second, command failure, missing runtime
output, and cleanup errors produce `instrument_failure` and CLI exit 1. Context
cleanup attempts task deletion and removal of mailbox objects on failure as well
as success.

## Pilot selection

```sh
python -m benchmarks.search.pilot_select --seed 20261005
```

Selection uses development catalog metadata only; it performs no downloads or
model calls. It excludes unseen reservations and used sets, validates usage
ledgers, and runs the existing reserved-repository guard as a black box. Additional
local unseen metadata/ledgers can be supplied with `--exclude` and `--ledger`.
Use `--cache` to inspect matching local checkouts for manifest/test-suite evidence;
the default cache is `~/.cache/openultrasast/repos`. Cached metadata affects
preference only and does not establish that the pinned revision builds.
The selector never opens population v3 files itself.

The default identity-bearing manifest is
`benchmarks/search/private/pilot.json`, explicitly gitignored. The summary is
`benchmarks/measurements/2026-10-05-search-pilot-selection/record.json`; it contains
counts, selection biases, input instrumentation, and digests only. Neither output
is overwritten. A successful selection is feasibility input, not evidence of
buildability, oracle operation, unseen performance, or BLOCK eligibility.
