# Search feasibility tools

Run these host-side tools from the repository root. Selection and executor smoke
make no model calls; the pilot driver calls the configured model unless `--dry-run`
is specified.

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


## One-sided pilot driver (task 6.2)

The shared virtualenv may be installed against another worktree; `PYTHONPATH`
below explicitly selects this worktree's source.

Offline probe, using a scripted model and in-process repository executor with real
host verification (no network or provider calls):

```sh
PYTHONPATH="$PWD/src" /home/mc/Source/OpenUltraSAST/.venv/bin/python -m benchmarks.search.pilot_run \
  --dry-run --side vulnerable --pairs 0 --ceiling-usd 0.50 \
  --out /tmp/search-pilot-dry.jsonl
```

For three **live** searches, after the oracle infrastructure probe and budget
approval, set `SEARCH_TASK_IMAGE` to the tested search image's complete
`REGISTRY/IMAGE@sha256:DIGEST` reference, then run:

```sh
PYTHONPATH="$PWD/src" /home/mc/Source/OpenUltraSAST/.venv/bin/python -m benchmarks.search.pilot_run \
  --manifest benchmarks/search/private/pilot.json \
  --side vulnerable --pairs 0,1,2 --ceiling-usd 1.50 \
  --verify-lane vm --image "${SEARCH_TASK_IMAGE:?Set the tested digest-pinned search image}" \
  --out benchmarks/measurements/2026-10-05-search-pilot-vulnerable.jsonl
```

This command spends money and contacts AX and the store. The ceiling shown is an
example for the three $0.50 searches, not evidence that a live run was approved or
performed. Use a fresh output path; output files are never overwritten.

The existing DeepSeek key/base URL environment variables and provider model/prices
are reused (`deepseek-flash` by default). `.env` does not override exported values.
Retries are disabled. Unknown models require both `--usd-per-mtok-in` and
`--usd-per-mtok-out`. Every call reserves its conservative input-token bound plus
`--max-tokens` output allowance against the task allowance and shared run ceiling;
failed calls and calls with missing usage settle the maximum. Reservations in the
record are cumulative admitted maxima, not outstanding spend. Their sum can exceed
the ceiling when usage settlements release unused allowances. Settled spend remains
bounded by the run ceiling and $0.50/search. Search defaults also cap reason rounds
at 4, intents at 3 per round, explore at 15 minutes including acquisition, and demos
at 3. Physical AX submissions and coordinator steps have separate 32-task caps.

The board defaults to a private local FileStore under a fresh directory in
`benchmarks/search/private/runs/`; `--board-memory` selects another board store URI.
The AX mailbox still requires the existing `OUSAST_MEMORY=s3://bucket/prefix`, public
HTTPS `S3_ENDPOINT`, and host store credentials. Board storage does not replace the
mailbox. Executors receive only presigned object URLs. The brain runs on the VM;
repository tools and build/export run in key-free AX executors. VM verification
requires working user namespaces and consumes executor-built archives. `--verify-lane
ax` switches to the existing dispatcher, with three fresh verifier tasks per side
and no executor holding a worker slot during those repetitions.

Each selected index produces a JSON line followed by one run summary: Req 3.4
outcome, reserved/settled spend, calls, tokens, physical tasks, coordinator steps,
phase timings, failure codes, input bytes, board bytes, end reason, and hashed
repository/revision identities. The private board and checkouts contain identity-bearing
data. The public JSONL omits raw model/executor diagnostics. Selection advantages
are explicit in the summary; this is feasibility evidence, not BLOCK qualification.

A fixed invocation creates a fresh board/demo and retains only the fixed revision.
Its verifier runs two independent sets of repetitions on that same fixed revision;
no vulnerable checkout or previously generated vulnerable demo is passed in.
`fixed_effect_observed` reports a consistent owned effect on the first three fixed
runs (`null` when unavailable or inconsistent). Such an effect requires adjudication;
it is not promoted to a differential `demonstrated` outcome. The normal safe probe
therefore ends `inconclusive`, never “not vulnerable”.

Generic `injection` needs an `oracle` value of `sql` or `command` in the private
manifest; without a subtype verification returns `no_oracle`. No subtype is guessed
from repository names. The selected manifest's pair 1 currently lacks this metadata.
Live transport, provider authentication/cost, real project buildability, and AX
oracle operation must still be measured; an offline probe cannot establish them.
