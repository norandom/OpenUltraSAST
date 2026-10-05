# Unseen evaluation, group 1

The coordinator runs task 1.5 from the repository root:

```sh
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH=$PWD/src
python -m benchmarks.unseen.eligibility --s3-store s3:// --verify-tests --output benchmarks/measurements/2026-10-04-unseen-01-used-set/record.json
```

This is the networked command; implementation tests use fakes. It loads `.env` with
`openultrasast.config.load_dotenv` (exported values win), opens the local FileStore and
S3 MemoryStore through `openultrasast.plane.memory.open_store(..., read_only=True)`,
and uses `GH_TOKEN` for GitHub GET resolution. `s3://` selects `S3_BUCKET`; pass
`--s3-store s3://BUCKET/PREFIX` for a prefixed store and `--local-store file:///PATH`
for a different local store. Read-only S3 opening skips the normal write/Select probe;
collection uses LIST/GET only. Existing normal store opening is unchanged.

Pair catalogs/recipes include local pointer rows (`vendored = false`, including
`fix_repo`). Additional external manifests can be supplied with repeatable
`--pointer-manifest PATH`. Registered units in memory and experiment YAML are followed;
missing units with a registered digest fail. Plans without frozen units are not used data.
Experiment units identify repositories in `group`. Binary measurement artifacts are
read and counted; structured JSON, TOML and multi-document YAML are parsed strictly.

Each source records files/objects read, bytes read, repository-bearing rows (distinct
names per input), and distinct repository counts. The digest is SHA-256 of sorted,
normalized names joined with newlines. Source counts overlap. An empty source fails;
only after establishing it is empty may the coordinator pass `--known-empty LABEL`.
The output records that declaration. Missing/unreadable inputs still fail.

GitHub redirects add the requested and canonical names, plus parent/source fork
identities. Used names are also resolved so an old used name excludes a renamed
candidate. GitHub cannot enumerate all historical names: injected clients may supply
`former_names`; actual historical aliases come from used references and redirects.
A 404 for a historical/synthetic used identity retains its literal identity; other
API failures stop collection. Candidate resolution always fails closed on a 404.
`resolve(candidate, api)` and `rejection(resolution, used, selected_networks)` are
available to the later sourcing task. Names stay in memory; output contains only
counts, labels and SHA-256 digests. Output files are created exclusively, never overwritten.

`--verify-tests` runs the three group-1 test modules with both output streams discarded,
including the existing population guard. Only aggregate test counts and the exit code
enter the record; a failed test prevents the record. V3 paths are excluded before
eligibility reads; only the existing guard handles v3 inside its black-box test process.

Population reservations retain their existing sweep over `benchmarks/`, `src/`, and
`tests/`. Pool reservations also cover `plane/`. Each reservation exempts only its own
directory; population checks include all of `benchmarks/unseen/private/`. This preserves
the existing population behavior while adding pools (the hard rule for this increment).

All `pool-pN.toml` files require a matching `freeze-pN.json`; drafts use `draft-pN.toml`.
The freeze digest is SHA-256 of parsed public TOML encoded as UTF-8 JSON with sorted
keys, compact separators and `ensure_ascii=False`. Private entries must be represented
by opaque digests in that public manifest, as task 3.2 requires.

The ledger exposes `append(path, row)` and `read(path)`. Rows contain `slice`, `decision`
(an opaque decision or experiment label), `purpose`, ISO `date`, `result_digest`, and
`freeze_digest`. Appends lock and validate the existing chain, reject duplicates or a
changed freeze, and reject qualification of an informed slice for the same decision.
Keep the published final digest to authenticate history: the chain detects row edits,
but cannot independently prove that an entire history was not replaced or truncated.

## Sourcing and extraction (tasks 2.1–2.4)

The coordinator's networked task **2.5** is now:

```sh
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH=$PWD/src
python -m benchmarks.unseen.draft --root "$PWD" --s3-store s3:// --seed 20260601 \
  --cache /home/mc/ousast-results/plane/unseen-draft --max-hours 8
```

Export `GH_TOKEN` first, or supply it through the root `.env` (exported values win).
The same read-only local/S3 stores, `--pointer-manifest`, and explicit `--known-empty`
options as task 1.5 apply. Missing or unreadable sources fail. The used set is rebuilt
and canonicalized before candidate selection, including redirects and fork networks.
No population v3 file is opened and no guard/bisection is run by this command; that is
reserved for group 3. An existing draft is never overwritten.

The command writes `--cache/journal/draft-p1.toml` and
`--cache/journal/private-draft-p1.toml` only after all sourcing stages complete.
Both stay outside the repository, with mode 0600. The public-format file contains permissive entries
and, for every private entry, only an opaque ID, slice, private marker, and SHA-256
of canonical JSON containing its URL and ordered `[base, head]` pairs. Private entries
carry the complete records, including licences, in the private-format file.
Licensing is re-read through GitHub's licence endpoint **at the actual extracted
vulnerability replay head**; the candidate's earlier fix-parent classification is
provisional. An explicit SPDX declaration in the pinned file takes precedence over
the API's classification. Missing/unknown/compound licences remain private.

Three seeded slices each contain 100 repositories, one vulnerability range and twelve
ordinary changes per repository. Each ecosystem/post-cutoff stratum differs from its
proportional per-slice target by less than one repository. Post-cutoff candidates are
attempted first within each ecosystem. Below 300 eligible repositories the command
exits 1 with counts and does not write a partial draft or relax any selection bar.
The group-2 measured exit and label confirmation remain coordinator tasks 2.5/2.6;
passing implementation tests does not assert that 300 eligible repositories exist.

Clones and checkpoints default to `results_root()/unseen-draft` (normally
`~/ousast-results/plane/unseen-draft`), overridable by `--cache /outside/path`.
The cache cannot lie inside `--root`. One opaque, disposable clone exists at a time;
it is removed on success, rejection, or failure. `--filter=blob:none --no-checkout`
keeps the commit graph needed for temporal thirds, blame, and release-tag ancestry,
and fetches source blobs on demand. This is a **partial clone**, not a shallow history.
The 500 MiB disk cap is checked after Git commands, including lazy blob fetches;
one in-flight command can transiently exceed it before rejection and cleanup.
Git output is captured, never forwarded. Each repository must read a nonempty source
blob before extraction. Summary instrumentation includes source read operations and
actual bytes, clone count, cumulative/peak disk bytes, wall time, and logical API calls
and HTTP attempts. Zero source bytes or a failed Git read is an instrument failure,
not an eligibility drop. Stdout is a JSON summary of counts/digests only; no names or
URLs enter stdout or a measurement record. Raw per-change data stays in the external journal and manifests.

Extraction uses Git and syntax boundaries, with no scanner, engine, or model. Python
uses stdlib AST; Java/PHP/JS/TS use conservative named-function brace matching. Ambiguous
or unparseable functions can reject a candidate. The first removed code line per
fix-touched function is the SZZ sink proxy; pure-addition fixes use its declaration.
Normalized text absence, non-root/non-merge ancestry, file/line limits, and the OSV
release bracket are checked before accepting `introducing`. Matching tags are `VERSION`
or `vVERSION`; an absent/ambiguous tag or missing prior release cannot certify the
bracket. After at most five walk-backs, `last_touch` uses `git log -L` with the resolved
numeric function extent (also works where Git lacks a language-specific function driver).
Method, bias, fallback reasons, head function/range, files/hunks, family, advisory, and
cutoff flag are recorded. Task 2.6 must review every third `introducing` label.

All reviewed advisories are enumerated to exclude **all** known repository fixes from
ordinary changes, including old advisories and advisories outside the four candidate
ecosystems. Fix URLs are canonicalized before indexing so renames cannot hide them.
The ordinary filter uses only the design's narrowed security pattern. It counts
rejections (including oversized commits and repositories failing the 40-commit floor),
checks both sides for touches to known vulnerable functions, and inspects generated
headers and inherited `.gitattributes`. Sampling allocates twelve draws proportionally
across three history-time thirds and four source-size buckets, with one per third.

For offline tests, inject GitHub/OSV clients, the clone context, and `UsedSet` into
`draft.run`; HTTP transports and Git subprocess runners also accept fakes. Tests use
sanitized REST-shaped data and a temporary synthetic local Git history. No implementation
test contacts GitHub, OSV, a model, or a cluster. HTTP retries are bounded to five attempts;
rate-limit reset/Retry-After waits and transient 5xx backoff are tested with fake clocks
and sleepers. A stale candidate 404 is counted; other service failures fail the run.

### Checkpoint and resume

The command above uses journal directory
`/home/mc/ousast-results/plane/unseen-draft/journal`. Run the same command to resume.
`--max-hours` is a per-invocation budget; changing it does not invalidate checkpoints.
Create `journal/STOP` to stop between units, then remove it before resuming. A page,
repository resolution, candidate decision, or repository extraction already running
finishes first, so the time budget is not a hard timeout on a large repository.
Clean stops exit 0 with `status: stopped`; failures and shortfalls exit 1. Completion
exits 0 with `status: draft`. No partial manifest is published.

`inputs.json` binds the seed, source-labelled used-set digest, known-empty declarations,
clone cap, and design fingerprints (sourcing/extraction/eligibility/publication code and
family taxonomy). A mismatch refuses resume and prints only the changed parameter
labels. Use a new external cache for a deliberately changed design or population.
The used set is rebuilt each invocation; repository resolutions, including 404s, are
reused from the journal. Live GitHub metadata for unfinished units can still change;
completed pages and decisions are the durable sourcing snapshot.

Each completed unit is appended to its stage JSONL and fsynced before work advances:
`advisories.jsonl` (pages), `resolution.jsonl` (alias/fork metadata),
`eligibility.jsonl` (candidate decisions), `extraction.jsonl` (repository/advisory
results, vulnerable range, ordinary draws, pinned licence, method and counts), and
`completion.jsonl` (final manifest digest). A lock permits only one writer.
`progress.json` is atomically rewritten after every unit with stage counts, last unit,
last observed GitHub rate-limit headers, and cumulative active elapsed seconds.
These files may contain identities and must stay outside version control. Stdout and
repository records contain only counts, digests and fixed labels.

Replaying completed units makes no GitHub/OSV or clone calls. Final manifests are
reconstructed deterministically from journal results; an interrupted publication can
be retried, but a different existing manifest is refused. Completed JSONL rows are
never rewritten. Malformed or torn records fail closed instead of being interpreted
as completed work. Tests interrupt each stage with fakes, then compare resumed and
uninterrupted manifests byte for byte.

### Planning estimate for task 2.5 (not measured)

Let A be all reviewed advisories, R distinct fix-linked repository identities, U used
identities not already cached, C candidate advisories passing early filters, and K
repositories surviving extraction. GitHub requests are approximately
`ceil(A/100) + R + U + 2*C + K` (enumeration, canonical repositories, fix metadata,
provisional licence, final licence), plus retries. OSV requests are at most C. Git
fetches and lazy blob transfers are additional network operations, not GitHub API calls.

For a planning scenario of A=40,000, R=15,000, U≈1,000, C=600–1,500, K=300:
about **18,000–20,000 GitHub calls** and **600–1,500 OSV calls**. The all-advisory index
makes this substantially more than 300 repository lookups. At an assumed 5,000-request
hourly allowance, allow several rate-limit windows. Actual token limits can differ.
For 300–1,000 attempted clones averaging 20–100 MB after source hydration, plan roughly
**6–100 GB transferred**, with one clone occupying about 500 MiB at most between commands
plus the retained journal and manifests after completion. Transfer volume is an estimate; disk bytes
are only a proxy. A working planning range is **8–48 hours**, potentially longer on
large histories: every first-parent commit is inspected and lazy blobs can dominate.
These are assumptions, not evidence from a network run. The command reports actual
counts and wall time; task 2.5 establishes the measured estimate.

## Dispatcher, replay and scoring (groups 4–6)

`benchmarks.ax.batch` owns Task transport and the shared scheduler. New workloads supply
`Item` input bytes/commands and a `Workload` image, URL allowlist, deadline and result
validator. Two AX slots and one VM slot are the default; sandbox death gets one fresh
Task before VM fallback, OOM goes straight to VM, and instrument failures get one rerun.
Cleanup failure prevents further launches. Create `STOP` in the output directory to stop
launching; remove it and repeat the command to resume matching input digests. The legacy
engine adapter retains its `questions.json` object name for compatibility; replay inputs
and outputs use `.dat`. Both use the same object polling and cleanup implementation.

Replay reads `pool-pN.toml`, verifies its adjacent `freeze-pN.json` canonical digest,
selects `--slice`, and resolves private pointers through `private/pool-pN.toml` (or
`--private-manifest`). It never reads a draft. `--dry-run` prints only counts and digests.
The five-change proof uses a separate frozen JSON manifest from this project's own
source-changing history. Raw output must be outside the repository.

Each output root contains `inputs.json` and digest-keyed records and artifact directories.
The scorer accepts that root directly, joins change labels, and includes missing or stale
results as instrument failures. It refuses a slice above 5% failure after reruns. Example:

```sh
python -m benchmarks.unseen.score "$HOME/ousast-results/unseen/p1/1/default" \
  --out "$HOME/ousast-results/unseen/p1/1/default-score.json"
```

For paired binary arms add `--against BASELINE_ROOT --slice-id p1/2`; `--informed` forces
`unseen.gate=not_run`. The later experiment integration owns ledger verification; callers
of `gate` must pass that ledger decision. Score-bearing arms use `budgets` with fixed
thresholds and `gate(..., binary=False, threshold=..., threshold_fixed=True)`. In-slice
thresholds are exploratory and cannot qualify adoption. JVM wall time is explicitly the
sum of the hook artifact's scan build/query times, not a separately observed process timer.

### Coordinator task 4.4

Run from the merged repository root. Set `ENGINE_IMAGE` to the **engine** digest printed
by Engine image CI, `ENGINE_UNITS` and `ENGINE_EXAMPLES` to the frozen input files for the
two stored pins, `ENGINE_BASELINE` to their stored record directory, and `AX_KUBECONFIG`
to the operator's kube-ax kubeconfig. Host store credentials stay on the VM; use the public
HTTPS `S3_ENDPOINT=https://files.because-security.com` and the operator's `OUSAST_MEMORY`.
Use a fresh output directory, so the smoke executes instead of resuming prior records.

```sh
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH=$PWD/src
export S3_ENDPOINT=https://files.because-security.com
python benchmarks/learn/engine_trace.py \
  --units "$ENGINE_UNITS" --examples "$ENGINE_EXAMPLES" \
  --executor ax --parallel 2 --limit 2 --image "$ENGINE_IMAGE" \
  --kubeconfig "$AX_KUBECONFIG" --out "$HOME/ousast-results/unseen/proof-04"
python -m benchmarks.unseen.proof engine --image "$ENGINE_IMAGE" \
  --records "$HOME/ousast-results/unseen/proof-04" --baseline "$ENGINE_BASELINE" \
  --out "benchmarks/measurements/$(date +%F)-unseen-04-dispatcher/record.json"
```

### Coordinator task 5.4

Merge before running this proof. `.github/workflows/engine-image.yml` builds the `engine`
and `replay` targets on push to main; it publishes `ousast-engine-task` and
`ousast-replay-task` separately and prints their digests. Set `REPLAY_IMAGE` to the latter
full `ghcr.io/...@sha256:...` reference. No manual image build is needed. Set
`KIND_KUBECONFIG` and `AX_KUBECONFIG` to the corresponding AX kubeconfigs; the kind lane
uses the identical Task API/manifest, never a Kubernetes Job.

```sh
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH=$PWD/src
export S3_ENDPOINT=https://files.because-security.com
python -m benchmarks.unseen.replay --proof-history \
  --manifest "$HOME/ousast-results/unseen/proof-05-inputs.json"
python -m benchmarks.unseen.replay --manifest "$HOME/ousast-results/unseen/proof-05-inputs.json" \
  --image "$REPLAY_IMAGE" --lane kind --kubeconfig "$KIND_KUBECONFIG" \
  --out "$HOME/ousast-results/unseen/proof-05-kind"
python -m benchmarks.unseen.replay --manifest "$HOME/ousast-results/unseen/proof-05-inputs.json" \
  --image "$REPLAY_IMAGE" --lane ax --kubeconfig "$AX_KUBECONFIG" \
  --out "$HOME/ousast-results/unseen/proof-05-ax"
python -m benchmarks.unseen.replay --manifest "$HOME/ousast-results/unseen/proof-05-inputs.json" \
  --image "$REPLAY_IMAGE" --lane docker \
  --out "$HOME/ousast-results/unseen/proof-05-vm"
python -m benchmarks.unseen.proof replay --image "$REPLAY_IMAGE" \
  --kind-records "$HOME/ousast-results/unseen/proof-05-kind" \
  --ax-records "$HOME/ousast-results/unseen/proof-05-ax" \
  --vm-records "$HOME/ousast-results/unseen/proof-05-vm" \
  --out "benchmarks/measurements/$(date +%F)-unseen-05-replay-task/record.json"
```

The record command fails if fewer than five results exist, identities differ, bytes/JVM
proof is missing, or quick-tier findings differ. It does not convert a quick-only run
without a JVM into an engine proof. Pool replays use `--lane mixed` (default) for the two
AX slots and single VM overflow/fallback lane; `--arm long_deadline` changes only the
hook deadline to 300 seconds and is a separate input digest.

### Deadline calibration and native agreement

The 2026-10-05 maintainer decision supersedes the unscaled cluster deadline above.
gVisor snapshot preparation can consume 30 seconds before any analysis. Calibrate
the pinned replay image against the VM's native Docker **runc** runtime first.
The default deterministic sample is the first 20 changes ordered by SHA-256 of
change ID; a smaller manifest (including the five-change proof) uses all changes.
Sampling never depends on manifest order.

`calibrate` runs both lanes with a 600-second hook deadline (override `--deadline`
if stages still time out). It reads resolution, provenance, preparation, snapshot,
and quick timings from the push artifact; snapshot is nested in preparation.
`quick_total` sums resolution + provenance + preparation + quick, without counting
snapshot twice. Engine build and query times sum across the hook's scans. Hook
wall time comes from the instrument block. Missing/nonpositive timings, deadline
exhaustion, degraded engine scans or failed instruments prevent a successful
calibration; failed changes are never silently dropped. Each factor is the median
of paired cluster/native ratios with a deterministic 2,000-resample percentile
bootstrap 95% interval. The measurement record contains opaque change digests,
counts and timings, with no repository names. Raw artifacts remain outside the repo.

Set `REPLAY_IMAGE` to the newly built replay image's pinned digest and
`REPLAY_IMAGE_BYTES` to an **unpacked image size upper bound in bytes** from the
image build. Do not use compressed registry layer size. Docker refuses to pull
without this bound or when `df` at its data root reports less than that bound plus
1 GiB free. It then explicitly pulls the image before issuing presigned task URLs.
Supply `--docker-image-bytes "$REPLAY_IMAGE_BYTES"` to VM and mixed replay commands,
including the earlier VM proof command.
Launch/pull failures retain exit codes and the last ten sanitized stderr lines in
`docker-error.json`, the result record and attempt history. URLs, known environment
secrets and credential assignments are redacted. The original VM failure's cause
remains unconfirmed until this diagnostic is captured; the old transport discarded it.

Coordinator commands (these run networked workloads; offline tests use fakes):

```sh
export PATH=/home/mc/Source/OpenUltraSAST/.venv/bin:$PATH
export PYTHONPATH=$PWD/src
export S3_ENDPOINT=https://files.because-security.com
CALIBRATION_RECORD="benchmarks/measurements/$(date +%F)-unseen-calibration/record.json"
python -m benchmarks.unseen.calibrate \
  --manifest "$HOME/ousast-results/unseen/proof-05-inputs.json" \
  --sample 20 --deadline 600 --image "$REPLAY_IMAGE" \
  --docker-image-bytes "$REPLAY_IMAGE_BYTES" --kubeconfig "$AX_KUBECONFIG" \
  --out "$HOME/ousast-results/unseen/calibration" --record "$CALIBRATION_RECORD"

python -m benchmarks.unseen.replay --manifest benchmarks/unseen/pool-p1.toml \
  --pool p1 --slice 1 --arm default --lane ax --image "$REPLAY_IMAGE" \
  --calibration "$CALIBRATION_RECORD" --native-sample 100 \
  --docker-image-bytes "$REPLAY_IMAGE_BYTES" --kubeconfig "$AX_KUBECONFIG" \
  --out "$HOME/ousast-results/unseen/p1/1/calibrated-default"
python -m benchmarks.unseen.score "$HOME/ousast-results/unseen/p1/1/calibrated-default" \
  --out "$HOME/ousast-results/unseen/p1/1/calibrated-default-score.json"
```

For a 20-change slice calibration, replace the proof manifest with
`benchmarks/unseen/pool-p1.toml --slice 1`; both commands accept `--private-manifest`.
For the long arm use `--arm long_deadline` and a separate output root. Calibration
requires the same image digest as replay. An explicit `--deadline-scale FACTOR`
is an alternative to `--calibration`, not an additional multiplier.

Cluster deadlines are `round(30 * factor)` or `round(300 * factor)` seconds;
native deadlines remain 30 or 300, including VM fallback in mixed runs.
Records carry configured and applied scale, base/applied deadline and actual lane;
the scorer reports their counts. Task, subprocess and presigned-object budgets
grow with the applied deadline.

Use `--lane ax` (or `kind`) with `--native-sample K` for an agreement run, so every
sampled change has a cluster counterpart. The native sample lives in `OUT/native`;
the scorer detects it automatically, or accepts `--native PATH`. Missing, failed,
wrong-lane or mismatched-image/arm pairs are unknown, never quiet agreements.
The decision is whether any of the three finding streams flags the push, not
whether the finding matches the vulnerability label.

**Decision rule:** if the Wilson 95% agreement lower bound is below 95%, do not use
the cluster results for the baseline. The score sets `flagged=true`,
`baseline_eligible=false` and the adoption gate to `not_run`. Unknown pairs also
flag the run. Disagreements are listed by change ID only, alongside per-change
flagged/not-flagged decisions. Even perfect agreement needs at least 73 pairs to
clear this bound; the five-change proof or a 20-change sample cannot qualify it.
