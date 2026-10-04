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
