# Stream run artifacts to RustFS, one bucket per purpose

Recorded 2026-10-09 from the maintainer's direction. The host's local disk is the scarce
resource (it runs near full, and the draw stops itself at under 2 GB free). Runs should stream
their durable artifacts to RustFS instead of accumulating them on local disk, and should spread
them across **purpose-specific buckets** rather than one shared bucket. This relieves the disk and
simplifies runs: local state becomes mostly a scratch cache that can be rebuilt or resumed from the
object store.

## Why per-purpose buckets

One shared bucket (`sast-memory`) already bit us: an append-rewritten key on a versioned bucket
with no noncurrent-version expiry ballooned to >10 GB (see the `engine-queue` command-upload fix and
the lifecycle rules added 2026-10-09). Separate buckets let each kind of artifact carry the
lifecycle it actually needs, and keep a transient firehose from polluting durable data.

Proposed split (names illustrative; the admin creates them and grants the store key):

- `sast-memory` — the plane memory store (existing): facts, excerpts, embeddings, index. Durable,
  versioned, with the noncurrent-version lifecycle now in place.
- `sast-pools` — frozen unseen pools and their provenance: `pool-pN.toml`, `freeze-pN.json`, and the
  draw journal needed to resume/reproduce. Durable, versioned. This is also the "don't redo the
  sourcing" archive.
- `sast-runs` (or `sast-journals`) — ephemeral run and queue state (engine-queue, replay results,
  per-run journals). Aggressive lifecycle: short current expiry + 1-day noncurrent expiry, since it
  is a transient firehose.
- optionally `sast-traces` — engine/replay traces, if kept.

## Principles

- **Stream, don't hoard.** Write a run's durable outputs to its bucket as they are produced; keep
  only a working scratch (e.g. the live git clone, which cannot be streamed) on local disk, and let
  the disk guard stay as the backstop.
- **Lifecycle per bucket**, tuned to the artifact: durable+versioned for pools/memory;
  short+noncurrent-expiry for transient run/queue state. Never a versioned bucket without a
  noncurrent-version rule.
- **Resume from the object store**, so a wiped or small local disk does not lose a long run.
- **Least privilege per bucket.** A run gets a key scoped to the bucket it writes; the store never
  creates or configures a bucket (admin does that once), consistent with the current S3Store.
- Content discipline unchanged: no secrets, no exploit payloads; pool manifests keep the existing
  public/private (licence) split.

## Foundation and dependency

`src/openultrasast/plane/memory.py` already speaks boto3 to RustFS (S3Store) with startup
verification of versioning/lifecycle/Select/tags; this direction extends that pattern to more
buckets rather than inventing a new transport. New buckets and their grants are an **operator
admin** action — the store credentials cannot create buckets or set lifecycle (confirmed by the
`AccessDenied` on the 2026-10-09 lifecycle apply).

## Status

Direction recorded; planned as a follow-up spec, not retrofitted into an in-flight run. The current
unseen draw finishes to its local journal and then archives its result to `sast-pools` once that
bucket exists.
