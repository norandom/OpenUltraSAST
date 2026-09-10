# Brief: flow-aware-ranking — spend the expensive query where the cheap evidence is strongest

**Status:** brief only, unapproved.

## Why now

> "we need a taint flow aware ranker, that is capable to put high risk areas into tiers"
> "can you engineer a prompt with enough information to steer the llm making ranker decisions"
> "this can be done, but it requires an iterative concept and clear plans"

A taint request costs **6.63 seconds** (contributor-scan 5.13). A 637-file plugin yields **4,463 regions**, and
the current ranker gives 83.8% of them the same rank, ordered alphabetically by path. So the budget is spent
arbitrarily and the scan does not finish.

The ranker is not weak. It is looking at the wrong thing.

## The evidence that this is tractable

Three regions from one plugin, with what the ranker sees today and what is actually in the code:

| region | rank today | sink in scope |
|---|---|---|
| `getMemberOrderByCode` — **holds CVE-2023-23488** | 0.30 | `$wpdb->get_var("... WHERE code = '" . $code . "' LIMIT 1")` |
| `getMemberOrderByID` — sibling | 0.30 | `$wpdb->get_row("... WHERE id = '$id' LIMIT 1")` |
| `pmpro_rest_api_get_membership_level` | **0.80** | none — no SQL sink at all |

A region with no sink outranks two holding raw concatenated SQL. The discriminating signal is in the sink
call's own source text — interpolated versus bound — and nothing in the ranker reads it.

One detail decides whether a keyword rule suffices, and it does not: `esc_sql` IS in scope for the CVE's
function, applied to a different statement. "A sanitizer is present, rank it lower" demotes precisely the
right answer. Knowing which call it wraps is reading, not matching.

## The unit, and the tiers

**Rank (region, family) PAIRS, not regions.** The expensive question is "does a source reach a sink of family
F here"; every cheap approximation of it is free from the fact tables and a text scan.

| tier | evidence | |
|---|---|---|
| **0** | no sink of F in scope | **never ask** — exact, cannot lose a finding |
| 1 | sink present, no source in scope or reachable | ask last |
| 2 | sink and source, a cleansing call on THAT call | may still corroborate |
| 3 | sink and source, interpolated shape, no cleansing on that call, entry point or declared public | ask first |

Tier 0 is the only tier that excludes rather than orders, so it alone must be exact. Above it, being wrong
costs position, not the finding. That bound is what makes a model safe here: **a ranker cannot manufacture a
finding**, it decides what is looked at, and `regions_truncated` already reports what went unexamined.

## The iterative concept

Each phase ships only if it beats the previous one **on a repository the change was not developed against**.
A phase that cannot show that is not an improvement, it is a story.

- **Phase 0 — the oracle and the baseline.** The evidence extractor (no model) and a scoring harness over the
  pinned CVEs, reporting each one's rank position. Gate: reproduces today's numbers — CVE-2023-23488 at
  position 390 of 4,463, 83.8% of regions in one tier. Without a baseline nothing later is measurable.
- **Phase 1 — tier 0 only, no model.** Exact pruning. Gate: 53% fewer taint requests, and `pmpro`'s taint
  query COMPLETES. This is the phase that turns a scan that never finishes into one that does.
- **Phase 2 — heuristic tiers, still no model.** Sink shape, cleansing on the call rather than in the file,
  source presence, declared access. Gate: every pinned CVE's region inside the examined budget, measured on
  all pinned repositories. **If this passes, the model may not be needed for tiering at all** — and knowing
  that is worth more than assuming it.
- **Phase 3 — the LLM ranker.** Same evidence, ordered by a model. Gate: beats phase 2 leave-one-repository-out.
  If it does not, phase 2 ships and phase 3 does not.
- **Phase 4 — break the closed loop.** An exploration slice (~10% of budget sampled outside the top-K) and
  full labelling on repositories small enough to arbitrate every region. Gate: a measured estimate of the
  selection bias in phase 3's numbers.
- **Phase 5 — prompt optimisation (GEPA / SIMBA / DSPy).** Only after 3 and 4. An optimiser run against a
  censored metric optimises the censorship.

## What the prompt has to carry

The question put to the model is **not** "is this vulnerable" — that is adjudication, it is the arbiter's job,
and it is the one thing a ranker must never be asked. It is:

> Given a fixed budget of expensive dataflow queries, which of these sites are worth spending it on?

and the evidence it needs is textual and already available: the sink calls in scope **with their source
text**, the untrusted-input expressions found, the cleansing calls and **which call each one wraps**, the
sink's shape (bound versus interpolated), the declared access and its provenance, and whether the region is
reachable from a request handler.

## Constraints, from measurement and from prior scars

- **Cost.** One model call per region is 4,463 calls a scan. Batch over a prefilter, or it does not ship.
- **The loop is closed.** A region the ranker excludes is never arbitrated, never labelled, so the ranker
  never learns it was wrong. Every run confirms the ordering it already had.
- **N projects.** Four pinned CVEs is not a training set. This project already has the closed-loop
  train-on-test scar; the reported figure must come from a repository the optimiser never saw.
- **Determinism.** Two runs of one repository must agree or a baseline diff is meaningless. The ranking is
  recorded in the manifest.
- **Degradation.** With no model configured, phases 0–2 still rank, and the report says which ranker ordered
  the scan.

## Open questions for the design phase

1. Where does the evidence extractor live — the mapper, or a new pass? It needs fact tables and file text but
   no CPG, which suggests it belongs beside `mapping` rather than in `model/`.
2. Is tier 0 computed per file (exact at `callDepth=0`) or per reachable set (exact at any depth)? The
   repository-wide form — no sink of F anywhere — is exact at any depth and removes a fifth of the budget on
   its own.
3. How many pinned repositories are needed before leave-one-out means anything? Four is not enough.
4. Does the arbiter's own verdict feed back as a label, and if so how is the selection bias corrected?
