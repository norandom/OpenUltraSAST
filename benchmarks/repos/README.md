# Pinned known-vulnerable checkouts

The pair corpus scores excerpts: a vulnerable function and its fixed twin, fifteen lines each, handed to the
engine with the answer already narrowed down. That measures arbitration. It cannot measure anything about a
repository — region ranking, the budget, one CPG over thousands of files, or whether a verdict that holds on
an excerpt still holds when the source, the sink and the guard live in three different modules.

These recipes name real checkouts so those questions can be measured instead of assumed.

## What a recipe is

One TOML file per repository, naming a url, a **full 40-character commit SHA**, the licence, and every known
vulnerability with the file, function and line it lives at.

```
ousast repos                          # what is pinned, and whether it is checked out
ousast repos --repo vampi --fetch     # materialise one (network; CI never does this)
ousast repos --json                   # the same, for an artifact
```

Nothing here is vendored. The repositories stay in their own projects under their own licences; the recipe
records the licence so a measurement artifact can say what it ran against.

## Three rules, and why

**Offline by default.** A recipe is inert until someone asks for the network — `--fetch` for one run, or
`OPENULTRASAST_REPOS_NETWORK=1`. CI sets neither, and the test suite clears both. This is the same rule the
pointer pairs follow, for the same reason: a test suite that quietly reaches the network is a test suite that
fails for reasons that have nothing to do with the code.

**Pinned, not tracked.** `commit` must be a full SHA; a branch or a tag is rejected at load. A tag gets
re-cut and a branch moves every week, and either would make the same recipe mean different code next month
while the baseline it produced still carried the old numbers.

**A recipe declares what it can measure.** `measures` is `detection`, `envelope`, or both, and every known
vulnerability states `in_scope` explicitly — whether it belongs to a family this engine arbitrates at all.
There is no default, because the default would silently decide the most important question about the result:

> An out-of-bounds read in a C library is a fine envelope test and an impossible detection test. Recording
> "not found" against it as a miss is the easiest way to make a measurement lie.

## Verification

`ousast repos` does not trust a recipe. Against a materialised checkout it checks that HEAD is the pinned
commit, that the licence file is really there, and that each declared function appears above its declared
line in its declared file. A recipe that contradicts the code exits non-zero; a recipe that simply has not
been fetched does not, or CI could never run this command.

That check earned its place immediately: the first libpng recipe named `LICENSE.md`, which is the filename at
HEAD today and not at the pinned commit, where it is still `LICENSE`.

## What is pinned

| repo | language | size | measures | why |
|---|---|---|---|---|
| `vampi` | python | 520 lines, 11 files | detection | Small enough that a detection result is not confounded by budget or ranking. Its routes are registered through an OpenAPI `operationId` rather than decorators, so it exercises registration-based entry-point mapping. Excerpts of it are already in the pair corpus, so a whole-repository run says directly whether a verdict survives the move off the excerpt. |
| `libpng` | c | 91k lines, 101 files | envelope | Whether one CPG over a real C library is affordable at all: build time, query time, peak memory, and whether the ranker yields a sane number of regions. Its CVE is out of scope by construction. |

## Baselines

Task 6.1 turns a scan of a pinned checkout into a committed baseline, so a change to the fact tables or the
queries can be read as findings gained, findings lost and rung movements (Req 10.1–10.4). Until then these
recipes exist to be measured against by hand, and the first such measurement is task 2.2.
