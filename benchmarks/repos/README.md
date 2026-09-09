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
| `pmpro` | php | 117k lines, 637 files | detection, envelope | Paid Memberships Pro 2.9.7. CVE-2023-23488 is an unauthenticated SQL injection whose value reaches the sink inside the function that receives it -- the shape the PHP fact tables were built for. 2.9.8 wraps it in `$wpdb->prepare`, so the pair separates. |
| `mwwpform` | php | MW WP Form 5.0.3 | detection | CVE-2023-6559, an arbitrary file deletion. The fix adds `realpath()`, `is_file()` and a directory-confinement test, all of which the facts already carry, so this is a pair the engine can separate rather than merely flag. |
| `wpstatistics` | php | WP Statistics 13.1.x | detection | CVE-2022-25148, an unauthenticated SQL injection that crosses `add_filter`/`apply_filters`. Pinned because it is NOT expected to be found: a table of hits teaches nothing about where the engine stops. |

## WordPress, class by class

WordPress's recurring flaw classes are narrow and well documented, which makes them a fair test: each one
maps to a family this engine already has, so "not found" has to name a mechanism rather than shrug. Three
plugins, each pinned at a version whose advisory was **read out of the code** and not out of the advisory
text, and each measured against its own fixed commit.

| class | plugin, CVE | vulnerable side | fixed side | verdict |
|---|---|---|---|---|
| Unauthenticated injection, sink in the function that receives the value | `pmpro`, CVE-2023-23488 | entailed at `class.memberorder.php:936:getMemberOrderByCode`, sourced from `$code` | absent | **found**, and the pair separates |
| Arbitrary file operation | `mwwpform`, CVE-2023-6559 | entailed at `class.mail.php:259:_delete_files` | absent | **found**, and the pair separates |
| Unauthenticated injection, value crosses a WordPress hook | `wpstatistics`, CVE-2022-25148 | not reported | not reported | **missed**, structurally |
| Missing capability check | — | — | — | **cannot be asked**: PHP has no obligation facts |
| Unescaped output | — | — | — | **cannot be trusted**: the sanitizer list is flat |

### The two it finds

Both are entailed by the graph alone — no judge, no model call, no spend — and both disappear on the fixed
side because the fix is a call the fact tables already carry: `$wpdb->prepare` for one, `realpath()` for the
other. That is the distinction worth teaching. The engine is not recognising a bug; it is failing to find a
cleansing call on a path it resolved, and then finding one.

The precision is not clean, and saying so is the point. On PMPro's order class the vulnerable side reports
**15 entailed findings**, of which **4** are sourced from a named parameter and **11** from the receiver,
`$this`. One receiver-sourced finding survives into 2.9.8 at a query whose every fragment is wrapped in
`esc_sql` — a false positive, and a legible one: the flow reaches the sink through `$this->sqlQuery`, so the
sanitizer is on the fragments and not on the path.

Excluding the receiver was tried and reverted. It cuts that file to 6 findings, all named-parameter sourced,
and makes the PMPro pair separate cleanly — and it **loses CVE-2023-6559**, because `_delete_files()` takes
no parameters at all and its attacker-controlled path arrives as `$this->attachments`, assigned by another
method. Trading a verified CVE for findings merely suspected of being false is the wrong trade. The real
defect is field-sensitivity: a field should be tainted where it is assigned.

### The one it misses, and why

WP Statistics' CVE is an unauthenticated REST hit whose `current_page_id` is interpolated into
`$wpdb->get_row`. Every piece is in scope — a modelled source, a modelled sink, and `esc_sql` as the fix —
and the engine still reports nothing, on both sides. The reason is checkable rather than inferred:

* the file holding the sink contains **zero** superglobals;
* it makes **no** call into the class holding the source;
* the only connection between them is

  ```php
  add_filter('wp_statistics_current_page', array($this, 'set_current_page'));   // hits.php:43
  return apply_filters('wp_statistics_current_page', $current_page);            // pages.php:105
  ```

Both ends name the callback with a **string**. No frontend can draw that edge, so no dataflow engine can
cross it, and the honest description is not "we missed it" but "the graph does not contain the path". Most
plugin data travels this way. It is the single largest structural gap for PHP, and it is not a fact-table
problem.

It is also not a permanent one, and "structurally impossible" would be the wrong thing to leave here. Note
what is and is not missing: `$_REQUEST` reaching `set_current_page`'s return is a path the graph *has*, and
`apply_filters`' return reaching `$wpdb->get_row` is a path the graph *has*. Only the join between them is
absent — and the key it joins on, `'wp_statistics_current_page'`, is a string literal written at both ends.
The same is true of `$this->attachments` in MW WP Form, where the key is a field name.

So the strategy is two-stage taint with a link table: ask the existing query for each half against a
synthetic endpoint, build the table by reading literals rather than inferring anything, and join. The rung
carries the join's uncertainty — one registered callback and a literal key entails, several callbacks or a
computed hook name corroborates. Task 5.11 states it, with both pinned pairs as its observable.

What the engine reports on that plugin instead is two other sites — `getTop:406` and `TotalCount:443` — the
same weakness class at the wrong lines, identical on both sides, so the pair does not separate. They are not
noise: upstream now annotates both with `// phpcs:ignore WordPress.DB.PreparedSQL...`, and later rewrote
one of them with `$wpdb->prepare`. Right class, wrong sites, no discrimination.

### The two it cannot ask

`dominance_specs(language="php")` returns an **empty** mapping. There are no PHP obligation facts, so the
missing-capability class — `current_user_can`, `check_admin_referer` — is never asked, on any plugin, and
would report nothing however many were added. That is not a miss; nothing was measured. Recorded as 5.9.

`output_encoding` for PHP has sinks (`echo`, `print`, `printf`) and shares the one **flat** sanitizer list
with every other family. That list contains `esc_sql`, `intval`, `realpath` and `escapeshellarg`, none of
which escape HTML, and excludes `esc_html` and `esc_attr`, which are the only ones that do. So it is wrong in
both directions at once: it would accept `echo esc_sql($x)` as safe and report
`echo esc_attr(sanitize_text_field($_REQUEST['login']))` — the pattern WordPress documents as correct, and
which appears verbatim at `pmpro/includes/login.php:684` — as a finding. Until a sanitizer can say which
weakness class it cleanses, no XSS verdict from this engine means anything. Recorded as 5.6.

### What nearly invalidated all of it

The first PMPro measurement in this series reported 64 regions examined, zero findings and zero degradations.
The graph it examined had no methods in it.

`php2cpg` 4.0.623 reads its PHP parser's stdout and stderr as one merged stream, and the parser writes a
progress banner to stderr the moment it starts the next file — while the previous file's multi-megabyte JSON
is still draining from a block-buffered stdout. The banner lands inside the JSON, the file is dropped, and
`joern-parse` propagates none of it: thirteen lines of output, exit status 0, "Successfully wrote graph".
One oversized file empties the entire graph, so this was never the scale limit it looked like.

It is also a **race**, not a threshold. Five builds of the same two-file input: three produced a graph, two
came back empty. Before the batched query started carrying a census of the graph, two of every five scans of
that plugin would have reported a clean bill of health.

That is the argument for why a corpus of benchmarks is not enough on its own, made concretely. Every gate
stayed byte-identical through all of it. A corpus tells you a verdict is right; it cannot tell you the
verdict was reached by looking at anything.

## Baselines

Task 6.1 turns a scan of a pinned checkout into a committed baseline, so a change to the fact tables or the
queries can be read as findings gained, findings lost and rung movements (Req 10.1–10.4). Until then these
recipes exist to be measured against by hand, and the first such measurement is task 2.2.
