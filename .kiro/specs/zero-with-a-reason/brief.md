# Brief: zero-with-a-reason — a finding count is meaningless without a denominator

**Status:** brief only, unapproved.

## Why now

> "can you think of an architecture to avoid these 0 findings issue?"

Because it is not one bug. It is the same bug seven times, and every single one was caught by a human
noticing that a number they had a reason to expect was zero:

| # | what produced the zero | how it was caught |
|---|---|---|
| 1 | `CpgResult` had no `run_batch`, so batching was unreachable | a scan took 275s and the reason did not add up |
| 2 | a 1.49MB batch over `execve`'s 128KB argv cap → `E2BIG` → `{}` | 500 regions "examined" in 0.05s of query |
| 3 | a 117k-line CPG threw during overlay load → `{}` | same shape, found again by hand |
| 4 | the budget's `break` halted unpaid CPG work | 6 of 22 VAmPI regions examined |
| 5 | `protected function` did not match `^\s*function` → one file-level region | a scan of a known-vulnerable file went quiet |
| 6 | `php2cpg` dropped every file and exited 0 | 64 regions, 0 findings, 0 degradations, over an empty graph |
| 7 | a Joern `[INFO ]` line landed inside the fenced payload | 205 requests lost in one batch |

Each was fixed at its own seam, and each fix was correct. None of them could have been found by the tool.
The pattern is that **the pipeline reports the last number in the chain and discards every number before
it**, so all seven look identical from outside: `0 findings`.

The rung ladder cannot help here by construction. It labels verdicts, and the failure is that no verdict was
produced. There is nothing to put on a ladder.

## The idea

**Every zero must be decomposable, and every scan must be able to prove it did work.** Three mechanisms,
independent, in order of value per line of code.

### 1. The funnel — make the denominator first-class

The scan is already a chain of narrowing stages, each of which computes a count and throws it away:

```
files discovered        637
files parsed into graph   12      <- 625 dropped
methods in graph         153
regions mapped            64
questions asked          205
sink sites matched         0      <- the zero is HERE
flows considered           0
verdicts                   0
findings                   0
```

The rule: **a zero at stage N is legitimate only if stage N-1 is non-zero.** Otherwise the zero belongs to
the earlier stage and is reported there. All seven bugs above are a different row of that table, and the
table distinguishes them without knowing anything about what went wrong.

Cheap, because every number already exists at the moment it is computed. `ModelScanResult` grows a funnel;
the coverage disclosure (Req 5.6, already written) is where it prints. The hard rule that gives it teeth: a
report may not describe a repository as clean without the funnel beside it.

### 2. The dumb oracle — an independent lower bound on the graph

The CPG is an elaborate instrument. A regex over the source text is a stupid one, and stupid instruments
fail differently — which is the entire reason to have two.

Before querying, count the fact tables' sink names in the raw source text. That is a floor on what the graph
must contain:

```
source text contains 26 occurrences of $wpdb->{get_var,query,...}
the CPG's sink match returns 0
-> degradation: graph_below_text_floor, both numbers reported
```

This catches an empty graph, the wrong frontend, dropped files, a broken name matcher, and a missing
overlay — bugs 2, 3, 5, 6 and 7 above, none of which it needs to know about in advance. It is the same trick
the pair corpus already uses: two independent measurements of one thing must agree.

What it cannot do: say anything about over-reporting, or about flows. It is purely "does the graph contain
the syntax the text contains". That narrowness is why it is trustworthy.

### 3. The canary — an end-to-end positive control

One synthetic file with an unmistakable flow, one extra request in the batch:

```php
<?php function __ousast_canary() { global $wpdb; $wpdb->query("SELECT " . $_GET['c']); }
```

If the canary is not entailed, the run is **invalid**, not clean. That single assertion proves the frontend
ran, the file reached the graph, overlays applied, the fact tables loaded, the query compiled, the batch
round-tripped, the payload parsed, the arbiter ran and the ladder assigned a rung.

With one honest caveat that must be designed around: **adding a file to a PHP build can itself trigger the
php2cpg race** — a two-line file added to `class.memberorder.php` is exactly what emptied that graph. So on
PHP the canary belongs in its own build (`ousast doctor`), where it proves the toolchain works, and the
funnel and the oracle prove that *this* build worked. They are complementary, not redundant.

### 4. Types that cannot express the confusion

`dict | None` meaning "no rows" versus "could not ask" is a convention, and bugs 2, 3 and 7 are each a place
where the convention was silently violated at a boundary. A two-case `Answer` (`Answered(rows)` /
`Unavailable(reason)`) makes mypy force the distinction at every call site. Mechanical, small, and it
prevents recurrence rather than detecting it.

## What this is not, and must not become

- **Not a confidence score.** The rung ladder exists precisely so uncertainty is carried as a claim about
  evidence rather than a number nobody can act on. A "coverage percentage" that averages the funnel away
  would undo it.
- **Not a retry loop.** Retrying a failed build until it succeeds hides bug 6's race instead of reporting it.
  Three of five builds succeeding is a fact about the toolchain and belongs in the output.
- **Not anomaly detection over historical finding counts.** 6.1's baselines already give the diff, and
  "findings dropped 90%" is a lagging indicator that needs a known-good prior run — which is exactly what a
  first scan of a new repository does not have.
- **Not more code than it saves.** The funnel is plumbing that already exists, the oracle is one pass over
  files the preprocessor already reads, the canary is one file and one request.

## Open questions for the design phase

1. Does the funnel live on `ModelScanResult`, or is it a separate ledger the driver writes into? The stages
   span `preprocess`, `mapping`, `regions` and `scan`, and only the last of those returns a result object.
2. Is the text floor a hard degradation or a hard failure? A file the frontend legitimately excludes would
   trip it, so the threshold needs stating rather than assuming zero tolerance.
3. Does the canary belong in `ousast doctor` for every language, or in-band for the ones where adding a file
   is safe? The PHP answer is settled; Python and C are not.
4. Which of the seven bugs above would each mechanism have caught? That table is the acceptance test for
   this spec, and it can be written before any code is.
