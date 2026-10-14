# Access-control feature table and separation screen, no model calls (2026-10-13/14)

## What was built

`table.py` checks out the head of every change of the frozen access-control training pool (digest 53f9f364:
5 fix pushes with 48 verified locations, 100 ordinary pushes, 5 repositories), enumerates the candidate rows
(functions the push touched, plus the verified fix sites of a positive) and runs the four producers over them.
Rows are labelled 1 at a verified fix site, 0 on an ordinary push. The screen scores every engineered feature alone
against the label (ROC-AUC) and names the strongest feature per model annotation. Repositories are the clusters,
and there are five, so the screen is a direction, not a result.

The final table: 952 rows, 74 positive rows (62 functions; a function with two verified spans counts twice),
878 negative rows, digest 02774edc (152a72ce with folds). Producer coverage: diff 952, source 933, semantic 262
(the semantic producer handles TypeScript and JavaScript only; Java has no obligations support and PHP is
unsupported), taxonomy 952 (a constant: it renders the family list, it is not a row feature).

## It took three builds, and the first two printed plausible numbers

1. **Build 1** (952 rows, source ok 783): the screen printed AUCs. 150 rows, 16%, every positive of trigger.dev
   among them, had read an empty file although git holds the blobs. The gate `source == 0` did not fire because
   most rows were fine.
2. **Build 2**, after adding a checkout proof (`git status` clean after the sparse checkout is undone) and an
   unread-row gate (every unread row checked against `git cat-file -s`): the gate refused the table, the same
   150 rows. The checkout proof never fired, so the checkout was not the cause.
3. The cause was a producer bug: the entry-point scan read every product file of the tree, one empty file raised
   `empty_source`, the exception escaped the cached property and failed the source producer on every row of
   the change, re-reading the whole tree per row (fcb43fd). **Build 3**: 0 unread rows, source ok 933; the 19
   remaining failures are files the push deleted (FileNotFoundError, 16) and three unparseable tsx files.

A producer that fails on every row of whole changes while the same files read fine by hand is a producer bug,
not disk or concurrency. The memory note carries it.

## The diff producer was blind to the shape of this class

A positive push here is the fix replayed backwards (base = fix commit, head = its parent). A fix that adds a
permission check becomes a push that only removes lines, and the diff producer kept only hunks with added lines
at head. In build 1, 38 of 74 positive rows had no hunk in their file at all and 69 of 74 were "not on a changed
line", while 60% of ordinary rows were: the hunks annotation separated the labels by construction and showed
the model nothing at the fix site. The producer (version 2, 537b61e) now records the head lines after which the
push removed code; distance and on_changed_line count them; the model's hunks input renders them as
`removed_after_line`; `diff.deletion_count` is an engineered feature. In build 3, 66 of 74 positive rows have a
deletion anchor in their file and 12 are on a changed line.

## Screen (build 3, `separation.csv`, `screen.csv`)

| Annotation | Strongest feature | AUC | rows |
|---|---|---|---|
| hunks | diff.deletion_count | 0.89 | 952 |
| obligations | semantic.obligations_undischarged | 0.76 | 262 |
| callers | source.caller_count | 0.72 | 933 |
| entry_points | source.entry_point_count | 0.71 | 933 |
| roles | semantic.sinks | 0.17 | 46 |
| function_text | source.span_lines | 0.36 | 933 |
| change_summary | source.is_module | 0.36 | 933 |
| def_use | semantic.binds | 0.36 | 262 |

Read with care:

- **deletion_count (0.89) and the low hunk_lines (0.15) are the construction, not the class.** Reversed fixes are
  deletion-heavy pushes with few added lines; ordinary pushes are not. Any feature that says "this push removed
  code and added little" separates these labels. `separation_deletion_rows.csv` repeats the screen on the 235
  rows whose file lost lines (66 positive, 169 negative, all 5 repositories): there deletion_count drops to 0.71,
  hunk_lines and hunk_count stay at 0.12 and 0.14, and **entry_point_count rises to 0.83, caller_count stays at
  0.73**. Those two are the class: the verified access-control sites are web entry points with callers.
- **obligations_undischarged (0.76) rests on 8 positive rows from one repository** (trigger.dev; the semantic
  producer covers no Java or PHP). Not evidence yet.
- **roles** scored 46 rows. The semantic annotation is absent for 80% of this pool.
- `leak_audit.csv` is the same screen over the folded table (`ablation.leak_audit`), kept for the ablation record.

## Folds and the first ablation manifest (registered, not run)

Folds are repository-grouped (`ablation.assign_folds`, k=5, seed 0), one repository per fold: 0 p4-plugin (6
positive rows), 1 dependency-track (4), 2 job-import (2), 3 shopper (54), 4 trigger.dev (8).
`ablation.json` registers the first manifest in `~/ousast-results/hunt/ac-ablation-1/` for a decision: arms
full, no-hunks, no-entry_points, no-callers, no-semantic; compile folds 0-2 (the Jenkins plugins), holdout 3-4
(shopper and trigger.dev, 62 of the 74 positive rows); metric search_outcome at tolerance 10; one repeat; 8
dollars and 1,500 calls per arm. The baseline cost 6.13 dollars for one arm over this pool, so this manifest is
about 35 dollars. With 5 positive pushes `analyse` will report `dry_run`; the location-level numbers are what it
can say.

## Open questions for the maintainer

- Whether the hunks annotation should be ablated at all while positives are reversed fixes, or whether the
  ordinary draw should be stratified by "push removed lines" so the construction signal cancels.
- Whether to extend the semantic producer to Java (obligations) and PHP before the next class round; 80% of
  this pool gets no roles, def_use or obligations today.
- The 21 access-control sources dropped by the disk guard and batch 2 (27 changes, 69 locations, awaiting the
  spot-check) would take positives past 40.

## Files

- `table.py`: the build (worktree per change, full checkout, producers, labels, gates, screen).
- `summary.json`, `separation.csv`, `screen.csv`, `separation_deletion_rows.csv`, `leak_audit.csv`, `log.json`
  (per-change seconds and rows; the slowest ordinary change of shopper took 2,407 s in the repository-wide
  caller scan), `ablation.json`.
- Table: `~/ousast-results/valid/train/work/ac-screen/table.jsonl` (94 MB) and `table_folds.jsonl`; builds 1 and
  2 kept beside it as `ac-screen-v1` and `ac-screen-v2-refused`.
