# Requirements: valid detection benchmark

Turns `brief.md` into testable requirements. The brief supersedes the retired SZZ pool
(`unseen-repo-evaluation`). This spec builds a benchmark with sound ground truth and standard
security metrics.

## Scope decisions (resolving the brief's open questions)

- **First-slice size.** Build a pilot of 10 to 12 verified positives end to end first, to prove the
  pipeline, then grow to a target of about 40 verified positives. 40 gives a recall interval of roughly
  ±0.10 at a true recall near 0.85 to 0.90; `score.py:required_n(p, width)` computes the exact number,
  so the target is set from that, not guessed.
- **Negative-to-positive ratio.** At least 20 ordinary commits per positive, drawn from the same repos.
  Negatives are free to collect, and false alarms decide adoption, so err large. Report false alarms as
  a rate per 100 pushes.
- **Languages first.** Python and JavaScript/TypeScript web applications (Flask, Django, FastAPI,
  Express, Koa). These are where the tool is strongest and where in-repo entry points are clear. PHP and
  others come later, named explicitly as not yet covered.
- **Curation record.** Each case stores the advisory, repo, fix commit, parent, path, function, the
  pre-fix and post-fix excerpts, the LLM verdict with confidence, and the human spot-check decision with
  reviewer and date. The set is frozen with a digest, the same way `advisory-fixes/` freezes its pairs.
- **Lane.** Curate and score locally on the Docker lane (research is local execution). The kube `ax`
  lane stays the scale target but is not required here and is still blocked on the gVisor checkpoint path.

## Requirements

### R1. Positives labelled from the fix, never from SZZ
- Take the vulnerability location from the security fix: the file and function the fix changed, read at
  the parent commit (pre-fix).
- Do not run SZZ blame walk-back. The sourcing must not use `extract.py`'s `introducing` or `last_touch`
  methods. Use the fix site directly (`fix_sites()`) and first-parent history only.
- Each positive is a pair: the vulnerable function at `parent`, and the same function at the fix commit.

### R2. App-shaped and reachable in-repo
- Keep a positive only if the vulnerability is reachable from an entry point inside the repo: a web
  route, a request handler, or a CLI argument.
- Drop library-internal cases whose trigger depends on a caller outside the repo. A pre-push tool cannot
  see that trust boundary, so scoring it there is unfair.

### R3. Every positive is verified
- Verify each case with an LLM adjudication call and a human spot-check. The call must confirm:
  (a) the pre-fix code is vulnerable, (b) the fix addresses it, (c) it is reachable from an in-repo entry
  point.
- Record the verdict, the confidence, and the human decision. A case that fails any of (a), (b), (c), or
  the human spot-check does not enter the benchmark.

### R4. Negatives are ordinary commits from the same repos
- Draw non-fix commits from the first-parent history of the same application repos, excluding the fix.
- The negative set is at least 20x the positive set.

### R5. Held out
- No repository in the benchmark was used to build, train, tune, mine, or harvest the tool. Enforce this
  with the existing used-set canonicalization (`eligibility.normalize`), the same guard the SZZ pool used.

### R6. Measure the whole tool on unseen repos
- Run the tool as a developer runs it at push time: quick rules on, engine on, LLM-guided arm on.
- Use the existing replay harness so the measured path is the shipped push hook.

### R7. Standard metrics
- Report recall (true-positive rate), precision (positive predictive value), false-positive rate as
  false alarms per 100 pushes, and exploit-verified rate (the share of flagged positives the proof arm
  demonstrates with a working proof of concept).
- Report recall with a Wilson 95% interval and a repo-clustered interval, reusing `score.py`.
- The headline pairs recall and false alarms per 100 pushes in one plain sentence.

### R8. Reproducible and frozen
- The positive catalog, the negative draw, and the held-out guarantee are frozen with digests so a run is
  reproducible. Re-running the freeze on an unchanged source yields the same digest.

## Non-goals
- No SZZ, no frozen-pool catch/false-alarm numbers (retired).
- No new detection capability in this spec. This measures the tool that exists.
- Not required to run on kube `ax` to be valid; the Docker lane is enough for the first numbers.

## Acceptance
- A frozen pilot of at least 10 verified positives plus their negatives, on held-out Python/JS repos,
  run through the whole tool, producing recall, precision, false alarms per 100 pushes, and
  exploit-verified rate, with intervals. Every positive has an LLM verdict and a human spot-check on
  record.
