# Use case: catch, prove, fix, re-verify

The tool closes the loop on a security regression. It finds the problem in your
change, proves it with a reproducible check, and after the fix re-runs that same
check to confirm the problem is gone. The proof becomes a regression test. It
does not write the patch for you; it hands you a failing check and a repair
direction, and your fix is confirmed when the check turns green.

## The loop

1. **Catch.** On the changed code, the static arm flags a likely regression with
   a location and a repair direction.
2. **Prove.** Where the app is runnable, the proof arm builds and runs it and
   demonstrates the issue: a check that triggers the effect on the current code.
3. **Fix.** You, or a coding agent, write the fix against the repair direction
   and the failing check. The tool does not generate the patch.
4. **Re-verify absence.** The same proof is re-run against the fixed code. It no
   longer triggers. That is the bug's absence demonstrated by execution, not a
   claim that it "looks fixed."
5. **Keep it.** The proof is a regression test. Commit it and the fix stays fixed.

## What "re-verify absence" means, precisely

A demonstrated finding is a differential: the proof triggers the effect on the
vulnerable code and does not on the fixed code. Re-verifying a fix is the same
operation run against your new revision. No effect means the specific issue the
proof captured is gone. It does not claim the code is secure in general; it
confirms that this proven issue no longer reproduces. That scoping is the point:
it is honest about exactly what it checked.

## What it does and does not do

- It produces a repair direction and a failing proof, not an auto-generated patch.
- It re-verifies the fix by re-running the proof; the verifier already runs a
  demo against a given revision, so this is the existing mechanism, not a new one.
- Families without a runnable proof (for example access control or configuration)
  get the catch and the repair direction but no execution proof, and are advisory
  only.

## In CI, with GitHub Actions

`ousast pre-push . --base <rev> --head <rev> --deadline <seconds>` runs an
explicit base-versus-head check, which is what an Action calls on a pull request.
The example below is reference material, not an active workflow in this repo.

```yaml
# .github/workflows/pre-push-security.yml  (example; adapt and enable in your repo)
name: pre-push security
on:
  pull_request:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0            # base and head must both be present
      - name: Install OpenUltraSAST
        run: pipx install openultrasast   # or your pinned distribution
      - name: Check the diff
        env:
          # model keys and spend caps, if the proof arm is used, come from secrets
          DEEPSEEK_API_KEY: ${{ secrets.DEEPSEEK_API_KEY }}
        run: |
          ousast pre-push . \
            --base "origin/${{ github.base_ref }}" \
            --head "${{ github.sha }}" \
            --deadline 300 \
            --mode advisory \
            --artifact "$GITHUB_WORKSPACE/pre-push.json"
      - name: Comment findings on the PR
        if: always()
        run: |
          # Placeholder: read pre-push.json and post the finding, its proof and the
          # repair direction as a PR comment. This formatter is not packaged yet
          # (see Honest status); wire your own, e.g. with gh pr comment.
          cat "$GITHUB_WORKSPACE/pre-push.json"
```

The intended flow on a repository:

- A pull request scans base to head. A demonstrated finding is posted as a PR
  comment with its proof and repair direction, the evidence a developer takes to
  a product owner to win capacity.
- The fix pull request re-runs the check. The proof flips from failing to
  passing, which is the fix confirmed.
- The proof is committed as a regression test so the issue cannot return
  unnoticed.

## Honest status

Re-verify by execution and the `--base/--head` entry point exist today. The
turnkey pieces around them are delivery work, not detection: the PR-comment
formatter and the automatic landing of a proof as a committed regression test are
not packaged yet, and the base-versus-head path inherits the open large-repo
latency limit, so a long deadline or a cluster lane may be needed on big diffs.
The full-repository CI scan (as opposed to a diff) is roadmap work
(`plane-on-kubernetes`), not the pre-push diff path shown here.
