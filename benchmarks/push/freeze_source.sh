#!/usr/bin/env bash
# Export the COMMITTED source into a FRESH immutable directory, and prove the export is whole.
#
# Every long run here mounts src into a container. Mounting the working tree is a live mount: edits
# made during a multi-hour run are picked up mid-run, and a measurement whose code changed underneath
# it is not a measurement of anything -- the failure looks exactly like the thing being measured
# failing. A five-hour PHP transfer replay was lost that way on 2026-09-22.
#
# The path is MINTED here, never taken from the caller, so a second freeze can never rm -rf a
# directory a running container is mounting -- which happened once, deleting taint.sc out from under
# a live scan and printing "no such cpg query" for every request after. Reuse is impossible by
# construction: each call gets its own <base>/frozen-<commit>-<pid>-<n>.
#
# The export is checked too. `git archive | tar -x` once produced a tree missing the whole ontology
# (every tracked file after `groovy` alphabetically) and reported success, because tar's status in a
# pipeline was never read. So: archive to a file, extract, count against git, require the ontology.
#
# Usage: DEST=$(benchmarks/push/freeze_source.sh <base-dir>)   -> prints the minted path on success
set -euo pipefail
base="${1:?base directory}"
mkdir -p "$base"
commit=$(git rev-parse --short HEAD)
n=0
while :; do
  dest="$base/frozen-$commit-$$-$n"
  if mkdir "$dest" 2>/dev/null; then break; fi
  n=$((n + 1))
done
git archive HEAD src benchmarks > "$dest.tar"
tar -xf "$dest.tar" -C "$dest"
rm -f "$dest.tar"
want=$(git ls-files src benchmarks | wc -l)
have=$(find "$dest" -type f | wc -l)
if [ "$want" -ne "$have" ]; then
  echo "TRUNCATED export: git tracks $want files, export holds $have" >&2
  exit 1
fi
test -d "$dest/src/openultrasast/ruleset/semantic" || { echo "export lacks the ontology" >&2; exit 1; }
echo "$dest"
