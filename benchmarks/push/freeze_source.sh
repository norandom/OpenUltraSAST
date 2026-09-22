#!/usr/bin/env bash
# Export the COMMITTED source for a long measurement run, and prove the export is whole.
#
# Every long run here mounts src into a container. Mounting the working tree is a live mount: edits
# made during a multi-hour run are picked up mid-run, and a measurement whose code changed underneath
# it is not a measurement of anything -- the failure looks exactly like the thing being measured
# failing. A five-hour PHP transfer replay was lost that way on 2026-09-22.
#
# And the export has to be checked. `git archive | tar -x` once produced a tree missing the whole
# ontology (every tracked file after `groovy` alphabetically) and reported success, because tar's
# status in a pipeline was never read. Every scan on that tree died at its first fact load and looked
# like a slow run for fourteen minutes. So: archive to a file, extract, count against git.
#
# Usage: benchmarks/push/freeze_source.sh <dest-dir>   -> prints the frozen commit on success
set -euo pipefail
dest="${1:?destination directory}"
rm -rf "$dest" && mkdir -p "$dest"
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
echo "$(git rev-parse --short HEAD) $have files"
