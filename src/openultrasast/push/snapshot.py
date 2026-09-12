"""Resolve supplied push tips using local Git objects, never the live checkout.

No fetch, replacement objects, checkout, filters or project commands are used.
Snapshots and change evidence come from exact tracked objects, not working-tree files.
"""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path

from openultrasast.model.contracts import (
    ChangeContext,
    ChangedSpan,
    ExecutionBudget,
    LineCorrespondence,
    PathRename,
)
from openultrasast.push.contracts import (
    PushComparison,
    PushResolution,
    PushUpdate,
    SnapshotBoundary,
    SnapshotFile,
    SnapshotManifest,
    UpdateResolution,
)


class SnapshotInputError(ValueError):
    """Malformed protocol input or an unavailable repository, never an empty success."""


class SnapshotAdapter:
    def __init__(self, repository: Path, *, comparison_base: str | None = None) -> None:
        self.repository = repository.resolve()
        self.comparison_base = comparison_base
        # Hook-inherited Git variables may redirect objects or worktrees elsewhere.
        self._env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self._env.update(
            GIT_NO_REPLACE_OBJECTS="1",
            GIT_NO_LAZY_FETCH="1",
            GIT_TERMINAL_PROMPT="0",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_ALLOW_PROTOCOL="",
            GIT_OPTIONAL_LOCKS="0",
            GIT_GRAFT_FILE=os.devnull,
        )
        self.object_format = self._required("rev-parse", "--show-object-format=storage")
        # Ask the installed Git for its object ID width rather than assuming SHA-1.
        self._oid_width = len(self._required("hash-object", "--stdin", input=""))
        self._zero = "0" * self._oid_width
        self._git_dir = self._repository_path("--absolute-git-dir")
        self._common_dir = self._repository_path("--path-format=absolute", "--git-common-dir")
        try:
            self._worktree = self._repository_path("--show-toplevel")
        except SnapshotInputError:
            self._worktree = self.repository  # Bare repositories have no working tree.

    def _repository_path(self, *args: str) -> Path:
        # Binary framing also matters for the repository's own whitespace/non-UTF8 name.
        raw = self._bounded_git(("rev-parse", *args), 65536, ExecutionBudget(time.monotonic() + 10.0, 2.0), None, [])
        return Path(os.fsdecode(raw.removesuffix(b"\n"))).resolve()

    def _git(self, *args: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", "-c", "protocol.allow=never", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.repository), *args],
                input=input,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="surrogateescape",
                env=self._env,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise SnapshotInputError(f"local Git resolution failed: {type(error).__name__}") from error

    def _required(self, *args: str, input: str | None = None) -> str:
        result = self._git(*args, input=input)
        if result.returncode:
            raise SnapshotInputError(f"local Git {args[0]} failed (exit {result.returncode})")
        return result.stdout.strip()

    def parse_updates(self, data: str) -> tuple[PushUpdate, ...]:
        """Validate every record before attempting resolution; malformed input fails closed."""
        updates = []
        # Git frames records with ASCII LF and fields with ASCII SP. Unicode
        # whitespace is legal inside refs and must never be stripped or split.
        records = data.split("\n") if data else []
        if records and records[-1] == "":
            records.pop()
        for number, record in enumerate(records, 1):
            parts = record.split(" ")
            if len(parts) != 4 or any(not part for part in parts) or any(ord(char) < 32 for char in record):
                raise SnapshotInputError(f"invalid pre-push update at line {number}")
            local_ref, local_oid, remote_ref, remote_oid = parts
            if any(re.fullmatch(r"[0-9a-f]{" + str(self._oid_width) + r"}", oid) is None for oid in (local_oid, remote_oid)):
                raise SnapshotInputError(f"invalid {self.object_format} object ID at line {number}")
            if self._git("check-ref-format", remote_ref).returncode or not remote_ref.startswith("refs/"):
                raise SnapshotInputError(f"invalid destination ref at line {number}")
            if (local_ref == "(delete)") != (local_oid == self._zero) or (local_oid == remote_oid == self._zero):
                raise SnapshotInputError(f"invalid deletion update at line {number}")
            updates.append(PushUpdate(*parts))
        return tuple(updates)

    def _commit(self, oid: str) -> tuple[str | None, str]:
        seen: set[str] = set()
        while oid not in seen:
            seen.add(oid)
            kind = self._git("cat-file", "-t", oid)
            if kind.returncode:
                return None, "missing"
            object_type = kind.stdout.strip()
            if object_type not in ("commit", "tag"):
                return None, "unsupported"
            content = self._git("cat-file", object_type, oid)
            if content.returncode:
                return None, "missing"
            if object_type == "commit":
                return oid, "commit"
            first = content.stdout.splitlines()[0] if content.stdout else ""
            if re.fullmatch(r"object [0-9a-f]{" + str(self._oid_width) + r"}", first) is None:
                return None, "unsupported"
            oid = first.removeprefix("object ")
        return None, "unsupported"

    def _resolve(self, update: PushUpdate) -> UpdateResolution:
        if update.local_oid == self._zero:
            return UpdateResolution(update, "deleted", None, None, "ref_deleted_no_analysis")
        head, kind = self._commit(update.local_oid)
        if head is None:
            return UpdateResolution(
                update, "missing_target" if kind == "missing" else "unsupported_target", None, None, "target_not_a_local_commit"
            )
        if update.remote_oid != self._zero:
            base, kind = self._commit(update.remote_oid)
            disposition = "ready" if base else ("missing_base" if kind == "missing" else "unsupported_base")
            return UpdateResolution(update, disposition, head, base, "supplied_remote_tip")  # type: ignore[arg-type]
        reason = "configured_unique_merge_base"
        if not self.comparison_base:
            return UpdateResolution(update, "missing_base", head, None, "new_ref_no_configured_base")
        configured = self._git("rev-parse", "--verify", "--end-of-options", self.comparison_base)
        if configured.returncode:
            return UpdateResolution(update, "missing_base", head, None, "configured_base_unavailable")
        anchor, kind = self._commit(configured.stdout.strip())
        if anchor is None:
            return UpdateResolution(
                update, "missing_base" if kind == "missing" else "unsupported_base", head, None, "configured_base_not_a_local_commit"
            )
        reason += ":" + anchor
        merged = self._git("merge-base", "--all", anchor, head)
        if merged.returncode not in (0, 1):
            return UpdateResolution(update, "resolution_error", head, None, reason)
        bases = merged.stdout.splitlines()
        if len(bases) != 1:
            return UpdateResolution(update, "ambiguous_base" if bases else "no_merge_base", head, None, reason)
        base, kind = self._commit(bases[0])
        return UpdateResolution(update, "ready" if base else "missing_base", head, base, reason)

    def resolve_updates(self, data: str) -> PushResolution:
        updates = self.parse_updates(data)
        records: list[UpdateResolution] = []
        comparisons: list[PushComparison] = []
        targets: list[str] = []
        for update in updates:
            try:
                record = self._resolve(update)
            except SnapshotInputError:
                record = UpdateResolution(update, "resolution_error", None, None, "local_git_resolution_failed")
            records.append(record)
            if record.head_oid is None:
                continue
            if record.head_oid not in targets:
                targets.append(record.head_oid)
            # Choice provenance is part of comparison identity, not just the target graph.
            key = (record.head_oid, record.base_oid, record.base_reason)
            for index, comparison in enumerate(comparisons):
                if (comparison.head_oid, comparison.base_oid, comparison.base_reason) == key:
                    if update.remote_ref not in comparison.refs:
                        comparisons[index] = replace(comparison, refs=(*comparison.refs, update.remote_ref))
                    break
            else:
                comparisons.append(PushComparison(*key, refs=(update.remote_ref,)))
        return PushResolution(self.object_format, tuple(records), tuple(comparisons), tuple(targets))

    def compare(
        self,
        comparison: PushComparison,
        *,
        declaration_paths: tuple[bytes, ...] | None = None,
        budget: ExecutionBudget | None = None,
        limits: SnapshotLimits | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ChangeContext:
        """Supply bounded lexical change evidence, never select analysis scope.

        Change paths, spans, renames and line anchors use raw path hex. Canonical
        question paths in relationships retain their own encoding. Declarations are
        supplied by project discovery (including configuration/manifests); None
        records unknown coverage. Unchanged-line anchors are not function identity
        or security proof. Semantic relationships belong to frontend/ranker work.
        """
        budget = budget or ExecutionBudget(time.monotonic() + 30.0, 2.0)
        limits = limits or SnapshotLimits()
        if declaration_paths is not None and (
            type(declaration_paths) is not tuple or any(type(p) is not bytes or not p or b"\0" in p for p in declaration_paths)
        ):
            raise ValueError("declaration paths must be a tuple of raw nonempty Git paths")
        boundaries = ["declaration_paths_unavailable"] if declaration_paths is None else []
        changed: list[str] = []
        deleted: list[str] = []
        spans: list[ChangedSpan] = []
        renames: list[PathRename] = []
        mappings: list[LineCorrespondence] = []
        cleanup: list[float] = []
        total_bytes = 0
        remaining_diff = limits.max_diff_bytes
        remaining_lines = limits.max_mapping_lines
        try:
            if comparison.base_oid is None:
                raise SnapshotInputError("comparison_base_unavailable")
            for oid in (comparison.base_oid, comparison.head_oid):
                if re.fullmatch(r"[0-9a-f]{" + str(self._oid_width) + r"}", oid) is None:
                    raise SnapshotInputError("comparison_requires_immutable_commit_oid")
                if self._bounded_git(("cat-file", "-t", oid), 64, budget, cancelled, cleanup) != b"commit\n":
                    raise SnapshotInputError("comparison_requires_commit_objects")
            raw = self._bounded_git(
                (
                    "diff-tree",
                    "-r",
                    "--no-commit-id",
                    "--raw",
                    "-z",
                    "--no-abbrev",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-relative",
                    "--ignore-submodules=none",
                    "--find-renames=50%",
                    "-l1000",
                    comparison.base_oid,
                    comparison.head_oid,
                    "--",
                ),
                min(limits.max_tree_bytes, remaining_diff),
                budget,
                cancelled,
                cleanup,
            )
            remaining_diff -= len(raw)
            records = _diff_records(raw, limits.max_files)
            statuses = {record[4] for record in records}
            if {"A", "D"} <= statuses:
                # Rename thresholds/limits can leave a moved declaration as A+D.
                # Absence of a Git pairing is not proof of unrelated/new behavior.
                boundaries.append("unmatched_added_deleted_path_correspondence")
            old_blob_counts = Counter(record[2] for record in records if record[4] != "A")
            new_blob_counts = Counter(record[3] for record in records if record[4] != "D")
            for mode_base, mode_head, oid_base, oid_head, status, path_base, path_head in records:
                _check_budget(budget, cancelled)
                paths = tuple(p for p in (path_base, path_head) if p is not None)
                for path in paths:
                    if path.hex() not in changed:
                        changed.append(path.hex())
                if status == "D":
                    assert path_base is not None
                    deleted.append(path_base.hex())
                if status == "R":
                    assert path_base is not None and path_head is not None
                    renames.append(PathRename(path_base.hex(), path_head.hex()))
                label = (path_head or path_base or b"?").hex()
                ambiguous_rename = status == "R" and (old_blob_counts[oid_base] > 1 or new_blob_counts[oid_head] > 1)
                if ambiguous_rename:
                    boundaries.append(label + ":ambiguous_path_rename_correspondence")
                try:
                    if any(len(p) > limits.max_path_bytes or len(p.split(b"/")) > limits.max_path_depth for p in paths):
                        raise SnapshotInputError("unsupported_path")
                    contents: list[bytes] = []
                    for mode, oid in ((mode_base, oid_base), (mode_head, oid_head)):
                        if mode == "000000":
                            contents.append(b"")
                            continue
                        if mode not in ("100644", "100755"):
                            raise SnapshotInputError("unsupported_diff_entry")
                        size = int(self._bounded_git(("cat-file", "-s", oid), 64, budget, cancelled, cleanup))
                        if size < 0 or size > min(limits.max_blob_bytes, limits.max_total_bytes - total_bytes):
                            raise SnapshotInputError("source_byte_limit")
                        data = self._bounded_git(("cat-file", "blob", oid), size, budget, cancelled, cleanup)
                        if (
                            len(data) != size
                            or hashlib.new(self.object_format, b"blob " + str(size).encode() + b"\0" + data).hexdigest() != oid
                        ):
                            raise SnapshotInputError("blob_identity_mismatch")
                        total_bytes += size
                        if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                            raise SnapshotInputError("lfs_content_unavailable")
                        if b"\0" in data:
                            raise SnapshotInputError("binary_line_correspondence_unavailable")
                        contents.append(data)
                    before, after = contents
                    # LF is the only source-line delimiter; Unicode and CR remain data.
                    line_count = sum(data.count(b"\n") + int(bool(data) and not data.endswith(b"\n")) for data in (before, after))
                    if line_count > remaining_lines:
                        raise SnapshotInputError("line_mapping_limit")
                    remaining_lines -= line_count
                    old_lines, new_lines = _source_lines(before), _source_lines(after)
                    if path_base is None:
                        if new_lines:
                            spans.append(ChangedSpan(label, 1, len(new_lines), "head"))
                        continue
                    if path_head is None:
                        if old_lines:
                            spans.append(ChangedSpan(label, 1, len(old_lines), "base"))
                        continue
                    patch = self._bounded_git(
                        (
                            "diff",
                            "--no-ext-diff",
                            "--no-textconv",
                            "--no-color",
                            "--no-relative",
                            "--text",
                            "--unified=0",
                            "--inter-hunk-context=0",
                            "--diff-algorithm=myers",
                            "--no-indent-heuristic",
                            oid_base,
                            oid_head,
                            "--",
                        ),
                        remaining_diff,
                        budget,
                        cancelled,
                        cleanup,
                    )
                    remaining_diff -= len(patch)
                    hunks = [
                        (int(a), int(b) if b else 1, int(c), int(d) if d else 1)
                        for a, b, c, d in re.findall(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", patch, re.M)
                    ]
                    if before != after and not hunks:
                        raise SnapshotInputError("diff_hunks_unavailable")
                    pairs: list[tuple[int, int]] = []
                    old_cursor = new_cursor = 0
                    for old_start, old_count, new_start, new_count in hunks:
                        # Git uses the preceding line for a zero-width edit interval.
                        old_index = old_start - 1 if old_count else old_start
                        new_index = new_start - 1 if new_count else new_start
                        if (
                            old_index < old_cursor
                            or new_index < new_cursor
                            or old_index + old_count > len(old_lines)
                            or new_index + new_count > len(new_lines)
                        ):
                            raise SnapshotInputError("invalid_diff_hunks")
                        pairs.extend(_equal_line_pairs(old_lines, new_lines, old_cursor, old_index, new_cursor, new_index))
                        if old_count:
                            spans.append(ChangedSpan(path_base.hex(), old_start, old_start + old_count - 1, "base"))
                        if new_count:
                            spans.append(ChangedSpan(path_head.hex(), new_start, new_start + new_count - 1, "head"))
                        old_cursor, new_cursor = old_index + old_count, new_index + new_count
                    pairs.extend(_equal_line_pairs(old_lines, new_lines, old_cursor, len(old_lines), new_cursor, len(new_lines)))
                    old_counts, new_counts = Counter(old_lines), Counter(new_lines)
                    ambiguous = False
                    for old_index, new_index in () if ambiguous_rename else pairs:
                        _check_budget(budget, cancelled)
                        content = old_lines[old_index]
                        if old_counts[content] != 1 or new_counts[content] != 1:
                            ambiguous = True
                            continue
                        mappings.append(LineCorrespondence(path_base.hex(), path_head.hex(), old_index + 1, old_index + 1, new_index + 1))
                    if ambiguous:
                        boundaries.append(label + ":ambiguous_line_correspondence")
                    if before and after and not any(m.base_path == path_base.hex() for m in mappings):
                        boundaries.append(label + ":line_correspondence_unavailable")
                except (SnapshotInputError, ValueError) as error:
                    boundaries.append(label + ":" + str(error))
                    if str(error) in ("deadline_exhausted", "cancelled", "git_cleanup_deadline_exhausted"):
                        break
        except (SnapshotInputError, ValueError) as error:
            boundaries.append(str(error))
        declared = {p.hex() for p in declaration_paths or ()}
        return ChangeContext(
            comparison.base_oid,
            comparison.head_oid,
            tuple(changed),
            tuple(deleted),
            tuple(spans),
            tuple(renames),
            tuple(p for p in changed if p in declared),
            (),
            tuple(boundaries),
            "filesystem-bytes-hex",
            tuple(mappings),
        )

    @contextmanager
    def materialize(
        self,
        commit_oid: str,
        *,
        budget: ExecutionBudget | None = None,
        limits: SnapshotLimits | None = None,
        scratch_parent: Path | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Iterator[MaterializedSnapshot]:
        """Own one disposable tracked-object tree, with no checkout/filter execution.

        Partial manifests are usable only for diagnostics/explicit partial analysis.
        Scratch is removed on normal return and exceptions, including cancellation.
        """
        budget = budget or ExecutionBudget(time.monotonic() + 30.0, 2.0)
        limits = limits or SnapshotLimits()
        if re.fullmatch(r"[0-9a-f]{" + str(self._oid_width) + r"}", commit_oid) is None:
            raise SnapshotInputError("snapshot requires a full immutable commit OID")
        parent = (scratch_parent or Path(tempfile.gettempdir())).resolve()
        if any(parent == root or root in parent.parents for root in (self.repository, self._worktree, self._git_dir, self._common_dir)):
            raise SnapshotInputError("scratch parent must be outside the checkout and Git metadata")
        _check_budget(budget, cancelled)
        cleanup_deadline: list[float] = []
        root = Path(tempfile.mkdtemp(prefix="ousast-snapshot-", dir=parent))
        files: list[SnapshotFile] = []
        boundaries: list[SnapshotBoundary] = []
        total = 0
        tree_complete = False
        try:
            try:
                if self._bounded_git(("cat-file", "-t", commit_oid), 64, budget, cancelled, cleanup_deadline) != b"commit\n":
                    raise SnapshotInputError("unsupported_snapshot_object")
                listing = self._bounded_git(
                    ("ls-tree", "-r", "-z", "--full-tree", commit_oid), limits.max_tree_bytes, budget, cancelled, cleanup_deadline
                )
                records = listing.split(b"\0")
                if records[-1] != b"":
                    raise SnapshotInputError("truncated_tree_metadata")
                records.pop()
                if len(records) > limits.max_files:
                    raise SnapshotInputError("file_count_limit")
                tree_complete = True
                for record in records:
                    _check_budget(budget, cancelled)
                    metadata, path = record.split(b"\t", 1)
                    mode, kind, oid = metadata.split(b" ")
                    path_hex = path.hex()
                    components = path.split(b"/")
                    if (
                        not path
                        or path.startswith(b"/")
                        or any(part in (b"", b".", b"..") for part in components)
                        or len(path) > limits.max_path_bytes
                        or len(components) > limits.max_path_depth
                        or any(part.lower() == b".git" for part in components)
                    ):
                        boundaries.append(SnapshotBoundary(path_hex or None, "unsupported_path"))
                        continue
                    if mode == b"120000":
                        boundaries.append(SnapshotBoundary(path_hex, "symlink_not_materialized"))
                        continue
                    if mode == b"160000":
                        boundaries.append(SnapshotBoundary(path_hex, "gitlink_not_materialized"))
                        continue
                    if kind != b"blob" or mode not in (b"100644", b"100755"):
                        boundaries.append(SnapshotBoundary(path_hex, "unsupported_tree_entry"))
                        continue
                    blob_oid = oid.decode("ascii")
                    try:
                        size = int(self._bounded_git(("cat-file", "-s", blob_oid), 64, budget, cancelled, cleanup_deadline))
                        if size < 0 or size > limits.max_blob_bytes or size > limits.max_total_bytes - total:
                            raise SnapshotInputError("source_byte_limit")
                        data = self._bounded_git(("cat-file", "blob", blob_oid), size, budget, cancelled, cleanup_deadline)
                        if len(data) != size:
                            raise SnapshotInputError("blob_size_mismatch")
                        digest = hashlib.new(self.object_format, b"blob " + str(size).encode() + b"\0" + data).hexdigest()
                        if digest != blob_oid:
                            raise SnapshotInputError("blob_identity_mismatch")
                        total += size
                        if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
                            raise SnapshotInputError("lfs_content_unavailable")
                        target = root / os.fsdecode(path)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open("xb") as output:
                            output.write(data)
                        target.chmod(0o555 if mode == b"100755" else 0o444)
                        files.append(SnapshotFile(path_hex, blob_oid, mode.decode("ascii"), size, hashlib.sha256(data).hexdigest()))
                    except SnapshotInputError as error:
                        boundaries.append(SnapshotBoundary(path_hex, str(error)))
                        if str(error) in ("deadline_exhausted", "cancelled", "git_output_limit", "git_cleanup_deadline_exhausted"):
                            break
            except (SnapshotInputError, OSError, ValueError) as error:
                boundaries.append(SnapshotBoundary(None, str(error) or type(error).__name__))
            yield MaterializedSnapshot(
                root, SnapshotManifest(commit_oid, self.object_format, tuple(files), tuple(boundaries), tree_complete, total)
            )
        finally:
            _remove_scratch(root, _cleanup_deadline(budget, cleanup_deadline))

    def _bounded_git(
        self,
        args: tuple[str, ...],
        limit: int,
        budget: ExecutionBudget,
        cancelled: Callable[[], bool] | None,
        cleanup_deadline: list[float],
    ) -> bytes:
        _check_budget(budget, cancelled)
        command = ["git", "-c", "protocol.allow=never", "-c", "core.hooksPath=" + os.devnull, "-C", str(self.repository), *args]
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, env=self._env, start_new_session=True
            )
        except OSError as error:
            raise SnapshotInputError("git_launch_failed") from error
        output = bytearray()
        try:
            assert process.stdout is not None
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    _check_budget(budget, cancelled)
                    for key, _ in selector.select(min(0.05, max(0, budget.deadline_monotonic - time.monotonic()))):
                        chunk = os.read(key.fd, min(65536, limit - len(output) + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > limit:
                                raise SnapshotInputError("git_output_limit")
            while process.poll() is None:
                _check_budget(budget, cancelled)
                time.sleep(0.001)
            if process.returncode:
                raise SnapshotInputError(f"local_git_{args[0]}_failed_exit_{process.returncode}")
            return bytes(output)
        finally:
            # Kill the entire group even if its leader exited while a child held stdout.
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            if process.poll() is None:
                deadline = _cleanup_deadline(budget, cleanup_deadline)
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise SnapshotInputError("git_cleanup_deadline_exhausted") from error
            if process.stdout is not None:
                process.stdout.close()


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int = 10000
    max_total_bytes: int = 128 * 1024 * 1024
    max_blob_bytes: int = 8 * 1024 * 1024
    max_tree_bytes: int = 4 * 1024 * 1024
    max_path_bytes: int = 4095
    max_path_depth: int = 64
    max_diff_bytes: int = 8 * 1024 * 1024
    max_mapping_lines: int = 100000

    def __post_init__(self) -> None:
        for value in vars(self).values():
            if type(value) is not int or value <= 0:
                raise ValueError("snapshot limits must be positive integers")


@dataclass(frozen=True)
class MaterializedSnapshot:
    root: Path
    manifest: SnapshotManifest


def _check_budget(budget: ExecutionBudget, cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise SnapshotInputError("cancelled")
    if time.monotonic() >= budget.deadline_monotonic:
        raise SnapshotInputError("deadline_exhausted")


def _cleanup_deadline(budget: ExecutionBudget, recorded: list[float]) -> float:
    if not recorded:
        recorded.append(time.monotonic() + budget.cancellation_allowance_seconds)
    return recorded[0]


def _remove_scratch(root: Path, deadline: float) -> None:
    # Directory-relative, no-follow operations avoid deleting through substituted links.
    def remove_contents(descriptor: int) -> None:
        for name in os.listdir(descriptor):
            if time.monotonic() >= deadline:
                raise SnapshotInputError("scratch_cleanup_deadline_exhausted: " + str(root))
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    remove_contents(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=descriptor)
            else:
                os.unlink(name, dir_fd=descriptor)

    if root.is_symlink():
        root.unlink()
        return
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        remove_contents(descriptor)
    finally:
        os.close(descriptor)
    root.rmdir()


def _diff_records(raw: bytes, max_files: int) -> list[tuple[str, str, str, str, str, bytes | None, bytes | None]]:
    """Parse only NUL-framed raw metadata; quoted patch filenames are never parsed."""
    if raw and not raw.endswith(b"\0"):
        raise SnapshotInputError("truncated_diff_metadata")
    fields = iter(raw.split(b"\0")[:-1])
    result = []
    try:
        for metadata in fields:
            old_mode, new_mode, old_oid, new_oid, status = metadata.decode("ascii").split(" ")
            if not old_mode.startswith(":") or status[0] not in "ADMRT":
                raise SnapshotInputError("unsupported_diff_metadata")
            first = next(fields)
            if not first:
                raise SnapshotInputError("empty_diff_path")
            second = next(fields) if status.startswith("R") else first
            if not second:
                raise SnapshotInputError("empty_diff_path")
            result.append(
                (old_mode[1:], new_mode, old_oid, new_oid, status[0], None if status == "A" else first, None if status == "D" else second)
            )
            if len(result) > max_files:
                raise SnapshotInputError("file_count_limit")
    except (ValueError, StopIteration, IndexError) as error:
        raise SnapshotInputError("invalid_diff_metadata") from error
    return result


def _source_lines(data: bytes) -> list[bytes]:
    if not data:
        return []
    # Keep LF in each record so a final-newline change cannot look unchanged.
    lines = data.split(b"\n")
    return [line + b"\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])


def _equal_line_pairs(
    old: list[bytes], new: list[bytes], old_start: int, old_end: int, new_start: int, new_end: int
) -> list[tuple[int, int]]:
    if old[old_start:old_end] != new[new_start:new_end]:
        raise SnapshotInputError("diff_line_identity_mismatch")
    return [(old_start + offset, new_start + offset) for offset in range(old_end - old_start)]
