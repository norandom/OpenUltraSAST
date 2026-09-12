"""Resolve supplied push tips using local Git objects, never the live checkout.

No fetch, replacement objects, checkout, filters or project commands are used.
Materialization and changed spans are separate subsequent snapshot-adapter tasks.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import replace
from pathlib import Path

from openultrasast.push.contracts import PushComparison, PushResolution, PushUpdate, UpdateResolution


class SnapshotInputError(ValueError):
    """Malformed protocol input or an unavailable repository, never an empty success."""


class SnapshotAdapter:
    def __init__(self, repository: Path, *, comparison_base: str | None = None) -> None:
        self.repository = repository.resolve()
        self.comparison_base = comparison_base
        # Hook-inherited Git variables may redirect objects or worktrees elsewhere.
        self._env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self._env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
                         GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_ALLOW_PROTOCOL="", GIT_OPTIONAL_LOCKS="0",
                         GIT_GRAFT_FILE=os.devnull)
        self.object_format = self._required("rev-parse", "--show-object-format=storage")
        # Ask the installed Git for its object ID width rather than assuming SHA-1.
        self._oid_width = len(self._required("hash-object", "--stdin", input=""))
        self._zero = "0" * self._oid_width

    def _git(self, *args: str, input: str | None = None) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                ["git", "-c", "protocol.allow=never", "-c", "core.hooksPath=" + os.devnull,
                 "-C", str(self.repository), *args],
                input=input, capture_output=True, text=True, encoding="utf-8", errors="surrogateescape",
                env=self._env, timeout=10, check=False,
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
            if any(re.fullmatch(r"[0-9a-f]{" + str(self._oid_width) + r"}", oid) is None
                   for oid in (local_oid, remote_oid)):
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
            return UpdateResolution(update, "missing_target" if kind == "missing" else "unsupported_target",
                                    None, None, "target_not_a_local_commit")
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
            return UpdateResolution(update, "missing_base" if kind == "missing" else "unsupported_base",
                                    head, None, "configured_base_not_a_local_commit")
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
