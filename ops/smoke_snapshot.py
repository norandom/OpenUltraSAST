"""Check packaged Git snapshot preparation; no graph, detector or hook-latency claim."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from openultrasast.model.contracts import ExecutionBudget
from openultrasast.push.snapshot import SnapshotAdapter


def main() -> None:
    assert os.getuid() != 0, "exercise the shipped non-root runtime"
    with tempfile.TemporaryDirectory(prefix="ousast-push-smoke-") as temporary:
        repo = Path(temporary) / "repository"
        repo.mkdir()

        def git(*args: str) -> bytes:
            return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=10).stdout

        def commit(message: str) -> str:
            git("add", ".")
            git("commit", "-m", message)
            return git("rev-parse", "HEAD").decode().strip()

        git("init")
        git("config", "user.name", "Snapshot smoke")
        git("config", "user.email", "snapshot@example.invalid")
        git("config", "core.hooksPath", os.devnull)
        before = (
            b"function before(req, res) {\n  if (!authorized(req)) return;\n"
            b"  const input = req.body;\n  const value = input.value;\n  res.send(value);\n}\n"
        )
        after = before.replace(b"function before", b"function after").replace(b"  if (!authorized(req)) return;\n", b"")
        php = b"<?php\nfunction handler($req) { return $req; }\n"
        (repo / "old-api.js").write_bytes(before)
        (repo / "handler.php").write_bytes(php)
        (repo / "package.json").write_bytes(b'{"type":"commonjs"}\n')
        base = commit("base")
        (repo / "old-api.js").unlink()
        (repo / "api.js").write_bytes(after)
        (repo / "package.json").write_bytes(b'{"type":"module"}\n')
        head = commit("pushed change")
        (repo / "api.js").write_bytes(b"different checked-out commit\n")
        checked = commit("checked-out revision")
        (repo / "api.js").write_bytes(b"uncommitted content\n")
        status = git("status", "--porcelain=v1", "-z")
        index = (repo / ".git/index").read_bytes()

        started = time.monotonic()
        budget = ExecutionBudget(started + 120, 2)
        adapter = SnapshotAdapter(repo)
        resolution = adapter.resolve_updates(f"refs/heads/topic {head} refs/heads/topic {base}\n")
        (comparison,) = resolution.comparisons
        assert comparison.head_oid == head and comparison.base_oid == base
        with adapter.materialize(head, budget=budget) as snapshot:
            scratch = snapshot.root
            assert snapshot.manifest.complete
            assert (scratch / "api.js").read_bytes() == after
            assert (scratch / "handler.php").read_bytes() == php
            assert snapshot.manifest.bytes_read == len(after) + len(php) + len(b'{"type":"module"}\n')
            context = adapter.compare(comparison, declaration_paths=(b"package.json",), budget=budget)
            assert context.base_revision == base and context.head_revision == head
            assert any(
                context.decode_path(item.base_path) == "old-api.js" and context.decode_path(item.head_path) == "api.js"
                for item in context.renames
            )
            assert any(context.decode_path(item.path) == "old-api.js" and item.side == "base" for item in context.spans)
            assert "package.json" in tuple(map(context.decode_path, context.declaration_paths))
        assert not scratch.exists()
        assert git("status", "--porcelain=v1", "-z") == status
        assert (repo / ".git/index").read_bytes() == index
        assert git("rev-parse", "HEAD").decode().strip() == checked
        assert (repo / "api.js").read_bytes() == b"uncommitted content\n"
        print(
            json.dumps(
                {
                    "purpose": "packaged snapshot and change-context smoke, not vulnerability detection or hook latency",
                    "uid": os.getuid(),
                    "git_version": git("--version").decode().strip(),
                    "source_bytes": {"javascript": len(after), "php": len(php)},
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "snapshot_complete": snapshot.manifest.complete,
                    "live_state_preserved": True,
                    "scratch_removed": True,
                    "change_context": context.to_payload(),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
