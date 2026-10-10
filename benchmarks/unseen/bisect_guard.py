"""Stage a cache draft, bisect with the black-box guard, and retain a digest receipt.

Coordinator: python -m benchmarks.unseen.bisect_guard --draft CACHE/draft-p1.toml
The cache is never changed. Successful subsets remain at benchmarks/unseen/draft-p1.toml
and private/draft-p1.toml; failures remove only this invocation's staging files.
Stdout reports only the dropped count. No reservation is opened by this module.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tomllib
from pathlib import Path

from .draft import manifest, private_digest
from .extract import InstrumentFailure
from .journal import atomic, digest
from .source import PERMISSIVE


def read_manifest(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        if not raw:
            raise ValueError
        data = tomllib.loads(raw.decode("utf-8"))
        if set(data) - {"status", "pool", "seed", "repository"}:
            raise ValueError
        if data["status"] != "draft" or data["pool"] != "p1" or type(data["seed"]) is not int:
            raise ValueError
        if not isinstance(data.get("repository", []), list):
            raise ValueError
        return data
    except (OSError, ValueError, KeyError, TypeError):
        raise InstrumentFailure("invalid_draft") from None


def read_pair(public_path: Path, private_path: Path) -> tuple[dict, dict]:
    """Validate the licensing split and every private pointer before staging names."""
    public, private = read_manifest(public_path), read_manifest(private_path)
    try:
        if public["seed"] != private["seed"]:
            raise ValueError
        hidden = {row["id"]: row for row in private.get("repository", [])}
        rows = public.get("repository", [])
        if len(hidden) != len(private.get("repository", [])) or len({r["id"] for r in rows}) != len(rows):
            raise ValueError
        if set(hidden) != {r["id"] for r in rows if r.get("private")}:
            raise ValueError
        # Slice IDs come from the draft; bisect may leave sparse slices.
        for row in rows:
            if type(row["slice"]) is not int or row["slice"] < 1:
                raise ValueError
            if row.get("private"):
                full = hidden[row["id"]]
                expected = {"id": full["id"], "slice": full["slice"], "private": True, "sha256": private_digest(full)}
                if row != expected or full["license_class"] != "private":
                    raise ValueError
            elif row["license_class"] != "permissive" or row["license_spdx"] not in PERMISSIVE:
                raise ValueError
        return public, private
    except (ValueError, KeyError, TypeError):
        raise InstrumentFailure("invalid_draft_pair") from None


def pytest_guard(root: Path) -> int:
    """Read only the exit code; never capture, inspect or forward either stream."""
    try:
        return subprocess.run(
            [".venv/bin/pytest", "-q", "-p", "no:cacheprovider", "tests/test_independent_population.py", "-k", "referenced"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    except OSError:
        raise InstrumentFailure("guard_launch") from None


def run(root: Path, draft: Path, *, private_draft: Path | None = None, guard_runner=None) -> dict:
    """Inject guard_runner(root) -> exit code for offline tests; default is pytest_guard.

    Run from an otherwise clean reservation directory. Existing staging/receipt or a
    frozen p1 is refused, so a crash cannot silently turn a partial subset into input.
    The receipt binds both retained manifests; freeze refuses edits after the guard.
    """
    private_draft = private_draft or draft.with_name("private-draft-p1.toml")
    public, private = read_pair(draft, private_draft)
    rows = public.get("repository", [])
    if not rows:
        raise InstrumentFailure("empty_draft")
    directory = root / "benchmarks/unseen"
    public_path = directory / "draft-p1.toml"
    private_path = directory / "private/draft-p1.toml"
    receipt_path = directory / "bisect-p1.json"
    targets = (private_path, public_path, receipt_path)
    if any(p.exists() for p in (*targets, directory / "pool-p1.toml", directory / "freeze-p1.json")):
        raise FileExistsError("staging_exists")
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    runner = guard_runner or pytest_guard
    created = []

    def check(subset):
        ids = {r["id"] for r in subset}
        selected = [r for r in private.get("repository", []) if r["id"] in ids]
        atomic(private_path, manifest(selected, private["seed"]).encode("utf-8"))
        atomic(public_path, manifest(subset, public["seed"]).encode("utf-8"))
        try:
            code = runner(root)
        except Exception:
            raise InstrumentFailure("guard_launch") from None
        if type(code) is not int or code not in (0, 1):
            raise InstrumentFailure("guard_exit")
        return code

    def retain(subset):
        if not subset or check(subset) == 0:
            return subset
        if len(subset) == 1:
            return []
        middle = len(subset) // 2
        return retain(subset[:middle]) + retain(subset[middle:])

    try:
        # Reserve destinations exclusively before any rewrites; never truncate an
        # existing coordinator's files. Empty manifests establish the control.
        for path in targets:
            with path.open("xb") as handle:
                created.append(path)
                os.fchmod(handle.fileno(), 0o600)
        if check([]) != 0:
            raise InstrumentFailure("guard_baseline")
        kept = retain(rows)
        if check(kept) != 0:
            raise InstrumentFailure("guard_final")
        result = {
            "guard_result": 0,
            "dropped_count": len(rows) - len(kept),
            "input_count": len(rows),
            "draft_digest": digest(read_manifest(public_path)),
            "private_draft_digest": digest(read_manifest(private_path)),
        }
        atomic(receipt_path, (json.dumps(result, sort_keys=True) + "\n").encode())
        return result
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--private-draft", type=Path)
    args = parser.parse_args(argv)
    try:
        result = run(args.root, args.draft, private_draft=args.private_draft)
    except Exception:
        print(json.dumps({"status": "instrument_failure"}))
        return 1
    print(json.dumps({"dropped_count": result["dropped_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
