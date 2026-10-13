"""Offline-first provenance checks for declared push evaluation populations.

This validates inputs, never detector outcomes or capability admission. Source bytes come
from pinned Git blobs, so a dirty cached worktree cannot silently change the experiment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from openultrasast.repos import RepoUnavailable, load_repo_recipe, resolve


class InputError(ValueError):
    """An input identity or label cannot be trusted."""


def _blob(root: Path, commit: str, path: str) -> bytes:
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or not path or "\\" in path:
        raise InputError(f"unsafe source path: {path!r}")
    # Git object reads neither follow worktree symlinks nor execute project code.
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", f"{commit}:{path}"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    if not result.stdout:
        raise InputError(f"empty source bytes: {path}")
    return result.stdout


def _snapshot(item: dict[str, Any], directory: Path, cache_root: Path | None, fetch: bool) -> dict[str, Any]:
    result: dict[str, Any] = {"id": item["id"], "status": "invalid_input", "bytes_read": 0, "files": []}
    try:
        recipe = load_repo_recipe(directory / item["recipe"])
        commit = item.get("commit", recipe.commit)
        if not isinstance(commit, str) or not re.fullmatch("[0-9a-f]{40}", commit):
            raise InputError("commit must be a full immutable SHA")
        recipe = replace(recipe, commit=commit)
        root = resolve(recipe, fetch=fetch, cache_root=cache_root)
        result.update(commit=commit, repository=recipe.url, license=recipe.license)
        files = item["files"]
        paths = [entry["path"] for entry in files]
        if recipe.license_file not in paths or len(paths) < 2 or len(paths) != len(set(paths)):
            raise InputError("declare a unique license file and at least one source file")
        for entry in files:
            content = _blob(root, commit, entry["path"])
            result["bytes_read"] += len(content)
            edit = entry.get("edit")
            if edit:
                if not isinstance(edit, dict):
                    raise InputError("authored edit must be an object")
                if not edit.get("provenance", "").startswith("authored"):
                    raise InputError("transformation must identify authored provenance")
                before, after = edit["before"].encode(), edit["after"].encode()
                if not before or content.count(before) != 1 or before == after:
                    raise InputError(f"authored edit must match exactly once: {entry['path']}")
                if hashlib.sha256(content).hexdigest() != entry.get("original_sha256"):
                    raise InputError(f"original hash mismatch: {entry['path']}")
                content = content.replace(before, after, 1)
            digest = hashlib.sha256(content).hexdigest()
            if len(content) != entry["size"] or digest != entry["sha256"] or not content:
                raise InputError(f"source size/hash mismatch: {entry['path']}")
            result["files"].append({"path": entry["path"], "size": len(content), "sha256": digest})
        result["status"] = "ready"
    except RepoUnavailable:
        result.update(
            status="missing_prerequisite",
            problem=f"{recipe.name}: pinned checkout {commit} unavailable; rerun this validator with --fetch to fetch it",
        )
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
        result["problem"] = str(exc)
    return result


def validate_manifest(path: Path, *, cache_root: Path | None = None, fetch: bool = False) -> dict[str, Any]:
    """Retain every case, marking unavailable inputs and unreviewed labels explicitly.

    `ready` means input provenance is verified. It never means a finding was reproduced.
    Explicit --fetch is required even if the ordinary repository network env var is set.
    """
    manifest_bytes = path.read_bytes()
    data = json.loads(manifest_bytes)
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise InputError("unsupported push input schema version")
    for field in ("snapshots", "cases"):
        if not isinstance(data.get(field), list) or not data[field]:
            raise InputError(f"{field} must be a nonempty list")
        for item in data[field]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                raise InputError(f"{field} entry requires an identity")
    snapshots = [_snapshot(item, path.parent, cache_root, fetch) for item in data["snapshots"]]
    indexed = {item["id"]: item for item in snapshots}
    if len(indexed) != len(snapshots):
        raise InputError("duplicate snapshot identity")
    cases = []
    ids: set[str] = set()
    for item in data["cases"]:
        case = dict(item, status="invalid_input", admission="experimental")
        try:
            if item["id"] in ids:
                raise InputError("duplicate case identity")
            ids.add(item["id"])
            if item["label"] not in {"vulnerable", "fixed", "benign", "regression", "unsupported", "unreviewed"}:
                raise InputError("invalid case label")
            if item["role"] not in {"development", "transfer", "regression", "envelope", "reserved_holdout"}:
                raise InputError("invalid workload role")
            if not item["capability"] or not item["provenance"]:
                raise InputError("capability and provenance are required")
            if item["label"] == "unreviewed" and not item["prerequisites"]:
                raise InputError("unreviewed labels require an explicit prerequisite")
            inputs = [indexed[item[key]] for key in ("base", "tip")]
            problems = [value.get("problem", "") for value in inputs if value["status"] != "ready"]
            if any(value["status"] == "invalid_input" for value in inputs):
                case["problem"] = "; ".join(problems)
            elif problems or item["prerequisites"]:
                case.update(status="missing_prerequisite", problem="; ".join(problems + item["prerequisites"]))
            else:
                case["status"] = "ready"
        except (ValueError, KeyError, TypeError) as exc:
            case["problem"] = str(exc)
        cases.append(case)
    return {
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "population": len(cases),
        "capability_prerequisites": data.get("capability_prerequisites", {}),
        "snapshots": snapshots,
        "cases": cases,
        "note": "Input validation only; every capability remains experimental pending independent evaluation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    try:
        result = validate_manifest(args.manifest, fetch=args.fetch)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "invalid_input", "problem": str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if all(case["status"] == "ready" for case in result["cases"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
