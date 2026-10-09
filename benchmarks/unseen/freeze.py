"""Freeze the staged, bisected p1 without running a guard, git, network or model.

Coordinator: python -m benchmarks.unseen.freeze --used-report USED-SET-REPORT.json
The report is eligibility.UsedSet.report() output. Label-check counts are derived
from retained vulnerability changes' label_check fields (missing means unchecked).
A matching retry is a no-op; any changed frozen artifact requires a new pool id.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
from pathlib import Path

from .bisect_guard import read_pair
from .draft import manifest
from .eligibility import SOURCES
from .journal import digest, sync_directory


def count(value) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid_count")
    return value


def sha256(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid_digest")
    return value


def metadata(used_report: dict) -> dict:
    """Only known source labels and numeric counts can enter the public record."""
    try:
        used_digest = sha256(used_report["sha256"])
        sources = used_report["sources"]
        if not sources or set(sources) - {*SOURCES, "memory_local", "memory_s3"}:
            raise ValueError
        return {"used_set_digest": used_digest, "source_counts": {k: count(v["count"]) for k, v in sources.items()}}
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ValueError("invalid_used_report") from None


def verify_receipt(receipt: dict, public: dict, private: dict) -> None:
    try:
        if type(receipt["guard_result"]) is not int or receipt["guard_result"] != 0:
            raise ValueError
        if sha256(receipt["draft_digest"]) != digest(public) or sha256(receipt["private_draft_digest"]) != digest(private):
            raise ValueError
        if count(receipt["input_count"]) != len(public.get("repository", [])) + count(receipt["dropped_count"]):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise ValueError("invalid_guard_receipt") from None


def frozen_text(data: dict) -> bytes:
    # Reuse the draft serializer, changing only the status. Hash its parsed value,
    # not the TOML bytes: table/key order and whitespace are not pool identity.
    text = manifest(data.get("repository", []), data["seed"])
    return text.replace('status = "draft"', 'status = "frozen"', 1).encode("utf-8")


def matches(path: Path, payload: bytes) -> bool:
    try:
        if path.suffix == ".toml":
            return digest(tomllib.loads(path.read_text(encoding="utf-8"))) == digest(tomllib.loads(payload.decode("utf-8")))
        return digest(json.loads(path.read_bytes())) == digest(json.loads(payload))
    except (OSError, ValueError):
        return False


def run(root: Path, *, used_report: dict) -> dict:
    directory = root / "benchmarks/unseen"
    record = metadata(used_report)
    public, private = read_pair(directory / "draft-p1.toml", directory / "private/draft-p1.toml")
    try:
        receipt = json.loads((directory / "bisect-p1.json").read_bytes())
    except (OSError, ValueError):
        raise ValueError("invalid_guard_receipt") from None
    verify_receipt(receipt, public, private)
    if not public.get("repository"):
        raise ValueError("empty_pool")
    labels = dict.fromkeys(("confirmed", "refactor", "unclear", "unchecked"), 0)
    hidden = {r["id"]: r for r in private.get("repository", [])}
    try:
        for pointer in public["repository"]:
            row = hidden[pointer["id"]] if pointer.get("private") else pointer
            for change in row["changes"]:
                if change["kind"] == "vulnerability":
                    labels[change.get("label_check", "unchecked")] += 1
    except (KeyError, TypeError):
        raise ValueError("invalid_label_check") from None
    try:
        protocol = (directory / "protocol-p1.md").read_bytes()
        if not protocol:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("invalid_protocol") from None
    public_bytes, private_bytes = frozen_text(public), frozen_text(private)
    record.update(
        guard_result=0,
        dropped_count=receipt["dropped_count"],
        label_check_counts=labels,
        freeze_digest=digest(tomllib.loads(public_bytes.decode("utf-8"))),
        protocol_digest=hashlib.sha256(protocol).hexdigest(),
    )
    outputs = (
        (directory / "private/pool-p1.toml", private_bytes),
        (directory / "pool-p1.toml", public_bytes),
        (directory / "freeze-p1.json", (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()),
    )
    # Check EVERY existing artifact before writing anything. The record is the
    # completion marker and is written last; matching interrupted writes can resume.
    if any(path.exists() and not matches(path, payload) for path, payload in outputs):
        raise FileExistsError("frozen_pool_differs_use_new_pool")
    for path, payload in outputs:
        try:
            with path.open("xb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            sync_directory(path.parent)
        except FileExistsError:
            if not matches(path, payload):
                raise FileExistsError("frozen_pool_differs_use_new_pool") from None
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--used-report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(args.root, used_report=json.loads(args.used_report.read_bytes()))
    except Exception:
        print(json.dumps({"status": "freeze_refused"}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
