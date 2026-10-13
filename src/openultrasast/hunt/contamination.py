"""Mark runs that used a reported repository and keep them out of gain reports."""

from __future__ import annotations

import hashlib
import json
import tomllib
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path


def _eligibility():
    """The benchmark's name normaliser and GitHub URL pattern, imported late so the package imports without the benchmarks tree."""
    from benchmarks.unseen.eligibility import URL, normalize

    return URL, normalize


def report_repositories(root: Path) -> set[str]:
    """Read repository identities from the pilot and benchmark reports under root.

    The pilot's repository entries contribute their id, repository and URL fields.
    Each measurements/*/accepted_repos.json is a list of names. GitHub links in
    measurements/*/NOTES.md also count. Missing sources contribute nothing, while
    unreadable or malformed files raise. Advisory and label fields are not inspected.
    """
    URL, normalize = _eligibility()
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(root)
    names = set()
    pilot = root / "benchmarks/valid/pilot/pool-valid.toml"
    if pilot.exists():
        data = tomllib.loads(pilot.read_text(encoding="utf-8"))
        for entry in data.get("repository", []):
            for key in ("id", "repository", "url"):
                if key in entry:
                    names.add(normalize(entry[key]))
    measurements = root / "benchmarks/measurements"
    for path in sorted(measurements.glob("*/accepted_repos.json")):
        entries = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or any(not isinstance(entry, str) for entry in entries):
            raise ValueError(f"repository report must be a list of names: {path}")
        names.update(normalize(entry) for entry in entries)
    for path in sorted(measurements.glob("*/NOTES.md")):
        names.update(normalize(match[1].rstrip(".")) for match in URL.finditer(path.read_text(encoding="utf-8")))
    return names


def _records(run_dir: Path) -> list[dict]:
    """Read JSON objects with a change id, skipping artifacts and other metadata."""
    records = []
    for path in sorted(run_dir.glob("*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and "id" in value:
            records.append(value)
    return records


def run_repositories(run_dir: Path) -> set[str]:
    """Read study.json changes' repo fields, or resolve each record's repository.

    A record's repo or repository field takes precedence. The current runner writes
    neither, so its record id is joined to inputs.json item_id and change.repo is
    read there. Inputs without a record do not count. No advisory or label fields
    are inspected. Raise if any change lacks a repository or no repositories exist.
    """
    _, normalize = _eligibility()
    run_dir = Path(run_dir)
    study = run_dir / "study.json"
    names = set()
    if study.exists():
        for change in json.loads(study.read_text(encoding="utf-8"))["changes"]:
            if not change.get("repo"):
                raise ValueError(f"missing repository in study: {run_dir}")
            names.add(normalize(change["repo"]))
    else:
        inputs = None
        for record in _records(run_dir):
            repo = record.get("repo") or record.get("repository")
            if not repo:
                if inputs is None:
                    path = run_dir / "inputs.json"
                    entries = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
                    inputs = {entry["item_id"]: entry["change"] for entry in entries}
                repo = inputs.get(record["id"], {}).get("repo")
            if not repo:
                raise ValueError(f"missing repository for record {record['id']} in {run_dir}")
            names.add(normalize(repo))
    if not names:
        raise ValueError(f"no repository named by run: {run_dir}")
    return names


def check(run_dir: Path, reports: set[str]) -> dict:
    """Atomically save the overlap and check time, including when the run is clean.

    The digest is SHA256 of sorted, normalized report names joined by newlines,
    with no trailing newline. Repository resolution must succeed before writing.
    """
    _, normalize = _eligibility()
    reports = {normalize(name) for name in reports}
    overlap = sorted(run_repositories(run_dir) & reports)
    result = {
        "contaminated": bool(overlap),
        "repositories": overlap,
        "reports_digest": hashlib.sha256("\n".join(sorted(reports)).encode("utf-8")).hexdigest(),
        "checked_at": datetime.now(UTC).isoformat(),
    }
    path = Path(run_dir) / "contamination.json"
    temporary = path.with_suffix(path.suffix + ".partial")
    temporary.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)
    return result


def mark_all(runs_root: Path, reports: set[str]) -> dict[str, dict]:
    """Check each immediate child directory containing study.json or change records.

    Return checks keyed by directory name. Unresolvable repositories raise instead
    of producing a clean check. Directories containing only metadata are skipped.
    """
    results = {}
    for path in sorted(Path(runs_root).iterdir()):
        if path.is_dir() and ((path / "study.json").is_file() or _records(path)):
            results[path.name] = check(path, reports)
    return results


def clean_runs(run_dirs: Iterable[Path]) -> list[Path]:
    """Return checked, uncontaminated runs in input order.

    Raise ValueError listing all unchecked paths if any contamination.json is
    absent. A missing or non-boolean contaminated value also raises; only an
    explicit false value qualifies a run for reporting gain.
    """
    run_dirs = [Path(path) for path in run_dirs]
    unchecked = [str(path) for path in run_dirs if not (path / "contamination.json").is_file()]
    if unchecked:
        raise ValueError("unchecked runs: " + ", ".join(unchecked))
    clean = []
    for path in run_dirs:
        result = json.loads((path / "contamination.json").read_text(encoding="utf-8"))
        if not isinstance(result, dict) or type(result.get("contaminated")) is not bool:
            raise ValueError(f"invalid contamination check: {path}")
        if not result["contaminated"]:
            clean.append(path)
    return clean
