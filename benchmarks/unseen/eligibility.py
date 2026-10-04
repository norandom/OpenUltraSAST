"""Read-only used-set collection. Only counts, source labels and digests leave this module's CLI.

Run from the repository root: python -m benchmarks.unseen.eligibility --help.
Population v3 is exclusively the existing guard's responsibility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from openultrasast.plane.memory import MemoryStore

URL = re.compile(r"github\.com/([\w.-]+/[\w.-]+)", re.I)
NAME = re.compile(r"[\w.-]+/[\w.-]+")
SOURCES = ("pairs", "pointers", "populations", "harvest", "units", "measurements", "sweep")


def normalize(value: str) -> str:
    text = value.strip().lower().rstrip("/")
    if NAME.fullmatch(text):
        name = text.removesuffix(".git")
    else:
        # Structured fields must be identities, not prose containing a URL.
        if any(char.isspace() for char in text):
            raise ValueError("invalid_repository")
        url = urlsplit(text if "://" in text else "https://" + text)
        if url.scheme not in {"http", "https", "ssh", "git"} or not url.hostname or "." not in url.hostname:
            raise ValueError("invalid_repository")
        parts = url.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError("invalid_repository")
        name = "/".join(parts[:2]).removesuffix(".git")
        if not NAME.fullmatch(name):
            raise ValueError("invalid_repository")
        if url.hostname != "github.com":
            return url.hostname + "/" + name
    if not NAME.fullmatch(name) or any(part in {".", ".."} for part in name.split("/")):
        raise ValueError("invalid_repository")
    return name


def excluded(path: Path) -> bool:
    return any("v3" in part.lower() or part in {".git", "__pycache__", ".venv"} for part in path.parts)


def repositories(value: object, counts: dict[str, int] | None = None) -> set[str]:
    """Structured repo fields include bare owner/name pointers; URLs also occur in prose."""
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"repo", "fix_repo", "repository", "full_name", "origin"} or (key == "group" and "unit" in value):
                try:
                    if not isinstance(item, str):
                        raise ValueError("invalid_repository")
                    found.add(normalize(item))
                except ValueError:
                    if counts is not None:
                        counts["skipped_values"] = counts.get("skipped_values", 0) + 1
            else:
                found.update(repositories(item, counts))
    elif isinstance(value, list):
        for item in value:
            found.update(repositories(item, counts))
    elif isinstance(value, str):
        found.update(normalize(m[1]) for m in URL.finditer(value))
    return found


def pointer_repositories(value: object, counts: dict[str, int] | None = None) -> set[str]:
    if isinstance(value, dict):
        if value.get("vendored") is False:
            return repositories(value, counts)
        return set().union(*(pointer_repositories(v, counts) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(pointer_repositories(v, counts) for v in value))
    return set()


def parse(path: Path, raw: bytes) -> object:
    structured = path.suffix in {".toml", ".json", ".jsonl", ".yaml", ".yml"}
    text = raw.decode("utf-8", errors="strict" if structured else "ignore")
    if path.suffix == ".toml":
        return tomllib.loads(text)
    if path.suffix == ".json":
        return json.loads(text)
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if path.suffix in {".yaml", ".yml"}:
        documents = list(yaml.safe_load_all(text))
        return documents[0] if len(documents) == 1 else documents
    return text


@dataclass
class UsedSet:
    sources: dict[str, set[str]] = field(default_factory=lambda: {label: set() for label in SOURCES})
    instrument: dict[str, dict[str, int]] = field(default_factory=dict)

    def add(self, label: str, names: set[str], size: int, files: int = 1, skipped_values: int = 0) -> None:
        self.sources.setdefault(label, set()).update(names)
        counts = self.instrument.setdefault(label, {"files": 0, "bytes": 0, "rows": 0, "skipped_values": 0})
        counts["files"] += files
        counts["bytes"] += size
        counts["rows"] += len(names)
        counts["skipped_values"] += skipped_values

    def report(self, known_empty: set[str] | None = None) -> dict:
        known_empty = known_empty or set()
        if known_empty - self.sources.keys():
            raise ValueError("unknown_source_label")
        records = {}
        for label, names in self.sources.items():
            counts = self.instrument.get(label, {"files": 0, "bytes": 0, "rows": 0, "skipped_values": 0})
            if not counts["rows"] and label not in known_empty:
                raise ValueError("empty_source:" + label)
            records[label] = {**counts, "count": len(names), "known_empty": label in known_empty}
        names = set().union(*self.sources.values())
        return {"sources": records, "count": len(names), "sha256": hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()}


def build_used(root: Path, *, stores: Mapping[str, MemoryStore] | None = None, pointer_manifests: Iterable[Path] = ()) -> UsedSet:
    used = UsedSet()

    def read(label: str, paths: Iterable[Path], structured: bool = True) -> list[object]:
        values = []
        for path in sorted(set(paths)):
            if excluded(path):
                continue
            raw = path.read_bytes()  # failure is an instrument failure, never a quiet empty source
            value = parse(path, raw) if structured else raw.decode("utf-8", errors="ignore")
            counts: dict[str, int] = {}
            names = repositories(value, counts)
            used.add(label, names, len(raw), skipped_values=counts.get("skipped_values", 0))
            if label == "pairs":
                pointer_counts: dict[str, int] = {}
                pointers = pointer_repositories(value, pointer_counts)
                if pointers or pointer_counts:
                    used.add("pointers", pointers, len(raw), skipped_values=pointer_counts.get("skipped_values", 0))
            values.append(value)
        return values

    pairs = root / "benchmarks/pairs"
    read("pairs", (p for p in pairs.rglob("*") if p.is_file() and p.suffix in {".toml", ".json", ".jsonl", ".csv", ".yaml", ".yml"}))
    read("pointers", pointer_manifests)
    read("populations", (p for p in (root / "benchmarks/independent").glob("population-v[12].toml")))
    read("harvest", (p for directory in pairs.glob("advisory-fixes*") for p in directory.rglob("*.toml")))
    units = set((root / "plane/experiments").glob("*.units.jsonl"))
    for path in (root / "plane/experiments").glob("*.y*ml"):
        if excluded(path):
            continue
        raw = path.read_bytes()
        manifest = parse(path, raw)
        counts = {}
        names = repositories(manifest, counts)
        used.add("units", names, len(raw), skipped_values=counts.get("skipped_values", 0))
        if isinstance(manifest, dict) and manifest.get("units_file"):
            declared = root / Path(manifest["units_file"]).expanduser()
            if declared.exists():  # an unregistered plan may not have frozen units yet
                units.add(declared)
    for label, store in (stores or {}).items():
        if label not in {"local", "s3"}:
            raise ValueError("unknown_store_label")
        source = "memory_" + label
        used.add(source, set(), 0, 0)
        # Read actual objects, not a serialized row size masquerading as bytes read.
        for key in store._keys("repos/"):
            if not key.endswith(".jsonl") or excluded(Path(key)):
                continue
            result = store._get(key)
            if result is None:
                raise ValueError("missing_memory_object")
            raw = result[0]
            rows = parse(Path("rows.jsonl"), raw)
            names = set()
            counts = {}
            for row in rows:
                if row.get("kind") == "example" and "repo" in row:
                    names.update(repositories({"repo": row["repo"]}, counts))
                if row.get("kind") == "experiment" and row.get("units_file"):
                    registered = root / Path(row["units_file"]).expanduser()
                    if row.get("units_digest") or registered.exists():
                        units.add(registered)
            used.add(source, names, len(raw), skipped_values=counts.get("skipped_values", 0))
    read("units", units)
    read("measurements", (p for top in ("measurements", "experiments") for p in (root / "benchmarks" / top).rglob("*") if p.is_file()))
    read(
        "sweep",
        (
            p
            for top in ("benchmarks", "src", "tests", "plane", ".kiro")
            for p in (root / top).rglob("*")
            if p.is_file() and not p.is_relative_to(root / "benchmarks/unseen") and not excluded(p)
        ),
        structured=False,
    )
    return used


@dataclass(frozen=True)
class Resolution:
    full_name: str
    names: frozenset[str]
    network: str


def resolve(candidate: str, api) -> Resolution:
    name = normalize(candidate)
    if name.count("/") > 1:
        return Resolution(name, frozenset({name}), name)
    data = api.get_repo(name)
    canonical = normalize(data["full_name"])
    names = {name, canonical, *(normalize(n) for n in data.get("former_names", []))}
    for key in ("parent", "source"):
        if data.get(key):
            names.add(normalize(data[key]["full_name"]))
    network = normalize((data.get("source") or data.get("parent") or data)["full_name"])
    return Resolution(canonical, frozenset(names), network)


def canonicalize_used(used: UsedSet, api) -> None:
    """Resolve old used names too: GitHub exposes redirects, not a complete rename history."""
    cache = {}
    for names in used.sources.values():
        for name in sorted(names):
            if name not in cache:
                try:
                    cache[name] = resolve(name, api)
                except RepositoryNotFound:
                    cache[name] = Resolution(name, frozenset({name}), name)
            names.update(cache[name].names)


def rejection(candidate: Resolution, used: UsedSet, selected: set[str]) -> str | None:
    for label, names in used.sources.items():
        if candidate.names & names:
            return label
    if candidate.network in selected:
        return "fork_network"
    selected.add(candidate.network)
    return None


class RepositoryNotFound(ValueError):
    """A historical or synthetic used identity no longer resolves; retain it verbatim."""


class GitHub:
    """Coordinator-only GET client. Exceptions never disclose request URLs or tokens."""

    def __init__(self, token: str):
        if not token:
            raise ValueError("missing_gh_token")
        self.token = token

    def get_repo(self, name: str) -> dict:
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        request = Request(
            "https://api.github.com/repos/" + normalize(name),
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                return json.load(response)
        except HTTPError as exc:
            if exc.code == 404:
                raise RepositoryNotFound("github_not_found") from None
            raise ValueError("github_resolution_failed") from None
        except Exception:
            raise ValueError("github_resolution_failed") from None


def verify_tests(root: Path) -> dict:
    """The coordinator runs the guard as a black box; only exit codes and counts escape."""
    import subprocess
    import sys
    import tempfile
    from xml.etree import ElementTree

    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "tests.xml"
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/test_unseen_eligibility.py",
                "tests/test_unseen_ledger.py",
                "tests/test_independent_population.py",
                "--junitxml=" + str(report),
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if done.returncode != 0:
            raise ValueError("guard_or_tests_failed")
        suites = ElementTree.parse(report).getroot().iter("testsuite")
        counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
        for suite in suites:
            for key in counts:
                counts[key] += int(suite.attrib[key])
        if not counts["tests"]:
            raise ValueError("empty_test_run")
        return {"guard": "green", "test_exit_code": done.returncode, "tests": counts}


def main(argv: list[str] | None = None) -> int:
    import os

    from openultrasast import config
    from openultrasast.plane import memory
    from openultrasast.plane.reconciler import results_root

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--local-store", default=None)
    parser.add_argument("--s3-store", default="s3://")
    parser.add_argument("--pointer-manifest", type=Path, action="append", default=[])
    parser.add_argument("--known-empty", choices=(*SOURCES, "memory_local", "memory_s3"), action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-tests", action="store_true")
    args = parser.parse_args(argv)
    step = "open_stores"
    try:
        config.load_dotenv(args.root / ".env")
        stores = {
            "local": memory.open_store(args.local_store or "file://" + str(results_root() / "memory"), read_only=True),
            "s3": memory.open_store(args.s3_store, read_only=True),
        }
        step = "build_used"
        used = build_used(args.root, stores=stores, pointer_manifests=args.pointer_manifest)
        step = "report"
        used.report(set(args.known_empty))  # prove inputs before API work
        step = "canonicalize"
        canonicalize_used(used, GitHub(os.environ.get("GH_TOKEN", "")))
        step = "report"
        report = used.report(set(args.known_empty))
        if args.verify_tests:
            step = "verify_tests"
            report.update(verify_tests(args.root))
        step = "report"
        text = json.dumps(report, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x") as handle:
                handle.write(text)
        print(text, end="")
        return 0
    except Exception as exc:
        # Source paths, store exceptions and JSON parser errors can contain repository names.
        report = {"status": "instrument_failure", "step": step, "type": type(exc).__name__}
        if str(exc) in {"empty_source:" + label for label in (*SOURCES, "memory_local", "memory_s3")}:
            report["source"] = str(exc).partition(":")[2]
        print(json.dumps(report))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
