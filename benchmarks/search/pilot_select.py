"""Offline development-pair feasibility pilot; identities stay in a gitignored manifest.

Run from the repository root with python -m benchmarks.search.pilot_select.
The existing reserved guard is executed as a black box: this module never reads v3.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from benchmarks.unseen import eligibility, ledger
from openultrasast.model.taxonomy import load_families

LANGUAGES = ("python", "javascript", "typescript", "php", "java")
FAMILIES = ("injection", "path", "output_encoding", "untrusted_destination")
SHA = re.compile(r"[0-9a-f]{40}")
MANIFESTS = {
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "setup.py": "pip",
    "Pipfile": "pip",
    "package.json": "npm",
    "composer.json": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
}


def encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def safe(path: Path) -> bool:
    return not eligibility.excluded(path) and not eligibility.excluded(path.resolve()) and not path.is_symlink()


def load_catalogs(root: Path) -> tuple[list[dict], dict]:
    """Read raw metadata only; PairCase materialization would unnecessarily open source excerpts."""
    rows = []
    counts = {"files": 0, "bytes": 0, "rows": 0}
    directory = (root / "benchmarks/pairs").resolve()
    for path in sorted(directory.rglob("catalog.toml")):
        if not safe(path) or not path.resolve().is_relative_to(directory):
            continue
        raw = path.read_bytes()
        items = eligibility.parse(path, raw).get("pair", [])
        if not isinstance(items, list) or not all(isinstance(row, dict) for row in items):
            raise ValueError("invalid_catalog")
        rows.extend(items)
        counts["files"] += 1
        counts["bytes"] += len(raw)
        counts["rows"] += len(items)
    if not counts["bytes"] or not rows:
        raise ValueError("empty_catalogs")
    return rows, counts


def exclusions(root: Path, extra: tuple[Path, ...] = (), ledgers: tuple[Path, ...] = ()) -> tuple[set[str], dict]:
    """Unseen-local reservations/used sets, including private journals; never the development used set.

    eligibility.build_used collects development data itself, so its union cannot exclude a
    development pilot. The unseen usage ledger has opaque slices, not identities: every pool
    is excluded in full regardless of usage, and ledger integrity is checked separately.
    """
    directory = root / "benchmarks/unseen"
    paths = {
        p
        for p in directory.rglob("*")
        if p.suffix in {".toml", ".json", ".jsonl", ".yaml", ".yml"} and "fixtures" not in p.relative_to(directory).parts
    }
    paths.update(extra)
    ledger_paths = set(ledgers)
    ledger_paths.update(p for p in paths if any(word in p.stem.lower() for word in ("ledger", "usage")))
    paths.update(ledger_paths)
    names: set[str] = set()
    report = {"files": 0, "bytes": 0, "ledger_rows": 0}
    for path in sorted(paths):
        if not safe(path):
            raise ValueError("unsafe_exclusion_source")
        raw = path.read_bytes()
        report["files"] += 1
        report["bytes"] += len(raw)
        if path in ledger_paths:
            report["ledger_rows"] += len(ledger.read(path))
        else:
            value = eligibility.parse(path, raw)

            # TOML [[repository]] is a collection, whereas repositories() treats
            # a scalar "repository" field as an identity. Walk containers too.
            def collect(item):
                names.update(eligibility.repositories(item))
                if isinstance(item, str) and eligibility.NAME.fullmatch(item):
                    names.add(eligibility.normalize(item))
                if isinstance(item, dict):
                    for child in item.values():
                        if isinstance(child, (dict, list)):
                            collect(child)
                elif isinstance(item, list):
                    for child in item:
                        collect(child)

            collect(value)
    report.update(count=len(names), sha256=hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest())
    return names, report


def cache_safe(path: Path) -> bool:
    # Git config is intentionally readable here; every other exclusion and all
    # symlink ancestors remain forbidden before opening files or listing trees.
    lexical = path.absolute()
    resolved = path.resolve()
    return not any("v3" in part.lower() or part in {"__pycache__", ".venv"} for p in (lexical, resolved) for part in p.parts) and not any(
        p.is_symlink() for p in (lexical, *lexical.parents)
    )


def enrich(rows: list[dict], caches: tuple[Path, ...], *, excluded: set[str] | None = None) -> dict:
    """Prefer metadata actually present in a matching local clone, without fetching.

    This is only a preference: a cached checkout is not proof the pinned revision builds.
    Only development-candidate paths are opened; unrelated cached repositories are not read.
    """
    report = {"matched_checkouts": 0, "config_bytes": 0, "manifest_bytes": 0}
    seen = {}
    for row in rows:
        try:
            name = eligibility.normalize(row.get("repo", ""))
        except (ValueError, TypeError):
            continue
        if name in (excluded or set()):
            continue
        if name not in seen:
            seen[name] = []
            for cache in caches:
                for checkout in (cache / name, cache / name.rsplit("/", 1)[-1]):
                    config = checkout / ".git/config"
                    if not cache_safe(config) or not config.is_file():
                        continue
                    parser = configparser.ConfigParser()
                    raw = config.read_bytes()
                    parser.read_string(raw.decode())
                    origin = parser.get('remote "origin"', "url", fallback="")
                    try:
                        matching = eligibility.normalize(origin) == name
                    except ValueError:
                        matching = False
                    if not matching:
                        continue
                    files = []
                    for manifest in MANIFESTS:
                        path = checkout / manifest
                        if cache_safe(path) and path.is_file():
                            report["manifest_bytes"] += len(path.read_bytes())
                            files.append(manifest)
                    for folder in ("tests", "test", "spec", "__tests__", "src/test"):
                        directory = checkout / folder
                        if cache_safe(directory) and directory.is_dir() and any(directory.iterdir()):
                            files.append(folder + "/")
                    seen[name] = files
                    report["matched_checkouts"] += 1
                    report["config_bytes"] += len(raw)
                    break
                if seen[name]:
                    break
        row["files"] = sorted(set(row.get("files", []) + seen[name]))
    return report


def candidates(rows: list[dict], excluded: set[str]) -> tuple[list[dict], dict]:
    taxonomy = load_families()
    used = eligibility.UsedSet(sources={"unseen": excluded})
    out, rejected = [], Counter()
    for row in rows:
        reason = None
        try:
            raw_repo = row.get("repo", "")
            repo = eligibility.normalize(raw_repo)
            if "://" in raw_repo and not raw_repo.startswith("https://"):
                raise ValueError
            url = raw_repo if raw_repo.startswith("https://") else "https://github.com/" + repo
            if repo.count("/") != 1:
                raise ValueError
            parsed = urlsplit(url)
            if (
                parsed.netloc != "github.com"
                or parsed.query
                or parsed.fragment
                or parsed.path.strip("/").removesuffix(".git").lower() != repo
            ):
                raise ValueError
            if row.get("fix_repo") and eligibility.normalize(row["fix_repo"]) != repo:
                raise ValueError
        except (ValueError, TypeError):
            rejected["repository"] += 1
            continue
        if row.get("split", "train") != "train" or row.get("provenance") == "synthetic":
            reason = "not_development_fix"
        elif row.get("language") not in LANGUAGES:
            reason = "language"
        elif eligibility.rejection(eligibility.Resolution(repo, frozenset({repo}), repo), used, set()):
            reason = "unseen"
        vulnerable, fixed = row.get("parent", ""), row.get("commit", "")
        if not all(isinstance(s, str) and SHA.fullmatch(s) for s in (vulnerable, fixed)) or vulnerable == fixed:
            reason = reason or "commits"
        expected = row.get("expected", [])
        families = {row["family"]} if row.get("family") else set()
        for item in [row, *expected]:
            family = taxonomy.family_of_cwe(item.get("cwe", ""))
            if family:
                families.add(family.id)
        families &= set(FAMILIES)
        function = row.get("function") or next((r.get("function") for r in expected if r.get("function")), "")
        file = row.get("path") or row.get("relpath", "")
        if len(families) != 1:
            reason = reason or "family"
        if not function or function in {"<anon>", "<module>", "*"} or not file:
            reason = reason or "location"
        if reason:
            rejected[reason] += 1
            continue
        files = row.get("files", [])
        manifest = next((MANIFESTS[Path(f).name] for f in sorted(files) if Path(f).name in MANIFESTS), None)
        tests = True if any(re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|(^|/)test_[^/]+", f) for f in files) else None
        out.append(
            {
                "repo": url.removesuffix(".git").rstrip("/"),
                "vulnerable": vulnerable,
                "fixed": fixed,
                "family": next(iter(families)),
                "language": row["language"],
                "file": file,
                "function": function,
                "manifest": manifest,
                "has_tests": tests,
            }
        )
    return out, dict(sorted(rejected.items()))


def select(rows: list[dict], *, seed: int, count: int = 20) -> list[dict]:
    """Balance language/family representation, then prefer evidenced runnable projects.

    Seeded SHA ordering is invariant to catalog ordering and Python hash randomization.
    At most one pair per normalized repository is selected.
    """
    if count < 1:
        raise ValueError("invalid_count")
    remaining = sorted(rows, key=lambda row: hashlib.sha256(str(seed).encode() + encoded(row)).digest())
    selected, used = [], set()
    languages, families = Counter(), Counter()
    while remaining and len(selected) < count:
        row = min(
            remaining,
            key=lambda r: (
                languages[r["language"]] >= 3,
                languages[r["language"]],
                families[r["family"]],
                not (r["has_tests"] and r["manifest"]),
                not r["manifest"],
                not r["has_tests"],
            ),
        )
        selected.append(row)
        used.add(eligibility.normalize(row["repo"]))
        languages[row["language"]] += 1
        families[row["family"]] += 1
        remaining = [r for r in remaining if eligibility.normalize(r["repo"]) not in used]
    return selected


def summary(rows: list[dict], *, seed: int, manifest: bytes, target: int = 20) -> dict:
    languages = Counter(row["language"] for row in rows)
    return {
        "status": "selected" if len(rows) == target else "insufficient_candidates",
        "purpose": "feasibility_only",
        "seed": seed,
        "target": target,
        "selected": len(rows),
        "gap_to_target": max(0, target - len(rows)),
        "per_language": {lang: languages[lang] for lang in LANGUAGES},
        "per_family": {family: sum(r["family"] == family for r in rows) for family in FAMILIES},
        "language_floor_gaps": {lang: max(0, 3 - languages[lang]) for lang in LANGUAGES},
        "unknown_test_suite": sum(r["has_tests"] is None for r in rows),
        "unknown_manifest": sum(r["manifest"] is None for r in rows),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "biases": ["known_vulnerable_location", "labelled_family", "runnable_project_preference"],
        "qualification": "not_an_unseen_evaluation_or_block_admission",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--seed", type=int, default=20261005)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    parser.add_argument("--ledger", type=Path, action="append", default=[])
    parser.add_argument("--cache", type=Path, action="append", default=[])
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/search/private/pilot.json"))
    parser.add_argument("--output", type=Path, default=Path("benchmarks/measurements/2026-10-05-search-pilot-selection/record.json"))
    args = parser.parse_args(argv)
    private = args.root / args.manifest
    created = False
    try:
        if not private.resolve().is_relative_to((args.root / "benchmarks/search/private").resolve()):
            raise ValueError("manifest_must_be_private")
        ignored = subprocess.run(["git", "check-ignore", "-q", str(private)], cwd=args.root, capture_output=True)
        if ignored.returncode != 0:
            raise ValueError("manifest_not_gitignored")
        guard = eligibility.verify_tests(args.root)
        rows, instrument = load_catalogs(args.root)
        excluded, exclusion_report = exclusions(args.root, tuple(args.exclude), tuple(args.ledger))
        # The black-box guard has already approved the development catalogs.
        metadata = enrich(rows, tuple(args.cache) or (Path.home() / ".cache/openultrasast/repos",), excluded=excluded)
        available, rejected = candidates(rows, excluded)
        selected = select(available, seed=args.seed, count=args.count)
        payload = encoded({"seed": args.seed, "pairs": selected})
        private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with private.open("xb") as handle:
            created = True
            os.chmod(private, 0o600)
            handle.write(payload)
        # The URL-bearing private selection now lies in the guard's development tree,
        # so even catalog bare-name aliases are checked without reading v3 ourselves.
        guard = eligibility.verify_tests(args.root)
        record = summary(selected, seed=args.seed, manifest=payload, target=args.count)
        record.update(
            catalogs=instrument,
            exclusions=exclusion_report,
            rejected=rejected,
            local_metadata=metadata,
            eligible_pairs=len(available),
            eligible_repositories=len({r["repo"] for r in available}),
            guard=guard,
        )
        output = args.root / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as handle:
            handle.write(encoded(record))
        print(encoded(record).decode(), end="")
        return 0 if len(selected) == args.count else 2
    except Exception as exc:
        if created:
            private.unlink(missing_ok=True)
        print(json.dumps({"status": "instrument_failure", "reason": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
