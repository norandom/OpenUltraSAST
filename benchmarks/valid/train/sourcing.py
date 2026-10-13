"""Sourcing run for the hunter-learning-loop TRAINING set (spec task 4.1, requirements R2.1-R2.3).

Subcommands, in the order they ran on 2026-10-13:

  used        the training-only used set (build_used minus measurements/populations; sweep without measurement text)
  sources     candidates: pool-fresh, pool-retry, then OSV (GHSA with one GitHub fix commit, permissive licence)
  clone       single-branch clones with history, fix + fix^1 fetched, parent read from git; disk guard
  filter      drop test, fixture, vendored and minified sites from the catalog
  verify      budgeted verifier run (counts calls, records provider errors by exception type only)
  candidates  CANDIDATES.md: every site that passed all three model checks, for the maintainer's spot-check
  precheck    ordinary-commit availability per repository with a passing site (what assemble will need)

Everything is deterministic given the seed and the OSV dump; network calls are counted and logged.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import zipfile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PILOT = ROOT / "benchmarks/measurements/2026-10-12-valid-benchmark-pilot"
POOL = ROOT / "benchmarks/unseen/pool-p1.toml"
HIST = Path.home() / "ousast-results/valid/train/hist"
# Intermediates, exclusion lists and per-batch files stay out of the tree: the repository guards in tests/ scan
# benchmarks/ for repository names, and an exclusion list is by construction a list of names used elsewhere.
WORK = Path.home() / "ousast-results/valid/train/work"
OSV_ECOSYSTEMS = {"PyPI": "pip", "npm": "npm", "Maven": "maven", "Packagist": "composer"}
MIN_FREE_BYTES = 6 * 1024**3
TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|fixtures?|testdata|e2e|__mocks__|mocks?)(/|$)|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)test_[^/]*\.py$|_test\.py$|Test\.java$|Tests?\.php$",
    re.I,
)
VENDORED_PATH = re.compile(r"(^|/)(node_modules|vendor|dist|build|third[_-]party|bower_components)(/|$)", re.I)
MINIFIED_PATH = re.compile(r"\.min\.[cm]?js$|\.bundle\.js$", re.I)


def log(message: str) -> None:
    print(message, flush=True)


def free_bytes(path: Path) -> int:
    usage = shutil.disk_usage(path)
    return usage.free


def git(path: Path, *args: str, check: bool = True, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "credential.helper=", *args],
        cwd=path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def pilot_accepted() -> set[str]:
    return set(json.loads((PILOT / "accepted_repos.json").read_text()))


def pilot_sources() -> list[dict]:
    return json.loads((PILOT / "sources.json").read_text())


def pool_public() -> list[dict]:
    rows = tomllib.loads(POOL.read_text())["repository"]
    return [row for row in rows if row.get("license_class") == "permissive"]


# ----------------------------------------------------------------------------- used


def cmd_used(args) -> int:
    from benchmarks.unseen.eligibility import build_used, excluded, repositories

    used = build_used(ROOT)
    strict = set().union(*(names for label, names in used.sources.items() if label not in {"measurements", "populations"}))
    # The sweep label reads benchmarks/measurements and the pilot's provenance as free text, which is the
    # circularity NOTES.md names: a repository is not "used for training" because a measurement wrote its
    # URL down. The refined set keeps every training label and sweeps only the tool's code, tests, plane
    # and specs, not measurement records.
    refined = set().union(*(names for label, names in used.sources.items() if label not in {"measurements", "populations", "sweep"}))
    sweep_roots = [ROOT / top for top in ("src", "tests", "plane", ".kiro")] + [ROOT / "benchmarks"]
    skip = (
        ROOT / "benchmarks/unseen",
        ROOT / "benchmarks/measurements",
        ROOT / "benchmarks/experiments",
        ROOT / "benchmarks/valid",
        ROOT / "benchmarks/independent",
    )
    files = 0
    for top in sweep_roots:
        for path in top.rglob("*"):
            if not path.is_file() or excluded(path) or any(path.is_relative_to(s) for s in skip):
                continue
            files += 1
            refined.update(repositories(path.read_bytes().decode("utf-8", errors="ignore"), {}))
    record = {
        "labels": {label: len(names) for label, names in used.sources.items()},
        "strict_count": len(strict),
        "refined_count": len(refined),
        "refined_sweep_files": files,
        "refined_sweep_skips": [str(s.relative_to(ROOT)) for s in skip],
        "pilot_repos_in_refined": sorted(pilot_accepted() & refined),
    }
    (WORK / "used_strict.json").write_text(json.dumps(sorted(strict), indent=0) + "\n")
    (WORK / "used.json").write_text(json.dumps(sorted(refined), indent=0) + "\n")
    (WORK / "used_log.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    log(json.dumps(record, sort_keys=True))
    return 0


# ----------------------------------------------------------------------------- sources


def osv_text(record: dict) -> str:
    summary = (record.get("summary") or "").strip()
    details = (record.get("details") or "").strip()
    return (summary + "\n\n" + details).strip() if summary else details


def cwe_for(record: dict, family: str, taxonomy) -> str | None:
    for cwe in (record.get("database_specific") or {}).get("cwe_ids", []):
        found = taxonomy.family_of_cwe(cwe)
        if found and found.id == family:
            return cwe
    return None


def github_row(record: dict) -> dict:
    """An OSV GHSA record in the shape source.candidate expects (GitHub advisory API, so GitHub ecosystem names:
    OSV's PyPI and Packagist become pip and composer)."""
    specific = record.get("database_specific") or {}
    return {
        "ghsa_id": record["id"],
        "published_at": record["published"],
        "type": "reviewed" if specific.get("github_reviewed") else "unreviewed",
        "withdrawn_at": record.get("withdrawn"),
        "cwes": [{"cwe_id": c} for c in specific.get("cwe_ids", [])],
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": OSV_ECOSYSTEMS.get(a["package"]["ecosystem"], a["package"]["ecosystem"]),
                    "name": a["package"]["name"],
                }
            }
            for a in record.get("affected", [])
            if a.get("package")
        ],
        "references": [r.get("url", "") for r in record.get("references", [])],
    }


class ZipOSV:
    """source.OSV look-alike that answers from the downloaded dump (no network)."""

    def __init__(self, records: dict[str, dict]):
        self.records = records
        self.calls = 0

    def get(self, identifier: str) -> dict:
        self.calls += 1
        return self.records.get(identifier, {})


def family_exclusions() -> dict[str, set[str]]:
    """Collect strict, pilot, tree and earlier batch exclusions before GitHub checks."""
    from benchmarks.unseen.eligibility import normalize

    def normalized(names) -> set[str]:
        out = set()
        for name in names:
            try:
                out.add(normalize(name))
            except ValueError:
                continue  # a link fragment that is not a repository name excludes nothing
        return out

    groups = {
        "pilot": normalized(pilot_accepted()),
        "named_elsewhere": normalized(named_elsewhere()),
        "used_strict": normalized(json.loads((WORK / "used_strict.json").read_text())) if (WORK / "used_strict.json").is_file() else set(),
        "already_sourced": set(),
    }
    for directory in (WORK, HERE):
        paths = {directory / "sources.json", *directory.glob("sources_batch*.json")}
        for path in sorted(paths):
            if not path.is_file() or path.stem.endswith("_log"):
                continue
            groups["already_sourced"].update(normalize(row["repository"]) for row in json.loads(path.read_text()))
    return groups


def cmd_sources(args) -> int:
    from benchmarks.unseen import source
    from benchmarks.unseen.eligibility import RepositoryNotFound, normalize
    from openultrasast.model.taxonomy import load_families

    taxonomy = load_families()
    family = args.family
    if family:
        log(f"family {family}: {', '.join(sorted(taxonomy.by_id(family).cwes))}")
    accepted = {normalize(name) for name in pilot_accepted()}
    pilot = [] if family else pilot_sources()
    pilot_advisories = {row["advisory"] for row in pilot}
    pilot_repos = {normalize(row["repository"]) for row in pilot}
    public = [] if family else pool_public()
    pool_repos = {normalize(row["repository"]) for row in public}
    used = set() if family else set(json.loads((WORK / "used.json").read_text()))
    excluded_repos = accepted | pilot_repos | pool_repos | used
    exclusion_groups = family_exclusions() if family else {"repository": excluded_repos}
    excluded_repos |= set().union(*exclusion_groups.values())
    if family:
        log(f"exclusion set: { {reason: len(names) for reason, names in exclusion_groups.items()} } -> {len(excluded_repos)} names")
    else:
        log(
            f"exclusion set: pilot accepted {len(accepted)}, pilot sourced {len(pilot_repos)}, pool public {len(pool_repos)}, used {len(used)} -> {len(excluded_repos)} names"  # noqa: E501
        )

    osv_api = source.OSV()
    rows: list[dict] = []
    counts: Counter = Counter()
    if args.extend and not family:
        # Second batch: only OSV, continuing the same seeded order past every repository already sourced.
        earlier = json.loads((WORK / "sources.json").read_text())
        excluded_repos |= {normalize(row["repository"]) for row in earlier}
        log(f"extend: {len(earlier)} earlier sources excluded")

    # (a) pool-fresh: permissive pool entries the pilot never sourced
    for row in [] if args.extend else public:
        repo = normalize(row["repository"])
        if repo in accepted or row["advisory"] in pilot_advisories or repo in pilot_repos:
            continue
        record = osv_api.get(row["advisory"])
        cwe = cwe_for(record, row["family"], taxonomy)
        if not record or not cwe:
            counts["pool-fresh:no_osv_record_or_cwe"] += 1
            log(f"pool-fresh skip {row['advisory']}: no OSV record or no CWE in family {row['family']}")
            continue
        rows.append(
            dict(
                repository=repo,
                repo=repo,
                url=row["url"],
                fix=row["fix"],
                parent=row["parent"],
                family=row["family"],
                cwe=cwe,
                advisory=row["advisory"],
                advisory_text=osv_text(record),
                ecosystem=row["ecosystem"],
                license_spdx=row.get("license_spdx"),
                origin="pool-fresh",
            )
        )
        counts["pool-fresh"] += 1

    # (b) pool-retry: the pilot sourced them, no site passed, repository not held out
    for row in [] if args.extend else pilot:
        repo = normalize(row["repository"])
        if repo in accepted:
            continue
        rows.append({**row, "repository": repo, "repo": repo, "origin": "pool-retry"})
        counts["pool-retry"] += 1

    # (c) OSV dump: GHSA advisories with exactly one GitHub fix commit, one family, repo not excluded
    pre: dict[str, dict] = {}
    records: dict[str, dict] = {}
    for eco_name, eco in OSV_ECOSYSTEMS.items():
        archive_path = Path(args.osv_dir) / f"{eco_name}.zip"
        counts[f"osv:{eco}:ghsa_records"] = 0
        counts[f"osv:{eco}:prefilter_pass"] = 0
        for record in dump_records(archive_path):
            counts[f"osv:{eco}:ghsa_records"] += 1
            row = github_row(record)
            try:
                if date.fromisoformat(row["published_at"][:10]) < date(2019, 1, 1):
                    raise source.Rejected("date")
                if row["type"] != "reviewed" or row.get("withdrawn_at"):
                    raise source.Rejected("advisory_status")
                if source.ecosystem(row) != eco:
                    raise source.Rejected("ecosystem")
                families = {f.id for c in row["cwes"] if (f := taxonomy.family_of_cwe(c["cwe_id"])) and f.id in source.FAMILIES}
                if len(families) != 1:
                    raise source.Rejected("family")
                if family and families != {family}:
                    raise source.Rejected("family_mismatch")
                links = source.fix_links(row)
                if len(links) != 1:
                    raise source.Rejected("fix_links")
                ((repo, _),) = links
                if repo in excluded_repos:
                    reason = next(reason for reason, names in exclusion_groups.items() if repo in names)
                    raise source.Rejected(f"excluded_{reason}")
            except source.Rejected as exc:
                counts[f"osv:{eco}:{exc}"] += 1
                continue
            counts[f"osv:{eco}:prefilter_pass"] += 1
            records[record["id"]] = record
            # one advisory per repository: the most recently published one
            current = pre.get(repo)
            if current is None or row["published_at"] > current["published_at"]:
                pre[repo] = {**row, "_eco": eco}
        log(json.dumps({k: v for k, v in sorted(counts.items()) if k.startswith(f"osv:{eco}:")}))
    log(f"OSV prefilter: {len(pre)} repositories with a candidate advisory")
    counts["osv:prefilter_repositories"] = len(pre)

    github = None
    if not args.prefilter_only:
        token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()
        github = source.GitHub(token)
    else:
        log("PREFILTER ONLY: GitHub checks did not run; no advisories are accepted.")
    osv_stub = ZipOSV(records)
    ordered = source.ordered_advisories(list(pre.values()), args.seed)
    target = args.target if args.target is not None else (120 if family else 75)
    counts["target"] = target
    counts["github_checks_run"] = int(github is not None)
    counts["accepted"] = 0
    picked = 0
    for row in ordered if github is not None else []:
        if picked >= target:
            break
        try:
            cand = source.candidate(row, github, osv_stub)
        except source.Rejected as exc:
            counts[f"osv:check:{exc}"] += 1
            continue
        except RepositoryNotFound:
            counts["osv:check:not_found"] += 1
            continue
        except ValueError as exc:
            counts[f"osv:check:{type(exc).__name__}:{exc}"] += 1
            continue
        if cand.license_class != "permissive":
            counts["osv:check:licence_not_permissive"] += 1
            continue
        if cand.repository in excluded_repos:
            counts["osv:check:excluded_after_resolution"] += 1
            continue
        record = records[row["ghsa_id"]]
        cwe = cwe_for(record, cand.family, taxonomy)
        rows.append(
            dict(
                repository=cand.repository,
                repo=cand.repository,
                url=cand.url,
                fix=cand.fix,
                parent=cand.parent,
                family=cand.family,
                cwe=cwe,
                advisory=cand.advisory,
                advisory_text=osv_text(record),
                ecosystem=cand.ecosystem,
                license_spdx=cand.license_spdx,
                origin="osv-extend" if args.extend else "osv",
            )
        )
        excluded_repos.add(cand.repository)
        picked += 1
        counts["osv"] += 1
        counts["accepted"] += 1
        log(f"osv pick {picked}/{target}: {cand.repository} {cand.advisory} {cand.ecosystem} {cand.family} {cand.license_spdx}")
    counts["github_api_calls"] = github.calls if github is not None else 0
    counts["osv_api_calls"] = osv_api.calls
    # the candidate list must not contain a held-out repository, whatever the origin
    assert not {row["repository"] for row in rows} & accepted
    stem = f"sources_{family}" if family else ("sources_extend" if args.extend else "sources")
    output = HERE if family else WORK
    (output / f"{stem}.json").write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n")
    (output / f"{stem}_log.json").write_text(json.dumps(dict(sorted(counts.items())), indent=2) + "\n")
    log(json.dumps(dict(sorted(counts.items()))))
    log(f"{stem}.json: {len(rows)} advisories, {len({r['repository'] for r in rows})} repositories")
    return 0


def dump_records(path: Path):
    """Read GHSA records from a dump and report the bytes read from the first record."""
    with zipfile.ZipFile(path) as archive:
        first = True
        for name in archive.namelist():
            if not name.startswith("GHSA-") or not name.endswith(".json"):
                continue
            data = archive.read(name)
            if first:
                log(f"read {path}: {name}, {len(data)} bytes")
                first = False
            yield json.loads(data)


# ----------------------------------------------------------------------------- clone


def clone_one(repo: str, url: str, fix: str) -> tuple[Path | None, str, str | None]:
    """Clone single-branch with history, make sure fix and fix^1 are present, return (dir, status, parent)."""
    target = HIST / repo.replace("/", "__")
    if not (target / ".git").exists():
        if target.exists():
            shutil.rmtree(target)
        done = subprocess.run(
            ["git", "-c", "credential.helper=", "clone", "--quiet", "--single-branch", "--no-tags", "--no-checkout", url, str(target)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=1800,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if done.returncode:
            shutil.rmtree(target, ignore_errors=True)
            return None, "clone_failed", None
        # No working tree: everything downstream reads objects (git show / log / diff). The first 64 clones were
        # emptied the same way after the disk guard fired: `git sparse-checkout disable` restores a checkout.
        git(target, "sparse-checkout", "set", "--no-cone", "/__worktree_emptied_for_disk__", check=False)
    has_fix = git(target, "cat-file", "-e", f"{fix}^{{commit}}", check=False).returncode == 0
    if not has_fix:
        fetched = git(target, "fetch", "--quiet", "--depth", "2", "origin", fix, check=False)
        if fetched.returncode:
            fetched = git(target, "fetch", "--quiet", "origin", fix, check=False)
        if fetched.returncode or git(target, "cat-file", "-e", f"{fix}^{{commit}}", check=False).returncode:
            return target, "fix_unreachable", None
    parents = git(target, "rev-list", "--parents", "-n", "1", fix).stdout.split()[1:]
    if len(parents) != 1:
        return target, f"parents_{len(parents)}", None
    parent = parents[0]
    if git(target, "cat-file", "-e", f"{parent}^{{commit}}", check=False).returncode:
        fetched = git(target, "fetch", "--quiet", "--depth", "1", "origin", parent, check=False)
        if fetched.returncode or git(target, "cat-file", "-e", f"{parent}^{{commit}}", check=False).returncode:
            return target, "parent_unreachable", None
    # prove the parent's tree is readable: the catalog reads blobs at fix^1
    if git(target, "ls-tree", "-r", "--name-only", parent, check=False).returncode:
        return target, "parent_tree_unreadable", None
    return target, "ok", parent


def cmd_clone(args) -> int:
    sources_path = Path(args.sources) if args.sources else WORK / "sources.json"
    rows = json.loads(sources_path.read_text())
    HIST.mkdir(parents=True, exist_ok=True)
    repos_path = WORK / "repos_hist.json"
    repos = json.loads(repos_path.read_text()) if repos_path.exists() else {}
    clone_log_path = WORK / "clone_log.json"
    clone_log = json.loads(clone_log_path.read_text()) if clone_log_path.exists() else {}
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_repo[row["repository"]].append(row)
    stopped = False
    for index, (repo, entries) in enumerate(sorted(by_repo.items()), 1):
        if repo in clone_log and clone_log[repo].get("status") == "ok" and all(e.get("parent_from_git") for e in entries):
            continue
        free = free_bytes(HIST)
        if free < MIN_FREE_BYTES:
            log(f"STOP: free space {free / 1024**3:.1f} GB under 6 GB before cloning {repo}")
            stopped = True
            break
        started = time.monotonic()
        url = entries[0]["url"]
        status, parent_seen = "ok", {}
        target = None
        for entry in entries:
            target, status, parent = clone_one(repo, url, entry["fix"])
            parent_seen[entry["fix"]] = parent
            if status != "ok":
                break
        size = sum(p.stat().st_size for p in target.rglob("*") if p.is_file()) if target and target.exists() else 0
        commits = (
            git(target, "rev-list", "--count", "--first-parent", "HEAD", check=False).stdout.strip() if target and status == "ok" else ""
        )
        clone_log[repo] = {
            "status": status,
            "bytes": size,
            "seconds": round(time.monotonic() - started, 1),
            "first_parent_commits": int(commits) if commits else None,
            "parents": parent_seen,
        }
        if status == "ok":
            repos[repo] = str(target)
            for entry in entries:
                entry["parent_from_git"] = parent_seen[entry["fix"]]
        else:
            if target and target.exists():
                shutil.rmtree(target, ignore_errors=True)
            repos.pop(repo, None)
        log(
            f"[{index}/{len(by_repo)}] {repo}: {status} {size / 1024**2:.1f} MB {clone_log[repo]['seconds']}s free={free_bytes(HIST) / 1024**3:.1f}GB"  # noqa: E501
        )
        repos_path.write_text(json.dumps(dict(sorted(repos.items())), indent=1) + "\n")
        clone_log_path.write_text(json.dumps(dict(sorted(clone_log.items())), indent=1) + "\n")
    # rewrite sources: parent = fix^1 from git; move uncloned entries aside
    kept, dropped = [], []
    for row in rows:
        entry = clone_log.get(row["repository"], {})
        parent = row.get("parent_from_git") or entry.get("parents", {}).get(row["fix"])
        if entry.get("status") == "ok" and parent:
            if row["parent"] != parent:
                row["source_parent"] = row["parent"]
            row["parent"] = parent
            row.pop("parent_from_git", None)
            kept.append(row)
        else:
            dropped.append({**row, "clone_status": entry.get("status", "not_cloned")})
    sources_path.write_text(json.dumps(kept, indent=1, ensure_ascii=False) + "\n")
    (sources_path.with_name(sources_path.stem + "_dropped.json")).write_text(json.dumps(dropped, indent=1, ensure_ascii=False) + "\n")
    total = sum(e["bytes"] for e in clone_log.values())
    log(
        f"cloned {sum(e['status'] == 'ok' for e in clone_log.values())}/{len(by_repo)} repositories, {total / 1024**3:.2f} GB, kept {len(kept)} sources, dropped {len(dropped)}, stopped={stopped}"  # noqa: E501
    )
    return 1 if stopped else 0


# ----------------------------------------------------------------------------- filter


def site_rejection(path: str) -> str | None:
    if MINIFIED_PATH.search(path):
        return "minified"
    if VENDORED_PATH.search(path):
        return "vendored"
    if TEST_PATH.search(path):
        return "test"
    return None


def cmd_filter(args) -> int:
    from benchmarks.valid.catalog import write_catalog

    cases = tomllib.loads(Path(args.catalog).read_text())["case"]
    kept, reasons = [], Counter()
    for case in cases:
        reason = site_rejection(case["path"])
        if reason:
            reasons[reason] += 1
            continue
        kept.append(case)
    write_catalog(Path(args.out), kept)
    log(f"catalog: {len(cases)} sites -> {len(kept)} kept, dropped {dict(reasons)}")
    (WORK / "catalog_filter_log.json").write_text(
        json.dumps({"input": len(cases), "kept": len(kept), "dropped": dict(reasons)}, indent=2) + "\n"
    )
    return 0


# ----------------------------------------------------------------------------- verify


class CountingClient:
    def __init__(self, inner, budget: int):
        self.inner, self.budget, self.calls = inner, budget, 0

    def complete(self, **kwargs):
        if self.calls >= self.budget:
            raise BudgetExhausted()
        self.calls += 1
        return self.inner.complete(**kwargs)


class BudgetExhausted(RuntimeError):
    pass


def cmd_verify(args) -> int:
    from benchmarks.unseen.eligibility import normalize
    from benchmarks.valid.catalog import local_git
    from benchmarks.valid.verify import DEFAULT_DETECTOR_MODEL, DeepSeekChatClient, verify_case, write_records
    from openultrasast.config import load_config
    from openultrasast.model.endpoint import resolve_chat_endpoint

    if not os.environ.get("DEEPSEEK_API_KEY"):
        log("DEEPSEEK_API_KEY is not exported")
        return 2
    resolved = resolve_chat_endpoint(load_config(dotenv=False))
    if resolved is None or resolved[1].provider != "deepseek":
        log("DeepSeek provider is required")
        return 2
    client = resolved[0]
    if isinstance(client, DeepSeekChatClient):
        client = client.bounded(1200)
    counting = CountingClient(client, args.budget)
    repos = {normalize(k): local_git(Path(v)) for k, v in json.loads(Path(args.repos).read_text()).items()}
    cases = tomllib.loads(Path(args.catalog).read_text())["case"]
    out = Path(args.out)
    records = {row["id"]: row for row in json.loads(out.read_text())["cases"]} if out.exists() else {}
    log_path = WORK / "verify_log.json"
    vlog = json.loads(log_path.read_text()) if log_path.exists() else {"calls": 0, "errors": {}, "passes": 0}
    # round-robin across advisories so an advisory with many sites cannot eat the budget alone
    groups: dict[str, list[dict]] = defaultdict(list)
    for case in sorted(cases, key=lambda c: c["id"]):
        groups[case["advisory"]].append(case)
    order = []
    depth = max(len(v) for v in groups.values())
    for level in range(depth):
        for advisory in sorted(groups):
            if level < len(groups[advisory]):
                order.append(groups[advisory][level])
    errors: Counter = Counter(vlog.get("errors", {}))
    started = time.monotonic()
    done = 0
    for case in order:
        if case["id"] in records and not (args.retry_errors and records[case["id"]].get("error")):
            continue
        if counting.calls >= args.budget:
            log(f"budget of {args.budget} calls reached")
            break
        try:
            record = verify_case(repos[normalize(case["repo"])], case, client=counting)
        except BudgetExhausted:
            break
        except Exception as exc:  # provider or parse failure: record the type only, never the payload
            record = {
                "id": case["id"],
                "verdict": "rejected",
                "error": type(exc).__name__,
                "model": DEFAULT_DETECTOR_MODEL,
                "human_spot_check": None,
            }
            errors[type(exc).__name__] += 1
        records[case["id"]] = record
        done += 1
        passed = record.get("verdict") == "pending_human"
        log(
            f"{case['id']} -> {record.get('verdict')}{' PASS' if passed else ''}{' error=' + record['error'] if record.get('error') else ''} calls={counting.calls}"  # noqa: E501
        )
        if done % 5 == 0:
            write_records(out, list(records.values()))
    write_records(out, list(records.values()))
    vlog["calls"] = vlog.get("calls", 0) + counting.calls
    vlog["errors"] = dict(errors)
    vlog["passes"] = sum(r.get("verdict") == "pending_human" for r in records.values())
    vlog["records"] = len(records)
    vlog["catalog_sites"] = len(cases)
    vlog["seconds"] = vlog.get("seconds", 0) + round(time.monotonic() - started)
    vlog["model"] = DEFAULT_DETECTOR_MODEL
    vlog["budget"] = args.budget
    log_path.write_text(json.dumps(vlog, indent=2, sort_keys=True) + "\n")
    log(json.dumps(vlog, sort_keys=True))
    return 0


# ----------------------------------------------------------------------------- candidates


def cmd_candidates(args) -> int:
    cases = {c["id"]: c for c in tomllib.loads(Path(args.catalog).read_text())["case"]}
    records = json.loads(Path(args.verification).read_text())["cases"]
    sources = {row["advisory"]: row for row in json.loads((HERE / "sources.json").read_text())}
    passing = [r for r in records if r.get("verdict") == "pending_human"]
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for record in passing:
        by_repo[cases[record["id"]]["repo"]].append(record)
    languages = Counter(cases[r["id"]]["language"] for r in passing)
    changes = {(cases[r["id"]]["repo"], cases[r["id"]]["commit"]) for r in passing}
    lines = [
        "# Training-set candidates for the maintainer's spot-check",
        "",
        f"Generated {date.today().isoformat()} by `benchmarks/valid/train/sourcing.py candidates`. Every location below passed all three",
        "model checks (vulnerable before the fix, fix addresses it, reachable from an in-repo entry point) and waits for a",
        "human accept or reject. Nothing here is a positive until accepted. Accept or reject a location with",
        "",
        "    .venv/bin/python -m benchmarks.valid.verify spot-check benchmarks/valid/train/verification.json <id> accept|reject --reviewer <you> --date YYYY-MM-DD",  # noqa: E501
        "",
        f"Sites passing: {len(passing)} in {len(by_repo)} repositories, {len(changes)} positive changes (fix commits); languages: "
        + ", ".join(f"{k} {v}" for k, v in sorted(languages.items())),
        "",
        "The verifier's entry point is the model's claim, not a checked fact; it is the reason the site passed the reachability check.",
        "",
    ]
    for repo in sorted(by_repo):
        rows = sorted(by_repo[repo], key=lambda r: r["id"])
        first = cases[rows[0]["id"]]
        src = sources.get(first["advisory"], {})
        lines += [
            f"## {repo}",
            "",
            f"- advisory: {first['advisory']} ({first['family']}, {first['cwe']}), origin `{src.get('origin', '?')}`, ecosystem {src.get('ecosystem', '?')}, licence {src.get('license_spdx', '?')}",  # noqa: E501
            f"- fix `{first['commit']}`, parent (fix^1) `{first['parent']}`",
            f"- advisory title: {(first.get('advisory_text') or '').strip().splitlines()[0][:160] if first.get('advisory_text') else ''}",
            "",
            "| id | path::function (pre-fix lines) | language | entry point (verifier) | confidence |",
            "|---|---|---|---|---|",
        ]
        for record in rows:
            case = cases[record["id"]]
            span = case["function_lines"][0]
            entry = str(record.get("entry_point", "")).replace("|", "\\|").replace("\n", " ")[:200]
            lines.append(
                f"| `{record['id']}` | `{case['path']}::{case['function']}` ({span[0]}-{span[1]}) | {case['language']} | {entry} | {record.get('confidence')} |"  # noqa: E501
            )
        lines.append("")
    Path(args.out).write_text("\n".join(lines) + "\n")
    log(f"CANDIDATES.md: {len(passing)} sites, {len(by_repo)} repos, {len(changes)} changes, languages {dict(languages)}")
    return 0


# ----------------------------------------------------------------------------- overlap

GITHUB = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.IGNORECASE)
REPO_LINE = re.compile(r'^\s*(?:repo|fix_repo)\s*=\s*"([^"]+)"', re.MULTILINE)


def named_elsewhere() -> dict[str, set[str]]:
    """Every repository the development tree already names, by where it is named. Mirrors the repository guards in
    tests/ (test_advisory_fix_pairs, test_independent_population): github.com/<name> anywhere under benchmarks/, src/,
    tests/, plane/ and .kiro/, plus `repo = "..."` lines, plus the strict used set. Vendored trees are skipped as the
    pair guard skips them; this directory is skipped because it is what is being checked."""
    from openultrasast.learn.labels import repo_name

    found: dict[str, set[str]] = defaultdict(set)
    for top in ("benchmarks", "src", "tests", "plane", ".kiro"):
        for path in (ROOT / top).rglob("*"):
            if "node_modules" in path.parts or "vendor" in path.parts or path.is_relative_to(HERE):
                continue
            if not path.is_file() or path.suffix in {".pyc", ".bin", ".gz"}:
                continue
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            label = "benchmarks/" + path.relative_to(ROOT / "benchmarks").parts[0] if top == "benchmarks" else top
            for match in GITHUB.findall(text):
                found[repo_name(match)].add(label)
            for match in REPO_LINE.findall(text):
                with contextlib.suppress(Exception):  # an unparseable value is not a repository name
                    found[repo_name(match)].add(label)
    for name in json.loads((WORK / "used_strict.json").read_text()):
        found[name].add("used_strict")
    return found


def cmd_overlap(args) -> int:
    """Drop every candidate whose repository the tree already names; write the surviving sources to the tree."""
    from openultrasast.learn.labels import repo_name

    elsewhere = named_elsewhere()
    if args.family:
        for reason, names in family_exclusions().items():
            for name in names:
                elsewhere.setdefault(name, set()).add(reason)
    rows = [row for name in args.batches for row in json.loads((WORK / name).read_text())]
    kept, dropped = [], []
    for row in rows:
        if args.family and row["family"] != args.family:
            continue
        where = sorted(elsewhere.get(repo_name(row["repository"]), ()))
        if where:
            dropped.append({"repository": row["repository"], "advisory": row["advisory"], "origin": row["origin"], "named_in": where})
        else:
            kept.append(row)
    assert not {repo_name(r["repository"]) for r in kept} & pilot_accepted()
    suffix = f"_{args.family}" if args.family else ""
    (WORK / f"overlap{suffix}_dropped.json").write_text(json.dumps(dropped, indent=1) + "\n")
    if not args.family:
        (WORK / "sources.json").write_text(json.dumps(kept, indent=1, ensure_ascii=False) + "\n")
    (HERE / f"sources{suffix}.json").write_text(json.dumps(kept, indent=1, ensure_ascii=False) + "\n")
    log(
        f"overlap: {len(rows)} sources, {len(dropped)} dropped (named elsewhere), {len(kept)} kept; by origin dropped {dict(Counter(d['origin'] for d in dropped))}"  # noqa: E501
    )
    return 0


def cmd_merge(args) -> int:
    """Tree catalog.toml and verification.json: the batch files restricted to the surviving sources."""
    from benchmarks.valid.catalog import write_catalog
    from benchmarks.valid.verify import write_records

    suffix = f"_{args.family}" if args.family else ""
    advisories = {row["advisory"] for row in json.loads((HERE / f"sources{suffix}.json").read_text())}
    cases = [c for name in args.catalogs for c in tomllib.loads((WORK / name).read_text()).get("case", []) if c["advisory"] in advisories]
    # A site whose code or advisory text links a repository the tree already names (a pair-corpus or reserved
    # repository in a code comment, say) would put that name back into benchmarks/: drop the site, record why.
    from openultrasast.learn.labels import repo_name

    elsewhere = json.loads((WORK / "named_elsewhere.json").read_text())
    dropped = []
    for case in list(cases):
        names = {repo_name(m) for value in case.values() if isinstance(value, str) for m in GITHUB.findall(value)} - {case["repo"]}
        hits = sorted(n for n in names if n in elsewhere and not n.startswith("user-attachments/"))
        if hits:
            cases.remove(case)
            dropped.append({"id": case["id"], "repo": case["repo"], "names": hits})
    (WORK / f"merge{suffix}_dropped_sites.json").write_text(json.dumps(dropped, indent=1) + "\n")
    ids = {c["id"] for c in cases}
    records = [r for name in args.verifications for r in json.loads((WORK / name).read_text())["cases"] if r["id"] in ids]
    write_catalog(HERE / f"catalog{suffix}.toml", cases)
    write_records(HERE / f"verification{suffix}.json", records)
    log(f"merge: {len(cases)} sites, {len(records)} verification records, {len(dropped)} sites dropped for naming a used repository")
    return 0


# ----------------------------------------------------------------------------- precheck


def cmd_precheck(args) -> int:
    from benchmarks.unseen import extract
    from benchmarks.unseen.eligibility import normalize
    from benchmarks.valid.catalog import local_git

    cases = {c["id"]: c for c in tomllib.loads(Path(args.catalog).read_text())["case"]}
    records = json.loads(Path(args.verification).read_text())["cases"]
    repos = json.loads(Path(args.repos).read_text())
    passing = defaultdict(list)
    for record in records:
        if record.get("verdict") == "pending_human":
            passing[cases[record["id"]]["repo"]].append(cases[record["id"]])
    result = {}
    for repo in sorted(passing):
        git_ = local_git(Path(repos[repo]))
        all_cases = [c for c in cases.values() if normalize(c["repo"]) == repo]
        fixes = {c["commit"] for c in all_cases}
        functions = {(c["path"], c["function"]) for c in all_cases}
        head = git_.run("rev-parse", "HEAD").strip()
        started = time.monotonic()
        try:
            history = extract.ordinary_history(git_, head)
        except Exception as exc:  # assemble.freeze calls the same function and would stop on this repository
            result[repo] = {"error": f"{type(exc).__name__}: {exc}", "seconds": round(time.monotonic() - started, 1)}
            log(f"{repo}: ordinary_history failed: {type(exc).__name__}: {exc}")
            (WORK / "precheck.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
            continue
        available = sum(extract.ordinary_rejection(row, fixes, functions) is None for row in history)
        changes = len({(c["commit"], c["parent"]) for c in passing[repo]})
        result[repo] = {
            "first_parent_commits": len(history),
            "ordinary_available": available,
            "positive_changes": changes,
            "needed_at_ratio_20": 20 * changes,
            "enough": available >= 20 * changes,
            "seconds": round(time.monotonic() - started, 1),
        }
        (WORK / "precheck.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        log(
            f"{repo}: {available} ordinary of {len(history)} first-parent commits, needs {20 * changes}, enough={available >= 20 * changes}"
        )
    (WORK / "precheck.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


def main(argv=None) -> int:
    from benchmarks.unseen.source import FAMILIES

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("used")
    p = sub.add_parser("sources")
    p.add_argument("--osv-dir", required=True)
    p.add_argument("--target", type=int, help="OSV advisories to accept after GitHub checks (default: 120 with --family, otherwise 75)")
    p.add_argument("--seed", type=int, default=1)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--extend", action="store_true", help="second OSV batch into sources_extend.json, excluding sources.json")
    mode.add_argument("--family", choices=sorted(FAMILIES), help="source one family into sources_<family>.json in the training directory")
    p.add_argument(
        "--prefilter-only", action="store_true", help="with --family, read dumps and exclusions without GitHub checks or accepts"
    )
    p = sub.add_parser("clone")
    p.add_argument("--sources", help="sources file to clone (default sources.json)")
    p = sub.add_parser("filter")
    p.add_argument("catalog")
    p.add_argument("--out", required=True)
    p = sub.add_parser("verify")
    p.add_argument("catalog")
    p.add_argument("--repos", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--budget", type=int, default=600)
    p.add_argument("--retry-errors", action="store_true")
    p = sub.add_parser("candidates")
    p.add_argument("verification")
    p.add_argument("catalog")
    p.add_argument("--out", required=True)
    p = sub.add_parser("overlap")
    p.add_argument("--family", choices=sorted(FAMILIES))
    p.add_argument("batches", nargs="+", help="source batch files in the work directory")
    p = sub.add_parser("merge")
    p.add_argument("--family", choices=sorted(FAMILIES))
    p.add_argument("--catalogs", nargs="+", required=True)
    p.add_argument("--verifications", nargs="+", required=True)
    p = sub.add_parser("precheck")
    p.add_argument("verification")
    p.add_argument("catalog")
    p.add_argument("--repos", required=True)
    args = parser.parse_args(argv)
    if args.command == "sources" and args.prefilter_only and not args.family:
        parser.error("--prefilter-only requires --family")
    return {
        "used": cmd_used,
        "sources": cmd_sources,
        "clone": cmd_clone,
        "filter": cmd_filter,
        "verify": cmd_verify,
        "candidates": cmd_candidates,
        "precheck": cmd_precheck,
        "overlap": cmd_overlap,
        "merge": cmd_merge,
    }[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
