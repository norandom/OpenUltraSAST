"""Coordinator-only sourcing command: python -m benchmarks.unseen.draft --help.

All network and git operations are injected at the run() boundary. Only counts,
digests and fixed failure codes go to stdout; identity-bearing output stays in the
private journal outside the repository. No population guard is run here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import random
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from . import eligibility, extract, source
from .extract import Git, InstrumentFailure
from .journal import Journal, ResolvedGitHub, ResumeMismatch, Stopped, atomic, digest, external


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def private_digest(row: dict) -> str:
    return hashlib.sha256(canonical({"url": row["url"], "commits": [[c["base"], c["head"]] for c in row["changes"]]})).hexdigest()


def assign_slices(rows: list[dict], *, seed: int) -> list[dict]:
    if len(rows) != 300 or len({r["repository"] for r in rows}) != 300:
        raise ValueError("pool_size")
    for row in rows:
        kinds = Counter(c["kind"] for c in row["changes"])
        if kinds != {"vulnerability": 1, "ordinary": 12}:
            raise ValueError("change_count")
        if row["license_class"] not in {"permissive", "private"}:
            raise ValueError("license_class")
        if row["license_class"] == "permissive" and row["license_spdx"] not in source.PERMISSIVE:
            raise ValueError("license_class")
    rng = random.Random(seed)
    groups = defaultdict(list)
    for row in sorted(rows, key=lambda r: r["repository"]):
        groups[row["ecosystem"], row["post_cutoff"]].append(row)
    sizes = Counter({1: 0, 2: 0, 3: 0})
    assigned = []
    for key in sorted(groups):
        group = groups[key]
        rng.shuffle(group)
        quotient, remainder = divmod(len(group), 3)
        # Give each stratum its floor on all slices, then fill globally least-full slices.
        quotas = {i: quotient for i in sizes}
        order = list(sizes)
        rng.shuffle(order)
        order.sort(key=lambda i: sizes[i])
        for i in order[:remainder]:
            quotas[i] += 1
        offset = 0
        for slice_id in sorted(quotas):
            for row in group[offset : offset + quotas[slice_id]]:
                digest = private_digest(row)
                assigned.append({**row, "id": "r-" + digest[:24], "slice": slice_id})
            sizes[slice_id] += quotas[slice_id]
            offset += quotas[slice_id]
    if set(sizes.values()) != {100}:
        raise ValueError("slice_size")
    return sorted(assigned, key=lambda r: (r["slice"], r["id"]))


def toml(value) -> str:
    """Inline TOML values keep nested change records structured without a new dependency."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(k) + " = " + toml(v) for k, v in sorted(value.items()) if v is not None) + "}"
    raise ValueError("unsupported_manifest_type")


def manifest(rows: list[dict], seed: int) -> str:
    lines = ['status = "draft"', 'pool = "p1"', f"seed = {seed}"]
    for row in rows:
        lines.append("\n[[repository]]")
        lines.extend(f"{key} = {toml(value)}" for key, value in sorted(row.items()) if value is not None)
    return "\n".join(lines) + "\n"


def write_draft(root: Path, assigned: list[dict], *, seed: int) -> tuple[Path, Path]:
    public_path = root / "benchmarks/unseen/draft-p1.toml"
    private_path = root / "benchmarks/unseen/private/draft-p1.toml"
    if public_path.exists() or private_path.exists():
        raise FileExistsError("draft_exists")
    public, private = [], []
    for row in assigned:
        if row["license_class"] == "permissive":
            public.append(row)
        else:
            private.append(row)
            public.append({"id": row["id"], "sha256": private_digest(row), "slice": row["slice"], "private": True})
    private_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Exclusive creates protect drafts awaiting human label review. Private first: never
    # publish a pointer whose private manifest failed to write.
    with private_path.open("x") as handle:
        os.chmod(private_path, 0o600)
        handle.write(manifest(private, seed))
    with public_path.open("x") as handle:
        handle.write(manifest(public, seed))
    return public_path, private_path


class Clones:
    """One disposable blobless clone at a time; no name in cache paths or subprocess output."""

    def __init__(self, root: Path, cache: Path, *, runner=None, limit_bytes=500 * 1024 * 1024):
        self.cache = external(root, cache)
        self.runner = runner or subprocess.run
        self.limit_bytes = limit_bytes
        self.counts = Counter()

    @contextmanager
    def open(self, url: str):
        self.cache.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="clone-", dir=self.cache) as directory:
            path = Path(directory)
            git = Git(path, runner=self.runner, limit_bytes=self.limit_bytes)
            try:
                # Full commit graph is needed for temporal thirds and OSV brackets; blobs
                # are fetched lazily. This is a partial clone, not a truncated history.
                done = self.runner(
                    ["git", "-c", "credential.helper=", "clone", "--quiet", "--filter=blob:none", "--no-checkout", url, str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=180,
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                )
                if done.returncode:
                    raise InstrumentFailure("clone_failed")
                self.counts["clones"] += 1
                if git.disk_bytes() > self.limit_bytes:
                    raise InstrumentFailure("clone_size_cap")
                yield git
            finally:
                size = git.disk_bytes()
                self.counts["clone_bytes"] += size
                self.counts["peak_clone_bytes"] = max(self.counts["peak_clone_bytes"], size)
                self.counts["source_bytes_read"] += git.bytes_read
                self.counts["source_files_read"] += git.files_read
                self.counts["clone_wall_seconds"] += round(time.monotonic() - started, 3)


def prove_source(git, revision: str) -> dict:
    files = git.run("ls-tree", "-r", "--name-only", revision).splitlines()
    for path in files:
        if Path(path).suffix in extract.LANGUAGES and not extract.generated_path(path):
            text = git.blob(revision, path)
            if text:
                return {"files": 1, "bytes": getattr(git, "last_blob_bytes", len(text.encode()))}
    raise InstrumentFailure("zero_source_bytes")


def advisory_index(rows: list[dict], github) -> dict[str, set[str]]:
    """Include ALL enumerated fixes, even old, unmapped, multi-fix and other ecosystems.

    Canonicalize link names as well, so an old advisory URL survives repository renames.
    A 404 is not treated as proof that an advisory is unrelated to a selected repository.
    """
    index = defaultdict(set)
    for row in rows:
        for name, sha in source.fix_links(row):
            try:
                resolved = eligibility.resolve(name, github)
            except eligibility.RepositoryNotFound:
                index[name].add(sha)
                continue
            index[resolved.full_name].add(sha)
    return dict(index)


def repository_changes(git, candidate, fixes: set[str], *, seed: int):
    proof = prove_source(git, candidate.parent)
    change = extract.introducing(git, candidate)
    known = set()
    expanded = set()
    for fix in sorted(fixes | {candidate.fix}):
        # Explicitly fetch detached advisory commits unavailable on default-branch history.
        # All git including this possible network call still goes through the injected client.
        git.run("fetch", "--quiet", "--filter=blob:none", "origin", fix)
        full = git.run("rev-parse", fix).strip()
        expanded.add(full)
        parents = git.parents(full)
        for parent in parents:
            sites = extract.fix_sites(git, full, parent, global_ok=True)
            known.update((site["path"], site["function"]) for site in sites)
    rows = extract.ordinary_history(git, "HEAD")
    ordinary, exclusions = extract.draw_ordinary(rows, expanded, known, seed=seed)
    return [change, *ordinary], exclusions, proof


def inputs(used, seed, known_empty, clones):
    from openultrasast.model.taxonomy import DEFAULT_FAMILIES_PATH

    parameters = {
        "seed": seed,
        "used_set_digest": digest({label: sorted(names) for label, names in used.sources.items()}),
        "known_empty": sorted(known_empty),
        "clone_limit_bytes": getattr(clones, "limit_bytes", 500 * 1024 * 1024),
        "journal_version": 2,
    }
    # Hardcoded design thresholds and algorithms are covered as well as taxonomy data.
    for name in ("draft", "source", "extract", "eligibility", "journal"):
        parameters["design_" + name] = hashlib.sha256(Path(__file__).with_name(name + ".py").read_bytes()).hexdigest()
    parameters["design_taxonomy"] = hashlib.sha256(DEFAULT_FAMILIES_PATH.read_bytes()).hexdigest()
    return parameters


def enumerate_advisories(github, journal):
    page, records = 1, {}
    while True:
        key = str(page)
        if key not in journal.rows["advisories"]:
            journal.boundary()
            result = github.advisory_page(page)
            journal.put("advisories", key, {"rows": [source.reduce_advisory(row) for row in result["rows"]], "done": result["done"]})
        result = journal.rows["advisories"][key]
        records.update((row["ghsa_id"], row) for row in result["rows"])
        if result["done"]:
            break
        page += 1
    if not records:
        raise InstrumentFailure("empty_advisories")
    return list(records.values())


def decide(row, github, osv, used, selected_networks):
    try:
        links = source.fix_links(row)
        if len(links) != 1:
            raise source.Rejected("fix_links")
        name, _ = next(iter(links))
        resolved = eligibility.resolve(name, github)
        rejected_by = eligibility.rejection(resolved, used, set(selected_networks))
        if rejected_by:
            raise source.Rejected("used_" + rejected_by)
        candidate = source.candidate(row, github, osv)
        return {"candidate": asdict(candidate), "network": resolved.network}
    except source.Rejected as exc:
        return {"rejected": str(exc)}
    except eligibility.RepositoryNotFound:
        return {"rejected": "repository_or_commit_not_found"}


def extract_repository(candidate, github, clones, fixes, seed):
    before = dict(clones.counts)
    try:
        with clones.open(candidate.url) as git:
            git.run("fetch", "--quiet", "--filter=blob:none", "origin", candidate.fix)
            changes, exclusions, proof = repository_changes(git, candidate, fixes, seed=seed)
            pinned = changes[0]["head"]
            license_record = github.get_license(candidate.repository, pinned)
            spdx, license_class = source.license_info(license_record)
            entry = {
                **asdict(candidate),
                "license_spdx": spdx,
                "license_class": license_class,
                "license_ref": pinned,
                "license_path": license_record.get("path", ""),
                "changes": changes,
                "instrument": proof,
            }
        result = {"entry": entry, "ordinary_exclusions": exclusions}
    except source.Rejected as exc:
        result = {"rejected": str(exc), "ordinary_exclusions": getattr(exc, "counts", {})}
    except eligibility.RepositoryNotFound:
        result = {"rejected": "repository_or_commit_not_found", "ordinary_exclusions": {}}
    result["counts"] = {key: value - before.get(key, 0) for key, value in clones.counts.items()}
    return result


def publish(journal, assigned, seed):
    """Idempotent publication from completed journal data, never inside the checkout."""
    public, private = [], []
    for row in assigned:
        if row["license_class"] == "permissive":
            public.append(row)
        else:
            private.append(row)
            public.append({"id": row["id"], "sha256": private_digest(row), "slice": row["slice"], "private": True})
    for name, rows in (("private-draft-p1.toml", private), ("draft-p1.toml", public)):
        path = journal.path / name
        data = manifest(rows, seed).encode()
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError("draft_exists")
        else:
            atomic(path, data)


def run(
    root: Path,
    *,
    github,
    osv,
    clones,
    used: eligibility.UsedSet,
    seed: int,
    known_empty=None,
    journal_path=None,
    max_hours=None,
    clock=None,
) -> dict:
    started = time.monotonic()
    report = {"status": "sourcing", "seed": seed, "candidates": {}, "rejections": {}, "ordinary_exclusions": {}}
    counts, rejected, ordinary_counts = Counter(), Counter(), Counter()
    checkpoint = None
    try:
        known_empty = set(known_empty or ())
        used.report(known_empty)
        cache = getattr(clones, "cache", root.parent / (root.name + "-cache"))
        path = external(root, journal_path or cache / "journal")
        checkpoint = Journal(
            path, max_hours=max_hours, clock=clock, rate_limit=lambda: getattr(getattr(github, "transport", None), "rate_limit", {})
        )
        with checkpoint.open(inputs(used, seed, known_empty, clones)):
            checkpoint.boundary()
            api = ResolvedGitHub(github, checkpoint)
            used = copy.deepcopy(used)  # canonicalization must not mutate the resume input
            eligibility.canonicalize_used(used, api)
            report["used_set"] = used.report(known_empty)
            rows = enumerate_advisories(api, checkpoint)
            report["advisories"] = len(rows)
            fixes_by_repo = advisory_index(rows, api)
            selected_networks, entries = set(), []
            for row in source.ordered_advisories(rows, seed):
                checkpoint.boundary()
                key = row["ghsa_id"]
                counts[source.ecosystem(row)] += 1
                if key not in checkpoint.rows["eligibility"]:
                    decision = decide(row, api, osv, used, selected_networks)
                    checkpoint.put("eligibility", key, decision)
                decision = checkpoint.rows["eligibility"][key]
                if "rejected" in decision:
                    rejected[decision["rejected"]] += 1
                    continue
                candidate = source.Candidate(**decision["candidate"])
                # Multiple advisories for one repository can have different fix/range inputs.
                extraction_key = digest({"repository": candidate.repository, "advisory": key, "fix": candidate.fix})
                if extraction_key not in checkpoint.rows["extraction"]:
                    checkpoint.boundary()
                    result = extract_repository(candidate, api, clones, fixes_by_repo.get(candidate.repository, set()), seed)
                    checkpoint.put("extraction", extraction_key, result)
                result = checkpoint.rows["extraction"][extraction_key]
                ordinary_counts.update(result["ordinary_exclusions"])
                if "rejected" in result:
                    rejected[result["rejected"]] += 1
                    continue
                selected_networks.add(decision["network"])
                entries.append(result["entry"])
                if len(entries) == 300:
                    break
            report.update(
                {
                    "repositories": len(entries),
                    "candidates": dict(counts),
                    "rejections": dict(rejected),
                    "ordinary_exclusions": dict(ordinary_counts),
                }
            )
            checkpoint.boundary()
            if len(entries) != 300:
                report["status"] = "insufficient_repositories"
                checkpoint.progress(report["status"])
                return report
            assigned = assign_slices(entries, seed=seed)
            completion = {"manifest_sha256": digest(assigned), "repositories": len(entries)}
            if "all" not in checkpoint.rows["completion"]:
                checkpoint.put("completion", "all", completion)
            elif checkpoint.rows["completion"]["all"] != completion:
                raise ValueError("journal_completion_mismatch")
            checkpoint.boundary()
            publish(checkpoint, assigned, seed)
            report.update(
                {
                    "status": "draft",
                    "changes": 3900,
                    "slices": 3,
                    "license_split": dict(Counter(e["license_class"] for e in entries)),
                    "methods": dict(Counter(e["changes"][0]["method"] for e in entries)),
                    "post_cutoff": sum(e["post_cutoff"] for e in entries),
                    **completion,
                }
            )
            checkpoint.progress("draft")
            return report
    except ResumeMismatch as exc:
        report.update({"status": "resume_refused", "changed_parameters": exc.parameters})
        return report
    except Stopped as exc:
        report.update({"status": "stopped", "reason": str(exc)})
        return report
    except Exception as exc:
        report.update({"status": "instrument_failure", "error_type": type(exc).__name__})
        return report
    finally:
        report.update({"candidates": dict(counts), "rejections": dict(rejected), "ordinary_exclusions": dict(ordinary_counts)})
        report["instrument"] = dict(clones.counts)
        report["wall_seconds"] = round(time.monotonic() - started, 3)
        report["github_calls"] = github.calls
        report["osv_calls"] = osv.calls
        report["github_http_attempts"] = getattr(getattr(github, "transport", None), "attempts", github.calls)
        report["osv_http_attempts"] = getattr(getattr(osv, "transport", None), "attempts", osv.calls)


def main(argv: list[str] | None = None) -> int:
    from openultrasast import config
    from openultrasast.plane import memory
    from openultrasast.plane.reconciler import results_root

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--max-hours", type=float, help="Stop between units after this many hours per invocation")
    parser.add_argument("--seed", type=int, default=20260601)
    parser.add_argument("--local-store")
    parser.add_argument("--s3-store", default="s3://")
    parser.add_argument("--pointer-manifest", type=Path, action="append", default=[])
    parser.add_argument("--known-empty", choices=(*eligibility.SOURCES, "memory_local", "memory_s3"), action="append", default=[])
    args = parser.parse_args(argv)
    try:
        config.load_dotenv(args.root / ".env")
        # Refuse an existing draft before doing any network work.
        if any((args.root / p).exists() for p in ("benchmarks/unseen/draft-p1.toml", "benchmarks/unseen/private/draft-p1.toml")):
            raise FileExistsError("draft_exists")
        clones = Clones(args.root, args.cache or results_root() / "unseen-draft")
        stores = {
            "local": memory.open_store(args.local_store or "file://" + str(results_root() / "memory"), read_only=True),
            "s3": memory.open_store(args.s3_store, read_only=True),
        }
        used = eligibility.build_used(args.root, stores=stores, pointer_manifests=args.pointer_manifest)
        report = run(
            args.root,
            github=source.GitHub(os.environ.get("GH_TOKEN", "")),
            osv=source.OSV(),
            clones=clones,
            used=used,
            seed=args.seed,
            known_empty=set(args.known_empty),
            journal_path=clones.cache / "journal",
            max_hours=args.max_hours,
        )
    except Exception as exc:
        report = {"status": "instrument_failure", "error_type": type(exc).__name__}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in {"draft", "stopped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
