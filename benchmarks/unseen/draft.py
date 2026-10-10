"""Coordinator-only sourcing command: python -m benchmarks.unseen.draft --help.

All network and git operations are injected at the run() boundary. Only counts,
digests and fixed failure codes go to stdout; identity-bearing output stays in the
private journal or corpus bucket. No population guard is run here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import multiprocessing
import os
import random
import subprocess
import tempfile
import time
from collections import Counter, defaultdict, deque
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from concurrent.futures.process import BrokenProcessPool
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
from pathlib import Path

from . import eligibility, extract, source
from .bank import CorpusBank, CorpusObjects, corpus_settings, split_decided
from .extract import EXTRACTION_CONTRACT, RESOLUTION_CONTRACT, Git, InstrumentFailure
from .journal import Journal, ResolvedGitHub, ResumeMismatch, Stopped, atomic, digest, external


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def private_digest(row: dict) -> str:
    return hashlib.sha256(canonical({"url": row["url"], "commits": [[c["base"], c["head"]] for c in row["changes"]]})).hexdigest()


def validate_pool(pool_size: int, slices: int) -> None:
    if pool_size < 1:
        raise ValueError("--pool-size must be at least 1")
    if slices < 1 or slices > pool_size:
        raise ValueError("--slices must be between 1 and --pool-size")
    if pool_size % slices:
        raise ValueError("--pool-size must be divisible by --slices")


def assign_slices(rows: list[dict], *, seed: int, pool_size: int = 300, slices: int = 3) -> list[dict]:
    validate_pool(pool_size, slices)
    if len(rows) != pool_size or len({r["repository"] for r in rows}) != pool_size:
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
    sizes = Counter({i: 0 for i in range(1, slices + 1)})
    assigned = []
    for key in sorted(groups):
        group = groups[key]
        rng.shuffle(group)
        quotient, remainder = divmod(len(group), slices)
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
    if set(sizes.values()) != {pool_size // slices}:
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
    """Disposable blobless clones; each worker receives its own counter accumulator."""

    def __init__(
        self,
        root: Path,
        cache: Path,
        *,
        runner=None,
        limit_bytes=500 * 1024 * 1024,
        deadline_seconds: float | None = None,
        parse_deadline_seconds: float | None = 120.0,
        extract_workers: int = 6,
    ):
        if extract_workers < 1:
            raise ValueError("invalid_extract_workers")
        self.extract_workers = extract_workers
        self.cache = external(root, cache)
        self.runner = runner or subprocess.run
        self.limit_bytes = limit_bytes
        self.deadline_seconds = deadline_seconds
        self.parse_deadline_seconds = parse_deadline_seconds
        self.counts = Counter()

    @contextmanager
    def open(self, url: str):
        self.cache.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="clone-", dir=self.cache) as directory:
            path = Path(directory)
            git = Git(path, runner=self.runner, limit_bytes=self.limit_bytes, deadline_seconds=self.deadline_seconds)
            try:
                # Full commit graph is needed for temporal thirds and OSV brackets.
                # A full-objects clone (no blob:none promisor) brings every blob in
                # one pack, so blame/log/diff read locally instead of fetching each
                # blob on demand (the old promisor path cost ~hundreds of round-trips
                # per repo). --no-checkout still skips the working tree. With no
                # promisor remote, a genuinely missing object errors loudly rather
                # than silently round-tripping. Disk is bounded by limit_bytes below.
                done = self.runner(
                    ["git", "-c", "credential.helper=", "clone", "--quiet", "--no-checkout", url, str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=git.command_timeout(),
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                )
                if done.returncode:
                    raise InstrumentFailure("clone_failed")
                self.counts["clones"] += 1
                if git.disk_bytes() > self.limit_bytes:
                    raise InstrumentFailure("clone_size_cap")
                yield git
            except subprocess.TimeoutExpired:
                raise extract.ExtractionTimeout("extraction_timeout") from None
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


class BankedGitHub(ResolvedGitHub):
    """Stream the fix index's repository metadata before continuing the draw."""

    def __init__(self, github, journal, bank):
        super().__init__(github, journal)
        self.bank = bank
        self.resolutions = bank.repositories(contract=RESOLUTION_CONTRACT)
        journal.rows["resolution"].update({name: body["metadata"] if body is not None else None for name, body in self.resolutions.items()})

    def resolve(self, name):
        key = eligibility.normalize(name)
        if key not in self.resolutions:
            try:
                resolved = eligibility.resolve(name, self)
            except eligibility.RepositoryNotFound:
                body = None
            else:
                body = {
                    "metadata": self.journal.rows["resolution"].get(key),
                    "full_name": resolved.full_name,
                    "names": sorted(resolved.names),
                    "network": resolved.network,
                }
            self.bank.bank_repository(key, body, contract=RESOLUTION_CONTRACT)
            self.resolutions[key] = body
        body = self.resolutions[key]
        if body is None:
            raise eligibility.RepositoryNotFound("not_found")
        return eligibility.Resolution(body["full_name"], frozenset(body["names"]), body["network"])


def resolve_repository(name, github):
    if isinstance(github, BankedGitHub):
        return github.resolve(name)
    return eligibility.resolve(name, github)


def advisory_index(rows: list[dict], github) -> dict[str, set[str]]:
    """Include ALL fixes in the enumerated population, even from rejected candidates.

    Canonicalize link names as well, so an old advisory URL survives repository renames.
    A 404 is not treated as proof that an advisory is unrelated to a selected repository.
    """
    index = defaultdict(set)
    for row in rows:
        for name, sha in source.fix_links(row):
            try:
                resolved = resolve_repository(name, github)
            except eligibility.RepositoryNotFound:
                index[name].add(sha)
                continue
            index[resolved.full_name].add(sha)
    return dict(index)


def repository_changes(git, candidate, fixes: set[str], *, seed: int):
    resolved = []
    for fix in sorted(fixes | {candidate.fix}):
        try:
            if fix != candidate.fix:
                # Extra advisory fixes are best-effort exclusions. The candidate
                # was fetched strictly by extract_repository. Do not import extra
                # tags before introducing() checks the candidate's version bracket.
                git.run("fetch", "--quiet", "--no-tags", "origin", fix)
            resolved.append(git.run("rev-parse", fix).strip())
        except InstrumentFailure as exc:
            if fix == candidate.fix or not str(exc).startswith("git_exit_"):
                raise
    proof = prove_source(git, candidate.parent)
    change = extract.introducing(git, candidate)
    known = set()
    expanded = set()
    for full in resolved:
        expanded.add(full)
        for parent in git.parents(full):
            sites = extract.fix_sites(git, full, parent, global_ok=True)
            known.update((site["path"], site["function"]) for site in sites)
    rows = extract.ordinary_history(git, "HEAD")
    ordinary, exclusions = extract.draw_ordinary(rows, expanded, known, seed=seed)
    return [change, *ordinary], exclusions, proof


def inputs(used, seed, known_empty, clones, *, pool_size=300, slices=3):
    from openultrasast.model.taxonomy import DEFAULT_FAMILIES_PATH

    parameters = {
        "seed": seed,
        "used_set_digest": digest({label: sorted(names) for label, names in used.sources.items()}),
        "known_empty": sorted(known_empty),
        "clone_limit_bytes": getattr(clones, "limit_bytes", 500 * 1024 * 1024),
        "journal_version": 4,
        "pool_size": pool_size,
        "slices": slices,
    }
    # Hardcoded design thresholds and algorithms are covered as well as taxonomy data.
    for name in ("draft", "source", "extract", "eligibility", "journal"):
        parameters["design_" + name] = hashlib.sha256(Path(__file__).with_name(name + ".py").read_bytes()).hexdigest()
    parameters["design_taxonomy"] = hashlib.sha256(DEFAULT_FAMILIES_PATH.read_bytes()).hexdigest()
    return parameters


def enumerate_advisories(github, journal):
    records = {}
    for ecosystem in source.ECOSYSTEMS:
        page = 1
        next_url = None
        while True:
            key = f"{ecosystem}:{page}"
            if key not in journal.rows["advisories"]:
                journal.boundary()
                result = github.advisory_page(next_url, ecosystem=ecosystem)
                journal.put(
                    "advisories", key, {"rows": [source.reduce_advisory(row) for row in result["rows"]], "next_url": result["next_url"]}
                )
            result = journal.rows["advisories"][key]
            records.update((row["ghsa_id"], row) for row in result["rows"])
            next_url = result["next_url"]
            if next_url is None:
                break
            page += 1
    if not records:
        raise InstrumentFailure("empty_advisories")
    return list(records.values())


def decide(row, github, osv, used, selected_networks=()):
    # selected_networks is retained for callers; only ordered acceptance consults it.
    network = {}
    try:
        links = source.fix_links(row)
        if len(links) != 1:
            raise source.Rejected("fix_links")
        name, _ = next(iter(links))
        resolved = resolve_repository(name, github)
        rejected_by = eligibility.rejection(resolved, used, set())
        if rejected_by:
            raise source.Rejected("used_" + rejected_by)
        network = {"network": resolved.network}
        candidate = source.candidate(row, github, osv)
        return {"candidate": asdict(candidate), "network": resolved.network}
    except source.Rejected as exc:
        return {"rejected": str(exc), **network}
    except eligibility.RepositoryNotFound:
        return {"rejected": "repository_or_commit_not_found", **network}
    except ValueError as exc:
        # A per-candidate transport failure (e.g. get_commit on an unresolvable fix ref)
        # skips this advisory; the run loop's systemic guard catches a broken instrument.
        if str(exc) == "http_failure":
            return {"rejected": "decide_http_failure", **network}
        raise


def extract_repository(candidate, github, clones, fixes, seed):
    before = dict(clones.counts)
    deadline = getattr(clones, "deadline_seconds", None)
    total = (deadline or 0) + (getattr(clones, "parse_deadline_seconds", None) or 0) if deadline is not None else None
    try:
        with extract.process_deadline(total):
            with clones.open(candidate.url) as git:
                git.run("fetch", "--quiet", "origin", candidate.fix)
                changes, exclusions, proof = repository_changes(git, candidate, fixes, seed=seed)
                entry = {**asdict(candidate), "changes": changes, "instrument": proof}
            result = {"entry": entry, "ordinary_exclusions": exclusions}
    except source.Rejected as exc:
        result = {"rejected": str(exc), "ordinary_exclusions": getattr(exc, "counts", {})}
    except eligibility.RepositoryNotFound:
        result = {"rejected": "repository_or_commit_not_found", "ordinary_exclusions": {}}
    except (extract.InstrumentFailure, OSError) as exc:
        result = {"rejected": "extract_" + str(exc), "ordinary_exclusions": {}}
    result["counts"] = {key: value - before.get(key, 0) for key, value in clones.counts.items()}
    return finish_license(result, github) if github is not None else result


def finish_license(result, github):
    """REST stays on the coordinator, including the license at the extracted pin."""
    if "entry" not in result:
        return result
    try:
        entry = result["entry"]
        pinned = entry["changes"][0]["head"]
        record = github.get_license(entry["repository"], pinned)
        spdx, license_class = source.license_info(record)
        entry.update(license_spdx=spdx, license_class=license_class, license_ref=pinned, license_path=record.get("path", ""))
    except (source.Rejected, eligibility.RepositoryNotFound) as exc:
        reason = "repository_or_commit_not_found" if isinstance(exc, eligibility.RepositoryNotFound) else str(exc)
        return {"rejected": reason, "ordinary_exclusions": {}, "counts": result["counts"]}
    except (extract.InstrumentFailure, OSError) as exc:
        return {"rejected": "extract_" + str(exc), "ordinary_exclusions": {}, "counts": result["counts"]}
    except ValueError as exc:
        if str(exc) != "http_failure":
            raise
        return {"rejected": "extract_http_failure", "ordinary_exclusions": {}, "counts": result["counts"]}
    return result


@contextmanager
def ordered_extractions(
    rows,
    api,
    osv,
    used,
    clones,
    fixes,
    seed,
    checkpoint,
    entries,
    workers,
    pool_size,
    bank: CorpusBank | None = None,
    decided=None,
    stale_resolutions=(),
):
    """Bounded in-flight work, completion journaling, and seed-order acceptance.

    Only running jobs count against `workers`; completed results wait in the
    journal while the acceptance cursor is blocked. Counters are private to each
    job, including clone cleanup, and merged exactly once on completion here.
    Graceful STOP/guard/target exits drain started work into the journal for resume;
    a hard interrupt may lose unjournaled work but cannot change accepted order.
    """
    decided = dict(decided or {})
    identities = {}
    pending = deque()  # Seed-order acceptance cursor; contains no futures/results.
    in_flight = {}  # Future -> extraction key, independent of the cursor.
    # Fork shares the coordinator's memory copy-on-write. Jobs receive only the
    # picklable extraction inputs, never the journal, REST clients or stores.
    context = multiprocessing.get_context("fork")
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=context)

    def resolution(row):
        key = row["ghsa_id"]
        if key not in checkpoint.rows["eligibility"]:
            result = decide(row, api, osv, used)
            if bank is not None:
                bank.bank_resolution(key, result, contract=RESOLUTION_CONTRACT)
            checkpoint.put("eligibility", key, result)
        return checkpoint.rows["eligibility"][key]

    def remember(repository, fix, result):
        bank.bank(repository, fix, result, contract=EXTRACTION_CONTRACT)
        # Reuse decisions made during this invocation too: another advisory for
        # the same pair must not overwrite an earlier accept with a rejection.
        decided[bank.key_for(repository, fix)] = {
            "repository": repository,
            "fix": fix,
            "decision": "accept" if "entry" in result else "reject",
            "entry": result.get("entry"),
            "reason": result.get("rejected"),
            "ordinary_exclusions": result.get("ordinary_exclusions", {}),
            "counts": result.get("counts", {}),
        }

    def collect(future):
        key = in_flight.pop(future)
        try:
            result = future.result()
        except BrokenProcessPool:
            # A killed worker also fails unrelated outstanding futures. Do not
            # mistake these collateral failures for a broken git instrument.
            result = {"rejected": "worker_crash", "ordinary_exclusions": {}, "counts": {}}
        except Exception:
            # Includes task/result serialization failures. Keep diagnostics
            # identity-free; repeated task errors still reach the normal guard.
            result = {"rejected": "extract_worker_failure", "ordinary_exclusions": {}, "counts": {}}
        for name, value in result["counts"].items():
            if name == "peak_clone_bytes":
                clones.counts[name] = max(clones.counts[name], value)
            else:
                clones.counts[name] += value
        result = finish_license(result, api)
        if bank is not None:
            repository, fix = identities[key]
            remember(repository, fix, result)
        checkpoint.put("extraction", key, result)

    def iterate():
        nonlocal pool
        ordered = iter(rows)
        exhausted = False

        def ready():
            return pending and (pending[0][2] is None or pending[0][2] in checkpoint.rows["extraction"])

        while (pending or not exhausted) and len(entries) < pool_size:
            # Only this cursor feeds acceptance, fork deduplication and the guard.
            # Replayed results follow the same path and need no worker submission.
            while ready():
                checkpoint.boundary()
                row, decision, key = pending.popleft()
                yield row, decision, checkpoint.rows["extraction"].get(key)
                if len(entries) == pool_size:
                    return
            while not exhausted and len(in_flight) < min(workers, pool_size - len(entries)):
                checkpoint.boundary()
                row = next(ordered, None)
                if row is None:
                    exhausted = True
                    break
                key = row["ghsa_id"]
                if key in stale_resolutions:
                    resolution(row)
                identity = None
                if bank is not None:
                    links = source.fix_links(row)
                    if len(links) == 1:
                        repository, fix = next(iter(links))
                        try:
                            resolved = resolve_repository(repository, api)
                            repository = resolved.full_name
                        except eligibility.RepositoryNotFound:
                            resolved = None
                        except ValueError as exc:
                            if str(exc) != "http_failure":
                                raise
                            resolved = None  # decide() records this as a resilient skip.
                        identity = (repository, fix)
                        saved = decided.get(bank.key_for(*identity))
                        if saved is None and len(fix) < 40:
                            matches = [
                                value for value in decided.values() if value["repository"] == repository and value["fix"].startswith(fix)
                            ]
                            if len(matches) == 1:
                                saved = matches[0]
                                identity = (repository, saved["fix"])
                        if saved is None:
                            # A duplicate advisory can arrive before its pair's
                            # worker finishes. Share that pending result as well.
                            matching = [key for key, pair in identities.items() if pair[0] == repository and pair[1].startswith(fix)]
                            if len(matching) == 1:
                                pending.append((row, {"network": resolved.network if resolved else repository}, matching[0]))
                                break
                        if saved is not None:
                            decision = {"network": resolved.network if resolved is not None else repository}
                            blocked = eligibility.rejection(resolved, used, set()) if resolved is not None else None
                            if blocked:
                                decision["rejected"] = "used_" + blocked
                                pending.append((row, decision, None))
                            else:
                                result = {"ordinary_exclusions": saved["ordinary_exclusions"], "counts": saved["counts"]}
                                if saved["decision"] == "accept":
                                    result["entry"] = saved["entry"]
                                else:
                                    result["rejected"] = saved["reason"]
                                extraction_key = bank.key_for(*identity)
                                if extraction_key not in checkpoint.rows["extraction"]:
                                    checkpoint.put("extraction", extraction_key, result)
                                pending.append((row, decision, extraction_key))
                            break
                decision = resolution(row)
                extraction_key, future = None, None
                if "candidate" in decision:
                    candidate = source.Candidate(**decision["candidate"])
                    extraction_key = digest({"repository": candidate.repository, "advisory": key, "fix": candidate.fix})
                    if bank is not None:
                        extraction_key = bank.key_for(candidate.repository, candidate.fix)
                        identities[extraction_key] = (candidate.repository, candidate.fix)
                    if extraction_key not in checkpoint.rows["extraction"] and extraction_key not in in_flight.values():
                        checkpoint.boundary()
                        local = copy.copy(clones)
                        local.counts = Counter()
                        args = (candidate, None, local, fixes.get(candidate.repository, set()), seed)
                        try:
                            future = pool.submit(extract_repository, *args)
                        except BrokenProcessPool:
                            # Already-submitted jobs retain their ordered crash
                            # skips; only new jobs enter the replacement pool.
                            pool.shutdown(wait=True, cancel_futures=True)
                            pool = ProcessPoolExecutor(max_workers=workers, mp_context=context)
                            future = pool.submit(extract_repository, *args)
                        in_flight[future] = extraction_key
                elif bank is not None and identity is not None:
                    remember(*identity, decision)
                pending.append((row, decision, extraction_key))
                # Finalize cached decisions promptly (especially on resume), and
                # service completed jobs even during a long run of decide skips.
                if ready() or any(future.done() for future in in_flight):
                    break
            if ready():
                continue
            if in_flight:
                checkpoint.boundary()
                done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                for future in done:
                    collect(future)
                # Freed slots are refilled on the next pass even if the oldest
                # candidate is still running. No result() waits on that cursor.

    interrupted = False
    stopped = None
    try:
        yield iterate()
    except BaseException as exc:
        interrupted = not isinstance(exc, Exception)
        stopped = str(exc) if isinstance(exc, Stopped) else None
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        if not interrupted:
            for future in list(in_flight):
                if not future.cancelled():
                    collect(future)
            if stopped is not None:
                checkpoint.progress("stopped", reason=stopped)


def publish(journal, assigned, seed, *, destination=None):
    """Idempotent publication from completed journal data, never inside the checkout."""
    public, private = [], []
    for row in assigned:
        if row["license_class"] == "permissive":
            public.append(row)
        else:
            private.append(row)
            public.append({"id": row["id"], "sha256": private_digest(row), "slice": row["slice"], "private": True})
    for name, rows in (("private-draft-p1.toml", private), ("draft-p1.toml", public)):
        path = (destination or journal.path) / name
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
    extract_workers=None,
    pool_size=300,
    slices=3,
    bank: CorpusBank | None = None,
) -> dict:
    validate_pool(pool_size, slices)
    workers = extract_workers if extract_workers is not None else getattr(clones, "extract_workers", 6)
    if workers < 1:
        raise ValueError("invalid_extract_workers")
    workers = min(workers, os.cpu_count() or 4)
    started = time.monotonic()
    report = {"status": "sourcing", "seed": seed, "candidates": {}, "rejections": {}, "ordinary_exclusions": {}}
    # Operational budget only: changing it must not invalidate journal resume inputs.
    report["extract_workers"] = workers
    report["extract_deadline_seconds"] = getattr(clones, "deadline_seconds", None)
    report["parse_deadline_seconds"] = getattr(clones, "parse_deadline_seconds", None)
    counts, rejected, ordinary_counts = Counter(), Counter(), Counter()
    checkpoint = None
    scratch = ExitStack()
    try:
        decided = bank.decided() if bank is not None else {}
        banked = bank.resolved() if bank is not None else {}
        accepted, reusable = split_decided(decided, contract=EXTRACTION_CONTRACT)
        decided = {key: value for key, value in decided.items() if key in reusable}
        known_empty = set(known_empty or ())
        used.report(known_empty)
        cache = getattr(clones, "cache", root.parent / (root.name + "-cache"))
        path = external(root, journal_path or cache / "journal")
        journal_directory = path
        if bank is not None:
            # Local records are a disposable cursor, never a cross-run authority.
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            journal_directory = Path(scratch.enter_context(tempfile.TemporaryDirectory(prefix="cursor-", dir=path)))
        checkpoint = Journal(
            journal_directory,
            max_hours=max_hours,
            clock=clock,
            rate_limit=lambda: getattr(getattr(github, "transport", None), "rate_limit", {}),
        )
        with checkpoint.open(inputs(used, seed, known_empty, clones, pool_size=pool_size, slices=slices)):
            checkpoint.boundary()
            api = BankedGitHub(github, checkpoint, bank) if bank is not None else ResolvedGitHub(github, checkpoint)
            checkpoint.rows["eligibility"].update(
                {key: body["result"] for key, body in banked.items() if body["resolution_contract"] == RESOLUTION_CONTRACT}
            )
            used = copy.deepcopy(used)  # canonicalization must not mutate the resume input
            eligibility.canonicalize_used(used, api)
            report["used_set"] = used.report(known_empty)
            rows = bank.cached_advisories(contract=RESOLUTION_CONTRACT) if bank is not None else None
            if rows is None:
                try:
                    rows = enumerate_advisories(api, checkpoint)
                except InstrumentFailure as exc:
                    if str(exc) != "empty_advisories" or not accepted:
                        raise
                    rows = []
                if bank is not None:
                    bank.cache_advisories(rows, contract=RESOLUTION_CONTRACT)
            if bank is not None:
                # Retain accepted entries even if their advisory disappeared upstream.
                present = {row["ghsa_id"] for row in rows}
                for entry in accepted:
                    if entry["advisory"] not in present:
                        rows.append(
                            {
                                "ghsa_id": entry["advisory"],
                                "published_at": "2026-06-02" if entry["post_cutoff"] else "2026-06-01",
                                "vulnerabilities": [{"package": {"ecosystem": entry["ecosystem"]}}],
                                "references": [f"https://github.com/{entry['repository']}/commit/{entry['fix']}"],
                            }
                        )
                        present.add(entry["advisory"])
            report["advisories"] = len(rows)
            fixes_by_repo = advisory_index(rows, api)
            selected_networks, entries = set(), []
            instrument_failures = 0
            with ordered_extractions(
                source.ordered_advisories(rows, seed),
                api,
                osv,
                used,
                clones,
                fixes_by_repo,
                seed,
                checkpoint,
                entries,
                workers,
                pool_size,
                bank=bank,
                decided=decided,
                stale_resolutions={key for key, body in banked.items() if body["resolution_contract"] != RESOLUTION_CONTRACT},
            ) as outcomes:
                for row, decision, result in outcomes:
                    counts[source.ecosystem(row)] += 1
                    if decision.get("network") in selected_networks:
                        # Serial decide skipped this candidate entirely. Even a failed
                        # speculative extraction must not affect the systemic guard.
                        rejected["fork_network"] += 1
                    elif "rejected" in decision:
                        rejected[decision["rejected"]] += 1
                        instrument_failures += int(decision["rejected"] == "decide_http_failure")
                    else:
                        ordinary_counts.update(result["ordinary_exclusions"])
                        if "rejected" in result:
                            rejected[result["rejected"]] += 1
                            instrument_failures += int(
                                result["rejected"].startswith("extract_") or result["rejected"] == "decide_http_failure"
                            )
                        else:
                            selected_networks.add(decision["network"])
                            entries.append(result["entry"])
                    # A low-yield draw can accumulate unbounded candidate failures;
                    # only zero accepted entries indicate a systemic failure.
                    if instrument_failures >= 25 and not entries:
                        raise extract.InstrumentFailure("systemic_extraction_failure")
                    if len(entries) == pool_size:
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
            if len(entries) != pool_size:
                report["status"] = "insufficient_repositories"
                checkpoint.progress(report["status"])
                return report
            assigned = assign_slices(entries, seed=seed, pool_size=pool_size, slices=slices)
            completion = {"manifest_sha256": digest(assigned), "repositories": len(entries)}
            if "all" not in checkpoint.rows["completion"]:
                checkpoint.put("completion", "all", completion)
            elif checkpoint.rows["completion"]["all"] != completion:
                raise ValueError("journal_completion_mismatch")
            checkpoint.boundary()
            publish(checkpoint, assigned, seed, destination=path if bank is not None else None)
            report.update(
                {
                    "status": "draft",
                    "changes": pool_size * 13,
                    "slices": slices,
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
        scratch.close()
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
    parser.add_argument("--extract-deadline", type=float, default=240.0, help="Extraction wall-clock budget per repository in seconds")
    parser.add_argument(
        "--parse-deadline",
        type=float,
        default=120.0,
        help="Extra wall-clock budget in seconds for the Python parse phase beyond --extract-deadline",
    )
    parser.add_argument("--extract-workers", type=int, default=6, help="Maximum extraction processes, capped to CPU cores (default: 6)")
    parser.add_argument("--pool-size", type=int, default=300, help="Repositories to accept (default: 300)")
    parser.add_argument("--slices", type=int, default=3, help="Equal-sized slices (default: 3)")
    parser.add_argument("--seed", type=int, default=20260601)
    parser.add_argument("--bank", nargs="?", const="unseen", default="", help="Corpus bucket prefix; enables durable decisions")
    parser.add_argument("--local-store")
    parser.add_argument("--s3-store", default="s3://")
    parser.add_argument("--pointer-manifest", type=Path, action="append", default=[])
    parser.add_argument("--known-empty", choices=(*eligibility.SOURCES, "memory_local", "memory_s3"), action="append", default=[])
    args = parser.parse_args(argv)
    try:
        validate_pool(args.pool_size, args.slices)
    except ValueError as exc:
        parser.error(str(exc))
    if args.extract_workers < 1:
        parser.error("--extract-workers must be at least 1")
    try:
        config.load_dotenv(args.root / ".env")
        # Refuse an existing draft before doing any network work.
        if any((args.root / p).exists() for p in ("benchmarks/unseen/draft-p1.toml", "benchmarks/unseen/private/draft-p1.toml")):
            raise FileExistsError("draft_exists")
        clones = Clones(
            args.root,
            args.cache or results_root() / "unseen-draft",
            deadline_seconds=args.extract_deadline,
            parse_deadline_seconds=args.parse_deadline,
            extract_workers=args.extract_workers,
        )
        stores = {
            "local": memory.open_store(args.local_store or "file://" + str(results_root() / "memory"), read_only=True),
            "s3": memory.open_store(args.s3_store, read_only=True),
        }
        used = eligibility.build_used(args.root, stores=stores, pointer_manifests=args.pointer_manifest)
        bank = CorpusBank(CorpusObjects(**corpus_settings()), seed=args.seed, prefix=args.bank) if args.bank else None
        report = run(
            args.root,
            github=source.GitHub(os.environ.get("GH_TOKEN", "")),
            osv=source.OSV(),
            clones=clones,
            used=used,
            seed=args.seed,
            pool_size=args.pool_size,
            slices=args.slices,
            known_empty=set(args.known_empty),
            journal_path=clones.cache / "journal",
            max_hours=args.max_hours,
            bank=bank,
        )
    except Exception as exc:
        report = {"status": "instrument_failure", "error_type": type(exc).__name__}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] in {"draft", "stopped"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
