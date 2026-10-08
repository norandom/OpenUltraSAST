"""Draft and coordinator tests contain synthetic identities only and use injected clients."""

import copy
import importlib
import sys
import tomllib
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
d = importlib.import_module("benchmarks.unseen.draft")
s = importlib.import_module("benchmarks.unseen.source")
e = importlib.import_module("benchmarks.unseen.eligibility")


def entries():
    rows = []
    for i in range(300):
        changes = [{"kind": "vulnerability", "method": "introducing", "base": "a" * 40, "head": "b" * 40}]
        changes += [{"kind": "ordinary", "method": "first_parent", "base": f"{j:040x}", "head": f"{j + 20:040x}"} for j in range(12)]
        rows.append(
            {
                "repository": f"fixture/project{i:03d}",
                "url": f"https://github.com/fixture/project{i:03d}",
                "ecosystem": s.ECOSYSTEMS[i % 4],
                "post_cutoff": i % 7 == 0,
                "license_spdx": "MIT" if i % 2 else "GPL-3.0",
                "license_class": "permissive" if i % 2 else "private",
                "license_ref": "b" * 40,
                "changes": changes,
            }
        )
    return rows


def test_draft_split_digest_and_balanced_slices(tmp_path):
    rows = entries()
    assigned = d.assign_slices(rows, seed=19)
    assert Counter(r["slice"] for r in assigned) == {1: 100, 2: 100, 3: 100}
    assert assigned == d.assign_slices(list(reversed(rows)), seed=19)
    strata = Counter((r["ecosystem"], r["post_cutoff"]) for r in assigned)
    for slice_id in (1, 2, 3):
        counts = Counter((r["ecosystem"], r["post_cutoff"]) for r in assigned if r["slice"] == slice_id)
        assert all(abs(counts[key] - total / 3) < 1 for key, total in strata.items())
    public, private = d.write_draft(tmp_path, assigned, seed=19)
    public_text = public.read_text()
    shared = tomllib.loads(public_text)
    hidden = tomllib.loads(private.read_text())
    assert len(shared["repository"]) == 300 and len(hidden["repository"]) == 150
    assert sum(len(r["changes"]) for r in shared["repository"] if "changes" in r) == 1950
    for row in hidden["repository"]:
        assert row["url"] not in public_text and row["repository"] not in public_text
        pointer = next(p for p in shared["repository"] if p["id"] == row["id"])
        assert set(pointer) == {"id", "sha256", "slice", "private"}
        assert pointer["sha256"] == d.private_digest(row)
        changed = copy.deepcopy(row)
        changed["changes"][0]["head"] = "c" * 40
        assert d.private_digest(changed) != pointer["sha256"]
    assert private.is_relative_to(tmp_path / "benchmarks/unseen/private")
    with pytest.raises(FileExistsError):
        d.write_draft(tmp_path, assigned, seed=19)


def test_draft_requires_full_size_and_valid_changes():
    with pytest.raises(ValueError, match="pool_size"):
        d.assign_slices(entries()[:299], seed=1)
    rows = entries()
    rows[0]["changes"].pop()
    with pytest.raises(ValueError, match="change_count"):
        d.assign_slices(rows, seed=1)


def test_cache_is_outside_repository_deleted_and_partial(tmp_path):
    import subprocess

    root, cache = tmp_path / "repo", tmp_path / "cache"
    root.mkdir()
    with pytest.raises(ValueError, match="cache_inside_repository"):
        d.Clones(root, root / "cache")
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        if "clone" in argv:
            target = Path(argv[-1])
            (target / ".git").mkdir()
            (target / ".git/pack").write_bytes(b"123")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    clones = d.Clones(root, cache, runner=runner)
    with clones.open("https://github.com/fixture/project") as git:
        assert git.path.exists()
        clone_path = git.path
    assert not clone_path.exists()
    assert "--filter=blob:none" in calls[0] and "--no-checkout" in calls[0]
    assert clones.counts["clones"] == 1 and clones.counts["clone_bytes"] == 3


def test_clone_failure_sanitized_and_cleaned(tmp_path, capsys):
    import subprocess

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 128, b"", b"private identity")

    clones = d.Clones(tmp_path / "repo", tmp_path / "cache", runner=runner)
    with pytest.raises(d.InstrumentFailure), clones.open("https://github.com/fixture/project"):
        pass
    assert list((tmp_path / "cache").iterdir()) == []
    assert not capsys.readouterr().out


class FakeAPI:
    calls = 0

    def __init__(self, count=300):
        self.count = count
        self.licenses = []
        self.advisory_pages = []

    def get_repo(self, name):
        self.calls += 1
        if name == "fixture/old":
            name = "fixture/project000"
        repo = {"full_name": name, "private": False, "size": 2, "clone_url": "https://github.com/" + name}
        if name == "fixture/fork":
            repo["source"] = {"full_name": "fixture/project001"}
        return repo

    def get_commit(self, name, sha):
        self.calls += 1
        return {"sha": sha, "parents": [{"sha": "b" * 40}]}

    def get_license(self, name, ref):
        self.licenses.append((name, ref))
        self.calls += 1
        # P is MIT but actual introducing head is GPL: public output must use V.
        return {"text": "", "spdx_id": "MIT" if ref == "b" * 40 else "GPL-3.0", "path": "LICENSE"}

    def advisory_page(self, next_url=None, *, ecosystem):
        self.calls += 1
        self.advisory_pages.append((ecosystem, next_url))
        population = list(self.advisories()) if ecosystem == "pip" else []
        offset = int(next_url.rsplit("=", 1)[1]) if next_url else 0
        rows = population[offset : offset + 100]
        following = f"https://api.github.com/advisories?after={offset + 100}" if offset + 100 < len(population) else None
        return {"rows": rows, "next_url": following}

    def advisories(self):
        for i in range(self.count):
            yield {
                "ghsa_id": f"GHSA-test-test-{i:04d}",
                "published_at": "2026-06-02T00:00:00Z",
                "cwes": [{"cwe_id": "CWE-89"}],
                "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "fixture"}}],
                "references": [f"https://github.com/fixture/project{i:03d}/commit/" + "a" * 40],
            }


class FakeOSV:
    calls = 0

    def get(self, identifier):
        self.calls += 1
        return {}


class FakeClones:
    def __init__(self):
        self.counts = Counter()
        self.commands = []

    @contextmanager
    def open(self, url):
        self.counts["clones"] += 1
        yield self

    def run(self, *args):
        self.commands.append(args)
        return ""


class FailingClones(FakeClones):
    def __init__(self, failures):
        super().__init__()
        self.failures = failures

    @contextmanager
    def open(self, url):
        self.url = url
        with super().open(url) as git:
            yield git

    def run(self, *args):
        if args[0] == "fetch" and self.url in self.failures:
            raise self.failures[self.url]
        return super().run(*args)


def test_extraction_failures_skip_bad_repositories_and_reach_target(tmp_path, monkeypatch):
    api, used = FakeAPI(303), e.UsedSet()
    ordered = s.ordered_advisories(list(api.advisories()), 7)
    failures = {row["references"][0].split("/commit/")[0]: d.InstrumentFailure("git_exit_128") for row in ordered[:3]}
    clones = FailingClones(failures)
    changes = entries()[0]["changes"]
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {}, {"bytes": 12, "files": 1}))
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=clones, used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "draft" and report["repositories"] == 300
    assert report["rejections"] == {"extract_git_exit_128": 3}
    assert clones.counts["clones"] == 303


@pytest.mark.parametrize(
    "successes,failures,status",
    [
        (0, 24, "insufficient_repositories"),
        (0, 26, "instrument_failure"),
        (1, 200, "insufficient_repositories"),
        (1, 202, "instrument_failure"),
    ],
)
def test_systemic_extraction_guard_boundaries(tmp_path, monkeypatch, successes, failures, status):
    api, used = FakeAPI(successes + failures), e.UsedSet()
    ordered = s.ordered_advisories(list(api.advisories()), 7)
    clones = FailingClones({row["references"][0].split("/commit/")[0]: d.InstrumentFailure("git_exit_128") for row in ordered[successes:]})
    changes = entries()[0]["changes"]
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {}, {"bytes": 12, "files": 1}))
    journal_path = tmp_path / "journal"
    kwargs = dict(
        root=tmp_path / "repo",
        github=api,
        osv=FakeOSV(),
        clones=clones,
        used=used,
        seed=7,
        known_empty=set(used.sources),
        journal_path=journal_path,
    )
    report = d.run(**kwargs)
    expected_failures = min(failures, 201 if successes else 25)
    assert report["status"] == status
    assert report["rejections"] == {"extract_git_exit_128": expected_failures}
    assert clones.counts["clones"] == successes + expected_failures
    assert not (journal_path / "draft-p1.toml").exists()
    if status == "instrument_failure":
        assert report["error_type"] == "InstrumentFailure"
        # Replayed failures must trip the same guard without attempting more clones.
        resumed = d.run(**kwargs)
        assert resumed["status"] == status and resumed["rejections"] == report["rejections"]
        assert clones.counts["clones"] == successes + expected_failures


@pytest.mark.parametrize(
    "exception,reason", [(d.InstrumentFailure("clone_size_cap"), "extract_clone_size_cap"), (OSError("disk_error"), "extract_disk_error")]
)
def test_extraction_failure_preserves_rejection_shape_and_count_delta(exception, reason):
    class BrokenClones(FakeClones):
        @contextmanager
        def open(self, url):
            with super().open(url):
                raise exception
                yield  # pragma: no cover

    candidate = s.candidate(next(FakeAPI(1).advisories()), FakeAPI(), FakeOSV())
    clones = BrokenClones()
    clones.counts["clones"] = 10
    assert d.extract_repository(candidate, FakeAPI(), clones, set(), 7) == {
        "rejected": reason,
        "ordinary_exclusions": {},
        "counts": {"clones": 1},
    }


def test_non_instrument_extraction_bug_propagates_and_aborts(tmp_path):
    api, used = FakeAPI(2), e.UsedSet()
    candidate = s.candidate(next(api.advisories()), api, FakeOSV())
    clones = FailingClones({row["references"][0].split("/commit/")[0]: ValueError("code_bug") for row in api.advisories()})
    with pytest.raises(ValueError, match="code_bug"):
        d.extract_repository(candidate, api, clones, set(), 7)
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=clones, used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "instrument_failure" and report["error_type"] == "ValueError"
    assert report["rejections"] == {} and clones.counts["clones"] == 2


def test_ordinary_rejections_do_not_trip_extraction_guard(tmp_path, monkeypatch):
    class ExcludedAPI(FakeAPI):
        def advisories(self):
            for row in super().advisories():
                if int(row["ghsa_id"].rsplit("-", 1)[1]) < 225:
                    row["references"] = []
                yield row

    def ordinary_floor(*args, **kwargs):
        raise s.Rejected("ordinary_floor")

    monkeypatch.setattr(d, "repository_changes", ordinary_floor)
    used, clones = e.UsedSet(), FakeClones()
    report = d.run(tmp_path, github=ExcludedAPI(450), osv=FakeOSV(), clones=clones, used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "insufficient_repositories" and report["repositories"] == 0
    assert report["rejections"] == {"fix_links": 225, "ordinary_floor": 225}
    assert clones.counts["clones"] == 225


def test_coordinator_end_to_end_fakes_pinned_license_and_no_names(tmp_path, monkeypatch, capsys):
    rows = entries()
    changes = copy.deepcopy(rows[0]["changes"])
    changes[0]["head"] = "c" * 40
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {"security": 4, "eligible": 40}, {"bytes": 12, "files": 1}))
    used, api, clones = e.UsedSet(), FakeAPI(), FakeClones()
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=clones, used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "draft" and report["changes"] == 3900
    assert report["license_split"] == {"private": 300}
    assert report["ordinary_exclusions"]["security"] == 1200
    assert len([ref for _, ref in api.licenses if ref == "c" * 40]) == 300
    public = (tmp_path.parent / (tmp_path.name + "-cache") / "journal/draft-p1.toml").read_text()
    assert "fixture/" not in public
    import json

    assert "fixture/" not in json.dumps(report)
    assert capsys.readouterr().out == ""


def test_used_rename_and_fork_resolution_and_shortfall(tmp_path, monkeypatch):
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (entries()[0]["changes"], {}, {"bytes": 1, "files": 1}))
    used, api, clones = e.UsedSet(), FakeAPI(2), FakeClones()
    used.add("pairs", {"fixture/old"}, 10)
    # project000 resolves from used alias; project001 is reached via used fork's source.
    used.add("pairs", {"fixture/fork"}, 10)
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=clones, used=used, seed=7, known_empty=set(used.sources) - {"pairs"})
    assert report["status"] == "insufficient_repositories"
    assert report["rejections"] == {"used_pairs": 2}
    assert report["repositories"] == 0 and not clones.counts
    assert not (tmp_path / "benchmarks/unseen/draft-p1.toml").exists()


def test_systemic_zero_source_is_instrument_failure_with_recorded_rejections(tmp_path, monkeypatch):
    def unread(*args, **kwargs):
        raise d.InstrumentFailure("zero_source_bytes")

    monkeypatch.setattr(d, "repository_changes", unread)
    used = e.UsedSet()
    clones = FakeClones()
    report = d.run(tmp_path, github=FakeAPI(30), osv=FakeOSV(), clones=clones, used=used, seed=1, known_empty=set(used.sources))
    assert report["status"] == "instrument_failure"
    assert report["rejections"] == {"extract_zero_source_bytes": 25}
    assert clones.counts["clones"] == 25


@pytest.mark.parametrize("deadline_args,deadline", [([], 240.0), (["--extract-deadline", "12.5"], 12.5)])
def test_cli_uses_environment_and_injected_stores(tmp_path, monkeypatch, capsys, deadline_args, deadline):
    import json

    from openultrasast import config
    from openultrasast.plane import memory

    seen = []
    monkeypatch.setenv("GH_TOKEN", "fake-secret")
    monkeypatch.setattr(config, "load_dotenv", lambda path: None)
    monkeypatch.setattr(memory, "open_store", lambda value, **kw: seen.append((value, kw)) or object())
    monkeypatch.setattr(d.eligibility, "build_used", lambda *a, **kw: e.UsedSet())
    monkeypatch.setattr(d.source, "GitHub", lambda token: seen.append(token) or FakeAPI(0))
    monkeypatch.setattr(d.source, "OSV", FakeOSV)
    args = ["--root", str(tmp_path), "--cache", str(tmp_path.parent / "clone-cache")]
    for label in e.SOURCES:
        args += ["--known-empty", label]
    assert d.main(args + deadline_args) == 1
    output = capsys.readouterr().out
    assert json.loads(output)["extract_deadline_seconds"] == deadline
    assert "instrument_failure" in output and "fake-secret" not in output and "fixture/" not in output
    assert seen[-1] == "fake-secret"
    assert all(kwargs == {"read_only": True} for _, kwargs in seen[:-1])


@pytest.mark.parametrize("timeout_stage", ["clone", "fetch"])
def test_timeout_skips_repository_and_draft_continues(tmp_path, monkeypatch, timeout_stage):
    import subprocess

    clone_count = 0

    def runner(cmd, **kwargs):
        nonlocal clone_count
        if "clone" in cmd:
            clone_count += 1
        if clone_count == 1 and timeout_stage in cmd:
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (entries()[0]["changes"], {}, {"bytes": 1, "files": 1}))
    clones = d.Clones(tmp_path / "repo", tmp_path / "cache", runner=runner, deadline_seconds=240.0)
    used = e.UsedSet()
    report = d.run(tmp_path / "repo", github=FakeAPI(2), osv=FakeOSV(), clones=clones, used=used, seed=1, known_empty=set(used.sources))
    assert report["status"] == "insufficient_repositories"
    assert report["rejections"] == {"extraction_timeout": 1}
    assert report["repositories"] == 1 and clone_count == 2
    assert not list(clones.cache.glob("clone-*"))


def test_clone_time_counts_and_each_repository_gets_fresh_deadline(tmp_path, monkeypatch):
    import subprocess

    now, timeouts = [0.0], []
    monkeypatch.setattr(d.time, "monotonic", lambda: now[0])

    def runner(cmd, **kwargs):
        timeouts.append(kwargs["timeout"])
        now[0] += 7.0 if "clone" in cmd else 1.0
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    clones = d.Clones(tmp_path / "repo", tmp_path / "cache", runner=runner, deadline_seconds=10.0)
    for _ in range(2):
        with clones.open("https://github.com/fixture/project") as git:
            git.run("log")
            now[0] += 3.0
            with pytest.raises(d.extract.ExtractionTimeout, match="^extraction_timeout$"):
                git.run("log")
    assert timeouts == [10.0, 3.0, 10.0, 3.0]


def test_deadline_is_reported_without_changing_resume_inputs(tmp_path):
    clones = d.Clones(tmp_path / "repo", tmp_path / "cache", deadline_seconds=240.0)
    used = e.UsedSet()
    before = d.inputs(used, 1, set(used.sources), clones)
    kwargs = dict(
        root=tmp_path / "repo",
        github=FakeAPI(),
        osv=FakeOSV(),
        clones=clones,
        used=used,
        seed=1,
        known_empty=set(used.sources),
        max_hours=0,
    )
    assert d.run(**kwargs)["status"] == "stopped"
    clones.deadline_seconds = 12.5
    assert d.inputs(used, 1, set(used.sources), clones) == before
    report = d.run(**kwargs)
    assert report["status"] == "stopped"
    assert report["extract_deadline_seconds"] == 12.5


def test_repository_changes_excludes_all_advisory_sites(monkeypatch):
    calls = []

    class FakeGit:
        def run(self, *args):
            calls.append(args)
            if args[0] == "ls-tree":
                return "app.py\n"
            return args[-1] if args[0] == "rev-parse" else ""

        def blob(self, revision, path):
            return "def handler():\n    return 1\n"

        def parents(self, fix):
            return ["b" * 40]

    candidate = s.Candidate(
        "fixture/project",
        "https://github.com/fixture/project",
        "a" * 40,
        "b" * 40,
        "GHSA-test-test-test",
        "pip",
        "injection",
        True,
        None,
        "MIT",
        "permissive",
        "b" * 40,
        "LICENSE",
    )
    monkeypatch.setattr(d.extract, "introducing", lambda *a: {"head": "c" * 40})
    monkeypatch.setattr(d.extract, "fix_sites", lambda git, fix, parent, **kw: [{"path": "app.py", "function": fix}])
    monkeypatch.setattr(d.extract, "ordinary_history", lambda *a: [])

    def draw(rows, fixes, known, **kwargs):
        assert fixes == {"a" * 40, "d" * 40}
        assert known == {("app.py", "a" * 40), ("app.py", "d" * 40)}
        return [], {}

    monkeypatch.setattr(d.extract, "draw_ordinary", draw)
    _, _, proof = d.repository_changes(FakeGit(), candidate, {"d" * 40}, seed=1)
    assert proof["bytes"] > 0
    assert len([c for c in calls if c[0] == "fetch"]) == 2


def test_candidate_404_is_counted_but_service_failure_aborts(tmp_path):
    class Missing(FakeAPI):
        def get_commit(self, name, sha):
            raise e.RepositoryNotFound("not_found")

    class Broken(FakeAPI):
        def get_commit(self, name, sha):
            raise ValueError("private URL must never escape")

    for api, status in [(Missing(1), "insufficient_repositories"), (Broken(1), "instrument_failure")]:
        used = e.UsedSet()
        report = d.run(
            tmp_path,
            github=api,
            osv=FakeOSV(),
            clones=FakeClones(),
            used=used,
            seed=1,
            known_empty=set(used.sources),
            journal_path=tmp_path.parent / (tmp_path.name + type(api).__name__) / "journal",
        )
        assert report["status"] == status
        if status == "insufficient_repositories":
            assert report["rejections"] == {"repository_or_commit_not_found": 1}
        assert "private URL" not in str(report)


def test_shortfall_keeps_ordinary_exclusion_counts(tmp_path, monkeypatch):
    def too_few(*args, **kwargs):
        exc = s.Rejected("ordinary_floor")
        exc.counts = {"eligible": 39, "size_cap": 10}
        raise exc

    monkeypatch.setattr(d, "repository_changes", too_few)
    used = e.UsedSet()
    report = d.run(tmp_path, github=FakeAPI(1), osv=FakeOSV(), clones=FakeClones(), used=used, seed=1, known_empty=set(used.sources))
    assert report["ordinary_exclusions"] == {"eligible": 39, "size_cap": 10}


def test_clone_disk_cap_cleans_up(tmp_path):
    import subprocess

    def runner(argv, **kwargs):
        (Path(argv[-1]) / "big").write_bytes(b"12345")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    clones = d.Clones(tmp_path / "repo", tmp_path / "cache", runner=runner, limit_bytes=4)
    with pytest.raises(d.InstrumentFailure, match="clone_size_cap"), clones.open("https://github.com/fixture/project"):
        pass
    assert list((tmp_path / "cache").iterdir()) == []


@pytest.mark.parametrize("stage,n", [("advisories", 2), ("resolution", 103), ("eligibility", 17), ("extraction", 23), ("completion", 1)])
def test_checkpoint_interrupt_resume_matches_uninterrupted(tmp_path, monkeypatch, stage, n):
    import json

    journal_module = importlib.import_module("benchmarks.unseen.journal")
    # Large fake populations exercise replay; durability is checked separately below.
    monkeypatch.setattr(journal_module.os, "fsync", lambda fd: None)
    root = tmp_path / "repo"
    full, interrupted = tmp_path / "full/journal", tmp_path / "interrupted/journal"
    changes = entries()[0]["changes"]
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {"eligible": 40}, {"bytes": 12, "files": 1}))
    used = e.UsedSet()

    def run(path, api=None, clones=None):
        return d.run(
            root,
            github=api or FakeAPI(),
            osv=FakeOSV(),
            clones=clones or FakeClones(),
            used=used,
            seed=7,
            known_empty=set(used.sources),
            journal_path=path,
        )

    assert run(full)["status"] == "draft"
    original = d.Journal.put

    def interrupt(self, current, key, value):
        original(self, current, key, value)
        if current == stage and len(self.rows[current]) == n:
            raise KeyboardInterrupt

    monkeypatch.setattr(d.Journal, "put", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run(interrupted)
    assert not (interrupted / "draft-p1.toml").exists()
    before = {p.name: p.read_bytes() for p in interrupted.glob("*.jsonl")}
    progress = json.loads((interrupted / "progress.json").read_text())
    assert progress["counts"][stage] == n
    assert progress["last_unit"]["stage"] == stage
    assert progress["elapsed_seconds"] >= 0
    assert "rate_limit" in progress
    monkeypatch.setattr(d.Journal, "put", original)
    clones = FakeClones()
    assert run(interrupted, clones=clones)["status"] == "draft"
    assert clones.counts["clones"] == 300 - progress["counts"]["extraction"]
    for name in ("draft-p1.toml", "private-draft-p1.toml"):
        assert (full / name).read_bytes() == (interrupted / name).read_bytes()
    assert all((interrupted / name).read_bytes().startswith(data) for name, data in before.items())
    assert not root.exists()  # no names, manifests, or other records in the checkout
    api, clones = FakeAPI(), FakeClones()
    assert run(interrupted, api, clones)["status"] == "draft"
    assert api.calls == 0 and clones.counts == {}


@pytest.mark.parametrize("parameter", ["seed", "used_set_digest", "clone_limit_bytes", "design_extract"])
def test_resume_refuses_changed_inputs_before_network(tmp_path, monkeypatch, parameter):
    path, root = tmp_path / "cache/journal", tmp_path / "repo"
    used = e.UsedSet()
    kwargs = dict(
        root=root,
        github=FakeAPI(),
        osv=FakeOSV(),
        clones=FakeClones(),
        used=used,
        seed=7,
        known_empty=set(used.sources),
        journal_path=path,
        max_hours=0,
    )
    assert d.run(**kwargs)["status"] == "stopped"
    if parameter == "seed":
        kwargs["seed"] = 8
    elif parameter == "used_set_digest":
        used.add("pairs", {"fixture/new"}, 12)
    elif parameter == "clone_limit_bytes":
        kwargs["clones"].limit_bytes = 12
    else:
        original = d.inputs
        monkeypatch.setattr(d, "inputs", lambda *a: {**original(*a), "design_extract": "changed"})
    report = d.run(**kwargs)
    assert report["status"] == "resume_refused"
    assert report["changed_parameters"] == [parameter]
    assert kwargs["github"].calls == 0


def test_stop_between_units_and_progress_rate_state(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    path, root = tmp_path / "cache/journal", tmp_path / "repo"
    api = FakeAPI(1)
    api.transport = SimpleNamespace(rate_limit={"remaining": "27", "reset": "1234"}, attempts=0)
    used = e.UsedSet()
    original = d.Journal.put

    def stop(self, stage, key, value):
        original(self, stage, key, value)
        if stage == "eligibility":
            (self.path / "STOP").touch()

    monkeypatch.setattr(d.Journal, "put", stop)
    clones = FakeClones()
    report = d.run(root, github=api, osv=FakeOSV(), clones=clones, used=used, seed=1, known_empty=set(used.sources), journal_path=path)
    assert report["status"] == "stopped" and report["reason"] == "STOP"
    assert clones.counts == {}
    progress = json.loads((path / "progress.json").read_text())
    assert progress["status"] == "stopped" and progress["counts"]["eligibility"] == 1
    assert progress["rate_limit"] == api.transport.rate_limit
    assert not (path / "draft-p1.toml").exists()


def test_max_hours_stops_after_completed_page(tmp_path):
    import json

    now = [0.0]

    class TimedAPI(FakeAPI):
        def advisory_page(self, next_url=None, *, ecosystem):
            result = super().advisory_page(next_url, ecosystem=ecosystem)
            now[0] += 3601
            return result

    path = tmp_path / "cache/journal"
    api, used = TimedAPI(), e.UsedSet()
    report = d.run(
        tmp_path / "repo",
        github=api,
        osv=FakeOSV(),
        clones=FakeClones(),
        used=used,
        seed=1,
        known_empty=set(used.sources),
        journal_path=path,
        max_hours=1,
        clock=lambda: now[0],
    )
    assert report["status"] == "stopped" and report["reason"] == "max_hours"
    assert api.calls == 1
    progress = json.loads((path / "progress.json").read_text())
    assert progress["counts"]["advisories"] == 1
    assert progress["elapsed_seconds"] == 3601


def test_journal_cannot_be_inside_repository(tmp_path):
    used = e.UsedSet()
    api = FakeAPI()
    report = d.run(
        tmp_path,
        github=api,
        osv=FakeOSV(),
        clones=FakeClones(),
        used=used,
        seed=1,
        known_empty=set(used.sources),
        journal_path=tmp_path / "journal",
    )
    assert report["status"] == "instrument_failure" and api.calls == 0
    assert not (tmp_path / "journal").exists()


def test_journal_fsync_lock_and_corruption(tmp_path, monkeypatch):
    import json

    j = importlib.import_module("benchmarks.unseen.journal")
    original = j.os.fsync
    synced = []

    def fsync(fd):
        synced.append(fd)
        original(fd)

    monkeypatch.setattr(j.os, "fsync", fsync)
    path = tmp_path / "journal"
    with j.Journal(path).open({"seed": 1}) as journal:
        before = len(synced)
        journal.put("advisories", "1", {"rows": [], "done": True})
        # Appended JSONL, directory, atomic progress file, directory.
        assert len(synced) - before == 4
        assert json.loads((path / "progress.json").read_text())["counts"]["advisories"] == 1
        with pytest.raises(ValueError, match="journal_busy"), j.Journal(path).open({"seed": 1}):
            pass
    with (path / "advisories.jsonl").open("ab") as handle:
        handle.write(b'{"id":')
    with pytest.raises(ValueError, match="journal_incomplete_record"), j.Journal(path).open({"seed": 1}):
        pass


def test_advisory_journal_reduces_nested_blobs_and_resumes_by_page(tmp_path):
    import json

    raw = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/unseen/fixtures/advisory.json").read_bytes())
    expected = copy.deepcopy(raw)
    raw.update(description="raw advisory blob" * 10000, cvss={"vector_string": "unused"})
    raw["cwes"][0]["name"] = "unused CWE description"
    raw["vulnerabilities"][0].update(vulnerable_version_range="unused", first_patched_version={"identifier": "unused"})
    raw["vulnerabilities"][0]["package"]["url"] = "https://example.invalid/unused"
    raw["references"] = [{"url": raw["references"][0], "type": "FIX"}, {"url": "https://example.invalid/unused"}]

    class Pages:
        calls = []

        def advisory_page(self, next_url=None, *, ecosystem):
            self.calls.append((ecosystem, next_url))
            return {"rows": [raw], "next_url": None, "unused": "raw page blob"}

    api, used = Pages(), e.UsedSet()
    parameters = d.inputs(used, 1, set(used.sources), FakeClones())
    path = tmp_path / "journal"
    with d.Journal(path).open(parameters) as journal:
        rows = d.enumerate_advisories(api, journal)
        assert rows == [expected]
    saved = [json.loads(line) for line in (path / "advisories.jsonl").read_bytes().splitlines()]
    assert [row["id"] for row in saved] == [f"{eco}:1" for eco in s.ECOSYSTEMS]
    assert all(row["value"] == {"rows": [expected], "next_url": None} for row in saved)
    assert b"unused" not in (path / "advisories.jsonl").read_bytes()
    assert b"raw advisory blob" not in (path / "advisories.jsonl").read_bytes()
    assert b"raw page blob" not in (path / "advisories.jsonl").read_bytes()
    with d.Journal(path).open(parameters) as journal:
        resumed = d.enumerate_advisories(api, journal)
    assert api.calls == [(eco, None) for eco in s.ECOSYSTEMS] and resumed == rows

    class Bracket(FakeOSV):
        def get(self, identifier):
            return {
                "affected": [
                    {"package": {"ecosystem": "PyPI", "name": "fixture"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2"}]}]}
                ]
            }

    decision = d.decide(resumed[0], FakeAPI(), Bracket(), used, set())
    candidate = s.Candidate(**decision["candidate"])
    assert candidate.repository == "fixture/project"
    assert candidate.fix == "a" * 40 and candidate.parent == "b" * 40
    assert candidate.first_affected == "1.2" and candidate.post_cutoff and candidate.family == "injection"
    assert s.candidate(raw, FakeAPI(), Bracket()) == candidate


def test_reduced_advisories_preserve_all_fix_exclusions_and_selection():
    rows = list(FakeAPI(2).advisories())
    rows[0].update(published_at="2018-01-01", type="unreviewed", withdrawn_at="2020-01-01", cwes=[])
    rows[0]["references"].append("https://github.com/fixture/project001/commit/" + "c" * 40)
    rows[0]["vulnerabilities"].append({"package": {"ecosystem": "rubygems", "name": "other"}})
    reduced = [s.reduce_advisory(row) for row in rows]
    assert (
        d.advisory_index(reduced, FakeAPI())
        == d.advisory_index(rows, FakeAPI())
        == {"fixture/project000": {"a" * 40}, "fixture/project001": {"a" * 40, "c" * 40}}
    )
    assert [r["ghsa_id"] for r in s.ordered_advisories(rows, 7)] == [r["ghsa_id"] for r in s.ordered_advisories(reduced, 7)]
    for key, value, reason in [
        ("published_at", "2018-01-01", "date"),
        ("type", "unreviewed", "advisory_status"),
        ("withdrawn_at", "2026-01-01", "advisory_status"),
        ("cwes", [], "family"),
    ]:
        raw = {**rows[1], key: value}
        with pytest.raises(s.Rejected, match=f"^{reason}$"):
            s.candidate(s.reduce_advisory(raw), FakeAPI(), FakeOSV())


@pytest.mark.parametrize("old_version", [1, 2, 3])
def test_old_advisory_journal_version_refused_before_calls(tmp_path, old_version):
    used, api, osv, clones = e.UsedSet(), FakeAPI(1), FakeOSV(), FakeClones()
    path = tmp_path / "journal"
    parameters = d.inputs(used, 7, set(used.sources), clones)
    assert parameters["journal_version"] == 4
    with d.Journal(path).open({**parameters, "journal_version": old_version}) as journal:
        journal.put("advisories", "1", {"rows": list(api.advisories()), "done": True})
    report = d.run(
        tmp_path / "repo", github=api, osv=osv, clones=clones, used=used, seed=7, known_empty=set(used.sources), journal_path=path
    )
    assert report["status"] == "resume_refused" and report["changed_parameters"] == ["journal_version"]
    assert api.calls == osv.calls == 0 and clones.counts == {}


def test_enumerate_ecosystem_pages_dedupes_and_resumes_partial_stream(tmp_path):
    rows = list(FakeAPI(3).advisories())
    cursor = "https://api.github.com/advisories?ecosystem=pip&after=opaque-cursor"
    pages = {
        ("pip", None): {"rows": [rows[0]], "next_url": cursor},
        ("pip", cursor): {"rows": [rows[0], rows[1]], "next_url": None},
        ("npm", None): {"rows": [rows[0], rows[2]], "next_url": None},
        ("maven", None): {"rows": [], "next_url": None},
        ("composer", None): {"rows": [], "next_url": None},
    }
    calls = []

    class Pages:
        def advisory_page(self, next_url=None, *, ecosystem):
            calls.append((ecosystem, next_url))
            return pages[ecosystem, next_url]

    path = tmp_path / "journal"
    with d.Journal(path).open({"journal_version": 4}) as journal:
        journal.put("advisories", "pip:1", pages["pip", None])
    with d.Journal(path).open({"journal_version": 4}) as journal:
        result = d.enumerate_advisories(Pages(), journal)
        assert [row["ghsa_id"] for row in result] == [row["ghsa_id"] for row in rows]
        assert list(journal.rows["advisories"]) == ["pip:1", "pip:2", "npm:1", "maven:1", "composer:1"]
    assert calls == list(pages)[1:]
    with d.Journal(path).open({"journal_version": 4}) as journal:
        assert d.enumerate_advisories(Pages(), journal) == result
    assert calls == list(pages)[1:]


def test_filtered_http_population_reaches_draft_floor_with_bounded_pages(tmp_path, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    population = list(FakeAPI(300).advisories())
    pages = []

    class FilteredTransport:
        def get(self, url, headers):
            query = parse_qs(urlsplit(url).query)
            # An unfiltered request would enumerate the global database: fail immediately.
            assert query["ecosystem"][0] in s.ECOSYSTEMS
            assert query["published"] == [">=2019-01-01"]
            assert "89" in query["cwes"][0].split(",")
            eco, offset = query["ecosystem"][0], int(query.get("after", ["0"])[0])
            assert "page" not in query
            pages.append((eco, offset))
            assert len(pages) <= 6
            rows = population if eco == "pip" else []
            self.response_headers = {}
            if offset + 100 < len(rows):
                self.response_headers = {"Link": f'<{url.split("&after=")[0]}&after={offset + 100}>; rel="next"'}
            return rows[offset : offset + 100]

    api, used = FakeAPI(), e.UsedSet()
    http = s.GitHub("fake", FilteredTransport())
    monkeypatch.setattr(api, "advisory_page", http.advisory_page)
    changes = entries()[0]["changes"]
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {}, {"bytes": 12, "files": 1}))
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=FakeClones(), used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "draft" and report["repositories"] == 300
    assert report["advisories"] == 300
    assert pages == [("pip", n) for n in (0, 100, 200)] + [(eco, 0) for eco in s.ECOSYSTEMS[1:]]


def test_decide_http_failure_skips_candidate_and_reaches_target(tmp_path, monkeypatch):
    # A per-candidate transport failure in decide (e.g. get_commit on an unresolvable
    # fix ref) is skipped as decide_http_failure; the draft still reaches its target.
    class HTTPFailAPI(FakeAPI):
        def __init__(self, count, bad):
            super().__init__(count)
            self.bad = bad

        def get_commit(self, name, sha):
            if name in self.bad:
                raise ValueError("http_failure")
            return super().get_commit(name, sha)

    bad = {f"fixture/project{i:03d}" for i in range(3)}
    api, used = HTTPFailAPI(303, bad), e.UsedSet()
    changes = entries()[0]["changes"]
    monkeypatch.setattr(d, "repository_changes", lambda *a, **kw: (changes, {}, {"bytes": 12, "files": 1}))
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=FakeClones(), used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "draft" and report["repositories"] == 300
    assert report["rejections"].get("decide_http_failure") == 3


def test_decide_http_failure_systemic_guard_aborts(tmp_path):
    # Every candidate failing the commit lookup is a broken instrument, not an empty result.
    class AllHTTPFailAPI(FakeAPI):
        def get_commit(self, name, sha):
            raise ValueError("http_failure")

    api, used = AllHTTPFailAPI(30), e.UsedSet()
    report = d.run(tmp_path, github=api, osv=FakeOSV(), clones=FakeClones(), used=used, seed=7, known_empty=set(used.sources))
    assert report["status"] == "instrument_failure" and report["error_type"] == "InstrumentFailure"
    assert report["rejections"].get("decide_http_failure") == 25
