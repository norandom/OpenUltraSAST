"""Offline extraction: an injected local Git client over a synthetic temporary history."""

import hashlib
import importlib
import json
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
e = importlib.import_module("benchmarks.unseen.extract")
s = importlib.import_module("benchmarks.unseen.source")


@pytest.fixture(autouse=True)
def _hermetic_git_env(monkeypatch):
    """Neutralise inherited Git control vars so each test is self-contained.

    A GIT_DIR / GIT_OBJECT_DIRECTORY / alternates value leaked from an earlier test in the suite redirects
    object lookup: the partial-clone lazy-fetch test then sees a different missing-blob count (it passes alone
    but failed mid-suite). These tests build their own repos under tmp_path and must not read ambient git env.
    """
    for var in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("slow", [False, True])
def test_process_deadline_restores_alarm(slow):
    original = signal.getsignal(signal.SIGALRM)
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)
    if slow:
        with pytest.raises(e.ExtractionTimeout, match="^wallclock_timeout$"), e.process_deadline(0.05):
            time.sleep(0.2)
    else:
        with e.process_deadline(0.2):
            assert signal.getitimer(signal.ITIMER_REAL)[0] > 0
    assert signal.getsignal(signal.SIGALRM) == original
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


@pytest.mark.parametrize("seconds", [None, 0, -1])
def test_process_deadline_disabled(seconds, monkeypatch):
    monkeypatch.setattr(signal, "signal", lambda *args: pytest.fail("disabled deadline installed a handler"))
    monkeypatch.setattr(signal, "setitimer", lambda *args: pytest.fail("disabled deadline armed a timer"))
    with e.process_deadline(seconds):
        pass


def test_process_deadline_off_main_thread(monkeypatch):
    monkeypatch.setattr(signal, "signal", lambda *args: pytest.fail("thread installed a handler"))
    monkeypatch.setattr(signal, "setitimer", lambda *args: pytest.fail("thread armed a timer"))

    def work():
        with e.process_deadline(0.01):
            time.sleep(0.02)
        return "finished"

    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(work).result() == "finished"


@pytest.mark.parametrize("operation", ["signal", "setitimer"])
def test_process_deadline_unsupported_operation(operation, monkeypatch):
    original = signal.getsignal(signal.SIGALRM)

    def unsupported(*args):
        raise ValueError("unsupported")

    monkeypatch.setattr(signal, operation, unsupported)
    with e.process_deadline(0.01):
        time.sleep(0.02)
    assert signal.getsignal(signal.SIGALRM) == original
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


def test_process_deadline_does_not_swallow_body_value_error():
    original = signal.getsignal(signal.SIGALRM)
    with pytest.raises(ValueError, match="body failure"), e.process_deadline(0.2):
        raise ValueError("body failure")
    assert signal.getsignal(signal.SIGALRM) == original
    assert signal.getitimer(signal.ITIMER_REAL) == (0, 0)


def test_process_deadline_inside_git_remains_rejection(tmp_path):
    def runner(*args, **kwargs):
        time.sleep(0.2)

    with pytest.raises(e.ExtractionTimeout, match="^wallclock_timeout$"), e.process_deadline(0.05):
        e.Git(tmp_path, runner=runner).run("log")


@pytest.fixture
def history(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        assert not {"clone", "fetch", "push", "pull"} & set(argv)
        calls.append(argv)
        return subprocess.run(argv, **kwargs)

    git = e.Git(tmp_path, runner=runner)
    git.run("init", "-q")
    git.run("config", "user.name", "Fixture")
    git.run("config", "user.email", "fixture@example.invalid")

    def commit(text, message="ordinary", extra=None):
        (tmp_path / "app.py").write_text(text)
        for path, content in (extra or {}).items():
            (tmp_path / path).write_text(content)
        git.run("add", ".")
        git.run("commit", "-q", "-m", message)
        return git.run("rev-parse", "HEAD").strip()

    root = commit("def handler(value):\n    return value\n")
    git.run("tag", "v1.0")
    intro = commit("def handler(value):\n    return eval(value)\n")
    git.run("tag", "v1.1")
    parent = commit("def handler(value):\n    return eval( value )\n", "format")
    fix = commit("def handler(value):\n    return int(value)\n", "security fix")
    candidate = s.Candidate(
        "fixture/project",
        "https://github.com/fixture/project",
        fix,
        parent,
        "GHSA-test-test-test",
        "pip",
        "injection",
        True,
        "1.1",
        "MIT",
        "permissive",
        parent,
        "LICENSE",
    )
    return git, commit, candidate, root, intro, parent, calls


def test_introducing_with_reformat_walkback(history):
    git, _, candidate, root, intro, _, calls = history
    change = e.introducing(git, candidate)
    assert change["method"] == "introducing"
    assert (change["base"], change["head"]) == (root, intro)
    assert change["function"] == "handler"
    assert change["family"] == "injection" and change["post_cutoff"]
    assert change["files"][0]["head_lines"] == [[2, 2]]
    assert change["bias"] and change["advisory"] == candidate.advisory
    assert any("-w" in args and "-M" in args and "-C" in args for args in calls)
    assert git.bytes_read > 0


def test_bracket_rejection_uses_fallback(history):
    git, _, candidate, _, _, parent, _ = history
    change = e.introducing(git, replace(candidate, first_affected="1.0"))
    assert change["method"] == "last_touch" and change["head"] == parent
    assert change["fallback_reasons"]["version_bracket"] >= 1


def test_size_cap_and_merge_rejection(history):
    git, _, candidate, _, _, _, _ = history

    class Oversize:
        def __getattr__(self, name):
            return getattr(git, name)

        def stats(self, base, head):
            return [("app.py", 2001, 0)]

    assert e.introducing(Oversize(), candidate)["method"] == "last_touch"

    class Merge(Oversize):
        def parents(self, sha):
            parents = git.parents(sha)
            return parents + ["f" * 40] if sha != candidate.fix else parents

    with pytest.raises(s.Rejected, match="no_range"):
        e.introducing(Merge(), candidate)


def test_pure_addition_blames_function_declaration(history):
    git, commit, candidate, _, _, _, _ = history
    git.run("checkout", "-q", candidate.parent)
    parent = commit("def handler(value):\n    return eval(value)\n\ndef added(value):\n    return value\n")
    fix = commit("def handler(value):\n    return eval(value)\n\ndef added(value):\n    assert value\n    return value\n")
    change = e.introducing(git, replace(candidate, fix=fix, parent=parent, first_affected=None, family="access_control"))
    assert change["head"] == parent and change["method"] == "introducing"
    assert change["function"] == "added"


def test_git_failures_are_sanitized_and_not_empty(tmp_path):
    def failed(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 128, b"", b"private repository secret")

    with pytest.raises(e.InstrumentFailure, match="git_exit_128"):
        e.Git(tmp_path, runner=failed).run("log")


@pytest.mark.parametrize("deadline,timeout", [(None, 180), (240.0, 180), (12.5, 12.5)])
def test_git_timeout_is_rejection(tmp_path, deadline, timeout):
    def runner(cmd, **kwargs):
        assert kwargs["timeout"] == timeout
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    git = e.Git(tmp_path, runner=runner, deadline_seconds=deadline, _now=lambda: 0.0)
    with pytest.raises(e.ExtractionTimeout, match="^extraction_timeout$") as caught:
        git.run("log")
    assert isinstance(caught.value, s.Rejected)
    assert not isinstance(caught.value, e.InstrumentFailure)


def test_git_cumulative_deadline_prevents_launch(tmp_path):
    now, timeouts = [100.0], []

    def runner(cmd, **kwargs):
        timeouts.append(kwargs["timeout"])
        now[0] += 4.0
        return subprocess.CompletedProcess(cmd, 0, b"read", b"")

    git = e.Git(tmp_path, runner=runner, deadline_seconds=10.0, _now=lambda: now[0])
    assert git.run("log") == "read"
    assert git.run("log") == "read"
    now[0] += 3.0  # Time between commands counts as well.
    with pytest.raises(e.ExtractionTimeout, match="^extraction_timeout$"):
        git.run("log")
    assert timeouts == [10.0, 6.0]


def test_git_launch_failure_stays_fatal(tmp_path):
    def runner(cmd, **kwargs):
        raise FileNotFoundError("private executable path")

    with pytest.raises(e.InstrumentFailure, match="^git_launch_failed$"):
        e.Git(tmp_path, runner=runner, deadline_seconds=240.0).run("log")


def test_walkback_is_bounded_and_file_cap_falls_back(history):
    git, _, candidate, _, _, parent, _ = history

    class FileCap:
        def __getattr__(self, name):
            return getattr(git, name)

        def stats(self, base, head):
            return [("app.py", 1, 0)] * 51

    result = e.introducing(FileCap(), candidate)
    assert result["method"] == "last_touch"
    assert result["fallback_reasons"]["size_cap"]

    class Walk:
        calls = 0

        def __getattr__(self, name):
            return getattr(git, name)

        def blame(self, revision, path, line):
            self.calls += 1
            return parent, path, 2

        def parents(self, revision):
            return [parent] if revision != candidate.fix else [candidate.parent]

    walk = Walk()
    result = e.introducing(walk, candidate)
    assert walk.calls == 6
    assert result["fallback_reasons"]["walkback_limit"] == 1


def test_root_rejected_and_head_function_resolved(history):
    git, _, candidate, root, _, _, _ = history

    class Root:
        def __getattr__(self, name):
            return getattr(git, name)

        def blame(self, revision, path, line):
            return root, path, 1

    result = e.introducing(Root(), candidate)
    assert result["method"] == "last_touch"
    assert result["fallback_reasons"]["merge_or_root"] == 1
    assert result["function_lines"] == [1, 2]


@pytest.mark.parametrize(
    "path,text",
    [
        ("a.php", "<?php\nfunction handle($x) {\n return $x;\n}\n"),
        ("a.js", "function handle(x) {\n return x;\n}\n"),
        ("a.ts", "const handle = (x) => {\n return x;\n}\n"),
        ("A.java", "class A {\n public String handle(String x) {\n return x;\n }\n}\n"),
    ],
)
def test_supported_function_boundaries(path, text):
    ranges = e.functions(path, text)
    assert len(ranges) == 1 and ranges[0][0] == "handle"
    assert ranges[0][2] < len(text.splitlines()) + 1


def test_ambiguous_parent_is_not_proof_of_absence(history):
    git, commit, candidate, _, _, _, _ = history
    duplicate = (
        "class A:\n    def handler(self, value):\n        return eval(value)\n\n"
        "class B:\n    def handler(self, value):\n        return value\n"
    )
    commit(duplicate)
    parent = commit("class A:\n    def handler(self, value):\n        return eval( value )\n")
    fix = commit("class A:\n    def handler(self, value):\n        return int(value)\n")
    selected = replace(candidate, fix=fix, parent=parent, first_affected=None)

    class BlameLast:
        def __getattr__(self, name):
            return getattr(git, name)

        def blame(self, revision, path, line):
            return parent, path, 3

    result = e.introducing(BlameLast(), selected)
    assert result["method"] == "last_touch"
    assert result["fallback_reasons"]["ambiguous_parent"] == 1


def ordinary(index, **overrides):
    row = {
        "head": f"{index:040x}",
        "parents": ["f" * 40],
        "timestamp": index * 100,
        "message": "update query token session valid",
        "author": "Human",
        "files": [{"path": "app.py", "added": 5, "removed": 0, "head_lines": [[2, 6]], "functions": ["ordinary"], "generated": False}],
    }
    row.update(overrides)
    return row


@pytest.mark.parametrize(
    "message",
    [
        "security fix",
        "CVE-2026",
        "GHSA-test",
        "vulnerability",
        "injection fix",
        "XSS",
        "CSRF",
        "SSRF",
        "exploit",
        "sanitize",
        "escaping",
        "Revert changes",
        "This reverts commit abc",
        "bump package",
        "upgrade package from 1 to 2",
    ],
)
def test_ordinary_message_exclusions(message):
    assert e.ordinary_rejection(ordinary(1, message=message), set(), set()) is not None


def test_narrow_filter_and_every_other_exclusion():
    assert e.ordinary_rejection(ordinary(1), set(), set()) is None
    assert e.ordinary_rejection(ordinary(1, parents=["a", "b"]), set(), set()) == "merge_or_root"
    assert e.ordinary_rejection(ordinary(1, author="dependabot[bot]"), set(), set()) == "dependency"
    assert e.ordinary_rejection(ordinary(1, author="renovate"), set(), set()) == "dependency"
    assert e.ordinary_rejection(ordinary(1), {f"{1:040x}"}, set()) == "advisory_fix"
    assert e.ordinary_rejection(ordinary(1), set(), {("app.py", "ordinary")}) == "vulnerable_function"
    row = ordinary(1)
    row["files"][0]["added"] = 1001
    assert e.ordinary_rejection(row, set(), set()) == "size_cap"
    for path, reason in [
        ("README.md", "no_source"),
        ("package.json", "manifest_only"),
        ("package-lock.json", "manifest_only"),
        ("vendor/a.py", "generated"),
        ("node_modules/a.js", "generated"),
        ("dist/a.js", "generated"),
        ("app.min.js", "generated"),
    ]:
        row = ordinary(1)
        row["files"][0]["path"] = path
        assert e.ordinary_rejection(row, set(), set()) == reason
    row = ordinary(1)
    row["files"][0]["generated"] = True
    assert e.ordinary_rejection(row, set(), set()) == "generated"


def test_draw_seed_proportional_cells_floor_and_thirds():
    rows = [ordinary(i) for i in range(120)]
    for i, row in enumerate(rows):
        row["files"][0]["added"] = [5, 20, 100, 500][i % 4]
    drawn, counts = e.draw_ordinary(rows, set(), set(), seed=19)
    assert len(drawn) == 12 and len({r["head"] for r in drawn}) == 12
    assert {r["time_third"] for r in drawn} == {0, 1, 2}
    assert len({(r["time_third"], r["size_bucket"]) for r in drawn}) == 12
    assert drawn == e.draw_ordinary(list(reversed(rows)), set(), set(), seed=19)[0]
    assert counts["eligible"] == 120
    with pytest.raises(s.Rejected, match="ordinary_floor"):
        e.draw_ordinary(rows[:39], set(), set(), seed=19)
    assert len(e.draw_ordinary(rows[:39], set(), set(), seed=19, floor=20)[0]) == 12  # a training freeze may lower the floor
    with pytest.raises(ValueError, match="below one draw"):
        e.draw_ordinary(rows, set(), set(), seed=19, floor=11)
    # Thirds come from the history's time span, not rank among eligible changes.
    with pytest.raises(s.Rejected, match="time_thirds"):
        e.draw_ordinary([ordinary(i) for i in range(40)] + [ordinary(10000, message="security")], set(), set(), seed=1)


def test_git_ordinary_collection_generated_attributes_and_headers(history):
    git, commit, _, _, _, _, _ = history
    commit("# Generated by fixture\nx = 2\n", extra={".gitattributes": "other.py linguist-generated=true\n", "other.py": "x = 1\n"})
    rows = e.ordinary_history(git, "HEAD")
    assert rows and rows[0]["files"]
    files = {f["path"]: f for f in rows[0]["files"]}
    assert files["app.py"]["generated"] and files["other.py"]["generated"]
    assert files["app.py"]["head_lines"]


def count_history_work(git, monkeypatch):
    calls = {}
    for target, names in ((git, ("stats", "hunks", "blob")), (e, ("functions", "generated"))):
        for name in names:
            calls[name] = Mock(wraps=getattr(target, name))
            monkeypatch.setattr(target, name, calls[name])
    return calls


def test_history_cache_matches_rows_and_skips_commit_work(history, monkeypatch):
    git, commit, _, _, _, _, commands = history
    commit("# Generated by fixture\ndef handler(value):\n    return value\n")
    expected = e.ordinary_history(git, "HEAD")
    calls = count_history_work(git, monkeypatch)
    cache = git.path / ".git/history-cache"
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count > 0 for call in calls.values())
    top = git.run("rev-parse", "--show-toplevel").strip()
    (path,) = cache.iterdir()
    assert path.name == hashlib.sha256(top.encode()).hexdigest() + ".jsonl"
    before = path.read_bytes()
    assert [json.loads(line) for line in before.splitlines()] == [
        {"version": e.HISTORY_CACHE_VERSION, "head": row["head"], "row": row} for row in expected
    ]
    for call in calls.values():
        call.reset_mock()
    commands.clear()
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count == 0 for call in calls.values())
    assert sum("log" in argv for argv in commands) == 1
    assert path.read_bytes() == before


@pytest.mark.parametrize("tail", [b'{"version": 1, "row": ', b'{"row": "\xc3'])
def test_history_cache_resumes_after_partial_line(history, monkeypatch, tail):
    git, _, _, _, _, _, _ = history
    expected = e.ordinary_history(git, "HEAD")
    cache = git.path / ".git/history-cache"
    e.ordinary_history(git, "HEAD", cache_dir=cache)
    (path,) = cache.iterdir()
    count = 2
    prefix = b"".join(path.read_bytes().splitlines(keepends=True)[:count]) + tail
    path.write_bytes(prefix)
    calls = count_history_work(git, monkeypatch)
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    missing = [row for row in expected[count:] if len(row["parents"]) == 1]
    assert [call.args[1] for call in calls["stats"].call_args_list] == [row["head"] for row in missing]
    assert calls["hunks"].call_count > 0 and calls["blob"].call_count > 0
    after = path.read_bytes()
    assert after.startswith(prefix + b"\n")
    assert [json.loads(line)["row"] for line in after.splitlines()[count + 1 :]] == expected[count:]
    for call in calls.values():
        call.reset_mock()
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count == 0 for call in calls.values())


@pytest.mark.parametrize("invalid", ["version", "parents", "json", "head"])
def test_history_cache_recomputes_invalid_entry(history, monkeypatch, invalid):
    git, _, _, _, _, _, _ = history
    expected = e.ordinary_history(git, "HEAD")
    cache = git.path / ".git/history-cache"
    e.ordinary_history(git, "HEAD", cache_dir=cache)
    (path,) = cache.iterdir()
    lines = path.read_text().splitlines(keepends=True)
    entry = json.loads(lines[0])
    if invalid == "version":
        entry["version"] += 1
    elif invalid == "parents":
        entry["row"]["parents"] = []
    elif invalid == "head":
        entry["head"] = "f" * 40
    lines[0] = "broken JSON\n" if invalid == "json" else json.dumps(entry) + "\n"
    before = "".join(lines)
    path.write_text(before)
    calls = count_history_work(git, monkeypatch)
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    calls["stats"].assert_called_once_with(expected[0]["parents"][0], expected[0]["head"])
    assert calls["hunks"].call_count > 0 and calls["blob"].call_count > 0
    assert path.read_text().startswith(before)
    assert json.loads(path.read_text().splitlines()[-1])["row"] == expected[0]


def test_history_without_cache_writes_nothing(history):
    git, _, _, _, _, _, commands = history
    before = {path.relative_to(git.path) for path in git.path.rglob("*")}
    expected = e.ordinary_history(git, "HEAD")
    assert e.ordinary_history(git, "HEAD", cache_dir=None) == expected
    assert {path.relative_to(git.path) for path in git.path.rglob("*")} == before
    assert not any("--show-toplevel" in argv for argv in commands)


def test_history_cache_tracks_new_heads_and_current_log(history, monkeypatch):
    git, commit, _, _, _, _, _ = history
    cache = git.path / ".git/history-cache"
    original = e.ordinary_history(git, "HEAD", cache_dir=cache)
    head = commit("def handler(value):\n    return value + 1\n")
    expected = e.ordinary_history(git, head)
    calls = count_history_work(git, monkeypatch)
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    calls["stats"].assert_called_once_with(original[0]["head"], head)
    for call in calls.values():
        call.reset_mock()
    assert e.ordinary_history(git, original[0]["head"], cache_dir=cache) == original
    assert all(call.call_count == 0 for call in calls.values())


def test_history_cache_includes_merges_and_roots(history, monkeypatch):
    git, _, _, root, _, _, _ = history
    head = git.run("rev-parse", "HEAD").strip()
    git.run("checkout", "-qb", "side", root)
    (git.path / "side.txt").write_text("side branch\n")
    git.run("add", "side.txt")
    git.run("commit", "-qm", "side")
    git.run("checkout", "-q", head)
    git.run("merge", "--no-ff", "-qm", "merge", "side")
    expected = e.ordinary_history(git, "HEAD")
    assert len(expected[0]["parents"]) == 2 and expected[0]["files"] == []
    assert expected[-1]["parents"] == [] and expected[-1]["files"] == []
    cache = git.path / ".git/history-cache"
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    (path,) = cache.iterdir()
    assert [json.loads(line)["row"] for line in path.read_text().splitlines()] == expected
    calls = count_history_work(git, monkeypatch)
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count == 0 for call in calls.values())


def test_history_cache_is_per_clone_and_uses_top_level(history, monkeypatch):
    git, _, _, _, _, _, _ = history
    cache = git.path / ".git/history-cache"
    expected = e.ordinary_history(git, "HEAD", cache_dir=cache)
    nested = git.path / "nested"
    nested.mkdir()
    subdir_git = e.Git(nested)
    calls = count_history_work(subdir_git, monkeypatch)
    assert e.ordinary_history(subdir_git, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count == 0 for call in calls.values())
    clone_path = git.path / "clone"
    subprocess.run(["git", "clone", "--quiet", str(git.path), str(clone_path)], check=True, capture_output=True)
    clone = e.Git(clone_path)
    calls = count_history_work(clone, monkeypatch)
    assert e.ordinary_history(clone, "HEAD", cache_dir=cache) == expected
    assert all(call.call_count > 0 for call in calls.values())
    assert len(list(cache.glob("*.jsonl"))) == 2


def test_history_cache_flushes_each_completed_commit(history, monkeypatch):
    git, _, _, _, _, _, _ = history
    expected = e.ordinary_history(git, "HEAD")
    cache = git.path / ".git/history-cache"
    stats = git.stats

    def interrupted(base, head):
        if head == expected[1]["head"]:
            (path,) = cache.iterdir()
            assert [json.loads(line)["row"] for line in path.read_text().splitlines()] == expected[:1]
            raise e.ExtractionTimeout("interrupted")
        return stats(base, head)

    monkeypatch.setattr(git, "stats", interrupted)
    with pytest.raises(e.ExtractionTimeout, match="interrupted"):
        e.ordinary_history(git, "HEAD", cache_dir=cache)
    monkeypatch.setattr(git, "stats", stats)
    calls = count_history_work(git, monkeypatch)
    assert e.ordinary_history(git, "HEAD", cache_dir=cache) == expected
    assert expected[0]["head"] not in [call.args[1] for call in calls["stats"].call_args_list]


def test_attribute_unset_and_mixed_generated_source(history):
    git, commit, _, _, _, _, _ = history
    sha = commit("x = 1\n", extra={".gitattributes": "*.py linguist-generated\napp.py -linguist-generated\n"})
    assert not e.generated(git, sha, "app.py", "x = 1\n")
    row = ordinary(1)
    row["files"].append({**row["files"][0], "path": "dist/b.js", "generated": True})
    assert e.ordinary_rejection(row, set(), set()) is None


def test_unbalanced_cells_remain_proportional_and_seed_changes_draw():
    rows = [ordinary(i) for i in range(120)]
    for i, row in enumerate(rows):
        row["files"][0]["added"] = 5 if i % 4 else 100
    draw, _ = e.draw_ordinary(rows, set(), set(), seed=1)
    assert len([r for r in draw if r["size_bucket"] == 0]) == 9
    assert draw != e.draw_ordinary(rows, set(), set(), seed=2)[0]


def test_disk_bytes_skips_files_that_vanish_mid_walk(tmp_path):
    # git churns .git/objects/pack (transient *.rev) during on-demand blob fetches,
    # so a path rglob just listed can be gone by the time disk_bytes stat()s it.
    git = e.Git(tmp_path, runner=subprocess.run)
    (tmp_path / "a").write_bytes(b"x" * 10)
    (tmp_path / "b").write_bytes(b"y" * 20)
    real = [p for p in tmp_path.rglob("*")]

    class Vanished:
        def is_file(self):
            return True

        def is_symlink(self):
            return False

        def stat(self):
            raise FileNotFoundError(2, "No such file or directory")

    git.path = type("P", (), {"rglob": lambda self, pattern: iter([*real, Vanished()])})()
    assert git.disk_bytes() == 30


def test_partial_clone_lazy_fetch_preserves_extraction_content(history, tmp_path):
    """Real promisor packs over file:// only: count lazy fetches via Git's trace."""
    import json
    import os

    git, commit, candidate, _, _, _, _ = history
    for revision in range(12):
        commit(
            f"def handler(value):\n    return int(value) + {revision}\n",
            extra={f"file{revision * 5 + i}.py": f"x = {revision * 5 + i}\n" for i in range(5)},
        )
    git.run("config", "uploadpack.allowFilter", "true")
    git.run("config", "uploadpack.allowAnySHA1InWant", "true")
    baseline = [e.introducing(git, candidate), e.ordinary_history(git, "HEAD")]
    path = tmp_path / "lazy"
    trace = tmp_path / "lazy.trace"
    # Local file transport only, no network. No checkout: all blobs start missing.
    subprocess.run(
        ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", tmp_path.as_uri(), str(path)],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_ALLOW_PROTOCOL": "file"},
    )

    def runner(argv, **kwargs):
        return subprocess.run(argv, **kwargs, env={**os.environ, "GIT_TRACE": str(trace), "GIT_ALLOW_PROTOCOL": "file"})

    partial = e.Git(path, runner=runner)
    missing = partial.run("rev-list", "--objects", "--missing=print", "HEAD")
    assert sum(line.startswith("?") for line in missing.splitlines()) >= 60
    result = [e.introducing(partial, candidate), e.ordinary_history(partial, "HEAD")]
    assert partial.files_read > 0 and partial.bytes_read > 0
    assert json.dumps(result, sort_keys=True).encode() == json.dumps(baseline, sort_keys=True).encode()
    assert sum("built-in: git fetch " in line for line in trace.read_text().splitlines()) >= 12


def test_history_limit_walks_only_the_newest_commits(history):
    git, *_ = history
    full = e.ordinary_history(git, "HEAD")
    assert len(full) > 2
    assert e.ordinary_history(git, "HEAD", limit=2) == full[:2]  # the newest first-parent commits, same rows
    with pytest.raises(ValueError, match="positive integer"):
        e.ordinary_history(git, "HEAD", limit=0)
