"""Offline extraction: an injected local Git client over a synthetic temporary history."""

import importlib
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
e = importlib.import_module("benchmarks.unseen.extract")
s = importlib.import_module("benchmarks.unseen.source")


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


def test_partial_clone_batch_matches_lazy_bytes_without_per_file_fetches(history, tmp_path):
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
    results, fetches = [], []
    for batch in (False, True):
        path = tmp_path / ("batch" if batch else "lazy")
        trace = tmp_path / (path.name + ".trace")
        # Local file transport only, no network. No checkout: all blobs start missing.
        subprocess.run(
            ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout", tmp_path.as_uri(), str(path)],
            check=True,
            capture_output=True,
        )
        commands = []

        def runner(argv, commands=commands, trace=trace, **kwargs):
            commands.append(argv)
            return subprocess.run(argv, **kwargs, env={**os.environ, "GIT_TRACE": str(trace), "GIT_ALLOW_PROTOCOL": "file"})

        partial = e.Git(path, runner=runner)
        missing = partial.run("rev-list", "--objects", "--missing=print", "HEAD")
        assert sum(line.startswith("?") for line in missing.splitlines()) >= 60
        if batch:
            partial.materialize(["HEAD", candidate.fix])
        results.append([e.introducing(partial, candidate), e.ordinary_history(partial, "HEAD")])
        assert partial.files_read > 0 and partial.bytes_read > 0
        fetches.append(sum("built-in: git fetch " in line for line in trace.read_text().splitlines()))
        if batch:
            assert sum("fetch" in argv for argv in commands) == 1
            partial.materialize(["HEAD", candidate.fix])  # Already hydrated: no second fetch.
            assert sum("fetch" in argv for argv in commands) == 1
    assert json.dumps(results[0], sort_keys=True).encode() == json.dumps(results[1], sort_keys=True).encode()
    assert results[1] == baseline
    assert fetches[0] >= 12 and fetches[1] == 1


def test_materialize_timeout_uses_repository_deadline_and_checks_completeness(tmp_path):
    oid = "a" * 40
    calls = []
    now = [0.0]

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        if "fetch" in argv:
            assert kwargs["timeout"] == 3
            assert kwargs["input"] == (oid + "\n").encode()
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        now[0] += 7
        return subprocess.CompletedProcess(argv, 0, ("?" + oid + "\n").encode(), b"")

    with pytest.raises(e.ExtractionTimeout, match="extraction_timeout"):
        e.Git(tmp_path, runner=runner, deadline_seconds=10, _now=lambda: now[0]).materialize(["HEAD"])
    assert len(calls) == 2

    def incomplete(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, ("?" + oid + "\n").encode(), b"")

    with pytest.raises(e.InstrumentFailure, match="missing_blobs_after_fetch"):
        e.Git(tmp_path, runner=incomplete).materialize(["HEAD"])
