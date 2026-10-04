"""Offline eligibility fixtures; no real repository identities are needed."""

import io
import json
from pathlib import Path

import pytest

from openultrasast.plane.memory import FileStore

with pytest.MonkeyPatch.context() as patch:
    patch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/unseen"))
    import eligibility as e


def plant(root, path, text):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


def test_sources_and_reserved_input_never_opened(tmp_path, monkeypatch, capsys):
    sources = {
        "benchmarks/pairs/a/catalog.toml": ("pairs", "pair"),
        "benchmarks/pairs/a/recipes.toml": ("pairs", "recipe"),
        "benchmarks/pairs/a/dataset.json": ("pairs", "dataset"),
        "benchmarks/pairs/advisory-fixes-b/catalog.toml": ("harvest", "harvest"),
        "benchmarks/independent/population-v1.toml": ("populations", "first"),
        "benchmarks/independent/population-v2.toml": ("populations", "second"),
        "plane/experiments/a.units.jsonl": ("units", "unit"),
        "benchmarks/measurements/a/record.json": ("measurements", "measurement"),
        "benchmarks/experiments/a.json": ("measurements", "experiment"),
        "src/example.txt": ("sweep", "sweep"),
    }
    for path, (_, name) in sources.items():
        text = f'repo = "https://github.com/fixture/{name}"' if path.endswith(".toml") else json.dumps({"repo": f"fixture/{name}"})
        if name == "sweep":
            text = "https://github.com/fixture/sweep"
        plant(tmp_path, path, text)
    pointer = plant(tmp_path, "local/pointers.toml", '[[pair]]\nrepo = "fixture/pointer"\nfix_repo = "fixture/fix"\nvendored = false')
    plant(tmp_path, "benchmarks/independent/population-v3.toml", "do not read")
    plant(tmp_path, "benchmarks/independent/results-v3.json", "do not read")
    original = io.open

    def guarded(file, *args, **kwargs):
        if "v3" in str(file):
            pytest.fail("reserved input opened")
        return original(file, *args, **kwargs)

    monkeypatch.setattr(io, "open", guarded)
    store = FileStore(tmp_path / "memory")
    plant(tmp_path, "memory/repos/opaque/pin.jsonl", json.dumps({"id": "1", "kind": "example", "repo": "fixture/memory"}) + "\n")
    used = e.build_used(tmp_path, stores={"local": store}, pointer_manifests=[pointer])
    for label, name in sources.values():
        assert f"fixture/{name}" in used.sources[label]
    assert {"fixture/pointer", "fixture/fix"} <= used.sources["pointers"]
    assert "fixture/memory" in used.sources["memory_local"]
    report = used.report()
    assert report["sources"]["memory_local"]["bytes"] > 0
    assert all(item["files"] > 0 and item["bytes"] > 0 for item in report["sources"].values())
    assert "fixture/" not in json.dumps(report)
    assert capsys.readouterr().out == ""
    assert e.normalize("HTTPS://GitHub.com/Fixture/Pair.GIT/") == "fixture/pair"
    assert len({e.normalize(s) for s in ["fixture/pair", "Fixture/Pair.git/", "github.com/fixture/pair"]}) == 1


def test_empty_sources_fail_unless_declared(tmp_path):
    used = e.build_used(tmp_path)
    with pytest.raises(ValueError, match="empty_source"):
        used.report()
    assert used.report(known_empty=set(used.sources))["count"] == 0


class FakeAPI:
    def __init__(self, records):
        self.records = records

    def get_repo(self, name):
        return self.records[name]


def test_resolution_rejects_used_renames_and_forks():
    used = e.UsedSet()
    used.add("pairs", {"fixture/used"}, 10)
    api = FakeAPI(
        {
            "fixture/used": {"full_name": "fixture/used"},
            "fixture/old": {"full_name": "fixture/new", "former_names": ["fixture/used"]},
            "fixture/fork": {"full_name": "fixture/fork", "parent": {"full_name": "fixture/used"}, "source": {"full_name": "fixture/used"}},
            "fixture/a": {"full_name": "fixture/a", "source": {"full_name": "fixture/root"}},
            "fixture/b": {"full_name": "fixture/b", "source": {"full_name": "fixture/root"}},
        }
    )
    selected = set()
    for name in ("used", "old", "fork"):
        resolved = e.resolve("fixture/" + name, api)
        assert e.rejection(resolved, used, selected) == "pairs"
    assert e.rejection(e.resolve("fixture/a", api), used, selected) is None
    assert e.rejection(e.resolve("fixture/b", api), used, selected) == "fork_network"


def test_registered_units_and_read_only_store(tmp_path):
    units = plant(tmp_path, "local/units.jsonl", json.dumps({"repo": "fixture/registered"}))
    store = FileStore(tmp_path / "memory")
    plant(tmp_path, "memory/repos/opaque/pin.jsonl", json.dumps({"kind": "experiment", "units_file": str(units)}))
    used = e.build_used(tmp_path, stores={"s3": store})
    assert "fixture/registered" in used.sources["units"]


def test_cli_injected_store_and_credentials(tmp_path, monkeypatch, capsys):
    from openultrasast import config
    from openultrasast.plane import memory

    calls = []
    monkeypatch.setattr(config, "load_dotenv", lambda path: calls.append("dotenv"))
    monkeypatch.setenv("GH_TOKEN", "test-token")
    store = FileStore(tmp_path / "store")
    monkeypatch.setattr(memory, "open_store", lambda spec, **kwargs: calls.append(spec) or store)
    monkeypatch.setattr(e, "GitHub", lambda token: calls.append(token) or FakeAPI({}))
    args = ["--root", str(tmp_path), "--s3-store", "s3://", "--local-store", "file:///unused"]
    for label in (*e.SOURCES, "memory_local", "memory_s3"):
        args += ["--known-empty", label]
    assert e.main(args) == 0
    assert calls == ["dotenv", "file:///unused", "s3://", "test-token"]
    output = capsys.readouterr().out
    assert json.loads(output)["count"] == 0
    assert "test-token" not in output


def test_s3_open_is_read_only(tmp_path, monkeypatch):
    from openultrasast.plane import memory

    class Objects:
        def keys(self, prefix):
            return ["repos/opaque/pin.jsonl"]

        def get(self, key):
            return json.dumps({"kind": "example", "repo": "fixture/stored"}).encode(), "1"

        def __getattr__(self, name):
            raise AssertionError("unexpected_store_operation")

    monkeypatch.setattr(memory, "S3Client", lambda **kwargs: Objects())
    monkeypatch.setattr(memory, "s3_settings", lambda env: {})
    store = memory.open_store("s3://fixture-bucket", read_only=True)
    used = e.build_used(tmp_path, stores={"s3": store})
    assert used.sources["memory_s3"] == {"fixture/stored"}
    with pytest.raises(memory.MemoryStoreError, match="read.only"):
        store._put("key", b"value")
    with pytest.raises(memory.MemoryStoreError, match="read.only"):
        store._delete("key")


def test_non_repository_provenance_and_missing_used_identity(tmp_path):
    plant(tmp_path, "benchmarks/pairs/recipes.toml", 'repo = "provenance-label"')
    assert not e.build_used(tmp_path).sources["pairs"]
    used = e.UsedSet()
    used.add("pairs", {"fixture/old", "fixture/nonexistent"}, 1)

    class API:
        def get_repo(self, name):
            if name.endswith("nonexistent"):
                raise e.RepositoryNotFound
            return {"full_name": "fixture/new"}

    e.canonicalize_used(used, API())
    assert "fixture/nonexistent" in used.sources["pairs"]
    assert e.rejection(e.resolve("fixture/new", API()), used, set()) == "pairs"


def test_binary_measurement_and_local_pointer_discovery(tmp_path):
    target = tmp_path / "benchmarks/measurements/a/image.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\xff\x00")
    plant(tmp_path, "benchmarks/pairs/a/recipes.toml", '[[pair]]\nrepo = "fixture/pointer"\nvendored = false')
    used = e.build_used(tmp_path)
    assert used.instrument["measurements"]["bytes"] == 2
    assert used.sources["pointers"] == {"fixture/pointer"}


def test_coordinator_verification_is_black_box(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace

    def run(command, **kwargs):
        assert kwargs["stdout"] == kwargs["stderr"] == kwargs["stdin"] == subprocess.DEVNULL
        path = Path(next(part.split("=", 1)[1] for part in command if part.startswith("--junitxml=")))
        path.write_text('<testsuites><testsuite tests="25" failures="0" errors="0" skipped="1"/></testsuites>')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    assert e.verify_tests(tmp_path)["tests"]["tests"] == 25
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=2))
    with pytest.raises(ValueError, match="guard_or_tests_failed"):
        e.verify_tests(tmp_path)


def test_registered_unit_group_is_repository(tmp_path):
    plant(tmp_path, "plane/experiments/a.units.jsonl", json.dumps({"unit": "opaque", "group": "fixture/unit", "label": 1}))
    assert "fixture/unit" in e.build_used(tmp_path).sources["units"]


def test_multidocument_measurement_and_missing_registered_units(tmp_path):
    plant(tmp_path, "benchmarks/measurements/a/run.yaml", "repo: fixture/first\n---\nrepo: fixture/second\n")
    assert e.build_used(tmp_path).sources["measurements"] == {"fixture/first", "fixture/second"}
    store = FileStore(tmp_path / "memory")
    plant(
        tmp_path,
        "memory/repos/opaque/pin.jsonl",
        json.dumps(
            {
                "kind": "experiment",
                "units_file": "absent.units.jsonl",
                "units_digest": "a" * 64,
            }
        ),
    )
    with pytest.raises(FileNotFoundError):
        e.build_used(tmp_path, stores={"local": store})


def test_catalog_skips_fixture_and_preserves_host_identity(tmp_path, capsys):
    plant(
        tmp_path,
        "benchmarks/pairs/catalog.toml",
        '[[pair]]\norigin = "in-tree-fixture"\nvendored = false\n[[pair]]\nrepo = "https://GitLab.com/Fixture/Private.git"\n',
    )
    used = e.build_used(tmp_path)
    assert used.sources["pairs"] == {"gitlab.com/fixture/private"}
    assert used.instrument["pairs"]["skipped_values"] == 1
    assert used.instrument["pointers"]["skipped_values"] == 1
    assert used.sources["sweep"] == set()
    e.canonicalize_used(used, FakeAPI({}))  # Non-GitHub identities never reach this API.
    assert e.rejection(e.resolve("https://gitlab.com/fixture/private", FakeAPI({})), used, set()) == "pairs"
    report = used.report(set(e.SOURCES) - {"pairs"})
    assert report["sources"]["pairs"]["skipped_values"] == 1
    assert "fixture" not in json.dumps(report)
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://bitbucket.org/Fixture/Repo.git", "bitbucket.org/fixture/repo"),
        ("https://git.example.org/Fixture/Repo", "git.example.org/fixture/repo"),
        ("https://github.com/Fixture/Repo/tree/main", "fixture/repo"),
        ("Fixture/Repo.git/", "fixture/repo"),
    ],
)
def test_repository_hosts(value, expected):
    assert e.normalize(value) == expected
    assert e.normalize(expected) == expected


def test_memory_values_are_skipped_and_counted(tmp_path, capsys):
    rows = [
        {"kind": "example", "repo": value}
        for value in ["local-slice", "free text https://github.com/fixture/prose", None, "https://bitbucket.org/fixture/repo"]
    ]
    plant(tmp_path, "memory/repos/opaque/pin.jsonl", "\n".join(json.dumps(row) for row in rows))
    used = e.build_used(tmp_path, stores={"local": FileStore(tmp_path / "memory")})
    assert used.sources["memory_local"] == {"bitbucket.org/fixture/repo"}
    assert used.instrument["memory_local"]["skipped_values"] == 3
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("step", ["open_stores", "build_used", "report", "canonicalize", "verify_tests"])
def test_cli_failure_reports_only_step_and_exception_type(tmp_path, monkeypatch, capsys, step):
    from openultrasast import config
    from openultrasast.plane import memory

    def fail(*args, **kwargs):
        raise RuntimeError("sensitive/identity")

    monkeypatch.setattr(config, "load_dotenv", lambda path: None)
    monkeypatch.setattr(memory, "open_store", lambda *args, **kwargs: object())
    monkeypatch.setattr(e, "build_used", lambda *args, **kwargs: e.UsedSet())
    monkeypatch.setattr(e.UsedSet, "report", lambda *args, **kwargs: {})
    monkeypatch.setattr(e, "GitHub", lambda token: object())
    monkeypatch.setattr(e, "canonicalize_used", lambda *args: None)
    monkeypatch.setattr(e, "verify_tests", lambda *args: {})
    if step == "open_stores":
        monkeypatch.setattr(memory, "open_store", fail)
    elif step == "report":
        monkeypatch.setattr(e.UsedSet, "report", fail)
    else:
        monkeypatch.setattr(e, "canonicalize_used" if step == "canonicalize" else step, fail)
    assert e.main(["--root", str(tmp_path), "--verify-tests"]) == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {"status": "instrument_failure", "step": step, "type": "RuntimeError"}
    assert "sensitive" not in output.out
