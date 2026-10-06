"""Offline replay through real preparation, multipart export and owned oracles."""

import json
import shutil
import sys
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmarks.ax import batch
from benchmarks.search import demo_replay, pilot_run
from openultrasast.search import executor as executor_module
from openultrasast.search.executor import InProcessExecutor
from openultrasast.search.probe import materialise
from openultrasast.search.verify import Side, verify_side_task
from openultrasast.search.verify_task import extract_checkout

IMAGE = "image@sha256:" + "a" * 64


def harness(tmp_path, monkeypatch, *, failing=False):
    sides, demos = materialise(tmp_path / "probe", "path")
    events, objects = [], {}

    class Transport:
        def put(self, url, data, timeout):
            objects[url] = data if isinstance(data, bytes) else data.read()

    monkeypatch.setattr(executor_module, "URLTransport", Transport)

    class Executor(InProcessExecutor):
        def _task_run(self, argv, timeout, limits, **kwargs):
            if argv[:2] == ["sh", "-ec"]:
                assert argv[2] == pilot_run.CLONE
                source = sides[argv[-1] == "b" * 40].checkout
                shutil.copytree(source, self.repo, dirs_exist_ok=True)
                if failing:
                    (self.repo / "build.gradle").write_text("// offline failing fixture\n")
                    (self.repo / "gradlew").write_text("echo replay build broke >&2\nexit 7\n")
                return dict(exit_code=0, stdout="cloned", stderr="")
            return super()._task_run(argv, timeout, limits, **kwargs)

    class Task:
        prepare = batch.SearchExecutorTask.prepare

        def __init__(self, lane, archive, deadline):
            self.lane = SimpleNamespace(store=SimpleNamespace(_get=lambda key: (objects[key], {}) if key in objects else None))
            self.keys = ["unused0", "unused1", "unused2", "manifest", "part"]
            self.end = time.monotonic() + deadline

        def __enter__(self):
            events.append("executor")
            repo = tmp_path / ("exec-" + str(len(events)))
            repo.mkdir()
            self.client = Executor(repo, task_boundary=True)
            self.client.prepared_put_url = "manifest"
            self.client.prepared_part_urls = ["part"]
            return self

        def __exit__(self, *args):
            events.append("deleted")

    monkeypatch.setattr(pilot_run, "SearchExecutorTask", Task)
    ids = []

    def lane(item, output, attempt):
        assert events[-1] in ("deleted", "verify")
        events.append("verify")
        assert item.id not in ids
        ids.append(item.id)
        bundle = output / "bundle"
        extract_checkout(item.inputs["VERIFY_INPUT_URL"], bundle)
        spec = json.loads((bundle / "spec.json").read_text())
        assert spec["demo"]["build"] == {"recipe": "none", "arguments": []}
        demo = output / "demo.json"
        demo.write_text(json.dumps(spec["demo"]))
        return asdict(
            verify_side_task(Side(bundle / "checkout", products=bundle / "products"), demo, spec["family"], spec["timeout_seconds"])
        )

    schema_path = demos["real"] / "demo.json"
    if failing:
        schema = json.loads(schema_path.read_text())
        schema["build"] = {"recipe": "gradle", "arguments": ["build.gradle"]}
        schema_path.write_text(json.dumps(schema))
    args = SimpleNamespace(
        repo_url="https://github.com/private-owner/private-project",
        commit="a" * 40,
        fixed_commit="b" * 40,
        demo=schema_path,
        family="path",
        lane="ax",
        image=IMAGE,
        both=True,
    )
    root = tmp_path / "replay"
    root.mkdir()
    return args, root, lane, events


def test_both_cli_demonstrates_probe_pair(tmp_path, monkeypatch):
    args, root, lane, events = harness(tmp_path, monkeypatch)
    monkeypatch.setattr(demo_replay, "AXLane", lambda *a: lane)
    out = tmp_path / "out"
    assert (
        demo_replay.main(
            [
                "--repo-url",
                args.repo_url,
                "--commit",
                args.commit,
                "--fixed-commit",
                args.fixed_commit,
                "--both",
                "--demo",
                str(args.demo),
                "--family",
                "path",
                "--lane",
                "ax",
                "--image",
                IMAGE,
                "--out",
                str(out),
            ]
        )
        == 0
    )
    record = json.loads((out / "record.json").read_text())
    assert record["outcome"] == "demonstrated", record
    assert events == ["executor", "deleted", "verify", "verify", "verify"] * 2
    assert [[r["observed"] for r in s["runs"]] for s in record["sides"]] == [[True] * 3, [False] * 3]
    assert all(r["evidence"] for s in record["sides"] for r in s["runs"])
    assert record["input_bytes"] > 0
    assert record["model_calls"] == record["spend_usd"] == 0
    for prep in record["preparations"]:
        assert prep["archive_bytes"] > 0 and prep["archive_parts"] == 1
        assert prep["build_exit_code"] == 0
        assert {"acquisition", "build", "bundle", "upload", "prepare_roundtrip"} <= prep["wall_seconds_by_phase"].keys()
    assert args.repo_url not in json.dumps(record)
    assert args.commit not in json.dumps(record)
    assert args.fixed_commit not in json.dumps(record)


def test_single_build_failure_retains_stderr(tmp_path, monkeypatch):
    args, root, lane, events = harness(tmp_path, monkeypatch, failing=True)
    args.both, args.fixed_commit = False, None
    record = demo_replay.run_replay(args, root, lane=lane)
    assert record["outcome"] == "could_not_build", record
    assert record["sides"][0]["outcome"] == "could_not_build"
    assert record["preparations"][0]["build_exit_code"] != 0
    assert "replay build broke" in record["preparations"][0]["build_stderr_tail"]
    assert events == ["executor", "deleted"]


@pytest.mark.parametrize("fixed", [False, True])
def test_single_observation_is_not_a_differential(tmp_path, monkeypatch, fixed):
    args, root, lane, events = harness(tmp_path, monkeypatch)
    args.both = False
    args.commit = args.fixed_commit if fixed else args.commit
    args.fixed_commit = None
    record = demo_replay.run_replay(args, root, lane=lane)
    assert record["outcome"] == "observed", record
    assert [r["observed"] for r in record["sides"][0]["runs"]] == [not fixed] * 3


def test_no_oracle_does_not_acquire(tmp_path, monkeypatch):
    args, root, lane, events = harness(tmp_path, monkeypatch)
    args.family = "access_control"
    record = demo_replay.run_replay(args, root, lane=lane)
    assert record["outcome"] == "no_oracle"
    assert not events


def test_both_identical_revisions_are_inconclusive(tmp_path, monkeypatch):
    args, root, lane, events = harness(tmp_path, monkeypatch)
    args.fixed_commit = args.commit
    record = demo_replay.run_replay(args, root, lane=lane)
    assert record["outcome"] == "inconclusive"
    assert record["verify_tasks"] == 6 and record["tasks_submitted"] == 8


def test_lane_failure_is_could_not_run(tmp_path, monkeypatch):
    args, root, lane, events = harness(tmp_path, monkeypatch)
    args.both, args.fixed_commit = False, None

    def broken(*args):
        raise ValueError("verifier unavailable")

    record = demo_replay.run_replay(args, root, lane=broken)
    assert record["outcome"] == "could_not_run"
    assert "verifier unavailable" in record["reason"]


def test_replay_registered_as_standalone():
    from openultrasast.model.audit import audit

    rows = {r.module: r for r in audit(Path("benchmarks"))}
    assert rows["search.demo_replay"].classification == "standalone_capability"


def test_docker_selection_uses_same_preparation_and_fresh_runs(tmp_path, monkeypatch):
    args, root, fake_lane, events = harness(tmp_path, monkeypatch)
    args.lane = "docker"

    class Docker(batch.DockerLane):
        def __init__(self, *args):
            pass

        def _prepare_image(self):
            events.append("docker-image")

        def __call__(self, *args):
            return fake_lane(*args)

    monkeypatch.setattr(demo_replay, "DockerLane", Docker)
    record = demo_replay.run_replay(args, root)
    assert record["outcome"] == "demonstrated"
    assert events[0] == "docker-image"
    assert record["executor_tasks"] == 2 and record["verify_tasks"] == 6


def test_docker_verifier_command_has_no_engine_arguments():
    import subprocess

    commands = []
    lane = batch.DockerLane.__new__(batch.DockerLane)
    lane._diagnostics = []

    def runner(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "container", "")

    lane.runner = runner
    lane._docker_command(
        "apply",
        manifest={
            "metadata": {"name": "verifier"},
            "spec": {
                "command": ["python3", "-m", "openultrasast.search.verify_task"],
                "env": [],
                "image": IMAGE,
            },
        },
    )
    assert commands[0][-3:] == [IMAGE, "-m", "openultrasast.search.verify_task"]
    assert "--heap-profile" not in commands[0]
