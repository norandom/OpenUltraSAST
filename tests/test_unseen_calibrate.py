"""Offline calibration, placement, agreement and Docker diagnostic controls."""

import importlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
c = importlib.import_module("benchmarks.unseen.calibrate")
r = importlib.import_module("benchmarks.unseen.replay")
s = importlib.import_module("benchmarks.unseen.score")
b = importlib.import_module("benchmarks.ax.batch")


def timing_record(identity="opaque", factor=1, lane="docker"):
    return {
        "id": identity,
        "lane": lane,
        "repo": "never-publish",
        "kind": "ordinary",
        "instrument": {
            "head_verified": True,
            "base_verified": True,
            "changed_bytes": {"app.py": 10},
            "hook_exit": 0,
            "hook_bytes_read": 10,
            "timings": {"pre-push": 60 * factor},
        },
        "push": {
            "timings": {
                f"comparison_0_{k}_seconds": v * factor
                for k, v in (("resolution", 1), ("provenance", 2), ("snapshot", 4), ("preparation", 6), ("quick", 1))
            },
            "quick_tier": [{"bytes_read": 10, "findings": []}],
            "scans": [{"scan": {"build_seconds": 20 * factor, "query_seconds": 30 * factor}}],
        },
    }


def test_calibration_median_bootstrap_and_privacy():
    result = c.slowdown([1, 10, 100], [2, 20, 200])
    assert result == {"n": 3, "factor": 2, "bootstrap95": [2, 2]}
    varied = c.slowdown([1] * 5, [1, 2, 3, 4, 5])
    assert varied["factor"] == 3
    assert varied["bootstrap95"] == [1, 5]
    assert varied == c.slowdown([1] * 5, [1, 2, 3, 4, 5])
    record = c.calibration_record([timing_record()], [timing_record(factor=3, lane="ax")])
    assert record["quick_total"]["factor"] == 3
    assert record["pairs"][0]["native"]["quick_total"] == 10  # Snapshot is nested, not added twice.
    assert record["engine_build"]["factor"] == record["engine_queries"]["factor"] == 3
    assert "never-publish" not in json.dumps(record)
    with pytest.raises(ValueError):
        c.slowdown([0], [2])
    bad = timing_record()
    bad["push"]["snapshots"] = [{"boundaries": [{"reason": "deadline_exhausted"}]}]
    with pytest.raises(ValueError, match="deadline"):
        c.stage_times(bad)
    bad = timing_record()
    del bad["push"]["timings"]["comparison_0_quick_seconds"]
    with pytest.raises(ValueError, match="missing"):
        c.stage_times(bad)


@pytest.mark.parametrize(
    "lane,arm,expected",
    [
        ("ax", "default", 75),
        ("ax", "long_deadline", 750),
        ("docker", "default", 30),
        ("docker", "long_deadline", 300),
    ],
)
def test_scaled_task_contract(lane, arm, expected):
    item = r.make_item({"id": "a"}, arm, "image", deadline_scale=2.5, lane=lane)
    spec = json.loads(item.inputs["SPEC_URL"])
    assert spec["hook_flags"] == ["--deadline", str(expected)]
    assert spec["deadline_seconds"] == expected and spec["deadline_scale"] == 2.5
    entry = importlib.import_module("benchmarks.unseen.replay_entry")
    entry.validate_spec({**spec, "repository_url": "https://public.example/test", "base": "a" * 40, "head": "b" * 40})


def test_native_sample_and_agreement():
    native = [timing_record(str(i)) for i in range(100)]
    cluster = [timing_record(str(i), lane="ax") for i in range(100)]
    assert r.sample_changes(native, 20) == r.sample_changes(list(reversed(native)), 20)
    report = s.agreement(cluster, native)
    assert report["rate"] == 1 and report["baseline_eligible"]
    assert s.agreement(cluster[:20], native[:20])["flagged"]  # Perfect small sample is insufficient.
    cluster[0]["push"]["quick_tier"][0]["findings"] = [{"cwe": "CWE-89"}]
    report = s.agreement(cluster, native)
    assert report["disagreements"] == ["0"] and report["rate"] == 0.99
    assert report["flagged"]
    cluster[0]["instrument"] = {}
    report = s.agreement(cluster, native)
    assert report["unknown"] == ["0"] and report["flagged"]
    assert s.agreement([], [])["flagged"]


def test_docker_error_capture_and_preflight(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("TEST_SECRET", "hidden-value")
    lane = object.__new__(b.DockerLane)
    lane.args = SimpleNamespace(docker_image_bytes=100)
    lane.workload = SimpleNamespace(image="pinned-image")
    lane._prepared = False

    def runner(command, **kwargs):
        calls.append(command)
        if command[:2] == ["docker", "info"]:
            return subprocess.CompletedProcess(command, 0, "/docker-data\n", "")
        if command[0] == "df":
            return subprocess.CompletedProcess(command, 0, "Avail\n2000000000\n", "")
        return subprocess.CompletedProcess(command, 125, "", "pull denied hidden-value https://host.example/?signature=private\nlast error")

    lane.runner = runner
    record = lane(None, tmp_path, 0)
    assert record["status"] == "instrument_failure"
    assert record["docker_errors"][0]["exit_code"] == 125
    assert record["docker_errors"][0]["stderr"].endswith("last error")
    assert "hidden-value" not in json.dumps(record) and "private" not in json.dumps(record)
    assert [cmd[0] for cmd in calls] == ["docker", "df", "docker"]
    assert calls[-1] == ["docker", "pull", "pinned-image"]
    assert (tmp_path / "docker-error.json").exists()
    lane.args.docker_image_bytes = 2000000000
    calls.clear()
    record = lane(None, tmp_path, 1)
    assert "refusing Docker pull" in record["docker_errors"][0]["stderr"]
    assert len(calls) == 2


def test_docker_launch_error_survives_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "https://store.example")

    class Store:
        def _put(self, *args):
            pass

        def _delete(self, *args):
            pass

        def presign_get(self, *args):
            return "https://store.example/secret"

        presign_put = presign_get

    image = "registry/image@sha256:" + "a" * 64
    lane = b.DockerLane(
        SimpleNamespace(atespace="default"),
        b.Workload(image, frozenset({"SPEC_URL", "RESULT_URL"}), 60, None),
        store=Store(),
        runner=lambda command, **kw: subprocess.CompletedProcess(command, 0 if command[1] == "rm" else 125, "", "runtime missing"),
    )
    lane._prepared = True
    item = r.make_item({"id": "x"}, "default", image)
    record = lane(item, tmp_path, 0)
    assert record["docker_errors"] == [{"step": "run", "exit_code": 125, "stderr": "runtime missing"}]
    assert record["status"] == "instrument_failure"


def test_placement_scales_cluster_but_not_vm_fallback(tmp_path, monkeypatch):
    observed = []

    class Transport:
        def __init__(self, args, workload):
            assert workload.deadline >= 750 + 600

        def __call__(self, item, output, attempt):
            spec = json.loads(item.inputs["SPEC_URL"])
            observed.append(spec)
            return {"status": "quick_only"}

    def dispatch(items, workload, out, executors, **kwargs):
        for lane in ("ax", "docker"):
            record = executors[lane](items[0], out, 0)
            assert record["lane"] == lane
            assert record["deadline_seconds"] == (750 if lane == "ax" else 300)
        return False

    monkeypatch.setattr(r, "AXLane", Transport)
    monkeypatch.setattr(r, "DockerLane", Transport)
    monkeypatch.setattr(r, "dispatch", dispatch)
    args = SimpleNamespace(arm="long_deadline", image="test-image")
    assert not r.run_replays([{"id": "opaque"}], args, tmp_path, "mixed", deadline_scale=2.5)
    assert observed[0]["id"] == observed[1]["id"]
    assert observed[0]["hook_flags"] == ["--deadline", "750"]
    assert observed[1]["hook_flags"] == ["--deadline", "300"]


def test_calibration_cli_writes_anonymous_record(tmp_path, monkeypatch):
    manifest, record = tmp_path / "manifest.json", tmp_path / "record.json"
    changes = [{"id": str(i), "repo": "do-not-publish"} for i in range(25)]
    monkeypatch.setattr(c, "load_slice", lambda *args: changes)
    calls = []

    def replay(selected, args, out, lane, **kwargs):
        calls.append((selected, lane, kwargs))
        return False

    monkeypatch.setattr(c, "run_replays", replay)
    monkeypatch.setattr(
        c,
        "load_records",
        lambda path: [
            timing_record(str(i), factor=3 if path.name == "cluster" else 1, lane="ax" if path.name == "cluster" else "docker")
            for i in range(20)
        ],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "calibrate",
            "--manifest",
            str(manifest),
            "--image",
            "digest",
            "--docker-image-bytes",
            "100",
            "--out",
            str(tmp_path / "raw"),
            "--record",
            str(record),
        ],
    )
    assert c.main() == 0
    assert len(calls[0][0]) == 20 and calls[0][0] == calls[1][0]
    assert [call[1] for call in calls] == ["docker", "ax"]
    assert all(call[2]["deadline"] == 600 for call in calls)
    payload = record.read_text()
    assert "do-not-publish" not in payload and "never-publish" not in payload
    assert json.loads(payload)["quick_total"]["factor"] == 3
