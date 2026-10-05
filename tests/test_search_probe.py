import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.search import probe
from openultrasast.search._sandbox import IsolationUnavailable


@pytest.fixture(autouse=True)
def namespace_diagnostics(monkeypatch):
    facts = {name: {"exit_code": 0} for name in ("user", "pid", "net", "ipc", "uts", "mount")}
    monkeypatch.setattr(probe, "namespace_facts", lambda: facts)
    monkeypatch.setattr(probe._sandbox, "isolation_mode", lambda: "userns")
    return facts


def test_isolation_failure_is_recorded_and_nonzero(monkeypatch, capsys):
    def fail(**kwargs):
        raise IsolationUnavailable("gVisor denied namespace")

    monkeypatch.setattr(probe._sandbox, "isolation_check", fail)
    monkeypatch.setattr(probe, "image_facts", lambda: {})
    monkeypatch.delenv("RESULT_URL", raising=False)
    assert probe.main([]) == 1
    record = json.loads(capsys.readouterr().out)
    assert record["status"] == "instrument_failure"
    assert "gVisor denied namespace" in record["exception"]
    assert record["oracles"] == {}


def test_packaged_pairs_and_three_demos(tmp_path):
    for family in probe.FAMILIES:
        sides, demos = probe.materialise(tmp_path / family, family)
        assert len(demos) == 3
        assert all((s.checkout / "app.py").stat().st_size > 0 for s in sides)
        assert (sides[1].checkout / "fixed").exists()
        assert json.loads((demos["real"] / "demo.json").read_text())["steps"][0]["arguments"][0] == family


def test_batch_workload_and_all_lanes(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from benchmarks.ax import search_probe as adapter
    from benchmarks.ax.batch import manifest

    image = "registry/search@sha256:" + "a" * 64
    item = adapter.probe_item(image)
    workload = adapter.probe_workload(image)
    doc = manifest(
        "ousast-engine-search-probe-123456789012", workload, item, {"RESULT_URL": "https://objects.example.org/probe"}, "default"
    )
    assert doc["spec"]["command"] == ["python3", "-m", "openultrasast.search.probe"]
    assert item.inputs == {}
    called = []

    def lane(args, workload):
        called.append(args.lane)
        return lambda *args: {"status": "ok"}

    monkeypatch.setattr(adapter, "AXLane", lane)
    monkeypatch.setattr(adapter, "DockerLane", lane)
    for name in ("ax", "kind", "docker"):
        args = SimpleNamespace(image=image, lane=name, deadline=900, out=tmp_path / name)
        assert not adapter.run_probe(args)
    assert called == ["ax", "kind", "docker"]


def test_probe_runs_all_fifteen_verifications(tmp_path, monkeypatch):
    from openultrasast.search.verify import SideRecord, VerificationRecord

    calls = []
    monkeypatch.setattr(probe._sandbox, "isolation_check", lambda: None)
    monkeypatch.setattr(probe, "image_facts", lambda: {"python": {"version": "test"}})
    monkeypatch.setattr(probe, "BrowserExecutor", lambda: object())

    def verify(a, b, demo, family, **kwargs):
        calls.append((family, demo.name))
        return VerificationRecord(
            "demonstrated" if demo.name == "real" else "inconclusive", (SideRecord("observed", (), 1, "", 0.2, 0.3, 0.5),) * 2, 2, ""
        )

    monkeypatch.setattr(probe, "verify", verify)
    record = probe.probe(tmp_path)
    assert record["status"] == "ok"
    assert len(calls) == 15
    assert record["oracles"]["sql"]["real"]["sides"][0]["ready_seconds"] == 0.3
    assert record["scratch_disk_bytes"] > 0


def test_result_put_same_record_without_credentials(monkeypatch, capsys):
    from io import BytesIO

    monkeypatch.setenv("RESULT_URL", "https://store.example/probe?signature=secret")
    monkeypatch.setattr(probe, "probe", lambda root: {"status": "ok"})
    seen = []

    class Response(BytesIO):
        status = 200

    def upload(request, **kwargs):
        seen.append(request)
        return Response()

    monkeypatch.setattr(probe.urllib.request, "urlopen", upload)
    assert probe.main([]) == 0
    assert seen[0].data == capsys.readouterr().out.encode()
    assert seen[0].method == "PUT"
    assert not seen[0].has_header("Authorization")


def test_oracle_namespace_failure_is_instrument_failure(tmp_path, monkeypatch):
    from openultrasast.search.verify import SideRecord, VerificationRecord

    monkeypatch.setattr(probe._sandbox, "isolation_check", lambda: None)
    monkeypatch.setattr(probe, "image_facts", lambda: {})
    monkeypatch.setattr(
        probe,
        "verify",
        lambda *a, **kw: VerificationRecord(
            "inconclusive", (SideRecord("could_not_run", (), 0, "verification unavailable or refused: net namespace denied"),), 0, ""
        ),
    )
    record = probe.probe(tmp_path)
    assert record["status"] == "instrument_failure"
    assert "net namespace denied" in record["exception"]
    assert record["isolation_check"]["status"] == "ok"


@pytest.mark.parametrize("execution", ["real", "stubbed"])
def test_task_boundary_probe_executes_packaged_pairs(tmp_path, monkeypatch, namespace_diagnostics, execution):
    if execution == "real":
        import socket

        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
        except PermissionError:
            pytest.skip("host policy prohibits localhost sockets required by SSRF and Chromium")
    else:
        from openultrasast.search.verify import RunObservation, SideRecord

        def run(side, demo, family):
            assert (side.checkout / "app.py").read_bytes()
            observed = not (side.checkout / "fixed").exists()
            return SideRecord(
                "observed",
                (RunObservation(observed, "stubbed owned effect", 0.5),),
                0.7,
                "stubbed execution",
                0,
                0.2,
                0.5,
                4096,
                "task-boundary",
                json.loads((demo / "demo.json").read_text())["oracle"] == "xss",
            )

        monkeypatch.setattr(probe, "verify_side_task", run)
    monkeypatch.setattr(probe._sandbox, "isolation_mode", lambda: "task-boundary")
    monkeypatch.setattr(probe, "image_facts", lambda: {})
    monkeypatch.setattr(probe._sandbox, "isolation_check", lambda **kw: pytest.fail("task boundary must skip preflight"))
    monkeypatch.setattr(probe, "verify", lambda *a, **kw: pytest.fail("must use task executor"))
    record = probe.probe(tmp_path)
    assert record["status"] == "ok", record
    assert record["isolation_check"] == {"status": "skipped", "reason": "task-boundary"}
    assert record["isolation_mode"] == "task-boundary"
    assert record["namespaces"] == namespace_diagnostics
    assert set(record["oracles"]) == set(probe.FAMILIES)
    for family, demos in record["oracles"].items():
        assert set(demos) == {"real", "observer_access", "revision_patch"}
        for name, result in demos.items():
            assert (result["outcome"] == "demonstrated") == (name == "real")
            assert result["isolation_mode"] == "task-boundary"
            assert result["elapsed_seconds"] > 0
        real = demos["real"]
        assert real["chromium_no_sandbox"] == (family == "xss")
        for index, side in enumerate(real["sides"]):
            assert len(side["runs"]) == 3
            assert all(run["observed"] == (index == 0) for run in side["runs"])
            assert side["isolation_mode"] == "task-boundary"
            assert side["chromium_no_sandbox"] == (family == "xss")
            assert side["build_seconds"] == 0
            assert side["ready_seconds"] > 0
            assert side["run_seconds"] > 0
            assert side["scratch_peak_bytes"] > 0
    assert record["wall_seconds"] > 0
    assert record["peak_rss_kib"]["sum"] > 0
    assert record["scratch_disk_bytes"] > 0
    assert record["verification_scratch_peak_bytes"] > 0
    assert record["scratch_filesystem_used_bytes"] > 0


@pytest.mark.parametrize("family", ["sql", "path", "command"])
def test_task_boundary_real_local_oracles(tmp_path, family):
    sides, demos = probe.materialise(tmp_path / family, family)
    result = probe._verify_task_pair(sides, demos["real"], family)
    assert result.outcome == "demonstrated", result
    assert all(len(side.runs) == 3 for side in result.sides)


def test_task_boundary_xss_uses_browser_mode(tmp_path, monkeypatch):
    from openultrasast.search.oracles import BrowserExecutor

    calls = []

    def capture(self, document, nonce):
        assert self.task_boundary and self.no_sandbox
        calls.append(document)
        return '<script>alert("ousast-xss")</script>' in document

    monkeypatch.setattr(BrowserExecutor, "__call__", capture)
    sides, demos = probe.materialise(tmp_path / "xss", "xss")
    result = probe._verify_task_pair(sides, demos["real"], "xss")
    assert result.outcome == "demonstrated"
    assert result.chromium_no_sandbox
    assert all(side.chromium_no_sandbox for side in result.sides)
    assert len(calls) == 6


@pytest.mark.parametrize("mismatch", ["real", "observer_access", "revision_patch", "exception"])
def test_task_boundary_mismatch_names_first_and_finishes(tmp_path, monkeypatch, mismatch):
    from openultrasast.search.verify import VerificationRecord

    # On AX the diagnostics select the boundary before the failed bwrap preflight.
    facts = {name: {"exit_code": 1} for name in ("user", "pid", "net", "ipc", "uts", "mount")}
    monkeypatch.setattr(probe, "namespace_facts", lambda: facts)
    monkeypatch.setattr(probe, "image_facts", lambda: {})
    monkeypatch.setattr(probe._sandbox, "isolation_check", lambda **kw: pytest.fail("must skip preflight"))

    def result(sides, demo, family):
        if mismatch == "exception":
            raise OSError("executor unavailable")
        demonstrated = demo.name == "real"
        if demo.name == mismatch:
            demonstrated = not demonstrated
        return VerificationRecord("demonstrated" if demonstrated else "inconclusive", (), 1, "", "task-boundary")

    monkeypatch.setattr(probe, "_verify_task_pair", result)
    record = probe.probe(tmp_path)
    assert record["status"] == "instrument_failure"
    assert record["exception"].startswith(f"sql/{'real' if mismatch == 'exception' else mismatch}:")
    assert record["namespaces"] == facts
    assert record["isolation_check"] == {"status": "skipped", "reason": "task-boundary"}
    assert sum(len(demos) for demos in record["oracles"].values()) == 15
