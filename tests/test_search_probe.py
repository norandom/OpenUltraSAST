import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.search import probe
from openultrasast.search._sandbox import IsolationUnavailable


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
        assert json.loads((demos["real"] / "request.json").read_text())[0] == family


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
