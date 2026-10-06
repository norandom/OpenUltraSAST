import io
import json
import sys
import tarfile
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.ax import search_verify as transport
from openultrasast.search import verify_task as entry
from openultrasast.search.verify import RunObservation, Side, SideRecord


def demo():
    return {
        "oracle": "sql",
        "build": {"recipe": "none", "arguments": []},
        "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
        "steps": [{"type": "cli", "arguments": []}],
    }


def record():
    return SideRecord("observed", (RunObservation(True, "proof", 0.01),), 0.1, "observed", isolation_mode="task-boundary")


def test_dispatch_uses_fresh_tasks_and_only_data(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print(1)")
    calls = []

    def lane(item, output, attempt):
        calls.append(item)
        assert item.extra_env == {}
        assert set(item.inputs) == {"VERIFY_INPUT_URL"}
        assert item.inputs["VERIFY_INPUT_URL"] == b"executor-built-archive"
        return asdict(record())

    dispatch = transport.AXSideDispatcher(
        SimpleNamespace(), "image@sha256:" + "a" * 64, tmp_path / "out", lane=lane, prepare=lambda side, spec: b"executor-built-archive"
    )
    result = dispatch(side=Side(root), demo=demo(), family="injection", timeout_seconds=2, fresh_task=True)
    assert result.isolation_mode == "task-boundary"
    assert len(result.runs) == 3
    assert len(calls) == 3 and calls[0].id != calls[1].id
    # The operator egress rules match the task-name prefix, which comes from the workload kind.
    assert all(len(i.id) == 32 and i.id.isalnum() for i in calls)
    assert len({i.id for i in calls}) == 3


@pytest.mark.parametrize(
    "name,kind", [("../escape", tarfile.REGTYPE), ("/escape", tarfile.REGTYPE), ("app.py", tarfile.SYMTYPE), ("app.py", tarfile.LNKTYPE)]
)
def test_extract_rejects_escape_and_links(tmp_path, name, kind):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    with pytest.raises(ValueError):
        entry.extract_checkout(data.getvalue(), tmp_path / "repo")


@pytest.mark.parametrize("multipart", [False, True])
def test_entry_reads_input_and_scrubs_environment(tmp_path, monkeypatch, capsys, multipart):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print(1)")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    import shutil

    shutil.copytree(root, bundle / "checkout")
    (bundle / "products").mkdir()
    (bundle / "spec.json").write_text(json.dumps({"demo": demo(), "family": "injection", "timeout_seconds": 2}))
    blob = entry.pack_checkout(bundle)

    objects = {}
    if multipart:
        urls = ["https://store.example/part"]
        manifest = json.loads(entry.upload_parts(io.BytesIO(blob), objects.__setitem__, urls))
        manifest["parts"][0]["url"] = urls[0]
        objects["https://store.example/input"] = json.dumps(manifest).encode()
    else:
        objects["https://store.example/input"] = blob

    def download(url, limit):
        assert len(objects[url]) <= limit
        return objects[url]

    monkeypatch.setattr(entry, "download", download)
    outputs = []
    monkeypatch.setattr(entry, "upload", lambda url, data: outputs.append(json.loads(data)))

    def execute(side, schema, family, timeout_seconds):
        assert (side.checkout / "app.py").read_text() == "print(1)"
        assert "HOME" not in entry.os.environ
        return record()

    monkeypatch.setattr(entry, "run_side", execute)
    monkeypatch.setattr(
        entry.os,
        "environ",
        {
            "VERIFY_INPUT_URL": "https://store.example/input",
            "RESULT_URL": "https://store.example/result",
        },
    )
    entry.task_main()
    assert outputs[0]["outcome"] == "observed"
    assert "checkout_bytes=" in capsys.readouterr().out


@pytest.mark.parametrize("key", ["OPENAI_API_KEY", "OPENAI_KEY", "GEMINI_TOKEN", "DEEPSEEK_API_KEY"])
def test_entry_rejects_inherited_model_key_before_download(monkeypatch, key):
    monkeypatch.setattr(entry.os, "environ", {key: "secret"})
    monkeypatch.setattr(entry, "download", lambda *a: pytest.fail("must not read input"))
    with pytest.raises(ValueError, match="credentials"):
        entry.task_main()


def test_archive_expansion_limit(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_bytes(b"A" * 1024)
    data = entry.pack_checkout(root)
    monkeypatch.setattr(entry, "MAX_CHECKOUT_BYTES", 10)
    with pytest.raises(ValueError, match="expanded checkout"):
        entry.extract_checkout(data, tmp_path / "destination")


def test_pack_refuses_symlinks(tmp_path):
    (tmp_path / "outside").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="special files"):
        entry.pack_checkout(tmp_path)


def test_result_requires_single_completed_attested_run(tmp_path):
    payload = asdict(record())
    for change in ({"isolation_mode": "userns"}, {"runs": []}, {"runs": [payload["runs"][0]] * 3}):
        with pytest.raises(ValueError):
            transport.validate_result(json.dumps({**payload, **change}).encode(), tmp_path)


def test_production_item_targets_packaged_module(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print(1)")
    captured = []

    class Lane:
        def __init__(self, args, workload):
            captured.append(workload)

        def __call__(self, item, output, attempt):
            assert item.command == ("python3", "-m", "openultrasast.search.verify_task")
            transport.validate_result(json.dumps(asdict(record())).encode(), output)
            return json.loads((output / "result.json").read_text())

    from unittest.mock import patch

    with patch.object(transport, "AXLane", Lane):
        dispatcher = transport.AXSideDispatcher(
            SimpleNamespace(), "image@sha256:" + "a" * 64, tmp_path / "out", prepare=lambda side, spec: b"built"
        )
        dispatcher(side=Side(root), demo=demo(), family="injection", timeout_seconds=2, fresh_task=True)
    assert captured[0].url_env == frozenset({"VERIFY_INPUT_URL", "RESULT_URL"})


@pytest.mark.parametrize("outcome", ["could_not_build", "could_not_run", "no_oracle", "inconclusive"])
def test_incomplete_outcomes_survive_transport(tmp_path, outcome):
    payload = {**asdict(record()), "outcome": outcome, "runs": []}
    transport.validate_result(json.dumps(payload).encode(), tmp_path)
    assert json.loads((tmp_path / "result.json").read_text())["outcome"] == outcome


@pytest.mark.parametrize("value", [-1, float("nan"), float("inf"), "0", True])
def test_result_rejects_invalid_measurements(tmp_path, value):
    with pytest.raises(ValueError):
        transport.validate_result(json.dumps({**asdict(record()), "elapsed_seconds": value}).encode(), tmp_path)


def test_default_dispatch_builds_in_executor_before_verifier(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('input')")
    events = []

    class Executor:
        def __init__(self, lane, archive):
            assert archive

        def __enter__(self):
            events.append("executor-start")
            return self

        def prepare(self, spec):
            assert spec["demo"] == demo()
            events.append("build")
            return b"built"

        def __exit__(self, *args):
            events.append("executor-deleted")

    def lane(item, output, attempt):
        assert events[:3] == ["executor-start", "build", "executor-deleted"]
        assert item.inputs == {"VERIFY_INPUT_URL": b"built"}
        events.append("verify")
        return asdict(record())

    monkeypatch.setattr(transport, "SearchExecutorTask", Executor)
    dispatch = transport.AXSideDispatcher(SimpleNamespace(), "image@sha256:" + "a" * 64, tmp_path / "out", lane=lane)
    assert len(dispatch(side=Side(root), demo=demo(), family="injection", timeout_seconds=2, fresh_task=True).runs) == 3
    assert events[3:] == ["verify"] * 3


def test_source_archive_omits_git_metadata(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("print('source')")
    (root / ".git").write_text("gitdir: /host/private/worktree")
    archive = entry.pack_checkout(root)
    target = tmp_path / "extracted"
    from openultrasast.search.executor import unpack_checkout

    unpack_checkout(archive, target)
    assert (target / "app.py").read_text() == "print('source')"
    assert not (target / ".git").exists()


@pytest.mark.parametrize(
    "family,oracle",
    [
        ("injection", "sql"),
        ("injection", "command"),
        ("path", "path"),
        ("output_encoding", "xss"),
        ("untrusted_destination", "ssrf"),
    ],
)
def test_transport_checks_family_and_demo_oracle(family, oracle):
    schema = demo()
    schema["oracle"] = oracle
    spec = {"demo": schema, "family": family, "timeout_seconds": 2}
    assert entry.validate_spec(spec) == spec
    schema["oracle"] = "path" if oracle != "path" else "sql"
    with pytest.raises(ValueError, match="not allowed"):
        entry.validate_spec(spec)


@pytest.mark.parametrize("mode,timeout", [("http", 90), ("cli", 30)])
def test_verifier_deadline_uses_mode_budget_and_all_steps(tmp_path, monkeypatch, mode, timeout):
    from openultrasast.search.budget import verification_run_seconds, verification_timeout

    schema = demo()
    schema["start"]["mode"] = mode
    schema["steps"] *= 8
    assert verification_timeout(schema) == timeout
    assert verification_timeout(schema, {mode + "_start_seconds": 17}) == 17
    workloads = []

    def lane(args, workload):
        workloads.append(workload)
        return lambda *args: asdict(record())

    monkeypatch.setattr(transport, "AXLane", lane)
    dispatch = transport.AXSideDispatcher(
        SimpleNamespace(), "image@sha256:" + "a" * 64, tmp_path / "out", prepare=lambda side, spec: b"archive"
    )
    dispatch(side=Side(tmp_path), demo=schema, family="injection", timeout_seconds=timeout, fresh_task=True)
    assert workloads[0].deadline == verification_run_seconds(schema, timeout) + 60 == timeout * 9 + 65


@pytest.mark.parametrize("corrupt", [False, True])
def test_multipart_digest_checked_before_extraction(tmp_path, monkeypatch, corrupt):
    import hashlib

    monkeypatch.setattr(entry, "MAX_PART_BYTES", 100)
    source = tmp_path / "source"
    source.mkdir()
    (source / "input").write_bytes(bytes(range(256)) * 4)
    blob = entry.pack_checkout(source)
    objects = {}
    urls = [f"https://store.example/part-{index}" for index in range(entry.MAX_PARTS)]
    manifest = entry.upload_parts(io.BytesIO(blob), objects.__setitem__, urls)
    parts = json.loads(manifest)["parts"]
    assert len(objects) == len(parts) > 1
    assert all(len(value) <= 100 for value in objects.values())
    assert all(hashlib.sha256(objects[urls[p["index"]]]).hexdigest() == p["sha256"] for p in parts)
    if corrupt:
        objects[urls[1]] = b"x" * len(objects[urls[1]])
    assembled = io.BytesIO()
    if corrupt:
        with pytest.raises(ValueError, match="part digest mismatch"):
            entry.assemble_parts(manifest, assembled, lambda part: objects[urls[part["index"]]])
        assert not (tmp_path / "restored").exists()
    else:
        entry.assemble_parts(manifest, assembled, lambda part: objects[urls[part["index"]]])
        entry.extract_checkout(assembled, tmp_path / "restored")
        assert (tmp_path / "restored/input").read_bytes() == (source / "input").read_bytes()


def test_multipart_rejects_total_cap_before_fetch(monkeypatch):
    monkeypatch.setattr(entry, "MAX_ARCHIVE_BYTES", 10)
    with pytest.raises(ValueError, match="size limit"):
        entry.upload_parts(io.BytesIO(b"x" * 11), lambda *args: pytest.fail("must not upload"), ["unused"])
    manifest = json.dumps({"format": "gzip-parts-v1", "size": 11, "parts": []}).encode()
    with pytest.raises(ValueError, match="size limit"):
        entry.assemble_parts(manifest, io.BytesIO(), lambda *args: pytest.fail("must not fetch"))
