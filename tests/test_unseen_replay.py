"""Replay workload privacy, validation and input identity."""

import importlib
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
r = importlib.import_module("benchmarks.unseen.replay")


def test_items_private_and_arm_identity():
    change = {
        "id": "repo-name-secret",
        "repo": "owner/private-name",
        "repository_url": "https://public.example/private-name",
        "base": "a" * 40,
        "head": "b" * 40,
        "files": [{"path": "app.py", "head_lines": [[1, 2]]}],
    }
    image = "registry/replay@sha256:" + "a" * 64
    a = r.make_item(change, "default", image)
    b = r.make_item(change, "long_deadline", image)
    assert a.input_digest != b.input_digest
    assert "private-name" not in a.id and "repo-name" not in a.id
    assert set(a.inputs) == {"SPEC_URL"} and not a.extra_env
    spec = json.loads(a.inputs["SPEC_URL"])
    assert spec["repository_url"] == change["repository_url"]
    assert json.loads(b.inputs["SPEC_URL"])["hook_flags"] == ["--deadline", "300"]


def test_validator_requires_instrument(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        data = b"{}"
        info = tarfile.TarInfo("push.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError, match="instrument"):
        r.validate_result(buffer.getvalue(), tmp_path)


def test_frozen_toml_slice_and_scoring_join(tmp_path):
    import hashlib

    from benchmarks.unseen.score import load_records

    pool = tmp_path / "pool-p1.toml"
    pool.write_text("""pool="p1"
[[repository]]
id="opaque-a"
slice=1
url="https://public.example/repo-a"
changes=[{kind="ordinary",base="aaa",head="bbb",files=[]}]
[[repository]]
id="opaque-b"
slice=2
url="https://public.example/repo-b"
changes=[{kind="ordinary",base="ccc",head="ddd",files=[]}]
""")
    import tomllib

    freeze = hashlib.sha256(r.canonical(tomllib.loads(pool.read_text()))).hexdigest()
    (tmp_path / "freeze-p1.json").write_text(json.dumps({"freeze_digest": freeze}))
    changes = r.load_slice(pool, 2)
    assert len(changes) == 1 and changes[0]["repo"] == "opaque-b"
    (tmp_path / "inputs.json").write_text(json.dumps([{"item_id": "replay-opaque", "change": changes[0], "input_digest": "digest"}]))
    assert load_records(tmp_path)[0]["kind"] == "ordinary"
    assert "instrument" not in load_records(tmp_path)[0]  # Missing result remains a measured failure.
    result = tmp_path / (hashlib.sha256(b"replay-opaque").hexdigest() + ".json")
    result.write_text(json.dumps({"input_digest": "digest", "instrument": {"head_verified": True}}))
    assert load_records(tmp_path)[0]["instrument"]["head_verified"]
    pool.write_text(pool.read_text() + "changed=true\n")
    with pytest.raises(ValueError, match="digest"):
        r.load_slice(pool, 2)
