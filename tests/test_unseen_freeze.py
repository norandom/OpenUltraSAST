"""Freeze fixture pools without reading reservations or running subprocesses."""

import hashlib
import importlib
import json
import tomllib
from pathlib import Path

import pytest
from test_unseen_bisect import b, d, draft_pair

f = importlib.import_module("benchmarks.unseen.freeze")


def prepared(tmp_path):
    root, draft, rows = draft_pair(tmp_path)
    b.run(root, draft, guard_runner=lambda root: 0)
    protocol = root / "benchmarks/unseen/protocol-p1.md"
    protocol.write_bytes(Path("benchmarks/unseen/protocol-p1.md").read_bytes())
    return root, rows


def used():
    return {"sha256": "a" * 64, "sources": {"pairs": {"count": 7}, "memory_s3": {"count": 3}}}


def test_freeze_split_receipt_and_existing_guard_digest(tmp_path, capsys, caplog, monkeypatch):
    root, rows = prepared(tmp_path)
    record = f.run(root, used_report=used())
    directory = root / "benchmarks/unseen"
    pool = directory / "pool-p1.toml"
    public = tomllib.loads(pool.read_text())
    private = tomllib.loads((directory / "private/pool-p1.toml").read_text())
    assert public["status"] == private["status"] == "frozen"
    assert record["used_set_digest"] == "a" * 64
    assert record["source_counts"] == {"pairs": 7, "memory_s3": 3}
    assert record["label_check_counts"] == {"confirmed": 3, "refactor": 3, "unclear": 3, "unchecked": 0}
    assert record["guard_result"] == 0 and record["dropped_count"] == 0
    assert record["protocol_digest"] == hashlib.sha256((directory / "protocol-p1.md").read_bytes()).hexdigest()
    assert record["freeze_digest"] == hashlib.sha256(d.canonical(public)).hexdigest()
    assert json.loads((directory / "freeze-p1.json").read_text()) == record
    for row in rows:
        assert row["repository"] not in json.dumps(record) and row["url"] not in json.dumps(record)
        if row["license_class"] == "private":
            assert row["url"] not in pool.read_text() and row["repository"] not in pool.read_text()
            pointer = next(p for p in public["repository"] if p["id"] == row["id"])
            assert pointer == {"id": row["id"], "slice": row["slice"], "private": True, "sha256": d.private_digest(row)}
            assert row in private["repository"]
        else:
            assert row in public["repository"]
    assert (directory / "private/pool-p1.toml").stat().st_mode & 0o777 == 0o600
    guard = importlib.import_module("test_independent_population")
    monkeypatch.setattr(guard, "ROOT", root)
    guard.test_frozen_pool_manifest_digest()
    assert capsys.readouterr() == ("", "") and not caplog.records


def test_digest_and_retry_ignore_toml_key_order(tmp_path):
    root, _ = prepared(tmp_path)
    original = f.run(root, used_report=used())
    pool = root / "benchmarks/unseen/pool-p1.toml"
    text = pool.read_text()
    lines = text.splitlines()
    pool.write_text("\n".join([lines[2], lines[1], lines[0], *lines[3:]]) + "\n")
    before = pool.read_bytes()
    assert f.run(root, used_report=used()) == original
    assert pool.read_bytes() == before


@pytest.mark.parametrize("target", ["pool-p1.toml", "private/pool-p1.toml", "freeze-p1.json"])
def test_numeric_type_change_is_a_different_frozen_artifact(tmp_path, target):
    root, _ = prepared(tmp_path)
    f.run(root, used_report=used())
    path = root / "benchmarks/unseen" / target
    text = path.read_text()
    if path.suffix == ".toml":
        modified = text.replace("seed = 19", "seed = 19.0")
    else:
        modified = text.replace('"guard_result": 0', '"guard_result": false')
    assert text != modified
    path.write_text(modified)
    with pytest.raises(FileExistsError, match="new_pool"):
        f.run(root, used_report=used())
    assert path.read_text() == modified


@pytest.mark.parametrize("target", ["pool-p1.toml", "private/pool-p1.toml", "freeze-p1.json", "protocol-p1.md"])
def test_refuses_different_frozen_files(tmp_path, target):
    root, _ = prepared(tmp_path)
    f.run(root, used_report=used())
    directory = root / "benchmarks/unseen"
    path = directory / target
    if path.suffix == ".toml":
        path.write_text(path.read_text().replace('status = "frozen"', 'status = "modified"'))
    elif path.suffix == ".json":
        record = json.loads(path.read_text())
        record["dropped_count"] += 1
        path.write_text(json.dumps(record))
    else:
        path.write_text("changed protocol")
    before = {p: p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    with pytest.raises(FileExistsError, match="new_pool"):
        f.run(root, used_report=used())
    assert all(p.read_bytes() == value for p, value in before.items())


@pytest.mark.parametrize("target", ["draft-p1.toml", "private/draft-p1.toml", "bisect-p1.json"])
def test_refuses_stale_or_red_guard_receipt(tmp_path, target):
    root, _ = prepared(tmp_path)
    path = root / "benchmarks/unseen" / target
    if target.endswith(".json"):
        receipt = json.loads(path.read_text())
        receipt["guard_result"] = 1
        path.write_text(json.dumps(receipt))
    else:
        before = path.read_text()
        after = before.replace('"head" = "', '"head" = "0', 1)
        assert before != after
        path.write_text(after)
    with pytest.raises((ValueError, b.InstrumentFailure)):
        f.run(root, used_report=used())
    assert not (root / "benchmarks/unseen/pool-p1.toml").exists()


@pytest.mark.parametrize("mutation", ["digest", "source_name", "count"])
def test_rejects_identity_bearing_metadata(tmp_path, mutation):
    root, rows = prepared(tmp_path)
    report = used()
    if mutation == "digest":
        report["sha256"] = rows[0]["url"]
    elif mutation == "source_name":
        report["sources"][rows[0]["repository"]] = {"count": 1}
    else:
        report["sources"]["pairs"]["count"] = rows[0]["url"]
    with pytest.raises(ValueError):
        f.run(root, used_report=report)
    assert not (root / "benchmarks/unseen/freeze-p1.json").exists()


def test_missing_protocol_aborts_before_publication(tmp_path):
    root, _ = prepared(tmp_path)
    (root / "benchmarks/unseen/protocol-p1.md").unlink()
    with pytest.raises(ValueError, match="protocol"):
        f.run(root, used_report=used())
    assert not (root / "benchmarks/unseen/pool-p1.toml").exists()


def test_drops_flow_into_freeze_counts_and_private_manifest(tmp_path):
    root, draft, rows = draft_pair(tmp_path)
    hidden = {rows[i]["repository"] for i in (1, 2)}
    from test_unseen_bisect import staged

    b.run(root, draft, guard_runner=lambda root: int(any(r["repository"] in hidden for r in staged(root))))
    directory = root / "benchmarks/unseen"
    (directory / "protocol-p1.md").write_bytes(Path("benchmarks/unseen/protocol-p1.md").read_bytes())
    record = f.run(root, used_report=used())
    assert record["dropped_count"] == 2
    assert record["label_check_counts"] == {"confirmed": 3, "refactor": 2, "unclear": 2, "unchecked": 0}
    assert len(tomllib.loads((directory / "pool-p1.toml").read_text())["repository"]) == 7
    assert len(tomllib.loads((directory / "private/pool-p1.toml").read_text())["repository"]) == 3


def test_changed_private_labels_invalidate_guard_receipt(tmp_path):
    root, _ = prepared(tmp_path)
    path = root / "benchmarks/unseen/private/draft-p1.toml"
    before = path.read_text()
    after = before.replace('"label_check" = "refactor"', '"label_check" = "confirmed"', 1)
    assert before != after
    path.write_text(after)
    with pytest.raises(ValueError, match="guard_receipt"):
        f.run(root, used_report=used())


def test_utf8_digest_matches_guard_with_non_ascii_metadata(tmp_path, monkeypatch):
    root, draft, _ = draft_pair(tmp_path)
    data = tomllib.loads(draft.read_text())
    data["repository"][0]["license_path"] = "licence-ä.txt"
    draft.write_text(d.manifest(data["repository"], 19))
    b.run(root, draft, guard_runner=lambda root: 0)
    (root / "benchmarks/unseen/protocol-p1.md").write_bytes(Path("benchmarks/unseen/protocol-p1.md").read_bytes())
    f.run(root, used_report=used())
    guard = importlib.import_module("test_independent_population")
    monkeypatch.setattr(guard, "ROOT", root)
    guard.test_frozen_pool_manifest_digest()


def test_freeze_cli_redacts_failure_and_reports_only_record(tmp_path, capsys):
    root, rows = prepared(tmp_path)
    report = tmp_path / "used.json"
    report.write_text(json.dumps(used()))
    assert f.main(["--root", str(root), "--used-report", str(report)]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["guard_result"] == 0 and output.err == ""
    assert all(r["repository"] not in output.out for r in rows)
    report.write_text(rows[0]["url"])
    assert f.main(["--root", str(root), "--used-report", str(report)]) == 1
    assert capsys.readouterr() == ('{"status": "freeze_refused"}\n', "")


@pytest.mark.parametrize("slices", [1, 4])
def test_hundred_repository_draft_bisects_and_freezes(tmp_path, slices):
    root, draft, rows = draft_pair(tmp_path, count=100, slices=slices)
    from test_unseen_bisect import staged

    seen = []

    def guard(root):
        current = staged(root)
        seen.append(len(current))
        return 0

    receipt = b.run(root, draft, guard_runner=guard)
    assert receipt["input_count"] == 100 and receipt["dropped_count"] == 0
    assert 100 in seen and staged(root) == rows
    directory = root / "benchmarks/unseen"
    (directory / "protocol-p1.md").write_bytes(Path("benchmarks/unseen/protocol-p1.md").read_bytes())
    record = f.run(root, used_report=used())
    public = tomllib.loads((directory / "pool-p1.toml").read_text())
    private = tomllib.loads((directory / "private/pool-p1.toml").read_text())
    assert len(public["repository"]) == 100 and len(private["repository"]) == 50
    assert {row["slice"] for row in public["repository"]} == set(range(1, slices + 1))
    assert record["freeze_digest"] == hashlib.sha256(d.canonical(public)).hexdigest()
    assert sum(record["label_check_counts"].values()) == 100
    assert f.run(root, used_report=used()) == record
