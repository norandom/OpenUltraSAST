"""plane-on-kubernetes task 2.1 (Req 3.1, 2.1): ``Delivery`` against an S3-shaped fake -- presigned URLs in the start
body, expiry, polling, extraction with the receiver's member checks, declared-only re-put, state seeding, and no URL
in any log line."""

from __future__ import annotations

import io
import json
import logging
import tarfile
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from plane_fake_store import HttpObjectStore

from openultrasast.plane.delivery import GRACE_SECONDS, Delivery, DeliveryError, declared, expiry, input_var


@pytest.fixture
def store() -> Iterator[HttpObjectStore]:
    fake = HttpObjectStore()
    try:
        yield fake
    finally:
        fake.close()


def tar_of(files: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tar.addfile(info)
    return buffer.getvalue()


def put_via_url(url: str, data: bytes) -> int:
    request = urllib.request.Request(url, data=data, method="PUT", headers={"Content-Type": "application/x-tar"})
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - the fake's local URL
        return int(response.status)


def test_the_start_body_names_exactly_the_tar_and_the_declared_inputs(store: HttpObjectStore, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUSAST_TASK_TIMEOUT", "100")
    delivery = Delivery(store, "run-1", tmp_path)
    body = delivery.body("verify", {"facts": "repo-facts/facts.json", "pass a": "va/units.jsonl"})
    assert set(body) == {"put", "inputs"}
    assert body["put"].startswith(f"http://localhost:{store.server.server_address[1]}/fake-bucket/runs/run-1/verify/output.tar?")
    assert set(body["inputs"]) == {"FACTS", "PASS_A"} and input_var("pass a") == "PASS_A"
    assert "/runs/run-1/repo-facts/facts.json?" in body["inputs"]["FACTS"] and "/runs/run-1/va/units.jsonl?" in body["inputs"]["PASS_A"]
    assert {m for m, _, _ in store.presigned} == {"PUT", "GET"}
    assert {e for _, _, e in store.presigned} == {100 + GRACE_SECONDS}, "expiry = OUSAST_TASK_TIMEOUT + 600"
    assert expiry({"OUSAST_TASK_TIMEOUT": "7200"}).total_seconds() == 7800 and expiry({}).total_seconds() == 7800
    assert delivery.host == "localhost", "the hostname the egress policy must allow"
    with pytest.raises(DeliveryError, match="not <producer>/<artifact>"):
        delivery.input_urls({"x": "no-slash"})


def test_delivered_polls_the_store_and_collect_extracts_republishes_and_marks_done(
    store: HttpObjectStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    delivery = Delivery(store, "r", tmp_path / "r")
    assert delivery.delivered("facts") is False
    summary = {"status": "done", "units_done": 1, "units_total": 1}
    tar = tar_of({"facts.json": b'{"a": 1}', "summary.json": json.dumps(summary).encode(), "scratch/notes.txt": b"not declared"})
    assert put_via_url(delivery.put_url("facts"), tar) == 200, "the runner's PUT to the presigned URL"
    assert delivery.delivered("facts") is True
    got, size = delivery.collect("facts", ["facts.json", "summary.json", "missing.json"])
    assert got == summary and size == len(tar)
    assert (tmp_path / "r" / "facts" / "facts.json").read_bytes() == b'{"a": 1}'
    assert (tmp_path / "r" / "facts" / "scratch" / "notes.txt").exists(), "extracted locally"
    assert store.objects["runs/r/facts/facts.json"] == b'{"a": 1}' and "runs/r/facts/summary.json" in store.objects
    assert "runs/r/facts/scratch/notes.txt" not in store.objects and "runs/r/facts/missing.json" not in store.objects, "declared only"
    done = json.loads(store.objects["runs/r/facts/done.json"])
    assert (
        done["status"] == "done"
        and done["bytes"] == len(tar)
        and done["files"] == 3
        and done["published"] == ["facts.json", "summary.json"]
    )
    # a consumer's presigned GET names one artifact and fetches it
    urls = delivery.input_urls({"facts": "facts/facts.json"})
    with urllib.request.urlopen(urls["FACTS"], timeout=10) as response:  # noqa: S310
        assert response.read() == b'{"a": 1}'
    assert "X-Amz" not in caplog.text and "fake-bucket" not in caplog.text, "URLs never appear in logs"
    delivery.reset("facts")  # the next attempt must not complete on this attempt's tar
    assert delivery.delivered("facts") is False and "runs/r/facts/done.json" not in store.objects
    assert "runs/r/facts/facts.json" in store.objects, "a re-put output stays for its consumers until it is re-published"


@pytest.mark.parametrize("bad", ["../escape.json", "/abs.json"])
def test_a_tar_member_that_escapes_is_rejected_and_nothing_is_written(store: HttpObjectStore, tmp_path: Path, bad: str) -> None:
    delivery = Delivery(store, "r", tmp_path / "r")
    store._put(delivery.key("t", "output.tar"), tar_of({bad: b"{}", "summary.json": b"{}"}))
    with pytest.raises(DeliveryError, match="rejected member"):
        delivery.collect("t", ["summary.json"])
    assert not (tmp_path / "r" / "t").exists() and not (tmp_path / "escape.json").exists()
    assert "runs/r/t/done.json" not in store.objects and "runs/r/t/summary.json" not in store.objects


def test_a_symlink_member_and_a_non_tar_are_rejected(store: HttpObjectStore, tmp_path: Path) -> None:
    delivery = Delivery(store, "r", tmp_path / "r")
    store._put(delivery.key("t", "output.tar"), tar_of({"summary.json": b"{}"}, symlink="link"))
    with pytest.raises(DeliveryError, match="rejected member link"):
        delivery.collect("t", ["summary.json"])
    store._put(delivery.key("t", "output.tar"), b"not a tar at all")
    with pytest.raises(DeliveryError, match="bad tar"):
        delivery.collect("t", ["summary.json"])
    with pytest.raises(DeliveryError, match="not in the store"):
        delivery.collect("never", [])


def test_state_is_mirrored_and_seeds_a_rerun_elsewhere(store: HttpObjectStore, tmp_path: Path) -> None:
    first = Delivery(store, "r", tmp_path / "machine-a")
    assert first.load_state() is None
    first.save_state({"run": "r", "tasks": {"facts": {"status": "done"}}})
    second = Delivery(store, "r", tmp_path / "machine-b")  # another results root, the same store
    assert second.load_state() == {"run": "r", "tasks": {"facts": {"status": "done"}}}
    store._put(second.key("state.json"), b"not json")
    assert second.load_state() is None


def test_put_input_stores_a_file_no_task_produces(store: HttpObjectStore, tmp_path: Path) -> None:
    delivery = Delivery(store, "r", tmp_path / "r")
    source = tmp_path / "candidates.json"
    source.write_bytes(b"[1, 2, 3]")
    url = delivery.put_input("candidates.json", source)
    assert store.objects["runs/r/inputs/candidates.json"] == b"[1, 2, 3]"
    with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
        assert response.read() == b"[1, 2, 3]"


def test_declared_artifacts_are_outputs_plus_what_consumers_name(tmp_path: Path) -> None:
    """A consumer may declare a producer's summary.json (every task writes one) without the producer listing it."""
    from openultrasast.plane.manifests import load_manifests

    text = (
        "apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata: {name: t}\nspec: {command: [repo-facts]}\n---\n"
        "apiVersion: openultrasast.io/v1alpha1\nkind: Run\nmetadata: {name: r}\nspec:\n  tasks:\n"
        "    - {name: facts, task: t, outputs: [facts.json]}\n"
        "    - {name: verify, task: t, inputs: {facts: facts/facts.json, facts_summary: facts/summary.json}, outputs: [units.jsonl]}\n"
        "    - {name: agree, task: t, inputs: {pass: verify/units.jsonl, pass_summary: verify/summary.json}}\n"
    )
    (tmp_path / "run.yaml").write_text(text, encoding="utf-8")
    run = next(iter(load_manifests([tmp_path / "run.yaml"]).runs.values()))
    assert declared(run) == {"facts": ["facts.json", "summary.json"], "verify": ["units.jsonl", "summary.json"], "agree": []}


def test_publish_reputs_only_declared_files_under_the_task_directory(store: HttpObjectStore, tmp_path: Path) -> None:
    delivery = Delivery(store, "r", tmp_path / "r")
    (tmp_path / "r" / "seeded").mkdir(parents=True)
    (tmp_path / "r" / "seeded" / "facts.json").write_bytes(b"{}")
    (tmp_path / "r" / "secret.txt").write_bytes(b"outside")
    assert delivery.publish("seeded", ["facts.json", "../secret.txt", "absent.json"]) == ["facts.json"]
    assert set(store.objects) == {"runs/r/seeded/facts.json"}
