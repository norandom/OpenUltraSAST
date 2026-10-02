"""The plane's memory store (harnessx-removal Req 6.1/6.4, design §4): one contract over every backend, the S3
bucket verification (versioning, the ``runs/`` expiry rule, S3 Select; no fallback) on a fake object client, backend
selection, fact reuse by ``seed``, disk refusal."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from openultrasast.plane import memory, reconciler
from openultrasast.plane.memory import (
    MINIO_KEYS,
    ExpiryRule,
    FileStore,
    MemoryStore,
    MemoryStoreError,
    MinioStore,
    SdkClient,
    memory_key,
    minio_settings,
    open_store,
    row_id,
    seed,
    where_sql,
)
from openultrasast.plane.tasks.repo_facts import _digest

PIN = "0123456789abcdef0123456789abcdef01234567"
OTHER_PIN = "fedcba9876543210fedcba9876543210fedcba98"
IMAGE = "sha256:" + "a" * 64
FACTS = json.dumps({"callers": {"a.py::run": []}, "counts": {"files": 1}, "files": {"a.py": {"functions": ["run"]}}}).encode()
MINIO_SKIP = (
    "MinIO/RustFS contract tests need OUSAST_MEMORY_TEST_MINIO=1 plus MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY "
    "and a bucket (OUSAST_MEMORY_TEST_BUCKET, else MINIO_BUCKET) exported (optional: MINIO_SECURE, MINIO_REGION) and the "
    "minio extra installed; the admin configures that bucket, the tests never do"
)


def row(kind: str, subject: str, *, pin: str = PIN, run: str = "r1", repo: str = "https://github.com/o/r", **fields: Any) -> dict[str, Any]:
    task = "c-remember"
    base = {"id": row_id(kind, run, task, subject), "kind": kind, "repo": memory.repo_key(repo), "pin": pin, "run": run, "task": task}
    return {**base, "population": "population-v2", "split": "validation", "image": IMAGE, **fields}


def verdict(candidate: str, final: str, **fields: Any) -> dict[str, Any]:
    return row("verdict", candidate, candidate=candidate, family="injection", final=final, tiebreak=False, **fields)


# The admin's rule for the prefixes these tests open stores under ("" and "p").
RUNS_RULES = [ExpiryRule("ousast-runs-expiry", "runs/", 30, True), ExpiryRule("ousast-runs-expiry-p", "p/runs/", 30, True)]


class FakeObjects:
    """An in-memory :class:`memory.ObjectClient`: versions per write, tags per object; ``select`` works, raises or
    answers wrongly, evaluating the equality clauses :func:`where_sql` writes. The bucket is configured as the admin
    does it unless ``versioning``/``rules`` say otherwise (``"denied"``: the read is refused)."""

    def __init__(self, select: str = "works", versioning: str = "Enabled", rules: list[ExpiryRule] | str | None = None) -> None:
        self.mode, self.objects, self.versions = select, {}, {}
        self.status, self.rules, self.tags_denied = versioning, RUNS_RULES if rules is None else rules, False
        self.selects: list[str] = []
        self.gets: list[str] = []
        self.calls: list[tuple[Any, ...]] = []

    def get(self, key: str) -> tuple[bytes, str | None] | None:
        self.gets.append(key)
        found = self.objects.get(key)
        return None if found is None else (found[0], f"v{self.versions[key]}")

    def put(self, key: str, data: bytes, labels: dict[str, str]) -> None:
        self.versions[key] = self.versions.get(key, 0) + 1
        self.objects[key] = (data, dict(labels))

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    def keys(self, prefix: str) -> list[str]:
        return sorted(k for k in self.objects if k.startswith(prefix))

    def tags(self, key: str) -> dict[str, str]:
        if self.tags_denied:
            raise PermissionError("Access Denied")
        return dict(self.objects[key][1])

    def version(self, key: str) -> str | None:
        return f"v{self.versions[key]}" if key in self.objects else None

    def select(self, key: str, expression: str) -> bytes:
        self.selects.append(expression)
        if self.mode == "raises":
            raise RuntimeError("NotImplemented: SelectObjectContent is not supported")
        if self.mode == "wrong":
            return b""
        if self.mode == "unbound":  # RustFS: a field absent from the object's leading rows
            raise type("S3Error", (Exception,), {"code": "EvaluatorBindingDoesNotExist"})("A column name ... does not exist")
        clauses = re.findall(r"s\.\"(\w+)\" = ('(?:[^']|'')*'|true|false|-?[\d.]+)", expression)
        want = {n: v[1:-1].replace("''", "'") if v.startswith("'") else json.loads(v) for n, v in clauses}
        rows = [json.loads(line) for line in self.objects[key][0].splitlines() if line.strip()]
        return b"".join(json.dumps(r).encode() + b"\n" for r in rows if all(r.get(k) == v for k, v in want.items()))

    def presign(self, method: str, key: str, expires: timedelta) -> str:
        return f"https://minio.test/{key}?method={method}&X-Amz-Expires={int(expires.total_seconds())}"

    def versioning(self) -> str:
        if self.status == "denied":
            raise PermissionError("Access Denied")
        return self.status

    def lifecycle(self) -> list[ExpiryRule]:
        if self.rules == "denied":
            raise PermissionError("Access Denied")
        return list(self.rules)


@pytest.fixture(autouse=True)
def fresh_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(memory, "_VERIFIED", set())


def _real_minio() -> Iterator[MemoryStore]:
    if os.environ.get("OUSAST_MEMORY_TEST_MINIO") != "1" or any(not os.environ.get(k) for k in MINIO_KEYS):
        pytest.skip(MINIO_SKIP)
    pytest.importorskip("minio", reason=MINIO_SKIP)
    bucket = os.environ.get("OUSAST_MEMORY_TEST_BUCKET") or os.environ.get("MINIO_BUCKET")
    if not bucket:
        pytest.skip(MINIO_SKIP)
    client = SdkClient(bucket=bucket, **minio_settings(os.environ))
    MinioStore(client, bucket)  # verifies the admin's setup at the bucket root; the tests never configure the bucket
    # The contract rows go under a fresh prefix so every test starts empty; the admin's expiry rule covers the root's
    # runs/, not this prefix's, so the prefixed store counts as verified by the root's check above.
    prefix = f"contract-{uuid.uuid4().hex[:12]}"
    memory._VERIFIED.add(f"minio://{bucket}/{prefix}")
    store = MinioStore(client, bucket, prefix)
    yield store
    for key in client.keys(store.prefix + "/"):
        client.delete(key)


@pytest.fixture(params=["file", "fake-minio", "minio"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryStore]:
    if request.param == "file":
        yield FileStore(tmp_path / "memory")
    elif request.param == "minio":
        yield from _real_minio()
    else:
        yield MinioStore(FakeObjects(), "bucket", "p")


# --- the contract --------------------------------------------------------------------------------------------------


def test_ingest_is_idempotent_by_the_index(store: MemoryStore) -> None:
    rows = [verdict("a.py::run", "agreed"), verdict("a.py::other", "rejected")]
    first = store.ingest_rows("r1", "c-remember", rows, FACTS)
    again = store.ingest_rows("r1", "c-remember", rows, FACTS)
    assert (first.skipped, again.skipped, first.kinds) == (False, True, {"verdict": 2})
    assert [(e["run"], e["task"], e["rows"]) for e in store.index()] == [("r1", "c-remember", 2)]
    assert len(store.rows(kind="verdict")) == 2


def test_identical_facts_are_stored_once_and_read_back_by_content(store: MemoryStore) -> None:
    sha = hashlib.sha256(FACTS).hexdigest()
    store.ingest_rows("r1", "c-remember", [row("facts", sha, sha256=sha)], FACTS)
    store.ingest_rows("r2", "c-remember", [row("facts", sha, run="r2", sha256=sha)], FACTS)
    assert store._keys("facts/") == [f"facts/{sha}.json"]
    assert store.get_facts(sha) == FACTS and store.get_facts("0" * 64) is None


def test_rows_filter_by_repo_pin_kind_and_where_with_their_object_version(store: MemoryStore) -> None:
    store.put_rows([
        verdict("a.py::run", "agreed"), verdict("a.py::x", "disputed"), verdict("b.py::y", "agreed", pin=OTHER_PIN),
        verdict("c.py::z", "agreed", repo="https://github.com/o/other.git"), row("unit_cost", "a:a.py", **{"pass": "a", "usd": 0.5}),
    ])  # fmt: skip
    assert len(store.rows()) == 5
    assert {r.row["candidate"] for r in store.rows("https://github.com/o/r", kind="verdict")} == {"a.py::run", "a.py::x", "b.py::y"}
    assert [r.row["candidate"] for r in store.rows("github.com/o/r", PIN, "verdict", {"final": "disputed"})] == ["a.py::x"]
    assert [r.row["kind"] for r in store.rows(where={"usd": 0.5})] == ["unit_cost"]
    assert store.rows(where={"final": "no such"}) == []
    record = store.rows("github.com/o/r", PIN, "verdict", {"candidate": "a.py::run"})[0]
    assert record.key == f"repos/github.com__o__r/{PIN}.jsonl" and record.version
    store.put_row(verdict("a.py::new", "agreed"))
    later = store.rows("github.com/o/r", PIN, "verdict", {"candidate": "a.py::run"})[0]
    assert later.row == record.row and later.version != record.version, "a rewrite is a new version: provenance pins the old"


def test_a_repeated_id_replaces_the_stored_row(store: MemoryStore) -> None:
    store.put_row(verdict("a.py::run", "disputed"))
    store.put_row(verdict("a.py::run", "agreed"))
    assert [r.row["final"] for r in store.rows(kind="verdict")] == ["agreed"]


def test_a_malformed_row_fails_naming_it_and_writes_nothing(store: MemoryStore) -> None:
    bad = {**verdict("a.py::run", "agreed"), "pin": "main"}
    with pytest.raises(MemoryStoreError, match=r"r1/c-remember row 2: pin 'main'"):
        store.ingest_rows("r1", "c-remember", [verdict("a.py::ok", "agreed"), bad])
    with pytest.raises(MemoryStoreError, match="unknown kind"):
        store.put_row({**verdict("a.py::run", "agreed"), "kind": "vibes"})
    assert store.index() == [] and store.rows() == []


def test_facts_that_no_longer_match_their_hash_are_dropped(store: MemoryStore, caplog: pytest.LogCaptureFixture) -> None:
    sha = store.put_facts(FACTS)
    store._put(f"facts/{sha}.json", b"tampered")
    with caplog.at_level(logging.WARNING, logger="openultrasast.plane.memory"):
        assert store.get_facts(sha) is None
    assert "no longer matches" in caplog.text and store._get(f"facts/{sha}.json") is None


def test_presigned_urls_name_the_object(store: MemoryStore) -> None:
    for url in (store.presign_put("runs/r1/x/units.jsonl"), store.presign_get("runs/r1/x/units.jsonl")):
        assert url.startswith(("file://", "http://", "https://")) and "runs/r1/x/units.jsonl" in url


# --- MinIO specifics on the fake client ----------------------------------------------------------------------------


def _filled(client: FakeObjects) -> MinioStore:
    store = MinioStore(client, "bucket")
    store.put_rows([verdict("a.py::run", "agreed"), verdict("a.py::x", "disputed"), row("unit_cost", "a:a.py", **{"pass": "a"})])
    return store


def test_select_is_pushed_down_when_the_probe_answers(caplog: pytest.LogCaptureFixture) -> None:
    client = FakeObjects("works")
    store = _filled(client)
    with caplog.at_level(logging.WARNING, logger="openultrasast.plane.memory"):
        got = [r.row["candidate"] for r in store.rows(kind="verdict", where={"final": "disputed"})]
    assert got == ["a.py::x"] and "locally" not in caplog.text
    assert client.selects[0] == 'SELECT * FROM S3Object s WHERE s."probe" = 1'
    assert client.selects[1:] == ["SELECT * FROM S3Object s WHERE s.\"final\" = 'disputed' AND s.\"kind\" = 'verdict'"]


@pytest.mark.parametrize("mode", ["raises", "wrong"])
def test_a_server_without_select_is_refused_at_open(mode: str) -> None:
    with pytest.raises(MemoryStoreError, match=r"S3 Select .* does not answer on _probe/select.jsonl .*no local fallback") as caught:
        MinioStore(FakeObjects(mode), "bucket")
    assert "versioning" not in str(caught.value) and "lifecycle" not in str(caught.value)


def test_a_failing_select_on_one_object_raises_instead_of_filtering_locally() -> None:
    client = FakeObjects("works")
    store = _filled(client)
    client.mode = "raises"
    with pytest.raises(MemoryStoreError, match=r"S3 Select on repos/github.com__o__r/\w+\.jsonl failed .*no local fallback"):
        store.rows(where={"final": "agreed"})


def test_an_unbound_field_on_rustfs_raises_naming_the_schema_inference_never_returning_no_rows() -> None:
    client = FakeObjects("works")
    store = _filled(client)
    client.mode = "unbound"
    with pytest.raises(MemoryStoreError, match=r"EvaluatorBindingDoesNotExist.*\['usd'\] is absent from the object's leading rows"):
        store.rows(where={"usd": 0.5})


# --- bucket verification: the admin configures once, the store only reads ------------------------------------------


def test_verify_bucket_passes_on_the_admin_setup_and_writes_only_its_probe() -> None:
    client = FakeObjects()
    store = MinioStore(client, "bucket", "p")
    assert sorted(client.objects) == ["p/_probe/select.jsonl"] and not hasattr(client, "enable_versioning")
    store.verify_bucket()
    MinioStore(client, "bucket", "p")
    assert len(client.selects) == 2, "opening a verified store again does not re-verify in the same process"


@pytest.mark.parametrize("status", ["Suspended", "Off"])
def test_verify_bucket_refuses_versioning_off_naming_the_admin_command(status: str) -> None:
    with pytest.raises(MemoryStoreError, match=rf"versioning is {status}, it must be Enabled") as caught:
        MinioStore(FakeObjects(versioning=status), "sast-memory")
    message = str(caught.value)
    assert "never configures its bucket" in message and "lifecycle" not in message and "Select" not in message
    assert 'aws s3api put-bucket-versioning --endpoint-url "$MINIO_ENDPOINT" --bucket sast-memory' in message


@pytest.mark.parametrize(
    "rules",
    [
        [],
        [ExpiryRule("other", "logs/", 7, True)],
        [ExpiryRule("ousast-runs-expiry", "runs/", 30, False)],
        [ExpiryRule("ousast-runs-expiry", "runs/", 30, True, tagged=True)],
        [ExpiryRule("ousast-runs-expiry", "runs/", None, True, expires=False)],
    ],
    ids=["none", "other-prefix", "disabled", "tag-narrowed", "no-expiration"],
)
def test_verify_bucket_refuses_a_missing_runs_expiry_rule(rules: list[ExpiryRule]) -> None:
    with pytest.raises(MemoryStoreError, match=r"no enabled lifecycle rule expires runs/") as caught:
        MinioStore(FakeObjects(rules=rules), "sast-memory")
    assert "put-bucket-lifecycle-configuration" in str(caught.value)
    assert '"Filter":{"Prefix":"runs/"},"Expiration":{"Days":30}' in str(caught.value)


def test_verify_bucket_names_the_prefixed_runs_and_refuses_a_rule_expiring_the_whole_store() -> None:
    with pytest.raises(MemoryStoreError, match=r"no enabled lifecycle rule expires mem/runs/"):
        MinioStore(FakeObjects(rules=[ExpiryRule("r", "runs/", 30, True)]), "bucket", "mem")
    wide = [ExpiryRule("everything", "", 30, True), ExpiryRule("ousast-runs-expiry", "runs/", 30, True)]
    with pytest.raises(MemoryStoreError, match=r"lifecycle rule\(s\) everything expire the whole store"):
        MinioStore(FakeObjects(rules=wide), "bucket")
    MinioStore(FakeObjects(rules=[ExpiryRule("r", "mem/runs/", 14, True)]), "bucket", "mem")


def test_verify_bucket_names_every_missing_piece_and_the_permissions_to_read_them() -> None:
    client = FakeObjects("raises", versioning="denied", rules="denied")
    client.tags_denied = True
    with pytest.raises(MemoryStoreError) as caught:
        MinioStore(client, "sast-memory")
    message = str(caught.value)
    assert "versioning cannot be read (PermissionError: Access Denied)" in message and "s3:GetBucketVersioning" in message
    assert "lifecycle configuration cannot be read" in message and "s3:GetLifecycleConfiguration" in message
    assert "object tags cannot be read" in message and "s3:GetObjectTagging" in message
    assert "S3 Select" in message and message.count("\n  - ") == 4


def test_row_objects_carry_tags_and_a_kind_tag_skips_objects_without_that_kind() -> None:
    client = FakeObjects("works")
    store = MinioStore(client, "bucket")
    store.put_rows([verdict("a.py::run", "agreed"), row("unit_cost", "a:b.py", pin=OTHER_PIN, **{"pass": "a"})])
    tags = client.tags(f"repos/github.com__o__r/{PIN}.jsonl")
    assert tags == {"repo": "github.com/o/r", "pin": PIN, "kind": "verdict", "family": "injection", "run": "r1",
                    "population": "population-v2", "split": "validation"}  # fmt: skip
    client.gets.clear()
    assert [r.row["kind"] for r in store.rows(kind="unit_cost")] == ["unit_cost"]
    assert f"repos/github.com__o__r/{PIN}.jsonl" not in client.gets, "an object tagged without the kind is not read"


def test_where_sql_quotes_values_and_refuses_odd_fields() -> None:
    assert where_sql({}) == "SELECT * FROM S3Object s"
    assert where_sql({"a": "it's", "b": True, "c": None, "d": 2}) == (
        'SELECT * FROM S3Object s WHERE s."a" = \'it\'\'s\' AND s."b" = true AND s."c" IS NULL AND s."d" = 2'
    )
    with pytest.raises(ValueError):
        where_sql({"a; drop": 1})


# --- selection and settings ----------------------------------------------------------------------------------------


def test_open_store_selects_the_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OUSAST_RESULTS", str(tmp_path))
    monkeypatch.delenv("OUSAST_MEMORY", raising=False)
    default = open_store()
    assert isinstance(default, FileStore) and default.root == tmp_path / "plane" / "memory"
    chosen = open_store(environ={"OUSAST_MEMORY": f"file://{tmp_path}/m"})
    assert isinstance(chosen, FileStore) and chosen.root == tmp_path / "m"
    with pytest.raises(MemoryStoreError, match="file:///<path> or minio://<bucket>"):
        open_store("s3://bucket")


def test_minio_settings_name_missing_keys_never_values() -> None:
    with pytest.raises(MemoryStoreError, match="MINIO_ACCESS_KEY, MINIO_SECRET_KEY") as caught:
        open_store(environ={"OUSAST_MEMORY": "minio://bucket", "MINIO_ENDPOINT": "minio.example:9000"})
    assert "minio.example" not in str(caught.value)
    env = {"MINIO_ENDPOINT": "h:9000", "MINIO_ACCESS_KEY": "ak", "MINIO_SECRET_KEY": "sk-value", "MINIO_SECURE": "false"}
    assert minio_settings(env) == {"endpoint": "h:9000", "access_key": "ak", "secret_key": "sk-value", "secure": False}
    assert minio_settings({**env, "MINIO_SECURE": ""})["secure"] is True


def test_minio_without_the_sdk_names_the_extra() -> None:
    try:
        import minio  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("the minio SDK is installed here")
    env = {"OUSAST_MEMORY": "minio://bucket", "MINIO_ENDPOINT": "h:9000", "MINIO_ACCESS_KEY": "ak", "MINIO_SECRET_KEY": "secret-xyz"}
    with pytest.raises(MemoryStoreError, match=r"install openultrasast\[minio\]") as caught:
        open_store(environ=env)
    assert "secret-xyz" not in str(caught.value)


# --- disk refusal (FileStore) --------------------------------------------------------------------------------------


def test_file_store_refuses_below_one_gib_free_naming_its_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "memory"
    monkeypatch.setattr(memory.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(100 << 30, 99 << 30, 512 << 20))  # type: ignore[attr-defined]
    with pytest.raises(MemoryStoreError, match=rf"refusing to write the memory store at {re.escape(str(root))}: 0.50 GiB free"):
        FileStore(root).ingest_rows("r1", "c-remember", [verdict("a.py::run", "agreed")], FACTS)
    assert not root.exists()


# --- fact reuse ----------------------------------------------------------------------------------------------------


def _plane(root: Path, key: str, run: str = "r2") -> Path:
    (root / "runs").mkdir(parents=True)
    (root / "tasks").mkdir()
    (root / "tasks" / "t.yaml").write_text(
        "apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: repo-facts-c\n  annotations:\n"
        f"    {memory.MEMORY_KEY_ANNOTATION}: '{key}'\nspec:\n  image: reg/img@{IMAGE}\n  command: [repo-facts]\n"
    )
    (root / "runs" / f"{run}.yaml").write_text(
        f"apiVersion: openultrasast.io/v1alpha1\nkind: Run\nmetadata:\n  name: {run}\nspec:\n  tasks:\n"
        "  - name: c-facts\n    task: repo-facts-c\n    outputs: [facts.json]\n"
    )
    return root / "runs" / f"{run}.yaml"


@pytest.fixture
def stored(tmp_path: Path) -> FileStore:
    store = FileStore(tmp_path / "memory")
    sha = hashlib.sha256(FACTS).hexdigest()
    facts = row("facts", sha, sha256=sha, candidates_digest=_digest(["run"]), files=1)
    store.ingest_rows("r1", "c-remember", [facts], FACTS)
    return store


def test_seed_reuses_facts_for_an_unchanged_key_and_marks_the_task_done(stored: FileStore, tmp_path: Path) -> None:
    manifest = _plane(tmp_path / "plane", memory_key("https://github.com/o/r", PIN, _digest(["run"]), f"reg/img@{IMAGE}"))
    results = tmp_path / "results"
    assert seed(manifest, stored, results_root=results) == ["c-facts"]
    base = results / "r2"
    assert (base / "c-facts" / "facts.json").read_bytes() == FACTS
    summary = json.loads((base / "c-facts" / "summary.json").read_text())
    reused = {"sha256": hashlib.sha256(FACTS).hexdigest(), "from_run": "r1", "image": IMAGE}
    assert reconciler.outcome_of(summary) == ("done", "") and summary["reused"] == reused
    state = json.loads((base / "state.json").read_text())
    assert state["tasks"]["c-facts"]["status"] == "done" and state["tasks"]["c-facts"]["reused"] == reused
    assert not (base / "lock").exists()
    assert seed(manifest, stored, results_root=results) == [], "a seeded task is never seeded again"


@pytest.mark.parametrize(
    "change", [{"pin": OTHER_PIN}, {"candidates": _digest(["run", "helper"])}, {"image": "reg/img@sha256:" + "b" * 64}]
)
def test_seed_recomputes_on_a_changed_pin_candidate_set_or_image(stored: FileStore, tmp_path: Path, change: dict[str, str]) -> None:
    key = {"repo": "https://github.com/o/r", "pin": PIN, "candidates": _digest(["run"]), "image": f"reg/img@{IMAGE}", **change}
    manifest = _plane(tmp_path / "plane", memory_key(**key))
    assert seed(manifest, stored, results_root=tmp_path / "results") == []
    assert not (tmp_path / "results" / "r2").exists()


def test_seed_never_overwrites_a_task_directory_and_drops_tampered_facts(stored: FileStore, tmp_path: Path) -> None:
    manifest = _plane(tmp_path / "plane", memory_key("https://github.com/o/r", PIN, _digest(["run"]), f"reg/img@{IMAGE}"))
    results = tmp_path / "results"
    (results / "r2" / "c-facts").mkdir(parents=True)
    assert seed(manifest, stored, results_root=results) == []
    (results / "r2" / "c-facts").rmdir()
    sha = hashlib.sha256(FACTS).hexdigest()
    (stored.root / "facts" / f"{sha}.json").write_bytes(b"changed underneath")
    assert seed(manifest, stored, results_root=results) == []
    assert not (stored.root / "facts" / f"{sha}.json").exists()
