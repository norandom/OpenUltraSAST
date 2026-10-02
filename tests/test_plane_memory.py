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
    S3_KEYS,
    ExpiryRule,
    FileStore,
    MemoryStore,
    MemoryStoreError,
    S3Client,
    S3Store,
    memory_key,
    open_store,
    row_id,
    s3_settings,
    seed,
    where_sql,
)
from openultrasast.plane.tasks.repo_facts import _digest

PIN = "0123456789abcdef0123456789abcdef01234567"
OTHER_PIN = "fedcba9876543210fedcba9876543210fedcba98"
IMAGE = "sha256:" + "a" * 64
FACTS = json.dumps({"callers": {"a.py::run": []}, "counts": {"files": 1}, "files": {"a.py": {"functions": ["run"]}}}).encode()
S3_SKIP = (
    "real-server contract tests need OUSAST_MEMORY_TEST_S3=1 plus S3_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY "
    "and a bucket (OUSAST_MEMORY_TEST_BUCKET, else S3_BUCKET) exported (optional: S3_REGION, AWS_SESSION_TOKEN) and the "
    "s3 extra (boto3) installed; the admin configures that bucket, the tests never do"
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
        self.schema_rows = 2  # RustFS: a `where` field must be present in the object's leading rows, else it is unbound
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
        rows = [json.loads(line) for line in self.objects[key][0].splitlines() if line.strip()]
        for name in re.findall(r"s\.\"(\w+)\"", expression):
            if any(name not in r for r in rows[: self.schema_rows]):  # RustFS infers the schema from the leading rows
                raise type("S3Error", (Exception,), {"code": "EvaluatorBindingDoesNotExist"})(f"column {name} does not exist")
        leading = rows[: self.schema_rows]
        typeless = {k for r in leading for k, v in r.items() if v is None and all(x.get(k) is None for x in leading)}
        if any(r.get(k) is not None for r in rows[self.schema_rows :] for k in typeless):  # null-typed, set later
            raise type("SelectFailure", (Exception,), {})("JSONParsingError: An error occurred while parsing the JSON file")
        clauses = re.findall(r"s\.\"(\w+)\" = ('(?:[^']|'')*'|true|false|-?[\d.]+)", expression)
        want = {n: v[1:-1].replace("''", "'") if v.startswith("'") else json.loads(v) for n, v in clauses}
        return b"".join(json.dumps(r).encode() + b"\n" for r in rows if all(r.get(k) == v for k, v in want.items()))

    def presign(self, method: str, key: str, expires: timedelta) -> str:
        return f"https://s3.test/{key}?method={method}&X-Amz-Expires={int(expires.total_seconds())}"

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


def _real_s3() -> Iterator[MemoryStore]:
    if os.environ.get("OUSAST_MEMORY_TEST_S3") != "1" or any(not os.environ.get(k) for k in S3_KEYS):
        pytest.skip(S3_SKIP)
    pytest.importorskip("boto3", reason=S3_SKIP)
    bucket = os.environ.get("OUSAST_MEMORY_TEST_BUCKET") or os.environ.get("S3_BUCKET")
    if not bucket:
        pytest.skip(S3_SKIP)
    client = S3Client(bucket=bucket, **s3_settings(os.environ))
    S3Store(client, bucket)  # verifies the admin's setup at the bucket root; the tests never configure the bucket
    # The contract rows go under a fresh prefix so every test starts empty; the admin's expiry rule covers the root's
    # runs/, not this prefix's, so the prefixed store counts as verified by the root's check above.
    prefix = f"contract-{uuid.uuid4().hex[:12]}"
    memory._VERIFIED.add(f"s3://{bucket}/{prefix}")
    store = S3Store(client, bucket, prefix)
    yield store
    client.purge(store.prefix + "/")  # every version and delete marker: the bucket keeps nothing of the test


@pytest.fixture(params=["file", "fake-s3-select", "s3"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryStore]:
    if request.param == "file":
        yield FileStore(tmp_path / "memory")
    elif request.param == "s3":
        yield from _real_s3()
    else:
        yield S3Store(FakeObjects(), "bucket", "p")


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
    assert [r.row["candidate"] for r in store.rows(where={"final": "disputed"})] == ["a.py::x"]
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


# --- the fixed schema: every row carries every queryable field ------------------------------------------------------


def _late(field_kind: str = "example", n: int = 6) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """``n`` alert rows without any queryable field, and one ``field_kind`` row whose id sorts after them all (the
    object is written in id order), so a declared field appears only after the object's leading rows."""
    alerts = [row("alert", f"rule-{i}", rule=f"r{i}") for i in range(n)]
    return alerts, {**row(field_kind, "late", profile="static"), "id": "f" * 64}


def test_rows_written_without_optional_fields_gain_them_as_empty_strings(store: MemoryStore) -> None:
    store.put_rows([verdict("a.py::run", "agreed"), row("unit_cost", "a:a.py", **{"pass": "a", "usd": 0.5})])
    store.ingest_rows("r2", "c-remember", [row("alert", "rule-1", run="r2", rule="r1", profile=None)])
    rows = {r.row["kind"]: r.row for r in store.rows()}
    assert all(set(memory.QUERYABLE) <= set(r) for r in rows.values())
    assert rows["unit_cost"]["final"] == "" and rows["alert"]["candidate"] == "" and rows["alert"]["profile"] == "", "null too"
    assert rows["verdict"]["final"] == "agreed" and rows["verdict"]["candidate"] == "a.py::run", "present values stay"
    assert rows["unit_cost"]["usd"] == 0.5, "a field nobody queries is not touched"
    store.drop_rows("github.com/o/r", PIN, [rows["alert"]["id"]])
    assert all(set(memory.QUERYABLE) <= set(r.row) for r in store.rows())


def test_a_queryable_field_of_another_type_is_refused_on_write(store: MemoryStore) -> None:
    with pytest.raises(MemoryStoreError, match=r"queryable field 'final' must be a string, got int"):
        store.put_row(verdict("a.py::run", 1))  # type: ignore[arg-type]
    assert store.rows() == []


def test_a_declared_field_absent_from_the_leading_rows_is_queryable(store: MemoryStore) -> None:
    alerts, late = _late(n=5000)  # RustFS measured: a field first at row 5000 was unbound before the rule
    store.put_rows([*alerts, late])
    assert [r.row["id"] for r in store.rows(kind="example", where={"profile": "static"})] == [late["id"]]
    assert [r.row["id"] for r in store.rows(where={"profile": "static"})] == [late["id"]], "any kind: the union is written"
    assert store.rows(kind="verdict", where={"final": "agreed"}) == []
    assert len(store.rows(where={"run": "r1", "profile": ""})) == len(alerts), "'' is the empty value"


def test_the_fake_client_mimics_rustfs_and_the_normaliser_repairs_a_pre_rule_object() -> None:
    client = FakeObjects("works")
    store = S3Store(client, "bucket")
    alerts, late = _late()
    key = f"repos/github.com__o__r/{PIN}.jsonl"
    legacy = sorted([*alerts, late], key=lambda r: str(r["id"]))  # written before the rule: no queryable fields
    client.put(key, "".join(json.dumps(r) + "\n" for r in legacy).encode(), {})
    with pytest.raises(MemoryStoreError, match=r"EvaluatorBindingDoesNotExist.*\['kind', 'profile'\] is absent"):
        store.rows(kind="example", where={"profile": "static"})
    nulls = [{**r, "profile": None} for r in alerts] + [late]  # the schema rows hold null, a later row a string
    client.put(key, "".join(json.dumps(r) + "\n" for r in nulls).encode(), {})
    with pytest.raises(MemoryStoreError, match=r"JSONParsingError"):
        store.rows(kind="example", where={"run": "r1"})
    assert store.normalise() == {"objects": 1, "objects_rewritten": 1, "rows": 7, "rows_changed": 7,
                                 "fields_filled": 7 * len(memory.QUERYABLE) - 1}  # fmt: skip
    assert client.versions[key] == 3, "a rewrite is a new object version; versioning keeps the old"
    assert [r.row["id"] for r in store.rows(kind="example", where={"profile": "static"})] == [late["id"]]


def test_a_where_on_an_undeclared_field_an_unknown_kind_or_null_is_refused_before_any_read() -> None:
    client = FakeObjects("works")
    store = _filled(client)
    client.selects.clear()
    with pytest.raises(MemoryStoreError, match=r"\['profile'\] are not queryable for kind 'verdict'.*QUERY_FIELDS"):
        store.rows(kind="verdict", where={"profile": "static"})
    with pytest.raises(MemoryStoreError, match=r"\['usd'\] are not queryable for any kind"):
        store.rows(where={"usd": 0.5})
    with pytest.raises(MemoryStoreError, match="unknown kind 'vibes'"):
        store.rows(kind="vibes")
    with pytest.raises(MemoryStoreError, match=r"\['final'\] = null never matches"):
        store.rows(kind="verdict", where={"final": None})
    assert client.selects == []
    assert memory.QUERYABLE == ("candidate", "candidates_digest", "final", "profile")


@pytest.mark.parametrize("backend", ["file", "fake-s3-select"])
def test_the_normaliser_is_idempotent_and_keeps_every_value(backend: str, tmp_path: Path) -> None:
    store: MemoryStore = FileStore(tmp_path / "memory") if backend == "file" else S3Store(FakeObjects(), "bucket", "p")
    legacy = [verdict("a.py::run", "agreed"), row("unit_cost", "a:a.py", **{"pass": "a", "usd": 0.5, "final": None})]
    store._put(f"repos/github.com__o__r/{PIN}.jsonl", "".join(json.dumps(r) + "\n" for r in legacy).encode())
    current = memory.normalise_row(row("alert", "x", pin=OTHER_PIN))
    store._put(f"repos/github.com__o__r/{OTHER_PIN}.jsonl", (json.dumps(current) + "\n").encode())
    first = store.normalise()
    assert first == {"objects": 2, "objects_rewritten": 1, "rows": 3, "rows_changed": 2, "fields_filled": 2 + 4}
    assert store.normalise() == {**first, "objects_rewritten": 0, "rows_changed": 0, "fields_filled": 0}
    got = {r.row["kind"]: r.row for r in store.rows(repo="github.com/o/r", pin=PIN)}
    assert got["verdict"] == memory.normalise_row(legacy[0]) and got["unit_cost"]["usd"] == 0.5


def test_the_normaliser_names_a_queryable_field_of_another_type(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "memory")
    store._put(f"repos/github.com__o__r/{PIN}.jsonl", (json.dumps({**verdict("a.py::run", "agreed"), "candidate": 3}) + "\n").encode())
    with pytest.raises(MemoryStoreError, match=rf"repos/github.com__o__r/{PIN}.jsonl:1: queryable field 'candidate'"):
        store.normalise()


def test_the_memory_normalise_command_prints_its_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from openultrasast.cli import main

    store = FileStore(tmp_path / "memory")
    store._put(f"repos/github.com__o__r/{PIN}.jsonl", (json.dumps(verdict("a.py::run", "agreed")) + "\n").encode())
    url = f"file://{tmp_path / 'memory'}"
    assert main(["plane", "memory-normalise", "--store", url, "--dry-run"]) == 0
    assert 'would rewrite 1/1 objects; 1/1 rows filled 2 absent or null fields with ""' in capsys.readouterr().out
    assert main(["plane", "memory-normalise", "--store", url]) == 0
    assert main(["plane", "memory-normalise", "--store", url]) == 0
    assert "rewrote 0/1 objects; 0/1 rows filled 0 absent or null fields" in capsys.readouterr().out.splitlines()[-1]


# --- S3 specifics on the fake client ----------------------------------------------------------------------------


def _filled(client: FakeObjects) -> S3Store:
    store = S3Store(client, "bucket")
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
        S3Store(FakeObjects(mode), "bucket")
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
    with pytest.raises(MemoryStoreError, match=r"EvaluatorBindingDoesNotExist.*\['final'\] is absent from the object's leading rows"):
        store.rows(where={"final": "agreed"})


# --- bucket verification: the admin configures once, the store only reads ------------------------------------------


def test_verify_bucket_passes_on_the_admin_setup_and_writes_only_its_probe() -> None:
    client = FakeObjects()
    store = S3Store(client, "bucket", "p")
    assert sorted(client.objects) == ["p/_probe/select.jsonl"] and not hasattr(client, "enable_versioning")
    store.verify_bucket()
    S3Store(client, "bucket", "p")
    assert len(client.selects) == 2, "opening a verified store again does not re-verify in the same process"


@pytest.mark.parametrize("status", ["Suspended", "Off"])
def test_verify_bucket_refuses_versioning_off_naming_the_admin_command(status: str) -> None:
    with pytest.raises(MemoryStoreError, match=rf"versioning is {status}, it must be Enabled") as caught:
        S3Store(FakeObjects(versioning=status), "sast-memory")
    message = str(caught.value)
    assert "never configures its bucket" in message and "lifecycle" not in message and "Select" not in message
    assert 'aws s3api put-bucket-versioning --endpoint-url "$S3_ENDPOINT" --bucket sast-memory' in message


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
        S3Store(FakeObjects(rules=rules), "sast-memory")
    assert "put-bucket-lifecycle-configuration" in str(caught.value)
    assert '"Filter":{"Prefix":"runs/"},"Expiration":{"Days":30}' in str(caught.value)


def test_verify_bucket_names_the_prefixed_runs_and_refuses_a_rule_expiring_the_whole_store() -> None:
    with pytest.raises(MemoryStoreError, match=r"no enabled lifecycle rule expires mem/runs/"):
        S3Store(FakeObjects(rules=[ExpiryRule("r", "runs/", 30, True)]), "bucket", "mem")
    wide = [ExpiryRule("everything", "", 30, True), ExpiryRule("ousast-runs-expiry", "runs/", 30, True)]
    with pytest.raises(MemoryStoreError, match=r"lifecycle rule\(s\) everything expire the whole store"):
        S3Store(FakeObjects(rules=wide), "bucket")
    S3Store(FakeObjects(rules=[ExpiryRule("r", "mem/runs/", 14, True)]), "bucket", "mem")


def test_verify_bucket_names_every_missing_piece_and_the_permissions_to_read_them() -> None:
    client = FakeObjects("raises", versioning="denied", rules="denied")
    client.tags_denied = True
    with pytest.raises(MemoryStoreError) as caught:
        S3Store(client, "sast-memory")
    message = str(caught.value)
    assert "versioning cannot be read (PermissionError: Access Denied)" in message and "s3:GetBucketVersioning" in message
    assert "lifecycle configuration cannot be read" in message and "s3:GetLifecycleConfiguration" in message
    assert "object tags cannot be read" in message and "s3:GetObjectTagging" in message
    assert "S3 Select" in message and message.count("\n  - ") == 4


def test_row_objects_carry_tags_and_a_kind_tag_skips_objects_without_that_kind() -> None:
    client = FakeObjects("works")
    store = S3Store(client, "bucket")
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
    with pytest.raises(MemoryStoreError, match="file:///<path> or s3://<bucket>"):
        open_store("gs://bucket")
    with pytest.raises(MemoryStoreError, match="names no bucket and S3_BUCKET is unset"):
        open_store(environ={"OUSAST_MEMORY": "s3://"})


def test_s3_settings_name_missing_keys_never_values() -> None:
    with pytest.raises(MemoryStoreError, match="AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY") as caught:
        open_store(environ={"OUSAST_MEMORY": "s3://bucket", "S3_ENDPOINT": "https://files.example:9000"})
    assert "files.example" not in str(caught.value)
    env = {"S3_ENDPOINT": "https://h:9000", "AWS_ACCESS_KEY_ID": "ak", "AWS_SECRET_ACCESS_KEY": "sk-value"}
    assert s3_settings(env) == {"endpoint": "https://h:9000", "access_key": "ak", "secret_key": "sk-value"}
    assert s3_settings({**env, "S3_REGION": "eu-1", "AWS_SESSION_TOKEN": "tok"}) == {
        **s3_settings(env), "region": "eu-1", "session_token": "tok"
    }  # fmt: skip
    with pytest.raises(MemoryStoreError, match=r"S3_ENDPOINT must be a URL with a scheme") as caught:
        s3_settings({**env, "S3_ENDPOINT": "h:9000"})
    assert "h:9000" not in str(caught.value)


def test_s3_without_boto3_names_the_extra() -> None:
    try:
        import boto3  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("boto3 is installed here")
    env = {"OUSAST_MEMORY": "s3://bucket", "S3_ENDPOINT": "https://h:9000", "AWS_ACCESS_KEY_ID": "ak"}
    with pytest.raises(MemoryStoreError, match=r"install openultrasast\[s3\]") as caught:
        open_store(environ={**env, "AWS_SECRET_ACCESS_KEY": "secret-xyz"})
    assert "secret-xyz" not in str(caught.value)


def test_the_boto3_client_is_built_for_path_style_sigv4_and_no_checksum_trailers() -> None:
    pytest.importorskip("boto3")
    client = S3Client("https://files.example", "ak", "secret-xyz", "sast-memory", region="eu-1")
    meta = client.sdk.meta
    assert (meta.endpoint_url, meta.region_name, meta.config.signature_version) == ("https://files.example", "eu-1", "s3v4")
    assert meta.config.s3 == {"addressing_style": "path"}
    assert getattr(meta.config, "request_checksum_calculation", "when_required") == "when_required"
    url = client.presign("PUT", "runs/r1/x/units.jsonl", timedelta(minutes=5))
    assert url.startswith("https://files.example/sast-memory/runs/r1/x/units.jsonl?") and "X-Amz-Expires=300" in url
    assert "secret-xyz" not in url


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
