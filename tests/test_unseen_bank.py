"""Offline decision-bank contract: durability, identity and plain object transport."""

import hashlib
import io
import json
import sys
from datetime import datetime
from types import SimpleNamespace

import pytest

from benchmarks.unseen.bank import CorpusBank, CorpusObjects, corpus_settings, split_decided


class FakeObjects:
    def __init__(self):
        self.objects = {}
        self.labels = {}
        self.calls = []
        self.failures = {}

    def call(self, operation):
        self.calls.append(operation)
        if self.failures.get(operation, 0):
            self.failures[operation] -= 1
            raise OSError("offline failure")

    def get(self, key):
        self.call("get")
        return (self.objects[key], "version") if key in self.objects else None

    def put(self, key, data, labels):
        self.call("put")
        self.objects[key] = data
        self.labels[key] = labels

    def keys(self, prefix):
        return [key for key in reversed(self.objects) if key.startswith(prefix)]


def test_cache_repo_roundtrip_404_and_shared_prefix():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=20260601, prefix="unseen")
    # the get_repo cache is shared across seeds, not under the seed prefix
    assert bank.repos_prefix == "unseen/repos/"
    bank.cache_repo("org/repo", {"full_name": "org/repo", "size": 10}, contract="v1")
    bank.cache_repo("org/gone", None, contract="v1")
    assert bank.get_cached_repo("org/repo", contract="v1") == (True, {"full_name": "org/repo", "size": 10})
    # a cached 404 is a hit (found True, metadata None): it must not re-hit GitHub
    assert bank.get_cached_repo("org/gone", contract="v1") == (True, None)
    assert bank.get_cached_repo("org/never", contract="v1") == (False, None)
    # a stale contract is a miss so the lookup is refreshed
    assert bank.get_cached_repo("org/repo", contract="v2") == (False, None)
    # idempotent: re-caching the same metadata does not rewrite
    puts = objects.calls.count("put")
    bank.cache_repo("org/repo", {"full_name": "org/repo", "size": 10}, contract="v1")
    assert objects.calls.count("put") == puts


def settings_env():
    return {
        "CORPUS_S3_ENDPOINT": "https://objects.invalid",
        "CORPUS_S3_BUCKET": "ousast-corpus",
        "CORPUS_AWS_ACCESS_KEY_ID": "private-access",
        "CORPUS_AWS_SECRET_ACCESS_KEY": "private-secret",
    }


@pytest.mark.parametrize("missing", list(settings_env()))
def test_settings_names_missing_key_without_values(missing):
    env = settings_env()
    del env[missing]
    with pytest.raises(ValueError) as error:
        corpus_settings(env)
    assert missing in str(error.value)
    assert all(value not in str(error.value) for value in env.values())


def test_settings_and_optional_region():
    env = settings_env()
    assert corpus_settings(env) == {
        "endpoint": env["CORPUS_S3_ENDPOINT"],
        "bucket": "ousast-corpus",
        "access_key": "private-access",
        "secret_key": "private-secret",
    }
    assert corpus_settings({**env, "CORPUS_S3_REGION": "region-1"})["region"] == "region-1"


def test_bank_roundtrip_and_idempotent_bytes():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=42)
    entry = {"repository": "org/a", "fix": "abc", "advisory": "GHSA-a", "changes": [{"code": "text"}]}
    result = {"entry": entry, "ordinary_exclusions": {"merge": 2}, "counts": {"eligible": 13}}
    key = bank.key_for("org/a", "abc")
    assert key == hashlib.sha256(b"org/a\nabc").hexdigest()
    bank.bank("org/a", "abc", result, contract="v1")
    original = objects.objects.copy()
    bank.bank("org/a", "abc", result, contract="v1")
    assert objects.objects == original
    assert list(objects.objects) == [f"unseen/42/decisions/{key}.json"]
    row = bank.decided()[key]
    assert row == {
        "repository": "org/a",
        "fix": "abc",
        "decision": "accept",
        "reason": None,
        "entry": entry,
        "ordinary_exclusions": {"merge": 2},
        "counts": {"eligible": 13},
        "contract": "v1",
        "seed": 42,
        "ts": row["ts"],
    }
    assert datetime.fromisoformat(row["ts"]).utcoffset().total_seconds() == 0
    assert objects.labels[next(iter(objects.labels))] == {"decision": "accept", "contract": "v1"}


def test_rejection_contract_update_and_split():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=3, prefix="custom")
    for repo, advisory in (("z", "GHSA-z"), ("a", "GHSA-a")):
        bank.bank(repo, "fix", {"entry": {"repository": repo, "fix": "fix", "advisory": advisory}}, contract="old")
    bank.bank("no", "fix", {"rejected": "reason"}, contract="v1")
    bank.bank("stale", "fix", {"rejected": "reason"}, contract="old")
    accepted, keys = split_decided(bank.decided(), contract="v1")
    assert [entry["repository"] for entry in accepted] == ["a", "z"]
    assert keys == {bank.key_for(repo, "fix") for repo in ("a", "z", "no")}
    row = bank.decided()[bank.key_for("no", "fix")]
    assert row["reason"] == "reason" and row["decision"] == "reject"
    assert row["entry"] is None and row["counts"] == row["ordinary_exclusions"] == {}
    bank.bank("stale", "fix", {"rejected": "different"}, contract="v1")
    assert len(objects.objects) == 4
    assert bank.decided()[bank.key_for("stale", "fix")]["contract"] == "v1"


@pytest.mark.parametrize("operation", ["get", "put"])
@pytest.mark.parametrize("failures", [1, 2])
def test_bank_retries_once_then_surfaces_failure(operation, failures):
    objects = FakeObjects()
    objects.failures[operation] = failures
    bank = CorpusBank(objects, seed=1)
    if failures == 1:
        bank.bank("repo", "fix", {"rejected": "reason"}, contract="v1")
        assert len(objects.objects) == 1
    else:
        with pytest.raises(OSError, match="offline failure"):
            bank.bank("repo", "fix", {"rejected": "reason"}, contract="v1")
    assert objects.calls.count(operation) == 2


def test_decided_retries_get_and_fails_on_missing_listed_object():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=1)
    bank.bank("repo", "fix", {"rejected": "reason"}, contract="v1")
    objects.failures["get"] = 1
    assert len(bank.decided()) == 1
    objects.get = lambda key: None
    with pytest.raises(ValueError, match="missing"):
        bank.decided()


def test_plain_s3_adapter_without_bucket_probes(monkeypatch):
    calls = []

    class Missing(Exception):
        response = {"Error": {"Code": "NoSuchKey"}}

    class S3:
        def put_object(self, **kwargs):
            calls.append(("put", kwargs))

        def get_object(self, **kwargs):
            calls.append(("get", kwargs))
            if kwargs["Key"] == "missing":
                raise Missing()
            return {"Body": io.BytesIO(b"data"), "ETag": "tag"}

        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return SimpleNamespace(paginate=self.pages)

        def pages(self, **kwargs):
            calls.append(("list", kwargs))
            return [{"Contents": [{"Key": "p/a"}]}, {}, {"Contents": [{"Key": "p/b"}]}]

    def client(service, **kwargs):
        calls.append((service, kwargs))
        return S3()

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: SimpleNamespace(**kwargs)))
    adapter = CorpusObjects(**corpus_settings(settings_env()))
    adapter.put("p/a", b"data", {"decision": "accept", "contract": "v1"})
    assert adapter.get("p/a") == (b"data", "tag")
    assert adapter.get("missing") is None
    assert adapter.keys("p/") == ["p/a", "p/b"]
    assert calls[0][0] == "s3"
    assert calls[0][1]["endpoint_url"] == "https://objects.invalid"
    assert calls[0][1]["config"].retries == {"total_max_attempts": 1}
    assert calls[1][1]["Bucket"] == "ousast-corpus"
    assert calls[1][1]["Body"] == b"data"
    assert calls[-1] == ("list", {"Bucket": "ousast-corpus", "Prefix": "p/"})


def test_decided_rejects_invalid_identity():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=1)
    bank.bank("repo", "fix", {"rejected": "reason"}, contract="v1")
    key = next(iter(objects.objects))
    row = json.loads(objects.objects[key])
    row["repository"] = "other"
    objects.objects[key] = json.dumps(row).encode()
    with pytest.raises(ValueError, match="identity"):
        bank.decided()


@pytest.mark.parametrize("endpoint", ["missing-scheme-private", "https://private[", "http://private／secret"])
def test_invalid_endpoint_does_not_expose_value(endpoint):
    with pytest.raises(ValueError) as error:
        corpus_settings({**settings_env(), "CORPUS_S3_ENDPOINT": endpoint})
    assert "CORPUS_S3_ENDPOINT" in str(error.value)
    assert endpoint not in str(error.value)


def test_import_does_not_require_boto3(monkeypatch):
    import importlib.util

    from benchmarks.unseen import bank

    monkeypatch.setitem(sys.modules, "boto3", None)
    spec = importlib.util.spec_from_file_location("offline_bank", bank.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.CorpusBank.key_for("a", "b") == CorpusBank.key_for("a", "b")


@pytest.mark.parametrize(
    "result",
    [
        {"candidate": {"repository": "org/é"}, "network": "org/root"},
        {"rejected": "used_pairs"},
        {"rejected": "family", "network": "org/root"},
    ],
)
def test_resolution_roundtrip_idempotent_and_contract_replacement(result):
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=42, prefix="custom")
    advisory = "GHSA-test/advisory"
    key = f"custom/42/resolved/{hashlib.sha256(advisory.encode()).hexdigest()}.json"
    assert bank.advisory_key(advisory) == hashlib.sha256(advisory.encode()).hexdigest()
    bank.bank_resolution(advisory, result, contract="old")
    first = objects.objects.copy()
    bank.bank_resolution(advisory, result, contract="old")
    assert objects.objects == first and objects.calls.count("put") == 1
    row = bank.resolved()[advisory]
    assert row == {
        "advisory": advisory,
        "result": result,
        "decision": "candidate" if "candidate" in result else "reject",
        "reason": result.get("rejected"),
        "resolution_contract": "old",
        "seed": 42,
        "ts": row["ts"],
    }
    assert list(objects.objects) == [key]
    assert datetime.fromisoformat(row["ts"]).utcoffset().total_seconds() == 0
    bank.bank_resolution(advisory, result, contract="v1")
    assert bank.resolved()[advisory]["resolution_contract"] == "v1"
    assert objects.calls.count("put") == 2


def test_advisory_snapshot_written_once_per_contract():
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=7)
    rows = [{"ghsa_id": "GHSA-é", "references": ["a", "b"]}]
    assert bank.cached_advisories(contract="v1") is None
    bank.cache_advisories(rows, contract="v1")
    original = objects.objects.copy()
    assert bank.cached_advisories(contract="v1") == rows
    assert bank.cached_advisories(contract="v2") is None
    bank.cache_advisories([], contract="v1")
    assert objects.objects == original and objects.calls.count("put") == 1
    body = json.loads(objects.objects["unseen/7/advisories/list.json"])
    assert body == {"advisories": rows, "advisories_contract": "v1", "seed": 7, "ts": body["ts"]}
    bank.cache_advisories([], contract="v2")
    assert bank.cached_advisories(contract="v2") == []
    assert bank.cached_advisories(contract="v1") is None


@pytest.mark.parametrize("method", ["resolution", "advisories", "repository"])
@pytest.mark.parametrize("operation", ["get", "put"])
@pytest.mark.parametrize("failures", [1, 2])
def test_new_bank_writes_retry_once(method, operation, failures):
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=7)
    objects.failures[operation] = failures

    def write():
        if method == "resolution":
            bank.bank_resolution("GHSA-a", {"rejected": "family"}, contract="v1")
        elif method == "advisories":
            bank.cache_advisories([], contract="v1")
        else:
            bank.bank_repository("org/repo", None, contract="v1")

    if failures == 2:
        with pytest.raises(OSError):
            write()
        assert objects.calls.count(operation) == 2
    else:
        write()
        assert len(objects.objects) == 1
        assert objects.failures[operation] == 0


@pytest.mark.parametrize("method", ["resolved", "cached_advisories", "repositories"])
@pytest.mark.parametrize("failures", [1, 2])
def test_new_bank_reads_retry_once(method, failures):
    objects = FakeObjects()
    bank = CorpusBank(objects, seed=7)
    bank.bank_resolution("GHSA-a", {"rejected": "family"}, contract="v1")
    bank.cache_advisories([], contract="v1")
    bank.bank_repository("org/old", {"full_name": "org/new"}, contract="v1")
    bank.bank_repository("org/missing", None, contract="old")
    objects.failures["get"] = failures
    read = getattr(bank, method)
    kwargs = {} if method == "resolved" else {"contract": "v1"}
    if failures == 2:
        with pytest.raises(OSError):
            read(**kwargs)
    else:
        result = read(**kwargs)
        assert result is not None
        if method == "repositories":
            assert result == {"org/old": {"full_name": "org/new"}}
