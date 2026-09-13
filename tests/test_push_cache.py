"""Publication, locking, corruption and eviction are observable cache contracts."""

import time

from openultrasast.cpg.artifact import digest_value
from openultrasast.model.contracts import ExecutionBudget
from openultrasast.push.cache import ArtifactCache


def budget(seconds=3):
    return ExecutionBudget(time.monotonic() + seconds, 0.2)


def test_completed_publication_is_readable_and_private(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")
    assert cache.publish(key, b"real bytes", {"kind": "test"}, budget())
    with cache.lookup(key, budget()) as entry:
        assert entry is not None
        assert entry.path.read_bytes() == b"real bytes"
        assert entry.metadata == {"kind": "test"}
        assert entry.path.stat().st_mode & 0o077 == 0
    assert cache.root.stat().st_mode & 0o077 == 0


def test_partial_and_corrupt_entries_are_misses(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")
    assert not cache.publish(key, b"partial", {}, budget(), complete=False)
    with cache.lookup(key, budget()) as entry:
        assert entry is None
    assert cache.publish(key, b"good", {}, budget())
    (cache.root / key / "payload").write_bytes(b"bad")
    with cache.lookup(key, budget()) as entry:
        assert entry is None
    assert cache.publish(key, b"repaired", {}, budget())
    (cache.root / key / "manifest.json").write_text("{}")
    with cache.lookup(key, budget()) as entry:
        assert entry is None


def test_eviction_skips_leases_and_enforces_limit(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=1700)
    one, two = digest_value("one"), digest_value("two")
    assert cache.publish(one, b"a" * 1000, {}, budget())
    with cache.lookup(one, budget()) as entry:
        assert entry is not None
        assert not cache.publish(two, b"b" * 1000, {}, budget(0.05))
        assert entry.path.read_bytes() == b"a" * 1000
    assert cache.publish(two, b"b" * 1000, {}, budget())
    with cache.lookup(one, budget()) as entry:
        assert entry is None
    with cache.lookup(two, budget()) as entry:
        assert entry is not None


def test_lock_wait_cannot_exceed_transaction_budget(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")
    assert cache.publish(key, b"x", {}, budget())
    with cache.lookup(key, budget()) as entry:
        assert entry is not None
        started = time.monotonic()
        assert not cache.publish(key, b"y", {}, budget(0.05))
        assert time.monotonic() - started < 0.25
    with cache.lookup(key, budget()) as entry:
        assert entry.path.read_bytes() == b"x"


def test_interrupted_publication_never_creates_complete_entry(tmp_path, monkeypatch):
    import os

    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")

    def fail(*args):
        raise OSError("interrupted before atomic publication")

    monkeypatch.setattr(os, "replace", fail)
    assert not cache.publish(key, b"x", {}, budget())
    with cache.lookup(key, budget()) as entry:
        assert entry is None
    assert not list(cache.root.glob(".pending-*"))


def test_concurrent_writers_publish_only_complete_payloads(tmp_path):
    import multiprocessing

    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")

    def write(value):
        assert cache.publish(key, value * 2000, {"writer": value.decode()}, budget())

    processes = [multiprocessing.get_context("fork").Process(target=write, args=(v,)) for v in (b"a", b"b")]
    for process in processes:
        process.start()
    for process in processes:
        process.join(5)
        assert process.exitcode == 0
    with cache.lookup(key, budget()) as entry:
        assert entry.path.read_bytes() == entry.metadata["writer"].encode() * 2000


def test_symlink_and_invalid_key_are_rejected(tmp_path):
    import pytest

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValueError):
        ArtifactCache(link, max_bytes=10000)
    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    with cache.lookup("../escape", budget()) as entry:
        assert entry is None
    assert not cache.publish("../escape", b"x", {}, budget())
    key = digest_value("link")
    (cache.root / key).symlink_to(target)
    with cache.lookup(key, budget()) as entry:
        assert entry is None


def test_lookup_failure_is_miss_and_consumer_exception_is_preserved(tmp_path):
    import pytest

    cache = ArtifactCache(tmp_path / "cache", max_bytes=10000)
    key = digest_value("one")
    assert cache.publish(key, b"bytes", {}, budget())
    with pytest.raises(OSError, match="consumer"), cache.lookup(key, budget()) as entry:
        assert entry is not None
        raise OSError("consumer")
    lock = cache.root / cache._bucket(key)
    lock.unlink()
    lock.symlink_to(tmp_path / "absent")
    with cache.lookup(key, budget()) as entry:
        assert entry is None


def test_abandoned_partial_files_count_toward_size_and_are_evicted(tmp_path):
    cache = ArtifactCache(tmp_path / "cache", max_bytes=1700)
    abandoned = cache.root / ".pending-dead-writer"
    abandoned.mkdir(mode=0o700)
    (abandoned / "payload").write_bytes(b"a" * 1000)
    key = digest_value("one")
    assert cache.publish(key, b"b" * 1000, {}, budget())
    assert not abandoned.exists()
    assert sum(p.stat().st_size for p in cache.root.rglob("*") if p.is_file()) <= cache.max_bytes
