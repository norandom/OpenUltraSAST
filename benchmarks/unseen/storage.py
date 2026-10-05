"""Disposable private SQLite working sets; JSONL remains the durable source of truth."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence, Set
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def working_store(directory=None):
    # TemporaryDirectory is mode 0700. No identity-bearing scratch data enters the checkout.
    with tempfile.TemporaryDirectory(prefix="sourcing-", dir=directory) as temporary:
        db = sqlite3.connect(Path(temporary) / "working.sqlite")
        try:
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("PRAGMA temp_store=FILE")
            db.execute("PRAGMA cache_size=-2048")
            db.execute("PRAGMA mmap_size=0")
            db.execute("CREATE TABLE records (kind TEXT, key TEXT, value TEXT, PRIMARY KEY (kind, key)) WITHOUT ROWID")
            db.execute("CREATE TABLE sequences (kind TEXT, position INTEGER, value TEXT, PRIMARY KEY (kind, position)) WITHOUT ROWID")
            yield db
        finally:
            db.close()


class DiskMap(Mapping):
    def __init__(self, db, kind):
        self.db, self.kind = db, kind
        self.count = 0

    def __len__(self):
        return self.count

    def __iter__(self):
        for (key,) in self.db.execute("SELECT key FROM records WHERE kind=? ORDER BY key", (self.kind,)):
            yield key

    def __contains__(self, key):
        return self.db.execute("SELECT 1 FROM records WHERE kind=? AND key=?", (self.kind, key)).fetchone() is not None

    def __getitem__(self, key):
        row = self.db.execute("SELECT value FROM records WHERE kind=? AND key=?", (self.kind, key)).fetchone()
        if row is None:
            raise KeyError(key)
        return json.loads(row[0])

    def __setitem__(self, key, value):
        if key not in self:
            self.count += 1
        self.db.execute("INSERT OR REPLACE INTO records VALUES (?, ?, ?)", (self.kind, key, json.dumps(value)))

    def values(self):
        for (value,) in self.db.execute("SELECT value FROM records WHERE kind=? ORDER BY key", (self.kind,)):
            yield json.loads(value)


class DiskSequence(Sequence):
    def __init__(self, db, kind):
        self.db, self.kind = db, kind
        self.count = 0

    def __len__(self):
        return self.count

    def __getitem__(self, position):
        if position < 0:
            position += self.count
        row = self.db.execute("SELECT value FROM sequences WHERE kind=? AND position=?", (self.kind, position)).fetchone()
        if row is None:
            raise IndexError(position)
        return json.loads(row[0])

    def __setitem__(self, position, value):
        self.db.execute("INSERT OR REPLACE INTO sequences VALUES (?, ?, ?)", (self.kind, position, json.dumps(value)))

    def append(self, value):
        self[self.count] = value
        self.count += 1

    def __iter__(self):
        for (value,) in self.db.execute("SELECT value FROM sequences WHERE kind=? ORDER BY position", (self.kind,)):
            yield json.loads(value)


class DiskSet(Set):
    def __init__(self, db, kind):
        self.rows = DiskMap(db, kind)

    def __len__(self):
        return len(self.rows)

    def __contains__(self, value):
        return json.dumps(value) in self.rows

    def __iter__(self):
        for key in self.rows:
            value = json.loads(key)
            yield tuple(value) if isinstance(value, list) else value

    def add(self, value):
        self.rows[json.dumps(value)] = None

    def update(self, values):
        for value in values:
            self.add(value)


class AdvisoryRows(DiskMap):
    def __iter__(self):
        return self.values()

    def ordered(self, seed):
        import random

        from .source import ECOSYSTEMS, ecosystem

        rng = random.Random(seed)
        groups = [DiskSequence(self.db, "order_" + eco) for eco in ECOSYSTEMS]
        for row in self.values():  # key order is the original ghsa_id sort
            eco = ecosystem(row)
            if eco in ECOSYSTEMS:
                groups[ECOSYSTEMS.index(eco)].append(row)
        for group in groups:
            rng.shuffle(group)  # Same Fisher-Yates draws as the in-memory implementation.
        cursors = [
            self.db.execute(
                "SELECT value FROM sequences WHERE kind=? "
                "ORDER BY substr(json_extract(value, '$.published_at'), 1, 10) <= '2026-06-01', position",
                (group.kind,),
            )
            for group in groups
        ]
        for _ in range(max(map(len, groups), default=0)):
            for cursor in cursors:
                row = cursor.fetchone()
                if row is not None:
                    yield json.loads(row[0])


class FixIndex:
    def __init__(self, db):
        self.db = db
        db.execute("CREATE TABLE fixes (repository TEXT, sha TEXT, PRIMARY KEY (repository, sha)) WITHOUT ROWID")

    def add(self, repository, sha):
        self.db.execute("INSERT OR IGNORE INTO fixes VALUES (?, ?)", (repository, sha))

    def get(self, repository, default=None):
        fixes = RepositoryFixes(self.db, repository)
        return fixes if fixes else default


class RepositoryFixes(Set):
    def __init__(self, db, repository):
        self.db, self.repository = db, repository

    def __len__(self):
        return self.db.execute("SELECT count(*) FROM fixes WHERE repository=?", (self.repository,)).fetchone()[0]

    def __iter__(self):
        for (sha,) in self.db.execute("SELECT sha FROM fixes WHERE repository=? ORDER BY sha", (self.repository,)):
            yield sha

    def __contains__(self, sha):
        return self.db.execute("SELECT 1 FROM fixes WHERE repository=? AND sha=?", (self.repository, sha)).fetchone() is not None
