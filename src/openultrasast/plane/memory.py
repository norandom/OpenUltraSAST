"""The plane's memory store (harnessx-removal Requirement 6.1/6.4, design section 4).

One store, keyed by repository and pin, holds what plane runs learned: repository facts by content hash, and rows
of the kinds in ``KINDS`` (``facts``, ``verdict``, ``unit_cost``, ``alert``, ``coverage``, ``features``, ...) that
``remember`` (:mod:`.tasks.remember`) derives from a run's delivered artifacts, plus the loop's and the decision
engine's own. Layout, identical for both backends::

    index.jsonl                               one row per ingested (run, task): sha256 of its rows, row count
    facts/<sha256>.json                       facts.json by content (identical facts stored once)
    repos/<host>__<owner>__<name>/<pin>.jsonl the rows of one repository + 40-hex pin, sorted by id
    <prefix>/<sha256>.<ext>                   blobs (``put_blob``): excerpts/*.txt by content, embeddings/<model>/*.json
                                              by excerpt sha, responses/*.json by request sha, programs/*.json

``OUSAST_MEMORY`` selects the backend: ``file:///path`` (:class:`FileStore`, default ``results_root()/memory``) or
``s3://<bucket>[/<prefix>]`` (:class:`S3Store`, the ``s3`` extra: boto3 against any S3-compatible server with
versioning, lifecycle rules, object tags and S3 Select; RustFS is the server this is tested on). ``s3://`` without a
bucket names ``S3_BUCKET``. The endpoint and credentials come from ``.env`` (``S3_ENDPOINT``, a full URL;
``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``; optional ``AWS_SESSION_TOKEN``, ``S3_REGION``), never from a
manifest, and are never printed. The store never configures its bucket: an admin enables versioning and the
``runs/`` expiry rule once, and opening an ``S3Store`` verifies them and S3 Select (:meth:`S3Store.verify_bucket`),
refusing to start otherwise.

Every row carries every queryable field (``QUERY_FIELDS``: strings, ``""`` where one does not apply, never ``null``):
the store fills them in on every write, ``rows`` refuses a ``where`` field no kind declared, and ``ousast plane
memory-normalise`` rewrites rows written before the rule. RustFS's S3 Select infers the schema from an object's first
1000 rows only.

Ingest is idempotent: an ``index.jsonl`` hit on (run, task, sha256) skips the delivery, and rows carry a
deterministic ``id``, so a repeated row replaces itself. Every object is written whole (``FileStore``: a temporary
file renamed) and the index last, so an interrupted ingest leaves nothing partial that a repeat would not repair.
``FileStore`` refuses to write below 1 GiB free and names its path.

Fact reuse: a facts entry is valid for (repo, pin, candidates digest, runner image digest), the key the generator
writes as the Task annotation ``openultrasast.io/memory-key``. :func:`seed` runs before a Run: for every entry whose
Task carries a key with stored facts and no state yet, it writes ``<run>/<task>/facts.json`` and a ``done``
summary and marks the task done under the run lock (``reconciler.mark_done``), so the reconciler skips it.

The loop's ``memory-snapshot`` (a Task annotated ``openultrasast.io/memory-snapshot`` with the train-on-test guard's
parameters) is seeded the same way: a sandboxed task cannot read this store, so :func:`seed` writes the store's rows
after the guard into ``<run>/memory-snapshot/`` (:func:`.tasks.loop.write_snapshot`) and marks it done.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

MEMORY_KEY_ANNOTATION = "openultrasast.io/memory-key"
POPULATION_ANNOTATION = "openultrasast.io/population"
SPLIT_ANNOTATION = "openultrasast.io/split"
SNAPSHOT_ANNOTATION = "openultrasast.io/memory-snapshot"  # the loop's guard: {"catalog", "manifest", "populations"}
# The decision engine's kinds (learned-decision-engine, Data Models): `features` from the `features` task through
# `remember`; `label`, `decision`, `experiment`, `arm_outcome` and `experiment_result` for the later tasks; `example`
# (a labelled case of the local memory: label + feature record + excerpt sha) from `ousast learn memory build`.
KINDS = (
    "facts", "verdict", "unit_cost", "alert", "coverage", "proposal_outcome",
    "features", "label", "decision", "experiment", "arm_outcome", "experiment_result", "example",
)  # fmt: skip
# Blobs (`put_blob`): a top-level prefix, optionally one sub-directory (`embeddings/<model-slug>`), and a 64-hex name.
_BLOB_PREFIX = re.compile(r"[a-z]+(?:/[A-Za-z0-9._-]+)?")
_BLOB_NAME = re.compile(r"[0-9a-f]{64}")
BLOB_SUFFIX = {"excerpts": ".txt", "labels": ".jsonl"}  # every other prefix holds JSON
ROW_FIELDS = ("id", "kind", "repo", "pin", "run", "task", "population", "split", "image")
# The fixed schema: every row carries every queryable field. RustFS's S3 Select infers an object's schema from its
# first 1000 rows: a ``where`` field absent there raises ``EvaluatorBindingDoesNotExist`` although later rows carry it
# (measured 2026-10-02: field only at row 5000, and absent everywhere), and a column that is ``null`` in all of them
# but set later fails the whole object with ``JSONParsingError``, whatever the ``where`` (measured 2026-10-02: 999
# leading nulls answer, 1000 fail; "" placeholders answer at 5000). So a queryable field is a string, and a row it
# does not apply to carries the empty string, never ``null``. Per kind, the fields a server-side filter
# (``rows(..., where=...)``) may name besides ``ROW_FIELDS`` (which every row carries already); a new query declares
# its field here first. One object holds every kind of a repository + pin, so the store writes the union of these
# fields (``QUERYABLE``) on every row (``normalise_row``).
QUERY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "facts": ("candidates_digest",),  # seed(): candidates_digest + image
    "verdict": ("candidate", "final"),
    "unit_cost": (),
    "alert": (),
    "coverage": (),
    "proposal_outcome": (),
    "features": (),  # benchmarks/learn/build_features.py: run + task
    "label": (),
    "decision": (),
    "experiment": (),
    "arm_outcome": (),
    "experiment_result": (),
    "example": ("profile",),  # learn.examples.load_examples
}
if tuple(QUERY_FIELDS) != KINDS:  # pragma: no cover -- a kind added without its queryable fields
    raise RuntimeError("QUERY_FIELDS must declare every kind of KINDS, in order")
QUERYABLE = tuple(sorted({f for fields in QUERY_FIELDS.values() for f in fields} - set(ROW_FIELDS)))
TAG_FIELDS = ("repo", "pin", "kind", "family", "run", "population", "split")
MIN_FREE_BYTES = 1 << 30
S3_KEYS = ("S3_ENDPOINT", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
_PIN = re.compile(r"[0-9a-f]{40}")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TAG_VALUE = re.compile(r"[^A-Za-z0-9 +\-=._:/@]")


class MemoryStoreError(RuntimeError):
    """The store refused or failed a read or write; the message names the store and the cause."""


# --- rows and keys -------------------------------------------------------------------------------------------------


def repo_key(repo: str) -> str:
    """``host/owner/name`` of a repository URL (scheme, credentials, ``.git`` and trailing slashes dropped)."""
    text = repo.strip()
    if "://" in text:
        parts = urlsplit(text)
        text = f"{parts.hostname or ''}{parts.path}"
    text = text.rstrip("/").removesuffix(".git").strip("/")
    if not text:
        raise ValueError(f"not a repository: {repo!r}")
    return text


def repo_dir(repo: str) -> str:
    return repo_key(repo).replace("/", "__")


def row_id(kind: str, run: str, task: str, subject: str) -> str:
    """The deterministic row id: sha256 of (kind, run, task, subject), subject being the candidate, the path,
    the facts sha256 or the rule id with its location."""
    return hashlib.sha256("\x00".join((kind, run, task, subject)).encode("utf-8")).hexdigest()


def image_digest(image: str) -> str:
    """The content part of an image reference (``sha256:...``): the registry host may differ, the code may not."""
    return image.rpartition("@")[2] if "@" in image else image


def memory_key(repo: str, pin: str, candidates: str, image: str) -> str:
    """The annotation text of a facts entry's validity key."""
    key = {"candidates": candidates, "image": image_digest(image), "pin": pin, "repo": repo_key(repo)}
    return json.dumps(key, sort_keys=True, separators=(",", ":"))


def parse_memory_key(text: str) -> dict[str, str]:
    key = json.loads(text)
    if not isinstance(key, dict) or set(key) != {"candidates", "image", "pin", "repo"}:
        raise ValueError(f"{MEMORY_KEY_ANNOTATION} must name candidates, image, pin and repo: {text[:200]!r}")
    return {k: str(v) for k, v in key.items()}


def blob_key(prefix: str, name: str) -> str:
    """The key of a blob: ``<prefix>/<name><suffix>``; a prefix or name outside the layout is refused."""
    if not _BLOB_PREFIX.fullmatch(prefix) or ".." in prefix or prefix.split("/", 1)[0] in ("repos", "facts", "index.jsonl"):
        raise MemoryStoreError(f"blob prefix {prefix!r} is not a blob prefix of the layout")
    if not _BLOB_NAME.fullmatch(name):
        raise MemoryStoreError(f"blob name {name!r} is not a 64-hex sha256")
    return f"{prefix}/{name}{BLOB_SUFFIX.get(prefix.split('/', 1)[0], '.json')}"


def validate_row(row: object, where: str = "row") -> dict[str, Any]:
    if not isinstance(row, dict):
        raise MemoryStoreError(f"{where}: a row must be a JSON object")
    missing = [f for f in ROW_FIELDS if not isinstance(row.get(f), str) or not row.get(f)]
    if missing:
        raise MemoryStoreError(f"{where}: missing or empty fields {missing}")
    if row["kind"] not in KINDS:
        raise MemoryStoreError(f"{where}: unknown kind {row['kind']!r} (one of {', '.join(KINDS)})")
    if not _PIN.fullmatch(row["pin"]):
        raise MemoryStoreError(f"{where}: pin {row['pin']!r} is not a 40-hex commit")
    return row


def normalise_row(row: Mapping[str, Any], where: str = "row") -> dict[str, Any]:
    """``row`` with every ``QUERYABLE`` field present: absent or ``null`` becomes ``""`` (see ``QUERY_FIELDS``);
    a string is kept; any other type is refused, since one column of two types fails the server's Select."""
    out = dict(row)
    for name in QUERYABLE:
        value = out.get(name)
        if value is None:
            out[name] = ""
        elif not isinstance(value, str):
            raise MemoryStoreError(f"{where}: queryable field {name!r} must be a string, got {type(value).__name__}")
    return out


def check_query(kind: str | None, where: Mapping[str, Any] | None) -> None:
    """Refuse a filter the fixed schema does not cover: an unknown kind, or a ``where`` field that ``kind`` (any kind
    when None) does not declare in ``QUERY_FIELDS``; the server could not bind it on every object."""
    if kind is not None and kind not in QUERY_FIELDS:
        raise MemoryStoreError(f"rows: unknown kind {kind!r} (one of {', '.join(KINDS)})")
    declared = set(ROW_FIELDS) | set(QUERY_FIELDS[kind] if kind is not None else QUERYABLE)
    undeclared = sorted(set(where or {}) - declared)
    if undeclared:
        scope = f"kind {kind!r}" if kind is not None else "any kind"
        raise MemoryStoreError(
            f"rows: where field(s) {undeclared} are not queryable for {scope}: declare them in memory.QUERY_FIELDS "
            '(every row then carries them, "" where they do not apply) and run `ousast plane memory-normalise`'
        )
    nulls = sorted(name for name, value in (where or {}).items() if value is None)
    if nulls:
        raise MemoryStoreError(f'rows: where {nulls} = null never matches: a queryable field that does not apply is ""')


def _line(row: Mapping[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


def rows_digest(rows: Iterable[Mapping[str, Any]]) -> str:
    return hashlib.sha256("".join(_line(r) + "\n" for r in rows).encode("utf-8")).hexdigest()


def matches(row: Mapping[str, Any], where: Mapping[str, Any] | None) -> bool:
    """Top-level equality on every ``where`` field; the rule the S3 Select expression pushes down."""
    return all(row.get(k) == v for k, v in (where or {}).items())


def where_sql(where: Mapping[str, Any]) -> str:
    """The S3 Select expression of ``where`` (JSON Lines input): equality per field, AND-joined."""
    clauses: list[str] = []
    for name, value in sorted(where.items()):
        if not _FIELD.fullmatch(name):
            raise ValueError(f"where: field {name!r} is not a plain identifier")
        ref = f's."{name}"'
        if value is None:
            clauses.append(f"{ref} IS NULL")
        elif isinstance(value, bool):
            clauses.append(f"{ref} = {'true' if value else 'false'}")
        elif isinstance(value, int | float):
            clauses.append(f"{ref} = {value!r}")
        elif isinstance(value, str):
            clauses.append(f"{ref} = '{value.replace(chr(39), chr(39) * 2)}'")
        else:
            raise ValueError(f"where: {name} must be a string, number, boolean or null")
    return "SELECT * FROM S3Object s" + (" WHERE " + " AND ".join(clauses) if clauses else "")


@dataclass(frozen=True)
class Record:
    """A row as read, with the object it came from and that object's version (Req 6.4 provenance)."""

    row: dict[str, Any]
    key: str
    version: str | None


@dataclass(frozen=True)
class IngestResult:
    run: str
    task: str
    rows: int
    skipped: bool
    kinds: dict[str, int]


# --- the interface -------------------------------------------------------------------------------------------------


class MemoryStore(ABC):
    """Rows by repository and pin, facts by content hash, and the ingest index; two backends, one behaviour."""

    # primitives a backend implements; keys are the layout's paths
    @abstractmethod
    def _get(self, key: str) -> tuple[bytes, str | None] | None: ...

    @abstractmethod
    def _put(self, key: str, data: bytes, labels: Mapping[str, str] | None = None) -> None: ...

    @abstractmethod
    def _delete(self, key: str) -> None: ...

    @abstractmethod
    def _keys(self, prefix: str) -> list[str]: ...

    @abstractmethod
    def describe(self) -> str: ...

    @abstractmethod
    def presign_put(self, key: str, expires: timedelta = timedelta(hours=1)) -> str: ...

    @abstractmethod
    def presign_get(self, key: str, expires: timedelta = timedelta(hours=1)) -> str: ...

    def _check_space(self) -> None:  # noqa: B027 -- optional: only a backend with a local disk overrides it
        """A backend with a local disk refuses a write that would fill it."""

    def _select(self, key: str, where: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None] | None:
        """Rows of ``key`` matching ``where``, filtered where the data lives; None when the object is absent."""
        found = self._get(key)
        if found is None:
            return None
        return [r for r in _parse_lines(found[0], key) if matches(r, where)], found[1]

    def _object_may_match(self, key: str, kind: str | None) -> bool:
        return True

    # --- reads ---
    def index(self) -> list[dict[str, Any]]:
        found = self._get("index.jsonl")
        return _parse_lines(found[0], "index.jsonl") if found else []

    def get_facts(self, sha256: str) -> bytes | None:
        """The facts.json stored under ``sha256``; a file whose content no longer hashes to it is dropped with a
        warning and reported absent, so the task recomputes."""
        key = f"facts/{sha256}.json"
        found = self._get(key)
        if found is None:
            return None
        if hashlib.sha256(found[0]).hexdigest() != sha256:
            log.warning("memory %s: %s no longer matches its sha256; dropped, the task recomputes", self.describe(), key)
            self._delete(key)
            return None
        return found[0]

    def get_blob(self, prefix: str, name: str, *, verify: bool = True) -> bytes | None:
        """The blob ``<prefix>/<name>``. With ``verify`` (a content-addressed blob) one whose content no longer hashes
        to its name is dropped with a warning and reported absent; keyed blobs (an embedding by its excerpt's sha, a
        response by its request's sha) pass ``verify=False``."""
        key = blob_key(prefix, name)
        found = self._get(key)
        if found is None:
            return None
        if verify and hashlib.sha256(found[0]).hexdigest() != name:
            log.warning("memory %s: %s no longer matches its sha256; dropped", self.describe(), key)
            self._delete(key)
            return None
        return found[0]

    def rows(
        self, repo: str | None = None, pin: str | None = None, kind: str | None = None, where: Mapping[str, Any] | None = None
    ) -> list[Record]:
        """Rows filtered by repository, pin, kind and top-level equality on ``where``, in key then id order. An unknown
        kind or a ``where`` field the kind does not declare in ``QUERY_FIELDS`` is refused (:func:`check_query`)."""
        check_query(kind, where)
        prefix = f"repos/{repo_dir(repo)}/" if repo else "repos/"
        keys = [k for k in self._keys(prefix) if k.endswith(".jsonl") and (pin is None or k.endswith(f"/{pin}.jsonl"))]
        wanted = {**(where or {}), **({"kind": kind} if kind else {})}
        records: list[Record] = []
        for key in sorted(keys):
            if not self._object_may_match(key, kind):
                continue
            selected = self._select(key, wanted)
            if selected is not None:
                records.extend(Record(r, key, selected[1]) for r in sorted(selected[0], key=lambda r: str(r["id"])))
        return records

    # --- writes ---
    def put_facts(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        key = f"facts/{sha}.json"
        if self._get(key) is None:
            self._check_space()
            self._put(key, data)
        return sha

    def put_blob(self, prefix: str, data: bytes, *, name: str | None = None) -> str:
        """Store ``data`` under ``<prefix>/<sha256(data)>`` (content-addressed; identical data stored once) or under
        ``name`` when the blob is keyed by something else (the excerpt an embedding is of). A blob already present is
        not rewritten: a key names one content. Returns the name."""
        name = name or hashlib.sha256(data).hexdigest()
        key = blob_key(prefix, name)
        if self._get(key) is None:
            self._check_space()
            self._put(key, data)
        return name

    def blob_names(self, prefix: str) -> list[str]:
        """The names of the blobs under ``prefix``, sorted."""
        blob_key(prefix, "0" * 64)
        suffix = BLOB_SUFFIX.get(prefix.split("/", 1)[0], ".json")
        return sorted(k.rsplit("/", 1)[1].removesuffix(suffix) for k in self._keys(prefix + "/") if k.count("/") == prefix.count("/") + 1)

    def put_row(self, row: Mapping[str, Any]) -> None:
        self.put_rows([row])

    def put_rows(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """Merge rows into their repository + pin objects by ``id`` (a repeated id replaces the stored row)."""
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for index, row in enumerate(rows):
            checked = normalise_row(validate_row(dict(row), f"row {index}"), f"row {index}")
            groups.setdefault(f"repos/{repo_dir(checked['repo'])}/{checked['pin']}.jsonl", {})[checked["id"]] = checked
        if groups:
            self._check_space()
        for key, new in sorted(groups.items()):
            found = self._get(key)
            merged = {str(r["id"]): normalise_row(r) for r in (_parse_lines(found[0], key) if found else [])}
            merged.update(new)
            ordered = [merged[i] for i in sorted(merged)]
            self._put(key, "".join(_line(r) + "\n" for r in ordered).encode("utf-8"), _labels(ordered))

    def drop_rows(self, repo: str, pin: str, ids: Iterable[str]) -> int:
        """Remove the rows ``ids`` from one repository + pin object (a rebuild that no longer produces them); returns
        how many were removed. The object is deleted when it ends up empty."""
        key = f"repos/{repo_dir(repo)}/{pin}.jsonl"
        found = self._get(key)
        unwanted = set(ids)
        if found is None or not unwanted:
            return 0
        rows = _parse_lines(found[0], key)
        kept = [normalise_row(r) for r in rows if str(r["id"]) not in unwanted]
        if len(kept) == len(rows):
            return 0
        if kept:
            self._put(key, "".join(_line(r) + "\n" for r in kept).encode("utf-8"), _labels(kept))
        else:
            self._delete(key)
        return len(rows) - len(kept)

    def ingest_rows(self, run: str, task: str, rows: Sequence[Mapping[str, Any]], facts: bytes | None = None) -> IngestResult:
        """One (run, task)'s rows and facts; a repeat of the same rows is skipped by the index."""
        checked = [validate_row(dict(r), f"{run}/{task} row {i + 1}") for i, r in enumerate(rows)]
        digest = rows_digest(checked)
        kinds: dict[str, int] = {}
        for row in checked:
            kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
        index = self.index()
        if any(e.get("run") == run and e.get("task") == task and e.get("sha256") == digest for e in index):
            return IngestResult(run, task, len(checked), True, kinds)
        self._check_space()
        if facts is not None:
            self.put_facts(facts)
        self.put_rows(checked)
        entry = {"run": run, "task": task, "sha256": digest, "rows": len(checked), "ingested": _now()}
        self._put("index.jsonl", "".join(_line(e) + "\n" for e in [*index, entry]).encode("utf-8"))
        return IngestResult(run, task, len(checked), False, kinds)

    def normalise(self, *, dry_run: bool = False) -> dict[str, int]:
        """Rewrite every row object to the fixed schema (every ``QUERYABLE`` field a string, ``""`` where it was
        absent or ``null``), once, before a store moves to a server that infers its schema (RustFS). Idempotent: an
        object already in the schema is not rewritten. On a versioned bucket a rewrite is a new object version; the
        old stays citable. A queryable field of another type fails naming its object and row. Returns counts:
        objects seen and rewritten, rows seen and changed, fields filled."""
        out = {"objects": 0, "objects_rewritten": 0, "rows": 0, "rows_changed": 0, "fields_filled": 0}
        for key in sorted(k for k in self._keys("repos/") if k.endswith(".jsonl")):
            found = self._get(key)
            if found is None:
                continue
            rows = _parse_lines(found[0], key)
            fixed = [normalise_row(r, f"{key}:{n}") for n, r in enumerate(rows, 1)]
            filled = [sum(r.get(f) is None for f in QUERYABLE) for r in rows]
            out["objects"] += 1
            out["rows"] += len(rows)
            out["rows_changed"] += sum(1 for n in filled if n)
            out["fields_filled"] += sum(filled)
            if any(filled):
                out["objects_rewritten"] += 1
                if not dry_run:
                    self._check_space()
                    self._put(key, "".join(_line(r) + "\n" for r in fixed).encode("utf-8"), _labels(fixed))
        return out


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _parse_lines(data: bytes, where: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except ValueError as exc:
            raise MemoryStoreError(f"{where}:{number}: not JSON ({exc})") from exc
        if not isinstance(row, dict):
            raise MemoryStoreError(f"{where}:{number}: not a JSON object")
        rows.append(row)
    return rows


def _labels(rows: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """Object metadata/tags: per field the distinct values of the object's rows, space-joined, S3-safe, <=256."""
    labels: dict[str, str] = {}
    for name in TAG_FIELDS:
        values = sorted({_TAG_VALUE.sub("_", str(r[name])) for r in rows if r.get(name) not in (None, "")})
        text = " ".join(values)
        labels[name] = text if len(text) <= 256 else "*"  # "*": too many to list; the object may match anything
    return labels


# --- the file backend ----------------------------------------------------------------------------------------------


class FileStore(MemoryStore):
    """The layout under a directory: this laptop's store and the unit tests'."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def describe(self) -> str:
        return f"file://{self.root}"

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise MemoryStoreError(f"{key!r} escapes the store {self.root}")
        return path

    def _check_space(self) -> None:
        probe = self.root
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        free = shutil.disk_usage(probe).free
        if free < MIN_FREE_BYTES:
            raise MemoryStoreError(
                f"refusing to write the memory store at {self.root}: {free / (1 << 30):.2f} GiB free, below 1 GiB "
                "(free space, or set OUSAST_MEMORY to another store; `ousast plane remember <run>` repeats the ingest)"
            )

    def _get(self, key: str) -> tuple[bytes, str | None] | None:
        path = self._path(key)
        if not path.is_file():
            return None
        data = path.read_bytes()
        return data, "sha256:" + hashlib.sha256(data).hexdigest()  # a file has no version: its content names it

    def _put(self, key: str, data: bytes, labels: Mapping[str, str] | None = None) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as sink:
                sink.write(data)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def _keys(self, prefix: str) -> list[str]:
        base = self._path(prefix)
        if not base.is_dir():
            return []
        return sorted(p.relative_to(self.root.resolve()).as_posix() for p in base.rglob("*") if p.is_file() and not p.name.startswith("."))

    def presign_put(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self._path(key).as_uri()

    def presign_get(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self._path(key).as_uri()


# --- the S3 backend ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpiryRule:
    """One bucket lifecycle rule as :meth:`S3Store.verify_bucket` reads it: ``prefix`` is the filter's key prefix
    (``""`` for a bucket-wide rule), ``tagged`` whether tags also narrow it, ``days`` its current-version
    expiration in days (None: no expiration by days), ``expires`` whether it expires current versions at all."""

    rule_id: str
    prefix: str
    days: int | None
    enabled: bool
    tagged: bool = False
    expires: bool = True


class ObjectClient(Protocol):
    """The object operations :class:`S3Store` needs; :class:`S3Client` adapts boto3, tests fake it. The
    bucket-configuration calls only read: the store never configures its bucket."""

    def get(self, key: str) -> tuple[bytes, str | None] | None: ...
    def put(self, key: str, data: bytes, labels: Mapping[str, str]) -> None: ...
    def delete(self, key: str) -> None: ...
    def keys(self, prefix: str) -> list[str]: ...
    def tags(self, key: str) -> dict[str, str]: ...
    def version(self, key: str) -> str | None: ...
    def select(self, key: str, expression: str) -> bytes: ...
    def presign(self, method: str, key: str, expires: timedelta) -> str: ...
    def versioning(self) -> str: ...
    def lifecycle(self) -> list[ExpiryRule]: ...


_VERIFIED: set[str] = set()
PROBE_KEY = "_probe/select.jsonl"
# Live finding: files.because-security.com denies presigned GETs ending in .tar, .gz,
# .zip or .bin (HTTP 403 AccessDenied). Use .dat for archive objects; bytes stay tar.
PRESIGNED_ARCHIVE_SUFFIX = ".dat"  # engine executors only; the plane keeps output.tar

RUNS_PREFIX = "runs/"
RUNS_RULE_ID = "ousast-runs-expiry"
RUNS_EXPIRE_DAYS = 30


def _code(exc: Exception) -> str | None:
    """The server's error code: a ``code`` attribute, or botocore's ``response["Error"]["Code"]``."""
    code = getattr(exc, "code", None)
    if code is None:
        response = getattr(exc, "response", None)
        if isinstance(response, Mapping):
            code = (response.get("Error") or {}).get("Code")
    return None if code is None else str(code)


def _failure(exc: Exception) -> str:
    return f"{_code(exc) or type(exc).__name__}: {str(exc)[:200]}"


class S3Store(MemoryStore):
    """The layout in one bucket (optionally under a prefix): object metadata and tags on every row object, S3
    Select pushdown for every filtered read, bucket versioning for provenance, lifecycle expiry for ``runs/``,
    presigned URLs. An admin configures the bucket once; opening a store verifies it (:meth:`verify_bucket`) and
    refuses a bucket without versioning, the ``runs/`` expiry rule or S3 Select. There is no local fallback."""

    def __init__(self, client: ObjectClient, bucket: str, prefix: str = "", *, read_only: bool = False) -> None:
        self.client, self.bucket, self.prefix = client, bucket, prefix.strip("/")
        self.read_only = read_only
        if not read_only and self.describe() not in _VERIFIED:
            self.verify_bucket()
            _VERIFIED.add(self.describe())

    def describe(self) -> str:
        return f"s3://{self.bucket}" + (f"/{self.prefix}" if self.prefix else "")

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def _get(self, key: str) -> tuple[bytes, str | None] | None:
        return self.client.get(self._k(key))

    def _put(self, key: str, data: bytes, labels: Mapping[str, str] | None = None) -> None:
        self._writable()
        self.client.put(self._k(key), data, dict(labels or {}))

    def _delete(self, key: str) -> None:
        self._writable()
        self.client.delete(self._k(key))

    def _keys(self, prefix: str) -> list[str]:
        cut = len(self.prefix) + 1 if self.prefix else 0
        return sorted(k[cut:] for k in self.client.keys(self._k(prefix)))

    def _object_may_match(self, key: str, kind: str | None) -> bool:
        """Filter by tag instead of reading: an object whose ``kind`` tag lacks ``kind`` holds no such row."""
        if kind is None:
            return True
        tagged = self.client.tags(self._k(key)).get("kind")
        return tagged is None or tagged == "*" or kind in tagged.split()

    def _writable(self) -> None:
        if self.read_only:
            raise MemoryStoreError("read-only store")

    def verify_bucket(self) -> None:
        """Check the admin's one-time setup, writing only the capability probe: versioning ``Enabled``, an enabled
        lifecycle rule expiring ``<prefix>/runs/`` and none expiring the whole store, S3 Select answering a probe
        over JSON Lines, and the probe's object tags readable. Every missing piece is named with its admin action
        in one :class:`MemoryStoreError`."""
        self._writable()
        runs = self._k(RUNS_PREFIX)
        endpoint = '--endpoint-url "$S3_ENDPOINT"'
        missing: list[str] = []
        try:
            status = self.client.versioning()
        except Exception as exc:  # noqa: BLE001 -- any failure is named; the store does not start
            missing.append(
                f"versioning cannot be read ({_failure(exc)}): the agent needs s3:GetBucketVersioning on "
                f"arn:aws:s3:::{self.bucket}, and versioning must be Enabled"
            )
        else:
            if status != "Enabled":
                missing.append(
                    f"versioning is {status or 'Off'}, it must be Enabled (provenance cites object versions). Admin: "
                    f"aws s3api put-bucket-versioning {endpoint} --bucket {self.bucket} "
                    "--versioning-configuration Status=Enabled"
                )
        rule_json = (
            f'{{"Rules":[{{"ID":"{RUNS_RULE_ID}","Status":"Enabled","Filter":{{"Prefix":"{runs}"}},'
            f'"Expiration":{{"Days":{RUNS_EXPIRE_DAYS}}}}}]}}'
        )
        lifecycle_admin = (
            f"Admin (merged with any rules the bucket already has): aws s3api put-bucket-lifecycle-configuration "
            f"{endpoint} --bucket {self.bucket} --lifecycle-configuration '{rule_json}'"
        )
        try:
            rules = self.client.lifecycle()
        except Exception as exc:  # noqa: BLE001
            missing.append(
                f"the lifecycle configuration cannot be read ({_failure(exc)}): the agent needs "
                f"s3:GetLifecycleConfiguration on arn:aws:s3:::{self.bucket}, and a rule must expire {runs}"
            )
        else:
            live = [r for r in rules if r.enabled and r.expires]
            store_root = self._k("")
            wide = [r.rule_id for r in live if store_root.startswith(r.prefix)]
            if wide:
                missing.append(
                    f"lifecycle rule(s) {', '.join(wide)} expire the whole store (repos/, facts/ and the index would be "
                    f"deleted); limit them to {runs}"
                )
            if not any(r.prefix in (runs, runs.rstrip("/")) and not r.tagged and r.days for r in live):
                missing.append(f"no enabled lifecycle rule expires {runs} after a number of days. {lifecycle_admin}")
        try:
            self.client.put(self._k(PROBE_KEY), b'{"probe":1}\n{"probe":2}\n', {})
            got = _parse_lines(self.client.select(self._k(PROBE_KEY), where_sql({"probe": 1})), PROBE_KEY)
            select_error = "" if got == [{"probe": 1}] else f"the probe returned {got!r}"
        except Exception as exc:  # noqa: BLE001
            select_error = _failure(exc)
        try:
            self.client.tags(self._k(PROBE_KEY))
        except Exception as exc:  # noqa: BLE001
            missing.append(
                f"object tags cannot be read on {self._k(PROBE_KEY)} ({_failure(exc)}): the store filters row objects by "
                f"their kind tag, so the agent needs s3:GetObjectTagging on arn:aws:s3:::{self.bucket}/*"
            )
        if select_error:
            missing.append(
                f"S3 Select (SelectObjectContent over JSON Lines) does not answer on {self._k(PROBE_KEY)} "
                f"({select_error}). The store requires it and has no local fallback: use a server with S3 Select "
                "(RustFS has it; not every S3-compatible server does) and let the agent s3:PutObject and s3:GetObject"
            )
        if missing:
            raise MemoryStoreError(
                f"memory {self.describe()}: the bucket is not set up for the store. The store never configures its "
                "bucket (an admin sets it once, the store verifies); missing:\n" + "\n".join(f"  - {m}" for m in missing)
            )

    def _select(self, key: str, where: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None] | None:
        if not where:
            return super()._select(key, where)  # no filter: the whole object is the answer
        version = self.client.version(self._k(key))  # stat, then select: Select takes no version id
        if version is None and self.client.get(self._k(key)) is None:
            return None
        try:
            return _parse_lines(self.client.select(self._k(key), where_sql(where)), key), version
        except Exception as exc:
            hint = ""
            if _code(exc) == "EvaluatorBindingDoesNotExist":
                # RustFS infers an object's JSON schema from its leading rows: a field missing there is unbound even
                # when later rows carry it, so "no rows" would be a guess. Measured 2026-10-02 (field at row 5000).
                hint = f" (a field of {sorted(where)} is absent from the object's leading rows, which the server reads as its schema)"
            raise MemoryStoreError(
                f"memory {self.describe()}: S3 Select on {key} failed ({_failure(exc)}){hint}; the store has no local fallback"
            ) from exc

    def presign_put(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        self._writable()
        return self.client.presign("PUT", self._k(key), expires)

    def presign_get(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self.client.presign("GET", self._k(key), expires)


_MISSING_OBJECT = ("NoSuchKey", "NoSuchObject", "NotFound", "404")


class S3Client:
    """:class:`ObjectClient` over boto3's S3 client; imported lazily so the core install needs no SDK. Path-style
    addressing and SigV4, as RustFS needs; the SDK's own checksum trailers stay off because not every S3-compatible
    server accepts them."""

    def __init__(
        self, endpoint: str, access_key: str, secret_key: str, bucket: str, region: str | None = None, session_token: str | None = None
    ) -> None:
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise MemoryStoreError("OUSAST_MEMORY=s3://... needs boto3: install openultrasast[s3]") from exc
        options: dict[str, Any] = {"signature_version": "s3v4", "s3": {"addressing_style": "path"}}
        try:
            config = Config(request_checksum_calculation="when_required", response_checksum_validation="when_required", **options)
        except TypeError:  # botocore before 1.36 has no checksum options and sends no trailers either
            config = Config(**options)
        self.sdk = boto3.client(
            "s3", endpoint_url=endpoint, aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            aws_session_token=session_token, region_name=region or "us-east-1", config=config,
        )  # fmt: skip
        self.bucket = bucket

    @staticmethod
    def _missing(exc: Exception) -> bool:
        return _code(exc) in _MISSING_OBJECT

    def get(self, key: str) -> tuple[bytes, str | None] | None:
        from botocore.exceptions import ClientError

        try:
            response = self.sdk.get_object(Bucket=self.bucket, Key=key)
        except ClientError as exc:
            if self._missing(exc):
                return None
            raise
        body = response["Body"]
        try:
            data: bytes = body.read()
        finally:
            body.close()
        version = response.get("VersionId")
        return data, None if version in (None, "null") else str(version)

    def put(self, key: str, data: bytes, labels: Mapping[str, str]) -> None:
        from urllib.parse import quote, urlencode

        extra: dict[str, Any] = {}
        if labels:
            extra["Metadata"] = dict(labels)
            extra["Tagging"] = urlencode(dict(labels), quote_via=quote)
        self.sdk.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType="application/x-ndjson", **extra)

    def delete(self, key: str) -> None:
        self.sdk.delete_object(Bucket=self.bucket, Key=key)

    def keys(self, prefix: str) -> list[str]:
        found: list[str] = []
        for page in self.sdk.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            found.extend(str(o["Key"]) for o in page.get("Contents") or [])
        return sorted(found)

    def versions(self, prefix: str) -> list[tuple[str, str]]:
        """Every (key, version id) under ``prefix``, delete markers included."""
        found: list[tuple[str, str]] = []
        for page in self.sdk.get_paginator("list_object_versions").paginate(Bucket=self.bucket, Prefix=prefix):
            for entry in [*(page.get("Versions") or []), *(page.get("DeleteMarkers") or [])]:
                found.append((str(entry["Key"]), str(entry["VersionId"])))
        return sorted(found)

    def delete_version(self, key: str, version: str) -> None:
        self.sdk.delete_object(Bucket=self.bucket, Key=key, VersionId=version)

    def purge(self, prefix: str) -> int:
        """Remove every version and delete marker under ``prefix`` (a test prefix, a copy that is not wanted);
        returns how many were removed. Nothing of the kind runs on a store's own layout."""
        removed = 0
        for key, version in self.versions(prefix):
            self.delete_version(key, version)
            removed += 1
        return removed

    def tags(self, key: str) -> dict[str, str]:
        response = self.sdk.get_object_tagging(Bucket=self.bucket, Key=key)
        return {str(t["Key"]): str(t["Value"]) for t in response.get("TagSet") or []}

    def version(self, key: str) -> str | None:
        from botocore.exceptions import ClientError

        try:
            version = self.sdk.head_object(Bucket=self.bucket, Key=key).get("VersionId")
        except ClientError as exc:
            if self._missing(exc):
                return None
            raise
        return None if version in (None, "null") else str(version)

    def select(self, key: str, expression: str) -> bytes:
        response = self.sdk.select_object_content(
            Bucket=self.bucket, Key=key, ExpressionType="SQL", Expression=expression,
            InputSerialization={"JSON": {"Type": "LINES"}}, OutputSerialization={"JSON": {"RecordDelimiter": "\n"}},
        )  # fmt: skip
        chunks: list[bytes] = []
        for event in response["Payload"]:  # an error frame mid-stream raises botocore's EventStreamError
            records = event.get("Records")
            if records:
                chunks.append(records["Payload"])
        return b"".join(chunks)

    def presign(self, method: str, key: str, expires: timedelta) -> str:
        operation = "put_object" if method == "PUT" else "get_object"
        return str(
            self.sdk.generate_presigned_url(
                operation, Params={"Bucket": self.bucket, "Key": key}, ExpiresIn=int(expires.total_seconds()), HttpMethod=method
            )
        )

    def versioning(self) -> str:
        return str(self.sdk.get_bucket_versioning(Bucket=self.bucket).get("Status") or "Off")

    def lifecycle(self) -> list[ExpiryRule]:
        from botocore.exceptions import ClientError

        try:
            config = self.sdk.get_bucket_lifecycle_configuration(Bucket=self.bucket)
        except ClientError as exc:
            if _code(exc) == "NoSuchLifecycleConfiguration":
                return []
            raise
        rules: list[ExpiryRule] = []
        for rule in config.get("Rules") or []:
            found = rule.get("Filter") or {}
            joined = found.get("And") or {}
            prefix = joined.get("Prefix") or found.get("Prefix") or rule.get("Prefix") or ""
            tagged = bool(found.get("Tag") or joined.get("Tags"))
            expiration = rule.get("Expiration") or {}
            expires = bool(expiration.get("Days") or expiration.get("Date"))
            days = expiration.get("Days")
            rules.append(ExpiryRule(str(rule.get("ID") or ""), prefix, days, rule.get("Status") == "Enabled", tagged, expires))
        return rules


def s3_settings(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Endpoint, keys, region and session token from ``.env``/the environment; a missing key is named, a value
    never is. ``S3_ENDPOINT`` is a full URL (``https://host[:port]``)."""
    if environ is None:
        from ..config import load_dotenv

        load_dotenv()
        environ = os.environ
    missing = [k for k in S3_KEYS if not environ.get(k)]
    if missing:
        raise MemoryStoreError(f"OUSAST_MEMORY=s3://... needs {', '.join(missing)} in .env or the environment")
    endpoint = environ["S3_ENDPOINT"].strip()
    if urlsplit(endpoint).scheme not in ("http", "https") or not urlsplit(endpoint).netloc:
        raise MemoryStoreError("S3_ENDPOINT must be a URL with a scheme (https://host[:port])")
    settings: dict[str, Any] = {
        "endpoint": endpoint, "access_key": environ["AWS_ACCESS_KEY_ID"], "secret_key": environ["AWS_SECRET_ACCESS_KEY"],
    }  # fmt: skip
    if environ.get("S3_REGION"):
        settings["region"] = environ["S3_REGION"]  # spares a GetBucketLocation the agent may not be allowed
    if environ.get("AWS_SESSION_TOKEN"):
        settings["session_token"] = environ["AWS_SESSION_TOKEN"]
    return settings


def open_store(spec: str | None = None, environ: Mapping[str, str] | None = None, *, read_only: bool = False) -> MemoryStore:
    """The store ``spec`` (else ``OUSAST_MEMORY``, else ``file://<results_root()>/memory``) names. ``s3://`` with no
    bucket uses ``S3_BUCKET``. ``read_only`` skips the S3 write/Select capability probe and refuses S3 mutations;
    it is intended for GET/list inventory readers, which do not need Select. Default opening is unchanged."""
    from .reconciler import results_root

    env = environ if environ is not None else os.environ
    text = spec or env.get("OUSAST_MEMORY") or ""
    if not text:
        return FileStore(results_root() / "memory")
    parts = urlsplit(text)
    if parts.scheme == "file" and parts.path:
        return FileStore(Path(parts.path))
    if parts.scheme == "s3":
        bucket = parts.netloc or env.get("S3_BUCKET") or ""
        if not bucket:
            raise MemoryStoreError("OUSAST_MEMORY=s3:// names no bucket and S3_BUCKET is unset: set one of them")
        settings = s3_settings(environ)
        return S3Store(S3Client(bucket=bucket, **settings), bucket, parts.path, read_only=read_only)
    raise MemoryStoreError(f"OUSAST_MEMORY must be file:///<path> or s3://<bucket>[/<prefix>], got {text!r}")


# --- ingest and seed -----------------------------------------------------------------------------------------------

REMEMBER_OUTPUT = "memory.jsonl"


def read_memory(path: Path) -> list[dict[str, Any]]:
    """A delivered ``memory.jsonl``: every row valid, else the error names the file and line."""
    rows: list[dict[str, Any]] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if raw.strip():
            try:
                rows.append(validate_row(json.loads(raw), f"{path}:{number}"))
            except ValueError as exc:
                raise MemoryStoreError(f"{path}:{number}: {exc}") from exc
    return rows


def ingest(run_dir: Path, store: MemoryStore | None = None) -> list[IngestResult]:
    """Every delivered ``<task>/memory.jsonl`` of ``run_dir`` (and the ``facts.json`` beside it) into the store.
    A run without remember outputs is a no-op that says so; a malformed file fails before anything is written."""
    store = store or open_store()
    delivered = sorted(p for p in Path(run_dir).glob(f"*/{REMEMBER_OUTPUT}") if p.is_file())
    if not delivered:
        log.info("memory: %s has no remember outputs; nothing to ingest", run_dir)
        return []
    parsed = [(path, read_memory(path)) for path in delivered]
    results: list[IngestResult] = []
    for path, rows in parsed:
        facts = path.parent / "facts.json"
        results.append(store.ingest_rows(Path(run_dir).name, path.parent.name, rows, facts.read_bytes() if facts.is_file() else None))
    return results


def seed(run_manifest: Path, store: MemoryStore | None = None, *, results_root: Path | None = None) -> list[str]:
    """Reuse stored facts for a Run's tasks whose ``openultrasast.io/memory-key`` matches (Req 6.1): each such task
    without a directory or a state gets ``facts.json`` and a ``done`` summary and is marked done under the run
    lock. Returns the seeded task names. A changed pin, candidate set or runner image finds nothing and recomputes.
    A ``memory-snapshot`` Task gets the store's rows after the guard its annotation names, marked done likewise."""
    from . import reconciler

    run_spec, manifests = reconciler.load_run(Path(run_manifest))
    store = store or open_store()
    base = reconciler.run_dir(run_spec.metadata.name, results_root)
    state = (reconciler._read_json(base / "state.json") or {}).get("tasks") or {}
    seeded: list[str] = []
    for entry in run_spec.tasks:
        annotations = manifests.tasks[entry.task].metadata.annotations
        text, snapshot = annotations.get(MEMORY_KEY_ANNOTATION), annotations.get(SNAPSHOT_ANNOTATION)
        if not (text or snapshot) or (base / entry.name).exists() or state.get(entry.name, {}).get("status", "pending") != "pending":
            continue
        if snapshot:
            from .tasks.loop import write_snapshot  # lazy: the guard reads the pair catalog and the benchmark manifest

            info = write_snapshot(base / entry.name, store, json.loads(snapshot))
            reused = {"snapshot": store.describe(), **{k: info[k] for k in ("rows", "kept", "index_digest")}}
            reconciler.mark_done(run_spec.metadata.name, entry.name, reused=reused, results_root=results_root)
            seeded.append(entry.name)
            continue
        key = parse_memory_key(str(text))
        where = {"candidates_digest": key["candidates"], "image": key["image"]}
        for record in sorted(store.rows(key["repo"], key["pin"], "facts", where), key=lambda r: str(r.row["run"]), reverse=True):
            data = store.get_facts(str(record.row["sha256"]))
            if data is None:
                continue
            reused = {"sha256": record.row["sha256"], "from_run": record.row["run"], "image": key["image"]}
            (base / entry.name).mkdir(parents=True)
            (base / entry.name / "facts.json").write_bytes(data)
            summary = {"status": "done", "units_done": 1, "units_total": 1, "usd": None, "calls": 0, "usage": {}, "model": None}
            (base / entry.name / "summary.json").write_text(json.dumps({**summary, "reused": reused}, indent=2, sort_keys=True) + "\n")
            reconciler.mark_done(run_spec.metadata.name, entry.name, reused=reused, results_root=results_root)
            seeded.append(entry.name)
            break
    return seeded


def counts(results: Iterable[IngestResult]) -> dict[str, int]:
    total: dict[str, int] = {}
    for result in results:
        for kind, number in result.kinds.items():
            total[kind] = total.get(kind, 0) + number
    return dict(sorted(total.items()))


__all__ = [
    "KINDS",
    "MEMORY_KEY_ANNOTATION",
    "POPULATION_ANNOTATION",
    "QUERYABLE",
    "QUERY_FIELDS",
    "SNAPSHOT_ANNOTATION",
    "SPLIT_ANNOTATION",
    "FileStore",
    "IngestResult",
    "MemoryStore",
    "MemoryStoreError",
    "ObjectClient",
    "S3Client",
    "S3Store",
    "ExpiryRule",
    "Record",
    "check_query",
    "counts",
    "image_digest",
    "ingest",
    "memory_key",
    "normalise_row",
    "open_store",
    "parse_memory_key",
    "repo_key",
    "row_id",
    "s3_settings",
    "seed",
    "validate_row",
    "where_sql",
]
