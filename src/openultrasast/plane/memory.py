"""The plane's memory store (harnessx-removal Requirement 6.1/6.4, design section 4).

One store, keyed by repository and pin, holds what plane runs learned: repository facts by content hash, and rows
of five kinds (``facts``, ``verdict``, ``unit_cost``, ``alert``, ``proposal_outcome``) that the ``remember`` task
(:mod:`.tasks.remember`) derives from a run's delivered artifacts. Layout, identical for both backends::

    index.jsonl                               one row per ingested (run, task): sha256 of its rows, row count
    facts/<sha256>.json                       facts.json by content (identical facts stored once)
    repos/<host>__<owner>__<name>/<pin>.jsonl the rows of one repository + 40-hex pin, sorted by id

``OUSAST_MEMORY`` selects the backend: ``file:///path`` (:class:`FileStore`, default ``results_root()/memory``) or
``minio://<bucket>[/<prefix>]`` (:class:`MinioStore`, the ``minio`` extra). MinIO's endpoint and credentials come
from ``.env`` (``MINIO_ENDPOINT``, ``MINIO_ACCESS_KEY``, ``MINIO_SECRET_KEY``, ``MINIO_SECURE``), never from a
manifest, and are never printed. Ingest is idempotent: an ``index.jsonl`` hit on (run, task, sha256) skips the
delivery, and rows carry a deterministic ``id``, so a repeated row replaces itself. Every object is written whole
(``FileStore``: a temporary file renamed) and the index last, so an interrupted ingest leaves nothing partial that
a repeat would not repair. ``FileStore`` refuses to write below 1 GiB free and names its path.

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
KINDS = ("facts", "verdict", "unit_cost", "alert", "proposal_outcome")
ROW_FIELDS = ("id", "kind", "repo", "pin", "run", "task", "population", "split", "image")
TAG_FIELDS = ("repo", "pin", "kind", "family", "run", "population", "split")
MIN_FREE_BYTES = 1 << 30
MINIO_KEYS = ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY")
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

    def rows(
        self, repo: str | None = None, pin: str | None = None, kind: str | None = None, where: Mapping[str, Any] | None = None
    ) -> list[Record]:
        """Rows filtered by repository, pin, kind and top-level equality on ``where``, in key then id order."""
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

    def put_row(self, row: Mapping[str, Any]) -> None:
        self.put_rows([row])

    def put_rows(self, rows: Sequence[Mapping[str, Any]]) -> None:
        """Merge rows into their repository + pin objects by ``id`` (a repeated id replaces the stored row)."""
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for index, row in enumerate(rows):
            checked = validate_row(dict(row), f"row {index}")
            groups.setdefault(f"repos/{repo_dir(checked['repo'])}/{checked['pin']}.jsonl", {})[checked["id"]] = checked
        if groups:
            self._check_space()
        for key, new in sorted(groups.items()):
            found = self._get(key)
            merged = {str(r["id"]): r for r in (_parse_lines(found[0], key) if found else [])}
            merged.update(new)
            ordered = [merged[i] for i in sorted(merged)]
            self._put(key, "".join(_line(r) + "\n" for r in ordered).encode("utf-8"), _labels(ordered))

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


# --- the MinIO backend ---------------------------------------------------------------------------------------------


class ObjectClient(Protocol):
    """The object operations :class:`MinioStore` needs; :class:`SdkClient` adapts the ``minio`` SDK, tests fake it."""

    def get(self, key: str) -> tuple[bytes, str | None] | None: ...
    def put(self, key: str, data: bytes, labels: Mapping[str, str]) -> None: ...
    def delete(self, key: str) -> None: ...
    def keys(self, prefix: str) -> list[str]: ...
    def tags(self, key: str) -> dict[str, str]: ...
    def version(self, key: str) -> str | None: ...
    def select(self, key: str, expression: str) -> bytes: ...
    def presign(self, method: str, key: str, expires: timedelta) -> str: ...
    def expire(self, prefix: str, days: int, rule_id: str) -> None: ...
    def enable_versioning(self) -> None: ...


_SELECT_PROBES: dict[str, bool] = {}
PROBE_KEY = "_probe/select.jsonl"


class MinioStore(MemoryStore):
    """The layout in one bucket (optionally under a prefix): object metadata and tags on every row object, S3
    Select pushdown when the server answers it (probed once per process) and a local filter otherwise, bucket
    versioning for provenance, lifecycle expiry for ``runs/``, presigned URLs."""

    def __init__(self, client: ObjectClient, bucket: str, prefix: str = "") -> None:
        self.client, self.bucket, self.prefix = client, bucket, prefix.strip("/")

    def describe(self) -> str:
        return f"minio://{self.bucket}" + (f"/{self.prefix}" if self.prefix else "")

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def _get(self, key: str) -> tuple[bytes, str | None] | None:
        return self.client.get(self._k(key))

    def _put(self, key: str, data: bytes, labels: Mapping[str, str] | None = None) -> None:
        self.client.put(self._k(key), data, dict(labels or {}))

    def _delete(self, key: str) -> None:
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

    def select_supported(self) -> bool:
        """Whether the server answers S3 Select over JSON Lines: one probe per bucket per process."""
        name = self.describe()
        if name not in _SELECT_PROBES:
            try:
                self.client.put(self._k(PROBE_KEY), b'{"probe":1}\n{"probe":2}\n', {})
                got = _parse_lines(self.client.select(self._k(PROBE_KEY), where_sql({"probe": 1})), PROBE_KEY)
                _SELECT_PROBES[name] = got == [{"probe": 1}]
                detail = "" if _SELECT_PROBES[name] else f"; the probe returned {got!r}"
            except Exception as exc:  # noqa: BLE001 -- any failure means "not supported"; the fallback is exact
                _SELECT_PROBES[name], detail = False, f"; {type(exc).__name__}: {str(exc)[:200]}"
            if not _SELECT_PROBES[name]:
                log.warning("memory %s: the server does not answer S3 Select%s; filtering rows locally", name, detail)
        return _SELECT_PROBES[name]

    def _select(self, key: str, where: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str | None] | None:
        if not where or not self.select_supported():
            return super()._select(key, where)
        version = self.client.version(self._k(key))  # stat, then select: Select takes no version id
        if version is None and self.client.get(self._k(key)) is None:
            return None
        try:
            return _parse_lines(self.client.select(self._k(key), where_sql(where)), key), version
        except Exception as exc:  # noqa: BLE001 -- one object's Select failing never loses rows
            log.warning("memory %s: S3 Select on %s failed (%s); filtering it locally", self.describe(), key, type(exc).__name__)
            return super()._select(key, where)

    def presign_put(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self.client.presign("PUT", self._k(key), expires)

    def presign_get(self, key: str, expires: timedelta = timedelta(hours=1)) -> str:
        return self.client.presign("GET", self._k(key), expires)

    def configure(self, runs_expire_days: int = 30) -> None:
        """Bucket versioning on (provenance) and the lifecycle rule expiring ``runs/`` after ``runs_expire_days``;
        ``repos/``, ``facts/`` and ``proposals/`` are kept."""
        if runs_expire_days < 1:
            raise ValueError("runs_expire_days must be at least 1")
        self.client.enable_versioning()
        self.client.expire(self._k("runs/"), runs_expire_days, "ousast-runs-expiry")


class SdkClient:
    """:class:`ObjectClient` over ``minio.Minio``; imported lazily so the core install needs no SDK."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, secure: bool, bucket: str) -> None:
        try:
            from minio import Minio
        except ImportError as exc:
            raise MemoryStoreError("OUSAST_MEMORY=minio://... needs the minio SDK: install openultrasast[minio]") from exc
        self.sdk, self.bucket = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure), bucket

    def get(self, key: str) -> tuple[bytes, str | None] | None:
        from minio.error import S3Error

        try:
            response = self.sdk.get_object(self.bucket, key)
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchObject"):
                return None
            raise
        try:
            return response.read(), response.headers.get("x-amz-version-id")
        finally:
            response.close()
            response.release_conn()

    def put(self, key: str, data: bytes, labels: Mapping[str, str]) -> None:
        import io

        from minio.commonconfig import Tags

        tags = Tags(for_object=True)
        for name, value in labels.items():
            tags[name] = value
        metadata: dict[str, str | list[str] | tuple[str]] = dict(labels)
        self.sdk.put_object(
            self.bucket, key, io.BytesIO(data), len(data), content_type="application/x-ndjson",
            metadata=metadata or None, tags=tags if labels else None,
        )  # fmt: skip

    def delete(self, key: str) -> None:
        self.sdk.remove_object(self.bucket, key)

    def keys(self, prefix: str) -> list[str]:
        return sorted(str(o.object_name) for o in self.sdk.list_objects(self.bucket, prefix=prefix, recursive=True))

    def tags(self, key: str) -> dict[str, str]:
        return dict(self.sdk.get_object_tags(self.bucket, key) or {})

    def version(self, key: str) -> str | None:
        from minio.error import S3Error

        try:
            version = self.sdk.stat_object(self.bucket, key).version_id
            return None if version is None else str(version)
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchObject"):
                return None
            raise

    def select(self, key: str, expression: str) -> bytes:
        from minio.select import JSONInputSerialization, JSONOutputSerialization, SelectRequest

        request = SelectRequest(expression, JSONInputSerialization(json_type="LINES"), JSONOutputSerialization(), request_progress=False)
        with self.sdk.select_object_content(self.bucket, key, request) as result:
            return b"".join(result.stream())

    def presign(self, method: str, key: str, expires: timedelta) -> str:
        if method == "PUT":
            return str(self.sdk.presigned_put_object(self.bucket, key, expires=expires))
        return str(self.sdk.presigned_get_object(self.bucket, key, expires=expires))

    def expire(self, prefix: str, days: int, rule_id: str) -> None:
        from minio.commonconfig import ENABLED, Filter
        from minio.lifecycleconfig import Expiration, LifecycleConfig, Rule

        rule = Rule(ENABLED, rule_filter=Filter(prefix=prefix), rule_id=rule_id, expiration=Expiration(days=days))
        self.sdk.set_bucket_lifecycle(self.bucket, LifecycleConfig([rule]))

    def enable_versioning(self) -> None:
        from minio.commonconfig import ENABLED
        from minio.versioningconfig import VersioningConfig

        self.sdk.set_bucket_versioning(self.bucket, VersioningConfig(ENABLED))


def minio_settings(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Endpoint, keys and TLS from ``.env``/the environment; a missing key is named, a value never is."""
    if environ is None:
        from ..config import load_dotenv

        load_dotenv()
        environ = os.environ
    missing = [k for k in MINIO_KEYS if not environ.get(k)]
    if missing:
        raise MemoryStoreError(f"OUSAST_MEMORY=minio://... needs {', '.join(missing)} in .env or the environment")
    secure = (environ.get("MINIO_SECURE") or "true").strip().lower() not in ("0", "false", "no", "off")
    return {
        "endpoint": environ["MINIO_ENDPOINT"], "access_key": environ["MINIO_ACCESS_KEY"],
        "secret_key": environ["MINIO_SECRET_KEY"], "secure": secure,
    }  # fmt: skip


def open_store(spec: str | None = None, environ: Mapping[str, str] | None = None) -> MemoryStore:
    """The store ``spec`` (else ``OUSAST_MEMORY``, else ``file://<results_root()>/memory``) names."""
    from .reconciler import results_root

    text = spec or (environ if environ is not None else os.environ).get("OUSAST_MEMORY") or ""
    if not text:
        return FileStore(results_root() / "memory")
    parts = urlsplit(text)
    if parts.scheme == "file" and parts.path:
        return FileStore(Path(parts.path))
    if parts.scheme == "minio" and parts.netloc:
        settings = minio_settings(environ)
        return MinioStore(SdkClient(bucket=parts.netloc, **settings), parts.netloc, parts.path)
    raise MemoryStoreError(f"OUSAST_MEMORY must be file:///<path> or minio://<bucket>[/<prefix>], got {text!r}")


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
    "SNAPSHOT_ANNOTATION",
    "SPLIT_ANNOTATION",
    "FileStore",
    "IngestResult",
    "MemoryStore",
    "MemoryStoreError",
    "MinioStore",
    "ObjectClient",
    "Record",
    "SdkClient",
    "counts",
    "image_digest",
    "ingest",
    "memory_key",
    "open_store",
    "parse_memory_key",
    "repo_key",
    "row_id",
    "seed",
    "validate_row",
    "where_sql",
]
