"""Task artifacts through the memory store (plane-on-kubernetes design section 3, Req 3.1).

A task's runner PUTs its output tar to a presigned URL the reconciler minted, and GETs each declared input from
another; the URLs travel in the start request's ``delivery`` field (a presigned URL is a bearer capability, so it
goes where the credentials go, never into an ActorTemplate's env). The reconciler polls the store for the tar,
extracts it under the run directory with the member checks the old receiver had, re-puts the task's declared
``outputs[]`` as single objects so a consumer's URL names exactly one artifact, and writes ``done.json``. The run's
``state.json`` is mirrored to the store after each change and seeded from it on a rerun elsewhere.

Store layout under the 30-day ``runs/`` expiry rule (``memory.RUNS_RULE_ID``)::

    runs/<run>/state.json                  the reconciler's state, mirrored
    runs/<run>/<task>/output.tar           the runner's PUT
    runs/<run>/<task>/<artifact>           each declared output, re-put by the reconciler
    runs/<run>/<task>/done.json            status, bytes, file count, finished
    runs/<run>/inputs/<name>               an input no task produces (``put_input``)

Nothing here logs or prints a URL.
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .memory import RUNS_PREFIX, MemoryStore

__all__ = ["DONE", "GRACE_SECONDS", "OUTPUT_TAR", "STATE", "Delivery", "DeliveryError", "expiry", "input_var"]

OUTPUT_TAR = "output.tar"
DONE = "done.json"
STATE = "state.json"
INPUTS_DIR = "inputs"
GRACE_SECONDS = 600  # a URL outlives the task timeout by this much; a re-start after a re-resume re-mints anyway
_NAME = re.compile(r"[^A-Z0-9]+")


class DeliveryError(RuntimeError):
    """A delivered tar that cannot be accepted, or an object that is not there; the message never carries a URL."""


def expiry(environ: Mapping[str, str] | None = None) -> timedelta:
    """``OUSAST_TASK_TIMEOUT`` (7200 s) plus :data:`GRACE_SECONDS`."""
    env = os.environ if environ is None else environ
    return timedelta(seconds=float(env.get("OUSAST_TASK_TIMEOUT") or 7200) + GRACE_SECONDS)


def input_var(name: str) -> str:
    """The ``OUSAST_INPUT_<NAME>`` suffix of a Run input name, as the reconciler renders it."""
    return _NAME.sub("_", name.upper())


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Delivery:
    """Presigned URLs, polling, collection and state mirroring for one Run on one store."""

    def __init__(self, store: MemoryStore, run: str, base: Path, *, expires: timedelta | None = None) -> None:
        self.store, self.run, self.base = store, run, base
        self.expires = expires or expiry()

    def key(self, *parts: str) -> str:
        return f"{RUNS_PREFIX}{self.run}/" + "/".join(parts)

    @property
    def host(self) -> str | None:
        """The hostname the runner will dial (for the task's egress policy); None for a store without one."""
        return urlsplit(self.store.presign_get(self.key(STATE), timedelta(seconds=60))).hostname

    # --- the start body -------------------------------------------------------------------------------------------

    def put_url(self, task: str) -> str:
        return self.store.presign_put(self.key(task, OUTPUT_TAR), self.expires)

    def input_urls(self, inputs: Mapping[str, str]) -> dict[str, str]:
        """``{OUSAST_INPUT_<NAME> suffix: presigned GET of runs/<run>/<producer>/<artifact>}``."""
        out: dict[str, str] = {}
        for name, ref in inputs.items():
            producer, _, artifact = ref.partition("/")
            if not producer or not artifact:
                raise DeliveryError(f"input {name}: {ref!r} is not <producer>/<artifact>")
            out[input_var(name)] = self.store.presign_get(self.key(producer, artifact), self.expires)
        return out

    def body(self, task: str, inputs: Mapping[str, str]) -> dict[str, Any]:
        """The start request's ``delivery`` field for ``task``."""
        return {"put": self.put_url(task), "inputs": self.input_urls(inputs)}

    # --- completion ----------------------------------------------------------------------------------------------

    def delivered(self, task: str) -> bool:
        """Whether the runner's tar is in the store (an exact-key listing, the store's HEAD)."""
        key = self.key(task, OUTPUT_TAR)
        return key in self.store._keys(key)

    def collect(self, task: str, outputs: Iterable[str]) -> tuple[dict[str, Any] | None, int]:
        """Download and extract the tar under ``<base>/<task>/``, re-put the declared ``outputs``, write
        ``done.json``; returns (the extracted ``summary.json`` or None, the tar's byte size)."""
        got = self.store._get(self.key(task, OUTPUT_TAR))
        if got is None:
            raise DeliveryError(f"task {task}: output.tar is not in the store")
        data = got[0]
        dest = (self.base / task).resolve()
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
                members = tar.getmembers()
                for m in members:
                    if m.issym() or m.islnk() or not (dest / m.name).resolve().is_relative_to(dest):
                        raise DeliveryError(f"task {task}: rejected member {m.name}")
                dest.mkdir(parents=True, exist_ok=True)
                tar.extractall(dest, members)  # every member checked above
        except tarfile.TarError as exc:
            raise DeliveryError(f"task {task}: bad tar: {exc}") from None
        published = self.publish(task, outputs)
        summary = _read_json(dest / "summary.json")
        done = {
            "task": task,
            "status": summary.get("status") if isinstance(summary, dict) else None,
            "bytes": len(data),
            "files": sum(1 for m in members if m.isfile()),
            "published": published,
            "finished": _now(),
        }
        self.store._put(self.key(task, DONE), json.dumps(done, sort_keys=True).encode("utf-8"))
        return (summary if isinstance(summary, dict) else None), len(data)

    def publish(self, task: str, outputs: Iterable[str]) -> list[str]:
        """Re-put the task's declared outputs that exist under ``<base>/<task>/`` as single objects; the names put."""
        put: list[str] = []
        root = (self.base / task).resolve()
        for artifact in outputs:
            path = (root / artifact).resolve()
            if path.is_relative_to(root) and path.is_file():
                self.store._put(self.key(task, artifact), path.read_bytes())
                put.append(artifact)
        return put

    def put_input(self, name: str, path: Path) -> str:
        """Store a file no task produces as ``runs/<run>/inputs/<name>``; returns its presigned GET URL."""
        self.store._put(self.key(INPUTS_DIR, name), Path(path).read_bytes())
        return self.store.presign_get(self.key(INPUTS_DIR, name), self.expires)

    # --- state ---------------------------------------------------------------------------------------------------

    def save_state(self, data: Mapping[str, Any]) -> None:
        self.store._put(self.key(STATE), (json.dumps(data, indent=2) + "\n").encode("utf-8"))

    def load_state(self) -> dict[str, Any] | None:
        got = self.store._get(self.key(STATE))
        if got is None:
            return None
        try:
            loaded = json.loads(got[0].decode("utf-8"))
        except ValueError:
            return None
        return loaded if isinstance(loaded, dict) else None


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
