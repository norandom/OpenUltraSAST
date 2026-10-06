"""Key-free AX task entry for one declarative verification repetition."""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import math
import os
import stat
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast
from urllib.parse import urlsplit

from . import task_storage
from .demo import validate_demo, validate_oracle
from .executor import clean_environment
from .verify import Side, SideRecord


def public_endpoint(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if (
        parts.scheme != "https"
        or not host
        or is_ip
        or "." not in host
        or host.endswith((".localhost", ".local", ".internal"))
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
    ):
        raise ValueError("task URL requires public HTTPS hostname")
    return host


MAX_ARCHIVE_BYTES = 1024**3
MAX_CHECKOUT_BYTES = 2 * 1024**3
MAX_FILES = 20000
MAX_SPEC_BYTES = 70000
MAX_RESULT_BYTES = 65536


CACHE_NAMES = {".npm", ".pip", ".m2", ".composer", ".gradle", "__pycache__", ".git"}


def bundle_ignore(directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in CACHE_NAMES or (Path(directory).name == "node_modules" and name == ".cache")}


class ArchiveLimit(ValueError):
    def __init__(self, size: int, directories: dict[str, int]) -> None:
        self.archive_bytes = size
        largest = sorted(directories.items(), key=lambda item: (-item[1], item[0]))[:5]
        super().__init__(
            f"archive exceeds size limit: {size} bytes > {MAX_ARCHIVE_BYTES} bytes; top 5 directories: "
            + ", ".join(f"{name} ({count} bytes)" for name, count in largest)
        )


def pack_checkout(root: Path, output: BinaryIO | None = None) -> bytes:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("checkout must be a real directory")
    buffer = output if output is not None else io.BytesIO()
    total, count = 0, 0
    directories: dict[str, int] = {}
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for parent, dirs, files in os.walk(root, followlinks=False):
            ignored = bundle_ignore(parent, dirs + files)
            dirs[:] = sorted(set(dirs) - ignored)
            for name in sorted(dirs + [name for name in files if name not in ignored]):
                path = Path(parent) / name
                mode = path.lstat().st_mode
                count += 1
                if count > MAX_FILES or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise ValueError("checkout contains too many files or special files")
                size = path.stat().st_size if path.is_file() else 0
                total += size
                if total > MAX_CHECKOUT_BYTES:
                    raise ValueError("checkout exceeds size limit")
                for directory in path.relative_to(root).parents:
                    if str(directory) != ".":
                        directories[str(directory)] = directories.get(str(directory), 0) + size
                archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
    if buffer.tell() > MAX_ARCHIVE_BYTES:
        raise ArchiveLimit(buffer.tell(), directories)
    return cast(io.BytesIO, buffer).getvalue() if output is None else b""


def extract_checkout(data: bytes, destination: Path) -> None:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds size limit")
    # Bound expansion before tarfile parses PAX headers, using disk rather than
    # allocating the entire expanded tree in worker RAM.
    with tempfile.TemporaryFile() as expanded:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            maximum = MAX_CHECKOUT_BYTES + MAX_FILES * 4096
            while block := compressed.read(min(65536, maximum - expanded.tell() + 1)):
                expanded.write(block)
                if expanded.tell() > maximum:
                    raise ValueError("expanded checkout exceeds size limit")
        expanded.seek(0)
        destination.mkdir(parents=True)
        total, seen = 0, set()
        with tarfile.open(fileobj=expanded, mode="r:") as archive:
            for index, member in enumerate(archive):
                path = PurePosixPath(member.name)
                if (
                    index >= MAX_FILES
                    or path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or "\\" in member.name
                    or member.name in seen
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError("unsafe checkout archive member")
                seen.add(member.name)
                total += member.size
                if member.size < 0 or total > MAX_CHECKOUT_BYTES:
                    raise ValueError("expanded checkout exceeds size limit")
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("missing regular checkout member")
                    with source, target.open("xb") as output:
                        remaining = member.size
                        while remaining:
                            block = source.read(min(65536, remaining))
                            if not block:
                                raise ValueError("truncated checkout member")
                            output.write(block)
                            remaining -= len(block)
                    target.chmod(0o755 if member.mode & 0o111 else 0o644)
    if not seen:
        raise ValueError("empty checkout")
    print(f"checkout_bytes={total} checkout_entries={len(seen)}", flush=True)


def validate_spec(spec: Any) -> dict[str, Any]:
    if not isinstance(spec, dict) or set(spec) != {"demo", "family", "timeout_seconds"}:
        raise ValueError("invalid verification spec")
    if len(json.dumps(spec, allow_nan=False).encode()) > MAX_SPEC_BYTES:
        raise ValueError("oversized verification spec")
    validate_demo(spec["demo"])
    if spec["demo"]["build"]["recipe"] != "none":
        raise ValueError("verifier requires executor-built archive; builds are forbidden")
    validate_oracle(spec["family"], spec["demo"]["oracle"])
    timeout = spec["timeout_seconds"]
    if type(timeout) is not int or not math.isfinite(timeout) or not 1 <= timeout <= 300:
        raise ValueError("invalid verification timeout")
    return cast(dict[str, Any], spec)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise ValueError("presigned redirects refused")


def download(url: str, limit: int, *, readiness_budget: float = 60) -> bytes:
    """The first object read tolerates the task egress policy's startup delay."""
    public_endpoint(url)
    end = time.monotonic() + readiness_budget
    delay = 1.0
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    while True:
        try:
            with opener.open(url, timeout=max(0.01, min(30, end - time.monotonic()))) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("oversized task input")
            return cast(bytes, data)
        except urllib.error.HTTPError as exc:
            if exc.code != 403 and not 500 <= exc.code < 600:
                raise OSError("task input download failed") from None
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= end:
            raise OSError("task input egress not ready before download deadline") from None
        time.sleep(min(delay, end - time.monotonic()))
        delay = min(delay * 2, 8)


def upload(url: str, data: bytes) -> None:
    public_endpoint(url)
    if len(data) > MAX_RESULT_BYTES:
        raise ValueError("oversized task result")
    request = urllib.request.Request(url, data=data, method="PUT")
    with urllib.request.build_opener(_NoRedirect).open(request, timeout=30) as response:
        if not 200 <= response.status < 300:
            raise ValueError("result upload failed")


def run_side(side: Side, demo: Path, family: str, timeout_seconds: int) -> SideRecord:
    from openultrasast.search.verify import verify_side_task

    return verify_side_task(side, demo, family, timeout_seconds)


def task_main() -> None:
    if any(
        value and any(word in key.upper() for word in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"))
        for key, value in os.environ.items()
    ):
        raise ValueError("verification task refuses inherited credentials")
    urls = {key: os.environ[key] for key in ("VERIFY_INPUT_URL", "RESULT_URL")}
    for url in urls.values():
        public_endpoint(url)
    scratch_limit = task_storage.configure()
    os.environ.clear()
    os.environ.update(clean_environment())
    os.environ["OUSAST_SCRATCH_BYTES"] = str(scratch_limit)
    archive = download(urls["VERIFY_INPUT_URL"], MAX_ARCHIVE_BYTES)
    with tempfile.TemporaryDirectory(prefix="ousast-verify-task-") as temporary:
        root = Path(temporary)
        try:
            extract_checkout(archive, root / "input")
            task_storage.check(task_storage.WORKSPACE if task_storage.WORKSPACE.is_dir() else root)
            bundle = root / "input"
            if {p.name for p in bundle.iterdir()} != {"checkout", "products", "spec.json"}:
                raise ValueError("expected built checkout, products and spec in one executor archive")
            spec = validate_spec(json.loads((bundle / "spec.json").read_bytes()))
            demo = root / "demo"
            demo.mkdir()
            (demo / "demo.json").write_text(json.dumps(spec["demo"]))
            result = run_side(Side(bundle / "checkout", products=bundle / "products"), demo, spec["family"], spec["timeout_seconds"])
        except task_storage.ScratchLimit as exc:
            result = SideRecord("could_not_build", (), 0, task_storage.exception_reason(exc), isolation_mode="task-boundary")
        upload(urls["RESULT_URL"], json.dumps(asdict(result)).encode())


if __name__ == "__main__":
    task_main()
