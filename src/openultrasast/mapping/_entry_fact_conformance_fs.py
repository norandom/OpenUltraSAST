"""No-follow filesystem primitives for the conformance handoff."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class ConformanceFilesystemError(ValueError):
    """A handoff path was redirected or was not the required node type."""


def _open_flags(*flags: int) -> int:
    result = 0
    for flag in flags:
        result |= flag
    return result


def _read_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while chunk := os.read(fd, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def read_regular_nofollow(path: Path) -> bytes:
    """Read one regular file without following its final path component."""
    flags = _open_flags(os.O_RDONLY, os.O_NOFOLLOW, os.O_NONBLOCK)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConformanceFilesystemError("path is not a readable regular file") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ConformanceFilesystemError("path is not a regular file")
        return _read_fd(fd)
    except OSError as exc:
        raise ConformanceFilesystemError("regular file could not be read") from exc
    finally:
        os.close(fd)


def require_real_directory(path: Path) -> None:
    """Require an existing directory whose final component is not a symlink."""
    flags = _open_flags(os.O_RDONLY, os.O_DIRECTORY, os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConformanceFilesystemError("path is not a real directory") from exc
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ConformanceFilesystemError("path is not a real directory")
    finally:
        os.close(fd)


def ensure_real_directory(path: Path) -> None:
    """Create a directory if absent, then reject redirected final components."""
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConformanceFilesystemError("directory could not be created") from exc
    require_real_directory(path)


def flat_regular_census(path: Path) -> tuple[str, ...]:
    """Return direct regular-file names and reject every other entry.

    Whole-directory validation assumes no concurrent writer. Opening both the
    directory and subsequently read files with ``O_NOFOLLOW`` closes the usual
    check-to-open symlink race for each operation.
    """
    flags = _open_flags(os.O_RDONLY, os.O_DIRECTORY, os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConformanceFilesystemError("census root is not a real directory") from exc
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise ConformanceFilesystemError("census root is not a real directory")
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                if not entry.is_file(follow_symlinks=False) or entry.is_symlink():
                    raise ConformanceFilesystemError("census contains an unsafe entry")
                names.append(entry.name)
        return tuple(sorted(names))
    except OSError as exc:
        raise ConformanceFilesystemError("directory census failed") from exc
    finally:
        os.close(fd)


def persist_regular_nofollow(path: Path, content: bytes) -> None:
    """Create an immutable-addressed file or verify an existing regular file."""
    flags = _open_flags(os.O_CREAT, os.O_EXCL, os.O_WRONLY, os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        if read_regular_nofollow(path) != content:
            raise ConformanceFilesystemError("existing digest file has different bytes") from None
        return
    except OSError as exc:
        raise ConformanceFilesystemError("digest file could not be created") from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ConformanceFilesystemError("digest file write made no progress")
            view = view[written:]
        os.fsync(fd)
    except OSError as exc:
        raise ConformanceFilesystemError("digest file could not be written") from exc
    finally:
        os.close(fd)


__all__ = [
    "ConformanceFilesystemError",
    "ensure_real_directory",
    "flat_regular_census",
    "persist_regular_nofollow",
    "read_regular_nofollow",
    "require_real_directory",
]
