"""The key of the ledger a scan keeps for a tree it could not write into: a digest of the tree's files."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path

from .preprocess import IGNORED_DIRS

# The hashed text starts with this, so that a later change of the definition cannot pass for the same key.
_VERSION = b"openultrasast-tree-v1\n"


def _identity(path: Path) -> tuple[int, int] | None:
    """The device and the inode of `path`: the same under every path it is reached by."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    return status.st_dev, status.st_ino


def _files(root: Path, skipped: tuple[int, int] | None) -> Iterator[tuple[str, Path | None]]:
    """Every file to hash and every directory that could not be listed: its path under `root`, and the file
    (None for a directory that could not be listed), in path order."""
    entries: list[tuple[str, Path | None]] = []

    def unlisted(error: OSError) -> None:
        if error.filename is not None:
            entries.append((Path(os.path.relpath(error.filename, root)).as_posix(), None))

    def kept(name: str, path: Path) -> bool:
        return name not in IGNORED_DIRS and (skipped is None or _identity(path) != skipped)

    for parent, directories, names in os.walk(root, followlinks=False, onerror=unlisted):
        base = Path(parent)
        directories[:] = sorted(name for name in directories if kept(name, base / name))
        for name in names:
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            entries.append((path.relative_to(root).as_posix(), path))
    yield from sorted(entries, key=lambda entry: entry[0])


def tree_digest(target: Path, runs_directory: Path | None = None) -> str:
    """A sha256 of the name and the bytes of every file under `target`, in path order.

    Left out: links; the directories a scan ignores (`IGNORED_DIRS`), so that the ledger in the tree does not
    change its own key; and `runs_directory`, whichever way it is reached. A file that cannot be read and a
    directory that cannot be listed are named `unreadable` instead of a hash, so that neither is skipped in
    silence. Each entry is the length of the path, a colon, the path, a tab and the hash: one path is one entry.
    A directory that can be listed but not searched raises, as the scan's own reading of the tree does.
    """
    digest = hashlib.sha256()
    digest.update(_VERSION)
    skipped = _identity(runs_directory) if runs_directory is not None else None
    for relative, path in _files(target, skipped):
        name = relative.encode("utf-8", "surrogatepass")
        digest.update(f"{len(name)}:".encode("ascii") + name + b"\t")
        digest.update(_hash(path) if path is not None else b"unreadable")
        digest.update(b"\n")
    return digest.hexdigest()


def _hash(path: Path) -> bytes:
    """The sha256 of the file's bytes, read in chunks, or the word `unreadable`."""
    try:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest().encode("ascii")
    except OSError:
        return b"unreadable"
