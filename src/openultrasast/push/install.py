"""`ousast pre-push install|uninstall`: the hook as package data (task 17.6, Requirements 7.4, 9.6).

Works from a pip install: the hook script and the Docker wrapper ship inside the wheel. Git's
effective hook directory is resolved (including `core.hooksPath`) and never edited. An existing
hook is never overwritten silently: without `--force` installation refuses; with it the existing
hook moves to `pre-push.before-ousast` and is chained with the same input and arguments.
Uninstall removes only a hook this tool wrote and restores the chained hook.
"""

from __future__ import annotations

import os
import subprocess
from importlib import resources
from pathlib import Path

PRIOR_SUFFIX = ".before-ousast"
# First lines this tool has written into an installed hook: the current one and the 2026-09 one.
_MARKERS = (b"# OpenUltraSAST pre-push safety net.", b"# Explicitly copy using the non-overwriting recipe in ops/README.md.")


def packaged(name: str) -> bytes:
    """The shipped `pre-push` hook or `ousast-docker` wrapper."""
    return resources.files("openultrasast.push").joinpath("hook", name).read_bytes()


def hooks_dir(repository: Path) -> Path:
    out = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--path-format=absolute", "--git-path", "hooks"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if out.returncode != 0:
        raise ValueError(f"{repository} is not a Git repository")
    return Path(os.fsdecode(out.stdout.rstrip(b"\n")))


def ours(path: Path) -> bool:
    try:
        head = path.read_bytes()[:400]
    except OSError:
        return False
    return any(marker in head for marker in _MARKERS)


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), 0o755)


def _exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def install(repository: Path, *, force: bool = False, docker: bool = False) -> tuple[int, list[str]]:
    hooks = hooks_dir(repository)
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-push"
    prior = hooks / ("pre-push" + PRIOR_SUFFIX)
    wrapper = hooks / "ousast-docker"
    lines: list[str] = []
    if _exists(hook):
        if not force:
            what = "an OpenUltraSAST hook is already installed" if ours(hook) else "an existing pre-push hook"
            return 1, [
                f"Installation refused: {what} at {hook}.",
                "Rerun with --force to replace ours, or to move a foreign hook to pre-push.before-ousast and chain it.",
            ]
        if ours(hook):
            hook.unlink()
            lines.append(f"Replaced the OpenUltraSAST hook at {hook}.")
        elif _exists(prior):
            return 1, [f"Installation refused: {prior} already holds a chained hook; resolve it by hand first."]
        else:
            os.rename(hook, prior)
            lines.append(f"Moved the existing hook to {prior}; it runs after the check with the same input.")
    if docker:
        if _exists(wrapper) and not (force and ours_wrapper(wrapper)):
            return 1, [f"Installation refused: {wrapper} exists; rerun with --force to replace it."]
        if _exists(wrapper):
            wrapper.unlink()
        _write(wrapper, packaged("ousast-docker"))
        lines.append(f"Installed the Docker wrapper {wrapper} (image: ghcr.io/norandom/openultrasast:2.0.1; pull it once).")
    _write(hook, packaged("pre-push"))
    lines.insert(0, f"Installed {hook}")
    lines.append("Advisory: the hook never blocks a push unless OUSAST_PUSH_MODE=blocking. Remove with 'ousast pre-push uninstall'.")
    return 0, lines


def ours_wrapper(path: Path) -> bool:
    try:
        return b"OpenUltraSAST in Docker, callable from a Git hook" in path.read_bytes()[:400]
    except OSError:
        return False


def uninstall(repository: Path, *, force: bool = False) -> tuple[int, list[str]]:
    hooks = hooks_dir(repository)
    hook = hooks / "pre-push"
    prior = hooks / ("pre-push" + PRIOR_SUFFIX)
    wrapper = hooks / "ousast-docker"
    if not _exists(hook):
        return 1, [f"Nothing to remove: no pre-push hook at {hook}."]
    if not ours(hook) and not force:
        return 1, [f"Removal refused: {hook} was not written by OpenUltraSAST. Inspect it, or rerun with --force."]
    hook.unlink()
    lines = [f"Removed {hook}"]
    if _exists(wrapper) and ours_wrapper(wrapper):
        wrapper.unlink()
        lines.append(f"Removed {wrapper}")
    if _exists(prior):
        os.rename(prior, hook)
        lines.append(f"Restored the previous hook from {prior}.")
    return 0, lines
