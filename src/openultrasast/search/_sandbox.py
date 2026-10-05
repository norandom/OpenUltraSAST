"""Local CLI lane using the existing sandbox job/result contract.

Bubblewrap is required, never emulated with chmod. Each process sees only the
immutable runtime, declared inputs, and its own scratch. No host /proc or home.
The seccomp filter denies sockets for artefacts and builds, even on hosts where
creating a network namespace is unavailable. SSRF apps join the oracle's private
loopback namespace. This is a Linux lane; other hosts fail closed.
"""

from __future__ import annotations

import math
import os
import platform
import resource
import signal
import struct
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path

from ..sandbox import SandboxJob, SandboxResult

ARTEFACT_UID = 10001
ARTEFACT_GID = 10001


def isolation_mode() -> str:
    """Root containers need no user namespace; ordinary host callers retain it."""
    return "root-no-userns" if os.geteuid() == 0 else "userns"


def drop_privileges() -> list[str]:
    return [
        "/usr/bin/setpriv",
        f"--reuid={ARTEFACT_UID}",
        f"--regid={ARTEFACT_GID}",
        "--clear-groups",
        "--no-new-privs",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
    ]


def capability_args() -> list[str]:
    # Retain only what the trusted setpriv trampoline needs, then erase the
    # bounding/inheritable/ambient sets before executing any untrusted code.
    args = ["--cap-drop", "ALL"]
    if isolation_mode() == "root-no-userns":
        for capability in ("CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"):
            args += ["--cap-add", capability]
    return args


def writable_directory(path: Path) -> None:
    if isolation_mode() == "root-no-userns":
        os.chown(path, ARTEFACT_UID, ARTEFACT_GID, follow_symlinks=False)


class IsolationUnavailable(RuntimeError):
    """The isolation instrument failed, so no product outcome can be recorded."""


def isolation_check(*, timeout_seconds: float = 5) -> None:
    """Prove a trivial job can read its input through the real sandbox path."""
    try:
        with tempfile.TemporaryDirectory(prefix="isolation-check-") as directory:
            root = Path(directory)
            if isolation_mode() == "root-no-userns":
                root.chmod(0o755)
            (root / "probe").write_text("isolation-ready\n")
            scratch = root / "scratch"
            scratch.mkdir()
            job = SandboxJob("", ("/bin/cat", "/workspace/probe"), root, {}, max(1, math.ceil(timeout_seconds)), 256, 128)
            result = run(job, scratch=scratch, wall_timeout_seconds=timeout_seconds)
    except (OSError, subprocess.SubprocessError) as exc:
        raise IsolationUnavailable(f"sandbox isolation preflight could not start: {exc}") from exc
    if result.exit_code or result.timed_out or result.stdout != "isolation-ready\n":
        raise IsolationUnavailable(
            f"sandbox isolation preflight failed (exit={result.exit_code}, timeout={result.timed_out}): {result.stderr}"
        )


def _filter(network: bool) -> bytes:
    # Audit architecture check also excludes x32 syscall-number bypasses.
    if platform.machine() == "x86_64":
        arch, forbidden = 0xC000003E, [101, 165, 166, 272, 308, 321]
        sockets = [41, 42, 43, 49, 50, 53, 288]
    elif platform.machine() == "aarch64":
        arch, forbidden = 0xC00000B7, [39, 40, 97, 117, 268, 280]
        sockets = [198, 199, 200, 201, 202, 203, 242]
    else:
        raise OSError("unsupported seccomp architecture")
    ins = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (6, 0, 0, 0x80000000), (0x20, 0, 0, 0), (0x35, 0, 1, 0x40000000), (6, 0, 0, 0x80000000)]
    for number in forbidden + ([] if network else sockets):
        ins.extend([(0x15, 0, 1, number), (6, 0, 0, 0x50001)])
    ins.append((6, 0, 0, 0x7FFF0000))
    return b"".join(struct.pack("HBBI", *i) for i in ins)


def run(
    job: SandboxJob,
    *,
    scratch: Path,
    mounts: dict[str, Path] | None = None,
    env: dict[str, str] | None = None,
    namespace_pid: int | None = None,
    scratch_bytes: int | None = None,
    wall_timeout_seconds: float | None = None,
    input_text: str = "",
    network: bool = False,
    writable_checkout: bool = False,
) -> SandboxResult:
    """Run with bounded files, memory, processes, and time; no inherited env."""

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_AS, (job.memory_mb * 1024**2,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (job.timeout_seconds + 1,) * 2)

    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-pid", "--unshare-ipc", "--unshare-uts"]
    mode = isolation_mode()
    if namespace_pid is None:
        if mode == "userns":
            argv += ["--unshare-user"]
    else:
        argv = [
            "/usr/bin/nsenter",
            *(["--preserve-credentials", f"--user=/proc/{namespace_pid}/ns/user"] if mode == "userns" else []),
            f"--net=/proc/{namespace_pid}/ns/net",
            "--",
            *argv,
        ]
    if network and namespace_pid is None:
        argv += ["--unshare-net"]
    argv += [*capability_args(), "--clearenv", "--dev", "/dev"]
    for path in ("/usr", "/lib", "/lib64", "/bin"):
        if Path(path).exists():
            argv += ["--ro-bind", path, path]
    argv += ["--bind" if writable_checkout else "--ro-bind", str(job.repo_root), "/workspace"]
    if scratch_bytes is None:
        writable_directory(scratch)
        argv += ["--bind", str(scratch), "/scratch"]
    else:
        if scratch_bytes < 1:
            raise ValueError("positive scratch limit required")
        argv += ["--size", str(scratch_bytes)]
        if mode == "root-no-userns":
            argv += ["--perms", "0777"]
        argv += ["--tmpfs", "/scratch"]
    for target, source in (mounts or {}).items():
        argv += ["--ro-bind", str(source), target]
    argv += [
        "--remount-ro",
        "/",
        "--chdir",
        "/scratch",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/scratch",
        "--setenv",
        "TMPDIR",
        "/scratch",
    ]
    for key, value in (env or {}).items():
        argv += ["--setenv", key, value]
    with tempfile.TemporaryFile() as policy, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        policy.write(_filter(namespace_pid is not None or network))
        policy.seek(0)
        # Apply NPROC after namespace setup and any uid drop. In root mode the
        # dedicated uid shares this process budget across concurrent sandboxes.
        argv += [
            "--seccomp",
            str(policy.fileno()),
            "--",
            *(drop_privileges() if mode == "root-no-userns" else []),
            "/usr/bin/prlimit",
            f"--nproc={job.pids_limit}:{job.pids_limit}",
            "--",
            *job.command,
        ]
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=out,
            stderr=err,
            pass_fds=(policy.fileno(),),
            start_new_session=True,
            preexec_fn=limits,
            env={"PATH": "/usr/bin:/bin"},
        )
        timed_out = False
        try:
            proc.communicate(
                input=input_text.encode(),
                timeout=min(job.timeout_seconds, wall_timeout_seconds) if wall_timeout_seconds is not None else job.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        finally:
            # Also terminate descendants left behind after a successful shell exit.
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        out.seek(0)
        err.seek(0)
        return SandboxResult(
            proc.returncode, out.read(1024 * 1024).decode(errors="replace"), err.read(1024 * 1024).decode(errors="replace"), timed_out
        )
