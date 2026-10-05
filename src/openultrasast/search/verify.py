"""Offline differential verification through an isolated, batch CLI interface.

Side.command and readiness_args are trusted integration configuration, not demo
contents. TARGET is an executable CLI bridge: each invocation queues arguments
for the app. It deliberately has no synchronous response channel. Alternatively
request.json contains one argument vector. HTTP apps need a trusted CLI adapter;
this lane never treats an artefact's stdout, exit status, or claimed result as
proof. Build scripts validate the immutable checkout and may write scratch only;
only Side.build_command (trusted integration config) can produce /build runtime outputs.

Run: python -m openultrasast.search.verify vulnerable fixed demo path --entry app.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..sandbox import SandboxJob
from . import _sandbox
from .oracles import BrowserExecutor, Canary, oracle_for

_BRIDGE = """#!/usr/bin/python3 -I
import json, sys
with open('/scratch/requests.jsonl', 'a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
"""


@dataclass(frozen=True)
class Side:
    checkout: Path
    command: tuple[str, ...]
    readiness_args: tuple[str, ...] = ("--ready",)
    dependencies: tuple[Path, ...] = ()
    build_command: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunObservation:
    observed: bool
    evidence: str
    elapsed_seconds: float


@dataclass(frozen=True)
class SideRecord:
    outcome: str
    runs: tuple[RunObservation, ...]
    elapsed_seconds: float
    reason: str
    build_seconds: float = 0.0
    ready_seconds: float = 0.0
    run_seconds: float = 0.0
    scratch_peak_bytes: int = 0


@dataclass(frozen=True)
class VerificationRecord:
    outcome: str
    sides: tuple[SideRecord, ...]
    elapsed_seconds: float
    reason: str


def _tree(root: Path) -> str:
    """Read every file; hash names, modes and bytes, refusing links/devices."""
    digest = hashlib.sha256()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("input must be a real directory")
    for path in [root, *sorted(root.rglob("*"))]:
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"links and special files refused: {path.name}")
        digest.update(str(path.relative_to(root)).encode())
        digest.update(str(mode).encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _requests(scratch: Path, demo: Path) -> list[list[str]]:
    path = demo / "request.json"
    if path.is_file():
        values = [json.loads(path.read_text())]
    else:
        queue = scratch / "requests.jsonl"
        if not queue.exists():
            return []
        if queue.is_symlink() or not queue.is_file() or queue.stat().st_size > 65536:
            raise ValueError("invalid request queue")
        values = [json.loads(line) for line in queue.read_text().splitlines()]
    if len(values) > 32 or any(
        not isinstance(v, list) or not all(isinstance(a, str) and "\0" not in a for a in v) or sum(map(len, v)) > 16384 for v in values
    ):
        raise ValueError("invalid or excessive CLI requests")
    return values


def _side(side: Side, demo: Path, family: str, timeout: int, browser: BrowserExecutor | None) -> SideRecord:
    started = time.monotonic()
    observations: list[RunObservation] = []
    timings = dict(build=0.0, ready=0.0, run=0.0)

    disk_peak = 0
    root: Path | None = None

    def timed(stage: str, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        nonlocal disk_peak
        tick = time.monotonic()
        try:
            return operation(*args, **kwargs)
        finally:
            timings[stage] += time.monotonic() - tick
            if root is not None:
                disk_peak = max(disk_peak, sum(p.lstat().st_blocks * 512 for p in root.rglob("*")))

    def record(outcome: str, reason: str) -> SideRecord:
        return SideRecord(
            outcome, tuple(observations), time.monotonic() - started, reason, timings["build"], timings["ready"], timings["run"], disk_peak
        )

    try:
        originals = (side.checkout, *side.dependencies, demo)
        initial = tuple(_tree(p) for p in originals)
        for _ in range(3):
            tick = time.monotonic()
            with tempfile.TemporaryDirectory(prefix="ousast-proof-") as temporary:
                root = Path(temporary)
                checkout = shutil.copytree(side.checkout, root / "checkout")
                artefact = shutil.copytree(demo, root / "demo")
                dependencies = [shutil.copytree(p, root / f"dep-{i}") for i, p in enumerate(side.dependencies)]
                immutable = (checkout, *dependencies, artefact)
                before = tuple(_tree(p) for p in immutable)
                mounts = {f"/deps/{i}": p for i, p in enumerate(dependencies)}

                def job(command: tuple[str, ...], checkout: Path = checkout) -> SandboxJob:
                    return SandboxJob("", command, checkout, {}, timeout, 256, 128)

                products = root / "products"
                products.mkdir()
                if side.build_command:
                    compiled = timed("build", _sandbox.run, job(side.build_command), scratch=products, mounts=mounts)
                    if compiled.exit_code or compiled.timed_out:
                        return record("could_not_build", "trusted build failed: " + compiled.stderr[:300])
                product_hash = _tree(products)
                mounts["/build"] = products
                build_scratch = root / "build"
                build_scratch.mkdir()
                built = timed(
                    "build", _sandbox.run, job(("/bin/sh", "/demo/build.sh")), scratch=build_scratch, mounts={**mounts, "/demo": artefact}
                )
                if built.exit_code or built.timed_out:
                    return record("could_not_build", "build failed: " + built.stderr[:300])
                if tuple(_tree(p) for p in immutable) != before or _tree(products) != product_hash:
                    return record("inconclusive", "build changed immutable inputs")

                oracle = oracle_for(family, browser)
                assert oracle is not None
                try:
                    canary = Canary.fresh(root / "fixture")
                    app_env = oracle.prepare(canary)
                    app_scratch = canary.root if family == "command" else root / "app"
                    app_scratch.mkdir(exist_ok=True)
                    app_mounts = {**mounts, "/fixture": canary.root}
                    ready = timed(
                        "ready",
                        _sandbox.run,
                        job((*side.command, *side.readiness_args)),
                        scratch=app_scratch,
                        mounts=app_mounts,
                        env=app_env,
                        namespace_pid=oracle.namespace_pid,
                    )
                    if ready.exit_code or ready.timed_out:
                        return record("could_not_run", "app readiness failed: " + ready.stderr[:300])
                    if family == "ssrf" and oracle.observe()[0]:
                        return record("inconclusive", "readiness triggered the SSRF oracle")
                    # Readiness cannot supply the attack's evidence or leave a command marker.
                    if family == "command" and any(canary.root.iterdir()):
                        return record("inconclusive", "readiness modified command fixture")
                    attack_scratch = root / "attack"
                    attack_scratch.mkdir()
                    if (artefact / "attack.sh").is_file():
                        bridge = root / "target"
                        bridge.write_text(_BRIDGE)
                        bridge.chmod(0o555)
                        attacker_input = root / "attacker-input"
                        attacker_input.mkdir()
                        attack = timed(
                            "run",
                            _sandbox.run,
                            job(("/bin/sh", "/demo/attack.sh"), checkout=attacker_input),
                            scratch=attack_scratch,
                            mounts={"/demo": artefact, "/target": bridge},
                            env={"TARGET": "/target", "SCRATCH": "/scratch"},
                        )
                        # Output/status are never evidence. Timeout and explicit filesystem
                        # denials veto verification; read-only mounts enforce the boundary.
                        if attack.timed_out:
                            return record("inconclusive", "attack timed out")
                        if "Read-only file system" in attack.stderr or "Permission denied" in attack.stderr:
                            return record("inconclusive", "attacker boundary refused")
                    for arguments in _requests(attack_scratch, artefact):
                        result = timed(
                            "run",
                            _sandbox.run,
                            job((*side.command, *arguments)),
                            scratch=app_scratch,
                            mounts=app_mounts,
                            env=app_env,
                            namespace_pid=oracle.namespace_pid,
                        )
                        if result.timed_out:
                            return record("inconclusive", "app attack timed out")
                        timed("run", oracle.capture, result.stdout)
                    observed, evidence = timed("run", oracle.observe)
                    if (
                        tuple(_tree(p) for p in immutable) != before
                        or tuple(_tree(p) for p in originals) != initial
                        or _tree(products) != product_hash
                    ):
                        return record("inconclusive", "immutable input or dependency changed")
                    observations.append(RunObservation(observed, evidence, time.monotonic() - tick))
                finally:
                    oracle.close()
        return record("observed", "three fresh runs completed")
    except (OSError, ValueError, AssertionError) as exc:
        return record("could_not_run", f"verification unavailable or refused: {exc}")


def verify(
    affected: Side,
    safe: Side,
    artefact: Path,
    family: str,
    *,
    timeout_seconds: int = 5,
    browser: BrowserExecutor | None = None,
) -> VerificationRecord:
    """Affected is vulnerable/head; safe is fixed/base. No negative verdict exists."""
    started = time.monotonic()
    if oracle_for(family, browser) is None:
        return VerificationRecord("no_oracle", (), time.monotonic() - started, "no configured owned oracle for " + family)
    if timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    _sandbox.isolation_check(timeout_seconds=timeout_seconds)
    sides = tuple(_side(s, artefact, family, timeout_seconds, browser) for s in (affected, safe))
    if sides[1].outcome != "observed":
        outcome, reason = "inconclusive", "safe side did not complete build/readiness/verification"
    elif sides[0].outcome != "observed":
        outcome, reason = sides[0].outcome, sides[0].reason
    elif all(r.observed for r in sides[0].runs) and not any(r.observed for r in sides[1].runs):
        outcome, reason = "demonstrated", "owned effect in 3/3 affected runs and 0/3 safe runs"
    else:
        outcome, reason = "inconclusive", "no consistent differential effect"
    return VerificationRecord(outcome, sides, time.monotonic() - started, reason)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("affected", type=Path)
    parser.add_argument("safe", type=Path)
    parser.add_argument("artefact", type=Path)
    parser.add_argument("family")
    parser.add_argument("--entry", required=True, help="trusted Python CLI entry relative to checkout")
    args = parser.parse_args()
    entry = Path(args.entry)
    if entry.is_absolute() or ".." in entry.parts:
        parser.error("entry must stay inside checkout")
    command = ("/usr/bin/python3", "-I", "/workspace/" + str(entry))
    result = verify(Side(args.affected, command), Side(args.safe, command), args.artefact, args.family)
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
