"""Verifier-owned execution of bounded JSON demonstrations and owned oracles.

When namespaces are unavailable, a trusted dispatcher must provide separate fresh
AX tasks for the two sides. There is deliberately no local unsandboxed fallback.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, cast

from ..sandbox import SandboxJob, SandboxResult
from . import _sandbox, task_storage
from .budget import SearchBudget
from .demo import BUILD_RECIPES, FAMILY_ORACLES, RUNTIMES, capture_output, load_demo, substitute, validate_oracle, write_start_files
from .oracles import BrowserExecutor, Canary, Oracle, oracle_for
from .task_storage import CommandFailure, diagnostic, exception_reason


@dataclass(frozen=True)
class Side:
    checkout: Path
    command: tuple[str, ...] = ()
    readiness_args: tuple[str, ...] = ("--ready",)
    dependencies: tuple[Path, ...] = ()
    build_command: tuple[str, ...] = ()
    products: Path | None = None


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
    isolation_mode: str = field(default_factory=_sandbox.isolation_mode)
    chromium_no_sandbox: bool = False
    phase: str = ""
    exit_code: int | None = None
    stderr: str = ""


@dataclass(frozen=True)
class VerificationRecord:
    outcome: str
    sides: tuple[SideRecord, ...]
    elapsed_seconds: float
    reason: str
    isolation_mode: str = field(default_factory=_sandbox.isolation_mode)
    chromium_no_sandbox: bool = False


def _tree(root: Path, *, generated_links: bool = False) -> str:
    """Hash every input byte; only post-build trees may link within themselves."""
    digest = hashlib.sha256()
    if root.is_symlink():
        raise ValueError("input must not be a link")
    if root.is_file():
        digest.update(root.read_bytes())
        return digest.hexdigest()
    if not root.is_dir():
        raise ValueError("input must be a real directory or JSON file")
    paths = [root, *sorted(root.rglob("*"))]
    directory_edges: dict[Path, list[Path]] = {}
    for path in paths:
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) and generated_links:
            try:
                target = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ValueError("dangling or cyclic build link") from exc
            if not target.is_relative_to(root.resolve()):
                raise ValueError("build link escapes its tree")
            if not (target.is_file() or target.is_dir()):
                raise ValueError("build link targets a special file")
            digest.update(str(path.relative_to(root)).encode())
            digest.update(str(mode).encode())
            digest.update(os.readlink(path).encode())
            if target.is_dir():
                directory_edges.setdefault(path.parent.resolve(), []).append(target)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError(f"links and special files refused: {path.name}")
        if path != root and path.is_dir():
            directory_edges.setdefault(path.parent.resolve(), []).append(path.resolve())
        digest.update(str(path.relative_to(root)).encode())
        digest.update(str(mode).encode())
        if path.is_file():
            digest.update(path.read_bytes())
    if generated_links:
        visiting: set[Path] = set()
        visited: set[Path] = set()

        def visit(directory: Path) -> None:
            if directory in visiting:
                raise ValueError("cyclic build directory link")
            if directory in visited:
                return
            visiting.add(directory)
            for target in directory_edges.get(directory, []):
                visit(target)
            visiting.remove(directory)
            visited.add(directory)

        visit(root.resolve())
    return digest.hexdigest()


# Executed as verifier-owned code inside the same network sandbox as the app.
# Redirects are refused: only the configured loopback application is reachable.
_HTTP_DRIVER = r"""
import http.client, importlib.util, json, os, socket, subprocess, sys, tempfile, time
spec = importlib.util.spec_from_file_location('demo', '/verifier-demo.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
config = json.load(sys.stdin)
schema = config['schema']
app_errors = tempfile.TemporaryFile()
app = subprocess.Popen(config['command'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=app_errors)
try:
    until = time.monotonic() + config['timeout'] / 2
    while True:
        if app.poll() is not None:
            raise SystemExit(app.returncode or 1)
        try:
            connection = socket.create_connection(('127.0.0.1', schema['start']['port']), timeout=0.1)
            connection.close()
            break
        except OSError:
            if time.monotonic() >= until:
                raise RuntimeError('HTTP readiness timed out')
            time.sleep(0.03)
    with open('/scratch/' + config['ready'], 'w') as ready:
        ready.write('ready')
    while not os.path.exists('/scratch/' + config['go']):
        if time.monotonic() >= until + config['timeout'] / 2:
            raise RuntimeError('verifier readiness acknowledgment timed out')
        time.sleep(0.01)
    captures, outputs = {}, []
    for step in schema['steps']:
        path = demo.substitute(step['path'], captures)
        if not path.startswith('/') or path.startswith('//') or '\r' in path or '\n' in path:
            raise ValueError('invalid expanded HTTP path')
        headers = {key: demo.substitute(value, captures) for key, value in step.get('headers', {}).items()}
        conn = http.client.HTTPConnection('127.0.0.1', schema['start']['port'], timeout=config['timeout'] / 2)
        conn.request(step['method'], path, body=demo.substitute(step.get('body', ''), captures).encode(), headers=headers)
        response = conn.getresponse()
        body = response.read(1048577)
        if len(body) > 1048576:
            raise ValueError('HTTP response exceeds limit')
        output = body.decode(errors='replace')
        outputs.append(output)
        demo.capture_output(step, output, captures, config['nonce'])
        conn.close()
    print(json.dumps(outputs))
finally:
    app.terminate()
    try:
        app.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        app.kill()
        app.wait()
    app_errors.seek(max(0, app_errors.seek(0, 2) - 16384))
    sys.stderr.write(app_errors.read().decode(errors="replace"))
    app_errors.close()
"""


def _http_steps(
    schema: dict[str, Any],
    command: tuple[str, ...],
    job: Callable[[tuple[str, ...]], SandboxJob],
    scratch: Path,
    mounts: dict[str, Path],
    env: dict[str, str],
    namespace_pid: int | None,
    nonce: str,
    runner: Callable[..., SandboxResult],
    ready_check: Callable[[], None],
) -> list[str]:
    from . import demo as demo_module

    ready, go = ".ready-" + secrets.token_hex(12), ".go-" + secrets.token_hex(12)
    request = {"schema": schema, "command": command, "timeout": job(command).timeout_seconds, "nonce": nonce, "ready": ready, "go": go}
    acknowledged = False
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runner,
            job(("/usr/bin/python3", "-I", "-c", _HTTP_DRIVER)),
            scratch=scratch,
            mounts={**mounts, "/verifier-demo.py": Path(demo_module.__file__)},
            env=env,
            namespace_pid=namespace_pid,
            network=True,
            input_text=json.dumps(request),
        )
        deadline = time.monotonic() + job(command).timeout_seconds
        while not (scratch / ready).exists() and not future.done() and time.monotonic() < deadline:
            time.sleep(0.01)
        if (scratch / ready).exists():
            ready_check()
            (scratch / go).touch()
            acknowledged = True
        result = future.result()
    if not acknowledged or result.exit_code or result.timed_out:
        raise CommandFailure(
            "start" if not acknowledged else "run",
            result.exit_code,
            result.stderr,
            "HTTP application/steps failed or readiness not acknowledged",
        )
    outputs = json.loads(result.stdout)
    if not isinstance(outputs, list) or len(outputs) != len(schema["steps"]) or not all(isinstance(value, str) for value in outputs):
        raise ValueError("invalid HTTP driver output")
    return cast(list[str], outputs)


def _side(side: Side, demo: Path, family: str, timeout: int, browser: BrowserExecutor | None, *, task_boundary: bool = False) -> SideRecord:
    started = time.monotonic()
    runner = _run_task if task_boundary else _sandbox.run
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

    def record(outcome: str, reason: str, phase: str = "", result: Any = None) -> SideRecord:
        return SideRecord(
            outcome,
            tuple(observations),
            time.monotonic() - started,
            diagnostic(reason, maximum=1500),
            timings["build"],
            timings["ready"],
            timings["run"],
            disk_peak,
            isolation_mode="task-boundary" if task_boundary else _sandbox.isolation_mode(),
            chromium_no_sandbox=bool(getattr(browser, "no_sandbox", False)),
            phase=phase,
            exit_code=result.exit_code if result is not None else None,
            stderr=diagnostic(result.stderr, maximum=1500) if result is not None else "",
        )

    try:
        schema = load_demo(demo)
        originals = (side.checkout, *side.dependencies, demo, *((side.products,) if side.products else ()))
        initial = tuple(_tree(p) for p in originals)
        for _ in range(1 if task_boundary else 3):
            tick = time.monotonic()
            with tempfile.TemporaryDirectory(prefix="ousast-proof-") as temporary:
                root = Path(temporary)
                checkout = shutil.copytree(side.checkout, root / "checkout")
                dependencies = [shutil.copytree(p, root / f"dep-{i}") for i, p in enumerate(side.dependencies)]
                immutable = (*dependencies,)
                before = tuple(_tree(p) for p in immutable)
                mounts = {f"/deps/{i}": p for i, p in enumerate(dependencies)}

                def job(command: tuple[str, ...], checkout: Path = checkout) -> SandboxJob:
                    return SandboxJob("", command, checkout, {}, timeout, SearchBudget().memory_bytes // 1024**2, 128)

                products = root / "products"
                if side.products is not None:
                    shutil.copytree(side.products, products)
                else:
                    products.mkdir()
                if task_boundary:
                    task_storage.check(task_storage.WORKSPACE if task_storage.WORKSPACE.is_dir() else root)
                recipe = schema["build"]["recipe"]
                build_args = schema["build"]["arguments"]
                if task_boundary and recipe != "none":
                    return record("could_not_build", "verifier requires executor-built archive; builds are forbidden")
                if recipe != "none":
                    build_input = checkout / build_args[0]
                    manifest = recipe in ("pip", "maven")
                    if not build_input.resolve().is_relative_to(checkout.resolve()) or not (
                        build_input.is_file() if manifest else build_input.is_dir()
                    ):
                        return record("could_not_build", "recipe input missing or outside checkout")
                    command = (*BUILD_RECIPES[recipe], "/workspace/" + build_args[0])
                    if recipe == "maven":
                        command += ("package", "-DskipTests")
                    elif recipe == "gradle":
                        command += ("assemble",)
                    compiled = timed("build", runner, job(command), scratch=products, mounts=mounts, writable_checkout=True)
                    if compiled.exit_code or compiled.timed_out:
                        return record("could_not_build", "build recipe failed", "build", compiled)
                if tuple(_tree(p) for p in immutable) != before:
                    return record("inconclusive", "build changed immutable inputs")
                write_start_files(checkout, schema["start"])
                if not task_boundary:
                    for name in schema["start"].get("files", {}):
                        _sandbox.writable_directory(checkout / ".demo" / name)
                product_hash = _tree(products, generated_links=True)
                checkout_hash = _tree(checkout, generated_links=True)
                mounts["/build"] = products
                start_spec = schema["start"]
                entry = checkout / start_spec["path"]
                if not entry.is_file() or not entry.resolve().is_relative_to(checkout.resolve()):
                    return record("could_not_build", "runtime entry missing from checkout")
                command = (*RUNTIMES[start_spec["runtime"]], "/workspace/" + start_spec["path"], *start_spec["arguments"])
                if start_spec["runtime"] == "python":
                    # Fixed bootstrap enables ordinary local imports and the pip
                    # recipe's offline packages without trusting PYTHONPATH.
                    bootstrap = (
                        "import os,runpy,sys; sys.dont_write_bytecode=True; p=sys.argv.pop(1); "
                        "sys.path[:0]=['/build/packages',os.path.dirname(p)]; sys.argv[0]=p; "
                        "runpy.run_path(p,run_name='__main__')"
                    )
                    command = ("/usr/bin/python3", "-I", "-c", bootstrap, "/workspace/" + start_spec["path"], *start_spec["arguments"])

                oracle = oracle_for(family, browser)
                assert oracle is not None
                try:
                    canary = Canary.fresh(root / "fixture")
                    if task_boundary and hasattr(oracle, "task_boundary"):
                        oracle.task_boundary = True
                    app_env = {
                        **{
                            key: "/workspace/" + value if value.startswith(".demo/") else value
                            for key, value in start_spec.get("environment", {}).items()
                        },
                        **oracle.prepare(canary),
                    }
                    app_scratch = canary.root if family == "command" else root / "app"
                    app_scratch.mkdir(exist_ok=True)
                    fixture = canary.root
                    if not task_boundary and _sandbox.isolation_mode() == "root-no-userns" and family != "command":
                        # Observer originals remain private. Only the app gets a
                        # read-only copy of the fixtures its interface requires.
                        fixture = shutil.copytree(canary.root, root / "app-fixture")
                        for path in [fixture, *fixture.rglob("*")]:
                            path.chmod(0o555 if path.is_dir() else 0o444)
                    app_mounts = {**mounts, "/fixture": fixture}
                    if schema["start"]["mode"] == "cli":
                        ready = timed(
                            "ready",
                            runner,
                            job((*command, *side.readiness_args)),
                            scratch=app_scratch,
                            mounts=app_mounts,
                            env=app_env,
                            namespace_pid=oracle.namespace_pid,
                        )
                        if ready.exit_code or ready.timed_out:
                            return record("could_not_run", "app readiness failed", "start", ready)
                    if family == "ssrf" and oracle.observe()[0]:
                        return record("inconclusive", "readiness triggered the SSRF oracle")
                    # Readiness cannot supply the attack's evidence or leave a command marker.
                    if family == "command" and any(canary.root.iterdir()):
                        return record("inconclusive", "readiness modified command fixture")

                    def http_ready_check(oracle: Oracle = oracle, canary: Canary = canary) -> None:
                        if family == "ssrf" and oracle.observe()[0]:
                            raise ValueError("HTTP readiness triggered the SSRF oracle")
                        if family == "command" and (canary.root / "marker").exists():
                            raise ValueError("HTTP readiness modified command fixture")

                    captures: dict[str, str] = {}
                    if schema["start"]["mode"] == "http":
                        outputs = timed(
                            "run",
                            _http_steps,
                            schema,
                            command,
                            job,
                            app_scratch,
                            app_mounts,
                            app_env,
                            oracle.namespace_pid,
                            canary.nonce,
                            runner,
                            http_ready_check,
                        )
                        for output in outputs:
                            timed("run", oracle.capture, output)
                    else:
                        for step in schema["steps"]:
                            arguments = [substitute(arg, captures) for arg in step["arguments"]]
                            result = timed(
                                "run",
                                runner,
                                job((*command, *arguments)),
                                scratch=app_scratch,
                                mounts=app_mounts,
                                env=app_env,
                                namespace_pid=oracle.namespace_pid,
                                input_text=substitute(step.get("stdin", ""), captures),
                            )
                            if result.timed_out:
                                return record("inconclusive", "app attack timed out")
                            if result.exit_code:
                                return record("could_not_run", "app invocation failed", "run", result)
                            timed("run", oracle.capture, result.stdout)
                            capture_output(step, result.stdout, captures, canary.nonce)
                    observed, evidence = timed("run", oracle.observe)
                    if (
                        tuple(_tree(p) for p in immutable) != before
                        or tuple(_tree(p) for p in originals) != initial
                        or _tree(products, generated_links=True) != product_hash
                        or _tree(checkout, generated_links=True) != checkout_hash
                    ):
                        return record("inconclusive", "immutable input or dependency changed")
                    observations.append(RunObservation(observed, evidence, time.monotonic() - tick))
                finally:
                    oracle.close()
        return record("observed", "fresh task run completed" if task_boundary else "three fresh runs completed")
    except CommandFailure as exc:
        return record("could_not_run", str(exc), exc.phase, exc)
    except task_storage.ScratchLimit as exc:
        return record("could_not_build", exception_reason(exc))
    except (OSError, ValueError, AssertionError, KeyError, IndexError, TypeError) as exc:
        return record("could_not_run", "verification unavailable or refused: " + exception_reason(exc))


def _run_task(
    job: SandboxJob,
    *,
    scratch: Path,
    mounts: dict[str, Path] | None = None,
    env: dict[str, str] | None = None,
    input_text: str = "",
    **kwargs: Any,
) -> SandboxResult:
    """Only called in a fresh externally isolated task by verify_side_task.

    The schema selects tracked programs, never agent scripts. The task itself is
    the filesystem/network boundary. Its launch manifest must contain no keys.
    """
    translations = {"/workspace": str(job.repo_root), "/scratch": str(scratch), **{k: str(v) for k, v in (mounts or {}).items()}}
    pattern = re.compile("(?:" + "|".join(re.escape(key) for key in sorted(translations, key=len, reverse=True)) + r")(?=/|$|['\"])")

    def translate(value: str) -> str:
        # One pass, at path-component boundaries: /fixture/fixture.db must
        # translate its mount prefix without also rewriting the filename.
        return pattern.sub(lambda match: translations[match.group(0)], value)

    command = tuple(translate(arg) for arg in job.command)
    environment = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "TMPDIR": str(scratch), **task_storage.environment()}
    environment.update({key: translate(value) for key, value in (env or {}).items()})

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024,) * 2)
        # The external task memory limit bounds app starts; RLIMIT_AS breaks V8 reservations.
        resource.setrlimit(resource.RLIMIT_CPU, (job.timeout_seconds + 1,) * 2)

    # Driver JSON includes command paths, but arbitrary user input stays data.
    if "-c" in command and _HTTP_DRIVER in job.command:
        config = json.loads(input_text)
        config["command"] = [translate(arg) for arg in config["command"]]
        input_text = json.dumps(config)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(
            command, cwd=scratch, env=environment, stdin=subprocess.PIPE, stdout=out, stderr=err, start_new_session=True, preexec_fn=limits
        )
        expired = False
        try:
            task_storage.communicate(proc, input_text.encode(), job.timeout_seconds, job.repo_root.parent, files=(out, err))
        except subprocess.TimeoutExpired:
            expired = True
        finally:
            with suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        out.seek(0)
        err.seek(max(0, os.fstat(err.fileno()).st_size - 16384))
        return SandboxResult(
            proc.returncode, out.read(1048576).decode(errors="replace"), err.read(1048576).decode(errors="replace"), expired
        )


def verify_side_task(side: Side, demo: Path, family: str, timeout_seconds: int = 5) -> SideRecord:
    """Fresh AX task entry: one repetition, grouped by the trusted dispatcher.

    This explicit API is never selected as a fallback in the host verifier.
    """
    schema = load_demo(demo)
    if family in FAMILY_ORACLES and not FAMILY_ORACLES[family]:
        return SideRecord("no_oracle", (), 0, "no owned oracle", isolation_mode="task-boundary")
    validate_oracle(family, schema["oracle"])
    kind = schema["oracle"]
    if timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    browser = BrowserExecutor(task_boundary=True) if kind == "xss" else None
    return _side(side, demo, kind, timeout_seconds, browser, task_boundary=True)


def verify(
    affected: Side,
    safe: Side,
    artefact: Path,
    family: str,
    *,
    timeout_seconds: int = 5,
    oracle: str | None = None,
    browser: BrowserExecutor | None = None,
    task_dispatcher: Callable[..., SideRecord] | None = None,
) -> VerificationRecord:
    """Affected is vulnerable/head; safe is fixed/base. No negative verdict exists."""
    started = time.monotonic()
    if family in FAMILY_ORACLES and not FAMILY_ORACLES[family]:
        return VerificationRecord("no_oracle", (), time.monotonic() - started, "no configured owned oracle for " + family)
    if timeout_seconds < 1:
        raise ValueError("timeout must be positive")
    try:
        schema = load_demo(artefact)
        validate_oracle(family, schema["oracle"])
        if oracle is not None and oracle != schema["oracle"]:
            raise ValueError("oracle differs from demo")
        kind = schema["oracle"]
        if oracle_for(kind, browser) is None:
            raise ValueError("oracle runtime unavailable")
    except (OSError, ValueError) as exc:
        return VerificationRecord("inconclusive", (), time.monotonic() - started, "invalid declarative demo: " + exception_reason(exc))
    mode = "task-boundary" if task_dispatcher is not None else _sandbox.isolation_mode()
    if task_dispatcher is None:
        try:
            _sandbox.isolation_check(timeout_seconds=timeout_seconds)
        except _sandbox.IsolationUnavailable:
            raise _sandbox.IsolationUnavailable("task-boundary requires a trusted fresh-task dispatcher; no local fallback") from None
    if mode == "task-boundary":
        assert task_dispatcher is not None
        # Only trusted infrastructure supplies this callback. One fresh task per
        # side; task IDs and cleanup are the dispatcher's responsibility.
        sides = tuple(
            task_dispatcher(side=s, demo=load_demo(artefact), family=family, timeout_seconds=timeout_seconds, fresh_task=True)
            for s in (affected, safe)
        )
        if any(s.isolation_mode != "task-boundary" for s in sides):
            raise _sandbox.IsolationUnavailable("dispatcher did not attest task-boundary isolation")
    else:
        sides = tuple(_side(s, artefact, kind, timeout_seconds, browser) for s in (affected, safe))
    if any(s.outcome == "observed" and len(s.runs) != 3 for s in sides):
        outcome, reason = "inconclusive", "each side requires exactly three fresh observations"
    elif sides[1].outcome != "observed":
        outcome, reason = "inconclusive", "safe side did not complete build/readiness/verification"
    elif sides[0].outcome != "observed":
        outcome, reason = sides[0].outcome, sides[0].reason
    elif all(r.observed for r in sides[0].runs) and not any(r.observed for r in sides[1].runs):
        outcome, reason = "demonstrated", "owned effect in 3/3 affected runs and 0/3 safe runs"
    else:
        outcome, reason = "inconclusive", "no consistent differential effect"
    return VerificationRecord(
        outcome,
        sides,
        time.monotonic() - started,
        reason,
        isolation_mode=mode,
        chromium_no_sandbox=bool(getattr(browser, "no_sandbox", False)),
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("affected", type=Path)
    parser.add_argument("safe", type=Path)
    parser.add_argument("artefact", type=Path)
    parser.add_argument("family")
    args = parser.parse_args()
    result = verify(Side(args.affected), Side(args.safe), args.artefact, args.family)
    print(json.dumps(asdict(result), indent=2))


if __name__ == "__main__":
    main()
