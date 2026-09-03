from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from openultrasast.sandbox import DockerCliRunner, FakeSandboxRunner, SandboxJob, SandboxResult, SandboxRunner, build_docker_argv
from openultrasast.sandbox import runner as runner_mod


def _job(tmp_path: Path, **overrides: object) -> SandboxJob:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("print(1)\n")
    values: dict[str, object] = {
        "image": "python:3.12-alpine",
        "command": ("python", "/scratch/case.py"),
        "repo_root": repo,
        "scratch_files": {"case.py": "print('ok')\n"},
        "timeout_seconds": 30,
        "memory_mb": 256,
        "pids_limit": 128,
    }
    values.update(overrides)
    return SandboxJob(**values)  # type: ignore[arg-type]


def _flag_value(argv: list[str], flag: str) -> str:
    try:
        return argv[argv.index(flag) + 1]
    except (ValueError, IndexError) as exc:
        raise AssertionError(f"{flag} missing from {argv}") from exc


def _mount_options(spec: str) -> dict[str, str]:
    options: dict[str, str] = {}
    for part in spec.split(","):
        if "=" in part:
            key, value = part.split("=", 1)
            options[key] = value
        else:
            options[part] = "true"
    return options


def _workspace_mount(argv: list[str]) -> dict[str, str]:
    specs: list[str] = []
    for index, item in enumerate(argv):
        if item in {"--mount", "-v", "--volume"} and index + 1 < len(argv):
            specs.append(argv[index + 1])
    for spec in specs:
        options = _mount_options(spec)
        target = options.get("dst") or options.get("destination") or options.get("target")
        if target == "/workspace" or spec.endswith(":/workspace") or ":/workspace:" in spec:
            return options if target == "/workspace" else {"raw": spec}
        if "/workspace" in spec:
            return options if options else {"raw": spec}
    raise AssertionError(f"no /workspace mount in {argv}")


def _seed_source(argv: list[str]) -> Path:
    mounts = [argv[index + 1] for index, item in enumerate(argv) if item == "--mount" and index + 1 < len(argv)]
    seed_mounts = [spec for spec in mounts if "/scratch-in" in spec]
    assert seed_mounts, argv
    options = _mount_options(seed_mounts[0])
    source = Path(options.get("src") or options.get("source") or "")
    assert source.is_dir(), argv
    return source


def _copy_script(argv: list[str]) -> str:
    try:
        return argv[argv.index("-c") + 1]
    except (ValueError, IndexError) as exc:
        raise AssertionError(f"no /bin/sh -c wrapper in {argv}") from exc


def _posix_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_build_docker_argv_starts_with_docker_run_rm_init(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    assert argv[0] == "docker"
    assert argv[1] == "run"
    assert "--rm" in argv
    assert "--init" in argv


def test_build_docker_argv_includes_network_none_and_read_only(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    joined = " ".join(argv)
    assert "--read-only" in argv
    assert "--network none" in joined or "--network=none" in argv
    assert "--network host" not in joined
    assert "--network=host" not in argv


def test_build_docker_argv_excludes_docker_sock(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    joined = " ".join(argv)
    assert "docker.sock" not in joined
    assert "/var/run/docker.sock" not in joined
    assert "-v" not in argv
    assert "--volume" not in argv


def test_build_docker_argv_forbids_privileged_and_host_network(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    assert "--privileged" not in argv
    assert "--pid" not in argv or _flag_value(argv, "--pid") != "host"
    assert "--ipc" not in argv or _flag_value(argv, "--ipc") != "host"
    assert "--userns" not in argv or "host" not in _flag_value(argv, "--userns")


def test_build_docker_argv_scratch_is_writable_tmpfs(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    tmpfs = _flag_value(argv, "--tmpfs")
    assert tmpfs.startswith("/scratch")
    assert "rw" in tmpfs
    assert "exec" in tmpfs


def test_build_docker_argv_applies_memory_and_pids_limits(tmp_path: Path) -> None:
    job = _job(tmp_path, memory_mb=512, pids_limit=64)
    argv = build_docker_argv(job)
    memory = _flag_value(argv, "--memory")
    assert "512" in memory
    assert memory.endswith("m") or memory.endswith("M") or memory.endswith("b")
    assert _flag_value(argv, "--pids-limit") == "64"


def test_build_docker_argv_drops_capabilities_and_new_privileges(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    assert _flag_value(argv, "--cap-drop") == "ALL"
    security = _flag_value(argv, "--security-opt")
    assert "no-new-privileges" in security


def test_build_docker_argv_uses_non_root_user(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    user = _flag_value(argv, "--user")
    uid = user.split(":", 1)[0]
    assert uid not in {"0", "root"}
    assert int(uid) != 0


def test_build_docker_argv_bind_mounts_repo_read_only_at_workspace(tmp_path: Path) -> None:
    job = _job(tmp_path)
    argv = build_docker_argv(job)
    mount = _workspace_mount(argv)
    source = mount.get("src") or mount.get("source")
    assert source == str(job.repo_root.resolve())
    assert mount.get("dst") == "/workspace" or mount.get("destination") == "/workspace" or mount.get("target") == "/workspace"
    assert mount.get("ro") == "true" or mount.get("readonly") == "true"
    assert "rw" not in mount


def test_build_docker_argv_source_tree_is_not_writable(tmp_path: Path) -> None:
    argv = build_docker_argv(_job(tmp_path))
    mount = _workspace_mount(argv)
    assert mount.get("ro") == "true" or mount.get("readonly") == "true"
    assert "--read-only" in argv
    joined = " ".join(argv)
    assert f"{_job(tmp_path).repo_root.resolve()}:/workspace:rw" not in joined
    assert f"{_job(tmp_path).repo_root.resolve()}:/workspace " not in joined + " "


def test_build_docker_argv_ends_with_image_and_command(tmp_path: Path) -> None:
    job = _job(tmp_path)
    argv = build_docker_argv(job)
    assert argv[-len(job.command) :] == list(job.command)
    assert argv[-len(job.command) - 1] == job.image


def test_fake_sandbox_runner_records_jobs_and_returns_programmed_result(tmp_path: Path) -> None:
    programmed = SandboxResult(exit_code=7, stdout="out", stderr="err", timed_out=False)
    runner: SandboxRunner = FakeSandboxRunner(programmed)
    job = _job(tmp_path)
    result = runner.run(job)
    assert result == programmed
    assert isinstance(runner, FakeSandboxRunner)
    assert runner.jobs == [job]


def test_fake_sandbox_runner_can_be_reprogrammed(tmp_path: Path) -> None:
    runner = FakeSandboxRunner()
    first = _job(tmp_path, command=("echo", "one"))
    second = _job(tmp_path, command=("echo", "two"))
    timeout_result = SandboxResult(exit_code=-1, stdout="", stderr="deadline", timed_out=True)
    runner.result = timeout_result
    assert runner.run(first).timed_out is True
    runner.result = SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False)
    assert runner.run(second).stdout == "ok"
    assert runner.jobs == [first, second]


def test_fake_sandbox_runner_does_not_need_docker_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("unit tests must not invoke the docker daemon")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(runner_mod.subprocess, "run", boom)
    programmed = SandboxResult(exit_code=0, stdout="fake", stderr="", timed_out=False)
    runner = FakeSandboxRunner(programmed)
    assert runner.run(_job(tmp_path)) == programmed


def test_docker_cli_runner_uses_constructed_argv_and_timeout(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}
    job = _job(tmp_path, scratch_files={}, timeout_seconds=19)

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["command"] = list(command)
        seen["timeout"] = kwargs.get("timeout")
        seen["check"] = kwargs.get("check")
        seen["capture_output"] = kwargs.get("capture_output")
        seen["text"] = kwargs.get("text")
        return subprocess.CompletedProcess(command, 3, stdout="hello", stderr="warn")

    result = DockerCliRunner(runner=fake_run).run(job)
    assert seen["command"] == build_docker_argv(job)
    assert seen["timeout"] == 19
    assert seen["check"] is False
    assert seen["capture_output"] is True
    assert seen["text"] is True
    assert result == SandboxResult(exit_code=3, stdout="hello", stderr="warn", timed_out=False)
    assert "--network" in seen["command"]
    assert "--read-only" in seen["command"]
    assert "docker.sock" not in " ".join(seen["command"])


def test_docker_cli_runner_maps_timeout_expired_to_timed_out(tmp_path: Path) -> None:
    job = _job(tmp_path, scratch_files={}, timeout_seconds=5)

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=command, timeout=5, output="partial", stderr="slow")

    result = DockerCliRunner(runner=fake_run).run(job)
    assert result.timed_out is True
    assert result.stdout == "partial"
    assert result.stderr == "slow"


def test_docker_cli_runner_does_not_invoke_daemon_when_runner_injected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise AssertionError("unit tests must not invoke the docker daemon")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(runner_mod.subprocess, "run", boom)

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = DockerCliRunner(runner=fake_run).run(_job(tmp_path, scratch_files={}))
    assert result.timed_out is False
    assert result.exit_code == 0


def test_docker_cli_runner_does_not_write_the_source_tree(tmp_path: Path) -> None:
    job = _job(tmp_path)
    original = (job.repo_root / "app.py").read_text()
    before = {path.relative_to(job.repo_root): path.read_text() for path in job.repo_root.rglob("*") if path.is_file()}

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        joined = " ".join(command)
        assert "docker.sock" not in joined
        assert "--read-only" in command
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    DockerCliRunner(runner=fake_run).run(job)
    assert (job.repo_root / "app.py").read_text() == original
    after = {path.relative_to(job.repo_root): path.read_text() for path in job.repo_root.rglob("*") if path.is_file()}
    assert after == before
    assert "case.py" not in {path.name for path in job.repo_root.iterdir()}


def test_docker_cli_runner_seeds_scratch_files_outside_the_repo(tmp_path: Path) -> None:
    job = _job(tmp_path, scratch_files={"nested/case.py": "print('seeded')\n"})
    seen: dict[str, Any] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["command"] = list(command)
        mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount" and index + 1 < len(command)]
        seed_mounts = [spec for spec in mounts if "/scratch-in" in spec]
        assert seed_mounts, command
        options = _mount_options(seed_mounts[0])
        source = Path(options.get("src") or options.get("source") or "")
        assert source.is_dir()
        assert job.repo_root.resolve() not in source.resolve().parents
        assert source.resolve() != job.repo_root.resolve()
        assert (source / "nested" / "case.py").read_text() == "print('seeded')\n"
        assert options.get("ro") == "true" or options.get("readonly") == "true"
        assert "--tmpfs" in command
        assert _flag_value(command, "--tmpfs").startswith("/scratch")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = DockerCliRunner(runner=fake_run).run(job)
    assert result.exit_code == 0
    argv = seen["command"]
    assert "docker.sock" not in " ".join(argv)
    assert "--read-only" in argv
    assert job.image in argv


def test_docker_cli_runner_scratch_seed_is_world_readable_for_container_user(tmp_path: Path) -> None:
    job = _job(tmp_path, scratch_files={"nested/dir/case.py": "print('seeded')\n"})
    seen: dict[str, Path] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        source = _seed_source(command)
        seen["source"] = source
        assert _posix_mode(source) == 0o755
        for dirpath, _dirnames, filenames in os.walk(source):
            directory = Path(dirpath)
            assert stat.S_ISDIR(directory.stat().st_mode)
            assert _posix_mode(directory) == 0o755, directory
            for name in filenames:
                file_path = directory / name
                assert _posix_mode(file_path) == 0o644, file_path
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    DockerCliRunner(runner=fake_run).run(job)
    assert "source" in seen


def test_docker_cli_runner_scratch_copy_uses_cp_r_not_cp_a(tmp_path: Path) -> None:
    job = _job(tmp_path, scratch_files={"nested/case.py": "print('seeded')\n"})
    seen: dict[str, str] = {}

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        script = _copy_script(command)
        seen["script"] = script
        assert command[command.index(job.image) + 1] == "/bin/sh"
        assert "cp -a" not in script
        assert "cp -a" not in " ".join(command)
        assert script.startswith("cp -r /scratch-in/. /scratch/")
        assert 'exec "$@"' in script
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    DockerCliRunner(runner=fake_run).run(job)
    assert seen["script"] == 'cp -r /scratch-in/. /scratch/ && exec "$@"'
