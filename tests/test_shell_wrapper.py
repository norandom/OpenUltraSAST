"""The shell wrapper, `ops/shell/ousast.sh`, run by bash against stubs: no Joern, no venv, no Docker."""

import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "ops/shell/ousast.sh"

STUB = """#!/bin/sh
echo "{name} cwd=$PWD args=$*"
"""


def ousast(tmp_path, executables, *arguments):
    """`ousast <arguments>` in tmp_path/project. OUSAST_HOME is a checkout that holds only what the wrapper looks
    for, the interpreter under its .venv is a stub, and so is each executable named, and docker, on PATH."""
    home = tmp_path / "checkout"
    home.mkdir()
    (home / "docker-compose.yml").write_text("services: {}\n")
    python = home / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(STUB.format(name="python"))
    python.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("docker", *executables):
        (bin_dir / name).write_text(STUB.format(name=name))
        (bin_dir / name).chmod(0o755)
    project = tmp_path / "project"
    project.mkdir()
    script = f'source "{WRAPPER}" && ousast {" ".join(shlex.quote(a) for a in arguments)}'
    return subprocess.run(
        ["bash", "-c", script],
        cwd=project,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "OUSAST_HOME": str(home)},
        capture_output=True,
        text=True,
    )


def test_a_native_scan_runs_in_the_callers_directory(tmp_path):
    """The native path changed into the checkout first, so `ousast scan .` scanned the checkout, not the caller.

    `-P` is passed because `-m` alone puts the working directory first on the interpreter's path, where a file
    of the scanned tree could stand in for a module the CLI imports."""
    result = ousast(tmp_path, ["joern", "joern-parse"], "scan", ".")
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"python cwd={tmp_path / 'project'} args=-P -m openultrasast.cli scan ."]


def test_the_native_path_needs_joern_as_well_as_joern_parse(tmp_path):
    """The batch queries run `joern`; with `joern-parse` alone every one fails, and the scan still exits 0."""
    result = ousast(tmp_path, ["joern-parse"], "scan", ".")
    assert result.returncode == 0, result.stderr
    calls = [line.split()[0] for line in result.stdout.splitlines()]
    assert "python" not in calls and "docker" in calls
