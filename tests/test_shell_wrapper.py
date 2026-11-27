"""The shell wrapper, `ops/shell/ousast.sh`, run by bash against stubs: no Joern, no venv, no Docker."""

import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "ops/shell/ousast.sh"

STUB = """#!/bin/sh
echo "{name} cwd=$PWD args=$*${{OUSAST_REPORTS:+ reports=$OUSAST_REPORTS}}"
"""


def ousast(tmp_path, executables, *arguments, without_home=False):
    """`ousast <arguments>` in tmp_path/project, with tmp_path as HOME unless `without_home` is passed. OUSAST_HOME is
    a checkout that holds only what the wrapper looks for, the interpreter under its .venv is a stub, and so is each
    executable named, and docker, on PATH."""
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {}\n")
    python = checkout / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text(STUB.format(name="python"))
    python.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("docker", *executables):
        stub = STUB.format(name=name)
        if name == "docker":
            # `image inspect` fails, as for an image that is not built, so the wrapper takes its build branch.
            shebang, body = stub.split("\n", 1)
            stub = f'{shebang}\n[ "$1" = image ] && exit 1\n{body}'
        (bin_dir / name).write_text(stub)
        (bin_dir / name).chmod(0o755)
    project = tmp_path / "project"
    project.mkdir()
    script = f'source "{WRAPPER}" && ousast {" ".join(shlex.quote(a) for a in arguments)}'
    environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "OUSAST_HOME": str(checkout), "HOME": str(tmp_path)}
    if without_home:
        del environment["HOME"]
    return subprocess.run(["bash", "-c", script], cwd=project, env=environment, capture_output=True, text=True)


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


def test_the_container_writes_its_runs_to_the_users_cache(tmp_path):
    """The wrapper wrote its runs to ./.ousast, inside the repository it was scanning."""
    result = ousast(tmp_path, "scan", ".")
    runs = tmp_path / ".cache" / "openultrasast" / "runs"
    assert result.returncode == 0, result.stderr
    assert runs.is_dir() and not any((tmp_path / "project").iterdir())
    words = result.stdout.splitlines()[-1].split()
    assert words[0] == "docker" and words[-1] == f"reports={runs}"
    # Without the override the run lands under runs/runs, where no pruning looks.
    assert words.index("OPENULTRASAST_RUNS_DIR=/reports") < words.index("ousast")


def test_the_container_path_stops_when_home_is_not_set(tmp_path):
    """With HOME unset, `$HOME/.cache` became `/.cache`: the wrapper went on to the container just the same."""
    result = ousast(tmp_path, (), "scan", ".", without_home=True)
    message = "ousast: HOME is not set, so there is no ~/.cache/openultrasast/runs to write the runs to"
    assert result.returncode == 1, result.stderr
    assert result.stderr.splitlines() == [message]
    # Neither the build nor the container is started.
    assert result.stdout == ""


def test_a_runs_directory_that_cannot_be_made_stops_the_wrapper(tmp_path):
    """`mkdir -p` was not checked: the wrapper went on to the container with a runs directory that did not exist."""
    (tmp_path / ".cache").write_text("")
    result = ousast(tmp_path, (), "scan", ".")
    runs = tmp_path / ".cache" / "openultrasast" / "runs"
    assert result.returncode == 1, result.stderr
    # mkdir says why first; the wrapper's line is the last.
    assert result.stderr.splitlines()[-1] == f"ousast: cannot create {runs}, where the runs are written"
    assert result.stdout == ""
