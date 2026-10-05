"""Offline image contracts; these do not claim a built image or measured size."""
import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return (ROOT / name).read_text()


def instructions(name):
    text = re.sub(r"\\\n\s*", " ", read(name))
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def workflow(name):
    # BaseLoader avoids YAML 1.1 interpreting GitHub's `on` as a boolean.
    return yaml.load(read(f".github/workflows/{name}.yml"), Loader=yaml.BaseLoader)


@pytest.mark.parametrize("name,variant", [
    ("plane/Dockerfile.engine-task", "BASE"),
    ("plane/Dockerfile.search-task", "BROWSER"),
    ("Dockerfile", "BASE"),
])
def test_digest_required_and_code_last(name, variant):
    lines = instructions(name)
    assert f"ARG TASK_{variant}_DIGEST" in lines
    ref = f"ghcr.io/norandom/ousast-task-base:${{TASK_{variant}_TAG}}@${{TASK_{variant}_DIGEST}}"
    assert any(line.startswith(f"FROM {ref}") for line in lines)
    code = next(i for i, line in enumerate(lines) if line.startswith("COPY src "))
    for i, line in enumerate(lines):
        if "apt-get" in line or "--from=joern-build" in line or "frontend-retention-install.py" in line:
            assert i < code
        if "pip install" in line:
            assert "--no-deps --no-cache-dir ." in line
            assert i > code
    assert not any("venv /venv" in line for line in lines)


def test_shared_ancestry_and_replay_exact_engine():
    base = read("plane/Dockerfile.base")
    assert "FROM ghcr.io/norandom/ax-task-runner:v0.3.1 AS base" in base
    assert "FROM ${TASK_BASE_REF} AS base-browser" in base
    common, browser = base.split("FROM ${TASK_BASE_REF} AS base-browser")
    assert "chromium" not in common and "chromium" in browser
    assert "21-jdk-jammy" in common
    assert "COPY src" not in base and 'p["dependencies"]' in base
    assert "pip install --no-cache-dir -r /tmp/requirements.txt" in base
    engine = read("plane/Dockerfile.engine-task")
    assert "ARG ENGINE_REF=engine" in engine and "FROM ${ENGINE_REF} AS replay" in engine
    wf = workflow("engine-image")
    assert wf["jobs"]["replay"]["needs"] == ["pins", "engine"]
    builds = [s["with"] for s in wf["jobs"]["replay"]["steps"] if s.get("uses") == "docker/build-push-action@v6"]
    assert "ENGINE_REF=${{ needs.engine.outputs.image }}@${{ needs.engine.outputs.digest }}" in builds[0]["build-args"]
    base_wf = workflow("task-base-image")
    browser_build = next(s["with"] for s in base_wf["jobs"]["base"]["steps"] if s.get("id") == "browser")
    assert "@${{ steps.base.outputs.digest }}" in browser_build["build-args"]
    # Remote ancestry and anonymous existence are checked before downstream builds.
    assert 'manifests["base-browser"][:len(base)] != base' in read(".github/workflows/engine-image.yml")


@pytest.mark.parametrize("name", ["engine-image", "task-base-image"])
def test_triggers_caches_and_digest_outputs(name):
    wf = workflow(name)
    assert "workflow_dispatch" in wf["on"]
    assert "src/**" not in wf["on"]["push"]["paths"]
    if name == "engine-image":
        assert wf["on"]["push"]["tags"] == ["v*"]
        assert "plane/task-base.digest" in wf["on"]["push"]["paths"]
    else:
        assert set(wf["on"]["push"]["paths"]) == {"plane/Dockerfile.base", "pyproject.toml", "uv.lock"}
    builds = [s["with"] for job in wf["jobs"].values() for s in job["steps"]
              if s.get("uses") == "docker/build-push-action@v6"]
    assert builds
    for build in builds:
        assert "type=gha" in build["cache-from"] and "type=gha" in build["cache-to"]
        assert build["push"] == "true"
    assert "outputs.digest" in read(f".github/workflows/{name}.yml")


def test_pin_bootstrap_fails_closed():
    pins = json.loads(read("plane/task-base.digest"))
    assert set(pins) >= {"base", "base-browser"}
    for key in ("base", "base-browser"):
        if pins[key] is None:
            assert "UNPUBLISHED" in pins["note"]
        else:
            assert re.fullmatch(r"ghcr.io/norandom/ousast-task-base:base-[a-z0-9-]+@sha256:[0-9a-f]{64}", pins[key])
    wf = read(".github/workflows/engine-image.yml")
    assert "raise SystemExit" in wf and '"inspect", "--raw", ref' in wf
    assert "needs: pins" in wf


@pytest.mark.parametrize("case", ["unpublished", "missing", "wrong-ancestry", "valid"])
def test_ci_pin_gate_offline(case, tmp_path, monkeypatch):
    """Exercise the actual workflow Python, with only registry reads replaced."""
    import subprocess

    pin_step = next(s for s in workflow("engine-image")["jobs"]["pins"]["steps"] if s.get("id") == "pins")
    script = pin_step["run"].split("<<'PYTHON'\n", 1)[1].rsplit("PYTHON", 1)[0]
    base = "ghcr.io/norandom/ousast-task-base:base-1234567@sha256:" + "a" * 64
    browser = "ghcr.io/norandom/ousast-task-base:base-1234567-browser@sha256:" + "b" * 64
    (tmp_path / "plane").mkdir()
    (tmp_path / "plane/task-base.digest").write_text(json.dumps({
        "base": None if case == "unpublished" else base, "base-browser": browser,
    }))
    output = tmp_path / "output"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    calls = []

    def inspect(argv):
        calls.append(argv)
        assert argv[:5] == ["docker", "buildx", "imagetools", "inspect", "--raw"]
        if case == "missing":
            raise subprocess.CalledProcessError(1, argv)
        layers = [{"digest": "sha256:shared"}]
        if argv[-1] == browser:
            if case == "wrong-ancestry":
                layers = [{"digest": "sha256:different"}]
            layers.append({"digest": "sha256:chromium"})
        return json.dumps({"layers": layers}).encode()

    monkeypatch.setattr(subprocess, "check_output", inspect)
    if case == "valid":
        exec(compile(script, "workflow-pin-gate", "exec"), {})
        assert "base_digest=sha256:" in output.read_text()
        assert "browser_digest=sha256:" in output.read_text()
        assert len(calls) == 2
    else:
        expected = subprocess.CalledProcessError if case == "missing" else SystemExit
        with pytest.raises(expected):
            exec(compile(script, "workflow-pin-gate", "exec"), {})
        if case == "unpublished":
            assert not calls


def test_base_preserves_executor_build_toolchains():
    common = read("plane/Dockerfile.base").split("FROM ${TASK_BASE_REF} AS base-browser")[0]
    commands = " ".join(instructions("plane/Dockerfile.base")).split("FROM ${TASK_BASE_REF} AS base-browser")[0]
    install = re.search(r"apt-get install -y --no-install-recommends\s+(.*?)\s+&&", commands).group(1)
    packages = set(install.split())
    assert packages == {
        "nodejs", "npm", "node-typescript", "php-cli", "composer", "maven",
        "sqlite3", "bubblewrap", "util-linux", "git", "ca-certificates",
        "libstdc++6", "zlib1g",
    }
    assert "gradle" not in packages
    assert "FROM eclipse-temurin:21-jdk-jammy AS jdk" in common
    assert "COPY --from=jdk /opt/java/openjdk /opt/java/openjdk" in common
    for command in ("javac -version", "npm --version", "composer --version", "mvn --version",
                    "python3 -m venv /venv", "/venv/bin/pip install"):
        assert command in common
    assert "joern" not in common.lower()
    assert "apt-get clean" in common
    for directory in ("doc", "man", "info"):
        assert f"path-exclude=/usr/share/{directory}/*" in common
        assert f" /usr/share/{directory}/*" in common
