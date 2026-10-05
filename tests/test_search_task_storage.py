"""Offline operator storage/egress contracts, using real local child processes."""

import json
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from openultrasast.search import executor, task_storage, verify_task
from openultrasast.search.verify import Side, verify_side_task


def spec():
    return {
        "demo": {
            "oracle": "path",
            "build": {"recipe": "none", "arguments": []},
            "start": {"runtime": "python", "path": "app.py", "arguments": [], "mode": "cli"},
            "steps": [{"type": "cli", "arguments": []}],
        },
        "family": "path",
        "timeout_seconds": 2,
    }


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(task_storage, "WORKSPACE", root)
    # Keep global tempfile state and environment changes local to this test.
    monkeypatch.setattr(task_storage.tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr(os, "environ", dict(os.environ))
    task_storage.configure()
    return root


def test_workspace_environment_and_cached_tempdir(workspace):
    env = executor.clean_environment()
    assert env["TMPDIR"] == str(workspace / "tmp")
    assert task_storage.tempfile.gettempdir() == env["TMPDIR"]
    for key, suffix in {
        "npm_config_cache": ".npm",
        "COMPOSER_HOME": ".composer",
        "PIP_CACHE_DIR": ".pip",
        "GRADLE_USER_HOME": ".gradle",
    }.items():
        assert env[key] == str(workspace / suffix)
    assert env["MAVEN_OPTS"] == "-Dmaven.repo.local=" + str(workspace / ".m2")


@pytest.mark.parametrize("wait", [False, True])
def test_executor_checks_caches_and_stops_at_scratch_limit(workspace, monkeypatch, wait):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "input").write_text("readable-input")
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    code = (
        "from pathlib import Path; import os,time; print(Path('input').stat().st_size); "
        "p=Path(os.environ['PIP_CACHE_DIR']); p.mkdir(); (p/'large').write_bytes(b'x'*30000); " + ("time.sleep(10)" if wait else "")
    )
    result = app.submit("run", {"command": [sys.executable, "-c", code]}, timeout_seconds=3)
    assert result["status"] == "could_not_build" and result["reason"] == "ScratchLimit: scratch limit"
    assert result["stopped"] and app.stopped


def test_executor_exports_built_input_and_verifier_needs_no_build(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text("print('safe')")
    blobs = []
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))
    result = app.submit("prepare_verification", spec())
    assert result["status"] == "ok", result
    destination = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], destination)
    assert (destination / "checkout/app.py").read_text() == "print('safe')"
    assert json.loads((destination / "spec.json").read_text()) == spec()
    assert (destination / "products").is_dir()
    demo = workspace / "demo"
    demo.mkdir()
    (demo / "demo.json").write_text(json.dumps(spec()["demo"]))
    observation = verify_side_task(Side(destination / "checkout", products=destination / "products"), demo, "path")
    assert observation.outcome == "observed", observation


def test_verifier_refuses_build_recipe():
    value = spec()
    value["demo"]["build"] = {"recipe": "npm", "arguments": ["project"]}
    with pytest.raises(ValueError, match="builds are forbidden"):
        verify_task.validate_spec(value)


def test_first_download_retries_for_60_seconds(monkeypatch):
    import urllib.error

    now, timeouts = [0.0], []

    class Opener:
        def open(self, url, timeout):
            timeouts.append(timeout)
            raise urllib.error.HTTPError(url, 403, "pending policy", {}, None)

    monkeypatch.setattr(verify_task.urllib.request, "build_opener", lambda *a: Opener())
    monkeypatch.setattr(verify_task.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(verify_task.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    with pytest.raises(OSError, match="egress not ready"):
        verify_task.download("https://files.because-security.com/input", 100)
    assert now[0] == 60 and len(timeouts) > 3


def test_verifier_reports_scratch_limit(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    # Writes happen after readiness, in a package cache outside the checkout.
    (repo / "app.py").write_text(
        "import sys,os\nfrom pathlib import Path\n"
        "if '--ready' not in sys.argv:\n"
        " p=Path(os.environ['npm_config_cache']); p.mkdir(exist_ok=True); (p/'large').write_bytes(b'x'*30000)\n"
    )
    demo = workspace / "demo"
    demo.mkdir()
    (demo / "demo.json").write_text(json.dumps(spec()["demo"]))
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "25000")
    result = verify_side_task(Side(repo), demo, "path")
    assert result.outcome == "could_not_build" and result.reason == "ScratchLimit: scratch limit", result


def test_preparation_builds_before_export_and_exports_products(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text("import dependency; print(dependency.VALUE)")
    (repo / "requirements.txt").write_text("dependency==1")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    blobs, commands = [], []
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))

    def build(argv, timeout, limits, **kwargs):
        commands.append(argv)
        products = Path(argv[argv.index("--target") + 1])
        assert products.is_relative_to(workspace)
        products.mkdir()
        (products / "dependency.py").write_text("VALUE = 42")
        return {"exit_code": 0, "timed_out": False, "stderr": ""}

    monkeypatch.setattr(app, "_task_run", build)
    request = spec()
    request["demo"]["build"] = {"recipe": "pip", "arguments": ["requirements.txt"]}
    result = app.submit("prepare_verification", request)
    assert result["status"] == "ok", result
    assert len(commands) == 1 and "--no-index" not in commands[0]
    unpacked = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], unpacked)
    assert (unpacked / "products/packages/dependency.py").read_text() == "VALUE = 42"
    assert json.loads((unpacked / "spec.json").read_text())["demo"]["build"] == {"recipe": "none", "arguments": []}


def test_open_logs_count_toward_scratch_guard(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    result = app.submit("run", {"command": [sys.executable, "-c", "print('x'*30000)"]})
    assert result["status"] == "could_not_build" and result["reason"] == "ScratchLimit: scratch limit"


def test_unreadable_scratch_is_not_reported_as_empty(tmp_path):
    with pytest.raises(OSError, match="scratch root unavailable"):
        task_storage.check(tmp_path / "missing")


def test_pip_removing_enumerated_directory_is_not_guard_failure(workspace, monkeypatch):
    original = task_storage.os.walk

    def disappearing(root, **kwargs):
        kwargs["onerror"](FileNotFoundError(2, "removed pip build directory", str(root / "pip-build")))
        yield from original(root, **kwargs)

    monkeypatch.setattr(task_storage.os, "walk", disappearing)
    (workspace / "input").write_bytes(b"input")
    assert task_storage.check(workspace) >= 5


def test_guard_still_refuses_permission_errors(workspace, monkeypatch):
    def unreadable(root, **kwargs):
        kwargs["onerror"](PermissionError("permission denied"))
        return iter(())

    monkeypatch.setattr(task_storage.os, "walk", unreadable)
    with pytest.raises(PermissionError):
        task_storage.check(workspace)


def test_child_environment_has_disk_home_and_owned_runtime_path(workspace):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "input").write_bytes(b"proof")
    code = (
        "import os; from pathlib import Path; print(Path('input').stat().st_size); "
        "print(os.environ['PATH']); p=Path.home()/'probe'; p.write_text('ok'); print(p)"
    )
    result = executor.InProcessExecutor(repo, task_boundary=True).submit("run", {"command": [sys.executable, "-c", code]})
    assert result["exit_code"] == 0
    assert result["stdout"].startswith("5\n/venv/bin:")
    assert (workspace / "home/probe").read_text() == "ok"


def test_scratch_failure_preserves_exit_and_stderr(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    monkeypatch.setenv("OUSAST_SCRATCH_BYTES", "20000")
    code = (
        "import sys,time; from pathlib import Path; print('pip build detail',file=sys.stderr,flush=True); "
        "Path('big').write_bytes(b'x'*30000); time.sleep(10)"
    )
    result = executor.InProcessExecutor(repo, task_boundary=True).submit("run", {"command": [sys.executable, "-c", code]})
    assert result["phase"] == "scratch guard"
    assert result["exit_code"] is not None
    assert result["stderr"] == "pip build detail"
    assert result["reason"].startswith("ScratchLimit:")


@pytest.mark.parametrize("project", [".", "subproject"])
def test_preparation_uses_project_gradle_wrapper(workspace, monkeypatch, project):
    repo = workspace / "checkout"
    repo.mkdir()
    root = repo / project
    root.mkdir(exist_ok=True)
    # A real local child proves wrapper execution without system Gradle or network.
    wrapper = root / "gradlew"
    wrapper.write_text(
        'test "$1" = "--no-daemon" || exit 1\n'
        'test "$2" = "--project-dir" || exit 2\n'
        'test "$4" = "assemble" || exit 3\n'
        'mkdir -p "$3/build"\n'
        'printf compiled > "$3/build/product"\n'
    )
    wrapper.chmod(0o644)
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    blobs = []
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))
    request = spec()
    request["demo"]["build"] = {"recipe": "gradle", "arguments": [project]}
    result = app.submit("prepare_verification", request)
    assert result["status"] == "ok", result
    unpacked = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], unpacked)
    assert (unpacked / "checkout" / project / "build/product").read_text() == "compiled"
    assert json.loads((unpacked / "spec.json").read_text())["demo"]["build"]["recipe"] == "none"


def test_preparation_with_many_host_processes(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "gradlew").write_text('mkdir -p "$3/build"\nprintf compiled > "$3/build/product"\n')
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: None)
    request = spec()
    request["demo"]["build"] = {"recipe": "gradle", "arguments": ["."]}
    children = []
    try:
        for _ in range(300):
            pid = os.fork()
            if pid == 0:
                time.sleep(60)
                os._exit(0)
            children.append(pid)
        result = app.submit("prepare_verification", request)
        assert result["status"] == "ok", result
        assert (repo / "build/product").read_text() == "compiled"
    finally:
        for pid in children:
            os.kill(pid, signal.SIGKILL)
        for pid in children:
            os.waitpid(pid, 0)


@pytest.mark.parametrize("memory_bytes", [None, 256 * 1024**2, 5 * 1024**3])
def test_prepare_build_virtual_memory(workspace, monkeypatch, memory_bytes):

    repo = workspace / "checkout"
    repo.mkdir()
    source = "import mmap; region=mmap.mmap(-1,512*1024**2); print(len(region))"
    (repo / "app.py").write_text(source)
    print("input_bytes=", len((repo / "app.py").read_bytes()))
    (repo / "package.json").write_text("{}")
    fake_bin = workspace / "bin"
    fake_bin.mkdir()
    tool = fake_bin / "npm"
    tool.write_text("#!" + sys.executable + "\n" + source)
    tool.chmod(0o755)
    monkeypatch.setitem(executor.SAFE_ENV, "PATH", str(fake_bin) + ":/usr/bin:/bin")
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    blobs = []
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))
    request = spec()
    request["demo"]["build"] = {"recipe": "npm", "arguments": ["."]}
    limits = {} if memory_bytes is None else {"memory_bytes": memory_bytes}
    result = app.submit("prepare_verification", request, limits=limits)
    if memory_bytes == 256 * 1024**2:
        assert result["status"] == "could_not_build" and not blobs
    else:
        assert result["status"] == "ok" and blobs, result


def test_verifier_app_virtual_memory(workspace):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text("import mmap; region=mmap.mmap(-1,512*1024**2); print(len(region))")
    print("input_bytes=", len((repo / "app.py").read_bytes()))
    demo = workspace / "demo.json"
    demo.write_text(json.dumps(spec()["demo"]))
    result = verify_side_task(Side(repo), demo, "path")
    assert result.outcome == "observed", result


@pytest.mark.parametrize(
    "recipe,manifest,extra,expected",
    [
        ("pip", "pyproject.toml", {}, ["-I", "-m", "pip", "install", "--no-deps", "--target", "PACKAGES", "PROJECT"]),
        ("pip", "requirements.txt", {}, ["-I", "-m", "pip", "install", "--no-deps", "--target", "PACKAGES", "-r", "MANIFEST"]),
        (
            "pip",
            "pyproject.toml",
            {"requirements.txt": ""},
            ["-I", "-m", "pip", "install", "--no-deps", "--target", "PACKAGES", "-r", "REQUIREMENTS"],
        ),
        ("npm", "package.json", {}, ["install", "--ignore-scripts"]),
        ("npm", "package.json", {"package-lock.json": "{}"}, ["ci", "--ignore-scripts"]),
        ("composer", "composer.json", {}, ["install", "--no-interaction", "--no-plugins", "--no-scripts"]),
        ("maven", "pom.xml", {}, ["-q", "-DskipTests", "package", "-f", "MANIFEST"]),
    ],
)
@pytest.mark.parametrize("directory", [False, True])
def test_recipe_command_with_real_fake_tool(workspace, monkeypatch, recipe, manifest, extra, expected, directory):
    repo = workspace / "checkout"
    project = repo / "project"
    project.mkdir(parents=True)
    (repo / "app.py").write_text("print('ready')")
    contents = '[build-system]\nbuild-backend="setuptools.build_meta"\n' if manifest == "pyproject.toml" and not extra else ""
    (project / manifest).write_text(contents)
    for name, content in extra.items():
        (project / name).write_text(content)
    tools = workspace / "bin"
    tools.mkdir()
    tool = tools / {"pip": "python3", "maven": "mvn"}.get(recipe, recipe)
    tool.write_text(
        "#!" + sys.executable + "\nimport json, os, sys\nfrom pathlib import Path\n"
        "Path('invocation.json').write_text(json.dumps([sys.argv[1:], os.getcwd()]))\n"
    )
    tool.chmod(0o755)
    monkeypatch.setitem(executor.SAFE_ENV, "PATH", str(tools) + ":/usr/bin:/bin")
    monkeypatch.setattr(executor.URLTransport, "put", lambda *args: None)
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    request = spec()
    request["demo"]["build"] = {"recipe": recipe, "arguments": ["project" if directory else "project/" + manifest]}
    result = app.submit("prepare_verification", request)
    assert result["status"] == "ok", result
    argv, cwd = json.loads((project / "invocation.json").read_text())
    assert cwd == str(project)
    replacements = {"PROJECT": str(project), "MANIFEST": str(project / manifest), "REQUIREMENTS": str(project / "requirements.txt")}
    if "--target" in argv:
        packages = argv[argv.index("--target") + 1]
        assert Path(packages).name == "packages" and Path(packages).is_relative_to(workspace)
        replacements["PACKAGES"] = packages
    assert argv == [replacements.get(arg, arg) for arg in expected]


def test_failed_build_preserves_sanitized_tail(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "gradlew").write_text(
        "for i in $(seq 1 30); do echo line-$i >&2; done\necho 'https://example.test/?token=secret token=hidden' >&2\nexit 7\n"
    )
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    request = spec()
    request["demo"]["build"] = {"recipe": "gradle", "arguments": ["."]}
    result = app.submit("prepare_verification", request)
    assert result["status"] == "could_not_build" and result["exit_code"] == 7
    assert result["phase"] == "build"
    assert "line-30" in result["stderr"] and "line-1\n" not in result["stderr"]
    assert "hidden" not in result["stderr"] and "https://" not in result["stderr"]
    assert len(result["stderr"]) <= 1500 and len(result["stderr"].splitlines()) <= 20


@pytest.mark.parametrize("mode", ["cli", "http"])
def test_verifier_start_failure_has_diagnostics(workspace, mode):
    repo = workspace / "checkout"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import sys\nprint('start failed token=hidden https://example.test/?secret=x', file=sys.stderr)\nsys.exit(9)"
    )
    demo = workspace / "demo.json"
    value = spec()["demo"]
    value["start"]["mode"] = mode
    if mode == "http":
        value["start"]["port"] = 19001
        value["steps"] = [{"type": "http", "method": "GET", "path": "/"}]
    demo.write_text(json.dumps(value))
    result = verify_side_task(Side(repo), demo, "path")
    assert result.outcome == "could_not_run", result
    assert result.phase == "start" and result.exit_code == 9
    assert "start failed" in result.stderr and "hidden" not in result.stderr and "https://" not in result.stderr


@pytest.mark.parametrize("secret", ['token="hidden"', '"password": "hidden"', "Bearer hidden", "ghp_hidden", "npm_hidden"])
def test_command_failure_sanitizes_tokens_and_caps_tail(secret):
    failure = task_storage.CommandFailure("build", 1, "old\n" * 50 + "x" * 2000 + "\n" + secret)
    assert "hidden" not in failure.stderr and "old" not in failure.stderr
    assert len(failure.stderr) <= 1500


def test_prepare_preserves_large_config_and_task_verifier_applies_it(workspace, monkeypatch):
    repo = workspace / "checkout"
    repo.mkdir()
    source = (
        "import os\nfrom pathlib import Path\n"
        "assert os.environ['JWT_KEY'] == 'required-key'\n"
        "assert Path(os.environ['JWT_FILE']).read_text() == 'x' * 65536\n"
        "print('ready')\n"
    )
    (repo / "app.py").write_text(source)
    request = spec()
    request["demo"]["start"].update(
        environment={"JWT_KEY": "required-key", "JWT_FILE": ".demo/jwt.pem"},
        files={"jwt.pem": "x" * 65536, "other.json": "{}"},
    )
    blobs = []
    app = executor.InProcessExecutor(repo, task_boundary=True)
    app.prepared_put_url = "https://files.example/output"
    monkeypatch.setattr(executor.URLTransport, "put", lambda self, url, data, timeout: blobs.append(data))
    result = app.submit("prepare_verification", request)
    assert result["status"] == "ok", result
    destination = workspace / "unpacked"
    verify_task.extract_checkout(blobs[0], destination)
    exported = json.loads((destination / "spec.json").read_text())
    assert exported == request
    assert not (destination / "checkout/.demo").exists()
    demo = workspace / "demo"
    demo.mkdir()
    (demo / "demo.json").write_text(json.dumps(exported["demo"]))
    observation = verify_side_task(Side(destination / "checkout", products=destination / "products"), demo, "path")
    assert observation.outcome == "observed", observation
    assert len(observation.runs) == 1
