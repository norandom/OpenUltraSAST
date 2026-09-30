"""Shared test fixtures."""

import subprocess
import sys

import pytest


@pytest.fixture(autouse=True)
def _pointer_pairs_offline(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Req 10.4: the default test run never touches the network for pointer pairs, whatever the operator's shell exports."""
    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path_factory.mktemp("pair-cache")))


@pytest.fixture(autouse=True)
def _repos_offline(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Req 4.1: pinned repository recipes never fetch during a test run, whatever the operator's shell exports.

    The cache is redirected as well as the switch cleared, so a developer with warm checkouts and a test that
    forgets to pass an explicit root still cannot read them by accident.
    """
    monkeypatch.delenv("OPENULTRASAST_REPOS_NETWORK", raising=False)
    monkeypatch.setenv("OPENULTRASAST_REPO_CACHE", str(tmp_path_factory.mktemp("repo-cache")))


@pytest.fixture
def assert_cold_import():  # type: ignore[no-untyped-def]
    """Run ``code`` in a fresh interpreter and assert it exits 0.

    Hermetic by construction: an import-laziness check (``code`` asserts on ``sys.modules`` itself) is not
    polluted by modules other tests have already imported into this process.
    """

    def _check(code: str) -> str:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"exit={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        return proc.stdout

    return _check


@pytest.fixture(autouse=True)
def _scratch_under_tmp_path(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Every CPG build makes an `ousast-cpg-*` scratch directory, and a test that feeds it a fake engine never
    reaches the cleanup a real run does: one run of the backend tests left fifteen of them in the system
    temp directory, and the product's stale sweep waits six hours. Pointing `tempfile` at the test's own
    directory keeps them out of `/tmp` entirely, whatever the test forgets.
    """
    import tempfile

    scratch = tmp_path_factory.mktemp("scratch")
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))


FAKE_KUBECTL_ATE = r'''#!{python}
"""Fake kubectl-ate for egress policies: an actor exists while ``applied/<actor>.json`` exists and is not gone
(the fake ax's record); its policy goes with it, as Substrate's store cascades. Every call is logged to ax.log."""
import json, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
argv = sys.argv[1:]
if argv[:1] == ["--context"]:
    argv = argv[2:]
verb, actor, space = argv[0], argv[2], argv[argv.index("-a") + 1]
with (HERE / "ax.log").open("a") as log:
    log.write(f"{time.monotonic():.4f} egress {verb} {actor}\n")
record = HERE / "applied" / f"{actor}.json"
alive = record.exists() and not json.loads(record.read_text()).get("gone")
store = HERE / "policies" / f"{space}_{actor}.json"
if not alive:
    store.unlink(missing_ok=True)
    sys.exit(print(f'Error: actor "{actor}" in atespace "{space}" not found', file=sys.stderr) or 1)
if verb == "get":
    if not store.exists():  # kubectl-ate: no policy is a valid state, exit 0 with nothing on stdout
        sys.exit(print(f'actor "{actor}" in atespace "{space}" has no egress policy', file=sys.stderr) or 0)
    print(store.read_text())
elif verb in ("create", "update"):
    body = json.loads(sys.stdin.read())
    old = json.loads(store.read_text()) if store.exists() else None
    if verb == "create" and old is not None:
        sys.exit(print("Error: already exists", file=sys.stderr) or 1)
    version = 1 if old is None else old["metadata"]["version"] + 1
    body["metadata"] = {"name": "default", "atespace": space, "uid": "uid-1", "version": version}
    store.parent.mkdir(exist_ok=True)
    store.write_text(json.dumps(body))
    (HERE / "policies" / f"{space}_{actor}.written.json").write_text(json.dumps(body))  # survives the cascade
    print(f"egress policy {verb}d")
'''


@pytest.fixture
def kubectl_ate(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A fake ``kubectl-ate`` in ``tmp_path`` (shared with the fake ax there); no settle wait."""
    path = tmp_path / "kubectl-ate"
    path.write_text(FAKE_KUBECTL_ATE.replace("{python}", sys.executable), encoding="utf-8")
    path.chmod(0o755)
    monkeypatch.setenv("OUSAST_KUBECTL_ATE", str(path))
    monkeypatch.setenv("OUSAST_EGRESS_SETTLE", "0")
    return path
