"""Shared test fixtures."""

import subprocess
import sys

import pytest

_HARNESSX_GUARD = (
    "\nimport sys as _sys\n"
    "_leaked = sorted(m for m in _sys.modules if m == 'harnessx' or m.startswith('harnessx.'))\n"
    "assert not _leaked, 'leaked harnessx modules: ' + repr(_leaked)\n"
)


@pytest.fixture(autouse=True)
def _pointer_pairs_offline(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Req 10.4: the default test run never touches the network for pointer pairs, whatever the operator's shell exports."""
    monkeypatch.delenv("OPENULTRASAST_PAIRS_NETWORK", raising=False)
    monkeypatch.setenv("OPENULTRASAST_PAIR_CACHE", str(tmp_path_factory.mktemp("pair-cache")))


@pytest.fixture
def assert_cold_of_harnessx():  # type: ignore[no-untyped-def]
    """Run ``code`` in a fresh interpreter and assert it imported no ``harnessx`` module.

    Hermetic by construction: the lazy-import guarantee is verified the same way
    whether or not the optional extra is installed in this environment (a global
    ``sys.modules`` check would be polluted by other tests once the extra is present).
    """

    def _check(code: str) -> str:
        proc = subprocess.run(
            [sys.executable, "-c", code + _HARNESSX_GUARD],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"exit={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        return proc.stdout

    return _check
