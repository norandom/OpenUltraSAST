"""Shared test fixtures."""

import subprocess
import sys

import pytest

_HARNESSX_GUARD = (
    "\nimport sys as _sys\n"
    "_leaked = sorted(m for m in _sys.modules if m == 'harnessx' or m.startswith('harnessx.'))\n"
    "assert not _leaked, 'leaked harnessx modules: ' + repr(_leaked)\n"
)


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
