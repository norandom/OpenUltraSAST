"""benchmarks/repos/measure.py reads the scan's run from the `run_dir=` line the scan prints, so it follows the run
into the user cache (it used to look under the scanned copy and recorded every repository as failed)."""

import importlib.util
from pathlib import Path


def _measure():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("measure", Path(__file__).resolve().parents[1] / "benchmarks" / "repos" / "measure.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_measure_finds_the_scan_run_where_the_scan_puts_it(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")

    outcome = _measure()._scan(repo, "quick")

    assert outcome["completed"] is True, outcome
    assert outcome["findings_total"] == 1
    assert not (repo / ".openultrasast" / "runs").exists()
