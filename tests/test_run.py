from pathlib import Path

from openultrasast.config import load_config
from openultrasast.run import create_scan_run


def test_create_scan_run_writes_directories_and_config(tmp_path: Path) -> None:
    run = create_scan_run(tmp_path, load_config(None))

    assert run.root.exists()
    assert (run.root / "preprocess").is_dir()
    assert (run.root / "resolved_config.json").is_file()
    assert run.root.parent.name == "runs"
