from pathlib import Path

import yaml


def test_image_matches_runner_and_publishes_digest():
    base = Path("plane/Dockerfile.base").read_text()
    image = Path("plane/Dockerfile.search-task").read_text()
    assert "FROM ghcr.io/norandom/ax-task-runner:v0.3.1" in base
    for package in ("nodejs", "node-typescript", "php-cli", "sqlite3", "bubblewrap", "util-linux", "chromium"):
        assert package in base
    assert "python3 -m venv /venv" in base
    assert image.rsplit("USER ", 1)[1].startswith("root\n")
    assert "--uid 10001 --gid 10001 search" in image
    assert "setpriv --version" in base
    assert "21-jdk" in base and "--no-install-recommends" in base
    assert "rm -rf /var/lib/apt/lists/" in base
    workflow_text = Path(".github/workflows/engine-image.yml").read_text()
    entries = yaml.safe_load(workflow_text)["jobs"]["image"]["strategy"]["matrix"]["include"]
    assert {"package": "ousast-search-task", "dockerfile": "plane/Dockerfile.search-task"} in entries
    assert "steps.build.outputs.digest" in workflow_text and "push: true" in workflow_text
