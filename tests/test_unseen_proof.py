"""Proof records fail closed using synthetic local results."""

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
p = importlib.import_module("benchmarks.unseen.proof")


def test_replay_proof(tmp_path):
    roots = {}
    for lane in ("kind", "ax", "vm"):
        root = tmp_path / lane
        root.mkdir()
        roots[lane] = root
        (root / "inputs.json").write_text("[]")
        for i in range(5):
            (root / f"{i}.json").write_text(
                json.dumps(
                    {
                        "input_digest": str(i),
                        "status": "engine_covered",
                        "instrument": {"hook_bytes_read": 20, "jvm_wall_seconds": 8, "seconds": 30, "hook_exit": 0},
                        "push": {"quick_tier": [{"findings": []}]},
                    }
                )
            )
    assert p.replay_proof(roots)["quick_tier_equal"]
    path = roots["vm"] / "0.json"
    record = json.loads(path.read_text())
    record["instrument"]["jvm_wall_seconds"] = 0
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="instrument"):
        p.replay_proof(roots)


def test_engine_proof_counts_differences_without_names(tmp_path):
    current, baseline = tmp_path / "current", tmp_path / "baseline"
    current.mkdir()
    baseline.mkdir()
    for i in range(2):
        record = {
            "repo": "synthetic",
            "pin": str(i),
            "done": True,
            "seconds": 20,
            "units": [{"unit": str(i), "status": "path", "instrument": {"bytes": 20, "jvm": [{"seconds": 8, "success": True}]}}],
        }
        (current / f"{i}.json").write_text(json.dumps(record))
        (baseline / f"{i}.json").write_text(json.dumps(record))
    proof = p.engine_proof(current, baseline)
    assert proof["differences"] == 0 and "synthetic" not in json.dumps(proof)
