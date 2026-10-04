"""Synthetic, offline result snapshots; no analyzer, model or corpus access."""

import hashlib
import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def audit_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "benchmarks/learn"))
    return importlib.import_module("joern_leak_audit")


def units(count=12):
    return [
        {"unit": f"{pair}-{label}", "pair": str(pair), "label": label, "family": "injection", "group": "g", "fold": "f"}
        for pair in range(count)
        for label in (1, 0)
    ]


def write_result(root, module, rows, name="pin", *, done=True, version=None):
    path = root / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "repo": "repo",
                "pin": name,
                "done": done,
                "materialization_version": module.materialization_version() if version is None else version,
                "units": rows,
            }
        )
    )
    return path


def result(unit, status):
    return {
        **unit,
        "source": "authored",
        "status": status,
        "pin_role": "vulnerable" if unit["label"] else "fixed",
        "traces": [{"steps": [{"roles": ["source"]}, {"roles": ["sink"]}], "sanitized": False, "guard": {"text": "", "bounded": False}}]
        if status == "path"
        else [],
        "witness_rows": [{"sink": "execute(x)"}] if status == "path" else [],
    }


def run(module, root, population):
    return module.audit(population, root, expected_rows=len(population), expected_pairs=len(population) // 2)


def test_skips_stale_unfinished_and_proves_read(audit_module, tmp_path):
    population = units(2)
    paths = [
        write_result(tmp_path, audit_module, [result(population[0], "path")], "valid"),
        write_result(tmp_path, audit_module, [result(population[1], "path")], "stale", version=-1),
        write_result(tmp_path, audit_module, [result(population[2], "path")], "unfinished", done=False),
        write_result(tmp_path, audit_module, [result(population[3], "path")], "both", version=-1, done=False),
    ]
    report = run(audit_module, tmp_path, population)
    evidence = report["inputs"]
    assert (evidence["stale"], evidence["unfinished"], evidence["skipped"]) == (2, 2, 3)
    assert evidence["files_read"] == 4 and evidence["accepted_files"] == evidence["result_rows_read"] == 1
    assert evidence["bytes_read"] == sum(p.stat().st_size for p in paths)
    assert report["matched_rows"] == 1
    assert report["overall"]["coverage"]["missing"] == 3
    assert report["by_source"]["unknown"]["rows"] == 3
    assert report["overall"]["signals"]["has_path"]["rows"] == 1
    assert report["overall"]["both_asked_signals"]["has_path"]["pooled_auc"] is None


def test_asymmetry_and_honest_denominator(audit_module, tmp_path):
    population = units(6)
    statuses = [
        "path",
        "asked-nothing",
        "asked-nothing",
        "path",
        "path",
        "path",
        "asked-nothing",
        "asked-nothing",
        "path",
        "failed",
        "unsupported",
        "timeout",
    ]
    write_result(tmp_path, audit_module, [result(u, s) for u, s in zip(population, statuses, strict=True)])
    report = run(audit_module, tmp_path, population)
    overall = report["overall"]
    assert overall["pair_asymmetry"] == {"vulnerable_only": 1, "fixed_only": 1, "both": 1, "neither": 1, "not_both_asked": 2}
    assert overall["both_asked_pairs"] == 4
    assert overall["both_asked_signals"]["asked"]["within_pair_accuracy"] == 0.5
    assert overall["coverage"] == {"path": 5, "asked-nothing": 4, "failed": 1, "timeout": 1, "unsupported": 1, "missing": 0}
    assert report["by_family"]["injection"] == overall == report["by_source"]["authored"]


@pytest.mark.parametrize("balanced", [False, True])
def test_constructed_leak_and_balanced_set(audit_module, tmp_path, balanced):
    population = units()
    rows = [result(u, "path" if u["label"] == (int(u["pair"]) % 2 if balanced else 1) else "asked-nothing") for u in population]
    write_result(tmp_path, audit_module, rows)
    overall = run(audit_module, tmp_path, population)["overall"]
    for denominator in ("signals", "both_asked_signals"):
        signals = overall[denominator]
        for name in ("has_path", "shortest_path_steps"):
            assert signals[name]["flagged"] is not balanced
            assert signals[name]["within_pair_accuracy"] == signals[name]["pooled_auc"] == (0.5 if balanced else 1)
        assert signals["sink_kind"]["execute"]["flagged"] is not balanced
        assert not signals["asked"]["flagged"]
        assert not signals["sanitized"]["flagged"]
        assert not signals["guard_present"]["flagged"]


def test_minimum_samples_reverse_and_source_proxy(audit_module, tmp_path):
    population = units(2)
    write_result(tmp_path, audit_module, [result(u, "path" if not u["label"] else "asked-nothing") for u in population])
    assert not run(audit_module, tmp_path, population)["overall"]["signals"]["has_path"]["flagged"]
    population = units(12)
    rows = []
    for u in population:
        row = result(u, "path" if not u["label"] else "unsupported")
        row["source"] = "positive" if u["label"] else "negative"
        rows.append(row)
    write_result(tmp_path, audit_module, rows)
    report = run(audit_module, tmp_path, population)
    assert report["overall"]["signals"]["asked"]["flagged"]
    assert report["overall"]["signals"]["asked"]["pooled_auc"] == 0
    assert report["overall"]["both_asked_pairs"] == 0
    assert report["by_source"]["positive"]["signals"]["asked"]["pooled_auc"] is None


def test_shortest_trace_evidence_and_missing_trace(audit_module):
    row = result(units(1)[0], "path")
    row["traces"].insert(0, {"steps": [{}] * 5, "sanitized": False})
    row["witness_rows"].insert(0, {"sink": "longer(x)"})
    row["traces"][1].update(sanitized=True, guard={"bounded": True, "text": "off-path bound"})
    features = audit_module.features(row)
    assert (features["shortest_path_steps"], features["sanitized"], features["guard_present"], features["sink_kind"]) == (
        2,
        1,
        1,
        "execute",
    )
    row["traces"] = []
    assert audit_module.features(row)["shortest_path_steps"] is None


def test_bad_inputs_fail_loudly(audit_module, tmp_path):
    population = units(1)
    write_result(tmp_path, audit_module, [result(population[0], "path")] * 2)
    with pytest.raises(ValueError, match="Duplicate"):
        run(audit_module, tmp_path, population)
    write_result(tmp_path, audit_module, [{**result(population[0], "path"), "label": 0}])
    with pytest.raises(ValueError, match="metadata mismatch"):
        run(audit_module, tmp_path, population)


@pytest.mark.parametrize("done", [False, True])
def test_record_uses_hashes_without_repository_identity(audit_module, tmp_path, done):
    repo = "https://github.com/owner/name"
    population = [{**u, "group": "owner/name", "repo": repo, "source": "population-v1"} for u in units(1)]
    root = tmp_path / "github.com" / "owner" / "name"
    root.mkdir(parents=True)
    paths = []
    for i, u in enumerate(population):
        row = {**result(u, "path"), "source": "population-v1"}
        path = write_result(root, audit_module, [row], f"name-{1 - i}", done=done)
        record = json.loads(path.read_text())
        record.update(repo=repo, pin="owner/name")
        path.write_text(json.dumps(record))
        paths.append(path)
    report = run(audit_module, root, population)
    serialized = json.dumps(report)
    assert repo not in serialized and "owner/name" not in serialized
    assert "files" not in report["inputs"]
    inventory = sorted((p.name, p.stat().st_size) for p in paths)
    assert report["inputs"]["files_sha256"] == hashlib.sha256(json.dumps(inventory, separators=(",", ":")).encode()).hexdigest()
    assert report["inputs"]["files_read"] == 2
    assert report["inputs"]["bytes_read"] == sum(size for _, size in inventory)
    assert report["inputs"]["result_rows_read"] == (2 if done else 0)
    assert report["by_source"]["population-v1"]["rows"] == 2
    assert [r["unit"] for r in report["units"]] == [u["unit"] for u in population]
    assert [r["pair"] for r in report["units"]] == [u["pair"] for u in population]
