import json
from pathlib import Path

from openultrasast.cli import main
from openultrasast.hunter import assign_tier, run_hunter_pool, schedule_hunter_tasks, select_skill_snippets, write_hunter_trajectories
from openultrasast.preprocess import FileTarget
from openultrasast.rank import RankingScore


def test_assign_tier_uses_priority_bands() -> None:
    assert assign_tier(3.0) == "A"
    assert assign_tier(2.0) == "B"
    assert assign_tier(1.99) == "C"


def test_schedule_hunter_tasks_assigns_budget_and_skill_metadata() -> None:
    target = FileTarget(
        path="parser.c",
        absolute_path="/repo/parser.c",
        language="c",
        loc=20,
        tags=["memory_unsafe", "parser"],
        has_fuzz_entry_point=False,
    )
    ranking = RankingScore(
        path="parser.c",
        surface=5,
        influence=2,
        reachability=4,
        priority=4.1,
        rationale="fixture",
        model_id=None,
        static_boosts=[],
    )

    tasks = schedule_hunter_tasks([target], [ranking], retrieval_context_by_path={"parser.c": "x" * 10_000})

    assert len(tasks) == 1
    assert tasks[0].tier == "A"
    assert tasks[0].budget.max_findings_per_target == 20
    assert len(tasks[0].retrieval_context) == tasks[0].budget.retrieval_budget_chars
    assert "address-sanitizer" in tasks[0].selected_skills
    assert "harness-writing" in tasks[0].selected_skills


def test_run_hunter_pool_persists_trajectory_linked_to_finding(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    target = FileTarget(
        path="app.py",
        absolute_path=str(repo / "app.py"),
        language="python",
        loc=3,
        tags=["network_entry"],
        has_fuzz_entry_point=False,
        reachability_hints=[
            {
                "kind": "route",
                "access_level": "public",
                "line": 1,
                "end_line": 3,
                "function_name": "admin",
                "conditions": [],
            }
        ],
    )
    ranking = RankingScore("app.py", 4, 1, 5, 3.7, "fixture", None, [])

    result = run_hunter_pool(repo, [target], [ranking], scan_id="scan-1")
    output = tmp_path / "hunter_trajectories.jsonl"
    write_hunter_trajectories(result.trajectories, output)

    line = json.loads(output.read_text().splitlines()[0])
    assert result.findings[0].finding_id in line["findings"]
    assert line["target_path"] == "app.py"
    assert line["retrieval_context_chars"] > 0
    assert line["status"] == "completed"


def test_select_skill_snippets_routes_crypto_and_auth_targets() -> None:
    target = FileTarget(
        path="auth/crypto.py",
        absolute_path="/repo/auth/crypto.py",
        language="python",
        loc=20,
        tags=["crypto", "auth_boundary"],
        has_fuzz_entry_point=False,
    )

    snippets = select_skill_snippets(target)

    assert "constant-time-analysis" in snippets
    assert "sharp-edges" in snippets


def test_standard_mode_writes_hunter_trajectory_and_manifest_ref(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("@app.route('/admin')\ndef admin():\n    return eval(request.data)\n")
    monkeypatch.setenv("OPENULTRASAST_RUNS_DIR", ".runs")

    assert main(["scan", str(repo), "--mode", "standard", "--fail-on", "verified"]) == 1

    run_dir = sorted((repo / ".runs").iterdir())[-1]
    trajectory_path = run_dir / "traces" / "hunter_trajectories.jsonl"
    manifest = json.loads((run_dir / "manifest.json").read_text())

    assert trajectory_path.exists()
    assert manifest["findings"][0]["artifact_refs"]["trajectories_jsonl"] == "traces/hunter_trajectories.jsonl"
