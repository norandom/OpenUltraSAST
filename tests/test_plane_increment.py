"""The increment's manifests under ``plane/`` (ai-service-plane task 7) and their generator."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml
from test_plane_reconciler import AX_FIELDS, non_ax_fields

from openultrasast.model.endpoint import price_of
from openultrasast.plane import reconciler
from openultrasast.plane.budget import prices_from
from openultrasast.plane.generate import TEMPLATES, fix_ranges, increment, read_cases, render, repin_templates
from openultrasast.plane.manifests import load_manifests

PLANE = Path("plane")
RUN = PLANE / "runs" / "validation-46.yaml"
POPULATION = Path("benchmarks/independent/population-v2.toml")
RESULTS = Path.home() / "ousast-results"
REPOS = Path.home() / ".cache" / "openultrasast" / "independent"
PIN = "0123456789abcdef0123456789abcdef01234567"


def _mebibytes(quantity: str) -> float:
    number, unit = re.fullmatch(r"([0-9.]+)(Mi|Gi)?", quantity).groups()  # type: ignore[union-attr]
    return float(number) * {"Mi": 1, "Gi": 1024, None: 1 / 2**20}[unit]


def test_every_manifest_under_plane_loads() -> None:
    paths = sorted(PLANE.rglob("*.yaml"))
    assert len(paths) >= 36, paths
    manifests = load_manifests(paths)
    assert set(manifests.models) == {"deepseek-flash"}
    assert set(TEMPLATES) <= set(manifests.tasks)
    assert len(manifests.workspaces) == 30 and "validation-46" in manifests.runs
    full = {t.name for t in manifests.runs["validation-46"].tasks}
    for name, other in manifests.runs.items():  # check Runs (e.g. check-lmdeploy) are subsets of the measurement
        assert {t.name for t in other.tasks} <= full, name


def test_model_prices_are_the_endpoint_prices() -> None:
    model = load_manifests([PLANE / "models" / "deepseek-flash.yaml"]).models["deepseek-flash"]
    assert model.provider == "deepseek" and model.model == "deepseek-flash"
    assert model.secret_key is not None and model.secret_key.key == "DEEPSEEK_API_KEY"
    assert prices_from(model.parameters) == price_of("deepseek-flash")


def test_validation_run_resolves_and_renders_every_task(tmp_path: Path) -> None:
    run, manifests = reconciler.load_run(RUN)
    assert len(run.tasks) == 60
    population = {c["id"]: c for c in tomllib.loads(POPULATION.read_text())["case"]}
    ax_names: set[str] = set()
    for task in manifests.tasks.values():
        assert task.image and "@sha256:" in task.image, task.metadata.name
        limits = task.resources.limits if task.resources else None
        assert limits and limits.cpu == "1" and _mebibytes(limits.memory or "0") <= 1536, task.metadata.name
    for entry in run.tasks:
        task = manifests.tasks[entry.task]
        model = task.metadata.annotations.get(reconciler.MODEL_ANNOTATION)
        assert model is None or model in manifests.models
        for binding in task.workspaces:
            workspace = manifests.workspaces[binding.name]
            for name, sha in workspace.pins.items():
                case_id = binding.name.removesuffix("-vulnerable")
                assert (name, sha) == ("repo", population[case_id]["vulnerable"])
        if entry.name.endswith(("-va", "-vb")):
            assert model == "deepseek-flash" and entry.budget and entry.budget.usd and entry.budget.calls
            env = {e.name: e.value for e in task.env}
            assert env["OUSAST_PASS"] == entry.name[-1]
        docs = reconciler.render_task(run, entry, manifests, tmp_path, "http://127.0.0.1:1/")
        for doc in docs:
            assert not non_ax_fields(doc["spec"], AX_FIELDS[doc["kind"]], doc["kind"])
            assert set(doc["metadata"]) <= {"name", "atespace"}
            assert len(doc["metadata"]["name"]) <= 63, doc["metadata"]["name"]
        assert docs[-1]["kind"] == "Task"
        assert docs[-1]["metadata"]["name"] not in ax_names
        ax_names.add(docs[-1]["metadata"]["name"])


def test_inputs_carry_the_validation_set() -> None:
    manifests = load_manifests(sorted((PLANE / "workspaces").glob("*-inputs.yaml")))
    assert len(manifests.workspaces) == 15
    candidates = kept = in_set = before = 0
    usd = triage = 0.0
    for workspace in manifests.workspaces.values():
        files = {f.path: json.loads(f.content) for f in workspace.files}
        assert set(files) == {"candidates.json", "functions.json", "case.json", "triage.json"}
        candidates += len(files["triage.json"]["candidates"])
        kept += len(files["candidates.json"]["candidates"])
        assert [[r["path"], r["function"], r["line"]] for r in files["functions.json"]] == files["candidates.json"]["candidates"]
        case = files["case.json"]
        assert case["ranges"] and all(first <= last for spans in case["ranges"].values() for first, last in spans), case["id"]
        assert set(case["sites_in_set"]) <= set(case["sites"])
        in_set += len(case["sites_in_set"])
        before += case["cost"]["candidates_before_triage"]
        usd += case["cost"]["recorded_usd"]
        triage += case["cost"]["recorded_triage_usd"]
        assert 0 < case["cost"]["recorded_triage_usd"] <= case["cost"]["recorded_usd"], case["id"]
    assert (candidates, kept, in_set, before) == (46, 43, 20, 46)
    # the reference's $1.01 for 46 candidates, two passes, triage included; triage was about 9% of it
    assert round(usd / before, 3) == 0.022 and 0.05 < triage / usd < 0.15


def test_templates_are_pinned_to_one_runner_image() -> None:
    images = {task.image for task in load_manifests(sorted((PLANE / "tasks").glob("*.yaml"))).tasks.values()}
    assert len(images) == 1 and re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", images.pop() or "")


def _committed_command() -> str:
    first = RUN.read_text().splitlines()[0]
    found = re.search(r"`([^`]+)`", first)
    assert found, first
    return found.group(1)


@pytest.mark.skipif(
    not (RESULTS / "independent-v2-batched-check" / "scans").is_dir() or not REPOS.is_dir(), reason="recorded results not on this host"
)
def test_committed_manifests_match_the_generator() -> None:
    templates = load_manifests([PLANE / "tasks" / f"{name}.yaml" for name in TEMPLATES]).tasks
    cases = read_cases(
        RESULTS / "independent-v2-sets" / "validation.json",
        RESULTS / "independent-v2-modelsinks",
        RESULTS / "independent-v2-batched-check" / "scans",
        POPULATION,
        REPOS,
    )
    for relative, text in render(cases, templates, "validation-46", _committed_command()).items():
        assert (PLANE / relative).read_text() == text, relative


# --- the generator on a synthetic set ---------------------------------------------------------------------------


def _fixture(root: Path) -> dict[str, Path]:
    population = root / "population.toml"
    population.write_text(
        "\n".join(
            f'[[case]]\nid = "{cid}"\nrepo = "https://example.com/{cid}"\nfamily = "injection"\n'
            f'vulnerable = "{PIN}"\nsites = ["a.py::run"]\n'
            for cid in ("beta", "alpha")
        )
    )
    candidates, scans = root / "cands", root / "scans"
    candidates.mkdir()
    scans.mkdir()
    rows = [["a.py", "run", 9], ["a.py", "run", 3], ["a.py", "helper", 20], ["b.py", "other", 1]]
    for cid in ("alpha", "beta"):
        (candidates / f"{cid}.json").write_text(json.dumps({"id": cid, "family": "injection", "candidates": rows}))
        asked = [["a.py", "helper", 20], ["a.py", "run", 9]]
        scan = {"path": "a.py", "candidates": asked, "kept": ["run"], "triage": {"helper": "internal"}}
        (scans / f"{cid}--vulnerable_a.jsonl").write_text(json.dumps({**scan, "usd": 0.5}) + "\n")
    validation = root / "set.json"
    validation.write_text(json.dumps({"beta": [["a.py", "run"], ["a.py", "helper"]], "alpha": [["a.py", "helper"], ["a.py", "run"]]}))
    plane = root / "plane"
    (plane / "tasks").mkdir(parents=True)
    for name in TEMPLATES:
        shutil.copy(PLANE / "tasks" / f"{name}.yaml", plane / "tasks")
    shutil.copytree(PLANE / "models", plane / "models")
    return {"population": population, "set": validation, "candidates": candidates, "scans": scans, "plane": plane}


def _generate(paths: dict[str, Path], plane: Path) -> list[Path]:
    return increment(
        paths["population"], paths["set"], paths["candidates"], paths["scans"], plane=plane, run_name="check", command="ousast plane test"
    )


def test_generator_is_deterministic_and_follows_the_reference(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    other = tmp_path / "again"
    shutil.copytree(paths["plane"], other)
    first, second = _generate(paths, paths["plane"]), _generate(paths, other)
    assert [p.relative_to(paths["plane"]) for p in first] == [p.relative_to(other) for p in second]
    assert all(a.read_bytes() == b.read_bytes() for a, b in zip(first, second, strict=True))
    assert first[0].read_text().startswith("# generated by `ousast plane test`")
    run, manifests = reconciler.load_run(paths["plane"] / "runs" / "check.yaml")
    assert [t.name for t in run.tasks][:4] == ["alpha-facts", "alpha-va", "alpha-vb", "alpha-agree"]
    inputs = {f.path: json.loads(f.content) for f in manifests.workspaces["alpha-inputs"].files}
    assert inputs["candidates.json"]["candidates"] == [["a.py", "run", 9]]  # last line of a repeated pair; triage applied
    assert inputs["triage.json"]["candidates"] == [["a.py", "helper", 20], ["a.py", "run", 9]]
    assert run.task("alpha-va").budget is not None and run.task("alpha-va").budget.usd == 0.38  # 1.5 * 0.5 / 2, cent up
    assert yaml.safe_load(first[0].read_text())["metadata"]["annotations"] == {"openultrasast.io/git-commits": f"repo={PIN}"}


def test_generator_refuses_a_set_the_recorded_scans_did_not_ask(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    paths["set"].write_text(json.dumps({"alpha": [["a.py", "run"], ["b.py", "other"]]}))
    with pytest.raises(ValueError, match="recorded scans asked"):
        _generate(paths, paths["plane"])
    (paths["scans"] / "alpha--vulnerable_a.jsonl").unlink()
    with pytest.raises(ValueError, match="no recorded triage"):
        _generate(paths, paths["plane"])


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def test_fix_ranges_are_the_old_side_of_the_fix_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "a.py").write_text("".join(f"line {i}\n" for i in range(1, 31)))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "vulnerable")
    vulnerable = _git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("".join(f"line {i}\n" if i not in (3, 4, 20) else "fixed\n" for i in range(1, 31)) + "added\n")
    _git(repo, "commit", "-qam", "fixed")
    assert fix_ranges(repo, vulnerable, _git(repo, "rev-parse", "HEAD")) == {"a.py": [(3, 4), (20, 20), (30, 30)]}
    with pytest.raises(ValueError, match="no repository"):
        fix_ranges(tmp_path / "absent", vulnerable, vulnerable)


def test_case_record_carries_sites_in_set_and_cost_and_the_image_is_repinned(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    digest = "localhost:5001/ousast-runner@sha256:" + "ab" * 32
    (tmp_path / "runner-image").write_text(digest + "\n")
    increment(
        paths["population"], paths["set"], paths["candidates"], paths["scans"], plane=paths["plane"], run_name="check",
        command="ousast plane test", runner_image=tmp_path / "runner-image",
    )  # fmt: skip
    manifests = load_manifests(sorted(paths["plane"].rglob("*.yaml")))
    assert {t.image for t in manifests.tasks.values()} == {digest}
    case = json.loads(next(f.content for f in manifests.workspaces["alpha-inputs"].files if f.path == "case.json"))
    assert "ranges" not in case and case["sites_in_set"] == ["a.py::run"]  # no --repos: agree reports not assessed
    assert case["cost"]["candidates_before_triage"] == 2 and case["cost"]["recorded_triage_usd"] == 0.5  # no hunt usage recorded
    (tmp_path / "runner-image").write_text("localhost:5001/ousast-runner:dev\n")
    with pytest.raises(ValueError, match="digest-pinned"):
        repin_templates(paths["plane"], tmp_path / "runner-image")
