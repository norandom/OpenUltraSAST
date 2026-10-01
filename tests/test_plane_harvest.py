"""The decision engine's harvest Runs (learned-decision-engine task 5): `ousast plane harvest`'s generator."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from openultrasast.plane import reconciler
from openultrasast.plane.harvest import MAX_INLINE_BYTES, Unit, blob_sha1, declaration_line, render_harvest
from openultrasast.plane.manifests import load_manifests

PLANE = Path("plane")
PIN = "0123456789abcdef0123456789abcdef01234567"


def _templates() -> dict:
    return load_manifests([PLANE / "tasks" / f"{n}.yaml" for n in ("repo-facts", "verify", "agree", "roles")]).tasks


def _units() -> list[Unit]:
    code = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"
    excerpt = Unit("h-aaaaaaaaaaaa", "pairs", "x-cwe-078-os-system", "vulnerable", "pairs/github/x", blob_sha1(code), "injection",
                   (("app.py", "run", 3),), (("app.py", code),))  # fmt: skip
    roles_only = Unit("h-bbbbbbbbbbbb", "pairs", "y-cwe-416", "fixed", "pairs/vfc/y", blob_sha1("int f(){}\n"), "",
                      (("f.c", "f", 1),), (("f.c", "int f(){}\n"),))  # fmt: skip
    big = "x = 1\n" * (MAX_INLINE_BYTES // 6 + 10)
    oversized = Unit(
        "h-cccccccccccc",
        "pairs",
        "z",
        "vulnerable",
        "pairs/github/z",
        blob_sha1(big),
        "injection",
        (("big.py", GLOBAL_, 1),),
        (("big.py", big),),
    )
    repo = Unit("h-dddddddddddd", "population-v1", "case", "vulnerable", "https://github.com/o/r", PIN, "injection",
                (("a.py", "q", 10), ("b.py", "r", 20)), sizes=(("a.py", 4000, 100), ("b.py", 8000, 900)))  # fmt: skip
    return [excerpt, roles_only, oversized, repo]


GLOBAL_ = "<global>"


def _render(tmp_path: Path, ceiling: float = 10.0) -> tuple[dict[str, str], Path]:
    files = render_harvest(_units(), _templates(), "hv", "test", ceiling=ceiling)
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "deepseek-flash.yaml").write_text((PLANE / "models" / "deepseek-flash.yaml").read_text())
    return files, tmp_path


def test_verify_run_shape_and_ceiling(tmp_path: Path) -> None:
    files, root = _render(tmp_path, ceiling=0.05)
    run, manifests = reconciler.load_run(root / "runs" / "hv-verify.yaml")
    names = [t.name for t in run.tasks]
    assert names == [
        "h-aaaaaaaaaaaa-va", "h-aaaaaaaaaaaa-vb", "h-aaaaaaaaaaaa-agree",
        "h-dddddddddddd-facts", "h-dddddddddddd-va", "h-dddddddddddd-vb", "h-dddddddddddd-agree",
    ]  # fmt: skip
    assert sum(float(t.budget.usd) for t in run.tasks) <= 0.05  # scaled down to the ceiling
    assert all(float(t.budget.usd) == 0 for t in run.tasks if t.name.endswith(("-agree", "-facts")))
    excerpt = manifests.tasks["verify-a-h-aaaaaaaaaaaa"]
    env = {e.name: e.value for e in excerpt.env}
    assert env["OUSAST_WORKSPACE_DIR"].endswith("/repo") and "/inputs/" in env["OUSAST_INPUT_CANDIDATES"]
    workspace = manifests.workspaces["h-aaaaaaaaaaaa-side"]
    paths = {f.path for f in workspace.files}
    assert paths == {"repo/app.py", "inputs/candidates.json"}  # candidates outside the hunt's root
    assert "cwe" not in yaml.safe_dump([workspace.metadata.name, *paths])  # the pair's name never reaches the sandbox
    units = json.loads(files["units.json"])
    assert "skipped" in units["h-cccccccccccc"] and "skipped" not in units["h-aaaaaaaaaaaa"]
    agree = {e.name: e.value for e in manifests.tasks["agree-h-dddddddddddd"].env}
    assert "OUSAST_INPUT_SITES" not in agree  # no declared sites: no site_match is computed


def test_roles_run_groups_excerpts_and_pins(tmp_path: Path) -> None:
    _, root = _render(tmp_path)
    run, manifests = reconciler.load_run(root / "runs" / "hv-roles.yaml")
    assert len(run.tasks) == 2 and sum(float(t.budget.usd) for t in run.tasks) <= 10.0
    grouped = next(w for w in manifests.workspaces.values() if w.metadata.name.startswith("hv-roles"))
    listing = json.loads(next(f.content for f in grouped.files if f.path == "inputs/files.json"))
    assert listing == ["h-aaaaaaaaaaaa/app.py", "h-bbbbbbbbbbbb/f.c"]  # the oversized excerpt is left out
    assert sum(len(f.content) for f in grouped.files) <= MAX_INLINE_BYTES + 200
    pin = manifests.tasks["roles-h-dddddddddddd"]
    assert {e.name: e.value for e in pin.env}["OUSAST_INPUT_FILES"].endswith("/files.json")


def test_blob_sha1_is_gits_and_declaration_lines() -> None:
    text = "def a():\n    pass\n\ndef b():\n    pass\n"
    done = subprocess.run(["git", "hash-object", "--stdin"], input=text, capture_output=True, text=True, check=True)
    assert blob_sha1(text) == done.stdout.strip()
    lines = text.splitlines()
    assert declaration_line(lines, "m.py", "b") == 4
    assert declaration_line(lines, "m.py", "missing") == 1 and declaration_line(None, "m.py", "a") == 1
