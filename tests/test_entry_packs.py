"""Entry-pack wiring tests for detection-core 8.2 part 2 (Req 10, 3)."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.mapping.entry_packs import load_entry_pack_patterns  # noqa: E402
from openultrasast.mapping.legacy import _js_entry_points, analyze_entry_points, entry_framework  # noqa: E402
from openultrasast.preprocess import FileTarget, detect_language  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

TS_SOURCE = """import express from "express";
const app = express();
app.all("/admin", adminHandler);
function adminHandler(req, res) { res.send("ok"); }
"""


def _target(root: Path, name: str, text: str) -> FileTarget:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return FileTarget(name, str(path), detect_language(path), 5, [], False, [], [])


def test_pack_patterns_loaded_for_typescript() -> None:
    patterns = load_entry_pack_patterns()
    assert patterns.get("typescript") and any(p.search("app.all(") for p in patterns["typescript"])


def test_pack_patterns_resolve_from_package_not_target_repo() -> None:
    # default call reads the installed package's ruleset, independent of any analyzed repo
    assert load_entry_pack_patterns().get("typescript")
    # an explicit root is a test-staging override only
    with tempfile.TemporaryDirectory() as tmp:
        assert load_entry_pack_patterns(Path(tmp)) == {}


def test_pack_only_pattern_recognised_as_express_route() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = _target(root, "src/routes.ts", TS_SOURCE)
        without = _js_entry_points(target, TS_SOURCE, [])
        assert not any(e.kind == "route" for e in without)
        packs = load_entry_pack_patterns()
        with_pack = _js_entry_points(target, TS_SOURCE, packs.get("typescript", []))
        routes = [e for e in with_pack if e.kind == "route"]
        assert routes, "pack-only pattern app.all( must be recognised"
        assert any("Express" in " ".join(e.access_evidence) for e in routes)
        assert entry_framework(routes[0]) == "express"


def test_analyze_entry_points_uses_packs() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = _target(root, "src/routes.ts", TS_SOURCE)
        entries = analyze_entry_points(root, [target], texts={target.path: TS_SOURCE}, include_manifests=False)
        routes = [e for e in entries if e.kind == "route" and e.defines_handler]
        assert routes
        assert entry_framework(routes[0]) == "express"
