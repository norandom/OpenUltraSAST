"""Handler-extraction tests for detection-core 8.2 part 3 (Req 3: recognition coverage)."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.mapping.legacy import _js_entry_points  # noqa: E402
from openultrasast.preprocess import FileTarget, detect_language  # noqa: E402

SOURCE = """import express from "express";
const app = express();
class Api {
  getHealth(req, res) { res.send("ok"); }
  submit(req, res) { res.send("done"); }
}
const api = new Api();
app.get("/health", api.getHealth.bind(api));
app.post("/submit", (req, res) => { res.send("done"); });
app.delete("/old", api.submit);
"""


def _target(root: Path) -> FileTarget:
    path = root / "src/routes.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SOURCE, encoding="utf-8")
    return FileTarget("src/routes.ts", str(path), detect_language(path), 9, [], False, [], [])


def test_bind_this_handler_resolves_with_defines_handler() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = _target(Path(tmp))
        routes = [e for e in _js_entry_points(target, SOURCE, []) if e.kind == "route"]
        health = next(e for e in routes if e.function_name == "getHealth")
        assert health.defines_handler is True


def test_arrow_inline_handler_counts_as_defined() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = _target(Path(tmp))
        routes = [e for e in _js_entry_points(target, SOURCE, []) if e.kind == "route"]
        submit = next(e for e in routes if e.function_name == "arrow_handler")
        assert submit.defines_handler is True


def test_plain_identifier_handler_still_works() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        target = _target(Path(tmp))
        routes = [e for e in _js_entry_points(target, SOURCE, []) if e.kind == "route"]
        delete = next(e for e in routes if e.function_name == "submit")
        assert delete.defines_handler is True
