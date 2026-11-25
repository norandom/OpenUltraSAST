"""The dagger pipeline uploads the working tree to its container; the local .env must stay out of that upload."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _uploaded_excludes() -> list[str]:
    """The exclude list of the upload in dagger/ci.py, parsed as text: the test needs no dagger engine."""
    tree = ast.parse((ROOT / "dagger" / "ci.py").read_text())
    keywords = [node for node in ast.walk(tree) if isinstance(node, ast.keyword) and node.arg == "exclude"]
    assert len(keywords) == 1, f"dagger/ci.py passes {len(keywords)} exclude lists, expected one"
    assert isinstance(keywords[0].value, ast.List), "the exclude list in dagger/ci.py is expected to be a list literal"
    return [ast.literal_eval(item) for item in keywords[0].value.elts]


def test_the_dagger_upload_leaves_the_local_env_file_out() -> None:
    assert ".env" in _uploaded_excludes()
