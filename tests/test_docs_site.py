"""The documentation site builds strictly, its Mermaid diagrams are well formed, and the RustFS page is complete.

The strict build runs only where ``mkdocs`` is importable (the ``docs`` extra); the other checks read the Markdown
and always run. The Mermaid check is syntactic (fences, a known diagram type, balanced brackets and quotes, the node
budget): the site renders diagrams in the browser, so nothing here can run the real parser.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PAGES = sorted(DOCS.rglob("*.md"))
DIAGRAM_TYPES = ("flowchart", "graph", "sequenceDiagram", "stateDiagram-v2", "stateDiagram", "classDiagram", "erDiagram")
MAX_NODES = 15
FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})(.*)$")

BUCKET_ACTIONS = (
    "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration",
)  # fmt: skip
OBJECT_ACTIONS = (
    "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
    "s3:GetObjectTagging", "s3:PutObjectTagging", "s3:GetObjectVersionTagging",
)  # fmt: skip
SECRET_SHAPES = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS-style access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:sk|pk)-[A-Za-z0-9_-]{16,}"),  # provider API keys
    re.compile(r"(?:SECRET|ACCESS)_KEY\s*=\s*[^\s<`.]"),  # an assignment with a value
    re.compile(r"(?<![0-9a-f])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])"),  # a 40-char secret-access-key shape
)


def mermaid_blocks(text: str, where: str) -> list[str]:
    """The bodies of the ```mermaid fences. Every fence must close with the same marker (balanced fences)."""
    blocks: list[str] = []
    opener: str | None = None  # the open fence's marker, None outside a fence
    language, body = "", []
    for line in text.splitlines():
        match = FENCE.match(line)
        if opener is None:
            if match:
                opener, language, body = match.group(2), match.group(3).strip(), []
            continue
        if match and match.group(2).startswith(opener) and not match.group(3).strip():
            if language == "mermaid":
                blocks.append("\n".join(body))
            opener = None
            continue
        body.append(line)
    assert opener is None, f"{where}: a {opener} fence is never closed"
    return blocks


def _balanced(line: str) -> bool:
    outside = re.sub(r'"[^"]*"', '""', line)
    if outside.count('"') % 2:
        return False
    stack: list[str] = []
    for char in outside:
        if char in "[({":
            stack.append(char)
        elif char in "])}" and (not stack or "[({"["])}".index(char)] != stack.pop()):
            return False
    return not stack


def _nodes(block: str) -> set[str]:
    """Node ids of a flowchart: the leading identifier of every edge endpoint, labels and shapes removed."""
    nodes: set[str] = set()
    for raw in block.splitlines()[1:]:
        line = re.sub(r'"[^"]*"', "", raw).strip()
        if not line or line.startswith(("%%", "subgraph", "end", "classDef", "class ", "style ", "direction")):
            continue
        line = re.sub(r"\[[^\]]*\]|\([^)]*\)|\{[^}]*\}", "", line)
        for part in re.split(r"-\.->|-->|==>|---|--|&", line):
            match = re.match(r"\s*([A-Za-z_]\w*)", part)
            if match:
                nodes.add(match.group(1))
    return nodes


def test_every_page_has_well_formed_mermaid() -> None:
    assert PAGES, "docs/ has no pages"
    total = 0
    for page in PAGES:
        for block in mermaid_blocks(page.read_text(encoding="utf-8"), page.name):
            total += 1
            lines = [ln for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("%%")]
            assert lines, f"{page.name}: empty mermaid block"
            kind = lines[0].split()[0]
            assert kind in DIAGRAM_TYPES, f"{page.name}: unknown diagram type {kind!r}"
            for line in lines[1:]:
                assert _balanced(line), f"{page.name}: unbalanced brackets or quotes in {line.strip()!r}"
                if kind == "sequenceDiagram":
                    assert ";" not in line, f"{page.name}: ';' ends a sequence-diagram statement: {line.strip()!r}"
            if kind in ("flowchart", "graph"):
                found = _nodes("\n".join(lines))
                assert len(found) <= MAX_NODES, f"{page.name}: {len(found)} nodes > {MAX_NODES}: split the diagram"
    assert total >= 10, f"only {total} mermaid diagrams in docs/"


def test_mermaid_fence_is_configured() -> None:
    config = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert "pymdownx.superfences" in config and "name: mermaid" in config and "fence_code_format" in config


def test_rustfs_page_lists_the_complete_policy_and_no_secret() -> None:
    text = (DOCS / "rustfs.md").read_text(encoding="utf-8")
    for action in BUCKET_ACTIONS + OBJECT_ACTIONS:
        assert f'"{action}"' in text, f"rustfs.md: the policy lacks {action}"
    for needle in (
        '"Sid": "BucketSettingsReadOnly"', '"Sid": "ObjectsReadWrite"', '"arn:aws:s3:::sast-memory"', '"arn:aws:s3:::sast-memory/*"',
        "put-bucket-versioning", "put-bucket-lifecycle-configuration", "--endpoint-url https://files.because-security.com",
        "--bucket sast-memory", '"Prefix":"runs/"', '"Days":30', "OUSAST_MEMORY", "s3://sast-memory", "S3_ENDPOINT",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "S3_REGION", "S3_BUCKET", "EvaluatorBindingDoesNotExist",
    ):  # fmt: skip
        assert needle in text, f"rustfs.md lacks {needle!r}"
    for shape in SECRET_SHAPES:
        hit = shape.search(text)
        assert hit is None, f"rustfs.md has a secret-looking string near {hit.group(0)[:6]!r}..."


def test_rustfs_page_quotes_the_refusals_verify_bucket_writes() -> None:
    """Each refusal line the page quotes still appears, as a template fragment, in the store's code."""
    code = (ROOT / "src" / "openultrasast" / "plane" / "memory.py").read_text(encoding="utf-8")
    for fragment in (
        "the bucket is not set up for the store. The store never configures its ",
        "it must be Enabled (provenance cites object versions)",
        "expire the whole store (repos/, facts/ and the index would be ",
        "no enabled lifecycle rule expires",
        "the store filters row objects by ",
        "The store requires it and has no local fallback",
        "is absent from the object's leading rows, which the server reads as its schema",
    ):
        assert fragment in code, f"memory.py no longer writes {fragment!r}: update docs/rustfs.md"


@pytest.mark.skipif(importlib.util.find_spec("mkdocs") is None, reason="mkdocs is not installed (the docs extra)")
def test_site_builds_strictly(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "mkdocs", "build", "--strict", "-f", str(ROOT / "mkdocs.yml"), "-d", str(tmp_path / "site")],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert proc.returncode == 0, f"mkdocs build --strict exited {proc.returncode}:\n{proc.stderr[-3000:]}"
    pages = list((tmp_path / "site").rglob("*.html"))
    assert len(pages) >= 12, f"the build wrote only {len(pages)} pages"  # proves the build read the docs
    ax = (tmp_path / "site" / "ops" / "ax" / "index.html").read_text(encoding="utf-8")
    assert "Bring-up" in ax, "the ax operations page did not include ops/ax/README.md"
    leaked = [p.name for p in pages if ".kiro" in p.read_text(encoding="utf-8") or "kiro-" in p.read_text(encoding="utf-8")]
    assert not leaked, f"maintainer Kiro tooling reached the site: {leaked}"
