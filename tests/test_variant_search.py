"""corpus-seeded-mechanisms task 2.2: structural variant search over a scanned tree, merged with overlay flows."""

from __future__ import annotations

from pathlib import Path

from openultrasast.semantic.facts import load_facts
from openultrasast.semantic.ir import parse_file
from openultrasast.semantic.overlay import OverlayRecord

PY_FACTS = load_facts()


def _shape(**overrides: object):
    from openultrasast.semantic.variants import Shape

    base: dict[str, object] = {
        "language": "python",
        "sink_name": "system",
        "arity": 1,
        "source_positions": (0,),
        "source_kinds": ("fact_source",),
        "guard": "allowlist_test",
        "mechanism": "source_reaches_sink",
    }
    base.update(overrides)
    return Shape(**base)  # type: ignore[arg-type]


VARIANT = "import os\nfrom flask import request\n\n\ndef handler():\n    q = request.args.get('q')\n    os.system(q)\n"
PARAM_VARIANT = "import os\n\n\ndef handler(q):\n    os.system(q)\n"
CONSTANT = "import os\n\n\ndef handler():\n    os.system('ls -la')\n"
ARITY = "import os\nfrom flask import request\n\n\ndef handler():\n    q = request.args.get('q')\n    os.system(q, 1)\n"


def test_match_shapes_finds_structural_variants_and_ignores_constants() -> None:
    from openultrasast.semantic.variants import match_shapes

    shape = _shape()
    hits = match_shapes(parse_file("a.py", VARIANT, "python"), [shape], PY_FACTS, mechanism_ids={shape.key(): "corpus:abc"})
    assert [(h.path, h.line, h.mechanism_id, h.sink_name, h.source_kind) for h in hits] == [
        ("a.py", 7, "corpus:abc", "system", "fact_source")
    ]
    param_hits = match_shapes(parse_file("b.py", PARAM_VARIANT, "python"), [shape], PY_FACTS, mechanism_ids={shape.key(): "corpus:abc"})
    assert [(h.line, h.source_kind) for h in param_hits] == [(5, "parameter")]  # any source kind at the shape's positions matches
    assert match_shapes(parse_file("c.py", CONSTANT, "python"), [shape], PY_FACTS, mechanism_ids={shape.key(): "corpus:abc"}) == []
    assert match_shapes(parse_file("d.py", ARITY, "python"), [shape], PY_FACTS, mechanism_ids={shape.key(): "corpus:abc"}) == []
    js_shape = _shape(language="javascript", sink_name="exec")
    assert match_shapes(parse_file("a.py", VARIANT, "python"), [js_shape], PY_FACTS, mechanism_ids={js_shape.key(): "x"}) == []


def test_hits_become_suspicion_findings_or_merge_into_an_overlay_flow() -> None:
    from openultrasast.semantic.variant_search import hits_to_findings
    from openultrasast.semantic.variants import VariantHit

    hit = VariantHit(path="a.py", line=7, mechanism_id="corpus:abc", sink_name="system", source_kind="fact_source")
    other = VariantHit(path="z.py", line=3, mechanism_id="corpus:abc", sink_name="system", source_kind="parameter")
    coverage = OverlayRecord(
        proposal_id="overlay-coverage:a.py:7:os.system",
        path="a.py",
        line=7,
        disposition="coverage",
        reason="uninventoried sink os.system reached from request",
        cwe="CWE-78",
        sources=("request",),
        sinks=("os.system",),
        sanitizers=(),
        evidence_level="static_corroboration",
        origin="overlay",
        engine="python-ast",
        language="python",
    )
    summaries = {"corpus:abc": ("request into os.system; fix adds allowlist_test", ("p1", "p2"), "CWE-78")}
    findings, records = hits_to_findings([hit, other], [coverage], summaries)
    assert len(records) == 1 and records[0].mechanism_id == "corpus:abc" and records[0].disposition == "coverage"
    assert [f.finding_id for f in findings] == ["variant:corpus:abc:z.py:3"]  # the a.py hit merged, no duplicate
    (finding,) = findings
    assert finding.evidence_level == "suspicion" and "variant" in finding.tags and "mechanism:corpus:abc" in finding.tags
    assert "p1" in finding.rationale and finding.line == 3 and finding.path == "z.py"


def test_search_tree_uses_the_store_and_respects_the_mechanism_cap(tmp_path: Path) -> None:
    from openultrasast.preprocess import preprocess_repository
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.variant_search import search_tree

    root = tmp_path / "repo"
    root.mkdir()
    (root / "views.py").write_text(VARIANT)
    (root / "safe.py").write_text(CONSTANT)
    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    record = append_from_pair(store, _shape(), summary="s", cwe="CWE-78", pair="p1", provenance="human", tier="seeded")
    _, targets = preprocess_repository(root)
    result = search_tree(root, targets, store, PY_FACTS, max_mechanisms=500)
    assert [(h.path, h.line, h.mechanism_id) for h in result.hits] == [("views.py", 7, record.id)]
    assert result.mechanisms_searched == 1 and result.files_searched == 2
    capped = search_tree(root, targets, store, PY_FACTS, max_mechanisms=0)
    assert capped.hits == () and capped.mechanisms_searched == 0
