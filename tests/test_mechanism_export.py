"""corpus-seeded-mechanisms: additive store fields and the corpus writer (task 1.2, Req 1.3/1.4)."""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.semantic.mechanisms import MechanismStore, append_mechanism


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


def test_old_sandbox_rows_load_with_corpus_defaults(tmp_path: Path) -> None:
    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    append_mechanism(store, summary="s", cwe="CWE-78", language="python", tags=("t",), what_made_it_exploitable="x")
    # a row written before this spec has no origin/tier/pairs/shape/guard fields at all
    raw = json.loads((tmp_path / "mechanisms.jsonl").read_text().splitlines()[0])
    for key in ("origin", "review_tier", "pairs", "shape", "guard"):
        raw.pop(key, None)
    (tmp_path / "mechanisms.jsonl").write_text(json.dumps(raw) + "\n")
    (record,) = store.load()
    assert (
        record.origin == "sandbox" and record.review_tier == "" and record.pairs == () and record.shape is None and record.guard == "none"
    )


def test_append_from_pair_dedupes_by_shape_and_extends_provenance(tmp_path: Path) -> None:
    from openultrasast.semantic.mechanisms import append_from_pair, corpus_mechanisms

    store = MechanismStore(tmp_path / "mechanisms.jsonl")
    first = append_from_pair(store, _shape(), summary="request into os.system", cwe="CWE-78", pair="p1", provenance="human", tier="seeded")
    second = append_from_pair(store, _shape(), summary="request into os.system", cwe="CWE-78", pair="p2", provenance="agent", tier="seeded")
    assert first.id == second.id
    assert (
        second.pairs == ("p1", "p2") and second.origin == "corpus" and second.review_tier == "seeded" and second.guard == "allowlist_test"
    )
    third = append_from_pair(
        store, _shape(guard="none"), summary="request into os.system", cwe="CWE-78", pair="p3", provenance="human", tier="reviewed"
    )
    assert third.id != first.id
    loaded = store.load()
    assert len(loaded) == 2 and {r.id for r in loaded} == {first.id, third.id}  # the store is append-only, load folds by id
    corpus = corpus_mechanisms(loaded)
    assert {r.id for r in corpus} == {first.id, third.id}
    assert all(r.shape is not None and r.shape["sink_name"] == "system" for r in corpus)
    assert "source_reaches_sink" in first.tags and "mechanism:source_reaches_sink" in first.tags


def test_corpus_rows_never_carry_source_text_and_ids_are_deterministic(tmp_path: Path) -> None:
    from openultrasast.semantic.mechanisms import append_from_pair

    a = append_from_pair(
        MechanismStore(tmp_path / "a.jsonl"), _shape(), summary="s", cwe="CWE-78", pair="p", provenance="human", tier="seeded"
    )
    b = append_from_pair(
        MechanismStore(tmp_path / "b.jsonl"), _shape(), summary="s", cwe="CWE-78", pair="q", provenance="human", tier="seeded"
    )
    assert a.id == b.id  # identity is the shape key, not a random uuid: the lever can name records across machines
    text = (tmp_path / "a.jsonl").read_text()
    assert "app.py" not in text and "cmd" not in text
