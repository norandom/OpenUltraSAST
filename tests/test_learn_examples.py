"""The example store (learned-decision-engine design 4.2, task 6.1): label + feature record + excerpt -> ``example``
rows, the refusals, the 10% unread-excerpt failure, and content-addressed blobs on both backends."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from test_plane_memory import FakeObjects

from openultrasast.cli import main
from openultrasast.learn.examples import (
    ExampleBuildError,
    build_examples,
    label_pin,
    load_examples,
    pair_pins,
    record_key,
    records_by_key,
)
from openultrasast.learn.features import Part, quick_part, record
from openultrasast.learn.labels import Source, Sources
from openultrasast.plane.memory import FileStore, MemoryStore, MemoryStoreError, S3Store

PIN = "0123456789abcdef0123456789abcdef01234567"
SOURCES = Sources(
    (Source("pairs", "pairs", (), (), "2026-09-30", "development"), Source("population-v1", "population", (), (), "2026-09-25", "spent")),
    frozenset(),
    {},
    Path("sources.toml"),
)
CODE = {
    "vulnerable": ["def handler(request):", "    # CVE-2021-1234 fixed later", "    return run(request.args['q'])", ""],
    "fixed": ["def handler(request):", "    return run(quote(request.args['q']))", ""],
}


@pytest.fixture(params=["file", "fake-s3-select"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[MemoryStore]:
    yield FileStore(tmp_path / "memory") if request.param == "file" else S3Store(FakeObjects("works"), "bucket", "p")


def label(**kw: Any) -> dict[str, Any]:
    base = {
        "candidate": "app.py::handler", "family": "injection", "label": 1, "source": "population-v1", "source_ref": "case-1",
        "unit": "pin", "weight": 1.0, "split": "population-v1", "group": "acme/webapp", "repo": "https://github.com/acme/webapp",
        "language": "python", "created": "2026-09-30", "pin": PIN, "pin_role": "vulnerable", "frameworks": ["flask"],
        "conditional": None, "direction": None,
    }  # fmt: skip
    return {**base, **kw}


def feature(lab: Mapping[str, Any], unit: str = "pin") -> dict[str, Any]:
    parts = {"quick": quick_part([("r1", "enabled")], {})}
    if unit == "delta":
        parts["delta"] = Part("ran", {"delta.novelty": "new", "delta.changed_lines": 1, "delta.sanitizer_removed": True})
    out = record(str(lab["candidate"]), str(lab["family"]), "python", "static", parts, unit=unit)
    return {**out, "repo": lab["repo"], "pin": label_pin(lab)}


def lines_of(lab: Mapping[str, Any], role: str) -> Sequence[str] | None:
    return CODE[role]


def test_example_rows_join_label_record_and_excerpt(store: MemoryStore) -> None:
    pos, neg = label(), label(label=0, pin_role="fixed", pin="f" * 40)
    records = records_by_key([feature(pos), feature(neg)])
    build = build_examples([pos, neg], records, lines_of, sources=SOURCES, store=store)
    assert build.summary()["examples"] == 2 and not build.failing()
    stored = load_examples(store)
    assert sorted(e.label for e in stored) == [0, 1] and {e.group for e in stored} == {"acme/webapp"}
    row = next(r.row for r in store.rows(kind="example") if r.row["label"] == 1)
    assert row["kind"] == "example" and row["frameworks"] == ["flask"] and "rationale" not in row
    text = store.get_blob("excerpts", row["excerpt_sha"])
    assert text is not None and hashlib.sha256(text).hexdigest() == row["excerpt_sha"]
    assert b"CVE-2021" not in text
    assert "acme" not in text.decode() and "app.py" not in text.decode()


def test_delta_units_carry_the_diff(store: MemoryStore) -> None:
    lab = label(unit="delta", direction="introduce")
    build = build_examples([lab], records_by_key([feature(lab, "delta")]), lines_of, sources=SOURCES, store=store)
    row = build.rows[0]
    text = store.get_blob("excerpts", row["excerpt_sha"])
    assert text is not None and b"\ndiff:\n@@" in text and b"+    return run(request.args['q'])" in text


def test_user_origin_and_unlisted_sources_are_refused() -> None:
    with pytest.raises(ExampleBuildError, match="origin: user"):
        build_examples([label(origin="user")], {}, lines_of, sources=SOURCES)
    with pytest.raises(ExampleBuildError, match="not in"):
        build_examples([label(source="population-v3")], {}, lines_of, sources=SOURCES)


def test_conditional_and_unrecorded_labels_never_become_examples() -> None:
    rows = [label(conditional="signal_at_tip_not_base", label=0), label(source="pairs", pin="", source_ref="p1")]
    build = build_examples(rows, {}, lines_of, sources=SOURCES)
    assert build.rows == [] and build.skipped == {"conditional label (condition not evaluated)": 1}
    assert build.sources["pairs"].no_record == 1


def test_more_than_ten_percent_without_excerpt_fails_the_source() -> None:
    labs = [label(candidate=f"app.py::f{i}", source_ref=f"c{i}") for i in range(10)] + [label()]
    records = records_by_key([feature(lab) for lab in labs])
    build = build_examples(labs, records, lines_of, sources=SOURCES)  # f0..f9 are not declared in CODE: no excerpt
    assert build.sources["population-v1"].no_excerpt == 10 and build.failing() == ["population-v1"]
    ok = build_examples([label()], records, lines_of, sources=SOURCES)
    assert ok.failing() == []


def test_pair_pins_are_stable_and_distinct_per_side() -> None:
    vuln, fixed = label(source="pairs", pin="", source_ref="p1"), label(source="pairs", pin="", source_ref="p1", pin_role="fixed")
    assert label_pin(vuln) != label_pin(fixed) and len(label_pin(vuln)) == 40 and label_pin(vuln) == label_pin(dict(vuln))
    assert label_pin(label()) == PIN
    key = record_key(vuln["repo"], label_pin(vuln), "app.py::handler", "injection", "pin")
    assert key[0] == "github.com/acme/webapp"


def test_blobs_are_content_addressed_on_both_backends(store: MemoryStore) -> None:
    sha = store.put_blob("excerpts", b"x = 1\n")
    assert sha == hashlib.sha256(b"x = 1\n").hexdigest() and store.get_blob("excerpts", sha) == b"x = 1\n"
    assert store.put_blob("excerpts", b"x = 1\n") == sha and store.blob_names("excerpts") == [sha]
    keyed = store.put_blob("embeddings/openai__text-embedding-3-small", b'{"v": 1}', name=sha)
    assert keyed == sha and store.get_blob("embeddings/openai__text-embedding-3-small", sha, verify=False) == b'{"v": 1}'
    assert store.get_blob("excerpts", "0" * 64) is None
    for bad in ("repos", "../x", "facts"):
        with pytest.raises(MemoryStoreError):
            store.put_blob(bad, b"x")
    with pytest.raises(MemoryStoreError):
        store.get_blob("excerpts", "not-a-sha")


def test_a_changed_blob_is_dropped_not_served(tmp_path: Path) -> None:
    store = FileStore(tmp_path / "m")
    sha = store.put_blob("excerpts", b"a\n")
    (tmp_path / "m" / "excerpts" / f"{sha}.txt").write_bytes(b"tampered\n")
    assert store.get_blob("excerpts", sha) is None and store.blob_names("excerpts") == []


def test_cli_build_writes_examples_and_exits_2_on_refusal(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    labels = tmp_path / "labels.jsonl"
    labels.write_text(json.dumps(label(origin="user")) + "\n")
    assert main(["learn", "memory", "build", "--labels", str(labels), "--dry-run"]) == 2
    assert "origin: user" in capsys.readouterr().err


def test_a_fixed_side_without_the_function_is_a_label_defect_not_an_unread_side() -> None:
    fixed = label(label=0, pin_role="fixed", pin="f" * 40)
    moved = {"vulnerable": CODE["vulnerable"], "fixed": ["def guard(request):", "    return True"]}
    build = build_examples([fixed], records_by_key([feature(fixed)]), lambda lab, role: moved[role], sources=SOURCES)
    count = build.sources["population-v1"]
    assert count.absent_fixed_side == 1 and count.no_excerpt == 0 and build.failing() == []
    unread = build_examples([fixed], records_by_key([feature(fixed)]), lambda lab, role: None, sources=SOURCES)
    assert unread.sources["population-v1"].unread == 1 and unread.failing() == ["population-v1"]


def test_the_excerpt_matcher_falls_back_to_the_labels_language_when_the_records_resolves_nothing() -> None:
    """A feature record carries the closed vocabulary's language (``other`` for Ruby, Go, C#); a Python ``def`` under
    ``other`` has no brace body, so the matcher gets the label's language instead. The record's field is kept."""
    lab = label()
    other = {**feature(lab), "language": "other"}
    build = build_examples([lab], records_by_key([other]), lambda lab, role: CODE[role], sources=SOURCES)
    assert build.summary()["examples"] == 1 and build.rows[0]["language"] == "other"  # the row keeps the vocabulary language
    assert build.sources["population-v1"].no_excerpt == 0


def test_pair_sides_join_the_record_stored_under_their_harvest_unit_pin() -> None:
    """The harvest stores a pair side's record under its unit pin (the blob sha1 of the side's excerpt), not under
    :func:`label_pin`; ``pins`` from the harvest ``units.json`` joins them, and without it the record is not found."""
    lab = label(source="pairs", source_ref="case-9", pin="")
    unit_pin = "a" * 40
    stored = {**feature(lab), "pin": unit_pin}
    units = {"h-1": {"source": "pairs", "ref": "case-9", "side": "vulnerable", "pin": unit_pin, "repo": lab["repo"]},
             "h-2": {"source": "population-v1", "ref": "case-9", "side": "vulnerable", "pin": PIN, "repo": lab["repo"]}}  # fmt: skip
    pins = pair_pins(units)
    assert pins == {("case-9", "vulnerable"): unit_pin}
    assert build_examples([lab], records_by_key([stored]), lines_of, sources=SOURCES).summary()["examples"] == 0
    build = build_examples([lab], records_by_key([stored]), lines_of, sources=SOURCES, pins=pins)
    assert build.summary()["examples"] == 1 and build.rows[0]["pin"] == unit_pin


def test_side_reader_reads_every_pair_kind_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Labels from the corpus catalog and from a second pair-kind source (advisory-fixes) are both source ``pairs``;
    the reader must find either side, not only the first catalog's (the 2026-10-02 advisory rebuild read 0 of 194)."""
    from types import SimpleNamespace

    import openultrasast.pairs as pairs
    from openultrasast.learn.examples import SideReader

    files = {}
    for name in ("corpus-case", "advisory-case"):
        files[name] = tmp_path / f"{name}.py"
        files[name].write_text("def handler(request):\n    return 1\n")
    catalogs = {"corpus.toml": "corpus-case", "advisory.toml": "advisory-case"}

    def fake(path: Path) -> tuple[Any, ...]:
        name = catalogs[Path(path).name]
        return (SimpleNamespace(name=name, vuln_file=files[name], fixed_file=files[name], license="MIT"),)

    monkeypatch.setattr(pairs, "load_pair_catalog", fake)
    sources = Sources(
        (Source("pairs", "pairs", ("corpus.toml",), (), "2026-09-30", "development"),
         Source("advisory-fixes", "pairs", ("advisory.toml",), (), "2026-10-01", "development")),
        frozenset(), {}, Path("sources.toml"),
    )  # fmt: skip
    reader = SideReader(tmp_path, tmp_path, sources, [])
    for name in catalogs.values():
        lab = label(source="pairs", source_ref=name, pin="")
        assert reader(lab, "vulnerable") == ["def handler(request):", "    return 1"]
        assert reader.license(lab) == "MIT"


def test_null_instruments_are_skipped_when_reading_and_writing() -> None:
    """Static-profile feature records carry the plane-only instruments as null; an example row must load (the live
    store had 937 unreadable rows on 2026-10-02) and never write such a null itself."""
    from openultrasast.learn.examples import Example

    row = {
        "id": "x", "kind": "example", "repo": "o/r", "pin": "p", "run": "learn-memory", "task": "build", "population": "pairs",
        "split": "train", "image": "host", "candidate": "a.py::f", "family": "injection", "language": "python",
        "profile": "static", "label": 1, "source": "pairs", "group": "o/r", "frameworks": None, "unit": "pin",
        "direction": None, "pin_role": "vulnerable", "weight": 1.0, "license": "MIT", "x": {},
        "instruments": {"language": {"state": "ran"}, "verify": None, "agree": None, "model_sinks": None},
        "roles": [], "excerpt_sha": "0" * 64, "label_set_digest": "1" * 64,
    }  # fmt: skip
    example = Example.from_row(row)
    assert set(example.instruments) == {"language"}
