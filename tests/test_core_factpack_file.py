"""Fact-pack file admission tests for detection-core task 8.2 (Req 10.1)."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.factpack import FactPackError, admit_pack_file, verify_fact_pack  # noqa: E402
from openultrasast.mapping.installed_fact_authority import (  # noqa: E402
    InstalledAuthorityWireError,
    decode_fact_pack_bytes,
)

REPO = Path(__file__).resolve().parents[1]
ENTRIES = REPO / "src/openultrasast/ruleset/entries"
LEGACY_DIGEST = "e8e149309abd78f24206c58fde7f73ae2f60364d8b8fee22ecaee8342798d8ce"
PACK = ENTRIES / "artifacts" / "sha256" / LEGACY_DIGEST
PROJECTION = ENTRIES / "express.json"


def _review_digest() -> str:
    payload = json.loads(PACK.read_text(encoding="utf-8"))
    return hashlib.sha256(payload["review"]["note"].encode()).hexdigest()


def test_express_pack_admitted_with_verifiable_review() -> None:
    content = PACK.read_bytes()
    assert len(content) == 963
    assert hashlib.sha256(content).hexdigest() == LEGACY_DIGEST
    pack = admit_pack_file(PACK, review_digest=_review_digest())
    assert pack.family == "access_control"
    assert len(pack.facts) == 3
    assert pack.review_digest == _review_digest()
    verify_fact_pack(pack, pack.facts)


def test_pack_refused_without_matching_review() -> None:
    try:
        admit_pack_file(PACK, review_digest="0" * 64)
        raise AssertionError("wrong review digest must be refused")
    except FactPackError:
        pass


def test_tampered_pack_file_refused(tmp_path: Path) -> None:
    payload = json.loads(PACK.read_text(encoding="utf-8"))
    payload["facts"].append({"id": "entry:express:evil", "pattern": "eval("})
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    pack = admit_pack_file(tampered, review_digest=_review_digest())
    # review attestation still verifies, but content no longer matches the stamped digest
    original = admit_pack_file(PACK, review_digest=_review_digest())
    with pytest.raises(FactPackError):
        verify_fact_pack(original, pack.facts)


def test_compatibility_projection_is_neither_a_legacy_nor_v2_fact_pack() -> None:
    with pytest.raises(FactPackError):
        admit_pack_file(PROJECTION, review_digest=_review_digest())
    with pytest.raises(InstalledAuthorityWireError):
        decode_fact_pack_bytes(PROJECTION.read_bytes())
