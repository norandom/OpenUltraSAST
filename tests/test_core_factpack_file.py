"""Fact-pack file admission tests for detection-core task 8.2 (Req 10.1)."""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.factpack import FactPackError, admit_pack_file, verify_fact_pack  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
PACK = REPO / "src/openultrasast/ruleset/entries/express.json"


def _review_digest() -> str:
    payload = json.loads(PACK.read_text(encoding="utf-8"))
    return hashlib.sha256(payload["review"]["note"].encode()).hexdigest()


def test_express_pack_admitted_with_verifiable_review() -> None:
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


def test_tampered_pack_file_refused() -> None:
    payload = json.loads(PACK.read_text(encoding="utf-8"))
    payload["facts"].append({"id": "entry:express:evil", "pattern": "eval("})
    tampered = PACK.parent / "tampered.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    try:
        pack = admit_pack_file(tampered, review_digest=_review_digest())
        # review attestation still verifies, but content no longer matches the stamped digest
        original = admit_pack_file(PACK, review_digest=_review_digest())
        try:
            verify_fact_pack(original, pack.facts)
            raise AssertionError("tampered content must fail verification")
        except FactPackError:
            pass
    finally:
        tampered.unlink()
