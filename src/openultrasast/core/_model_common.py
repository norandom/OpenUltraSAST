"""Shared validation primitives for dependency-free model contracts."""

import json
import re
from typing import cast

from openultrasast.core import canonical
from openultrasast.core.evidence import EvidenceRecord, evidence_record_bytes

_DIGEST = re.compile(r"[0-9a-f]{64}")


class ModelContractError(ValueError):
    """A model request, response, or result cannot be reproduced."""


def require_text(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ModelContractError(f"{field} must be nonempty text")


def require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ModelContractError(f"{field} must be a full lowercase SHA-256 digest")


def _frozen_json(value: object) -> canonical.JsonValue:
    if isinstance(value, list):
        return tuple(_frozen_json(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _frozen_json(item) for key, item in value.items()}
    return cast(canonical.JsonValue, value)


def record_value(record: EvidenceRecord) -> canonical.JsonValue:
    body = _frozen_json(json.loads(evidence_record_bytes(record)))
    if not isinstance(body, dict):
        raise ModelContractError("canonical evidence record must be an object")
    return body | {"record_id": record.record_id}
