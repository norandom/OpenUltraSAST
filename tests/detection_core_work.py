"""Test-owned counters around actual detection-core validation boundaries."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType
from typing import Any
from unittest.mock import patch

from openultrasast.core import admission_case, evidence, family, readiness


@dataclass(frozen=True)
class ValidationWork:
    canonical_relations: int
    canonical_observations: int
    validated_relations: int
    validated_observations: int
    readiness_receipts: int
    admission_cases: int
    total_operations: int


def _counted(
    module: ModuleType,
    function_name: str,
    counter: dict[str, int],
    counter_name: str,
) -> Any:
    original = getattr(module, function_name)

    def wrapped(*args: object, **kwargs: object) -> Any:
        result = original(*args, **kwargs)
        counter[counter_name] += 1
        return result

    return patch.object(module, function_name, wrapped)


def count_validation_work(run: Callable[[], int]) -> tuple[int, ValidationWork]:
    """Run real production validators and count each successful scaled boundary."""
    counts = {
        "canonical_relations": 0,
        "canonical_observations": 0,
        "validated_relations": 0,
        "validated_observations": 0,
        "readiness_receipts": 0,
        "admission_cases": 0,
    }
    hooks = (
        _counted(evidence, "_relation_value", counts, "canonical_relations"),
        _counted(evidence, "_observation_value", counts, "canonical_observations"),
        _counted(family, "_validate_relation", counts, "validated_relations"),
        _counted(family, "_validate_observation", counts, "validated_observations"),
        _counted(readiness, "validate_readiness_result", counts, "readiness_receipts"),
        _counted(admission_case, "validate_admission_case_shape", counts, "admission_cases"),
    )
    with hooks[0], hooks[1], hooks[2], hooks[3], hooks[4], hooks[5]:
        serialized_bytes = run()
    values = tuple(counts.values())
    return serialized_bytes, ValidationWork(*values, sum(values))


__all__ = ["ValidationWork", "count_validation_work"]
