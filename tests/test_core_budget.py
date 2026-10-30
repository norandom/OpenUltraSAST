"""Measured-budget contract tests for detection-core task 2 (Req 4, 12)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from openultrasast.core.budget import (  # noqa: E402
    Budget,
    BudgetGateFailure,
    Complexity,
    check_budget,
    derive_budget,
)

SAMPLES = tuple((Complexity(regions=1 + i % 3, calls=10 * i, changed_bytes=100 * i), float(1 + i)) for i in range(20))


def test_derive_budget_publishes_derivation_metadata() -> None:
    budget = derive_budget(SAMPLES, workload_class="dev-pool", percentile=0.95, hardware="ci-runner-4cpu")
    assert isinstance(budget, Budget)
    assert budget.workload_class == "dev-pool"
    assert budget.n == 20
    assert budget.percentile == 0.95
    assert budget.hardware == "ci-runner-4cpu"
    assert budget.seconds == 19.05  # linear-interpolated p95 of samples 1..20


def test_derive_budget_is_deterministic() -> None:
    first = derive_budget(SAMPLES, workload_class="pilot", percentile=0.9, hardware="h")
    second = derive_budget(SAMPLES, workload_class="pilot", percentile=0.9, hardware="h")
    assert first == second


def test_derive_budget_refuses_empty_samples() -> None:
    try:
        derive_budget((), workload_class="dev", percentile=0.95, hardware="h")
        raise AssertionError("empty sample set must be refused")
    except ValueError:
        pass


def test_budget_is_configurable_per_class_not_a_constant() -> None:
    dev = derive_budget(SAMPLES, workload_class="dev-pool", percentile=0.95, hardware="h")
    pilot = derive_budget(tuple((c, s / 10) for c, s in SAMPLES), workload_class="pilot", percentile=0.95, hardware="h")
    assert dev.seconds != pilot.seconds
    assert dev.workload_class != pilot.workload_class


def test_budget_gate_names_change_elapsed_and_derivation() -> None:
    budget = derive_budget(SAMPLES, workload_class="dev-pool", percentile=0.95, hardware="ci-runner-4cpu")
    check_budget("case-1", 5.0, budget)
    try:
        check_budget("case-2", 999.0, budget)
        raise AssertionError("over-budget change must fail the gate")
    except BudgetGateFailure as error:
        message = str(error)
        assert "case-2" in message
        assert "999" in message
        assert "dev-pool" in message and "ci-runner-4cpu" in message and "n=20" in message
