import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("feasibility", Path("benchmarks/push/feasibility.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_timeouts_and_missing_runs_remain_in_fixed_population():
    plan = [{"id": str(i), "workload": "function-edit"} for i in range(3)]
    runs = [
        {"id": "0", "elapsed_seconds": 2, "target_completed": True, "timed_out": False},
        {"id": "1", "elapsed_seconds": 30.5, "target_completed": False, "timed_out": True},
    ]
    result = module.summarize(plan, runs)
    row = result["workloads"]["function-edit"]
    assert row["population"] == 3 and row["missing"] == 1
    assert row["p95_seconds"] == 30.5 and row["timeouts"] == 1
    assert row["completed_targets"] == 1
    assert result["runtime_verdict"] == "NO-GO"


def test_duplicate_or_unplanned_measurement_is_rejected():
    plan = [{"id": "a", "workload": "cold"}]
    with pytest.raises(ValueError):
        module.summarize(plan, [{"id": "outside"}])
    with pytest.raises(ValueError):
        module.summarize(plan, [{"id": "a"}, {"id": "a"}])


def test_identical_tip_alone_cannot_qualify_runtime():
    plan = [{"id": "a", "workload": "identical-tip"}]
    runs = [{"id": "a", "elapsed_seconds": 1, "target_completed": True, "coverage": "complete_within_scope", "deferred": 0}]
    assert module.summarize(plan, runs)["runtime_verdict"] == "NO-GO"


@pytest.mark.parametrize("elapsed", [-1, float("nan"), float("inf")])
def test_invalid_elapsed_is_an_instrument_error(elapsed):
    with pytest.raises(ValueError):
        module.summarize([{"id": "a", "workload": "cold"}], [{"id": "a", "elapsed_seconds": elapsed}])


def test_multi_ref_target_denominator_is_fixed_before_execution():
    result = module.summarize(
        [{"id": "a", "workload": "multi-ref", "expected_targets": 2}],
        [{"id": "a", "elapsed_seconds": 30.5, "target_completed": False, "completed_targets": 1, "timed_out": True}],
    )
    assert result["workloads"]["multi-ref"]["expected_targets"] == 2
    assert result["workloads"]["multi-ref"]["completed_targets"] == 1
