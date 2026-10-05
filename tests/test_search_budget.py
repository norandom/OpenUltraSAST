from concurrent.futures import ThreadPoolExecutor

import pytest

from openultrasast.plane.budget import BudgetExhausted, SpendBudget
from openultrasast.search.budget import SearchBudget


def test_reserve_settle_release():
    meter = SpendBudget(1)
    reservation = meter.reserve(0.7)
    with pytest.raises(BudgetExhausted):
        meter.reserve(0.4)
    reservation.settle(0.2)
    assert meter.spent == 0.2 and meter.reserved == 0
    other = meter.reserve(0.8)
    other.release()
    assert meter.reserved == 0
    with pytest.raises(ValueError):
        reservation.settle(0.1)
    for bad in [-1, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            meter.reserve(bad)


def test_concurrent_reservations_cannot_overrun():
    meter = SpendBudget(1)

    def reserve(_):
        try:
            return meter.reserve(0.3)
        except BudgetExhausted:
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        reservations = list(pool.map(reserve, range(20)))
    assert sum(r is not None for r in reservations) == 3
    assert meter.reserved <= 1


def test_config_validation():
    assert SearchBudget().task_wall_seconds == 900
    for kwargs in [dict(retries=-1), dict(memory_bytes=0), dict(wall_seconds=float("nan"))]:
        with pytest.raises(ValueError):
            SearchBudget(**kwargs)


def test_settlement_bound_and_release_then_readmission():
    meter = SpendBudget(0.5)
    reserved = meter.reserve(0.5)
    with pytest.raises(ValueError, match="exceeds reservation"):
        reserved.settle(0.6)
    assert meter.reserved == 0.5 and meter.spent == 0
    reserved.release()
    meter.reserve(0.5).settle(0.5)
    assert meter.spent == 0.5
    with pytest.raises(BudgetExhausted):
        meter.reserve(0.001)
