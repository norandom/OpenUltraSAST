import json

from openultrasast.stages import MODE_STAGES, Stage, StagePlan, plan_for_mode, record_skip


def test_mode_stages_maps_existing_depths() -> None:
    assert Stage.STATIC == "static"
    assert Stage.MAP == "map"
    assert Stage.REGRESS == "regress"
    assert MODE_STAGES["quick"] == (Stage.STATIC,)
    assert MODE_STAGES["standard"] == (Stage.STATIC, Stage.MAP)
    assert MODE_STAGES["deep"] == (Stage.STATIC, Stage.MAP, Stage.REGRESS)


def test_quick_never_includes_map_or_regress() -> None:
    plan = plan_for_mode("quick")
    assert plan.mode == "quick"
    assert plan.requested == (Stage.STATIC,)
    assert Stage.MAP not in plan.requested
    assert Stage.REGRESS not in plan.requested
    assert Stage.MAP not in MODE_STAGES["quick"]
    assert Stage.REGRESS not in MODE_STAGES["quick"]


def test_plan_for_mode_requests_ordered_stages() -> None:
    standard = plan_for_mode("standard")
    deep = plan_for_mode("deep")

    assert standard.requested == (Stage.STATIC, Stage.MAP)
    assert deep.requested == (Stage.STATIC, Stage.MAP, Stage.REGRESS)
    assert standard.completed == ()
    assert deep.skipped == ()
    assert isinstance(standard, StagePlan)
    assert isinstance(deep, StagePlan)


def test_skipped_stage_is_structured_degradation_not_exception() -> None:
    plan = plan_for_mode("deep")
    skipped = record_skip(plan, Stage.REGRESS, "sandbox_unavailable")

    assert skipped.requested == (Stage.STATIC, Stage.MAP, Stage.REGRESS)
    assert skipped.completed == ()
    assert skipped.skipped == ({"stage": "regress", "reason": "sandbox_unavailable"},)
    degradations = list(skipped.skipped)
    assert degradations[0]["stage"] == "regress"
    assert degradations[0]["reason"] == "sandbox_unavailable"
    assert json.dumps(degradations) == json.dumps([{"stage": "regress", "reason": "sandbox_unavailable"}])
