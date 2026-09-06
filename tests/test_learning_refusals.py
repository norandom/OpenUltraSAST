"""A refusal is data, not a `continue` (learning-harness review round 3, Req 5.1, 5.2).

`Refusal.degradation()` existed and nothing ever called it, so every path that declined to learn from a pair
declined silently: the mechanism lever skipped a holdout-taught shape without a word, leave-one-out dropped
non-teachers with no record, and the seeder gave a train-split identical twin the reason `split:train`, which
is not true. A leak the run does not mention is a leak nobody reads.
"""

from __future__ import annotations

import json
from pathlib import Path

from openultrasast.benchmark import ExpectedFinding
from openultrasast.pairs import PairCase

VULN = "import os\nfrom flask import request\n\n\ndef run():\n    os.system(request.args.get('cmd'))\n"
FIXED = "import subprocess\nfrom flask import request\n\n\ndef run():\n    subprocess.run(['echo'], check=False)\n"


def _case(tmp_path: Path, name: str, *, split: str = "train", unscorable: str | None = None, tier: str = "seeded") -> PairCase:
    (tmp_path / f"{name}-v.py").write_text(VULN)
    (tmp_path / f"{name}-f.py").write_text(FIXED)
    return PairCase(
        name=name,
        slice="vibe-py",
        language="python",
        origin="test",
        vuln_file=tmp_path / f"{name}-v.py",
        fixed_file=tmp_path / f"{name}-f.py",
        relpath="app.py",
        expected=(ExpectedFinding(cwe="CWE-78", vulnerability_class="x", path="app.py", evidence="", function="run", mechanism="other"),),
        min_recall=1.0,
        fix_policy="silent",
        split=split,
        review_tier=tier,
        unscorable=unscorable,
    )


def test_a_train_split_twin_is_refused_for_being_a_twin_not_for_its_split(tmp_path: Path) -> None:
    """`split:train` on a train-split row is a lie, and it hides a corpus fact behind a split fact.

    Two vibe-py rows are exactly this: `python-insecure-app-main-try-hack-me` and
    `vulnpy-deserialization-do-pickle-load` are train-split identical twins."""
    from openultrasast.semantic.seed import _skip_reason

    assert _skip_reason(_case(tmp_path, "twin", split="train", unscorable="identical_twin")) == "identical_twin"
    assert _skip_reason(_case(tmp_path, "held", split="holdout")) == "split:holdout"
    assert _skip_reason(_case(tmp_path, "good", split="train")) is None


def test_leave_one_out_records_the_pairs_it_would_not_learn_from(tmp_path: Path) -> None:
    """Req 5.2: the refusal is recorded with the pair names, on a channel a caller can read."""
    from openultrasast.semantic.loo import evaluate_loo

    result = evaluate_loo([_case(tmp_path, "train-a"), _case(tmp_path, "hold-a", split="holdout")])
    refusals = [item for item in result.degradations if item.get("reason") == "holdout_pair_refused"]
    assert refusals, "leave-one-out excluded a holdout pair from teaching and said nothing"
    assert refusals[0]["pairs"] == ["hold-a"]
    assert result.teaching_pairs <= 1


def test_the_mechanism_lever_records_every_shape_a_holdout_pair_taught(tmp_path: Path) -> None:
    """The lever used to `continue` past a refused candidate; the run then showed a shorter list with no reason."""
    from openultrasast.improve.evolve import propose_mechanism_edits
    from openultrasast.semantic.mechanisms import MechanismStore, append_from_pair
    from openultrasast.semantic.variants import Shape

    cases = [_case(tmp_path, "train-a"), _case(tmp_path, "hold-a", split="holdout")]
    candidates = MechanismStore(tmp_path / "candidates.jsonl")
    append_from_pair(
        candidates,
        Shape(
            language="python",
            sink_name="system",
            arity=1,
            source_positions=(0,),
            source_kinds=("request",),
            guard="none",
            mechanism="source_reaches_sink",
        ),
        summary="s",
        cwe="CWE-78",
        pair="hold-a",
        provenance="human",
        tier="seeded",
    )
    refusals: list[dict[str, object]] = []
    edits = propose_mechanism_edits(cases, candidates, tmp_path / "scan.jsonl", degradations=refusals)
    assert [edit.mechanism_id for edit in edits if edit.action == "admit"] == []
    assert [item["reason"] for item in refusals] == ["holdout_pair_refused"]
    assert refusals[0]["pairs"] == ["hold-a"]
    json.dumps(refusals)  # a degradation has to survive the artifact it is written into
