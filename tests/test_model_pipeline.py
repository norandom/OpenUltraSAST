"""Wiring the model layer into a detector (model-grounded-detection, Req 8).

Everything before this built an *arbiter* — something that judges a flow taint reachability already found.
Nothing proposed. This is the piece that makes it a detector: the enumerator offers candidates, the LLM
answers one bounded question about each, and the model checks the answer.

The distinction that matters, and that `judge` alone conflated:

    the model CONTRADICTS   it has coverage here and says no -- a sanitizer on the path, a safe sink shape.
                            The claim is dropped (Req 8.2).
    the model CANNOT DECIDE no modelled sink or source reaches this site at all, so the model is silent
                            rather than negative. The claim is reported at `suspicion` (Req 8.4).

Conflating them is the difference between a precision-first tool that misses most real bugs and an honest one
that says how sure it is. 23 of 39 misses in the ceiling were absent sinks -- "no flow" usually means the
model cannot see it, not that nothing is there.
"""

from __future__ import annotations

from pathlib import Path


def _spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import TaintSpec

    return TaintSpec(family="injection", language="python", sources=("request.args",), sinks=("os.system",), sanitizers=("escape",))


def _cpg(rows):  # type: ignore[no-untyped-def]
    from openultrasast.cpg.backend import CpgResult

    return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: rows)


class _Client:
    def __init__(self, answer: str = '{"vulnerable": true, "why": "unsanitised"}') -> None:
        self.calls = 0
        self._answer = answer

    def complete(self, **kw: object):  # type: ignore[no-untyped-def]
        from openultrasast.tool_hunter import ChatResponse

        self.calls += 1
        return ChatResponse(content=self._answer)


ENTAILING = [
    {
        "sink": "os.system(cmd)",
        "sinkLine": "4",
        "sinkMethod": "run",
        "source": "request.args['c']",
        "sanitized": False,
        "length": 3,
        "inLabeledScope": True,
    }
]
SANITIZED = [
    {
        "sink": "os.system(cmd)",
        "sinkLine": "4",
        "sinkMethod": "run",
        "source": "request.args['c']",
        "sanitized": True,
        "length": 3,
        "inLabeledScope": True,
    }
]


def test_an_entailed_site_becomes_a_finding_with_no_model_call() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    client = _Client()
    findings = scan_region(_cpg(ENTAILING), _spec(), function="run", client=client, model="m", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.ENTAILED
    assert client.calls == 0


def test_an_arbitrated_finding_names_its_file_the_way_a_candidate_does() -> None:
    """One consumer parses both shapes, so both must be ``path:line:function``.

    An arbitrated finding was ``function:line``, which the report layer read as ``path:line``: every entailed
    finding reached a contributor with a function name where its file belonged and no line at all. A whole
    repository scan is what made it visible -- `model:access_control:get_all_books:?`, path `get_all_books`.
    """
    from openultrasast.model.pipeline import scan_region

    findings = scan_region(_cpg(ENTAILING), _spec(), path="models/user_model.py", function="get_user", client=_Client(), model="m")

    path, _, rest = findings[0].site.partition(":")
    assert path == "models/user_model.py", "the file, not the function"
    assert rest.endswith(":get_user")


def test_a_sanitized_flow_the_judge_confirms_becomes_corroborated() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    findings = scan_region(_cpg(SANITIZED), _spec(), function="run", client=_Client(), model="m", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.CORROBORATED


def test_a_sanitized_flow_the_judge_rejects_yields_nothing() -> None:
    """The model found a flow AND has coverage; the judge says the sanitizer suffices. That is a contradiction."""
    from openultrasast.model.pipeline import scan_region

    client = _Client('{"vulnerable": false, "why": "escaped"}')
    assert scan_region(_cpg(SANITIZED), _spec(), function="run", client=client, model="m", candidates=()) == []


def test_a_candidate_the_model_cannot_see_is_reported_at_suspicion() -> None:
    """Req 8.4, and the reason recall exists at all: no modelled sink reaches this site, so the model is
    SILENT, not negative. The LLM's claim is reported, honestly labelled."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    client = _Client()
    findings = scan_region(
        _cpg([]),
        _spec(),
        function="run",
        client=client,
        model="m",
        candidates=({"id": "app.py:9:raw_query", "text": "db.raw(q)", "line": 9},),
    )
    assert client.calls == 1, "one bounded question per candidate"
    assert len(findings) == 1 and findings[0].rung is Rung.SUSPICION
    assert findings[0].site == "app.py:9:raw_query"


def test_a_candidate_the_judge_declines_is_not_reported() -> None:
    from openultrasast.model.pipeline import scan_region

    client = _Client('{"vulnerable": false, "why": "constant"}')
    findings = scan_region(
        _cpg([]),
        _spec(),
        function="run",
        client=client,
        model="m",
        candidates=({"id": "app.py:9:x", "text": "db.raw('literal')", "line": 9},),
    )
    assert findings == []


def test_without_a_client_only_what_the_model_establishes_is_reported() -> None:
    """Req 11.3: the endpoint is optional. Entailment still works; the suspicion band simply goes unasked."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    assert scan_region(_cpg(ENTAILING), _spec(), function="run", client=None, model="", candidates=())[0].rung is Rung.ENTAILED
    assert (
        scan_region(_cpg([]), _spec(), function="run", client=None, model="", candidates=({"id": "a:1:x", "text": "t", "line": 1},)) == []
    )


def test_the_candidate_budget_is_bounded() -> None:
    """A region with many sites must not turn into an unbounded spend."""
    from openultrasast.model.pipeline import MAX_JUDGED_CANDIDATES, scan_region

    client = _Client()
    many = tuple({"id": f"a:{i}:x", "text": "db.raw(q)", "line": i} for i in range(50))
    scan_region(_cpg([]), _spec(), function="run", client=client, model="m", candidates=many)
    assert client.calls == MAX_JUDGED_CANDIDATES


# --- family dispatch ------------------------------------------------------------------------------------
#
# The pipeline first shipped taking a TaintSpec and calling taint_verdict, so access_control and
# config_secrets -- which have working arbiters since group 4 -- produced nothing at all. On the first
# vibe-py run every one of their pairs scored `both_silent`, which read as the model failing when in fact
# there was no code path to the arbiter. Same class as the ceiling harness routing config through taint.


def _dominance_spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import DominanceSpec

    return DominanceSpec(family="access_control", language="python", operations=("filter_by",), dischargers=("current_user",))


def _config_spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import ConfigSpec

    return ConfigSpec(family="config_secrets", language="python", settings=("CORS",), permissive=('"*"',))


def test_an_absence_family_is_arbitrated_by_dominance_not_taint() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    rows = [
        {"operation": "Note.query.filter_by(id=n)", "opLine": "9", "opMethod": "leaky", "dominatingGuards": []},
        {"operation": "Note.query.filter_by(id=n)", "opLine": "3", "opMethod": "safe", "dominatingGuards": ["current_user.id"]},
    ]
    findings = scan_region(_cpg(rows), _dominance_spec(), function="leaky", client=None, model="", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.ENTAILED
    assert findings[0].family == "access_control"


def test_a_configuration_family_is_arbitrated_by_constant_abstraction() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    rows = [{"setting": 'CORS(app, origins="*")', "line": "3", "method": "create_app", "literalArgs": ['"*"'], "args": ["app"]}]
    findings = scan_region(_cpg(rows), _config_spec(), function="create_app", client=None, model="", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.ENTAILED
    assert findings[0].family == "config_secrets"


def test_the_residual_question_matches_the_arbiter_that_raised_it() -> None:
    """A corroborated verdict from dominance is not a question about a sanitizer.

    The pipeline asked `_sanitizer_question` for every corroboration, so an absence finding was put to the
    judge as "a sanitizer appears on the path: yes -- does it suffice?", which is meaningless for a missing
    guard. The judge answered no and the finding was discarded: all three vibe-py access_control pairs scored
    both_silent even though the dominance arbiter had returned model_corroborated for each. Fourth instance in
    this feature of taint-specific behaviour applied to every family.
    """
    from openultrasast.model.pipeline import residual_question

    dom = residual_question(_dominance_spec(), "leaky line 9: no discharging guard", "leaky")
    assert "sanitizer" not in dom.lower(), "an absence bug has no sanitizer to judge"
    assert "guard" in dom.lower()

    cfg = residual_question(_config_spec(), 'CORS(...): permissive literal "*"', "create_app")
    assert "sanitizer" not in cfg.lower() and "setting" in cfg.lower()

    taint = residual_question(_spec(), "request.args['c'] -> os.system(cmd)", "run")
    assert "sanitizer" in taint.lower()


def test_a_corroborated_absence_finding_survives_a_judge_that_agrees() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    rows = [
        {"operation": "q.filter_by(id=n)", "opLine": "9", "opMethod": "leaky", "dominatingGuards": []},
        {"operation": "q.filter_by(id=n)", "opLine": "3", "opMethod": "safe", "dominatingGuards": ["current_user"]},
    ]
    findings = scan_region(_cpg(rows), _dominance_spec(), function="leaky", client=_Client(), model="m", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.ENTAILED


def test_the_dominance_question_describes_the_evidence_the_model_actually_has() -> None:
    """The residual question is only ever asked for CORROBORATED, never ENTAILED -- entailed returns early.

    It was written for the entailed case, so it asserted "in a file where sibling handlers are guarded" and
    asked about "the guard its siblings have", directly above a witness reading "and no guarded sibling".
    The judge, handed a prompt contradicting its own evidence line, answered no and the finding was dropped:
    vampi-users-update-password scored both_silent while the arbiter returned corroborated on the vulnerable
    side and nothing on the fixed one.
    """
    from openultrasast.model.pipeline import residual_question

    witness = "update_password line 16: obligated operation with no discharging guard, and no guarded sibling"
    q = residual_question(_dominance_spec(), witness, "update_password")
    assert "siblings have" not in q, "the corroborated case has no guarded siblings to appeal to"
    assert "sibling handlers are guarded" not in q
    assert "guard" in q.lower() and "public" in q.lower(), "it must still ask whether the operation needs a guard"


def test_a_witness_line_is_read_whatever_follows_the_number() -> None:
    """The delimiter after the line number differs by family: `(line 17,` in one, `(line 17):` in another.

    Splitting on the comma produced sites like `config.py:17): permissive literal '0.0.0.0':?` -- a line
    number no editor can open and no consumer can compare.
    """
    from openultrasast.model.pipeline import _site

    assert _site("config.py", "", "permissive literal '0.0.0.0' (line 17): permissive") == "config.py:17:?"
    assert _site("a.py", "run", "flow reaches os.system (line 9, via x)") == "a.py:9:run"
    assert _site("a.py", "run", "no line at all") == "a.py:?:run"
