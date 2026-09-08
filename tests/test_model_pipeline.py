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

    return TaintSpec(family="injection", language="python", sources=("request.args",),
                     sinks=("os.system",), sanitizers=("escape",))


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


ENTAILING = [{"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']",
              "sanitized": False, "length": 3, "inLabeledScope": True}]
SANITIZED = [{"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']",
              "sanitized": True, "length": 3, "inLabeledScope": True}]


def test_an_entailed_site_becomes_a_finding_with_no_model_call() -> None:
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    client = _Client()
    findings = scan_region(_cpg(ENTAILING), _spec(), function="run", client=client, model="m", candidates=())
    assert len(findings) == 1 and findings[0].rung is Rung.ENTAILED
    assert client.calls == 0


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
    findings = scan_region(_cpg([]), _spec(), function="run", client=client, model="m",
                           candidates=({"id": "app.py:9:raw_query", "text": "db.raw(q)", "line": 9},))
    assert client.calls == 1, "one bounded question per candidate"
    assert len(findings) == 1 and findings[0].rung is Rung.SUSPICION
    assert findings[0].site == "app.py:9:raw_query"


def test_a_candidate_the_judge_declines_is_not_reported() -> None:
    from openultrasast.model.pipeline import scan_region

    client = _Client('{"vulnerable": false, "why": "constant"}')
    findings = scan_region(_cpg([]), _spec(), function="run", client=client, model="m",
                           candidates=({"id": "app.py:9:x", "text": "db.raw('literal')", "line": 9},))
    assert findings == []


def test_without_a_client_only_what_the_model_establishes_is_reported() -> None:
    """Req 11.3: the endpoint is optional. Entailment still works; the suspicion band simply goes unasked."""
    from openultrasast.model.ladder import Rung
    from openultrasast.model.pipeline import scan_region

    assert scan_region(_cpg(ENTAILING), _spec(), function="run", client=None, model="", candidates=())[0].rung is Rung.ENTAILED
    assert scan_region(_cpg([]), _spec(), function="run", client=None, model="",
                       candidates=({"id": "a:1:x", "text": "t", "line": 1},)) == []


def test_the_candidate_budget_is_bounded() -> None:
    """A region with many sites must not turn into an unbounded spend."""
    from openultrasast.model.pipeline import MAX_JUDGED_CANDIDATES, scan_region

    client = _Client()
    many = tuple({"id": f"a:{i}:x", "text": "db.raw(q)", "line": i} for i in range(50))
    scan_region(_cpg([]), _spec(), function="run", client=client, model="m", candidates=many)
    assert client.calls == MAX_JUDGED_CANDIDATES
