"""model-grounded-detection task 3.2: the LLM proposes, the model disposes (Req 8).

The judge is where the prior architecture's whole premise is inverted. There is no K-run averaging, no noise
floor and no acceptance rule; there is one bounded, typed question per candidate, and the answer is CHECKED
against the CPG rather than voted on. The three outcomes are exhaustive:

    the model entails it        -> report it, and never call the model at all
    the model contradicts it    -> drop the claim, and record the contradiction
    the model cannot decide     -> report `suspicion`, honestly

Every test here runs with no network and a scripted client.
"""

from __future__ import annotations

from pathlib import Path


def _spec():  # type: ignore[no-untyped-def]
    from openultrasast.model.specs import TaintSpec

    return TaintSpec(family="injection", language="python", sources=("request.args",), sinks=("os.system",), sanitizers=("escape",))


def _cpg(rows):  # type: ignore[no-untyped-def]
    from openultrasast.cpg.backend import CpgResult

    return CpgResult(cpg_path=Path("cpg.bin"), run=lambda q, p: rows)


ENTAILING_ROW = [
    {"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']", "sanitized": False, "length": 3}
]


class _Client:
    """A scripted chat client that records whether it was called at all."""

    def __init__(self, answer: str = '{"vulnerable": true, "family": "injection"}') -> None:
        self.calls: list[object] = []
        self._answer = answer

    def complete(self, **kwargs: object):  # type: ignore[no-untyped-def]
        from openultrasast.tool_hunter import ChatResponse

        self.calls.append(kwargs)
        return ChatResponse(content=self._answer, tool_calls=[], reasoning=None)


def test_an_entailed_candidate_costs_no_model_call() -> None:
    """The point of the arbiter: where the graph decides, the LLM is not consulted at all."""
    from openultrasast.model.judge import judge
    from openultrasast.model.ladder import Rung

    client = _Client()
    answer = judge(_cpg(ENTAILING_ROW), _spec(), function="run", client=client, model="m")
    assert answer.rung is Rung.ENTAILED
    assert client.calls == [], "an entailed candidate must not reach the model"


def test_a_claim_the_model_contradicts_is_dropped_with_its_reason() -> None:
    """Req 8.2. The LLM says vulnerable; the CPG shows no flow reaches the sink. The graph wins."""
    from openultrasast.model.judge import judge
    from openultrasast.model.ladder import Rung

    client = _Client('{"vulnerable": true, "family": "injection"}')
    answer = judge(_cpg([]), _spec(), function="run", client=client, model="m")
    assert answer.rung is Rung.SUSPICION
    assert answer.contradiction, "a dropped claim must say why it was dropped"
    assert "no flow" in answer.contradiction.lower() or "not reach" in answer.contradiction.lower()


def test_a_claim_the_model_supports_advances_to_corroborated() -> None:
    """Req 8.3: a sanitized path is a real flow whose sufficiency only the LLM can judge."""
    from openultrasast.model.judge import judge
    from openultrasast.model.ladder import Rung

    rows = [{"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']", "sanitized": True, "length": 3}]
    client = _Client('{"vulnerable": true, "family": "injection"}')
    answer = judge(_cpg(rows), _spec(), function="run", client=client, model="m")
    assert answer.rung is Rung.CORROBORATED
    assert len(client.calls) == 1, "exactly one bounded question, never a loop"


def test_the_llm_declining_leaves_a_corroborated_flow_at_suspicion() -> None:
    """The model saw a flow but the LLM says the sanitizer suffices; the claim does not advance."""
    from openultrasast.model.judge import judge
    from openultrasast.model.ladder import Rung

    rows = [{"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']", "sanitized": True, "length": 3}]
    client = _Client('{"vulnerable": false, "family": "injection"}')
    answer = judge(_cpg(rows), _spec(), function="run", client=client, model="m")
    assert answer.rung is Rung.SUSPICION


def test_without_a_client_the_verdict_still_stands_on_its_own() -> None:
    """Req 11.3: the endpoint is optional. The model layer does not need it to entail."""
    from openultrasast.model.judge import judge
    from openultrasast.model.ladder import Rung

    assert judge(_cpg(ENTAILING_ROW), _spec(), function="run", client=None, model="").rung is Rung.ENTAILED
    sanitized = [
        {"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']", "sanitized": True, "length": 3}
    ]
    answer = judge(_cpg(sanitized), _spec(), function="run", client=None, model="")
    assert answer.rung is Rung.SUSPICION and "endpoint" in answer.contradiction.lower()


def test_the_question_is_bounded_typed_and_offers_no_tools() -> None:
    """Req 8.1: the LLM answers one question about a site it was handed; it never searches for the site."""
    from openultrasast.model.judge import judge

    rows = [{"sink": "os.system(cmd)", "sinkLine": "4", "sinkMethod": "run", "source": "request.args['c']", "sanitized": True, "length": 3}]
    client = _Client()
    judge(_cpg(rows), _spec(), function="run", client=client, model="m")
    call = client.calls[0]
    assert call["tools"] == [], "no tools: the candidate is given, not searched for"
    assert call["json_object"] is True, "a typed answer, not prose"
    text = " ".join(str(m.get("content", "")) for m in call["messages"])  # type: ignore[union-attr]
    assert "os.system(cmd)" in text and "request.args['c']" in text, "the question carries the model's own evidence"


def test_the_prompt_is_redacted() -> None:
    """Req 11.4: every prompt passes through redaction."""
    from openultrasast.model.judge import judge

    rows = [
        {
            "sink": "connect(pw)",
            "sinkLine": "4",
            "sinkMethod": "run",
            "source": "AKIA" + "IOSFODNN7" + "EXAMPLE",
            "sanitized": True,
            "length": 2,
        }
    ]
    client = _Client()
    judge(_cpg(rows), _spec(), function="run", client=client, model="m")
    text = " ".join(str(m.get("content", "")) for m in client.calls[0]["messages"])  # type: ignore[index,union-attr]
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_there_is_no_k_run_averaging_anywhere_in_the_judge() -> None:
    """Req 8.5, asserted structurally: the noise architecture must not grow back."""
    import ast

    source = Path("src/openultrasast/model/judge.py").read_text()
    tree = ast.parse(source)

    # Check CODE, not prose: the docstring is allowed to name the machinery it replaced.
    names = (
        {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    )
    for banned in ("k_runs", "majority", "vote", "votes", "average", "mean", "acceptance", "floor", "budget"):
        assert banned not in names, f"{banned} has no place in the judge"

    # No loop over runs anywhere in the module.
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.For | ast.While)], "the judge asks once"

    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not any("rounds" in m or "acceptance" in m for m in imported)
