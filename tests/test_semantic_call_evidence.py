"""Task 8.1 -- call receiver and arity evidence in the semantic IR (Reqs 3.2, 3.3)."""

from openultrasast.semantic.ir import CallSite, parse_file


def _calls(path: str, text: str, language: str) -> list[CallSite]:
    parsed = parse_file(path, text, language)
    assert parsed.parse_ok, parsed.reason
    return [call for function in parsed.functions for call in function.calls]


PHP_SOURCE = """<?php
final class Controller {
    public function run(): void {
        $this->helper('a', 'b');
        self::staticHelper('c');
        plain('d');
    }
}
"""

JAVA_SOURCE = """public final class Job {
    void execute() {
        getListener().onEvent(item, 1);
    }
}
"""

TYPESCRIPT_SOURCE = """export function handle(client: Client) {
    client.send(payload);
    log("done");
}
"""

PYTHON_SOURCE = """def handle(request):
    store.save(request.body)
    audit(request, flag=True)
    log("done")
"""


def test_php_member_call_retains_receiver_and_arity() -> None:
    calls = {call.name: call for call in _calls("controller.php", PHP_SOURCE, "php")}
    helper = calls["helper"]
    assert helper.receiver == "$this"
    assert helper.arity == 2


def test_php_scoped_call_names_the_class_scope_as_receiver() -> None:
    calls = {call.name: call for call in _calls("controller.php", PHP_SOURCE, "php")}
    assert calls["staticHelper"].receiver == "self"
    assert calls["staticHelper"].arity == 1


def test_php_bare_function_call_has_no_receiver() -> None:
    calls = {call.name: call for call in _calls("controller.php", PHP_SOURCE, "php")}
    assert calls["plain"].receiver is None
    assert calls["plain"].arity == 1


def test_java_method_invocation_retains_receiver_expression_and_arity() -> None:
    calls = {call.name: call for call in _calls("Job.java", JAVA_SOURCE, "java")}
    event = calls["onEvent"]
    assert event.receiver == "getListener()"
    assert event.arity == 2


def test_typescript_member_call_retains_receiver_and_arity() -> None:
    calls = {call.name: call for call in _calls("handle.ts", TYPESCRIPT_SOURCE, "typescript")}
    send = calls["client.send"]
    assert send.receiver == "client"
    assert send.arity == 1
    assert calls["log"].receiver is None


def test_python_attribute_call_retains_receiver_and_arity() -> None:
    calls = {call.name: call for call in _calls("handle.py", PYTHON_SOURCE, "python")}
    save = calls["store.save"]
    assert save.receiver == "store"
    assert save.arity == 1


def test_python_keyword_argument_counts_toward_arity() -> None:
    calls = {call.name: call for call in _calls("handle.py", PYTHON_SOURCE, "python")}
    assert calls["audit"].receiver is None
    assert calls["audit"].arity == 2


def test_python_bare_call_has_no_receiver() -> None:
    calls = {call.name: call for call in _calls("handle.py", PYTHON_SOURCE, "python")}
    assert calls["log"].receiver is None
    assert calls["log"].arity == 1


def test_existing_positional_construction_stays_valid_with_default_evidence() -> None:
    call = CallSite("perform", 7, ("x",), (False,), (("x",),), False, 3)
    assert call.receiver is None
    assert call.arity is None


def test_receiver_capture_survives_whitespaced_member_syntax() -> None:
    source = "export function go(c: Client) {\n    c . flush ( );\n}\n"
    calls = {call.name: call for call in _calls("go.ts", source, "typescript")}
    flush = calls["c . flush"]
    assert flush.receiver == "c"
    assert flush.arity == 0
