"""Task 8.2: stable declaration identities and the per-change symbol index (Reqs 3.2, 3.5, 6.2)."""

from openultrasast.semantic.cst import declaration_scopes
from openultrasast.semantic.obligations.resolution import SymbolId, SymbolIndex

JAVA_A = "package pkg.a;\npublic class Handler {\n    public void run() {}\n    public void run(String command) {}\n}\n"
JAVA_B = "package pkg.b;\npublic class Handler {\n    public void run() {}\n}\n"
PHP_EXTENDS = "<?php\nfinal class InvoiceController extends Controller {\n    public function preview(array $fields) {}\n}\n"
TS_CLASS = "class Client {\n    send(payload: string): void {}\n}\n"
PYTHON_MIXED = "class Service:\n    def audit(self, request):\n        return request\n\n\ndef audit(request):\n    return request\n"


def test_duplicate_type_names_across_modules_get_distinct_identities() -> None:
    index = SymbolIndex.build([("pkg/a/Handler.java", JAVA_A, "java"), ("pkg/b/Handler.java", JAVA_B, "java")])
    handler_a = SymbolId("pkg/a/Handler.java", "Handler", "run", None)
    handler_b = SymbolId("pkg/b/Handler.java", "Handler", "run", None)
    assert handler_a in index.declarations
    assert handler_b in index.declarations
    assert handler_a != handler_b


def test_same_class_overloads_get_distinct_signatures() -> None:
    index = SymbolIndex.build([("pkg/a/Handler.java", JAVA_A, "java")])
    no_argument = SymbolId("pkg/a/Handler.java", "Handler", "run", None)
    with_command = SymbolId("pkg/a/Handler.java", "Handler", "run", ("command",))
    assert no_argument in index.declarations
    assert with_command in index.declarations
    assert no_argument != with_command


def test_php_extends_records_base_types() -> None:
    index = SymbolIndex.build([("src/InvoiceController.php", PHP_EXTENDS, "php")])
    assert index.base_types[("src/InvoiceController.php", "InvoiceController")] == ("Controller",)


def test_typescript_method_carries_enclosing_type() -> None:
    index = SymbolIndex.build([("src/Client.ts", TS_CLASS, "typescript")])
    assert SymbolId("src/Client.ts", "Client", "send", ("payload",)) in index.declarations


def test_python_class_method_and_module_function_stay_distinct() -> None:
    index = SymbolIndex.build([("service.py", PYTHON_MIXED, "python")])
    method = SymbolId("service.py", "Service", "audit", ("self", "request"))
    module_function = SymbolId("service.py", None, "audit", ("request",))
    assert method in index.declarations
    assert module_function in index.declarations
    assert method != module_function


def test_by_name_returns_every_same_name_symbol() -> None:
    index = SymbolIndex.build([("pkg/a/Handler.java", JAVA_A, "java"), ("pkg/b/Handler.java", JAVA_B, "java")])
    assert len(index.by_name["run"]) == 3


def test_build_is_deterministic_and_deduplicating() -> None:
    files = [("pkg/a/Handler.java", JAVA_A, "java"), ("pkg/a/Handler.java", JAVA_A, "java")]
    first = SymbolIndex.build(files)
    second = SymbolIndex.build(files)
    assert first == second
    assert len(first.declarations) == len(set(first.declarations))
    assert first.declarations == tuple(sorted(first.declarations))


def test_no_argument_method_has_signature_none() -> None:
    index = SymbolIndex.build([("pkg/b/Handler.java", JAVA_B, "java")])
    assert index.by_name["run"] == (SymbolId("pkg/b/Handler.java", "Handler", "run", None),)


def test_unparsable_file_yields_no_scopes() -> None:
    assert declaration_scopes("broken.php", "<?php class {{{", "php") == ()
