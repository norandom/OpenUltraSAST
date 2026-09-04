"""One CST walker: tree-sitter nodes into FileIR. No per-language visitors."""

from __future__ import annotations

from typing import Any

from .ir import Bind, CallSite, FileIR, FunctionIR

_KIND = {
    "python": {
        "function": frozenset({"function_definition"}),
        "assign": frozenset({"assignment", "augmented_assignment"}),
        "call": frozenset({"call"}),
        "args": frozenset({"argument_list", "arguments"}),
        "string": frozenset({"string"}),
        "params": frozenset({"parameters"}),
    },
    "javascript": {
        "function": frozenset({"function_declaration", "method_definition", "arrow_function", "function_expression"}),
        "assign": frozenset({"assignment_expression", "augmented_assignment_expression"}),
        "call": frozenset({"call_expression"}),
        "args": frozenset({"arguments"}),
        "string": frozenset({"string"}),
        "params": frozenset({"formal_parameters"}),
    },
    "c": {
        "function": frozenset({"function_definition"}),
        "assign": frozenset({"assignment_expression"}),
        "call": frozenset({"call_expression"}),
        "args": frozenset({"argument_list"}),
        "string": frozenset({"string_literal"}),
        "params": frozenset({"parameter_list"}),
    },
    "java": {
        "function": frozenset({"method_declaration", "constructor_declaration"}),
        "assign": frozenset({"assignment_expression", "variable_declarator"}),
        "call": frozenset({"method_invocation"}),
        "args": frozenset({"argument_list"}),
        "string": frozenset({"string_literal"}),
        "params": frozenset({"formal_parameters"}),
    },
}
_KIND["cpp"] = _KIND["c"]
_KIND["typescript"] = _KIND["javascript"]

_CONST = frozenset(
    {
        "string",
        "string_literal",
        "integer",
        "number",
        "float",
        "true",
        "false",
        "null",
        "nil",
        "character_literal",
        "escape_sequence",
    }
)
_SEQUENCE = frozenset({"list", "tuple", "array", "array_creation_expression", "initializer_list"})


def parse_with_cst(path: str, text: str, language: str) -> FileIR | None:
    from .extra import grammar_for

    grammar = grammar_for(language)
    if grammar is None:
        return None
    try:
        from tree_sitter import Parser

        parser = Parser(grammar)
        tree = parser.parse(text.encode())
    except Exception:
        return FileIR(path=path, language=language, engine="tree-sitter", functions=(), parse_ok=False, reason="parse_failed")
    return file_ir_from_tree(path=path, text=text, language=language, tree=tree)


def file_ir_from_tree(*, path: str, text: str, language: str, tree: Any) -> FileIR:
    del text
    root = tree.root_node
    if bool(getattr(root, "has_error", False)):
        return FileIR(path=path, language=language, engine="tree-sitter", functions=(), parse_ok=False, reason="parse_failed")
    kinds = _KIND.get(language)
    if kinds is None:
        return FileIR(path=path, language=language, engine="none", functions=(), parse_ok=False, reason="language_unsupported")
    functions: list[FunctionIR] = []
    module_binds, module_calls = _collect(root, kinds, skip=kinds["function"])
    functions.append(
        FunctionIR(
            name="<module>",
            params=(),
            start_line=_line(root),
            end_line=_end_line(root),
            binds=tuple(module_binds),
            calls=tuple(module_calls),
        )
    )
    for node in _walk(root):
        if node.type not in kinds["function"]:
            continue
        binds, calls = _collect(node, kinds, skip=kinds["function"])
        functions.append(
            FunctionIR(
                name=_function_name(node),
                params=_params(node, kinds),
                start_line=_line(node),
                end_line=_end_line(node),
                binds=tuple(binds),
                calls=tuple(calls),
            )
        )
    return FileIR(path=path, language=language, engine="tree-sitter", functions=tuple(functions), parse_ok=True)


def _collect(node: Any, kinds: dict[str, frozenset[str]], *, skip: frozenset[str]) -> tuple[list[Bind], list[CallSite]]:
    binds: list[Bind] = []
    calls: list[CallSite] = []
    for child in _walk(node, skip=skip):
        if child.type in kinds["assign"]:
            bind = _bind(child, kinds)
            if bind is not None:
                binds.append(bind)
        if child.type in kinds["call"]:
            calls.append(_call(child, kinds))
    return binds, calls


def _walk(node: Any, *, skip: frozenset[str] | None = None) -> list[Any]:
    found: list[Any] = [node]
    for child in getattr(node, "named_children", ()) or ():
        if skip is not None and child.type in skip:
            continue
        found.extend(_walk(child, skip=skip))
    return found


def _bind(node: Any, kinds: dict[str, frozenset[str]]) -> Bind | None:
    children = list(getattr(node, "named_children", ()) or ())
    if not children:
        return None
    name_node = children[0]
    value_node = children[-1] if len(children) > 1 else None
    name = _left_name(name_node)
    if not name:
        return None
    value_text = _text(value_node) if value_node is not None else ""
    return Bind(
        name=name,
        line=_line(node),
        value_text=value_text,
        is_constant=_is_constant(value_node, kinds) if value_node is not None else False,
        names=_identifiers(value_node) if value_node is not None else (),
        call_name=_call_name(value_node, kinds) if value_node is not None and value_node.type in kinds["call"] else None,
    )


def _call(node: Any, kinds: dict[str, frozenset[str]]) -> CallSite:
    args_node = next((child for child in getattr(node, "named_children", ()) or () if child.type in kinds["args"]), None)
    arg_nodes = list(getattr(args_node, "named_children", ()) or ()) if args_node is not None else []
    extra = len(arg_nodes) >= 2 and arg_nodes[1].type in _SEQUENCE
    return CallSite(
        name=_callee_name(node, args_node),
        line=_line(node),
        arg_texts=tuple(_text(arg) for arg in arg_nodes),
        arg_is_constant=tuple(_is_constant(arg, kinds) for arg in arg_nodes),
        arg_names=tuple(_identifiers(arg) for arg in arg_nodes),
        extra_arg_is_sequence=extra,
    )


def _callee_name(node: Any, args_node: Any) -> str:
    idents = [
        _text(child)
        for child in getattr(node, "named_children", ()) or ()
        if child is not args_node and child.type in {"identifier", "property_identifier"}
    ]
    if idents:
        return idents[-1]
    for child in getattr(node, "named_children", ()) or ():
        if child is not args_node:
            text = _text(child)
            if text:
                return text.split("(")[0]
    return _text(node).split("(")[0]


def _call_name(node: Any, kinds: dict[str, frozenset[str]]) -> str | None:
    if node.type in kinds["call"]:
        args_node = next((child for child in getattr(node, "named_children", ()) or () if child.type in kinds["args"]), None)
        return _callee_name(node, args_node)
    return None


def _function_name(node: Any) -> str:
    for child in getattr(node, "named_children", ()) or ():
        if child.type == "identifier":
            return _text(child)
        if child.type == "function_declarator":
            for grandchild in getattr(child, "named_children", ()) or ():
                if grandchild.type == "identifier":
                    return _text(grandchild)
    return "<anon>"


def _params(node: Any, kinds: dict[str, frozenset[str]]) -> tuple[str, ...]:
    for child in _walk(node, skip=frozenset()):
        if child.type in kinds["params"]:
            return _identifiers(child)
        if child.type == "function_declarator":
            for grandchild in getattr(child, "named_children", ()) or ():
                if grandchild.type in kinds["params"]:
                    return _identifiers(grandchild)
    return ()


def _left_name(node: Any) -> str:
    if node.type in {"identifier", "property_identifier"}:
        return _text(node)
    idents = _identifiers(node)
    return idents[0] if idents else ""


def _identifiers(node: Any) -> tuple[str, ...]:
    names: list[str] = []
    for child in _walk(node):
        if child.type == "identifier":
            names.append(_text(child))
    return tuple(names)


def _is_constant(node: Any, kinds: dict[str, frozenset[str]]) -> bool:
    if node.type in _CONST or node.type in kinds["string"]:
        return True
    if node.type not in {"binary_expression", "concatenated_string"}:
        return False
    children = list(getattr(node, "named_children", ()) or ())
    return bool(children) and all(_is_constant(child, kinds) for child in children)


def _text(node: Any) -> str:
    raw = getattr(node, "text", None)
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode(errors="ignore")
    return str(raw)


def _line(node: Any) -> int:
    point = getattr(node, "start_point", (0, 0))
    return int(point[0]) + 1


def _end_line(node: Any) -> int:
    point = getattr(node, "end_point", getattr(node, "start_point", (0, 0)))
    return int(point[0]) + 1
