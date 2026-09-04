"""Intra-file IR: tree-sitter when a grammar works, Python stdlib ast as last resort."""

from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .engines import tree_sitter_available

_EXTENSION = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "c": ".c",
    "cpp": ".cpp",
    "java": ".java",
}


@dataclass(frozen=True)
class Bind:
    name: str
    line: int
    value_text: str
    is_constant: bool
    names: tuple[str, ...]
    call_name: str | None


@dataclass(frozen=True)
class CallSite:
    name: str
    line: int
    arg_texts: tuple[str, ...]
    arg_is_constant: tuple[bool, ...]
    arg_names: tuple[tuple[str, ...], ...]
    extra_arg_is_sequence: bool


@dataclass(frozen=True)
class FunctionIR:
    name: str
    params: tuple[str, ...]
    start_line: int
    end_line: int
    binds: tuple[Bind, ...]
    calls: tuple[CallSite, ...]


@dataclass(frozen=True)
class FileIR:
    path: str
    language: str
    engine: str
    functions: tuple[FunctionIR, ...]
    parse_ok: bool
    reason: str | None = None


def parse_file(path: str, text: str, language: str) -> FileIR:
    if tree_sitter_available():
        parsed = parse_tree_sitter_cli(path, text, language)
        if parsed is not None and parsed.parse_ok:
            return parsed
    if language == "python":
        return parse_python_ast(path, text)
    return FileIR(path=path, language=language, engine="none", functions=(), parse_ok=False, reason="language_unsupported")


def parse_python_ast(path: str, text: str) -> FileIR:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return FileIR(path=path, language="python", engine="python-ast", functions=(), parse_ok=False, reason="parse_failed")
    functions = _python_functions(tree)
    return FileIR(path=path, language="python", engine="python-ast", functions=tuple(functions), parse_ok=True)


def parse_tree_sitter_cli(path: str, text: str, language: str) -> FileIR | None:
    binary = shutil.which("tree-sitter")
    if binary is None:
        return None
    suffix = _EXTENSION.get(language, ".txt")
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(text.encode())
            tmp_path = handle.name
        result = subprocess.run(
            [binary, "parse", tmp_path],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    finally:
        if tmp_path:
            Path(tmp_path).unlink(missing_ok=True)
    combined = f"{result.stdout or ''}{result.stderr or ''}"
    if result.returncode != 0 or "No language found" in combined or "Failed to load language" in combined:
        return None
    # A successful parse without an extractor still cannot adjudicate JS/C/Java.
    # Return a parse_ok IR only when we actually built functions; otherwise None
    # so Python can fall back to ast and other languages stay unsupported.
    return None


def _python_functions(tree: ast.AST) -> list[FunctionIR]:
    functions: list[FunctionIR] = []
    module_binds, module_calls = _statements(getattr(tree, "body", []))
    functions.append(
        FunctionIR(
            name="<module>",
            params=(),
            start_line=1,
            end_line=getattr(tree, "end_lineno", 1) or 1,
            binds=tuple(module_binds),
            calls=tuple(module_calls),
        )
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            binds, calls = _statements(node.body)
            functions.append(
                FunctionIR(
                    name=node.name,
                    params=tuple(arg.arg for arg in node.args.args),
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    binds=tuple(binds),
                    calls=tuple(calls),
                )
            )
    return functions


def _statements(body: list[ast.stmt]) -> tuple[list[Bind], list[CallSite]]:
    binds: list[Bind] = []
    calls: list[CallSite] = []
    for stmt in body:
        _collect_stmt(stmt, binds, calls)
    return binds, calls


def _collect_stmt(stmt: ast.stmt, binds: list[Bind], calls: list[CallSite]) -> None:
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return
    if isinstance(stmt, ast.Assign):
        value_bind = _bind_from_value(stmt.value, stmt.lineno)
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                binds.append(
                    Bind(
                        name=target.id,
                        line=stmt.lineno,
                        value_text=value_bind[0],
                        is_constant=value_bind[1],
                        names=value_bind[2],
                        call_name=value_bind[3],
                    )
                )
        _collect_expr_calls(stmt.value, calls)
        return
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
        value_bind = _bind_from_value(stmt.value, stmt.lineno)
        binds.append(
            Bind(
                name=stmt.target.id,
                line=stmt.lineno,
                value_text=value_bind[0],
                is_constant=value_bind[1],
                names=value_bind[2],
                call_name=value_bind[3],
            )
        )
        _collect_expr_calls(stmt.value, calls)
        return
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        value_bind = _bind_from_value(stmt.value, stmt.lineno)
        binds.append(
            Bind(
                name=stmt.target.id,
                line=stmt.lineno,
                value_text=f"{stmt.target.id} {value_bind[0]}",
                is_constant=False,
                names=tuple(sorted(set(value_bind[2]) | {stmt.target.id})),
                call_name=value_bind[3],
            )
        )
        _collect_expr_calls(stmt.value, calls)
        return
    if isinstance(stmt, ast.Return) and stmt.value is not None:
        _collect_expr_calls(stmt.value, calls)
        return
    if isinstance(stmt, ast.Expr):
        _collect_expr_calls(stmt.value, calls)
        return
    for child in ast.iter_child_nodes(stmt):
        if isinstance(child, ast.stmt):
            _collect_stmt(child, binds, calls)
        elif isinstance(child, ast.expr):
            _collect_expr_calls(child, calls)


def _bind_from_value(value: ast.expr, line: int) -> tuple[str, bool, tuple[str, ...], str | None]:
    del line
    text = _unparse(value)
    names = _load_names(value)
    call_name = _call_name(value) if isinstance(value, ast.Call) else None
    return text, _is_constant(value), names, call_name


def _collect_expr_calls(expr: ast.expr, calls: list[CallSite]) -> None:
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            calls.append(_call_site(node))


def _call_site(node: ast.Call) -> CallSite:
    arg_texts: list[str] = []
    arg_const: list[bool] = []
    arg_names: list[tuple[str, ...]] = []
    for arg in node.args:
        arg_texts.append(_unparse(arg))
        arg_const.append(_is_constant(arg))
        arg_names.append(_load_names(arg))
    extra_sequence = False
    if len(node.args) >= 2:
        extra_sequence = isinstance(node.args[1], ast.Tuple | ast.List | ast.Set)
    return CallSite(
        name=_call_name(node),
        line=node.lineno,
        arg_texts=tuple(arg_texts),
        arg_is_constant=tuple(arg_const),
        arg_names=tuple(arg_names),
        extra_arg_is_sequence=extra_sequence,
    )


def _call_name(node: ast.AST) -> str:
    func = node.func if isinstance(node, ast.Call) else node
    return _unparse(func)


def _load_names(node: ast.AST) -> tuple[str, ...]:
    names: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            names.append(child.id)
    return tuple(names)


def _is_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(value, ast.Constant) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_constant(node.left) and _is_constant(node.right)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_constant(elt) for elt in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd | ast.USub):
        return _is_constant(node.operand)
    return False


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""
