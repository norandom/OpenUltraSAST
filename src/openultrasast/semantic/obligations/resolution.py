"""Stable declaration identities for repository-defined symbols (task 8.2).

The symbol index gives every declaration an identity keyed by module, enclosing type, name, and -- when
the declaration carries them -- parameter names, so same-name targets never merge (Req 3.2) and base-type
declarations attach only through explicit descendant edges (Req 3.5). Engine purity: no framework or
product names appear here; target vocabulary arrives as data through the acquisition pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ..cst import DeclarationScope, declaration_scopes


@dataclass(frozen=True)
class SymbolId:
    """The stable identity of one declaration: module (repository path), enclosing type, name, signature."""

    module: str
    enclosing_type: str | None
    name: str
    signature: tuple[str, ...] | None

    @property
    def sort_key(self) -> tuple[str, str, str, tuple[str, ...]]:
        """A total-order key; a missing signature sorts before every present one."""
        return (self.module, self.enclosing_type or "", self.name, self.signature or ())

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SymbolId):
            return NotImplemented
        return self.sort_key < other.sort_key


@dataclass(frozen=True)
class SymbolIndex:
    """Repository-defined declarations and the inheritance edges between their types."""

    declarations: tuple[SymbolId, ...]
    base_types: Mapping[tuple[str, str], tuple[str, ...]]
    by_name: Mapping[str, tuple[SymbolId, ...]] = field(default_factory=dict)

    @classmethod
    def build(cls, files: Iterable[tuple[str, str, str]]) -> SymbolIndex:
        """Build the index from (path, text, language) triples; deterministic and deduplicated."""
        declarations: set[SymbolId] = set()
        base_types: dict[tuple[str, str], tuple[str, ...]] = {}
        for path, text, language in files:
            scopes = declaration_scopes(path, text, language)
            declarations.update(_symbol_id(path, scope) for scope in scopes)
            base_types.update(_inheritance_edges(path, scopes))
        by_name: dict[str, list[SymbolId]] = {}
        for declaration in sorted(declarations):
            by_name.setdefault(declaration.name, []).append(declaration)
        return cls(
            declarations=tuple(sorted(declarations)),
            base_types=dict(sorted(base_types.items())),
            by_name={name: tuple(symbols) for name, symbols in sorted(by_name.items())},
        )


def _symbol_id(module: str, scope: DeclarationScope) -> SymbolId:
    """Parameter names are the signature when present; a declaration without them has none."""
    signature = tuple(scope.params) if scope.params else None
    return SymbolId(module=module, enclosing_type=scope.enclosing_type, name=scope.function_name, signature=signature)


def _inheritance_edges(module: str, scopes: Iterable[DeclarationScope]) -> dict[tuple[str, str], tuple[str, ...]]:
    """(module, type) -> the base names that type declares, from any method declared inside it."""
    edges: dict[tuple[str, str], tuple[str, ...]] = {}
    for scope in scopes:
        if scope.enclosing_type is not None:
            edges[(module, scope.enclosing_type)] = scope.enclosing_base_types
    return edges
