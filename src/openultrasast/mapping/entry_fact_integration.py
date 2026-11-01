"""Authority-bearing integration of reviewed entry facts at the mapping boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from openultrasast.core import family
from openultrasast.core.factpack import FactPack, StructuralRequirementKind
from openultrasast.mapping.entry_fact_matcher import EntryFactMatchResult, match_entry_fact
from openultrasast.mapping.entry_fact_structure import candidates, read_source_structure
from openultrasast.mapping.entry_packs import load_installed_entry_fact_authority
from openultrasast.mapping.fact_authority import EntryFactAuthorityBundle, EntryFactAuthorityContext
from openultrasast.mapping.fact_match_store import FactMatchArtifactWriter
from openultrasast.mapping.installed_fact_authority import DigestDirectoryResolver, fact_pack_bytes, installed_authority_bytes
from openultrasast.preprocess import FileTarget

_DIGEST = re.compile(r"[0-9a-f]{64}")
_LANGUAGES = frozenset(("javascript", "typescript"))


class EntryFactIntegrationError(ValueError):
    """The production mapping boundary cannot run reviewed fact matching safely."""


def _validate_contract_and_packs(supplied: EntryFactAuthorityBundle, installed: EntryFactAuthorityBundle) -> None:
    if type(supplied.contract) is not family.FamilyContract:
        raise TypeError("authority contract must use the exact FamilyContract type")
    try:
        supplied_contract = family.family_contract_digest(supplied.contract)
        installed_contract = family.family_contract_digest(installed.contract)
    except (family.FamilyContractError, TypeError, ValueError) as exc:
        raise EntryFactIntegrationError("authority contract cannot be validated") from exc
    if supplied_contract != installed_contract:
        raise EntryFactIntegrationError("authority contract differs from the installed reviewed contract")
    if type(supplied.packs) is not tuple or len(supplied.packs) != len(installed.packs):
        raise EntryFactIntegrationError("authority pack tuple differs from the installed reviewed packs")
    for supplied_pack, installed_pack in zip(supplied.packs, installed.packs, strict=True):
        if type(supplied_pack) is not FactPack or type(supplied_pack.language) is not str:
            raise TypeError("authority packs must use exact FactPack and language types")
        if supplied_pack.language != installed_pack.language or fact_pack_bytes(supplied_pack) != fact_pack_bytes(installed_pack):
            raise EntryFactIntegrationError("authority pack body differs from the installed reviewed pack")


def _validate_inputs(
    authority: EntryFactAuthorityContext,
    writer: FactMatchArtifactWriter,
    evaluation_population_digest: str,
) -> EntryFactAuthorityContext:
    if type(authority) is not EntryFactAuthorityContext:
        raise TypeError("authority must be an authenticated EntryFactAuthorityContext")
    if type(authority.bundle) is not EntryFactAuthorityBundle:
        raise TypeError("authority bundle must use the exact reviewed bundle type")
    if type(writer) is not FactMatchArtifactWriter:
        raise TypeError("writer must be a FactMatchArtifactWriter")
    if writer.store_identity not in authority.bundle.review_policy.trusted_store_identities:
        raise EntryFactIntegrationError("fact-match writer does not use a trusted store")
    if not isinstance(evaluation_population_digest, str) or _DIGEST.fullmatch(evaluation_population_digest) is None:
        raise EntryFactIntegrationError("evaluation population digest is invalid")
    installed = load_installed_entry_fact_authority(authority.custody)
    _validate_contract_and_packs(authority.bundle, installed.bundle)
    if installed_authority_bytes(authority.bundle) != installed_authority_bytes(installed.bundle):
        raise EntryFactIntegrationError("authority context does not equal externally authenticated installed authority")
    supplied_resolver, installed_resolver = authority.resolver, installed.resolver
    if type(supplied_resolver) is not DigestDirectoryResolver or type(installed_resolver) is not DigestDirectoryResolver:
        raise EntryFactIntegrationError("authority resolver is not the exact installed resolver type")
    if (
        type(supplied_resolver.root) is not type(installed_resolver.root)
        or supplied_resolver.root.parts != installed_resolver.root.parts
        or type(supplied_resolver.store_identity) is not str
        or supplied_resolver.store_identity != installed_resolver.store_identity
    ):
        raise EntryFactIntegrationError("authority resolver does not equal the installed resolver identity")
    return installed


def _pack(authority: EntryFactAuthorityContext, language: str) -> FactPack:
    packs = tuple(item for item in authority.bundle.packs if item.language == language)
    if len(packs) != 1:
        raise EntryFactIntegrationError("reviewed language pack is missing or ambiguous")
    return packs[0]


def _target_for_fact(fact: object) -> str:
    requirements = getattr(fact, "structural_requirements", ())
    values = tuple(
        item.expected for item in requirements if item.kind is StructuralRequirementKind.QUALIFIED_NAME and isinstance(item.expected, str)
    )
    if len(values) != 1:
        raise EntryFactIntegrationError("reviewed fact does not declare one qualified target")
    return values[0]


def _candidate_fact_ids(repository_root: Path, target: FileTarget, pack: FactPack) -> tuple[str, ...]:
    source = read_source_structure(repository_root, target.path, target.language)
    return tuple(fact.fact_id for fact in pack.facts if candidates(source, _target_for_fact(fact)))


def _validate_source_texts(repository_root: Path, targets: Sequence[FileTarget], source_texts: Mapping[str, str] | None) -> None:
    if source_texts is None:
        return
    for target in targets:
        if target.language not in _LANGUAGES:
            continue
        try:
            installed = (repository_root / target.path).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise EntryFactIntegrationError("reviewed matching requires readable UTF-8 product source") from exc
        if source_texts.get(target.path) != installed:
            raise EntryFactIntegrationError("cached source text differs from reviewed matcher input")


def match_reviewed_entry_targets(
    repository_root: Path,
    targets: Sequence[FileTarget],
    authority: EntryFactAuthorityContext,
    writer: FactMatchArtifactWriter,
    evaluation_population_digest: str,
    *,
    source_texts: Mapping[str, str] | None = None,
) -> tuple[EntryFactMatchResult, ...]:
    """Persist and validate every structurally present reviewed entry fact.

    Compatibility projection rows are deliberately absent from this interface. They
    may recognize legacy entries, but only reviewed pack facts with typed structure
    reach the matcher and its canonical artifact writer.
    """
    authenticated = _validate_inputs(authority, writer, evaluation_population_digest)
    root = Path(repository_root)
    _validate_source_texts(root, targets, source_texts)
    results: list[EntryFactMatchResult] = []
    for target in targets:
        if target.language not in _LANGUAGES:
            continue
        pack = _pack(authenticated, target.language)
        for fact_id in _candidate_fact_ids(root, target, pack):
            results.extend(
                match_entry_fact(
                    repository_root=root,
                    relative_path=target.path,
                    language=target.language,
                    fact_id=fact_id,
                    authority=authenticated,
                    writer=writer,
                    evaluation_population_digest=evaluation_population_digest,
                )
            )
    return tuple(results)


__all__ = ["EntryFactIntegrationError", "match_reviewed_entry_targets"]
