"""Trail of Bits skill index + router (Phase 14).

Security skills are scoped expertise, not global prompt bloat. Each skill is a small
descriptor with routing metadata (languages, tags, vulnerability classes, stages) and
a short operating checklist. The router selects the most relevant skills for a target
and stage; ``select_skill_context`` packs their checklists into a char budget; and
``skill_chunks`` chunks the guidance into the ``skills`` retrieval namespace. Nothing
here imports a model or the optional extra — it is pure routing data.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .index import CodeChunk, chunk_text_namespace
from .preprocess import FileTarget

# Pipeline stages a skill can apply to.
STAGES = ("map", "hunt", "verify", "fix")

# FileTarget tags → vulnerability classes the router reasons over.
TAG_TO_VULN = {
    "memory_unsafe": "memory-safety",
    "parser": "parsing",
    "fuzzable": "parsing",
    "crypto": "crypto",
    "deserialization": "deserialization",
    "auth_boundary": "access-control",
    "network_entry": "access-control",
    "privileged": "access-control",
}


@dataclass(frozen=True)
class SkillDescriptor:
    id: str
    title: str
    summary: str
    checklist: str
    languages: tuple[str, ...] = ()  # empty => language-agnostic
    tags: tuple[str, ...] = ()
    vulnerability_classes: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()  # empty => any stage

    def descriptor(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "languages": list(self.languages),
            "tags": list(self.tags),
            "vulnerability_classes": list(self.vulnerability_classes),
            "stages": list(self.stages),
        }


# Curated inventory aligned with the spec's Trail of Bits skill routing examples.
SKILL_INVENTORY: tuple[SkillDescriptor, ...] = (
    SkillDescriptor(
        "c-review",
        "C/C++ security review",
        "Manual review discipline for memory-unsafe code.",
        "Audit buffer indexing, object lifetime, integer overflow before length math, and unchecked copies.",
        languages=("c", "cpp", "c++"),
        tags=("memory_unsafe",),
        vulnerability_classes=("memory-safety",),
        stages=("map", "hunt"),
    ),
    SkillDescriptor(
        "address-sanitizer",
        "AddressSanitizer",
        "Detect memory-safety violations at runtime.",
        "Build with -fsanitize=address; reproduce the overflow/UAF; capture the ASan trace as crash evidence.",
        languages=("c", "cpp", "c++"),
        tags=("memory_unsafe",),
        vulnerability_classes=("memory-safety",),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "libfuzzer",
        "libFuzzer harnessing",
        "In-process coverage-guided fuzzing of C/C++ entries.",
        "Write a LLVMFuzzerTestOneInput harness over the parser entry; minimize crashing inputs.",
        languages=("c", "cpp", "c++"),
        tags=("memory_unsafe", "fuzzable", "parser"),
        vulnerability_classes=("memory-safety", "parsing"),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "harness-writing",
        "Fuzz harness writing",
        "Build deterministic harnesses around attacker-controlled entries.",
        "Identify the smallest attacker-controlled entry; build a deterministic harness; seed a corpus.",
        languages=("c", "cpp", "c++"),
        tags=("memory_unsafe", "fuzzable", "parser"),
        vulnerability_classes=("memory-safety", "parsing"),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "fuzzing-dictionary",
        "Fuzzing dictionary",
        "Reach deep parser states with a format dictionary.",
        "Extract format tokens/magic bytes into a fuzzing dictionary to reach deep parser states.",
        tags=("parser", "fuzzable"),
        vulnerability_classes=("parsing",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "fuzzing-obstacles",
        "Fuzzing obstacles",
        "Remove coverage barriers that block the fuzzer.",
        "Remove checksums/magic gates that block coverage; document each bypass.",
        tags=("parser", "fuzzable"),
        vulnerability_classes=("parsing",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "atheris",
        "Atheris (Python fuzzing)",
        "Coverage-guided fuzzing for Python parsers.",
        "Fuzz the Python parser entry with Atheris; assert on uncaught exceptions and resource blowups.",
        languages=("python",),
        tags=("parser", "fuzzable"),
        vulnerability_classes=("parsing",),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "property-based-testing",
        "Property-based testing",
        "Encode parser invariants as properties.",
        "Encode parser invariants as Hypothesis properties; shrink counterexamples.",
        languages=("python",),
        tags=("parser",),
        vulnerability_classes=("parsing",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "constant-time-analysis",
        "Constant-time analysis",
        "Find secret-dependent timing in crypto code.",
        "Find secret-dependent branches/indexing/early-exit comparisons; require constant-time primitives.",
        tags=("crypto",),
        vulnerability_classes=("crypto",),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "wycheproof",
        "Wycheproof vectors",
        "Stress crypto usage with known-edge test vectors.",
        "Run Wycheproof test vectors against the crypto usage; flag edge-case acceptance.",
        tags=("crypto",),
        vulnerability_classes=("crypto",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "vector-forge",
        "Crypto vector forging",
        "Forge boundary vectors to probe crypto APIs.",
        "Forge boundary test vectors (zero/identity/malleable signatures) to probe the crypto API.",
        tags=("crypto",),
        vulnerability_classes=("crypto",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "zeroize-audit",
        "Secret zeroization audit",
        "Verify secrets are wiped after use.",
        "Verify secrets are zeroized on drop; check for lingering copies.",
        languages=("rust",),
        tags=("crypto",),
        vulnerability_classes=("crypto",),
        stages=("verify",),
    ),
    SkillDescriptor(
        "cargo-fuzz",
        "cargo-fuzz",
        "Coverage-guided fuzzing for Rust entries.",
        "Add a cargo-fuzz target over the entry; run under ASan.",
        languages=("rust",),
        tags=("fuzzable", "parser"),
        vulnerability_classes=("memory-safety", "parsing"),
        stages=("hunt", "verify"),
    ),
    SkillDescriptor(
        "sarif-parsing",
        "SARIF parsing",
        "Normalize external tool output into the map.",
        "Normalize SARIF locations/rules/fingerprints into FileTarget static hints.",
        vulnerability_classes=(),
        stages=("map",),
    ),
    SkillDescriptor(
        "semgrep",
        "Semgrep mapping",
        "Pattern sinks and iterate variants.",
        "Pattern the sink shape; iterate variants; export normalized findings.",
        vulnerability_classes=("injection", "deserialization"),
        stages=("map",),
    ),
    SkillDescriptor(
        "semgrep-rule-creator",
        "Semgrep rule creator",
        "Author a Semgrep rule for a sink.",
        "Author a Semgrep rule for the sink; validate against the fixture.",
        tags=("deserialization",),
        vulnerability_classes=("injection", "deserialization"),
        stages=("map",),
    ),
    SkillDescriptor(
        "semgrep-rule-variant-creator",
        "Semgrep variant creator",
        "Widen sink coverage with variants.",
        "Generate sink variants (aliases, wrappers) to widen coverage without false positives.",
        vulnerability_classes=("injection",),
        stages=("map",),
    ),
    SkillDescriptor(
        "codeql",
        "CodeQL dataflow",
        "Model source→sink taint paths.",
        "Model source→sink taint with a CodeQL query; inspect the dataflow path.",
        vulnerability_classes=("injection",),
        stages=("map",),
    ),
    SkillDescriptor(
        "differential-review",
        "Differential review",
        "Scope the changed attack surface in a diff.",
        "Scope the changed attack surface and new trust-boundary crossings in the diff.",
        stages=("map", "fix"),
    ),
    SkillDescriptor(
        "graph-evolution",
        "Graph evolution",
        "Bound a patch's blast radius.",
        "Trace how the call/dataflow graph changed; bound the patch blast radius.",
        stages=("fix",),
    ),
    SkillDescriptor(
        "sharp-edges",
        "Sharp edges review",
        "Map misuse-prone APIs at the boundary.",
        "Map misuse-prone APIs, insecure defaults, and confusing configuration at the boundary.",
        tags=("auth_boundary", "network_entry"),
        vulnerability_classes=("access-control", "api-misuse"),
        stages=("map", "hunt"),
    ),
    SkillDescriptor(
        "insecure-defaults",
        "Insecure defaults review",
        "Flag unsafe defaults exposed at entries.",
        "Flag unsafe default flags/permissions/timeouts exposed at the entry.",
        tags=("auth_boundary", "network_entry"),
        vulnerability_classes=("access-control", "api-misuse"),
        stages=("map", "hunt"),
    ),
)

_BY_ID = {skill.id: skill for skill in SKILL_INVENTORY}


@dataclass(frozen=True)
class SkillMatch:
    skill: SkillDescriptor
    score: int
    reasons: list[str] = field(default_factory=list)


def route_skills(
    *,
    language: str | None = None,
    tags: tuple[str, ...] = (),
    vulnerability_classes: tuple[str, ...] = (),
    stage: str | None = None,
    max_snippets: int = 4,
) -> list[SkillDescriptor]:
    """Select the most relevant skills for the given routing signals.

    A skill is excluded when its language list is non-empty and ``language`` is not in
    it, or its stage list is non-empty and ``stage`` is not in it. Eligibility requires
    at least one topical signal (tag/vulnerability-class/stage) — a pure language match
    never selects a skill. Ranked by score, then id, for determinism.
    """
    tag_set, vuln_set = set(tags), set(vulnerability_classes)
    matches: list[SkillMatch] = []
    for skill in SKILL_INVENTORY:
        if skill.languages and language is not None and language not in skill.languages:
            continue
        if skill.stages and stage is not None and stage not in skill.stages:
            continue
        signal = 2 * len(vuln_set & set(skill.vulnerability_classes)) + len(tag_set & set(skill.tags))
        if stage is not None and stage in skill.stages:
            signal += 1
        if signal == 0:
            continue  # no topical match — do not select on language alone
        rank = signal + (3 if skill.languages and language in skill.languages else 0)
        matches.append(SkillMatch(skill=skill, score=rank))
    matches.sort(key=lambda match: (-match.score, match.skill.id))
    return [match.skill for match in matches[:max_snippets]]


def _vuln_classes_for_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({TAG_TO_VULN[tag] for tag in tags if tag in TAG_TO_VULN}))


def route_skills_for_target(target: FileTarget, *, stage: str | None = None, max_snippets: int = 4) -> list[SkillDescriptor]:
    """Route skills for a scan target (language + tags + derived vulnerability classes)."""
    tags = tuple(target.tags)
    return route_skills(
        language=target.language,
        tags=tags,
        vulnerability_classes=_vuln_classes_for_tags(tags),
        stage=stage,
        max_snippets=max_snippets,
    )


def route_skill_ids(target: FileTarget, *, stage: str | None = None, max_snippets: int = 4) -> list[str]:
    return [skill.id for skill in route_skills_for_target(target, stage=stage, max_snippets=max_snippets)]


def select_skill_context(target: FileTarget, *, stage: str | None = None, budget_chars: int, max_snippets: int = 4) -> str:
    """Pack routed skill checklists into a prompt context capped at ``budget_chars``."""
    if budget_chars <= 0:
        return ""
    parts: list[str] = []
    used = 0
    for skill in route_skills_for_target(target, stage=stage, max_snippets=max_snippets):
        snippet = f"### {skill.title}\n{skill.checklist}"
        if not parts and len(snippet) > budget_chars:
            return snippet[:budget_chars]  # first snippet alone exceeds the cap → truncate
        if used + len(snippet) + (1 if parts else 0) > budget_chars:
            break
        used += len(snippet) + (1 if parts else 0)
        parts.append(snippet)
    return "\n".join(parts)


def skill_chunks(skills: tuple[SkillDescriptor, ...] | None = None, *, max_lines: int = 40) -> list[CodeChunk]:
    """Chunk skill operating guidance into the ``skills`` retrieval namespace."""
    chunks: list[CodeChunk] = []
    for skill in skills or SKILL_INVENTORY:
        text = f"# {skill.title}\n{skill.summary}\n\nChecklist:\n{skill.checklist}"
        chunks.extend(
            chunk_text_namespace(
                namespace="skills",
                path=f"skills/{skill.id}.md",
                text=text,
                metadata={
                    "skill_id": skill.id,
                    "languages": ",".join(skill.languages),
                    "tags": ",".join(skill.tags),
                    "vulnerability_classes": ",".join(skill.vulnerability_classes),
                    "stages": ",".join(skill.stages),
                },
                max_lines=max_lines,
            )
        )
    return chunks


__all__ = [
    "SKILL_INVENTORY",
    "STAGES",
    "TAG_TO_VULN",
    "SkillDescriptor",
    "route_skill_ids",
    "route_skills",
    "route_skills_for_target",
    "select_skill_context",
    "skill_chunks",
]
