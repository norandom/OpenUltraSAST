"""Labels from ground truth, with provenance (learned-decision-engine Req 2, 7.1; design section 3).

Host only, never in a sandbox: ``ousast learn labels``. The sources are an allow-list, **fail-closed**
(``sources.toml``): the builder reads a file only through :class:`SourceGuard`, which refuses any path the list does
not name and every ``[[excluded]]`` file name *before* opening it -- population v3 is excluded unread.

Rules per source (design section 3):

- *Populations* (v1, v2): positive -- a declared site (v2) or a function the fix changed on the vulnerable side
  (v1, which declares no sites); negative -- the same function on the fixed pin when the fix changed it (a function
  the fix did not touch is the same code at both pins and is not a negative). Delta units: fixed..vulnerable
  introduces (positive), vulnerable..fixed repairs (negative). The benign base..tip functions are negative by
  protocol assumption, **conditional** on a candidate there having a signal at the tip and none at the base
  (``benign_control``). A vulnerable-pin candidate matching no site is unlabelled, never negative.
- *Pairs*: the labelled function on the vulnerable side (positive) and on the fixed side (negative); unscorable
  pairs and the ``title`` tier are excluded (the tier is a sensitivity arm, ``--include-title``). The negative is
  emitted only where the fixed side's source declares the function (the excerpt builder's matcher) or a
  deterministic rename at a distinct fix commit replaces it (``provenance = fixed_side_moved``); a fixed side that
  holds another function of the same snapshot (a guard helper, a sibling handler) gives no negative and is counted
  as ``absent_fixed_side``.
- *Recipes* (dev-php): the reviewed ``[[known]]`` function at the recipe commit (positive).
- *Adjudications*: recorded ``True``/``TP`` verdicts positive (``privileged`` kept), ``False``/``FP`` negative, with
  the recorded reason as evidence.
- *Assumed benign* (maintainer decision 2026-09-30): ordinary non-security commits of the training repositories,
  at least 90 days from any fix, with no later security commit touching the same files. Their own source
  (``assumed_benign``, weight 0.5), conditional like ``benign_control``, reported separately, never merged with the
  verified negatives. The security filter is multilingual (:func:`security_reason`).

A plane verdict (agreed/rejected/disputed) is never a label (Req 2.2). Every row carries its source, reference, split,
creation date and ``group``: the normalised ``owner/name`` repository, merged across URLs and forks by shared advisory
ids (CVE/GHSA), shared fix commits and ``[[alias]]`` rows, so a repository cannot straddle folds (Req 7.1).
"""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

from ..model.taxonomy import load_families
from ..plane.tasks.repo_facts import _EXCLUDED_DIRS, _NOT_PRODUCT, DECLARATION, GLOBAL, _declared_name, declared_functions, enclosing
from ..preprocess import detect_language
from ..ruleset.frameworks import load_frameworks

DEFAULT_SOURCES = Path(__file__).resolve().parent / "sources.toml"
DEFAULT_CACHE = Path.home() / ".cache" / "openultrasast"
KINDS = ("population", "pairs", "recipes", "adjudications", "history")
ANY_FAMILY = "*"  # a benign push is negative for whatever family a candidate there has
CONDITIONAL = "signal_at_tip_not_base"
PER_FAMILY_FLOOR = 20  # positive and negative repository groups for a per-family model (design section 4)
POOLED_FLOOR = 10
MANIFESTS = (
    "composer.json", "package.json", "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "pom.xml",
    "build.gradle", "build.gradle.kts",
)  # fmt: skip
_ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{3,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b", re.IGNORECASE)
_SITE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):?(?P<function>.*)$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
DAY = 86_400


class LabelSourceError(RuntimeError):
    """A source outside ``sources.toml``, an excluded file, a missing evaluation record or an unreadable cache."""


# --- the source list and its guard -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    id: str
    kind: str
    files: tuple[str, ...]
    evaluation: tuple[str, ...]
    recorded: str
    status: str
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Sources:
    sources: tuple[Source, ...]
    excluded: frozenset[str]
    aliases: Mapping[str, str]
    path: Path

    def get(self, source_id: str) -> Source:
        for source in self.sources:
            if source.id == source_id:
                return source
        raise LabelSourceError(f"{source_id!r} is not a label source in {self.path}: it cannot label")


def load_sources(path: Path = DEFAULT_SOURCES) -> Sources:
    """``sources.toml``, checked: known kinds, unique ids, and no source naming an excluded file."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    excluded = frozenset(str(row["file"]) for row in data.get("excluded", []))
    sources: list[Source] = []
    for row in data.get("source", []):
        if row.get("kind") not in KINDS:
            raise LabelSourceError(f"{path}: source {row.get('id')!r} has kind {row.get('kind')!r}, not one of {KINDS}")
        files = tuple(str(f) for f in ([row["file"]] if "file" in row else row.get("files", [])))
        named = {Path(f.split("#", 1)[0]).name for f in files}
        if named & excluded:
            raise LabelSourceError(f"{path}: source {row['id']!r} names an excluded file {sorted(named & excluded)}")
        options = {k: v for k, v in row.items() if k not in ("id", "kind", "file", "files", "evaluation", "recorded", "status")}
        sources.append(
            Source(
                str(row["id"]), str(row["kind"]), files, tuple(row.get("evaluation", [])), str(row["recorded"]), str(row["status"]), options
            )
        )
    ids = [s.id for s in sources]
    if len(ids) != len(set(ids)):
        raise LabelSourceError(f"{path}: a source id is listed twice")
    aliases = {str(row["repo"]).lower(): str(row["group"]).lower() for row in data.get("alias", [])}
    return Sources(tuple(sources), excluded, aliases, Path(path))


class SourceGuard:
    """The only way the builder reads a label file: a path must be one a listed source names (or, for ``pairs``, lie
    under that catalog's directory), and its name must not be excluded. Refused before the file is opened."""

    def __init__(self, sources: Sources, root: Path) -> None:
        self.root = Path(root).resolve()
        self.excluded = sources.excluded
        self.files: set[Path] = set()
        self.trees: set[Path] = set()
        for source in sources.sources:
            for name in source.files:
                resolved = (self.root / name.split("#", 1)[0]).resolve()
                self.files.add(resolved)
                if source.kind == "pairs":
                    self.trees.add(resolved.parent)
        if any(source.kind == "pairs" for source in sources.sources):
            from ..pairs import pair_cache_dir

            self.trees.add(pair_cache_dir().resolve())  # pointer pairs: the catalog's sides, materialised outside the tree
        self.opened: list[Path] = []

    def check(self, path: Path) -> Path:
        resolved = (self.root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
        if resolved.name in self.excluded:
            raise LabelSourceError(f"{resolved.name} is excluded from labels (sources.toml [[excluded]]); it is never opened")
        if resolved not in self.files and not any(tree in resolved.parents for tree in self.trees):
            raise LabelSourceError(f"{path} is not a listed label source (sources.toml): refused unread")
        return resolved

    def text(self, path: Path | str) -> str:
        resolved = self.check(Path(path))
        self.opened.append(resolved)
        return resolved.read_text(encoding="utf-8")

    def json(self, path: Path | str) -> Any:
        return json.loads(self.text(path))

    def toml(self, path: Path | str) -> dict[str, Any]:
        return tomllib.loads(self.text(path))


# --- repository groups -----------------------------------------------------------------------------------------------


def repo_name(repo: str) -> str:
    """``owner/name`` of a repository URL or slug, lower-cased: scheme, host, user, ``.git`` and slashes dropped."""
    text = repo.strip().lower()
    text = re.sub(r"^[a-z+]+://", "", text)
    text = re.sub(r"^[^/@]+@([^:/]+)[:/]", r"\1/", text)
    text = text.removesuffix("/").removesuffix(".git").removesuffix("/")
    parts = [p for p in text.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else text


def advisories(*texts: str | Iterable[str] | None) -> set[str]:
    """CVE and GHSA ids named anywhere in ``texts`` (upper-cased)."""
    found: set[str] = set()
    for text in texts:
        values = [text] if isinstance(text, str) else list(text or ())
        for value in values:
            found |= {m.upper() for m in _ADVISORY.findall(str(value))}
    return found


class Groups:
    """Union-find over repository names: one group per repository, merged across names that share an advisory id or
    a fix commit (a fork carries its upstream's commits), or that an ``[[alias]]`` joins."""

    def __init__(self, aliases: Mapping[str, str] | None = None) -> None:
        self.parent: dict[str, str] = {}
        self.aliases = dict(aliases or {})
        self.merged: dict[str, int] = {"advisory": 0, "commit": 0, "alias": 0}
        self._by_key: dict[str, str] = {}

    def _find(self, name: str) -> str:
        self.parent.setdefault(name, name)
        while self.parent[name] != name:
            self.parent[name] = self.parent[self.parent[name]]
            name = self.parent[name]
        return name

    def _union(self, a: str, b: str, why: str) -> None:
        ra, rb = self._find(a), self._find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)
            self.merged[why] += 1

    def add(self, repo: str, *, advisory_ids: Iterable[str] = (), commits: Iterable[str] = ()) -> str:
        name = repo_name(repo) if repo else ""
        if not name:
            return ""
        self._find(name)
        if name in self.aliases:
            self._union(name, self.aliases[name], "alias")
        for key, why in [(f"adv:{a}", "advisory") for a in advisory_ids] + [
            (f"sha:{c.lower()}", "commit") for c in commits if len(c) >= 12
        ]:
            if key in self._by_key:
                self._union(name, self._by_key[key], why)
            else:
                self._by_key[key] = name
        return name

    def group(self, repo: str) -> str:
        return self._find(repo_name(repo)) if repo else ""

    def count(self) -> int:
        return len({self._find(n) for n in self.parent})


# --- the security filter ---------------------------------------------------------------------------------------------

# English stems (matched at a word start) and whole words; then other languages, matched as substrings after NFKC
# case-folding (CJK has no word boundaries). A commit naming any of these, or a CVE/GHSA/CWE reference, or a
# dependency bump (which may be a security update), is not an assumed-benign push.
ENGLISH_STEMS = (
    "secur", "vuln", "exploit", "attack", "malicious", "inject", "sanitiz", "sanitis", "escap", "unescap", "travers",
    "deserializ", "deserialis", "unserializ", "overflow", "underflow", "privileg", "permission", "unauthori",
    "unauthenti", "authoriz", "authoris", "authenticat", "bypass", "forger", "hijack", "spoof", "leak", "disclos",
    "exposure", "taint", "harden", "clickjack", "brute", "redos", "denial of service", "out of bounds", "out-of-bounds",
    "use after free", "use-after-free", "open redirect", "prototype pollution", "access control", "csrf", "xsrf", "ssrf",
    "sqli", "xss", "xxe", "idor", "insecure", "unsafe", "advisory", "hackerone", "huntr", "snyk", "cve", "cwe", "ghsa",
    # checks and secrets: a push that adds or loosens one is not assumed benign (found reading accepted pushes)
    "validat", "password", "passwd", "credential", "secret", "allowlist", "allow-list", "whitelist", "blacklist",
    "denylist", "deny-list", "guard", "reject", "restrict", "captcha", "encrypt", "decrypt", "certificat", "tls", "ssl",
    "sandbox", "safe", "protect", "mask",
)  # fmt: skip
ENGLISH_WORDS = ("rce", "lfi", "rfi", "dos", "oob", "csp", "cors", "nonce", "acl", "jwt", "crlf", "poc", "sec")
OTHER_LANGUAGES = (
    # Chinese
    "安全", "漏洞", "注入", "越权", "跨站", "提权", "绕过", "繞過", "鉴权", "鑒權", "权限", "權限", "未授权", "未授權", "越界",
    "溢出", "反序列化", "敏感", "泄露", "洩漏", "攻击", "攻擊", "转义", "轉義", "过滤", "過濾", "任意文件", "路径穿越",
    "目录遍历", "命令执行", "代码执行", "远程代码", "重定向", "伪造", "偽造", "劫持", "修复漏洞", "弱口令",
    "校验", "验证", "驗證", "密码", "密碼", "白名单", "黑名单", "限制", "加密",
    # Japanese
    "脆弱性", "セキュリティ", "攻撃", "インジェクション", "権限", "認証", "改ざん", "漏洩", "エスケープ", "サニタイズ", "検証",
    "パスワード",
    # Korean
    "보안", "취약점", "취약성", "인젝션", "권한", "인증", "우회", "공격", "유출", "이스케이프", "검증", "비밀번호",
    # Russian / Ukrainian
    "уязвим", "безопасн", "инъекц", "атак", "эксплойт", "обход", "привилег", "утечк", "санитиз", "экраниров", "валидац", "пароль",
    "вразлив", "безпек",
    # German, Dutch
    "sicherheit", "schwachstelle", "lücke", "angriff", "umgehung", "einschleus", "berechtigung", "beveilig", "kwetsba",
    "passwort", "validier",
    # French, Spanish, Portuguese, Italian, Romanian
    "sécurité", "securite", "vulnérab", "vulnerab", "faille", "attaque", "contournement", "seguridad", "segurança",
    "seguranca", "inyecci", "injeç", "injec", "ataque", "permiso", "permissõ", "sicurezza", "securitate",
    # Polish, Czech, Turkish, Vietnamese, Indonesian
    "bezpiecz", "podatno", "zranitel", "bezpečnost", "güvenlik", "zafiyet", "bảo mật", "lỗ hổng", "keamanan", "kerentanan",
    # Persian, Arabic, Hebrew, Hindi
    "امنیت", "آسیب", "أمان", "ثغرة", "حماية", "אבטח", "פגיע", "सुरक्षा", "भेद्यता",
)  # fmt: skip
_REFERENCE = re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA(?:-\w{4}){3}|CWE-\d+)\b", re.IGNORECASE)
_DEPENDENCY = re.compile(r"\b(?:bump|bumps|dependabot|renovate)\b|\bupgrade [\w@/.-]+ (?:from|to)\b", re.IGNORECASE)
_STEM = re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(s) for s in ENGLISH_STEMS) + ")")
_WORD = re.compile(r"(?<![a-z0-9])(?:" + "|".join(re.escape(w) for w in ENGLISH_WORDS) + r")(?![a-z0-9])")


def security_reason(message: str) -> str | None:
    """Why a commit message is security-relevant -- ``reference``, ``english``, ``other_language``, ``dependency`` --
    or ``None`` for an ordinary commit. Not English-only: a Chinese "修复越权" (fix IDOR) is caught with no English."""
    if _REFERENCE.search(message):
        return "reference"
    folded = unicodedata.normalize("NFKC", message).casefold()
    if _STEM.search(folded) or _WORD.search(folded):
        return "english"
    if any(term.casefold() in folded for term in OTHER_LANGUAGES):
        return "other_language"
    if _DEPENDENCY.search(message):
        return "dependency"
    return None


# --- labels ----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Label:
    """One label row (design, Data Models). ``candidate`` is ``path::function`` and, with ``repo``/``pin``, stays in
    the envelope; ``conditional`` names the signal a candidate needs for a conditional (benign) row to apply."""

    candidate: str
    family: str
    label: int
    source: str
    source_ref: str
    unit: str
    weight: float
    split: str
    group: str
    repo: str
    language: str
    created: str
    evidence: str = ""
    direction: str | None = None
    pin_role: str = "vulnerable"
    pin: str = ""
    frameworks: tuple[str, ...] | None = None
    conditional: str | None = None
    design_informed: bool = False
    privileged: bool = False
    provenance: str = ""  # how a negative was derived when it is not the labelled function itself (``fixed_side_moved``)


def _family_of(cwe: str | None, family: str | None) -> str:
    if family:
        return family
    found = load_families().family_of_cwe(cwe or "") if cwe else None
    return found.id if found is not None else "unknown"


def _language(path: str) -> str:
    return detect_language(Path(path)) or "other"


def _product(path: str) -> bool:
    parts = path.split("/")
    return not _NOT_PRODUCT.search(path) and not any(p in _EXCLUDED_DIRS or p.startswith(".") for p in parts[:-1])


def frameworks_from(manifests: Mapping[str, str], headers: Iterable[str] = ()) -> tuple[str, ...]:
    """The ``frameworks.toml`` ids a repository's dependency manifests name (``composer.json``, ``package.json``, ...),
    or whose markers a root file header carries (a WordPress plugin header). Stratification only, never a feature."""
    text = "\n".join(_dependency_text(name, body) for name, body in manifests.items())
    head = "\n".join(headers)
    found = []
    for framework in load_frameworks():
        names = {p for pkg in framework.packages for p in (pkg, pkg.rsplit(":", 1)[-1])}
        named = any(re.search(r"(?<![\w.\-/])" + re.escape(n) + r"(?![\w\-])", text, re.IGNORECASE) for n in names)
        if named or any(marker in head for marker in framework.markers):
            found.append(framework.id)
    return tuple(sorted(found))


def _dependency_text(name: str, body: str) -> str:
    """The dependency names of a manifest: a JSON manifest's dependency keys only (its description can say anything);
    any other manifest as text."""
    if not name.endswith(".json"):
        return body
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    keys = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "require", "require-dev")
    return "\n".join(str(k) for key in keys if isinstance(payload, dict) and isinstance(payload.get(key), dict) for k in payload[key])


class Clone:
    """Read-only git access to one case's clone (``git -C``); a failure is loud."""

    def __init__(self, path: Path) -> None:
        if not (path / ".git").exists() and not (path / "HEAD").exists():
            raise LabelSourceError(f"no clone at {path}")
        self.path = path
        self._shows: dict[tuple[str, str], list[str] | None] = {}

    def git(self, *args: str) -> str:
        done = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True, errors="replace")
        if done.returncode != 0:
            raise LabelSourceError(f"git {' '.join(args[:3])} failed in {self.path.name}: {done.stderr.strip()[:200]}")
        return done.stdout

    def lines(self, pin: str, path: str) -> list[str] | None:
        key = (pin, path)
        if key not in self._shows:
            done = subprocess.run(["git", "-C", str(self.path), "show", f"{pin}:{path}"], capture_output=True, text=True, errors="replace")
            self._shows[key] = done.stdout.splitlines() if done.returncode == 0 else None
        return self._shows[key]

    def ranges(self, base: str, tip: str) -> tuple[dict[str, list[tuple[int, int]]], dict[str, list[tuple[int, int]]]]:
        """(base-side, tip-side) changed line ranges per path of ``git diff -U0 base tip``."""
        return parse_diff(self.git("diff", "-U0", "--no-renames", base, tip))

    def frameworks(self, pin: str) -> tuple[str, ...]:
        root = self.git("ls-tree", "--name-only", pin).split()
        manifests = {name: "\n".join(self.lines(pin, name) or ()) for name in root if name in MANIFESTS}
        headers = ["\n".join((self.lines(pin, name) or [])[:30]) for name in root if name.endswith(".php")][:10]
        return frameworks_from(manifests, headers)

    def time(self, commit: str) -> int:
        return int(self.git("show", "-s", "--format=%ct", commit).strip())


def parse_diff(diff: str) -> tuple[dict[str, list[tuple[int, int]]], dict[str, list[tuple[int, int]]]]:
    old: dict[str, list[tuple[int, int]]] = {}
    new: dict[str, list[tuple[int, int]]] = {}
    old_path = new_path = ""
    for line in diff.splitlines():
        if line.startswith("--- "):
            old_path = line[6:] if line.startswith("--- a/") else ""
        elif line.startswith("+++ "):
            new_path = line[6:] if line.startswith("+++ b/") else ""
        elif match := _HUNK.match(line):
            o_start, o_len, n_start, n_len = (int(match.group(i)) if match.group(i) is not None else 1 for i in range(1, 5))
            if old_path and o_len:
                old.setdefault(old_path, []).append((o_start, o_start + o_len - 1))
            if new_path and n_len:
                new.setdefault(new_path, []).append((n_start, n_start + n_len - 1))
    return old, new


def changed_functions(clone: Clone, pin: str, ranges: Mapping[str, Sequence[tuple[int, int]]]) -> set[tuple[str, str]]:
    """``(path, function)`` enclosing a changed line at ``pin``, product source files of a declared language only."""
    out: set[tuple[str, str]] = set()
    for path, spans in ranges.items():
        language = detect_language(Path(path))
        if language not in DECLARATION or not _product(path):
            continue
        lines = clone.lines(pin, path)
        if not lines:
            continue
        for lo, hi in spans:
            for number in range(max(lo, 1), min(hi, len(lines)) + 1):
                out.add((path, enclosing(lines, number - 1, language)))
    return out


# --- the fixed side of a pair ----------------------------------------------------------------------------------------

FIXED_DECLARED = "declared"
FIXED_MOVED = "fixed_side_moved"
ABSENT_UNREAD = "fixed side unread"
ABSENT_UNMATCHED = "fixed side does not declare the function"
ABSENT_SAME_SNAPSHOT = "fixed side is another function of the same snapshot"
ABSENT_NO_EQUIVALENT = "fixed side does not declare the function, no renamed equivalent"
_HEADER = re.compile(r"^\s*(?:#|//|/\*|\*)")  # comment lines: the excerpt header names the labelled function
_PIN_LINE = re.compile(r"^\W*(commit|parent):\s*([0-9a-f]{7,40})\b", re.IGNORECASE)


@dataclass(frozen=True)
class FixedSide:
    verdict: str
    function: str = ""


def _fix_commits(case: Any, fixed_lines: Sequence[str]) -> tuple[str, str] | None:
    """``(vulnerable, fix)`` commits of a pair: the recipe's ``parent``/``commit`` (pointer pairs) or the excerpt
    header's; ``None`` when either is unrecorded (a fix that cannot be told apart from its snapshot)."""
    recorded = dict(getattr(case, "recipe", ()) or ())
    header = {m.group(1).lower(): m.group(2) for line in fixed_lines[:20] if (m := _PIN_LINE.match(line))}
    parent = str(recorded.get("parent") or header.get("parent") or "")
    commit = str(getattr(case, "commit", "") or recorded.get("commit") or header.get("commit") or "")
    return (parent.lower(), commit.lower()) if parent and commit else None


def _signature(lines: Sequence[str], start: int, function: str) -> str | None:
    """The parameter list after ``function`` on its declaration (up to 5 lines), whitespace-normalised."""
    text = "\n".join(lines[start : start + 5])
    at = re.search(rf"(?<![\w$]){re.escape(function)}\s*\(", text)
    if at is None:
        return None
    depth, out = 0, []
    for char in text[at.end() - 1 :]:
        depth += char == "("
        depth -= char == ")"
        out.append(char)
        if depth == 0:
            return re.sub(r"\s+", " ", "".join(out))
    return None


@dataclass
class Build:
    """The rows of one build and what it could not label (reported, never silent)."""

    labels: list[Label] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    history: dict[str, Any] = field(default_factory=dict)
    absent_fixed_side: dict[str, int] = field(default_factory=dict)  # family -> pair labels with no fixed-side negative

    def skip(self, reason: str, n: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + n


class LabelBuilder:
    def __init__(
        self,
        sources: Sources,
        root: Path,
        *,
        cache: Path = DEFAULT_CACHE,
        created: str | None = None,
        include_title: bool = False,
        assumed_benign: bool = True,
    ) -> None:
        self.sources = sources
        self.guard = SourceGuard(sources, root)
        self.root = Path(root)
        self.cache = Path(cache)
        self.created = created or date.today().isoformat()
        self.include_title = include_title
        self.assumed_benign = assumed_benign
        self.groups = Groups(sources.aliases)
        self.build = Build()
        self._cases: dict[str, tuple[Source, dict[str, Any]]] = {}

    # -- entry --------------------------------------------------------------------------------------------------------

    def run(self) -> Build:
        for source in self.sources.sources:
            missing = [e for e in source.evaluation if not (self.root / e).is_file()]
            if missing:
                raise LabelSourceError(f"source {source.id}: its evaluation record is not recorded ({missing}); it cannot label")
        for source in self.sources.sources:
            if source.kind == "population":
                self._population(source)
        for source in self.sources.sources:
            if source.kind == "pairs":
                self._pairs(source)
            elif source.kind == "recipes":
                self._recipes(source)
            elif source.kind == "adjudications":
                self._adjudications(source)
            elif source.kind == "history" and self.assumed_benign:
                self._history(source)
        self.build.labels = [replace(label, group=self.groups.group(label.repo) or label.group) for label in self.build.labels]
        return self.build

    def _row(self, **kw: Any) -> None:
        self.build.labels.append(Label(created=self.created, **kw))

    # -- populations --------------------------------------------------------------------------------------------------

    def _clone(self, source: Source, case_id: str) -> Clone:
        return Clone(self.cache / str(source.options.get("cache", "independent")) / case_id)

    def _population(self, source: Source) -> None:
        data = self.guard.toml(source.files[0])
        design_informed = bool(source.options.get("design_informed"))
        for case in data.get("case", []):
            self._cases[str(case["id"])] = (source, case)
            self.groups.add(case["repo"], advisory_ids=advisories(case.get("advisory")), commits=(case["fixed"],))
        for case in data.get("case", []):
            clone = self._clone(source, str(case["id"]))
            vulnerable, fixed = str(case["vulnerable"]), str(case["fixed"])
            old, new = clone.ranges(vulnerable, fixed)
            if source.options.get("matching") == "declared_sites":
                positives = {(site.partition("::")[0], site.partition("::")[2]) for site in case.get("sites", []) if "::" in site}
            else:
                positives = changed_functions(clone, vulnerable, old)
            fixed_changed = changed_functions(clone, fixed, new)
            frameworks = clone.frameworks(vulnerable)
            common = {
                "source": source.id, "source_ref": str(case["id"]), "split": source.id, "group": repo_name(case["repo"]),
                "repo": str(case["repo"]), "frameworks": frameworks, "design_informed": design_informed,
            }  # fmt: skip
            family = str(case["family"])
            if not positives:
                self.build.skip(f"population: case with no {source.options.get('matching')} positive")
            for path, function in sorted(positives):
                language = _language(path)
                evidence = "declared site" if source.options.get("matching") == "declared_sites" else "fix range (vulnerable side)"
                self._row(
                    candidate=f"{path}::{function}",
                    family=family,
                    label=1,
                    unit="pin",
                    weight=1.0,
                    language=language,
                    evidence=evidence,
                    pin=vulnerable,
                    **common,
                )
                self._row(
                    candidate=f"{path}::{function}", family=family, label=1, unit="delta", weight=1.0, language=language, evidence=evidence,
                    direction="introduce", pin=vulnerable, **common,
                )  # fmt: skip
                if (path, function) in fixed_changed:
                    for unit, direction in (("pin", None), ("delta", "repair")):
                        self._row(
                            candidate=f"{path}::{function}", family=family, label=0, unit=unit, weight=1.0, language=language,
                            evidence="the fix changed this function", direction=direction, pin_role="fixed", pin=fixed, **common,
                        )  # fmt: skip
                else:
                    self.build.skip("population: positive the fix did not change (no negative)")
            benign = case.get("benign") or {}
            if benign.get("base") and benign.get("tip"):
                _, tip_side = clone.ranges(str(benign["base"]), str(benign["tip"]))
                for path, function in sorted(changed_functions(clone, str(benign["tip"]), tip_side)):
                    self._row(
                        candidate=f"{path}::{function}", family=ANY_FAMILY, label=0, unit="delta", weight=1.0, language=_language(path),
                        evidence="benign control push (protocol assumption)", direction="benign", pin_role="benign", pin=str(benign["tip"]),
                        conditional=CONDITIONAL, **{**common, "source": "benign_control"},
                    )  # fmt: skip

    # -- pairs --------------------------------------------------------------------------------------------------------

    def _pairs(self, source: Source) -> None:
        from ..pairs import load_pair_catalog

        catalog = self.guard.check(Path(source.files[0]))
        excluded_tiers = set() if self.include_title else set(source.options.get("exclude_tiers", []))
        for case in load_pair_catalog(catalog):
            repo = case.repo or f"{case.slice}:{case.name}"
            if case.repo:
                self.groups.add(case.repo, advisory_ids=advisories(case.cve, case.name), commits=(case.commit,))
            if case.unscorable:
                self.build.skip("pairs: unscorable pair")
                continue
            if case.review_tier in excluded_tiers:
                self.build.skip(f"pairs: {case.review_tier} tier (sensitivity arm)")
                continue
            for expected in case.expected:
                if not expected.function:
                    self.build.skip("pairs: label names no function")
                    continue
                path = expected.path or case.relpath
                common = {
                    "candidate": f"{path}::{expected.function}", "family": _family_of(expected.cwe, expected.family), "source": "pairs",
                    "source_ref": case.name, "weight": 1.0, "split": case.split, "group": repo_name(repo) if case.repo else repo,
                    "repo": case.repo or repo, "language": case.language, "evidence": f"{case.review_tier} tier, {case.provenance}",
                }  # fmt: skip
                self._row(label=1, unit="pin", **common)
                self._row(label=1, unit="delta", direction="introduce", **common)
                fixed = self._fixed_side(case, expected.function)
                if fixed.verdict == FIXED_DECLARED:
                    self._row(label=0, unit="pin", pin_role="fixed", **common)
                    self._row(label=0, unit="delta", direction="repair", pin_role="fixed", **common)
                elif fixed.verdict == FIXED_MOVED:
                    rename = f"{FIXED_MOVED}: {expected.function} -> {fixed.function} (same file, same signature, body changed)"
                    moved = {
                        **common, "candidate": f"{path}::{fixed.function}", "provenance": FIXED_MOVED,
                        "evidence": f"{common['evidence']}; {rename}",
                    }  # fmt: skip
                    self._row(label=0, unit="pin", pin_role="fixed", **moved)
                    self._row(label=0, unit="delta", direction="repair", pin_role="fixed", **moved)
                else:
                    family = str(common["family"])
                    self.build.absent_fixed_side[family] = self.build.absent_fixed_side.get(family, 0) + 1
                    self.build.skip(f"pairs: no fixed-side negative ({fixed.verdict})")

    def _pair_lines(self, file: Path) -> list[str] | None:
        """A pair side's lines through the guard (catalog excerpts, or pointer files in the pair cache); ``None`` unread."""
        try:
            return self.guard.text(file).splitlines() if Path(file).is_file() else None
        except (OSError, UnicodeDecodeError):
            return None

    def _fixed_side(self, case: Any, function: str) -> FixedSide:
        """Whether the fixed side gives a defensible negative for ``function`` (Req 2.1: the same function at the fix).

        Verified from the fixed side's source with the excerpt builder's own matcher: the fixed side must declare the
        labelled function. Where it does not, the only other negative accepted is a deterministic rename at a real
        fix (a fix commit distinct from the vulnerable one): exactly one function the fixed side declares that the
        vulnerable side does not, with the labelled function's parameter list and a changed body (``fixed_side_moved``).
        A different function of the same snapshot (a guard helper, a sibling handler) is never a negative."""
        from .excerpt import LANGUAGE_ALIASES, function_bounds

        fixed_lines, vuln_lines = self._pair_lines(case.fixed_file), self._pair_lines(case.vuln_file)
        if not fixed_lines:
            return FixedSide(ABSENT_UNREAD)
        language = LANGUAGE_ALIASES.get(case.language, case.language)
        if function_bounds(fixed_lines, language, function):
            return FixedSide(FIXED_DECLARED)
        vuln_span = function_bounds(vuln_lines or (), language, function)
        if vuln_span is None:
            # the matcher resolves the function on neither side: its limit, not evidence of absence. The fixed side
            # still declares it when its name is on a code line (the excerpt header names it in a comment).
            named = re.compile(rf"(?<![\w$]){re.escape(function)}(?![\w$])")
            code = [line for line in fixed_lines if not _HEADER.match(line)]
            return FixedSide(FIXED_DECLARED if any(named.search(line) for line in code) else ABSENT_UNMATCHED)
        commits = _fix_commits(case, fixed_lines)
        if commits is not None and commits[0] == commits[1]:
            return FixedSide(ABSENT_SAME_SNAPSHOT)
        pattern = DECLARATION.get(language)
        if pattern is None or vuln_lines is None or commits is None:
            return FixedSide(ABSENT_NO_EQUIVALENT)
        vulnerable_names = set(declared_functions(vuln_lines, language))
        fixed_names = [name for name in (_declared_name(pattern, line) for line in fixed_lines) if name]
        signature = _signature(vuln_lines, vuln_span[0], function)
        body = "\n".join(vuln_lines[slice(*vuln_span)][1:]).strip()
        moved = []
        for name in dict.fromkeys(fixed_names):
            span = function_bounds(fixed_lines, language, name)
            if name in vulnerable_names or fixed_names.count(name) != 1 or span is None or signature is None:
                continue
            if _signature(fixed_lines, span[0], name) == signature and "\n".join(fixed_lines[slice(*span)][1:]).strip() != body:
                moved.append(name)
        return FixedSide(FIXED_MOVED, moved[0]) if len(moved) == 1 else FixedSide(ABSENT_NO_EQUIVALENT)

    # -- development recipes ------------------------------------------------------------------------------------------

    def _recipes(self, source: Source) -> None:
        for name in source.files:
            recipe = self.guard.toml(name)
            url, commit = str(recipe.get("url", "")), str(recipe.get("commit", ""))
            self.groups.add(url, advisory_ids=advisories([k.get("id", "") for k in recipe.get("known", [])]))
            checkout = self.cache / str(source.options.get("checkouts", "repos")) / str(recipe.get("name", "")) / commit[:12]
            frameworks: tuple[str, ...] | None = None
            if checkout.is_dir():
                manifests = {m: (checkout / m).read_text(errors="replace") for m in MANIFESTS if (checkout / m).is_file()}
                headers = [p.read_text(errors="replace")[:3000] for p in sorted(checkout.glob("*.php"))[:10]]
                frameworks = frameworks_from(manifests, headers)
            for known in recipe.get("known", []):
                if not known.get("in_scope", True) or not known.get("function") or not known.get("file"):
                    self.build.skip("recipes: known entry without an in-scope function")
                    continue
                self._row(
                    candidate=f"{known['file']}::{known['function']}", family=str(known.get("family", "unknown")), label=1,
                    source=source.id,
                    source_ref=f"{recipe.get('name')}:{known.get('id', '')}", unit="pin", weight=1.0, split=source.id, group=repo_name(url),
                    repo=url, language=_language(str(known["file"])), evidence="reviewed known vulnerability", pin=commit,
                    frameworks=frameworks,
                )  # fmt: skip

    # -- adjudications ------------------------------------------------------------------------------------------------

    def _adjudications(self, source: Source) -> None:
        for name in source.files:
            path, _, key = name.partition("#")
            for index, row in enumerate(self.guard.json(path).get(key) or []):
                verdict = str(row.get("verdict") or "")
                label = 1 if verdict.startswith(("True", "TP")) else 0 if verdict.startswith(("False", "FP")) else None
                found = self._cases.get(str(row.get("case")))
                match = _SITE.match(str(row.get("site") or ""))
                if label is None or found is None or match is None:
                    self.build.skip("adjudications: verdict, case or site unreadable")
                    continue
                population, case = found
                site_path, line, function = match.group("path"), int(match.group("line")), match.group("function").strip()
                if not function:
                    lines = self._clone(population, str(case["id"])).lines(str(case["vulnerable"]), site_path)
                    language = detect_language(Path(site_path))
                    function = enclosing(lines, line - 1, language) if lines and language in DECLARATION and line <= len(lines) else GLOBAL
                self._row(
                    candidate=f"{site_path}::{function}", family=str(row.get("family") or case["family"]), label=label, source=source.id,
                    source_ref=f"{Path(path).name}#{key}[{index}]", unit="pin", weight=1.0, split=population.id,
                    group=repo_name(case["repo"]),
                    repo=str(case["repo"]), language=_language(site_path), pin=str(case["vulnerable"]),
                    evidence=f"recorded review: {verdict}: {str(row.get('reason') or '')[:300]}", privileged="privileged" in verdict,
                    design_informed=bool(population.options.get("design_informed")),
                )  # fmt: skip

    # -- assumed-benign history ---------------------------------------------------------------------------------------

    def _history(self, source: Source) -> None:
        opts = source.options
        wanted = set(opts.get("repositories_from", []))
        by_group: dict[str, list[tuple[Source, dict[str, Any]]]] = {}
        for population, case in self._cases.values():
            if population.id in wanted:
                by_group.setdefault(repo_name(case["repo"]), []).append((population, case))
        stats: dict[str, Any] = {"repositories": 0, "commits_scanned": 0, "accepted": 0, "rejected": {}}
        for group, members in sorted(by_group.items()):
            members.sort(key=lambda m: str(m[1]["id"]))
            population, case = members[0]
            clone = self._clone(population, str(case["id"]))
            pins = {str(c[k]) for _, c in members for k in ("vulnerable", "fixed")} | {
                str((c.get("benign") or {}).get(k)) for _, c in members for k in ("base", "tip") if (c.get("benign") or {}).get(k)
            }
            fixes = [clone.time(str(c["fixed"])) for _, c in members]
            fix_files = set().union(*(set(clone.ranges(str(c["vulnerable"]), str(c["fixed"]))[1]) for _, c in members))
            log = clone.git(
                "log", "--no-merges", "--no-renames", "--name-only", f"-n{int(opts.get('scan_commits', 1500))}",
                "--format=%x1e%H%x1f%ct%x1f%B%x1d", str(case["fixed"]),
            )  # fmt: skip
            commits: list[tuple[str, int, str, set[str]]] = []
            for record in log.split("\x1e"):
                head, _, names = record.partition("\x1d")
                parts = head.split("\x1f", 2)
                if len(parts) == 3:
                    commits.append((parts[0].strip(), int(parts[1]), parts[2], {n for n in names.split("\n") if n.strip()}))
            stats["repositories"] += 1
            frameworks = clone.frameworks(str(case["vulnerable"]))
            flagged_files: list[tuple[int, set[str]]] = [(t, fix_files) for t in fixes]
            ordinary: list[tuple[str, int, set[str]]] = []
            for sha, when, message, touched in commits:
                stats["commits_scanned"] += 1
                reason = "protocol pin" if sha in pins else security_reason(message)
                if reason in ("reference", "english", "other_language", "dependency"):
                    flagged_files.append((when, touched))
                if reason is not None:
                    stats["rejected"][reason] = stats["rejected"].get(reason, 0) + 1
                    continue
                if any(abs(when - fix) < int(opts.get("min_days_from_fix", 90)) * DAY for fix in fixes):
                    stats["rejected"]["near_fix"] = stats["rejected"].get("near_fix", 0) + 1
                    continue
                ordinary.append((sha, when, touched))
            accepted = 0
            for sha, when, touched in ordinary:
                if accepted >= int(opts.get("max_commits_per_repository", 40)):
                    break
                files = {p for p in touched if detect_language(Path(p)) in DECLARATION and _product(p)}
                later = {name for t, f in flagged_files if t > when for name in f}
                if not files or len(touched) > int(opts.get("max_files_per_commit", 20)) or files & later:
                    why = (
                        "no product source"
                        if not files
                        else "bulk change"
                        if len(touched) > int(opts.get("max_files_per_commit", 20))
                        else "later fix touches its files"
                    )
                    stats["rejected"][why] = stats["rejected"].get(why, 0) + 1
                    continue
                _, tip_side = parse_diff(clone.git("show", "--format=", "-U0", "--no-renames", sha))
                functions = changed_functions(clone, sha, {p: tip_side[p] for p in files if p in tip_side})
                if not functions:
                    stats["rejected"]["no changed function"] = stats["rejected"].get("no changed function", 0) + 1
                    continue
                accepted += 1
                for path, function in sorted(functions):
                    self._row(
                        candidate=f"{path}::{function}", family=ANY_FAMILY, label=0, source=source.id, source_ref=f"{group}@{sha[:12]}",
                        unit="delta", weight=float(opts.get("weight", 0.5)), split=source.id, group=group, repo=str(case["repo"]),
                        language=_language(path), evidence="ordinary commit, no security keyword, no later fix touching its files",
                        direction="benign_history", pin_role="benign", pin=sha, frameworks=frameworks, conditional=CONDITIONAL,
                    )  # fmt: skip
            stats["accepted"] += accepted
        stats["rejected"] = dict(sorted(stats["rejected"].items()))
        self.build.history = stats


class LabelIndex:
    """Verified labels by ``(candidate, family, unit, pin_role)``: a candidate with no row is **unlabelled** (a
    vulnerable-pin candidate matching no site is never a negative)."""

    def __init__(self, labels: Iterable[Label]) -> None:
        self._rows: dict[tuple[str, str, str, str], Label] = {}
        for row in verified(labels):
            self._rows.setdefault((row.candidate, row.family, row.unit, row.pin_role), row)

    def lookup(self, candidate: str, family: str, *, unit: str = "pin", pin_role: str = "vulnerable") -> Label | None:
        return self._rows.get((candidate, family, unit, pin_role))


# --- the snapshot: counts only ---------------------------------------------------------------------------------------


def _tally(rows: Iterable[Label], key: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        for value in key(row):
            entry = out.setdefault(str(value), {"positive_rows": 0, "negative_rows": 0, "positive_groups": set(), "negative_groups": set()})
            side = "positive" if row.label == 1 else "negative"
            entry[f"{side}_rows"] += 1
            entry[f"{side}_groups"].add(row.group)
    return {k: {n: (len(v) if isinstance(v, set) else v) for n, v in entry.items()} for k, entry in sorted(out.items())}


def verified(rows: Iterable[Label]) -> list[Label]:
    """Rows a model may train on as verified labels: unconditional, not ``assumed_benign``."""
    return [r for r in rows if r.conditional is None and r.source != "assumed_benign"]


def snapshot(build: Build, sources: Sources) -> dict[str, Any]:
    """The committed record: counts per source, family, language, framework, unit and label, and repository-group
    counts. No candidate, path, function, commit or repository name."""
    rows = build.labels
    pins = [r for r in verified(rows) if r.unit == "pin"]
    families = _tally(pins, lambda r: [r.family])
    for entry in families.values():
        pos, neg = entry["positive_groups"], entry["negative_groups"]
        entry["model"] = (
            "per_family" if min(pos, neg) >= PER_FAMILY_FLOOR else "pooled" if min(pos, neg) >= POOLED_FLOOR else "insufficient"
        )
    conditional = [r for r in rows if r.conditional is not None]
    return {
        "schema": 1,
        "created": rows[0].created if rows else None,
        "sources": sorted(s.id for s in sources.sources),
        "excluded_unread": sorted(sources.excluded),
        "rows": len(rows),
        "groups": len({r.group for r in rows}),
        "group_merges": {},
        "verified_pin_labels": {
            "by_source": _tally(pins, lambda r: [r.source]),
            "by_family": families,
            "by_language": _tally(pins, lambda r: [r.language]),
            "by_framework": _tally(
                pins, lambda r: list(r.frameworks) if r.frameworks else ["none" if r.frameworks is not None else "unknown"]
            ),
            "by_split": _tally(pins, lambda r: [r.split]),
            "design_informed": _tally([r for r in pins if r.design_informed], lambda r: [r.source]),
            "privileged_positives": sum(1 for r in pins if r.privileged and r.label == 1),
        },
        "verified_delta_labels": _tally([r for r in verified(rows) if r.unit == "delta"], lambda r: [f"{r.family}:{r.direction}"]),
        "conditional_negatives": {
            source: {
                "rows": sum(1 for r in conditional if r.source == source),
                "groups": len({r.group for r in conditional if r.source == source}),
                "pushes": len(
                    {r.source_ref if source == "assumed_benign" else f"{r.source_ref}:{r.pin}" for r in conditional if r.source == source}
                ),
                "by_language": dict(sorted(_count(r.language for r in conditional if r.source == source).items())),
            }
            for source in sorted({r.source for r in conditional})
        },
        "assumed_benign_history": build.history,
        "pair_fixed_side": {
            "absent_fixed_side": {
                "labels": sum(build.absent_fixed_side.values()),
                "by_family": dict(sorted(build.absent_fixed_side.items())),
            },
            "fixed_side_moved": sum(1 for r in pins if r.provenance == FIXED_MOVED),
        },
        "skipped": dict(sorted(build.skipped.items())),
        "floors": {
            "per_family": PER_FAMILY_FLOOR,
            "pooled": POOLED_FLOOR,
            "unit": "repository groups with positive and with negative pin labels",
        },
    }


def _count(values: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def build_labels(
    root: Path,
    *,
    sources_path: Path = DEFAULT_SOURCES,
    cache: Path = DEFAULT_CACHE,
    include_title: bool = False,
    assumed_benign: bool = True,
    created: str | None = None,
) -> tuple[Build, dict[str, Any]]:
    """Every label the listed sources give, and the counts-only snapshot."""
    sources = load_sources(sources_path)
    builder = LabelBuilder(sources, root, cache=cache, include_title=include_title, assumed_benign=assumed_benign, created=created)
    build = builder.run()
    record = snapshot(build, sources)
    record["group_merges"] = dict(builder.groups.merged)
    return build, record


def write_labels(build: Build, path: Path) -> str:
    """``labels.jsonl`` (full rows, local only: they name paths and functions); returns its sha256."""
    import hashlib

    text = "".join(
        json.dumps(asdict(label), sort_keys=True) + "\n"
        for label in sorted(build.labels, key=lambda r: json.dumps(asdict(r), sort_keys=True))
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = [
    "ANY_FAMILY", "CONDITIONAL", "DEFAULT_SOURCES", "Build", "Clone", "Groups", "Label", "LabelBuilder", "LabelIndex", "LabelSourceError",
    "SourceGuard", "Sources", "advisories", "build_labels", "frameworks_from", "load_sources", "parse_diff", "repo_name",
    "security_reason", "snapshot", "verified", "write_labels",
]  # fmt: skip
