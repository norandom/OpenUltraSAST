"""Advisory selection. Network adapters are constructed only by the coordinator CLI."""

from __future__ import annotations

import base64
import json
import random
import re
from dataclasses import dataclass
from datetime import date
from urllib.parse import urlencode, urlsplit

from openultrasast.model.taxonomy import load_families

from .eligibility import RepositoryNotFound, normalize

ECOSYSTEMS = ("pip", "npm", "maven", "composer")
OSV_ECOSYSTEMS = dict(zip(ECOSYSTEMS, ("PyPI", "npm", "Maven", "Packagist"), strict=True))
FAMILIES = {"injection", "path", "deserialization", "access_control", "output_encoding", "untrusted_destination", "config_secrets"}
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense", "Zlib", "PostgreSQL", "BSL-1.0"}
FIX = re.compile(r"https://github\.com/([\w.-]+/[\w.-]+)/commit/([a-fA-F0-9]{7,40})(?:[/?#].*)?$", re.I)


class Rejected(ValueError):
    """Expected eligibility rejection; messages are fixed reason codes, never names."""


@dataclass(frozen=True)
class Candidate:
    repository: str
    url: str
    fix: str
    parent: str
    advisory: str
    ecosystem: str
    family: str
    post_cutoff: bool
    first_affected: str | None
    license_spdx: str
    license_class: str
    license_ref: str
    license_path: str


def post_cutoff(row: dict) -> bool:
    return date.fromisoformat(row["published_at"][:10]) > date(2026, 6, 1)


def fix_links(row: dict) -> set[tuple[str, str]]:
    links = set()
    for reference in row.get("references", []):
        url = reference if isinstance(reference, str) else reference.get("url", "")
        match = FIX.fullmatch(url)
        if match:
            links.add((normalize(match[1]), match[2].lower()))
    return links


def ecosystem(row: dict) -> str | None:
    values = {v["package"]["ecosystem"].lower() for v in row.get("vulnerabilities", [])}
    return next((e for e in ECOSYSTEMS if e in values), None)


def reduce_advisory(row: dict) -> dict:
    """Keep only selection inputs, including every fix needed by the exclusion index.

    Preserve the parser's shape so fresh and resumed pages follow the same path.
    Commit parents, licenses and OSV brackets are resolved later into Candidate.
    """
    return {
        "ghsa_id": row["ghsa_id"],
        "published_at": row["published_at"],
        "type": row.get("type", "reviewed"),
        "withdrawn_at": row.get("withdrawn_at"),
        "cwes": [{"cwe_id": c["cwe_id"]} for c in row.get("cwes", [])],
        "vulnerabilities": [{"package": {key: v["package"][key] for key in ("ecosystem", "name")}} for v in row.get("vulnerabilities", [])],
        "references": [f"https://github.com/{name}/commit/{sha}" for name, sha in sorted(fix_links(row))],
    }


def ordered_advisories(rows: list[dict], seed: int) -> list[dict]:
    """Stable seeded ordering, post-cutoff first in each ecosystem; round-robin strata."""
    rng = random.Random(seed)
    groups = []
    for eco in ECOSYSTEMS:
        group = sorted((r for r in rows if ecosystem(r) == eco), key=lambda r: r["ghsa_id"])
        rng.shuffle(group)
        group.sort(key=lambda r: not post_cutoff(r))
        groups.append(group)
    return [group[i] for i in range(max(map(len, groups), default=0)) for group in groups if i < len(group)]


def first_affected(record: dict, row: dict, eco: str) -> str | None:
    packages = {v["package"]["name"] for v in row["vulnerabilities"] if v["package"]["ecosystem"].lower() == eco}
    versions = set()
    for affected in record.get("affected", []):
        package = affected.get("package", {})
        if package.get("ecosystem") != OSV_ECOSYSTEMS[eco] or package.get("name") not in packages:
            continue
        for span in affected.get("ranges", []):
            if span.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in span.get("events", []):
                if event.get("introduced") not in {None, "0"}:
                    versions.add(event["introduced"])
    if len(versions) > 1:
        raise Rejected("ambiguous_version_bracket")
    return next(iter(versions), None)


def license_info(record: dict) -> tuple[str, str]:
    # Explicit pinned-file SPDX wins. For GitHub-recognized full texts its license endpoint
    # provides the detected SPDX. Unknown/custom/compound declarations stay private.
    declared = re.search(r"SPDX-License-Identifier:\s*([^\r\n]+)", record.get("text", ""))
    spdx = declared[1].strip().removesuffix("*/").strip() if declared else record.get("spdx_id") or "NONE"
    return spdx, "permissive" if spdx in PERMISSIVE else "private"


def candidate(row: dict, github, osv) -> Candidate:
    if date.fromisoformat(row["published_at"][:10]) < date(2019, 1, 1):
        raise Rejected("date")
    if row.get("type", "reviewed") != "reviewed" or row.get("withdrawn_at"):
        raise Rejected("advisory_status")
    eco = ecosystem(row)
    if eco is None:
        raise Rejected("ecosystem")
    taxonomy = load_families()
    families = {f.id for c in row.get("cwes", []) if (f := taxonomy.family_of_cwe(c["cwe_id"])) and f.id in FAMILIES}
    if len(families) != 1:
        raise Rejected("family")
    links = fix_links(row)
    if len(links) != 1:
        raise Rejected("fix_links")
    name, fix = next(iter(links))
    repo = github.get_repo(name)
    url = urlsplit(repo.get("clone_url", ""))
    if (
        repo.get("private", True)
        or not 0 <= repo.get("size", -1) <= 500 * 1024
        or url.scheme != "https"
        or url.hostname != "github.com"
        or url.username
        or url.password
        or url.query
        or url.fragment
        or normalize(repo["clone_url"]) != normalize(repo["full_name"])
    ):
        raise Rejected("repository")
    commit = github.get_commit(repo["full_name"], fix)
    if len(commit["parents"]) != 1:
        raise Rejected("parents")
    parent = commit["parents"][0]["sha"]
    license_record = github.get_license(repo["full_name"], parent)
    spdx, license_class = license_info(license_record)
    return Candidate(
        normalize(repo["full_name"]),
        repo["clone_url"],
        commit["sha"],
        parent,
        row["ghsa_id"],
        eco,
        next(iter(families)),
        post_cutoff(row),
        first_affected(osv.get(row["ghsa_id"]), row, eco),
        spdx,
        license_class,
        parent,
        license_record.get("path", ""),
    )


class JSONTransport:
    """Coordinator GET transport with bounded retries; all I/O and waits are injectable."""

    def __init__(self, *, opener=None, sleeper=None, clock=None):
        import time
        from urllib.request import urlopen

        self.opener = opener or urlopen
        self.sleeper = sleeper or time.sleep
        self.clock = clock or time.time
        self.attempts = 0
        self.rate_limit = {}

    def get(self, url: str, headers: dict) -> object:
        from http.client import IncompleteRead
        from urllib.error import HTTPError, URLError
        from urllib.request import Request

        for attempt in range(5):
            self.attempts += 1
            retry_headers, limited = {}, False
            try:
                with self.opener(Request(url, headers=headers), timeout=60) as response:
                    retry_headers = getattr(response, "headers", {})
                    self.record_rate(retry_headers)
                    return json.load(response)
            except HTTPError as exc:
                self.record_rate(exc.headers)
                if exc.code == 404:
                    raise RepositoryNotFound("not_found") from None
                limited = exc.code == 429 or (
                    exc.code == 403 and (exc.headers.get("X-RateLimit-Remaining") == "0" or exc.headers.get("Retry-After"))
                )
                transient = exc.code in {500, 502, 503, 504}
                if attempt == 4 or not (limited or transient):
                    raise ValueError("http_failure") from None
                retry_headers = exc.headers
            except (URLError, TimeoutError, ConnectionError, IncompleteRead, json.JSONDecodeError):
                if attempt == 4:
                    raise ValueError("http_failure") from None
            except Exception:
                raise ValueError("http_failure") from None
            try:
                delay = float(retry_headers.get("Retry-After", "0"))
                if limited and not delay:
                    delay = max(60, float(retry_headers.get("X-RateLimit-Reset", "0")) - self.clock() + 1)
                delay = max(delay, 2**attempt)
                if delay > 3605:
                    raise ValueError("retry_window")
            except (TypeError, ValueError):
                raise ValueError("http_retry_failed") from None
            self.sleeper(delay)
        raise ValueError("http_failure")

    def record_rate(self, headers):
        self.rate_limit = {
            key: headers.get(header)
            for key, header in (
                ("remaining", "X-RateLimit-Remaining"),
                ("limit", "X-RateLimit-Limit"),
                ("reset", "X-RateLimit-Reset"),
                ("retry_after", "Retry-After"),
            )
            if headers.get(header) is not None
        }


class GitHub:
    def __init__(self, token: str, transport=None):
        if not token:
            raise ValueError("missing_gh_token")
        self.transport = transport or JSONTransport()
        self.headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"}
        self.repos: dict[str, dict] = {}
        self.calls = 0

    def get(self, path: str):
        self.calls += 1
        return self.transport.get("https://api.github.com" + path, self.headers)

    def get_repo(self, name: str) -> dict:
        name = normalize(name)
        if name not in self.repos:
            self.repos[name] = self.get("/repos/" + name)
        return self.repos[name]

    def get_commit(self, name: str, sha: str) -> dict:
        return self.get("/repos/" + normalize(name) + "/commits/" + sha)

    def get_license(self, name: str, ref: str) -> dict:
        try:
            row = self.get("/repos/" + normalize(name) + "/license?" + urlencode({"ref": ref}))
        except RepositoryNotFound:
            return {"spdx_id": "NONE", "text": "", "path": ""}
        return {
            "spdx_id": (row.get("license") or {}).get("spdx_id"),
            "path": row.get("path", ""),
            "text": base64.b64decode(row.get("content", "")).decode("utf-8", errors="replace"),
        }

    def advisory_page(self, page: int, *, ecosystem: str) -> dict:
        if ecosystem not in ECOSYSTEMS:
            raise ValueError("invalid_ecosystem")
        # Oldest first: newly published advisories do not shift already persisted pages.
        parameters = {
            "type": "reviewed",
            "per_page": 100,
            "page": page,
            "sort": "published",
            "direction": "asc",
            "ecosystem": ecosystem,
            # Inclusive syntax used in benchmarks/independent/research-2026-09-30-php.md.
            "published": ">=2019-01-01",
        }
        taxonomy = load_families()
        cwes = {cwe for family in taxonomy.families if family.id in FAMILIES for cwe in family.cwes}
        # family_of_cwe uses exact membership. If the taxonomy gains non-exact tokens,
        # fetch broadly rather than risk excluding a client-selectable advisory.
        # GitHub's advisories `cwes` filter expects bare numbers (89), not "CWE-89".
        if cwes and all(re.fullmatch(r"CWE-[1-9][0-9]*", cwe) for cwe in cwes):
            parameters["cwes"] = ",".join(sorted((cwe.removeprefix("CWE-") for cwe in cwes), key=int))
        rows = self.get("/advisories?" + urlencode(parameters))
        if not isinstance(rows, list):
            raise ValueError("invalid_advisory_page")
        return {"rows": rows, "done": len(rows) < 100}

    def advisories(self):
        """Enumerate the candidate population, deduplicating multi-ecosystem advisories."""
        seen = set()
        for ecosystem in ECOSYSTEMS:
            page = 1
            while True:
                result = self.advisory_page(page, ecosystem=ecosystem)
                for row in result["rows"]:
                    if row["ghsa_id"] not in seen:
                        seen.add(row["ghsa_id"])
                        yield row
                if result["done"]:
                    break
                page += 1


class OSV:
    def __init__(self, transport=None):
        self.transport = transport or JSONTransport()
        self.calls = 0

    def get(self, identifier: str) -> dict:
        if not re.fullmatch(r"GHSA-[\w-]+", identifier):
            raise ValueError("invalid_advisory_id")
        self.calls += 1
        try:
            return self.transport.get("https://api.osv.dev/v1/vulns/" + identifier, {})
        except RepositoryNotFound:
            return {}  # No OSV bracket is distinct from a failed service call.
