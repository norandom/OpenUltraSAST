# Provenance: Ahkeratmehilaiset/waggledance-swarm  (vuln).
# repo: Ahkeratmehilaiset/waggledance-swarm
# commit: 934b939f1cca5259eaf807db3319eb97b90d8d80
# parent: 934b939f1cca5259eaf807db3319eb97b90d8d80
# commit_url: https://github.com/Ahkeratmehilaiset/waggledance-swarm/commit/9a454843aa35332ff2eb3106023eee0c4b5e444b
# cve: 
# license: Apache-2.0
# function: normalize_allowed_hosts
# relpath: waggledance/core/v3_13_0/ssrf_host_guard.py
# provenance: agent
# mechanism: source_reaches_sink

def normalize_allowed_hosts(raw_hosts: Sequence[str]) -> frozenset[str]:
    """Validate and canonicalize an exact-host allowlist."""
    if not isinstance(raw_hosts, Sequence) or isinstance(raw_hosts, (str, bytes)):
        raise ValueError("ALLOWLIST_HOSTS_REFUSED")
    normalized: set[str] = set()
    for index, host in enumerate(raw_hosts):
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"ALLOWLIST_HOSTS_REFUSED_{index}")
        clean = normalize_host(host)
        if "://" in clean or "/" in clean or "?" in clean or "@" in clean:
            raise ValueError(f"ALLOWLIST_HOSTS_REFUSED_{index}")
        normalized.add(clean)
    return frozenset(normalized)
