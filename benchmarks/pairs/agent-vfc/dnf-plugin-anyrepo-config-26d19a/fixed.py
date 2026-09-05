# Provenance: jfut/dnf-plugin-anyrepo  (fixed).
# repo: jfut/dnf-plugin-anyrepo
# commit: 26d19aeb8884f244e34ccfdc4f49f07055adc4d0
# parent: 33cde479d0db8f45dd89fbdcfb2bc0f1be66bd7a
# commit_url: https://github.com/jfut/dnf-plugin-anyrepo/commit/26d19aeb8884f244e34ccfdc4f49f07055adc4d0
# cve: 
# license: Apache-2.0
# function: validate_repo_name
# relpath: dnf_plugin_anyrepo/config.py
# provenance: agent
# mechanism: path_join_user_input

def validate_repo_name(name: str) -> str:
    """Validate the INI section name used as the repository alias."""

    normalized = str(name).strip()
    if not normalized:
        raise ConfigError("repository name must not be empty")
    if normalized == "main":
        raise ConfigError("repository name must not be main")
    # Keep the alias from resolving to the cache directory itself or its parent.
    if normalized in {".", ".."}:
        raise ConfigError(f"invalid repository name: {name}")
    if any(char in normalized for char in "\x00\r\n[]/\\"):
        raise ConfigError(f"invalid repository name: {name}")
    return normalized
