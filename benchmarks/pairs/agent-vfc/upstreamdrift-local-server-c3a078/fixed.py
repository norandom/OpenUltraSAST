# Provenance: D-sorganization/UpstreamDrift  (fixed).
# repo: D-sorganization/UpstreamDrift
# commit: c3a0787080489b30e2ed0abfac03b51e45da184b
# parent: e28d1da5e103d93951ef11b78a6e9b89ac1fa2bc
# commit_url: https://github.com/D-sorganization/UpstreamDrift/commit/c3a0787080489b30e2ed0abfac03b51e45da184b
# cve: 
# license: MIT
# function: _find_logo_file
# relpath: src/api/local_server.py
# provenance: agent
# mechanism: path_join_user_input

def _find_logo_file(logo_name: str) -> Path | None:
    """Search for a logo file in known asset directories.

    The caller-supplied ``logo_name`` is joined onto each candidate root via
    :func:`_safe_join` so that ``..`` traversal, absolute paths, and symlink
    escape are rejected before touching the filesystem.

    Args:
        logo_name: Filename of the logo to find.

    Returns:
        Path to the logo file, or None if not found or rejected as unsafe.
    """
    for root in (
        Path(__file__).parent.parent.parent / "assets" / "logos",
        Path(__file__).parent.parent / "launchers" / "assets",
    ):
        resolved = _safe_join(root, logo_name)
        if resolved is not None and resolved.exists() and resolved.is_file():
            return resolved
    return None
