# Provenance: D-sorganization/UpstreamDrift  (vuln).
# repo: D-sorganization/UpstreamDrift
# commit: e28d1da5e103d93951ef11b78a6e9b89ac1fa2bc
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

    Args:
        logo_name: Filename of the logo to find.

    Returns:
        Path to the logo file, or None if not found.
    """
    logos_dir = Path(__file__).parent.parent.parent / "assets" / "logos"
    logo_path = logos_dir / logo_name
    if logo_path.exists() and logo_path.is_file():
        return logo_path
    launcher_logos = Path(__file__).parent.parent / "launchers" / "assets"
    alt_path = launcher_logos / logo_name
    if alt_path.exists() and alt_path.is_file():
        return alt_path
    return None
