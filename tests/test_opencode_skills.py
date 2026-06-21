from pathlib import Path


def test_project_opencode_skills_have_required_frontmatter() -> None:
    skills_root = Path(".opencode/skills")
    # Scope to the project's own skills; third-party tooling (e.g. kiro-*) lives
    # alongside them and uses a different frontmatter convention.
    skill_files = sorted(skills_root.glob("openultrasast-*/SKILL.md"))

    assert {path.parent.name for path in skill_files} == {
        "openultrasast-fix-audit",
        "openultrasast-kiro-impl",
        "openultrasast-scan",
        "openultrasast-triage",
    }

    for skill_file in skill_files:
        text = skill_file.read_text()
        header = text.split("---", 2)[1]
        assert f"name: {skill_file.parent.name}" in header
        assert "description: " in header
        assert "Use when" in header
