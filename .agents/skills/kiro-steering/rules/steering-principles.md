# Steering Principles

Steering files are **project memory**, not exhaustive specifications.

---

## Content Granularity

### Golden Rule
> "If new code follows existing patterns, steering shouldn't need updating."

### ✅ Document
- Organizational patterns (feature-first, layered)
- Naming conventions (PascalCase rules)
- Import strategies (absolute vs relative)
- Architectural decisions (state management)
- Technology standards (key frameworks)

### ❌ Avoid
- Complete file listings
- Every component description
- All dependencies
- Implementation details
- Agent-specific tooling directories (e.g. `.cursor/`, `.gemini/`, `.claude/`)
- Detailed documentation of `.kiro/` metadata directories (settings, automation)

### Example Comparison

**Bad** (Specification-like):
```markdown
- /components/Button.tsx - Primary button with variants
- /components/Input.tsx - Text input with validation
- /components/Modal.tsx - Modal dialog
... (50+ files)
```

**Good** (Project Memory):
```markdown
## UI Components (`/components/ui/`)
Reusable, design-system aligned primitives
- Named by function (Button, Input, Modal)
- Export component + TypeScript interface
- No business logic
```

---

## Security

Never include:
- API keys, passwords, credentials
- Database URLs, internal IPs
- Secrets or sensitive data

---

## Quality Standards

- **Single domain**: One topic per file
- **Concrete examples**: Show patterns with code
- **Explain rationale**: Why decisions were made
- **Maintainable size**: 100-200 lines typical

---

## Preservation (when updating)

- Preserve user sections and custom examples
- Additive by default (add, don't replace)
- Add `updated_at` timestamp
- Note why changes were made

---

## Notes

- Templates are starting points, customize as needed
- Follow same granularity principles as core steering
- All steering files loaded as project memory
- Light references to `.kiro/specs/` and `.kiro/steering/` are acceptable; avoid other `.kiro/` directories
- Custom files equally important as core files

---

## File-Specific Focus

This repository's core steering files:

- **overview.md**: What the project is and what is actually true of it; a dated current-state section wins over older history
- **roadmap.md**: Milestones, their measured status, and the accepted order of work (not a task list)
- **safety-net.md**: Product direction and acceptance criteria (not feature catalogs)
- **Custom files**: Specialized patterns (API, testing, security, etc.); they may exist beside the core files and carry equal weight

(The generic bootstrap templates `product.md`, `tech.md`, `structure.md` under `.kiro/settings/templates/steering/` cover purpose, key frameworks and organization patterns for a fresh project.)
