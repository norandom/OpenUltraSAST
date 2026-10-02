---
name: kiro-steering
description: Manage .kiro/steering/ as persistent project knowledge, including custom steering documents for specialized contexts
metadata:
  shared-rules: "steering-principles.md"
---


# Kiro Steering Management

<background_information>
**Role**: Maintain `.kiro/steering/` as persistent project memory.

**Core steering in this repository**: `overview.md` (what the project is and what is actually true of it, dated current state), `roadmap.md` (milestones and status), `safety-net.md` (product direction). Custom files may exist beside them (for example a domain or standards file); all `.kiro/steering/*.md` are loaded as project memory. The generic bootstrap templates under `.kiro/settings/templates/steering/` are named `product.md`, `tech.md`, `structure.md`; they are starting points for a fresh project, not this repository's file names.

**Mission**:
- Bootstrap: Generate core steering from codebase (first-time)
- Sync: Keep steering and codebase aligned (maintenance)
- Custom: Create specialized steering documents beyond the core files (optional, see below)
- Preserve: User customizations are sacred, updates are additive

**Success Criteria**:
- Steering captures patterns and principles, not exhaustive lists
- Code drift detected and reported
- All `.kiro/steering/*.md` treated equally (core + custom)
</background_information>

<instructions>
## Scenario Detection

Check `.kiro/steering/` status:

**Bootstrap Mode**: Empty OR missing core files (here `overview.md`, `roadmap.md`, `safety-net.md`; in a fresh project the template names `product.md`, `tech.md`, `structure.md`)  
**Sync Mode**: All core files exist  
**Custom Mode**: The user asks for a specialized steering document (see Custom Steering below)

---

## Bootstrap Flow

1. Load templates from `.kiro/settings/templates/steering/`
2. Analyze codebase (JIT):

#### Parallel Research

The following research areas are independent and can be executed in parallel:
1. **Product analysis**: README, package.json, documentation files for purpose, value, core capabilities
2. **Tech analysis**: Config files, dependencies, frameworks for technology patterns and decisions
3. **Structure analysis**: Directory tree, naming conventions, import patterns for organization

If multi-agent is enabled, spawn sub-agents for each area above. Otherwise execute sequentially.

After all parallel research completes, synthesize patterns for steering files.

3. Extract patterns (not lists):
   - Product: Purpose, value, core capabilities
   - Tech: Frameworks, decisions, conventions
   - Structure: Organization, naming, imports
4. Generate steering files (follow templates)
5. Load principles from `rules/steering-principles.md` from this skill's directory
6. Present summary for review

**Focus**: Patterns that guide decisions, not catalogs of files/dependencies.

---

## Sync Flow

1. Load all existing steering (`.kiro/steering/*.md`)
2. Analyze codebase for changes (JIT)
3. Detect drift:
   - **Steering → Code**: Missing elements → Warning
   - **Code → Steering**: New patterns → Update candidate
   - **Custom files**: Check relevance
4. Propose updates (additive, preserve user content)
5. Report: Updates, warnings, recommendations

**Update Philosophy**: Add, don't replace. Preserve user sections.

---

## Custom Steering (optional)

Create a specialized steering document for one domain beyond the core files.

1. **Ask the user** for the domain/topic (e.g. "API standards", "testing approach") and the specific patterns to document
2. **Check for a template** in `.kiro/settings/templates/steering-custom/`: `api-standards.md`, `testing.md`, `security.md`, `database.md`, `error-handling.md`, `authentication.md`, `deployment.md`. Load the matching one as a starting point; without a template, generate from domain knowledge
3. **Analyze the codebase** (JIT) for the domain's patterns with Glob/Grep/Read (template and principles in parallel with the domain analysis when multi-agent is available)
4. **Generate** the document: follow the template structure if any, apply `rules/steering-principles.md`, patterns not exhaustive lists, one domain per file, 100-200 lines (a 2-3 minute read), never secrets
5. **Create** `.kiro/steering/{name}.md`; ensure it does not duplicate core steering content

Custom files are loaded as project memory like the core files and carry equal weight.

---

## Granularity Principle

From `rules/steering-principles.md` (in this skill's directory):

> "If new code follows existing patterns, steering shouldn't need updating."

Document patterns and principles, not exhaustive lists.

**Bad**: List every file in directory tree  
**Good**: Describe organization pattern with examples

</instructions>

## Tool guidance

- **Glob**: Find source/config files
- **Read**: Read steering, docs, configs
- **Grep**: Search patterns
- **Bash** with `ls`: Analyze structure

**JIT Strategy**: Fetch when needed, not upfront.

## Output description

Chat summary only (files updated directly).

### Bootstrap:
```
✅ Steering Created

## Generated:
- overview.md: [What it is, current state]
- roadmap.md: [Milestones, status]
- safety-net.md: [Product direction]

Review and approve as Source of Truth.
```

### Sync:
```
✅ Steering Updated

## Changes:
- overview.md: Current state dated, retired component removed
- roadmap.md: Milestone status updated

## Code Drift:
- Components not following import conventions

## Recommendations:
- Consider api-standards.md
```

### Custom:
```
✅ Custom Steering Created

## Created:
- .kiro/steering/api-standards.md

## Based On:
- Template: api-standards.md
- Analyzed: src/api/ directory patterns

Review and customize as needed.
```

## Examples

### Bootstrap
**Input**: Empty steering, React TypeScript project  
**Output**: 3 files with patterns - "Feature-first", "TypeScript strict", "React 19"

### Sync
**Input**: Existing steering, new `/api` directory  
**Output**: Updated overview.md, flagged non-compliant files, suggested api-standards.md

### Custom
**Input**: "Create API standards steering"  
**Action**: Load template, analyze src/api/, extract patterns  
**Output**: api-standards.md with project-specific REST conventions

## Safety & Fallback

- **Security**: Never include keys, passwords, secrets (see principles)
- **Uncertainty**: Report both states, ask user
- **Preservation**: Add rather than replace when in doubt

## Notes

- All `.kiro/steering/*.md` loaded as project memory
- Templates and principles are external for customization
- Focus on patterns, not catalogs
- "Golden Rule": New code following patterns shouldn't require steering updates
- Avoid documenting agent-specific tooling directories (e.g. `.cursor/`, `.gemini/`, `.claude/`)
- `.kiro/settings/` content should NOT be documented in steering files (settings are metadata, not project knowledge)
- Light references to `.kiro/specs/` and `.kiro/steering/` are acceptable; avoid other `.kiro/` directories

