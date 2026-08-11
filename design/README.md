# design/ — Visual Spec + Mockup Staging

This directory exists to enforce the rule in `WARDEN_BUILD_CONTEXT.md §1`:
**no frontend/UI code is generated until a spec exists here and a human has produced a mockup from it.**

## Structure

```
design/
├── README.md                  # this file
└── <feature-name>/
    ├── spec.md                # plain-language visual spec (builder writes this)
    └── mockup/                # human-produced rough mockup goes here
        └── (paint sketch, screenshot from Stitch, etc.)
```

One subfolder per screen or feature — e.g. `design/dashboard-main/`, `design/cli-log-view/`.
Don't let specs pile into a single file as more UI gets added; each feature gets its own folder.

## Workflow (do not skip steps)

1. **Builder writes `spec.md`** using the template below — plain language, no code, no component names yet.
2. **Stop.** Do not generate any frontend code at this point.
3. **Human produces a rough mockup** (Paint-style sketch, or a page in Stitch) and drops it into `mockup/`.
4. **Only then** does frontend code generation begin, built against the approved mockup.

This gate is absolute for anything user-facing. Skippable only if the human explicitly says so in that session (e.g. "just build it plain, skip the mockup step").

## `spec.md` Template

```markdown
# <Feature Name>

## Purpose
What is this screen/view for? One or two sentences.

## Layout (in words)
Describe the layout top to bottom / left to right. No code, no component names —
just what a person would see and where. Reference structure, not styling.

## Data
What does this view read? (Should be read-only from the Ledger — see
WARDEN_SPEC.md §3. If it needs anything else, that's a flag, not a given.)

## States
- Empty state (no data yet):
- Loading state:
- Error state:
- Populated state:

## Aesthetic Rules Applied
Reference WARDEN_SPEC.md §9 explicitly. E.g.:
- Dark background, monospace font: yes
- Two-column layout: yes/no, why
- Color usage: what uses green/red/neutral here, specifically

## Open Questions
Anything the builder wasn't sure about — leave for human review, don't guess.
```
