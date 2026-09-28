# Workflow (mandatory)

Every task follows these steps. Skipping a step is a failure.

## Before starting
1. Read .ai/project.md, .ai/rules.md, .ai/architecture.md,
   .ai/tasks/current.md, and any relevant file in .ai/architecture/.
2. State in one short paragraph: the task, the files you will touch,
   and which rules from .ai/rules.md apply.
3. If the task conflicts with the architecture, rules, or current stage,
   STOP and ask. Do not improvise.
4. For non-trivial work, write a short plan first and wait for approval.

## While working
- Stay inside the current stage. No extra features.
- Follow .ai/rules.md. If a rule blocks you, ask, do not bypass.
- New architectural decision -> create an ADR in docs/adr/ and add a
  line to .ai/decisions.md.
- New endpoint or trust boundary -> threat model note using
  .ai/prompts/threat-model.md.
- Never invent cryptography, never put secrets in code or logs.

## Before finishing (definition of done)
- [ ] Code builds, tests pass, lint passes (see .ai/commands.md)
- [ ] Tests added for auth/authz logic
- [ ] Docs and .ai/architecture files updated if reality changed
- [ ] ADR added if a decision was made
- [ ] .ai/tasks/current.md updated: what is done, what is next
- [ ] Final message lists: changed files, decisions made, open questions

## Communication
- Be concise. Report facts, not praise.
- If unsure, ask one specific question instead of guessing.

## Memory rule (mandatory)
After EVERY step, and before EVERY commit, update .ai/:
1. .ai/journal.md - append an entry (format below).
2. .ai/tasks/current.md - mark done items, set next step.
3. .ai/changelog.md - add the commit line (after the commit).
4. .ai/architecture.md or .ai/architecture/*.md - if structure, API,
   data model, or config changed.
5. .ai/decisions.md + docs/adr/ - if a decision was made.

A commit without a .ai/journal.md update is not allowed.
Commit message ends with: "Journal: <date> <step id>".

## Journal entry format
### YYYY-MM-DD HH:MM - <step id> - <short title>
- Done: what was implemented
- Files: main files changed
- Decisions: choices made and why (link ADR if any)
- Problems: what broke, how it was fixed
- Next: the very next step
- Commit: <hash or "pending">