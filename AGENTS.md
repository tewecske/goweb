# Project Instructions

Before any Go coding, review and load the `samber/cc-skills-golang@golang-how-to` skill first. It routes each task to relevant Go skills.

## Architecture

Use hexagonal boundaries and manual constructor wiring. Keep domain code independent of adapters and third-party packages. Define ports at consuming boundaries only when a second implementation or test double needs them.

## Go development

Use Go 1.26 language features only. Prefer standard-library packages. Add third-party dependencies only under the policy in `docs/dependency-policy.md`.
