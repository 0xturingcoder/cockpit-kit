# Contributing to Cockpit Kit

This file is the source of truth for how work is done in this repository. If the process changes, update this file in the same PR; do not leave a rule only in chat.

Work is tracked in GitHub Issues and grouped by phase milestones ("Phase N: Name"), each with a `phase-N-name` label. Each phase has a tracking issue that lists its issues in dependency order.

## Roles

- **Maintainer:** picks the next issue whose dependencies are done, assigns an implementer, posts the plan as a comment on the issue, keeps labels and the tracking issue current, and tags releases.
- **Implementer:** builds one issue on one branch and opens one PR for it.
- **Reviewer:** reviews PRs against the issue's acceptance criteria. The author of a PR must not be its required reviewer.
- **Automated reviewer:** may review every PR when available.

## Workflow for each issue

1. **Plan.** The maintainer assigns the issue only after its dependencies are done, and comments with the plan: branch name, approach, and sequencing notes.
2. **Build.** The implementer branches from current `main` as `issue-<N>-<slug>` (for example `issue-7-users-store`). Run `node --test` before pushing; it is the same command CI runs. Write tests against the acceptance criteria. A draft PR is fine until ready.
3. **PR.** One issue per PR, with `Closes #N` in the body. Fill in the PR template and check off the issue's acceptance criteria.
4. **Review.** CI must be green and a non-author must approve. Post findings as inline comments on the specific lines, one finding per comment, with only a short summary and the verdict in the review body. PRs labelled `security` also get an explicit security pass: the reviewer states in the review what was checked (auth bypass, replay, secret leakage, input validation) and the result.
5. **Merge.** Squash-merge only, after green CI and a non-author approval. The reviewer or the maintainer may merge.
6. **Release.** At the end of each phase the maintainer tags `v0.<phase>.0` (for example `v0.1.0` after phase 1) with a one-line summary.

## Rules

- Never push to `main`. Never force-push a branch others may be using.
- One issue per PR. Keep PRs small.
- Docs travel with the change: a PR that changes behavior, config, commands, or this process updates the docs (and this file, if relevant) in the same PR. No follow-up docs PRs.
- No secrets, real hostnames, real personal data, or machine-specific paths in code, tests, fixtures, docs, or commit messages. Use invented names and reserved example domains such as `example.com`. Generate secret-shaped test values at runtime.
- The kit is generic and upstream-friendly. Do not add deployment-specific code.
- **No runtime dependencies.** The kit uses only Node's standard library. Keep it that way unless a maintainer agrees otherwise, and record that decision on the issue before adding one.

## Escalation

If work is blocked for more than a day, or a design choice is ambiguous, the implementer tells the maintainer on the issue.

## Definition of done

- The PR linked with `Closes #N` has every acceptance criterion checked off
- Tests cover those criteria
- CI is green
- A non-author reviewer approved (plus the security pass for `security` PRs)
- Docs are updated in the same PR
- Squash-merged and the issue is closed
- No secrets or personal data introduced
