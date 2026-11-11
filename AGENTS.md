# Repository working rules

## Fast validation and release

- The default local gate is `python3 .github/scripts/preflight.py`: changed/outgoing Go formatting, Git whitespace, Python AST and JSON syntax only. It must not start Docker/PostgreSQL, build images or contact production. It includes staged, unstaged, untracked source and unpushed commits relative to the local upstream; it does not fetch. Review the diff and explicitly stage only intended files.
- Do not run full local `go test -race ./...`, `go vet ./...`, `go build ./...`, all deployment tests, image smoke or a disposable database as a routine pre-push/pre-deploy checklist. Use a small targeted test to reproduce/fix a bug when needed, or a full rehearsal only when requested or essential to investigate a failure. Missing local Docker/DB is not a release blocker: CI provides the supported environment.
- After an unchanged tree has passed its local gate, do not repeat it on a deployment request. Reuse existing GitHub Actions results only for the exact commit SHA; never treat an older green commit as validation of new code.
- Commit/push only when authorized. A release request authorizes the normal commit/push/Actions path, not a manual VPS workaround. Watch the run for the pushed SHA through completion; distinguish pushed, checked and successfully deployed. On failure, inspect the failed job and rerun only the relevant targeted checks, not every local suite.
- Full CI remains the authority: race/integration tests on PostgreSQL 17, image smoke, immutable-digest deployment, verified backup and public readiness/MCP acceptance are mandatory whenever application/deployment inputs changed. A planner may skip image/deploy only for a proven docs-only diff against the latest successful production deployment (PRs use their merge base). Unknown baselines/paths/errors require the full path; manual dispatch is always full. No global `*.md` shortcut: embedded Markdown under `internal/` is application input.

## Deployment

- Normal production updates, including remote MCP/OAuth, go through `.github/workflows/ci.yml`: build/test the committed source, publish GHCR, then release by digest using `deploy/release.py`.
- Remote MCP is part of the main app image. Do not introduce a separate SSH/SCP binary/image installation path or deploy uncommitted local source to the VPS.
- Do not create `.deploy/` in this checkout. Keep disposable scripts, previews, archives and Git worktrees outside the checkout, and never put production secrets in source/build contexts.
- Manual production recovery/provisioning is only for an explicitly requested operation following `README.md` and `docs/ci-cd.md`. Never change live data, credentials, host nginx or containers as part of ordinary code edits.
- Preserve existing staged/unstaged changes. Before removing a worktree, verify its changes are retained and keep a private recovery copy when necessary.
