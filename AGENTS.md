# Repository working rules

## Deployment

- Normal production updates, including remote MCP/OAuth, go through `.github/workflows/ci.yml`: build/test the committed source, publish GHCR, then release by digest using `deploy/release.py`.
- Remote MCP is part of the main app image. Do not introduce a separate SSH/SCP binary/image installation path or deploy uncommitted local source to the VPS.
- Do not create `.deploy/` in this checkout. Keep disposable scripts, previews, archives and Git worktrees outside the checkout, and never put production secrets in source/build contexts.
- Manual production recovery/provisioning is only for an explicitly requested operation following `README.md` and `docs/ci-cd.md`. Never change live data, credentials, host nginx or containers as part of ordinary code edits.
- Preserve existing staged/unstaged changes. Before removing a worktree, verify its changes are retained and keep a private recovery copy when necessary.
