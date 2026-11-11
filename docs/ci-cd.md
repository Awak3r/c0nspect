# CI/CD: GitHub Actions → GHCR → existing VPS

Repository: <https://github.com/Awak3r/c0nspect>. Workflow: `.github/workflows/ci.yml`.

## Normal updates

The default delivery path is **one short local preflight → commit/push → authoritative CI → digest-pinned production release**. Do not repeat the full CI suite locally before every push or deployment request.

### Local gate: syntax and formatting, not a CI rehearsal

Run `python3 .github/scripts/preflight.py` from the checkout, review the diff, explicitly stage intended paths, then commit/push when authorized. The script checks Git whitespace, Go formatting, Python AST and JSON syntax. It covers staged blobs, working changes, untracked source and outgoing commits against the **locally known upstream**. It is read-only and makes no network requests; use `--base REF` for a different local baseline. Without an upstream it reports a HEAD fallback, so outgoing-commit coverage then requires an explicit base. Fetch separately when needed; the script never fetches or autoformats.

Do **not** start Docker/PostgreSQL, run all Go race tests/vet/build, all deployment tests or image smoke as an additional release prerequisite. Those are CI gates below. Use a small targeted local test when reproducing/fixing a bug, and reserve a full disposable rehearsal for an explicit request or a failure that requires it. Missing local Docker/DB is not a reason to delay a push or invent a manual server deployment.

If the unchanged tree already passed its local gate during the implementation task, do not repeat it when the user says “deploy”. Reuse a completed Actions run only for its exact SHA; a previous green revision never validates new code. After an authorized push, find the run by commit SHA and watch it through completion. Report **pushed**, **CI passed**, and **production healthy** as separate facts. If a job fails, inspect that job and reproduce/rerun the relevant failure instead of launching every local suite again.

### CI: complete checks once, in the supported environment

On each push/PR, **Checks** always runs. A small **Plan image and release** job runs alongside it and decides whether image/release work is necessary. For application/deployment changes, Actions retains the two expensive paths in parallel (image waits only for the planner, not for Checks):

1. **Checks:** formatting, vet, race tests against disposable PostgreSQL 17, all Go entrypoints, Python deployment/transport tests, and OpenAPI JSON parsing. Production credentials/database are never used for tests.
2. **Image:** builds and loads `linux/amd64` using Docker Buildx, publishes `ghcr.io/awak3r/c0nspect:<full-commit-sha>` on main, then smoke-tests that same image with disposable PostgreSQL 17. The smoke check enables remote MCP and verifies readiness, OAuth discovery, canonical issuer/resource/endpoints, PKCE S256, and an unauthenticated `POST /mcp` returning `401` with its discovery challenge. It uses random test credentials, a temporary Docker network and only loopback port 18080; containers/network are cleaned even on failure. No production configuration or data is used. A failed smoke check blocks deployment even if the image was already published. Both build layers and the Go compiler cache survive ephemeral runners. Only Go source/embedded assets and module metadata enter the build context.

Only after **both** succeed does **Deploy production** connect through verified SSH and deploy the exact published image **digest**, not a mutable tag. PRs never deploy. `workflow_dispatch` on main always requests the full path. Main runs remain serialized without interrupting a live deployment; GitHub keeps at most one pending run per concurrency group, replacing older pending runs. PR runs may be canceled. Do not move the lock to only the deploy job without a separately reviewed stale-revision admission check: an older slow build must never overwrite a newer release.

The VPS does not compile Go, receive a full Docker archive, pull a new PostgreSQL tag, or restart host nginx. Registry pulls transfer only missing layers. The first run warms the caches and is slower; actual duration depends on GitHub capacity/network and snapshot size. There is still a short maintenance window for the consistent backup and container replacement: this is not zero-downtime deployment.

### Docs-only fast path: prove it or build

`.github/scripts/plan_ci.py` may skip **only Image and Deploy**, never Checks. Its exact allowlist is `README.md`, `AGENTS.md`, `DESIGN.md`, `PRODUCT.md`, `SPEC.md`, `docs/ci-cd.md`, `docs/MCP.md`, and `docs/performance.md`. There is no workflow-level `paths-ignore` or blanket `*.md` exception: Markdown under `internal/` can be embedded application input. Any unknown path, executable/symlink/type change, mixed change or inspection error requires the full path. The plan prints `build_image` and a short reason; unavailable job outputs never authorize skipping.

- **PR:** compare the complete diff from its merge base, not just the last commit; no production metadata is needed.
- **Main push:** compare the current SHA against the latest recorded **production deployment**, which must have a successful latest status and an ancestor SHA. The planner reads GitHub deployment metadata with `deployments: read`; it does not connect to the VPS. It never falls back to an older success when the latest deployment is failed, pending or unknown. Unavailable metadata/history also means full build.
- **Manual dispatch:** always full, including docs-only revisions.

Comparing only `event.before` or `HEAD~1` is unsafe: a pending code push can be replaced by a later docs push, or its CI may have failed. The production-baseline comparison includes any such undelivered application changes and forces a release. Repeated docs-only pushes can safely leave the runtime revision unchanged. A green docs-only run means **documentation checked**, not “a new production revision deployed”. GitHub metadata is not a live health probe; after manual recovery or uncertain production state, use a reviewed full manual-dispatch/recovery path, not a docs-only skip.

### Measured critical path and further optimization

For run [42996893080](https://github.com/Awak3r/c0nspect/actions/runs/42996893080), the pre-planner pipeline completed in approximately **2 min 49 s**: Checks **61 s**, Image **101 s**, Deploy **57 s**. Checks and Image overlapped. These are one warm-run sample, not an SLA; queue, cache misses and backup sizes affect duration. Docs-only runs now avoid image publication, backup and container replacement; their remaining cost is complete Checks plus planning/queue overhead. New workflow behavior has to be confirmed by Actions after push, not inferred from local unit tests.

The immediate win is removing the duplicated full local rehearsal and avoiding unnecessary docs-only releases, **not removing race/integration tests or verified backups**. Buildx layers and compiler caches remain enabled. Do not remove cache extraction or weaken release safety based on a single timing sample. Keep prepare/image and deploy scheduling unchanged until repeated timings justify a separate optimization.

## One-time configuration

Use an existing, healthy **host-nginx** installation with root-owned `/opt/conspect`, `deploy/`, deployment sources, and a root-owned mode-0600 `.env`. Follow the README provisioning/TLS runbook first. Docker Compose, Python 3.10+, GNU tar on the host, and outbound HTTPS access to GHCR are required. Keep the Compose project name `conspect`. App/database volumes and the stable `APP_SECRET` remain unchanged.

The only supported production topology is **host nginx + app/db**; no reverse-proxy container or deployment profile is shipped. Keep `deploy/compose.nginx.yaml` on all production Compose commands. Backup/restore/scheduled-backup scripts select that overlay by default; explicit `--nginx` remains compatible with existing systemd units and commands. Local development still uses `--local` and `deploy/compose.local.yaml`, never combined with the production overlay. Removing the former container-proxy configuration does not delete existing Docker containers/volumes or modify host TLS configuration; review any legacy resources manually, never use `down -v` on live data.

In GitHub **Settings → Environments → production**, restrict deployment branches to `main` and configure:

| Type | Name | Value |
| --- | --- | --- |
| Variable | `DEPLOY_HOST` | VPS IP or hostname (must match known_hosts) |
| Variable | `DEPLOY_USER` | `root` |
| Variable | `DEPLOY_PORT` | SSH port, defaults to `22` |
| Variable | `DEPLOY_PATH` | Existing installation, defaults to `/opt/conspect` |
| Secret | `DEPLOY_SSH_KEY` | Dedicated Ed25519 private key for this repository |
| Secret | `DEPLOY_KNOWN_HOSTS` | Previously/independently verified SSH host-key entries |

Authorize only the dedicated public key in root's `authorized_keys`, with `restrict` to disable forwarding and PTY. Do not upload an existing personal SSH key. Host-key verification is strict; never use an unverified runtime `ssh-keyscan` as the trust anchor. Key rotation requires updating both the server and environment secret.

The existing root-owned deployment model requires root SSH, and the workflow can install executable source. **Anyone who can modify main or these workflows can control the production host.** Limit repository write access and protect main (reviews/status checks) as appropriate for the team. Never run a self-hosted production runner on public PR code. GitHub Actions, caches and GHCR are external services with their own quotas/billing; the built application image/source assets are uploaded to GitHub. Database/notes/uploads and the production `.env` stay on the VPS. No long-lived registry PAT is required: the deployment uses the job-scoped `GITHUB_TOKEN`, stores Docker credentials temporarily for the pull, then removes them. The package must retain this repository's Actions read/write access.

## Remote MCP configuration

Remote MCP/OAuth is part of the main `conspect` binary and Docker image; there is no separate MCP container, port, build or SCP installation step. Zed connects directly to `/mcp` with its existing scoped `csp_` API key; ChatGPT keeps OAuth. Deploying the app does not change Zed's settings: validate/migrate them separately using `.github/scripts/configure_zed.py`, which refuses replacement until authenticated initialize succeeds. Ready-made WSL Markdown is sent through the optional `cmd/conspect-upload` HTTP CLI, not a local MCP server or a server-side filesystem path. The production nginx overlay defaults `MCP_ENABLED` to `true`, including installations whose `.env` predates MCP. Explicit `MCP_ENABLED=false` in the server `.env` disables it and skips the public OAuth acceptance check. Local development keeps MCP disabled by default. The base application/Compose default remains disabled outside the production overlay.

Keep a canonical HTTPS `APP_BASE_URL` (an optional trailing slash is normalized like the application), stable `APP_SECRET`, and the Compose-managed `MCP_API_URL=http://127.0.0.1:8080`. Existing host nginx must preserve Host and forward `/mcp`, `/oauth/*` and OAuth discovery paths to app; the supplied catch-all TLS proxy already does this. No nginx changes/reload are performed by Actions. OAuth tables are initialized with additive migrations when MCP starts; existing notes and grants stay in the same database/volumes. Database backups and `APP_SECRET` are necessary to preserve connections. See [MCP configuration and security](MCP.md).

Normal updates must go through Actions. Do not recreate a local `.deploy/` directory or use ad-hoc SSH/SCP binary/image deployment. Put disposable experiments and worktrees outside the checkout; emergency manual recovery still follows the reviewed runbook below.

## Server release behavior

`.github/scripts/deploy.py` transfers **only committed `compose.yaml` and `deploy/`** to a unique root-private `.releases/` directory. `deploy/release.py`:

1. Validates paths, permissions, image digest and a running installation; acquires the same nonblocking lock used by backup/restore.
2. Pulls the immutable image while the old app still serves traffic, then validates the incoming Compose configuration, MCP flag and HTTPS origin before any backup or activation.
3. Uses the existing backup code for a consistent database + uploads + configuration snapshot. Backup failure prevents activation. It resumes the previously running app after the snapshot.
4. Saves old deployment files inside the private backup directory; atomically installs new deployment sources and changes only `CONSPECT_IMAGE` in `.env`.
5. Recreates **only app**, with `--no-deps --no-build --pull never --wait`. PostgreSQL, host nginx, unrelated services and persistent volumes are not recreated.
6. If remote MCP is enabled, checks the canonical public HTTPS origin: `/healthz`, both OAuth discovery documents and the unauthenticated MCP challenge. This also exercises TLS and host-nginx routing. Requests have timeouts/size limits, follow no redirects and use no owner credentials or OAuth tokens. Explicitly disabled MCP keeps the ordinary container-readiness gate.
7. Records the revision, digest, backup path and status in `/opt/conspect/.release.json`; the workflow removes its temporary source staging and local SSH credentials.

Backups remain local and contain private credentials/data. Automatic release backups are **not** automatically pruned; monitor disk usage and use a reviewed retention/offsite policy. Do not prune the previous image or recovery bundle until the new release has been accepted. This pipeline does not establish offsite durability.

## Failure and recovery

- A failed check/image build never starts deployment. A failed image pull or snapshot never replaces the live app.
- Backups/restores/releases share a lock: conflicting operations fail rather than race. Resolve the active operation and rerun the workflow.
- A failure before app activation restores the old `.env` and previously existing deployment files.
- A failure during activation **or the enabled MCP public HTTPS check** attempts to **stop app** and leaves the failed release configuration/backup pointer for investigation. Confirm its actual state on the host if stopping also failed. Host nginx may return 502, but is never restarted.
- **No automatic binary rollback:** startup may already have applied database migrations. Inspect `.release.json` privately. Restore a verified full backup with `python3 deploy/restore.py <bundle> --nginx --yes` using the existing destructive-restore runbook, and restore the matching previous deployment files from `<bundle>/deployment/` if the release changed Compose/scripts. Use the old locally retained image/source version. Review recovery commands/configuration before execution; a binary downgrade alone is not a database rollback.
- If Actions is canceled externally or the host loses power, the lock is released by the OS but the app may need manual recovery. Check the container, `.release.json` and latest complete backup before rerunning. Do not blindly cancel deployment or delete volumes.

Read status in the repository's Actions tab and the production environment's deployment history. An Actions success means the new container passed readiness and, when enabled, public MCP/OAuth acceptance checks—not a browser/ChatGPT consent-flow acceptance test or a proven restore drill.
