# CI/CD: GitHub Actions → GHCR → existing VPS

Repository: <https://github.com/Awak3r/c0nspect>. Workflow: `.github/workflows/ci.yml`.

## Normal updates

Push reviewed changes to `main`. Actions runs two jobs in parallel:

1. **Checks:** formatting, vet, race tests against disposable PostgreSQL 17, all Go entrypoints, Python deployment/transport tests, and OpenAPI JSON parsing. Production credentials/database are never used for tests.
2. **Image:** builds `linux/amd64` using Docker Buildx, publishes `ghcr.io/awak3r/c0nspect:<full-commit-sha>` on main. Both build layers and the Go compiler cache survive ephemeral runners. Only Go source/embedded assets and module metadata enter the build context.

Only after **both** succeed does **Deploy production** connect through verified SSH and deploy the exact published image **digest**, not a mutable tag. PRs are checked/built but cannot deploy. `workflow_dispatch` on main reruns the pipeline. Main runs are serialized without interrupting a live deployment; GitHub keeps at most one pending run per concurrency group, replacing older pending runs. PR runs may be canceled.

The VPS does not compile Go, receive a full Docker archive, pull a new PostgreSQL tag, or restart host nginx. Registry pulls transfer only missing layers. The first run warms the caches and is slower; actual duration depends on GitHub capacity/network and snapshot size. There is still a short maintenance window for the consistent backup and container replacement: this is not zero-downtime deployment.

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

## Server release behavior

`.github/scripts/deploy.py` transfers **only committed `compose.yaml` and `deploy/`** to a unique root-private `.releases/` directory. `deploy/release.py`:

1. Validates paths, permissions, image digest and a running installation; acquires the same nonblocking lock used by backup/restore.
2. Pulls the immutable image while the old app still serves traffic, then validates the incoming Compose configuration.
3. Uses the existing backup code for a consistent database + uploads + configuration snapshot. Backup failure prevents activation. It resumes the previously running app after the snapshot.
4. Saves old deployment files inside the private backup directory; atomically installs new deployment sources and changes only `CONSPECT_IMAGE` in `.env`.
5. Recreates **only app**, with `--no-deps --no-build --pull never --wait`. PostgreSQL, host nginx, unrelated services and persistent volumes are not recreated.
6. Records the revision, digest, backup path and status in `/opt/conspect/.release.json`; the workflow removes its temporary source staging and local SSH credentials.

Backups remain local and contain private credentials/data. Automatic release backups are **not** automatically pruned; monitor disk usage and use a reviewed retention/offsite policy. Do not prune the previous image or recovery bundle until the new release has been accepted. This pipeline does not establish offsite durability.

## Failure and recovery

- A failed check/image build never starts deployment. A failed image pull or snapshot never replaces the live app.
- Backups/restores/releases share a lock: conflicting operations fail rather than race. Resolve the active operation and rerun the workflow.
- A failure before app activation restores the old `.env` and previously existing deployment files.
- A failure during activation attempts to **stop app** and leaves the failed release configuration/backup pointer for investigation. Confirm its actual state on the host if stopping also failed. Host nginx may return 502, but is never restarted.
- **No automatic binary rollback:** startup may already have applied database migrations. Inspect `.release.json` privately. Restore a verified full backup with `python3 deploy/restore.py <bundle> --nginx --yes` using the existing destructive-restore runbook, and restore the matching previous deployment files from `<bundle>/deployment/` if the release changed Compose/scripts. Use the old locally retained image/source version. Review recovery commands/configuration before execution; a binary downgrade alone is not a database rollback.
- If Actions is canceled externally or the host loses power, the lock is released by the OS but the app may need manual recovery. Check the container, `.release.json` and latest complete backup before rerunning. Do not blindly cancel deployment or delete volumes.

Read status in the repository's Actions tab and the production environment's deployment history. An Actions success means the new container passed readiness, not a browser acceptance test or a proven restore drill.
