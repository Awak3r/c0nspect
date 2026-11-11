# Conspect

Self-hosted Markdown notes: **Go 1.26**, `net/http` + `html/template`, PostgreSQL **17** via pgx, goldmark, local syntax highlighting and local KaTeX. Web/reader assets are embedded in the Go binary; there is **no Node runtime** or CDN dependency. Zed/ChatGPT use **remote MCP** in the app at `/mcp`; the legacy stdio entrypoint has been removed. `cmd/conspect-upload` imports ready-made local Markdown over HTTP without a local MCP server or model rewriting. See [MCP setup and ADHD note workflow](docs/MCP.md).

`SPEC.md` is the product specification (v0.5). The service entrypoint is `cmd/conspect/main.go`; browser/authentication/image/API handlers are in `internal/web`. `internal/web/openapi.json` is embedded in the binary and served publicly at `/api/v1/openapi.json`. The application is implemented; these instructions do **not** establish that a VPS deployment or a real backup/restore drill has been performed.

## CI/CD

Pushes to `main` run [GitHub Actions](https://github.com/Awak3r/c0nspect/actions): PostgreSQL-backed tests and a cached Docker build run in parallel, followed by a digest-pinned GHCR release to the existing host-nginx VPS. The server pulls changed image layers instead of receiving a full image archive, takes a verified local backup, and updates only the app container. PRs never deploy. See [configuration, security and recovery](docs/ci-cd.md).

The provisioning runbook below is for initial setup/manual recovery; normal updates, including remote MCP, use Actions only. Production `.env`, volumes and SSH keys are never committed. Do not create local deployment scripts or a `.deploy/` workspace; keep disposable tools/worktrees outside the checkout.

For measured response-time findings, the host connection-tracking fix, public-asset caching and optimization priorities, see [Performance](docs/performance.md).

## Interface boundaries

- `/projects`: owner project listing and management entry point.
- `/projects/:projectId`: private project contents/navigation.
- `/projects/:projectId/manage`: separate uploads, replacement, metadata, attachment and share management.
- `/settings/api-keys`: owner-only issuance, resource-grant updates and revocation of external-client keys.
- `/notes/:noteId`: owner note reader. `/s/:token`: public reader for one shared note.
- **Both readers have no buttons, forms, editor, hover actions or code-copy controls.** Owner navigation uses ordinary links. Public readers do not expose the project or neighboring notes.
- `/api/v1`: scoped REST API. `/api/v1/openapi.json`: public schema, without authentication. `/healthz`: origin-root readiness, including database connectivity.

A share grants access to the latest saved note and its images, not a frozen copy. Revocation cannot erase already downloaded copies. No project-wide public sharing is provided.

## Production behind existing host nginx

Production uses the **existing host nginx on ports 80/443** and GitHub Actions for updates. The app publishes only loopback port **8096**; PostgreSQL is never published. Always combine `compose.yaml` with `deploy/compose.nginx.yaml` for production. The base Compose file contains only `app` and `db`; it is not a complete production launch configuration. Never combine nginx/local overlays.

The following initial-provisioning procedure is a **deployer-run runbook**, separate from the [automated update pipeline](docs/ci-cd.md). CI/CD updates an existing installation; it does not provision a VPS or reload host nginx. Examples assume the deployer stages a **new** checkout at `/opt/conspect` and the host already uses Debian/Ubuntu-style `sites-available`/`sites-enabled`. If its per-site include layout differs, adapt only the Conspect site path after review; do not change global `nginx.conf`, default sites, other vhosts or existing services. Replace `notes.example.com` consistently in both nginx examples, certificate paths, redirect and app configuration.

### 1. Stage root-owned source, configuration and image

Have the deployer transfer reviewed source and an approved app image archive. Keep the image archive outside the Docker build context. Source/Compose/scripts must be **root-owned and not group/other-writable**, and `.env` must be **root:root, mode 0600**. These ownership commands are only for a newly staged source directory, never Docker volumes or an existing data tree (uploads require UID 10001):

```sh
sudo install -d -o root -g root -m 0750 /opt/conspect
# The deployer stages the reviewed checkout here before the following commands.
sudo chown -R root:root /opt/conspect
sudo chmod -R go-w /opt/conspect
sudo chmod 0750 /opt/conspect
# Create/review .env privately, then:
sudo chown root:root /opt/conspect/.env
sudo chmod 0600 /opt/conspect/.env
```

Use an explicitly chosen root shell for the remaining host steps, with working directory `/opt/conspect`; do not rely on an accidental sudo/Docker context switch. Fill the required database, stable `APP_SECRET` and initial owner settings from [Configuration](#configuration), without putting real secrets into this README, terminal tracing or logs. The additional **nonsecret** `.env` settings are:

```dotenv
APP_BASE_URL=https://notes.example.com
CONSPECT_IMAGE=conspect:local
CONSPECT_HTTP_PORT=8096
MCP_ENABLED=true
```

Remote MCP runs inside the app, with no extra port/container. The production overlay defaults `MCP_ENABLED` to `true`; set `MCP_ENABLED=false` in the server `.env` to opt out. Local development defaults to disabled. Keep `APP_SECRET` stable to preserve existing OAuth connections. See [MCP](docs/MCP.md).

`CONSPECT_IMAGE` must match the loaded image tag/digest. `CONSPECT_HTTP_PORT` defaults to 8096; if changed, update `proxy_pass` in `deploy/nginx.tls.conf` and loopback health-check commands too. Do not set `COMPOSE_PROFILES` in `.env`; clear unintended ambient Compose/profile overrides.

`deploy/compose.nginx.yaml` limits **app and db to 256 MiB each**. App runtime settings are `GOMEMLIMIT=192MiB`, `GOMAXPROCS=1`, `TRUST_PROXY=true`. PostgreSQL uses `shared_buffers=64MB`, `max_connections=30`, `work_mem=2MB`, `maintenance_work_mem=32MB`. These are a starting budget, not a measured capacity guarantee: Go's memory limit is soft, `work_mem` multiplies across operations/connections, and OOM kills remain possible. Leave RAM for the OS, Docker, nginx and existing workloads; monitor before increasing load. `GOMAXPROCS=1` is not a hard CPU quota.

### 2. Enable the ACME-only bootstrap site, not the app

`deploy/nginx.bootstrap.conf` needs **no certificate**. It serves only `/.well-known/acme-challenge/` from the new isolated root `/var/lib/conspect-acme` and returns **503 for all app traffic**. It never proxies logins, API calls or share URLs over HTTP. Do not enable bootstrap and TLS examples simultaneously.

For a new Conspect vhost only; the existence checks prevent overwriting an existing site:

```sh
set -eu
cd /opt/conspect
unset COMPOSE_PROFILES COMPOSE_FILE
install -d -o root -g root -m 0755 /var/lib/conspect-acme/.well-known/acme-challenge
test ! -e /etc/nginx/sites-available/conspect.conf
test ! -L /etc/nginx/sites-available/conspect.conf
test ! -e /etc/nginx/sites-enabled/conspect.conf
test ! -L /etc/nginx/sites-enabled/conspect.conf
install -o root -g root -m 0644 deploy/nginx.bootstrap.conf /etc/nginx/sites-available/conspect.conf
ln -s /etc/nginx/sites-available/conspect.conf /etc/nginx/sites-enabled/conspect.conf
if nginx -t; then
    systemctl reload nginx
else
    rm -- /etc/nginx/sites-enabled/conspect.conf
    exit 1
fi
```

Always **`nginx -t` before a graceful reload**, never restart/rewrite global configuration to force this site through. On failure, fix the isolated Conspect snippet; the existing nginx workers and other sites must remain undisturbed. Review all validator output, including duplicate `server_name` warnings.

### 3. Verify DNS A and HTTP reachability, then issue the certificate

A public **A record for the chosen domain must point to this VPS and propagate before certificate issuance**. If an AAAA record exists, its IPv6 routing/listeners must work too; a stale AAAA record can break ACME even with a correct A record. Allow public HTTP/HTTPS to the existing nginx, not to Docker app/db ports. This runbook does not claim DNS/firewall verification has been performed.

Use only a nonsecret ACME probe before TLS. The challenge URL should return the probe, while `/` should report **503**:

```sh
printf '%s\n' 'conspect-acme-ok' > /var/lib/conspect-acme/.well-known/acme-challenge/conspect-probe
chmod 0644 /var/lib/conspect-acme/.well-known/acme-challenge/conspect-probe
curl --fail --silent --show-error http://notes.example.com/.well-known/acme-challenge/conspect-probe
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' http://notes.example.com/
rm -- /var/lib/conspect-acme/.well-known/acme-challenge/conspect-probe
certbot certonly --webroot --webroot-path /var/lib/conspect-acme \
    --domain notes.example.com --cert-name notes.example.com
```

Use the host's existing Certbot installation/account workflow; answer its account/terms prompts privately. **Do not use the nginx installer plugin** to rewrite unrelated vhosts. The TLS example expects `/etc/letsencrypt/live/notes.example.com/fullchain.pem` and `privkey.pem`. Keep the HTTP ACME exception for renewal. Review the existing Certbot renewal timer and arrange a certificate-specific deploy hook running `nginx -t && systemctl reload nginx` after successful renewal; do not add duplicate timers or replace global nginx settings. Certificate renewal/reload is separate from the app's backup/restore scripts.

### 4. Load the app image, start only app/db, then enable TLS

With required `.env` values reviewed, load the approved transferred image and pull only PostgreSQL. A prebuilt image avoids compiling on the small VPS. `--no-build --pull never` makes an absent image fail rather than unexpectedly building/pulling an app release:

```sh
printf 'Path to the approved transferred app image archive: '
IFS= read -r IMAGE_ARCHIVE
docker load --input "$IMAGE_ARCHIVE"
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml pull db
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml config --quiet
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml up -d --no-build --pull never --wait --wait-timeout 180 app db
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml ps
curl --fail --silent --show-error http://127.0.0.1:8096/healthz
```

The production configuration contains **only app/db**, with no containerized reverse proxy or host-published database port. The host nginx snippets deliberately remain separate from Compose. Do not apply the local override in production: it publishes a database port and disables proxy trust.

After certificates exist, replace only the Conspect bootstrap file, retaining a rollback copy outside the enabled directory. If the syntax check fails, restore that file without reloading nginx:

```sh
test -s /etc/letsencrypt/live/notes.example.com/fullchain.pem
test -s /etc/letsencrypt/live/notes.example.com/privkey.pem
test ! -e /etc/nginx/sites-available/conspect.conf.before-tls
cp -p /etc/nginx/sites-available/conspect.conf /etc/nginx/sites-available/conspect.conf.before-tls
install -o root -g root -m 0644 deploy/nginx.tls.conf /etc/nginx/sites-available/conspect.conf
if nginx -t; then
    systemctl reload nginx
else
    cp -p /etc/nginx/sites-available/conspect.conf.before-tls /etc/nginx/sites-available/conspect.conf
    nginx -t
    exit 1
fi
curl --fail --silent --show-error https://notes.example.com/healthz
```

The TLS example has separate port-80 and port-443 servers. HTTP redirects to canonical HTTPS **except ACME**; only HTTPS proxies to `127.0.0.1:8096`. Both examples disable access logs and use `error_log /dev/null crit` to avoid request/share-token logging (at the cost of per-request proxy diagnostics). TLS permits bodies up to **16m**; the app's stricter file/envelope/pixel limits still apply. It overwrites `X-Forwarded-For` with `$remote_addr`, **not** the caller's forwarding chain: this is a single trusted host proxy, not an unreviewed CDN/proxy chain. It never overrides `Referrer-Policy`; check inherited host/CDN settings also preserve the app's reader/admin split.

Open `/login` at the HTTPS canonical URL and follow [First browser steps](#first-browser-steps). Verify other existing sites before and after each host reload. Review nginx logs/configuration locally without printing secrets or share URLs. **No VPS deployment is performed by the checks in this repository.**

### Host-nginx updates and recovery

Always use the overlay and `--nginx` consistently. Take a backup **before loading/replacing the current image tag**, then review/load the next approved image and run the same guarded app/db `up` command. The preflight intentionally rejects an image replaced before its running version was backed up.

```sh
python3 deploy/backup.py --nginx
# Review/load the next approved image only AFTER the backup succeeds.
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml up -d --no-build --pull never --wait --wait-timeout 180 app db
# For restore, use a real verified bundle directory and keep the selector:
printf 'Complete backup directory to restore: '
IFS= read -r BACKUP_DIR
python3 deploy/restore.py "$BACKUP_DIR" --nginx --yes
```

These scripts stop/restart **only the Compose app**, leave the DB running, and **never stop/reload host nginx or manage other host services**. While the app is stopped, the TLS vhost can return 502; do not stop the shared host nginx to hide maintenance. A failed destructive restore keeps the app offline until corrected; host nginx and unrelated sites remain up. Full consistency/security/offsite limitations remain in [Backups](#backups-local-until-offsite-storage-is-configured).

## Topology and persistent state

Host nginx terminates HTTPS and forwards requests to `127.0.0.1:8096`. The app retains its frontend network and reaches PostgreSQL through the internal backend network. Production publishes no database port. Docker Compose manages only `app` and `db`; host nginx and Certbot remain outside this project. The Docker host/daemon and other services deliberately attached to these networks remain trusted infrastructure.

| Service | Storage | Purpose |
| --- | --- | --- |
| `app` | `uploads:/data/uploads` | Uploaded images; Go binary runs as UID/GID **10001:10001** |
| `db` (`postgres:17-alpine`) | `db_data:/var/lib/postgresql/data` | Notes, owner, sessions, keys, shares and metadata |

Compose prefixes volume names with `conspect_`. Keep that project name for all operations; do not override `COMPOSE_PROJECT_NAME`. The app has a read-only root filesystem, a small temporary `/tmp`, dropped capabilities, and a writable uploads volume. The runtime contains CA certificates, GNU tar (used by backups), and BusyBox wget (readiness checks). There are no runtime source-tree/renderer mounts.

Docker checks PostgreSQL and application readiness; host nginx/Certbot manage TLS as described in the provisioning runbook. Do not enable request/debug logging or send token-bearing paths to upstream analytics: URLs may contain share tokens. Review Go logging separately; proxy configuration cannot prevent the app from logging secrets.

The **app owns the per-route referrer policy**. Login/admin documents use `Referrer-Policy: same-origin` and matching management-head metadata. Owner/public note readers use `no-referrer`; all `/s/...` responses (including errors and attachments) and API responses also retain `no-referrer`. Host nginx must not impose a global `Referrer-Policy` override. A blanket `no-referrer` on a login/admin document can make a native form POST send `Origin: null`, which authentication intentionally rejects.

If native login/admin forms return a CSRF/403 error, check that `APP_BASE_URL` exactly matches the browser origin, remove any proxy/CDN referrer-policy overrides, and freshly reload the login or management document before submitting again. Do **not** accept null/missing origins, disable CSRF checks, or reset the owner password to work around this policy mismatch.

Do not use `docker compose down -v` on a data-bearing installation. Normal `stop`, `start`, `up` and `down` without `-v` preserve named volumes. Changing PostgreSQL environment values on an existing volume does **not** rename the database/user or rotate its stored password.

## Configuration

Prerequisites for production: a Linux VPS with existing nginx/Certbot, Docker Engine with Compose v2+ (`--wait` support), Python 3.10+, DNS/TLS configured for the chosen hostname, and enough disk space for live data **and backups**.

Create a private configuration only for a **new installation**; never replace an existing `.env` or regenerate its stable secret during an update:

```sh
cp -n .env.example .env
chmod 600 .env
openssl rand -hex 32    # POSTGRES_PASSWORD: copy into .env
openssl rand -hex 32    # APP_SECRET: a DIFFERENT value; retain permanently
```

Set `APP_BASE_URL=https://your-domain`, the generated values, matching database credentials, and an initial `OWNER_PASSWORD` (12–72 UTF-8 **bytes**). A URL-safe hex database password needs no URL escaping; otherwise percent-encode it in `DATABASE_URL`. Dotenv single quotes prevent interpolation in passwords containing `$` or `#`. Do not `source .env` as a shell script. Use the host-nginx provisioning runbook for first startup and Actions for normal updates.

App configuration names (all size limits are encoded **bytes**):

| Variable | Default / requirement | Notes |
| --- | --- | --- |
| `DATABASE_URL` | **Required** | PostgreSQL connection URL. Compose uses `db:5432`; example `sslmode=disable` is only for this isolated backend, not a remote database. |
| `APP_ADDR` | `:8080` | Compose pins this to match the internal port/probes. |
| `APP_BASE_URL` | `http://localhost:8080` for a direct process | Set production to `https://your-domain`. Must be an absolute HTTP(S) origin without credentials, query, fragment or path prefix. Browser forms require an exactly matching `Origin`. Compose requires an explicit canonical value. |
| `APP_SECRET` | **Required**, exactly 64 hex characters | Stable 32-byte secret used for HMAC-derived, reproducible public share URLs. |
| `OWNER_USERNAME` | `admin` | Initial owner bootstrap only; trimmed username must contain 1–100 bytes. |
| `OWNER_PASSWORD` | Required for initial bootstrap; 12–72 UTF-8 bytes | Does not reset an existing owner. May be cleared from `.env` after bootstrap; the database retains the password hash. |
| `DATA_DIR` | `/data` in the image/Compose; use `./data` on host | Uploads live in `DATA_DIR/uploads`. Compose pins `/data`. |
| `MAX_MARKDOWN_BYTES` | `2097152` (2 MiB) | UTF-8 Markdown source/import limit. |
| `MAX_IMAGE_BYTES` | `10485760` (10 MiB) | Per-image limit; also at most 20,000,000 decoded pixels and 16,000 pixels per side. |
| `MAX_STORAGE_BYTES` | `1073741824` (1 GiB) | Quota on the sum of attachment metadata sizes in PostgreSQL, checked transactionally. Not a disk reservation or a bound on Markdown/DB/log/backup growth or orphaned files. |
| `TRUST_PROXY` | `true` only in production Compose | Trust forwarded metadata **only** when isolated behind the trusted host-nginx proxy. Direct/local service: `false`. |

Compose also uses `POSTGRES_DB`/`POSTGRES_USER` (both default `conspect`) and required `POSTGRES_PASSWORD`. `DOMAIN`, if retained in `.env`, is only optional metadata/interpolation for the canonical URL; Compose no longer requires it. The host-nginx overlay additionally reads `CONSPECT_IMAGE` (default `conspect:local`) and `CONSPECT_HTTP_PORT` (default `8096`), and pins Go runtime `GOMEMLIMIT=192MiB`, `GOMAXPROCS=1`. Production Compose pins `APP_ADDR=:8080`, `DATA_DIR=/data` and `TRUST_PROXY=true`; changing those variables in `.env` does not override the pins. A direct process defaults to `DATA_DIR=data` and `TRUST_PROXY=false`. Configured byte limits must be positive integers no greater than 1 TiB. Browser owner sessions last **12 hours**, using an `HttpOnly`, `SameSite=Lax` cookie that is `Secure` when `APP_BASE_URL` is HTTPS; no session-duration environment knob is defined here.

**Keep `APP_SECRET` with every backup.** It is not a disposable deployment/session secret: changing or losing it prevents reproducing existing public share URLs from restored share records. Do not regenerate it during upgrades, restores or container recreation. The secret is not an encryption key for the database; there is no end-to-end encryption. Preserve it securely even if you stop sharing temporarily.

If `APP_SECRET` changes, share management **remains usable**: it displays a warning and omits the copyable URL when it cannot reproduce the active token. Already-issued URLs and their authorized images **still work** against stored token hashes until you explicitly revoke or rotate the share; changing the secret is **not** revocation. Restore the original secret to recover copying of the unchanged URL, or use management to revoke access or rotate to a new URL (invalidating the old one). The backup/restore secret-matching guard remains in force; do not alter a backup manifest to bypass it.

Bootstrap checks `OWNER_USERNAME` and the 12–72-byte `OWNER_PASSWORD` **only when no owner exists**, then hashes the password with `bcrypt.DefaultCost` (cost 10). Changing either owner environment variable does **not** change the stored login/password; existing-owner startups do not revalidate these bootstrap fields. Password recovery must use an explicitly implemented and tested owner recovery procedure, not environment edits or deletion of the production volume. Restoring a backup also restores the owner credentials from that snapshot.

Imports accept UTF-8 `.md` files up to 2 MiB by default; invalid UTF-8 or NUL bytes return **422**, while a non-`.md` extension returns **415**. Titles must be nonblank UTF-8 without NUL and at most 300 Unicode code points. Images use multipart field `file`, accept only PNG/JPEG/WebP up to 10 MiB by default, and require positive dimensions, **width × height ≤ 20,000,000** and **each side ≤ 16,000**. Dimensions exceeding those bounds return **422**; unsupported MIME types or undecodable image headers return **415**. There is no `MAX_IMAGE_PIXELS` environment variable. SVG, HTML, executables and PDF uploads are not accepted.

Per-file limits are separate from request-envelope limits:

- Authenticated browser forms: `max(MAX_MARKDOWN_BYTES, MAX_IMAGE_BYTES) + 1 MiB` for the **whole request** (11 MiB at defaults). A Markdown import accepts up to 32 files, but their combined multipart request still has this bound.
- API image upload: `MAX_IMAGE_BYTES + 64 KiB` for the whole multipart body (10,551,296 bytes at defaults), and still `MAX_IMAGE_BYTES` for the file itself.
- API note create/update: JSON body at most `6 × MAX_MARKDOWN_BYTES + 8192` bytes to accommodate escaping; decoded Markdown still has the separate 2 MiB default limit. Invalid UTF-8 on the JSON wire returns **422 `invalid_utf8`**.

Oversized requests/files return **413**. Review the shared 16 MiB Compose `/tmp` tmpfs if raising upload limits or expecting concurrent multipart uploads. Relative image paths in Markdown do not upload local files automatically; source references must use `attachment:<id>` after a separate image upload, with no automatic append.

## Local development

Use the explicit override; it publishes app and database on **127.0.0.1 only** and sets canonical local HTTP plus `TRUST_PROXY=false`. No reverse-proxy container or deployment profile is involved:

```sh
# Fill .env secrets/bootstrap values as above.
docker compose --env-file .env -f compose.yaml -f deploy/compose.local.yaml up -d --build --wait app db
curl --fail http://localhost:8080/healthz
```

Use `http://localhost:8080`, not a different browser hostname, to match the canonical URL. Plain HTTP bearer use is a **loopback-only development exception**, never a production integration. Never include `deploy/compose.local.yaml` in production commands or combine it with `deploy/compose.nginx.yaml`. Local development and production intentionally use the same project/volumes: switch modes deliberately with `down` **without** `-v`, not by running both simultaneously. Never use a live production data directory for local experiments.

For a host Go process, start only `db` with the local override, set `DATABASE_URL` to the same credentials at `127.0.0.1:5432`, `APP_ADDR=:8080`, `APP_BASE_URL=http://localhost:8080`, `DATA_DIR=./data`, `TRUST_PROXY=false`, and the required secret/bootstrap values in the process environment; then `go run ./cmd/conspect`. Stop the containerized app first. Goldmark/KaTeX/reader assets remain local; no Node process is needed.

## First browser steps

1. Open `/login` at the configured canonical origin (`https://your-domain` in production or `http://localhost:8080` locally). Sign in with the **initially bootstrapped** owner credentials, not subsequently edited environment values.
2. At `/projects`, create a project with a name and optional description. Creation redirects to `/projects/:projectId/manage`, the separate management screen. Upload your UTF-8 `.md` files there; titles come from the first H1 or otherwise the filename. Keep batch size/request limits above in mind.
3. Open `/projects/:projectId` for the private contents/navigation, then a note at `/notes/:noteId`. This is a **reader**, not an editor: no upload, sharing, delete, image-insert or code-copy buttons. Return to project management for those operations; the public `/s/:token` reader likewise has no buttons or project navigation.
4. In management, upload one image to the chosen note and obtain its suggested `![filename](attachment:<id>)` source reference. Insert it at the intended position in your **local Markdown**, then explicitly replace that note's `.md` file, or use an authorized MCP/API update with a fresh ETag. Uploading alone changes neither Markdown nor its text version. Replacement preserves the note ID, current title, attachments and share URL; rename/move controls are separate. A new import, even with the same filename, creates another note. Management reports unresolved image references per note; review those warnings, upload the intended images and correct the source references before replacing/updating the note. Successful Markdown import does not mean every referenced image is available, and uploading never fixes references or appends images automatically.
5. From management, open `/notes/:noteId/share` to enable, copy, revoke or rotate a single-note share. Test it in a private browser window. Do not look for sharing controls on either reader.
6. Use `/settings/api-keys` to issue/revoke a separately scoped integration key or update its resource grants without replacing the secret. Neither that screen nor project management is public. If a batch import reports a partial database failure, inspect the project list before retrying: already committed notes are not rolled back as one batch.

## MCP integration

The app exposes **remote Streamable HTTP MCP** at `/mcp`, built with the official Go MCP SDK. Zed uses its scoped `csp_` API key; ChatGPT uses OAuth. There is no local MCP executable or separate MCP container. Follow [docs/MCP.md](docs/MCP.md) for native Zed settings, safe migration and the complete workflow. The model in your MCP client writes new notes; the server provides instructions and saves the resulting Markdown. Ready-made WSL files use `conspect-upload` directly over REST without model rewriting. No extra LLM key or AI worker is required, and the web service never sends notes to a model itself.

1. Sign in and create the target project in browser management.
2. At `/settings/api-keys`, issue a separate named `csp_...` key for the adapter. Select only the required project(s) or note(s), scopes, and optionally expiry. Copy the secret at issuance; it is shown once and stored hashed by the service.
   New projects are not implicitly included in a specific-project grant. To let an agent discover future projects, explicitly select **«Все текущие и будущие проекты»** when issuing the key, or open its existing card at `/settings/api-keys`, update material access and save. Existing keys default to restricted access; no grants are silently expanded. The same token and OAuth connection remain valid, scopes do not change, and the next `conspect_list_projects`/search reads the current permissions without restarting MCP.
3. Put the key in Zed's private remote Authorization header or the HTTP uploader's protected configuration, never in notes, image URLs, client JavaScript, model prompts or tool arguments visible to the model. Use only canonical HTTPS in production; do not forward bearer credentials across redirects.
4. Connect Zed directly to `/mcp` using the settings in [docs/MCP.md](docs/MCP.md), or use public `/api/v1/openapi.json` for a different REST client. The OpenAPI server base is `/api/v1`, so its path `/openapi.json` resolves to `/api/v1/openapi.json`, not a double-prefixed path. Only `/healthz` overrides the base to `/`. Note contents remain untrusted data, not instructions capable of expanding permissions. MCP runs inside the app image and is updated by the same Actions deployment.
5. For edits, GET the current note and exact ETag, compute a change, and PUT **both** title and Markdown with `If-Match`. On `412`, fetch/recompute; do not replay a stale full replacement. On `428`, fix the missing header.
6. For images, upload first; then GET a fresh note/ETag, place the returned `attachment:<id>` fragment at the desired position, and PUT. The upload itself never changes Markdown or automatically appends an image.
7. Test scope denial, out-of-resource `404`, stale writes, revocation and attachment isolation. Revoke the adapter key in browser settings when no longer needed. Model-provider privacy and billing are your responsibility once your adapter sends it content.

Scopes are independent:

| Scope | Operations |
| --- | --- |
| `notes:read` | List visible projects/notes; GET a note's flat source/metadata |
| `notes:write` | Create in an explicitly allowed project; update selected notes |
| `attachments:read` | Include attachment metadata in Note responses; GET image bytes |
| `attachments:write` | Upload images to allowed notes |

Write does not imply read. A note-only grant reveals that note's current parent project's metadata, but lists only permitted notes, never its neighbors; `q` filters note titles/Markdown and `sort=title` selects title order (otherwise most recently modified). A key scoped only to individual notes cannot create neighboring notes. Resource grants follow current project membership after moves. API keys cannot delete notes/attachments, edit the project structure, publish/unpublish, manage shares/keys, or change owner settings. A shared note can still be edited by an authorized write key: its existing public link then shows the new content. A public share URL is not a bearer credential.

### REST shapes and errors

| Method and path | Success |
| --- | --- |
| `GET /api/v1/projects` | `200 {"projects": [...]}` |
| `GET /api/v1/projects/{projectId}/notes` | `200 {"notes": [...]}` (permitted notes only) |
| `GET /api/v1/notes/{noteId}` | `200` flat Note + `ETag: "v1"` |
| `POST /api/v1/projects/{projectId}/notes` | `201` flat Note; input `{"title":"...","markdown":"..."}` |
| `PUT /api/v1/notes/{noteId}` | `200` updated flat Note + new ETag; both fields and quoted `If-Match` required |
| `POST /api/v1/notes/{noteId}/attachments` | `201 {"attachment": {...}, "markdown":"![alt](attachment:<id>)"}` |
| `GET /api/v1/notes/{noteId}/attachments/{attachmentId}/content` | `200` binary PNG/JPEG/WebP, not JSON |
| `GET /api/v1/openapi.json` | Public OpenAPI 3.1 schema (server `/api/v1` + schema path `/openapi.json`) |

A Note contains `id`, `project_id`, `title`, `markdown`, `source_name` (possibly empty for API creation), integer `version`, boolean `shared`, `created_at`, `updated_at`; `attachments` is included **only** with `attachments:read`. There is no `{ "note": ... }` wrapper and no public token/URL. Attachment metadata contains `id`, `note_id`, `name`, `mime_type`, byte `size`, `created_at`, never a storage path. Lists use empty arrays, not null.

Errors have the JSON shape:

```json
{"error":{"code":"invalid_input","message":"Нужны поля title и markdown","request_id":"example-request-id"}}
```

`401`: missing/invalid/expired/revoked bearer. `403`: insufficient scope. `404`: missing **or outside allowed resources**, including an attachment from another note. `412`: stale ETag. `428`: missing `If-Match`. `413`: byte/storage limit. `415`: unsupported content/image format. `422`: missing required fields, invalid UTF-8/NUL/title, invalid file selection or image dimensions. `400`: malformed/unknown-field/multiple-object JSON, malformed multipart, or a noncanonical `If-Match` (weak tags, lists and wildcards are rejected). Unexpected failures return safe `500` errors. `429` carries `Retry-After: 60`; API limits are 600 requests/minute per client IP and 240/minute per authenticated key. Responses include `X-Request-ID` for troubleshooting. Do not blindly retry creation/upload POSTs after an uncertain network response; there is no promised idempotency key.

### curl walkthrough

The following examples use **Bash, curl and jq**. Start with a disposable project and a key with all four scopes for that project. Substitute your domain and image filename. No key is embedded in the command history; avoid shell tracing, `curl -v`, shared request logs and printing credentials. Curl header arguments can still be visible to privileged local process inspection.

```bash
set -euo pipefail
BASE_URL=https://notes.example.com
read -rsp 'Conspect API key: ' CONSPECT_API_KEY; printf '\n'
umask 077
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"; unset CONSPECT_API_KEY' EXIT

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $CONSPECT_API_KEY" \
  "$BASE_URL/api/v1/projects" > "$workdir/projects.json"
jq . "$workdir/projects.json"
read -rp 'Allowed project ID from the response: ' PROJECT_ID

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $CONSPECT_API_KEY" \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/notes"

# Create: title and Markdown are explicit. The returned Note is flat.
jq -n '{title:"API example", markdown:"# API example\n\n$A^{-1}A=I$\n"}' > "$workdir/create.json"
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $CONSPECT_API_KEY" -H 'Content-Type: application/json' \
  --data-binary @"$workdir/create.json" \
  "$BASE_URL/api/v1/projects/$PROJECT_ID/notes" > "$workdir/created.json"
NOTE_ID=$(jq -er .id "$workdir/created.json")

# Read current content and retain the exact, quoted strong ETag.
read_note() {
  curl --fail-with-body --silent --show-error \
    -D "$workdir/note.headers" -o "$workdir/note.json" \
    -H "Authorization: Bearer $CONSPECT_API_KEY" \
    "$BASE_URL/api/v1/notes/$NOTE_ID" || return
  ETAG=$(awk 'tolower($1)=="etag:" {sub(/\r$/, "", $2); print $2; exit}' "$workdir/note.headers")
  test -n "$ETAG"
}
read_note || exit 1
jq '{title, markdown:(.markdown + "\nA deliberate client edit.\n")}' \
  "$workdir/note.json" > "$workdir/update.json"
curl --fail-with-body --silent --show-error -X PUT \
  -H "Authorization: Bearer $CONSPECT_API_KEY" -H 'Content-Type: application/json' \
  -H "If-Match: $ETAG" --data-binary @"$workdir/update.json" \
  "$BASE_URL/api/v1/notes/$NOTE_ID"

# Upload only: multipart field MUST be file. This does not edit the note.
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $CONSPECT_API_KEY" \
  -F 'file=@./diagram.png;type=image/png' \
  "$BASE_URL/api/v1/notes/$NOTE_ID/attachments" > "$workdir/upload.json"
ATTACHMENT_ID=$(jq -er .attachment.id "$workdir/upload.json")
FRAGMENT=$(jq -er .markdown "$workdir/upload.json")

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $CONSPECT_API_KEY" \
  "$BASE_URL/api/v1/notes/$NOTE_ID/attachments/$ATTACHMENT_ID/content" \
  -o "$workdir/downloaded.png"

# Fetch a fresh version. This example deliberately places the image at the end
# in the CLIENT; a real MCP tool chooses its requested position. Not server magic.
read_note || exit 1
jq --arg fragment "$FRAGMENT" '{title, markdown:(.markdown + "\n\n" + $fragment + "\n")}' \
  "$workdir/note.json" > "$workdir/with-image.json"
curl --fail-with-body --silent --show-error -X PUT \
  -H "Authorization: Bearer $CONSPECT_API_KEY" -H 'Content-Type: application/json' \
  -H "If-Match: $ETAG" --data-binary @"$workdir/with-image.json" \
  "$BASE_URL/api/v1/notes/$NOTE_ID"
```

If any operation fails, stop and inspect the safe error before continuing. A `412` is a merge/recomputation event, not permission to remove the `If-Match` check. Importing local Markdown into a JSON request can use `jq -n --arg title 'Title' --rawfile markdown ./note.md '{title:$title,markdown:$markdown}'` instead of hand-escaping content.

## Backups: local until offsite storage is configured

`deploy/backup.py` and `deploy/restore.py` use the **local Docker daemon**, the fixed `conspect` project, `.env`, and the committed Compose files, regardless of your current directory. They do not SSH, configure cron, upload anywhere or provision external storage. They require a built app image (for tar helpers), a running PostgreSQL 17 `db`, and Python 3.10+ on Linux. No host PostgreSQL client or Python package installation is needed. Run as the deliberately selected deployment account with Docker access and permission to read the mode-0600 `.env`; use the explicit root context for the root-owned host-nginx checkout, not an accidental sudo/context switch. Production uses the nginx overlay **by default**; `--nginx` remains an explicit equivalent for existing commands/timers. Choose `--local` only for local development. The selectors are mutually exclusive and the same overlay remains attached to every Compose command, including helpers and restarts; no mode is autodetected. Host nginx is never stopped/reloaded by these scripts.

The app must be the **only writer**. Do not run another app instance, host Go process, manual SQL writes, image processing job or deployment concurrently. The scripts serialize each other with `deploy/.operations.lock`, but cannot lock your external tools. Avoid ambient environment overrides of `.env`; Compose gives process variables precedence. The scripts check that the app/database configuration agrees, and refuse a URL targeting some other database or an app image/secret changed before the snapshot. For unambiguous target selection, these scripts accept only `sslmode`, `connect_timeout` and `application_name` URL query parameters (not host/user/database overrides). Supported database name/user defaults are `conspect`; use a dedicated database, never `postgres` or template databases.

```sh
python3 deploy/backup.py
# Optional alternative LOCAL directory (not an offsite guarantee):
python3 deploy/backup.py --output ./backups/manual
# Choose the matching mode, not both selectors:
python3 deploy/backup.py --nginx
python3 deploy/backup.py --local
```

Backup stops the app (brief downtime), leaves PostgreSQL running, streams a custom-format `pg_dump`, archives `uploads/` as UID 10001, and records checksums plus the effective configuration and secret fingerprint. With no writers, the DB and files describe the same snapshot. It publishes a `backups/conspect-<UTC timestamp>/` directory only after completion. It removes incomplete working directories on handled failures and restarts the app **only if it was previously running**, even if copying failed. A hard kill/power loss can leave `.partial-*` directories; never restore those. DB and uploads are never backed up while the app is still writing.

Each complete bundle contains:

- `database.dump`: PostgreSQL 17 logical dump, without role ownership/ACL restoration.
- `uploads.tar.gz`: complete uploads tree, including files not currently referenced.
- `config.env`: snapshot of `.env`.
- `compose.resolved.json`: **effective configuration, including actual APP_SECRET and other secrets**, useful if environment overrides were used. Do not feed this JSON directly back into Compose on a different host.
- `manifest.json`: format/version, time, DB name/user, app image ID, secret fingerprint and SHA-256 integrity checks.

Bundles are private (directory mode 0700, restrictive umask) but **not encrypted or authenticated**. Anyone with the bundle can read notes, owner/password hashes, session/key hashes and deployment secrets. Restore only your own trusted backups: a database dump can execute SQL, and checksums detect corruption, not a maliciously replaced manifest. Protect the files and encrypt before transferring them elsewhere. `.gitignore`/`.dockerignore` exclude the default local state; never commit or build with a custom backup directory containing secrets.

**This is not offsite backup.** Loss of the VPS/disk can destroy both data and these local bundles. Choose and configure a real external destination, encryption, credentials, transfer verification, monitoring and retention before calling the service production-ready. No external destination is assumed here. The suggested offsite policy is daily snapshots with 14 daily copies **off the VPS**; offsite transfer/encryption/retention is still not configured. The optional local-only timer and 14-snapshot retention below are separate and become active only when the deployer installs/enables them. Plan downtime and disk use; retain a separate verified safety copy before deleting anything. Each Docker operation has a 15-minute limit; large installs may require reviewing that bound in `deploy/operations.py`.

The scripts do not back up `/etc/letsencrypt`, host nginx site files, Docker images, the source tree, host configuration or unrelated databases/roles. Retain the matching application version/image and deployment files separately; host TLS configuration/certificates need their own recovery plan. PostgreSQL 17 restores do not constitute a major-version upgrade procedure.

### Daily local scheduling (root, opt-in)

The existing host-nginx deployment at `/opt/conspect` can use `deploy/scheduled_backup.py`, `deploy/conspect-backup.service` and `deploy/conspect-backup.timer`. **These are local artifacts only: the agent does not SSH, install/start units or enable the timer.** The parent/deployer must transfer/review them and opt in. Adding this timer does not require rerunning nginx bootstrap, changing Compose/security settings, or reloading host nginx.

The small wrapper holds the existing `operation_lock` across Compose selection, `create_backup` and retention. Production/nginx is the default; it also accepts the same mutually exclusive explicit `--nginx`/`--local` selectors and `--keep` (positive integer, default **14**). There is deliberately **no output-directory option**: both snapshot and retention are fixed to the real, nonsymlink `ROOT/backups` (`/opt/conspect/backups` on this host).

```sh
# Manual, root-run rehearsal; this creates a snapshot and applies local retention:
python3 /opt/conspect/deploy/scheduled_backup.py --nginx --keep 14
```

As with manual backups, the **app is briefly paused during the consistent DB/uploads snapshot** and resumed only if it was running before; snapshot size can lengthen downtime. PostgreSQL and host nginx stay running, and the TLS vhost may return 502 while the app is paused. Retention runs only after `create_backup` succeeds, including its app restart. If snapshot creation/restart fails, **no pruning runs**. If later retention fails, the completed new snapshot is preserved and the command reports failure without dumping exception/config/credential payloads into the journal.

Retention keeps the newest **14 snapshots**, not necessarily 14 distinct days, ordered by their generated UTC directory timestamp rather than filesystem mtime. It considers only direct `conspect-<timestamp>` children with the exact known bundle-file set, passing `validate_bundle` and matching the configured PostgreSQL major/database/user. Each deletion candidate is revalidated before removal. It never deletes partial directories, symlinks, corrupt/unrecognized bundles, extra-content directories, foreign-DB bundles, nested/custom backup directories or anything outside this dedicated directory. A symlinked backup root is refused; clock skew that would discard the new snapshot aborts pruning instead. Keep this directory private and do not modify bundles concurrently with a job. Skipped entries are logged as counts for operator review and can make the total directory count exceed 14.

**All copies remain on this VPS. There is no offsite backup, transfer or encryption here.** Bundles contain database data and live configuration secrets including `APP_SECRET`; keep `.env` and backup files root-only, directories mode 0700 and files mode 0600, with root-owned, non-writable-by-others source/scripts. Unit files contain no secrets. Provision room for at least **15 default-size bundles plus live data**, because a new verified snapshot must succeed before old ones can be removed. A full disk does not trigger emergency pre-backup deletion; failed runs leave existing snapshots alone. `backup.py --output ...` copies elsewhere remain outside this retention policy.

The service runs as `root:root` in `/opt/conspect`, with `UMask=0077`, `Nice=10`, and `TimeoutStartSec=1h`. It invokes `/usr/bin/python3 /opt/conspect/deploy/scheduled_backup.py --nginx --keep 14`; systemd does not source `.env` (Compose handles it privately). Shutdown uses SIGINT and a three-minute cleanup grace so Python's existing `finally` cleanup can run. Hard kills, power loss or a Docker outage can still leave an app stopped, helper running or partial backup; inspect app readiness and follow the existing recovery guidance before retrying.

The timer is daily at **03:30 UTC**, with up to **10 minutes randomized delay** and `Persistent=true` for one catch-up activation after a missed schedule. Manual/catch-up snapshots count toward the same 14-copy limit. A long-running job does not overlap another activation of the same systemd service; the shared lock also serializes manual backup/restore commands. No schedule is enabled merely by adding these files.

**Deployer-only installation on the live host**, in an explicit root shell after transferring the reviewed files (do not run any of these remotely from the agent):

```sh
set -eu
cd /opt/conspect
test ! -L /opt/conspect/backups
install -d -o root -g root -m 0700 /opt/conspect/backups
chown root:root deploy/scheduled_backup.py deploy/conspect-backup.service deploy/conspect-backup.timer
chmod 0644 deploy/scheduled_backup.py deploy/conspect-backup.service deploy/conspect-backup.timer
install -o root -g root -m 0644 deploy/conspect-backup.service /etc/systemd/system/conspect-backup.service
install -o root -g root -m 0644 deploy/conspect-backup.timer /etc/systemd/system/conspect-backup.timer
systemd-analyze --no-pager --man=no --generators=no verify /etc/systemd/system/conspect-backup.service /etc/systemd/system/conspect-backup.timer
systemctl daemon-reload
# Optional one-shot test in an approved brief maintenance window; it also prunes:
systemctl start conspect-backup.service
systemctl --no-pager status conspect-backup.service
# Only the parent/deployer enables scheduling (catch-up can run soon after enabling):
systemctl enable --now conspect-backup.timer
systemctl --no-pager list-timers --all conspect-backup.timer
```

For a successful oneshot, `status` may show the service as inactive after it completes; inspect its exit result/journal rather than expecting a daemon to stay active. Monitor failures and skipped-entry counts without printing secrets:

```sh
journalctl --unit=conspect-backup.service --since '2 days ago' --no-pager
# Deployer-only way to stop future scheduling; an already-running job is not canceled:
systemctl disable --now conspect-backup.timer
```

Verify a real disposable restore separately; a green timer exit is not an offsite-durability or restore-readiness guarantee. No host nginx stop/reload, automatic timer installation or remote production actions are performed by the wrapper/tests.

### Restore (destructive, offline, guarded)

1. Obtain a trusted complete bundle and the matching app version/image. Make a **separate safety backup of current data** before proceeding.
2. Restore/review `config.env` as `.env` (`chmod 600 .env`). If the original deployment used environment overrides, recover the effective `APP_SECRET` from `compose.resolved.json`. Keep `POSTGRES_DB`, `POSTGRES_USER` and the **original APP_SECRET**. Database connection credentials must match the target database; do not blindly import old host paths. Review `APP_BASE_URL` for the target host. Do not print the resolved config to shared logs.
3. Load the matching app image and start **only** the database if the target is fresh. For host nginx:

   ```sh
   docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml up -d --no-build --pull never --wait db
   ```

   For local development use `deploy/compose.local.yaml` instead of the nginx overlay. Keep the same mode for the restore CLI. Provision certificates/site configuration separately; a database restore does not manage nginx or ACME.

4. Run the restore, substituting an actual complete backup directory:

   ```sh
   printf 'Complete backup directory to restore: '
   IFS= read -r BACKUP_DIR
   python3 deploy/restore.py "$BACKUP_DIR" --nginx --yes
   # Use --local INSTEAD for the local stack; no selector defaults to nginx.
   ```

The explicit `--yes` acknowledges replacement of **all** data. Before stopping services, restore verifies the file checksums, archive paths/file types, DB identity, original secret fingerprint and dump table of contents. It then stops only the app, drops and recreates the dedicated database (terminating connections), restores the dump transactionally, removes **all existing uploads including dotfiles**, and extracts only regular files/directories under `uploads/`, without restoring arbitrary ownership. No stale files are merged in. Symlinks, hard links, path traversal and special files in the backup archive are rejected.

Only after **both** database and uploads succeed does it recreate/start the app if it was previously running, and wait for readiness. PostgreSQL stays running; host nginx is untouched. A fresh target's previously absent/stopped app stays stopped; explicitly start app/db after success:

```sh
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml up -d --no-build --pull never --wait --wait-timeout 180 app db
```


Preflight failures leave the current deployment untouched. **Once replacement begins, a restore failure or interruption keeps the app stopped in both production and local development.** The database/uploads may be partially replaced; never start the service to “see if it works.” Fix the cause and rerun the full restore from a verified bundle. A lost Docker connection can require manually removing a reported `conspect-ops-*` helper; confirm no helper/writer is running before retrying. The script does not promise atomic filesystem+DB rollback or recovery from disk failure.

After success, verify login, project/note counts, Markdown, image rendering/content, ETags, access isolation, and that an existing shared URL still works without logging its token. Restored sessions/API keys/share state and owner password reflect the snapshot: credentials or links revoked **after** that snapshot can become active again. Review/revoke them as appropriate. A backup is not proven recoverable until you have rehearsed restoration on a disposable installation. Daily backups can lose up to a day's changes; there is no point-in-time recovery or Markdown version history here.

## Updating and security limitations

Take a verified backup **before** replacing the app image/config or allowing schema changes. `store.Open` applies embedded, versioned migrations in the connection's current schema during startup under a PostgreSQL transaction/advisory lock; it rejects a schema newer than the supported version. There is no separate migration CLI or automatic down-migration. Base schema version 2 adds `api_keys.all_projects NOT NULL DEFAULT false`, preserving existing resource selections and credentials; version-1 binaries cannot open this newer schema. Keep the old application image/source version: a binary rollback alone is not a database rollback. The app allows 20 seconds for graceful HTTP shutdown; the Compose/scripts' 30-second stop grace leaves time to drain requests before snapshots.

```sh
# Host-nginx deployment; preserve this selector/overlay on every operation:
python3 deploy/backup.py --nginx
# Review/load the next approved image only after the backup completes.
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml up -d --no-build --pull never --wait --wait-timeout 180 app db
```

Normal production updates use the [Actions pipeline](docs/ci-cd.md). The commands above are for reviewed manual recovery; always keep the nginx overlay attached.

Actions pins application releases by immutable digest; the PostgreSQL and build/runtime base-image tags still track patch releases. Review changes and update Go/Alpine/PostgreSQL deliberately; blindly pulling a new PostgreSQL major version against this volume is not supported. Never regenerate `APP_SECRET` during an update. Test restart/recreation and restoration rather than assuming volumes alone are a backup.

TLS, scoped keys and secret-free proxy logs do not provide end-to-end encryption, offsite durability, an audit history of note contents or protection from a compromised VPS/Docker daemon. Public links are bearer secrets; sharing one deliberately publishes that note to its holders. `noindex` is advisory, not authorization. Application responsibilities still include secure cookies (`HttpOnly`, production `Secure`, appropriate `SameSite`), CSRF protection, a 12-hour session lifetime, rate limits, safe Markdown/KaTeX rendering, no default external-image fetches, authorization on every attachment, revocation checks before commits, and secret-free application/audit logs. These must be verified in Go tests; deployment configuration cannot implement them.

## Checks

### Default local gate before push

```sh
python3 .github/scripts/preflight.py
```

This read-only gate checks changed/outgoing Go formatting, Git whitespace, Python AST and JSON syntax, including staged, unstaged and untracked source. It uses the local upstream without fetching (`--base REF` overrides it). Review the diff and explicitly stage intended files. **Do not duplicate CI locally:** Docker/PostgreSQL, full race tests/vet/build and image smoke are not routine pre-push requirements. A small targeted regression test is appropriate while fixing a bug. If the unchanged tree already passed the gate, do not run it again merely because the user requests deployment.

GitHub Actions is the full validation authority for the exact pushed SHA. Checks always run; proven docs-only changes can skip Image/Deploy using a conservative production-baseline comparison. Application/deployment changes keep full tests, image smoke, verified backup and HTTPS/MCP acceptance. See [fast release policy, planner and measured timings](docs/ci-cd.md). Missing local Docker/DB is not a release blocker; never substitute an ad-hoc VPS deployment.

### Targeted diagnostics and optional full rehearsal

The commands below are **not an additional mandatory release checklist**. Use only the relevant check when investigating a failure, or the full set when an isolated rehearsal is explicitly needed.

```sh
# No Docker services/network or real env files are needed. Compose CLI enables
# the synthetic-env overlay contracts; those tests skip if the CLI is absent:
python3 -m unittest discover -s deploy -p 'test_*.py' -v
python3 -m json.tool internal/web/openapi.json > /dev/null
# Only for deliberate local Compose debugging, not every push/deploy.
# Use your local development .env, never production credentials; no resolved secrets are printed:
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml -f deploy/compose.local.yaml config --quiet
docker compose --env-file .env -f compose.yaml -f deploy/compose.nginx.yaml config --quiet
```

`deploy/test_operations.py` uses a fake Docker backend to exercise snapshot order and failure guards; it is **not** a real PostgreSQL/filesystem restore drill. `deploy/test_contract.py` checks effective OpenAPI routes against the Go router, schema references, the absence of a containerized reverse proxy, and README shell syntax without reading `.env` or `.env.example`. `deploy/test_nginx.py` validates bootstrap/TLS snippet contracts and uses an isolated synthetic env file to check merged ports, profiles, image overrides and resource limits with `docker compose config`; it never reads real `.env`/`.env.example` or starts containers. Production/default and local CLI selection, app-only restore isolation, and nginx's preservation of the app-specific referrer policy are covered by the deployment tests. `deploy/test_scheduled_backup.py` covers retention, failure/symlink/foreign-directory protection, CLI/lock behavior and systemd unit contracts using only synthetic local bundles and fake Docker; it does not read protected local env files, enable timers or run production backups. Host `nginx -t` remains a deployer step after installing the site/certificates, not proof supplied by static contracts. Validate OpenAPI with an OpenAPI 3.1 validator as well as JSON parsing; use an isolated validation environment, not global package installs.

Go checks require Go 1.26; race detection also needs a C compiler and `CGO_ENABLED=1` (the production binary remains `CGO_ENABLED=0`). Build with an explicit output location so the image build and source tree stay separate:

```sh
go build -mod=readonly -o ./bin/conspect ./cmd/conspect
# Safe no-database run: database-backed store/web tests SKIP rather than pass.
env -u TEST_DATABASE_URL CGO_ENABLED=1 go test -mod=readonly -race -count=1 -timeout=5m -v ./...
```

To exercise database-backed tests, provision a **dedicated disposable PostgreSQL 17 test database**, never the live `DATABASE_URL` or production database. The `TEST_DATABASE_URL` role must be able to create/drop schemas. Store/web helpers generate a random schema, verify `search_path`, apply migrations there and drop only that schema during cleanup; they do not provision/start Docker containers. Without `TEST_DATABASE_URL`, those integration tests skip. They configure test-only app secrets and temporary uploads themselves, so real `APP_SECRET`/bootstrap credentials are not needed.

```bash
# Bash: read the test URL privately; do not enable shell tracing or print it.
read -rsp 'Dedicated test PostgreSQL URL (never production): ' TEST_DATABASE_URL; printf '\n'
export TEST_DATABASE_URL
CGO_ENABLED=1 go test -mod=readonly -race -count=1 -timeout=5m -v ./...
unset TEST_DATABASE_URL
```

A successful build or a run with skipped database tests does not prove browser acceptance, PostgreSQL integration, a real container build, backup restoration, or VPS readiness. Rehearse those separately on disposable data. No actual VPS deployment is performed by these checks.
