# Conspect API client

This package implements the HTTP/configuration/local-read boundary for the MCP
frontend. `models.go` is the shared DTO/config contract and is not modified.

## Interface

```go
func ConfigFromEnv() (Config, error)
func New(Config) (*Client, error)
func (*Client) Close() error
func (*Client) ListProjects(context.Context) ([]Project, error)
func (*Client) ListNotes(ctx context.Context, projectID, query, sort string) ([]NoteSummary, error)
func (*Client) GetNote(ctx context.Context, id string) (Note, error)
func (*Client) CreateNote(ctx context.Context, projectID, title, markdown string) (Note, error)
func (*Client) UpdateNote(ctx context.Context, noteID, title, markdown, etag string) (Note, error)
func (*Client) UploadImage(ctx context.Context, noteID, relativePath string) (UploadedImage, error)
func (*Client) ReadMarkdown(relativePath string) (string, error)
func (*Client) ReadSource(relativePath string) (string, error)
```

`New` makes **no network calls**. It validates credentials and opens the optional
local root. `Close` is idempotent, waits for in-flight operations, closes the root
and idle HTTP connections, and disables subsequent operations.

## Trusted startup configuration

| Environment variable | Config field | Behavior |
| --- | --- | --- |
| `CONSPECT_URL` | `BaseURL` | Defaults to `https://conspect.awak3r.ru`; accepts an origin or an origin with `/api/v1` (optional trailing slash), normalizing to the origin. |
| `CONSPECT_API_KEY` | `APIKey` | Nonempty `csp_` secret, printable ASCII without whitespace, at most 4096 bytes. |
| `CONSPECT_API_KEY_FILE` | `APIKeyFile` | Trusted startup credential filename, not an MCP argument; mutually exclusive with `APIKey`. |
| `CONSPECT_FILES_ROOT` | `FilesRoot` | Empty disables all local reads and uploads; otherwise opens a directory using `os.OpenRoot`. |

Exactly one nonempty credential source is required. `ConfigFromEnv` validates the
URL and credential source but preserves `APIKeyFile` rather than putting its
contents into `APIKey`. `New` independently repeats validation and reads that
file, so direct callers cannot bypass checks. Only `New` opens `FilesRoot`.
Direct `New(Config{...})` also defaults an empty `BaseURL`.

The key file must be a regular file, not a symlink, at most 4 KiB, and have exactly
`0600` permission bits on Unix. Surrounding whitespace (such as a final newline)
is removed from **file** credentials only. Direct/environment keys are not
trimmed. Key-file errors never contain its path or contents.

**Windows ACLs:** Unix mode checks do not enforce Windows security. Provision the
key file's ACL before startup: disable inherited access, remove broad groups such
as Everyone/Users/Authenticated Users, and grant read access only to the identity
running the frontend (plus trusted administrators/SYSTEM as required). This
package does not claim to inspect or enforce Windows ACLs.

Configuration is trusted startup data, never tool input. Do not serialize or log
`Config`, credentials, or the client. Keep the key file outside `FilesRoot` and
exclude other secrets from that root; file tools intentionally can read any
allowed regular file inside it. Root ancestors and mount configuration must be
trusted. `os.Root` does not isolate hard links, bind mounts or filesystem mounts.

## HTTP contract and errors

- Only `/api/v1/projects`, `/api/v1/projects/{id}/notes`, `/api/v1/notes/{id}`
  and `/api/v1/notes/{id}/attachments` are used. No health checks or probes.
- HTTPS uses normal certificate validation. HTTP is permitted only for literal
  loopback IPs or the exact hostname `localhost` (case-insensitive), not arbitrary
  hostnames that happen to resolve to loopback. Base credentials, query strings,
  fragments and other paths are rejected.
- Bearer authentication is sent only in the authorization header. All redirects,
  including same-origin ones, are refused. The HTTP client has a 20-second total
  timeout and honors context cancellation. Response bodies are capped at 32 MiB
  after transparent decompression; response headers are capped at 1 MiB.
- IDs must match `store.NewID`: 32 lowercase hexadecimal characters.
- Lists decode the documented envelopes and normalize empty results to non-nil
  slices. Note lists decode directly into summaries, discarding Markdown.
  `sort=title` is preserved; other sort values normalize to `modified`, matching
  the server. Queries are encoded using `url.Values`.
- GET/POST/PUT notes decode flat objects and require a header ETag matching the
  returned positive version. The exact strong ETag is preserved. `Note.URL` is
  always the configured origin plus `/notes/{id}`: a private owner URL, never a
  public share URL. Body-supplied ETags/URLs are ignored.
- Create requires HTTP 201; update requires HTTP 200 and the caller's exact,
  canonical quoted `"vN"` ETag with positive int64 N. Update never fetches an ETag,
  retries, or changes sharing. Titles must be nonblank UTF-8 without NUL, at most
  300 Unicode code points; Markdown is UTF-8 without NUL, at most 2 MiB.
- Errors use locally curated messages, never server response bodies, URLs,
  transport error strings, secrets, or unvalidated request IDs. `*APIError`
  exposes `StatusCode` for status-specific handling. A 412 instructs the caller
  to refetch and **recompute** the edit. A 429 requires an explicit later attempt.
- There is no application retry loop or write-body replay hook. Transport,
  response-decoding and server failures on writes warn about an unknown outcome;
  inspect current state before explicitly retrying, especially POSTs, which
  could otherwise create duplicate notes or attachments.

## Local files

Paths are relative, slash-separated, at most 4096 bytes and must not contain
absolute paths, empty/dot/traversal components, backslashes, drive/ADS colons or
control characters. Symlink components and nonregular targets are rejected.
Directory handles are pinned and checked; all opens stay behind an `os.Root`
boundary. Unix final opens additionally use `O_NOFOLLOW | O_NONBLOCK`, followed by
regular-file/identity checks, preventing FIFO substitutions from blocking reads.
No files are created or modified. Only read-only descriptors and bounded in-memory
buffers are used.

`ReadMarkdown` accepts `.md`; `ReadSource` accepts `.md` or `.txt` (extensions are
case-insensitive). Both require UTF-8 without NUL, at most 2 MiB.

Uploads accept `.png`, `.jpg`, `.jpeg`, `.webp`, at most 10 MiB. The detected MIME
must match the extension; decoded image headers must satisfy the API's positive
dimensions, 20-million-pixel and 16000-pixels-per-side limits. The multipart body
contains one `file` field with the detected MIME and basename only. A successful
upload returns `{attachment, markdown}` without changing the note's Markdown or
ETag. Inserting the fragment requires an explicit, separately computed update.

Unit tests use only local temporary files and an in-memory HTTP transport. They
do not need a running API. Tests are intentionally not executed as part of this
implementation task.
