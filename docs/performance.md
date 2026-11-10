# Response-time investigation and optimization priorities

Measured on 2026-11-10. This is an operational investigation, not a browser-performance acceptance report.

## Confirmed incident: host connection-tracking exhaustion

The VPS kernel reported repeated `nf_conntrack: table full, dropping packet` messages. The tracking table held 65,535 entries against a 65,536-entry limit. This affected new connections independently of Go request processing, including loopback Docker connections and outbound registry access.

Before mitigation:

- A fresh-connection sample of 20 requests to `http://127.0.0.1:8096/login` included approximately 1-second TCP-connect delays, one approximately 2-second total response, and another approximately 1-second response delay. Normal requests took about 1–3 ms.
- External HTTPS samples included intermittent HTTP 504 and multi-second delays, even on `/login` and static CSS.
- Release attempts passed checks and image publication but failed at the VPS's GHCR pull, before replacing the application.
- Application/database memory usage was about 7/31 MiB respectively at one idle snapshot; neither container showed meaningful CPU usage. These snapshots are not capacity guarantees.

### Applied host change

Raised `net.netfilter.nf_conntrack_max` from **65536 to 262144** using `sysctl -w`, persisted in `/etc/sysctl.d/90-conspect-conntrack.conf`. The hash table already had 65,536 buckets. Existing flows were not flushed; no firewall allow/deny rules or connection timeouts were changed. Applying this setting required no Docker/nginx restart.

The observed conntrack slab object size was 320 bytes. An additional 196,608 objects would occupy approximately 60 MiB **before allocator/extension overhead**; this is not a hard memory bound. Available memory exceeded 850 MiB before the change. Track actual slab/memory usage as load changes.

The optional `conntrack` diagnostic package was installed to inspect aggregate flow counts. No payload capture, private note inspection, or credential extraction was needed. Network sampling captured only TCP SYN/SYN-ACK headers, not application payloads.

### Validation after mitigation

- 25 fresh loopback `/login` requests: median **2.24 ms**, maximum **5.08 ms**, no response over 500 ms.
- 40 fresh external HTTPS requests across `/healthz`, `/login`, app CSS and KaTeX JS: **all HTTP 200**. One CSS sample still exceeded 500 ms because its DNS lookup alone took about 428 ms; no multi-second upstream stall was observed in this sample.
- External `/login` median: approximately **199 ms**, including DNS, a fresh TCP/TLS connection, and network latency from the measuring machine. This is not a user-browser percentile.
- The subsequent Actions release of `eb2d851` succeeded, including its image pull and application readiness check. This supports a shared networking cause for the earlier pull failures, but the registry's raw error was intentionally not logged.

### Sustained load and limitations

The table grew beyond 65,536 once capacity was available, reaching roughly 140,000–150,000 entries during follow-up observations. Aggregate flow inspection identified a **different proxy workload**, not Conspect, as the dominant source: roughly 141,000 outbound TCP flows to port 8888, predominantly completed connections retained in `TIME_WAIT`/`CLOSE` tracking states. The unrelated workload was not reconfigured or restarted.

The larger limit resolves the demonstrated capacity bottleneck under the observed load; it does **not** remove the source of connection churn or guarantee future headroom. Monitor occupancy and kernel drops. If it approaches capacity again, investigate connection reuse and isolate the high-churn workload on a separate host/networking failure domain rather than repeatedly increasing limits or globally shortening TCP timeouts.

Read-only host checks:

```sh
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
free -m
conntrack -S
```

Also review kernel `table full` messages and conntrack slab usage locally. Never publish a raw `conntrack -L` dump: it contains other clients' network metadata. Alert before occupancy is sustained above roughly 75–80%, and watch available memory/drop counters alongside it.

For a reviewed rollback, remove the dedicated sysctl drop-in and restore the prior limit **only after count is safely below it and the churn is controlled**. Do not flush the tracking table, restart Docker, or lower the limit below live occupancy as a cleanup shortcut.

## Implemented application optimizations

- **Public static delivery:** the web handler prepares text gzip representations and strong representation-specific ETags once per process. The handler's tested KaTeX JS representation is **76,372 bytes gzip versus 273,081 bytes identity** (about 72% smaller). Reader templates use `/assets/reader/<bundle-sha256>/...`; CSS-relative font references stay inside the same bundle. Current versioned reader assets and the matching versioned app stylesheet use `public, max-age=31536000, immutable`. Legacy/unversioned or mismatched-query CSS URLs revalidate (`public, no-cache`). Old bundle paths and directory listings are not served. Conditional GET/304, HEAD, encoding exclusions and byte ranges are covered by tests. Private HTML, note/API/image responses and authorization retain `no-store`; no generic response cache or dynamic compression was added.
- **Bounded code-fragment reuse:** each reusable Renderer retains at most 8 MiB of payload/keys and 512 entries, plus list/map overhead. LRU eviction and singleflight bound retained data and coalesce identical concurrent work. Entries depend on language/source digest, contain no attachment URLs or complete notes, and vanish on process replacement. The full Markdown pipeline still sanitizes every output and reevaluates attachment authorization on every call.
- **Per-document highlighting budget:** the existing 128 KiB per-block limit is also a total 128 KiB source budget per document. Later blocks remain intact escaped plain code rather than consuming more highlighting CPU/output expansion. Hits use the same budget as misses so cache history never changes output. This is a visible styling tradeoff for code-heavy documents, not truncation of source.

Local single-CPU synthetic benchmarks (three runs of five operations each) compared identical documents with fragment caching disabled versus warmed:

| Mode | Time per complete render | Cumulative allocations per render |
| --- | --- | --- |
| No fragment reuse | 145–186 ms | 47.3 MB |
| Warm fragment cache | 42–45 ms | 10.4 MB |

These are developer-machine measurements, not production response percentiles or peak resident memory. Sanitization still accounts for much of the remaining work. A cold unique block must still be highlighted; reuse is not a universal speedup.

## Remaining optimization priorities

1. **Transport:** consider HTTP/2 on the specific nginx site if supported; this change does not reload nginx or alter unrelated vhosts. Measure browser LCP/INP and cold/repeated navigation, not just curl response time.
2. **Library/project lists.** `Store.Notes` fetches full Markdown bodies with no pagination, even for browser lists that display titles/dates only. Separate metadata-only browser queries and paginate before optimizing search indexes. Preserve the existing REST/MCP response contract. Verify query plans and actual collection sizes before adding speculative indexes.
3. **API batching and bookkeeping.** Note listings can perform two additional SQL statements per note to enumerate attachments, and each API-key authentication updates `last_used_at` under a row lock. Batch authorized attachment metadata and coalesce bookkeeping updates if measured traffic justifies it. Never cache away authoritative expiration/revocation checks or transactional authorization for writes.
4. **Measure the actual slow interaction.** Add bounded aggregate timings by route pattern for DB acquisition/query, render and total response; never log SQL parameters, note contents, tokens or full share URLs. Browser LCP/INP, authenticated page latency, client-side formula rendering and production query plans were **not measured** in this investigation. Distinguish cold navigation, repeat navigation and form submission before selecting the next change.

The host incident mitigation and these application optimizations are separate. SQL semantics, authorization behavior, runtime memory limits and worker counts are unchanged. Whole-note/page caching remains deliberately absent: note version alone would not invalidate attachment changes or owner/share-specific URLs.
