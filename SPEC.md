# Loghound — MASTER SPEC v1

> **Solr-based traffic analytics and bot forensics for Apache, nginx and Caddy.**

Every agent working on this repo MUST read this file in full and treat it as binding.
Field names, file paths, and function signatures below are CONTRACTS. Do not rename,
do not "improve" them, do not invent parallel ones. If something here is wrong, say so
in your report — do not silently diverge.

---

## 0. What this is, and what makes it different

Two things, and only two things, are the reason this project exists:

1. **It is the best bot detector available for web logs.** Not "it filters known crawler
   User-Agents" — every tool does that and it catches nothing. It detects *headless Chrome
   on rotating residential proxies*, which is what modern scraping actually looks like and
   what every existing analytics product silently counts as human traffic.

2. **It measures real time-on-site.** Not "the page was loaded for 7 minutes" (which is what
   Clicky, GA and everything else report, and which is wrong the moment a tab is left open in
   the background). Actual **visible** time and actual **engaged** time, including the last
   page of the session, which log-only tools structurally cannot see.

Everything else — charts, geo, facets — is table stakes. If a design decision trades away
accuracy on those two things for convenience anywhere else, the answer is no.

### The three-plane model

Detection happens on three independent planes. The power is in **correlating** them; each
plane alone is defeatable and every existing tool uses exactly one.

| Plane | Source | Sees |
|---|---|---|
| **1. Transport** | webserver access log | headers, ASN, rDNS, protocol, status, timing |
| **2. Behavior** | correlation across log lines | asset ratio, cache behaviour, session shape, inter-request timing, cross-IP fingerprint clusters |
| **3. Execution** | our own JS beacon | does JS run at all, does the engine match the UA's claim, is a human driving |

**The verdict matrix — this is the core idea of the product:**

| Plane 1 (log) | Plane 3 (beacon) | Verdict |
|---|---|---|
| HTML 200 served | no beacon ever arrived | `bot` — non-JS client, certain |
| HTML 200 served | beacon arrived, headless signals positive | `bot` — headless automation, certain |
| HTML 200 served | beacon arrived, zero interaction, left < 15s | `likely_bot` |
| HTML 200 served | beacon + interaction + plausible timing distribution | `human` |

GoAccess/AWStats only ever see plane 1. Clicky/GA/Plausible/Matomo-JS only ever see plane 3,
and they *trust* it. Loghound sees all three and cross-checks them. A scraper must now defeat
all three simultaneously, and defeating plane 3 without defeating plane 2 is what gives it away.

---

## 1. Non-negotiables

### Security
This application parses hostile input by definition. Log lines contain attacker-controlled
paths, User-Agents and referers; the beacon endpoint is a public, unauthenticated write path.

- **Output escaping is mandatory and contextual.** HTML → `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`.
  JS context → `json_encode($s, JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT)`.
  URL attribute → validated scheme allowlist (`http`, `https` only). Never echo a raw log field.
- **Client-side**: any `innerHTML` fed from Solr data must go through the project's `esc()`
  helper. Prefer `textContent`. No `eval`, no `new Function`, no `innerHTML` of raw API data.
- **Solr injection**: user text is NEVER spliced into `q`/`fq`/`sort`/`fl`. Bound params only
  (`{!edismax v=$uq}` + `uq=<text>`). `rows`/`start` clamped to hard maxima. Field names for
  sort/facet must pass an allowlist. Never accept caller-supplied `shards`, `qt`, `wt`,
  `stream.*`, `distrib`.
- **No raw Solr passthrough.** The panel talks to Solr only through `src/Solr.php`, which
  builds every request server-side. There is no "proxy this query to Solr" endpoint. Ever.
- **Shell**: `escapeshellarg()` on every argument, always. Prefer no shell at all.
- **Paths**: any filesystem path from config is resolved with `realpath()` and checked against
  an allowlist of permitted roots. `basename()` on anything that becomes a filename.
- **ReDoS**: a user-supplied regex is untrusted. Enforce `pcre.backtrack_limit` and a wall-clock
  timeout per line; a pattern that exceeds it is rejected at save time, not at ingest time.
- **CSRF** token on every state-changing panel request. **HTTP auth or session auth** on the
  whole panel, configurable, default deny.
- **Beacon anti-forgery**: see §6. The collector must never trust client-supplied timings blindly.
- **Privilege**: daemons run as user `loghound`, member of group `adm` (log read). Never root.
  The systemd units set `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`.
- **Secrets** (Opensolr API key, HMAC secret) live in `config/loghound.php` mode `0640`,
  outside the docroot. Never in the repo, never in a public path, never logged.

### Privacy
- IP storage mode is configurable: `full` | `truncate` (v4 /24, v6 /48) | `hash` (rotating daily salt).
  Default `full` for self-hosters, but the setting must be prominent in setup.
- Configurable retention with a real deletion job, not just docs saying you should.
- No cookies set by the beacon by default (visitor identity is a derived fingerprint hash,
  documented as such). A cookie mode may be offered but must be opt-in.

### Correctness
- Never fabricate a metric. If `engaged_ms` is unknown because no beacon arrived, the field is
  ABSENT, not zero. Every aggregate must state which population it covers.
- `bot_score_f` must always be accompanied by `bot_reasons_ss`. An unexplainable verdict is a bug.

---

## 2. Stack

- **PHP 8.1+**, zero Composer dependencies. Everything uses ext-curl, ext-json, ext-pcre,
  ext-sqlite3, ext-mbstring. This is deliberate: `git clone` + `install.sh` must work on a
  bare box with no toolchain.
- **Solr 9.x** (dev target: Solr 9.6 on Opensolr).
- **Frontend**: vanilla JS, no build step. **ECharts 5.x self-hosted** in `public/assets/vendor/`.
  No CDN — the panel must work on an air-gapped box.
- **State**: SQLite at `var/state.db` (tail offsets, open sessions, whois cache, rate limits).
- **License**: MIT.
- **Indentation: 4 spaces. Single quotes in PHP. PSR-12.**
- **Every function gets a doc comment saying what it does and why. Every non-obvious line gets
  an inline comment.** This is a public repo people will read to decide whether to trust it.

---

## 3. Repository layout (CONTRACT)

```
loghound/
  bin/
    loghound-tail          # daemon: tail → parse → enrich → sessionize → index
    loghound-score         # periodic: close sessions, score, roll up
    loghound-setup         # CLI: detect logs, provision Solr, write config
    loghound-retention     # periodic: delete-by-query past retention
  src/
    Config.php             # config load/save/validate
    Solr.php               # Solr HTTP client (curl). ALL Solr access goes through this.
    Security.php           # esc(), csrf(), auth(), safe_path(), clamp()
    State.php              # SQLite: offsets, open sessions, caches
    LogFormat.php          # LogFormat/log_format string → compiled parser
    LogDetect.php          # discover config files + log files, detect format
    Parser.php             # line → normalized hit array
    Enrich/Geo.php         # ip-to-location via Opensolr, Cymru country floor, tz from country
    Enrich/Asn.php         # ASN + netblock org + country via Team Cymru + RIR whois, cached
    Enrich/Ua.php          # UA → browser/os/device + bot classification
    Sessionizer.php        # hit → session_id, running session state
    Score/Signals.php      # extract individual signals from a hit/session
    Score/Rules.php        # weighted ruleset → bot_score_f + bot_reasons_ss
    Beacon.php             # beacon payload validation, HMAC, active-time merge
    Panel/                 # controllers for the web panel
  public/
    index.php              # front controller (panel) — auth-gated
    collect.php            # beacon collector — public, rate-limited, hardened
    b.js                   # the beacon (served with cache headers + version query)
    assets/
  solr/
    hits/conf/             # managed-schema + solrconfig.xml
    sessions/conf/
  install/
    install.sh
    loghound-tail.service
    loghound-score.service loghound-score.timer
    loghound-retention.service loghound-retention.timer
    apache-vhost.conf.example
    nginx-vhost.conf.example
  docs/
    INSTALL.md             # install, the recommended LogFormat, header-by-header value
    DETECTION.md           # the three planes, every rule, worked examples, evasion
    SECURITY.md            # threat model, controls by surface, hardening
    PRIVACY.md             # what is collected, IP modes, retention, GDPR posture
    SCHEMA.md              # the operator-facing version of §4, with size arithmetic
    BEACON.md              # the beacon: clocks, signal codes, wire protocol
    PANEL.md               # the web panel: request flow, review notes, demo mode
  config/
    loghound.example.php
  tools/
    panel-preview.php      # throwaway config so the panel can be looked at without Solr
  tests/
    fixtures/              # real log lines, one file per format
    helpers.php            # assertion helpers, auto-loaded
    run.php                # dependency-free test runner
  .htaccess                # deny rules for anyone who serves the tree from the repo root
  SPEC.md  README.md  CONTRIBUTING.md  LICENSE  CHANGELOG.md
```

There is no `docs/API.md`: there is no public HTTP API to document. The panel's `?api=`
endpoints are internal to it and are described in `docs/PANEL.md`; the only public write
path is `public/collect.php`, whose wire protocol is in `docs/BEACON.md` §5.

---

## 4. Solr schema (CONTRACT — exact field names)

Two cores. **Disk discipline is a hard requirement**: default to `stored=false` and rely on
docValues for retrieval. Only the fields marked STORED below are stored.

`omitNorms=true` on every string field. `omitTermFreqAndPositions=true` unless the field feeds
the catchall. **Delete the stock `_text_` catchall from the configset** — it silently doubles
the index and nothing uses it.

### 4.1 Core `hits` — one doc per log line

**Identity / time**
| Field | Type | I | DV | S | Notes |
|---|---|---|---|---|---|
| `id` | string | ✓ | | ✓ | `sha1(file+offset)` — idempotent re-ingest |
| `ts` | pdate | ✓ | ✓ | ✓ | request time, UTC |
| `host_s` | string | ✓ | ✓ | | vhost (`%v`) |
| `src_s` | string | ✓ | ✓ | | which log file this came from |

**Network**
| `ip_s` | string | ✓ | ✓ | ✓ | subject to privacy mode |
| `ip_ver_i` | pint | | ✓ | | 4 or 6 |
| `ip_net_s` | string | ✓ | ✓ | | /24 or /48 — cluster key |
| `asn_i` | pint | ✓ | ✓ | | |
| `as_org_s` | string | ✓ | ✓ | ✓ | |
| `as_type_s` | string | ✓ | ✓ | | `isp`\|`hosting`\|`vpn`\|`edu`\|`gov`\|`mobile`\|`unknown` |
| `netname_s` | string | ✓ | ✓ | | RIR netname — catches leased ranges |
| `rdns_s` | string | ✓ | ✓ | | |
| `rdns_ok_b` | boolean | ✓ | ✓ | | forward-confirmed rDNS passed |
| `country_s` `region_s` `city_s` | string | ✓ | ✓ | | Opensolr geolocation. `country_s` falls back to Team Cymru's `CC`, which arrives free with the ASN lookup, so the country survives the geolocation endpoint being off or down. May be a registry pseudo-code (`EU`) when that is what the registry says. |
| `geo_p` | location | ✓ | | | lat,lon. **ABSENT when the service returned only a country-level centroid** (MaxMind's `37.751,-97.822`) with no city, and absent for `0,0` and out-of-range pairs. A false point is worse than no point. |
| `tz_s` | string | ✓ | ✓ | | IANA tz. From the geolocation service when it names one, otherwise **derived from `country_s`** for the 216 territories that have exactly one IANA zone. Absent for a multi-zone country (US, RU, CA, AU, BR, DE, …) unless the service named a zone — guessing one would make `tz_mismatch` fire on innocent traffic. |

**Request**
| `method_s` | string | ✓ | ✓ | | |
| `path_s` | string | ✓ | ✓ | ✓ | exact path, no query |
| `path_depth_i` | pint | | ✓ | | |
| `query_s` | string | | | ✓ | STORED only |
| `proto_s` | string | ✓ | ✓ | | `HTTP/1.1`, `HTTP/2` |
| `status_i` | pint | ✓ | ✓ | ✓ | |
| `bytes_l` | plong | | ✓ | | |
| `dur_us_l` | plong | | ✓ | | from `%D`, absent if not logged |
| `kind_s` | string | ✓ | ✓ | | `html`\|`asset`\|`api`\|`beacon`\|`robots`\|`favicon`\|`other` |
| `asset_kind_s` | string | ✓ | ✓ | | `js`\|`css`\|`img`\|`font`\|`media` |

**Client**
| `ua_s` | string | ✓ | ✓ | ✓ | raw UA |
| `ua_hash_s` | string | ✓ | ✓ | | sha1 of raw UA |
| `browser_s` `browser_ver_i` `os_s` `device_s` | | ✓ | ✓ | | `device_s`: `desktop`\|`mobile`\|`tablet`\|`bot`\|`unknown` |
| `ua_bot_b` | boolean | ✓ | ✓ | | UA self-declares as a bot |
| `ua_bot_name_s` | string | ✓ | ✓ | | |
| `ua_bot_cat_s` | string | ✓ | ✓ | | `search`\|`ai`\|`seo`\|`monitor`\|`security`\|`social`\|`other` |
| `ai_crawler_b` | boolean | ✓ | ✓ | | GPTBot, ClaudeBot, PerplexityBot, Bytespider, Amazonbot, meta-externalagent, Applebot-Extended, CCBot, Diffbot, Omgili, cohere-ai, ImagesiftBot, YouBot, Timpibot, Webzio |

**Headers (present only when the operator logs them — ABSENT, never empty-string, if not)**
| `referer_s` | string | ✓ | ✓ | ✓ | |
| `referer_host_s` | string | ✓ | ✓ | | |
| `referer_type_s` | string | ✓ | ✓ | | `direct`\|`search`\|`social`\|`ai`\|`internal`\|`link`\|`ad` |
| `accept_s` `accept_lang_s` `accept_enc_s` | string | ✓ | ✓ | | |
| `sec_ch_ua_s` `sec_ch_platform_s` | string | ✓ | ✓ | | |
| `sec_ch_mobile_b` | boolean | ✓ | ✓ | | |
| `sec_fetch_site_s` `sec_fetch_mode_s` `sec_fetch_dest_s` `sec_fetch_user_s` | string | ✓ | ✓ | | |
| `xff_s` | string | ✓ | ✓ | | |
| `tls_proto_s` `tls_cipher_s` | string | ✓ | ✓ | | |
| `ja4_s` | string | ✓ | ✓ | | v2, HAProxy-sourced; leave the field defined |

**Fingerprints & session**
| `fp_hash_s` | string | ✓ | ✓ | | **THE cluster key.** sha1 of the normalized header tuple: ua + accept + accept_lang + accept_enc + sec_ch_ua + sec_ch_platform + sec_fetch_* + proto. Excludes IP by design — that is the point. |
| `session_id_s` | string | ✓ | ✓ | ✓ | assigned at ingest |
| `session_seq_i` | pint | | ✓ | | 1-based position within session |
| `visitor_s` | string | ✓ | ✓ | | stable-ish visitor hash (ip_net + ua_hash + accept_lang), daily-salted in `hash` privacy mode |

**Provisional verdict (final verdict lives on the session doc)**
| `hit_flags_ss` | strings | ✓ | ✓ | ✓ | multi-valued signal codes fired by this single hit |

**Raw**
| `raw_s` | string | | | ✓ | STORED, **NOT INDEXED**. Enables retroactive rescoring. Config toggle `keep_raw` (default true) — document that it roughly doubles index size. |

**Catchall** — `text_all`, `indexed=true, stored=false`, fed by copyField from `path_s`,
`ua_s`, `referer_s`, `as_org_s`, `netname_s`, `country_s`, `city_s`, `rdns_s`.
Config toggle `catchall` (default **on**), documented as the first thing to turn off at high volume.
Query it with **edismax**, `qf = path_txt^3 ua_txt^2 as_org_txt^2 netname_txt^2 rdns_txt city_txt country_txt`.

### 4.2 Core `sessions` — one doc per session (this is what the dashboard queries)

`id` = `session_id`. Everything docValues; store only what the drill-down shows.

Rollup: `ts_start` (pdate), `ts_end` (pdate), `hits_i`, `pages_i`, `assets_i`, `uniq_paths_i`,
`bytes_l`, `status_2xx_i` `_3xx_i` `_4xx_i` `_5xx_i`, `got_304_b`, `entry_path_s`, `exit_path_s`,
`paths_ss` (capped at 50), plus every identity/network/client field copied from the first hit.

**Timing — the differentiator. Four distinct numbers, never conflated:**
| `log_span_ms_l` | last request minus first request. What log-only tools call "time on site". |
| `wall_ms_l` | beacon: page open wall-clock, summed across pageviews. What Clicky/GA report. |
| `visible_ms_l` | beacon: time `document.visibilityState === 'visible'` **and** the window focused. |
| `engaged_ms_l` | beacon: time within 30s of a real interaction while visible. **The honest number.** |

`beacon_b` — did any beacon arrive at all. **Absent timing fields when false. Never zero-fill.**

Behavioural: `gap_p50_ms_l`, `gap_stddev_ms_l`, `asset_ratio_f`, `interactions_i`,
`max_scroll_pct_i`, `pageviews_i`.

Execution plane (from beacon, see §6): `js_b`, `headless_b`, `automation_ss`,
`ua_claim_ok_b`, `tz_match_b`, `webgl_s`, `client_score_f`.

Cluster: `fp_hash_s`, `fp_ips_24h_i` (how many distinct IPs shared this fingerprint in ±12h —
computed by the scorer via a Solr facet, **the single strongest signal against proxy fleets**).

Verdict: `bot_score_f` (0–100), `bot_verdict_s`
(`human`|`likely_human`|`unknown`|`likely_bot`|`bot`), `bot_reasons_ss`, `rule_version_i`,
`bot_class_s` (`headless`|`scripted`|`declared_crawler`|`ai_crawler`|`monitor`|`spoofed_ua`|`proxy_fleet`|`none`).

**`provisional_b` — the session has not ended yet.**

A session document is written for an OPEN session too, on every scorer run, so the dashboard
shows traffic within a minute of ingestion starting rather than after `session_idle_sec` (30
minutes). It is written under the session's own id, so the final document REPLACES it when the
session closes; there is never a second document for the same session.

| | |
|---|---|
| Value | `true` on an open session. **ABSENT on a settled one — never written as `false`.** |
| Settled population | `-provisional_b:true`. This is the only correct form: it also matches every session indexed before the field existed. `provisional_b:false` would exclude a site's entire history. |
| Provisional population | `provisional_b:true` |
| Counts | `hits_i`, `pages_i`, `assets_i`, `uniq_paths_i`, `bytes_l`, `status_*`, `log_span_ms_l`, `paths_ss` are **partial** — what has been logged so far, not what the session will amount to. |
| Verdict | Reached with the five absence-based rules **not evaluated** (§7), and **floored at `unknown`**: a provisional verdict may never be `human` or `likely_human`. |
| Rollups | Excluded. Daily rollups count settled sessions only (§4.2 rollup block). |

---

## 5. Ingestion pipeline

`bin/loghound-tail` runs as a systemd daemon (NOT cron — cron's floor is 60s and he wants live).

1. **Tail**: for each configured log file keep `(dev, inode, offset)` in SQLite. On each poll
   (default 1s) read new bytes. **Logrotate handling is mandatory and is the #1 source of silent
   data loss**: if inode changed, drain the OLD inode to EOF first, then switch. Handle
   truncation (size < offset → restart at 0). Handle `.1`/`.gz` appearing.
2. **Parse** via the compiled parser for that file's format. A line that fails to parse is
   counted in `parse_errors` and sampled to `var/badlines.log` (capped) — never silently dropped.
3. **Enrich**: geo (Opensolr geolocation endpoint, authenticated with the account's own
   `opensolr.email` / `api_key`, cached per address in SQLite ≥30d, with Team Cymru's `CC` as
   the country of last resort and `tz_s` derived from a single-zone country), ASN/netname
   (Cymru + whois, cached per netblock ≥30d), UA parse, rDNS + forward confirm (cached, ≥7d).
   All caches are negative-caching too. Enrichment failure never blocks indexing — the field is
   simply absent, a transport failure is not negative-cached as if it were an answer, and a run
   of them trips a breaker so a dead endpoint costs a bounded number of timeouts rather than
   one per address.
4. **Sessionize**: `client_key = ip_net + ua_hash`. 30-min idle timeout (configurable).
   Open sessions live in SQLite. `session_id = sha1(client_key + first_ts + random)`.
5. **Index** into `hits` in batches (default 500 docs / 2s, whichever first).
   **`softCommit` only. Never `commit=true` per batch.** Core config:
   `autoSoftCommit maxTime=5000`, `autoCommit maxTime=60000 openSearcher=false`.

`bin/loghound-score` runs every 60s via systemd timer:
1. Close sessions idle > timeout, and collect the OPEN sessions whose aggregate has advanced
   since they were last published (§4.2 `provisional_b`). Without the second half the panel is
   empty for the whole idle timeout on a fresh install, which reads as a broken product.
2. Merge beacon data for those sessions (§6). Staged rows are marked merged only for sessions
   that CLOSED — a provisional merge must not consume the only copy of the beacon data.
3. Compute `fp_ips_24h_i` via one JSON Facet query per distinct fingerprint in the batch.
4. Run `Score/Rules.php` → verdict + reasons. Open sessions are scored under the provisional
   gate (§7).
5. Upsert the `sessions` doc — same id whether provisional or final, so a close overwrites.
6. Write the daily rollup doc, over SETTLED sessions only, for the days the CLOSED batch
   touched. A run that published nothing but provisional documents rebuilds no rollup.

**Cost bound.** The provisional half of a run is bounded by `PROVISIONAL_BATCH` (500) documents,
and by dirty tracking: a session is republished only when it has logged a new hit since its last
publication, so steady-state cost tracks the REQUEST rate, not the accumulated open-session
population. Ten thousand idle open sessions cost nothing; the bound bites only above ~8
newly-active sessions per second, and a session whose provisional refresh is deferred still gets
its final document the moment it closes.

---

## 6. The beacon (`public/b.js`) — plane 3

Served from our own vhost. Sites embed one line. **No dependencies, no build step.**

Size, measured rather than aspired to: `public/b.js` ships as commented source — there is
no minifier in the project, because there is no build step (§2) — which is roughly 33 KB on
disk and **about 12 KB over the wire** once the vhost gzips it, which both shipped vhost
examples do. An earlier draft of this spec asked for "under 6 KB minified"; that target was
never met and is not compatible with the rule that every non-obvious line carries an inline
comment. Readable source that a site owner can audit before embedding it is the better
trade. If it ever needs to shrink, minify at release time — never by deleting comments from
the file people read.

### 6.1 Time measurement — get this exactly right

Three clocks, never conflated:

- `wall_ms` — `performance.now()` delta since page start. Runs regardless of visibility.
- `visible_ms` — accumulates ONLY while `document.visibilityState === 'visible'` AND
  `document.hasFocus()`. Pause/resume on `visibilitychange`, `blur`, `focus`.
- `engaged_ms` — accumulates only while visible AND the last interaction was < 30s ago.
  Interactions: `mousemove` (throttled 1/s), `scroll`, `keydown`, `click`, `pointerdown`,
  `touchstart`, `wheel`. **Passive listeners, throttled — the beacon must not cost jank.**

**Flush strategy** — this is what lets us measure the LAST page, which log-based tools cannot:
- Heartbeat every 15s while `engaged_ms` is advancing (so a killed tab keeps data to the last beat).
- `navigator.sendBeacon()` on `visibilitychange → hidden` and on `pagehide`. Never `unload`.
- Use monotonic `performance.now()` deltas throughout; never `Date.now()` for durations
  (wall-clock jumps and NTP steps would corrupt it).

### 6.2 Execution-plane signals (collect ALL of these)

Report as `automation_ss` codes. Each is a string code; the server scores them.

**Definitive automation markers**: `navigator.webdriver === true`; `window.cdc_` /
`$cdc_asdjflasutopfhvcZLmcfl_` (chromedriver); `window.__nightmare`, `__phantomas`,
`_phantom`, `callPhantom`; `window.__playwright*`, `__puppeteer*`, `__selenium*`,
`document.$cdc_`; `window.domAutomation`, `domAutomationController`.

**Headless-Chrome tells**: WebGL `UNMASKED_RENDERER` matching `SwiftShader|llvmpipe|Mesa
OffScreen|Microsoft Basic Render` ; `navigator.plugins.length === 0` on a desktop UA;
`navigator.languages` empty or absent; `window.outerHeight === 0` or `outerWidth === 0`;
`Notification.permission === 'denied'` while `navigator.permissions.query({name:'notifications'})`
returns `prompt` (the classic headless contradiction); missing `window.chrome.runtime` on a
Chrome UA; `screen.availWidth === screen.width && screen.availHeight === screen.height` combined
with other tells; zero device memory / hardwareConcurrency anomalies.

**UA-claim verification — cheap and near-definitive.** The UA claims a Chrome major version.
Test whether the engine actually has features that shipped in that version, and whether it has
features that shipped *after* it. A spoofed UA cannot retrofit V8. Report `ua_claim_ok_b` plus
the specific mismatch code. Maintain a small table of `chrome_version → feature probe` in b.js
(keep it to ~8 probes across a wide version span; document how to extend it).

**Consistency cross-checks**: `Intl.DateTimeFormat().resolvedOptions().timeZone` vs the
IP-derived timezone (`tz_s`) → `tz_match_b`. `navigator.platform` / `userAgentData.platform`
vs the UA's OS claim. Touch support vs a mobile UA claim. `devicePixelRatio` vs claimed device.
`screen` dimensions vs `window.outer*` sanity.

**Human-presence evidence** (absence is itself a signal): count of distinct interaction types,
mousemove entropy (do coordinates vary naturally or move in straight lines / not at all),
max scroll depth, whether any scroll happened on a page taller than the viewport.

### 6.3 Collector (`public/collect.php`) — public write path, treat as hostile

- Accepts POST only, `Content-Type: text/plain` (sendBeacon default) or JSON. Size cap 8 KB.
- **HMAC token**: the beacon's first call gets a token `HMAC(secret, session_id|issued_at)`.
  Subsequent calls must present it. Reject missing/invalid/expired (> 12h) tokens.
- **Timing sanity**: reject or clamp `engaged_ms > visible_ms`, `visible_ms > wall_ms`, and
  `wall_ms > (now - token_issued_at + 60s slack)`. A client claiming 4 hours of engagement 30
  seconds after being issued a token is lying — record `beacon_forged` as a bot signal rather
  than discarding, because the lie is itself evidence.
- **Never trust client-supplied** IP, UA, host, or referer. Read them from the connection.
- Rate limit per IP (SQLite token bucket, default 120 req/min) and per session.
- Respond `204` always, with no body — never leak whether a token was valid.
- The collector writes to a `beacon` staging table in SQLite; `loghound-score` merges it into
  the session doc. The collector itself must NOT touch Solr (keeps the public path cheap and
  keeps Solr credentials out of the request path).

### 6.4 Correlating beacon ↔ log

The beacon sends `session_id` only after the server issues it. First hit: the collector derives
the same `client_key` (ip_net + ua_hash) the tailer uses, and matches to the open session in
SQLite. Where a log line and a beacon disagree, **the log wins on facts** (IP, UA, path, status)
and **the beacon wins on time** (visible/engaged). Record `beacon_orphan_b` when a beacon has no
matching log session — that combination is itself suspicious and worth surfacing.

---

## 7. Scoring (`src/Score/Rules.php`)

Weighted additive, 0–100, with an explicit reason code for every point added. **A verdict with
no reasons is a bug.** Config-overridable weights. `rule_version_i` bumped on every change so
historical rescoring is traceable.

Suggested starting weights (tune against real data, document the tuning):

| Code | Weight | Condition |
|---|---|---|
| `automation_marker` | 100 | any definitive marker from §6.2 |
| `headless_renderer` | 90 | SwiftShader/llvmpipe/Mesa OffScreen |
| `ua_claim_failed` | 85 | engine features contradict the claimed Chrome version |
| `no_js_on_html` | 70 | HTML 200 served, no beacon ever, and UA claims a real browser |
| `fp_cluster_proxy_fleet` | 80 | `fp_ips_24h_i >= 5` and `as_type_s != mobile` |
| `ua_secch_mismatch` | 75 | Sec-CH-UA absent or contradicting a Chrome UA claim |
| `platform_mismatch` | 70 | Sec-CH-UA-Platform vs UA OS |
| `rdns_claim_failed` | 95 | declares itself Googlebot/Bingbot etc, forward-confirmed rDNS fails |
| `hosting_asn_browser_ua` | 45 | `as_type_s=hosting` with a consumer-browser UA |
| `tz_mismatch` | 35 | browser timezone vs IP geo timezone |
| `no_interaction` | 40 | beacon arrived, zero interactions, session ended |
| `no_304_on_repeat` | 30 | revisited assets, never sent a conditional request |
| `periodic_timing` | 45 | `gap_stddev_ms_l` below threshold across ≥4 requests |
| `single_page_10s` | 15 | 1 page, ≤10s — weak alone, meaningful stacked |
| `no_assets` | 25 | HTML fetched, zero sub-resources |
| `beacon_forged` | 90 | timing claims impossible against the token |
| `ua_declared_bot` | 100 | honest self-declaring crawler — verdict `bot`, class `declared_crawler`/`ai_crawler`, **not** a threat |

Thresholds: `>=80 bot`, `60–79 likely_bot`, `40–59 unknown`, `20–39 likely_human`, `<20 human`.

**Scoring a session that has not ended (`provisional_b`, §4.2).**

Five of the seventeen rules fire on the ABSENCE of something a session may still go on to do,
and every one of them would accuse a live human visitor:

| Deferred code | What its absence means while the session is open |
|---|---|
| `no_js_on_html` | the beacon reports on pagehide — a visitor still reading has not sent one |
| `no_assets` | the sub-resource log lines have not been written yet |
| `no_304_on_repeat` | nothing has been re-fetched yet, and no 304 has arrived yet |
| `no_interaction` | the visitor has not scrolled or clicked **yet** |
| `single_page_10s` | every session is one page and under ten seconds at second one |

So a provisional verdict rests only on evidence already PRESENT in the log, and it is
**floored at `unknown`**: it may reach `likely_bot` or `bot` on positive evidence — all seven
decisive-alone rules are presence-based, so `navigator.webdriver` is still called immediately —
but it may never claim `human` or `likely_human`, because "nothing incriminating yet" on one
request is not an acquittal. When the floor applies, `bot_reasons_ss` carries the pseudo-code
`provisional_session` so the verdict still explains itself, exactly as `no_bot_signals` does.

`rule_version_i` is NOT bumped for this. A CLOSED session's verdict is unchanged, byte for
byte; the discriminator is per-document (`provisional_b`) and not per-ruleset, and bumping
would send a rescoring pass over all of history to no effect.

**Honest crawlers are not the enemy.** GPTBot/Googlebot get `bot` + their class, and the UI
must present declared crawlers separately from evasive ones. Conflating them is what makes
existing tools useless.

---

## 8. Log format handling — setup must be effortless

**Default: works out of the box on Apache with zero configuration.**

Detection ladder, in this order:

1. **Read their webserver config.** Parse `/etc/apache2/apache2.conf`, `httpd.conf`,
   `sites-enabled/*` for `LogFormat` definitions and `CustomLog <path> <name>` pairs; parse
   nginx `log_format` + `access_log`. This yields the exact parser, the exact file list, AND
   the vhost each file belongs to. **Deterministic — no guessing.** This is the headline
   setup feature.
2. **Known-format library** when configs are unreadable. Score the last 200 lines of each
   candidate file against every known format; pick the highest full-parse rate. Formats:
   apache `combined`, `vhost_combined`, `common`; nginx `combined`, nginx+XFF; Caddy JSON;
   HAProxy http-log; AWS ALB; CloudFront; Traefik JSON; Kubernetes ingress-nginx.
   Structural scoring, not regex-luck: field 1 must parse as an IP, the bracketed field as a
   date, the status as 3 digits, etc.
3. **Generate a candidate** from the sample when nothing matches (tokenize, propose).
4. **Custom regex with named groups** as the escape hatch. ReDoS-guarded (§1).

**Always show the mapping and require confirmation**: a table of detected-field → Loghound
field, five sample lines rendered as parsed records, a confidence percentage, and one
"Looks right" button. Never silently ingest with a guessed format.

`LogFormat.php` compiles a format string to a parser. Support at minimum: `%h %l %u %t %r %s
%>s %b %O %D %T %v %p %H %m %U %q %{VARNAME}i %{VARNAME}o %{VARNAME}x %{VARNAME}e`, and the
nginx `$variable` equivalents. **JSON log formats are first-class**, not an afterthought.

### Recommended LogFormat (ship this, document it prominently)
The detection quality ceiling is set by what gets logged. `docs/INSTALL.md` must give a
copy-paste block and be honest that plain `combined` gives a weaker (but still working) result:

```
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O %D \"%{Referer}i\" \"%{User-Agent}i\" \
\"%{Accept}i\" \"%{Accept-Language}i\" \"%{Accept-Encoding}i\" \
\"%{Sec-CH-UA}i\" \"%{Sec-CH-UA-Platform}i\" \"%{Sec-CH-UA-Mobile}i\" \
\"%{Sec-Fetch-Site}i\" \"%{Sec-Fetch-Mode}i\" \"%{Sec-Fetch-Dest}i\" \"%{Sec-Fetch-User}i\" \
\"%{X-Forwarded-For}i\" \"%H\" \"%{SSL_PROTOCOL}x\" \"%{SSL_CIPHER}x\"" loghound
```

---

## 9. Opensolr integration

Setup asks no question about where the index lives. **An Opensolr account is a hard
requirement**: Loghound provisions and manages its own two indexes there — creating them,
uploading their configsets, reloading the cores and verifying them — and it cannot do that on
a Solr it does not administer, so there is no bring-your-own-Solr path. (There was one; it was
removed for exactly that reason.)

Email + API key → app calls
`https://opensolr.com/solr_manager/api/create_index?email=&api_key=&index_name=&region=`
(region list from `.../api/regions`), then pushes the configset, then verifies.

The user sees only: `Index created ✓` / `Rebuilt ✓` / `Healthy ✓`, plus copy telling them
backups, downloads and restores are available in their Opensolr control panel. They never need
to learn what a configset is. **Never print the API key back to the screen or into a log.**

`solr.base_url`, `solr.http_user` and `solr.http_pass` are filled in from what the platform
returns, and `src/Solr.php` is mode-agnostic: it talks to a node it has credentials for and does
not care how they got there. No form, POST action or environment variable accepts a Solr address,
HTTP credentials or a core name from the caller; the two index names are generated by
`Config::coreName()`. `solr.mode` is retained as a constant `'opensolr'`, and a configuration
carrying `mode: custom` from before the removal is refused by `Config::validate()` with an
explanation — every daemon validates at startup, so it fails loudly rather than running against
a Solr Loghound cannot manage.

---

## 10. Dashboard

Facet-first. The dashboard queries `sessions` and `rollup_daily`, essentially never `hits`
(the session explorer drill-down is the one exception, and it is always `fq`-bounded and
`rows`-clamped).

Views for v1:
1. **Overview** — human / bot / AI-crawler stacked area by hour; totals; top pages (humans only,
   with a visible toggle); the four timing numbers side by side.
2. **Bot forensics** — `bot_reasons_ss` facet bars; verdict distribution; bot class breakdown;
   declared crawlers listed separately from evasive ones.
3. **Fingerprint clusters** — THE view. Table of `fp_hash_s` with `unique(ip_s)`, session count,
   timespan sparkline, expand to member IPs and their ASNs. This is the README hero image.
4. **Networks** — ASN treemap coloured by `as_type_s`; netname table; geo map from `geo_p`.
   Country facets are wider than the map, because `country_s` is populated for addresses that
   have no point at all.
5. **Session explorer** — searchable (edismax over the catchall), filterable by every facet,
   drill into a single session's hit timeline with the beacon overlay.
6. **Performance** — p50/p95/p99 latency by path from `dur_us_l`, status heatmap by hour.
7. **Settings/Setup** — log sources + detected mapping review, Solr connection, privacy mode,
   retention, scoring weights, beacon snippet to copy.

Charts: ECharts. Dark/light aware. Every chart must state the population it covers
("humans only", "sessions with beacon data") — an unlabelled number is a lie.

---

## 11. Deployment target (dev instance)

- Host: `opensolr.com` (5.161.242.87). **Do not modify ANY existing vhost, FPM pool, config
  file, cron, or service.** New files only, new pool `loghound`, new vhost file.
- App root is `--prefix`, default `/opt/loghound`, docroot `<prefix>/public`, user `loghound`
  in group `adm`. The reference install lives at `/var/www/workspace/loghound`, so that the
  box's own management platform picks it up as an application and gives it git deploy,
  backups and log viewing for free. Every generated artefact follows the prefix.
- Domain `loghound.opensolr.com` — DNS A record must be added by Cip (Fastmail NS); until then
  test with `curl --resolve`.
- Solr: two Opensolr indexes on region `FINLAND9` (= `fi.solrcluster.com`, Solr 9.6), owner
  `cip@opensolr.com`. **The names are generated per installation, not fixed**: Opensolr index
  names are unique across the entire platform, so `Config::coreName()` produces
  `loghound_<8 hex>_hits` and `loghound_<8 hex>_sessions` from one install id shared by the
  pair. A collision on either name retries the whole pair with a fresh id and deletes
  anything the failed attempt created, so a retry never leaves orphaned indexes on the
  account.
- It will ingest `/var/log/apache2/opensolr_com_access.log` — **read-only**.

---

## 12. Definition of done for v1

- `git clone` + `sudo ./install/install.sh` on a clean Ubuntu box → working panel.
- Apache `combined` parsed with zero configuration.
- nginx `combined` parsed with zero configuration.
- Beacon measures visible/engaged time and flushes on `pagehide`.
- All 17 scoring rules implemented, each with a test proving it fires and does not misfire.
- The Chiron fleet from `docs/DETECTION.md` (real captured lines in `tests/fixtures/`) is
  correctly classified as `bot` / `proxy_fleet`.
- A legitimate human session from the same fixtures is classified `human`.
- `tests/run.php` passes with no network access.
- README with the fingerprint-cluster screenshot, honest limitations section, and a
  "what this does NOT catch" section.
