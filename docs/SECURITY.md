# Security

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [What is trusted, and what is not](#what-is-trusted-and-what-is-not)
- [Controls by surface](#controls-by-surface)
- [Hardening checklist](#hardening-checklist)
- [Secrets](#secrets)
- [Known limitations](#known-limitations)

---

## Reporting a vulnerability

**Email `cip@opensolr.com`** with `LOGHOUND SECURITY` in the subject line.

Please do **not** open a public GitHub issue for a security problem.

Useful things to include, in rough order of usefulness: the affected file and line, a
minimal reproduction, the version or commit, and what an attacker gets out of it. A proof
of concept is welcome and is never required — a clear description of the flaw is worth
more than a weaponised exploit.

**What to expect.** Acknowledgement within a few days. This is a small project maintained
by one person; there is no bug bounty and no SLA, and claiming one would be dishonest.
There is no embargo requirement — publish when you think it is right — but a little
warning is appreciated so a fix can land alongside the disclosure. Credit in
`CHANGELOG.md` unless you would rather not be named.

---

## Threat model

Loghound parses hostile input by definition. That is not a caveat, it is the job
description.

**Who the adversaries are**

| Adversary | Capability | What they want |
|---|---|---|
| Anyone who can send an HTTP request to a monitored site | Full control of request path, query string, User-Agent, Referer and every other header — all of which end up as bytes in a log line Loghound parses | Stored XSS in the panel, SQL/Solr injection, path traversal, resource exhaustion of the ingest daemon |
| Anyone on the internet | Can POST to `/collect.php`, which is public and unauthenticated by design | Forge sessions, poison timing metrics, exhaust the SQLite staging table, get code execution on a public write path |
| A local unprivileged user on the same box | Can read world-readable files and connect to world-writable sockets | The Opensolr API key, the beacon HMAC secret, the traffic data |
| Another site on the same shared host | Executes as the shared web server user | The same secrets, via a readable config file |
| A compromised panel session | Authenticated, can drive every panel action | Pivot from "read the dashboard" to "read arbitrary files" or "run arbitrary Solr queries" |
| A malicious or compromised upstream (geo/ASN/whois service) | Controls the enrichment response body | Injection through a field the operator assumes is trustworthy |

**What is explicitly out of scope**

- An attacker with root on the box. Nothing here survives that.
- A compromised Solr. Loghound trusts the documents it reads back, though the panel still
  escapes them contextually on output.
- Denial of service by sheer traffic volume against the origin web server itself.
- The security of your web server, PHP build and TLS configuration.

---

## What is trusted, and what is not

**Untrusted, always, without exception:**

log lines and every field in them · request paths · query strings · User-Agent · Referer ·
every logged header · `$_GET` / `$_POST` / `php://input` · URI segments · cookies ·
`X-Forwarded-For` and every other client header · beacon payloads · documents read back
from Solr · enrichment responses (geo, ASN, whois, rDNS) · the contents of any file under
`/var/log`.

**Trusted:**

`config/loghound.php` (the operator wrote it, mode `0700` directory) · the application's
own source · the Solr connection parameters.

The important consequence: **there is no point in the pipeline where a log-derived value
becomes safe.** It is escaped at the sink, every time, in the encoding that sink requires.

---

## Controls by surface

### Output escaping — contextual, never generic

There is exactly one implementation of each escaper, in `src/Security.php`. If you find
yourself writing `htmlspecialchars()` anywhere else, use `Security::esc()` instead.

| Context | Function | Why not something else |
|---|---|---|
| HTML text or attribute | `Security::esc()` — `htmlspecialchars(ENT_QUOTES\|ENT_SUBSTITUTE, 'UTF-8')` | `ENT_QUOTES` covers both quote styles, so the same call is safe in a single- or double-quoted attribute. `ENT_SUBSTITUTE` stops invalid UTF-8 from producing an empty string, which would silently drop the escaping. |
| Inside `<script>` | `Security::escJs()` — `json_encode` with `JSON_HEX_TAG\|JSON_HEX_AMP\|JSON_HEX_APOS\|JSON_HEX_QUOT` | `JSON_HEX_TAG` is the load-bearing flag: a User-Agent containing `</script>` cannot break out of the element. |
| `href` / `src` | `Security::safeUrl()` | Scheme allowlist (`http`, `https` only) plus a control-character check. Referer values from the wire routinely contain `javascript:`, `data:` and `vbscript:` payloads. Anything else renders as `#`. |
| Client-side `innerHTML` | Prefer `textContent`. Where markup is genuinely needed, the project's `esc()` helper. | No `eval`, no `new Function`, no `innerHTML` of raw API data. |

### Solr injection

- User text is **never** spliced into `q`, `fq`, `sort`, `fl` or `defType`. It goes in as a
  bound local param: `{!edismax v=$uq}` with `uq=<text>`.
- `rows` and `start` are clamped to `Security::MAX_ROWS` (500) and `Security::MAX_START`
  (100000). Deep paging is both a DoS vector and a useless UX.
- Field names used for sort and facet must pass `Security::isSafeFieldName()`
  (`[A-Za-z0-9_]{1,64}`).
- Core names must pass `Security::isSafeCoreName()`.
- Caller-supplied `shards`, `qt`, `wt`, `stream.*` and `distrib` are never accepted.
- **There is no raw Solr passthrough.** The panel talks to Solr only through `src/Solr.php`,
  which builds every request server-side. There is no "proxy this query to Solr" endpoint,
  and there will not be one.

### The beacon collector — the public write path

`public/collect.php` is unauthenticated by design and is treated as hostile:

- POST only. `text/plain` (sendBeacon's default) or JSON. **8 KB payload cap.**
- **HMAC token.** The first call is issued `HMAC(secret, session_id|issued_at)`. Every
  subsequent call must present it. Missing, invalid or expired (> 12h) is rejected.
- **Timing sanity.** `engaged_ms > visible_ms`, `visible_ms > wall_ms`, or
  `wall_ms > (now − issued_at + 60s)` are impossible. The payload is recorded with a
  `beacon_forged` signal rather than discarded — **the lie is evidence**.
- **Client-supplied IP, UA, host and referer are never trusted.** They are read from the
  connection.
- Rate limited per IP (SQLite token bucket, default 120/min) and per session.
- Always responds `204` with no body. Never leaks whether a token was valid, whether a
  session exists, or whether anything was stored.
- **It does not touch Solr.** It writes one row to a SQLite staging table;
  `loghound-score` merges it later. That keeps the public path cheap and keeps Solr
  credentials entirely out of the request path.

### The panel

- **Authentication is required and fails closed.** With `auth.mode = 'none'`,
  `Security::requireAuth()` returns HTTP 503 and refuses to serve. An analytics dashboard
  left open on the internet is a data breach, and defaults decide outcomes.
- Passwords are stored with `password_hash(PASSWORD_DEFAULT)`. Failed Basic auth sleeps a
  randomised 150–400 ms to blunt online guessing, and the username is compared with
  `hash_equals` so it cannot be enumerated by timing.
- **CSRF token on every state-changing request**, enforced before the handler runs.
- A strict Content-Security-Policy: `default-src 'self'`, `script-src 'self'`,
  `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`. No inline handlers, no
  `eval`, no third-party origins. **ECharts is self-hosted precisely so this policy can
  stay closed** — and so the panel works on an air-gapped box.
- Plus `X-Content-Type-Options`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy` and a restrictive `Permissions-Policy`.

### Filesystem

- Every configured log path is resolved with `realpath()` and checked against
  `allowed_log_roots` by `Security::safePath()`. The prefix comparison is against the
  *resolved* root with a trailing separator, so `/var/log-evil` cannot match `/var/log`
  and a symlink cannot escape the tree.
- **Globs are re-validated at read time, not just at save time.** A source pattern is
  expanded on every poll cycle and each expanded path goes through `safePath()` again.
  Validating only the pattern would leave a hole.
- Source log files are opened `'rb'` and never any other mode. Loghound never writes to,
  truncates, rotates, renames or deletes a log file it reads. There is a test asserting a
  source file's size is unchanged after a full read.
- The bad-line sample strips C0 control characters and DEL before writing, because that
  file **will** be read in a terminal and a crafted User-Agent should not be able to emit
  escape sequences into it.

### ReDoS

A custom log pattern is untrusted code that runs against every line of a firehose.
`Security::validateUserRegex()` refuses it **at save time**, which is the only moment a
human is present to fix it:

- length cap (4096 bytes) and a required delimiter/modifier shape;
- compiled under a reduced `pcre.backtrack_limit` against a subject engineered to expose
  nested-quantifier blowup;
- wall-clock budget (100 ms); anything slower is rejected as unable to keep up with
  ingestion.

### Trusted proxies

`X-Forwarded-For` is attacker-controlled unless the immediate peer is a proxy you placed
there yourself. `Security::clientIp()` honours it **only** when `REMOTE_ADDR` is in the
configured `trusted_proxies` CIDR list, and then takes the right-most hop that is not
itself a trusted proxy. Getting this wrong lets any visitor forge their own source
address, which would poison every IP-based signal in the ruleset.

### Privilege separation

- The daemons run as `loghound`, in `adm` for log read access, and never as root.
- Application code is owned by `root` and only *read* by the service user: a compromise of
  the daemon cannot rewrite the code that runs next time.
- The systemd units set `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, an empty `CapabilityBoundingSet`, a restricted
  `RestrictAddressFamilies`, `SystemCallFilter=@system-service` and `MemoryMax`. The only
  writable path is `<prefix>/var`; `/var/log` is explicitly read-only.
- The panel runs in a **dedicated** PHP-FPM pool as `loghound`, with `open_basedir`,
  `file_uploads = off` and a `disable_functions` list covering every process-spawning
  function.

---

## Hardening checklist

Things worth doing that the installer cannot decide for you.

- [ ] **Do not expose the panel to the internet if you do not need to.** Bind it to a VPN
      or an internal address. It is the highest-value target in the whole system: it
      contains every visitor, path and IP on your site.
- [ ] **Use a real TLS certificate.** The installer refuses to deploy one that does not
      chain to a trusted root, but it will let you choose self-signed. Do not leave it
      that way.
- [ ] **Add IP allowlisting in the vhost** if your operators come from known addresses.
      Two lines of Apache config, and it removes the panel from the internet's attack
      surface entirely.
- [ ] **Set `privacy.ip_mode` deliberately.** `full` is the default because self-hosters
      already have the raw address in their own logs, but `truncate` or `hash` may be the
      right answer for you. See [PRIVACY.md](PRIVACY.md).
- [ ] **Set `privacy.retention_days` to a number you can justify** and confirm
      `loghound-retention.timer` is enabled and running.
- [ ] **Configure `trusted_proxies`** if anything sits in front of your web server, or
      every IP-based signal is worthless.
- [ ] **Keep `keep_raw` on only if you need retroactive rescoring.** It roughly doubles
      the index size and it stores the complete original log line, including any secret
      that ended up in a query string.
- [ ] **Never point Loghound at its own vhost's access log.** It would ingest its own
      beacon traffic and inflate every number.
- [ ] **Check `<prefix>/config` is not readable by the web server user.** The installer
      verifies this; verify it again after any change:
      `sudo -u www-data test -r <prefix>/config && echo EXPOSED`.
- [ ] **Rotate the beacon secret** if you suspect it leaked: re-run `loghound-setup` and
      answer yes to the rotation prompt. Every issued token becomes invalid, which costs
      you one heartbeat interval of beacon data and nothing else.
- [ ] **Watch `parse_errors` and `solr_errors`** in `loghound-tail --status`. A sudden
      climb in parse errors is usually a format change, but it is also what a
      log-injection attempt looks like.

---

## Secrets

Two secrets exist:

| Secret | Where | If it leaks |
|---|---|---|
| Opensolr API key | `config/loghound.php` | Full control of your Opensolr indexes |
| Beacon HMAC secret | `config/loghound.php` | Anyone can forge beacon payloads and poison your timing metrics and verdicts |

Plus `privacy.ip_salt`, which is only sensitive in `hash` IP mode — with it, hashed
addresses can be brute-forced back (the IPv4 space is small).

**How they are protected**

- `config/loghound.php` is mode `0640` in a `0700` directory owned by the service user.
  The web server user cannot reach it, and the installer *verifies* that with an inverted
  permission check.
- It is a PHP file rather than JSON or YAML for one reason: if it is ever served by a
  misconfigured web server it **executes and returns nothing**, instead of printing the
  secrets as text. It also opens with a guard that exits unless the application defined
  its marker constant.
- It is written atomically (temp file, `chmod`, `rename`) so a crash mid-write cannot
  leave a half-parsed config.
- Both vhost examples and both generated vhosts deny `config/`, `src/`, `var/`, `bin/`,
  `tests/`, `.git` and a long list of dangerous extensions, twice — once by directory and
  once by URL path.
- The setup wizard reads the API key with terminal echo off, never prints it back — not
  even masked, because a masked key in a scrollback is still a key in a scrollback — and
  the installer never writes it to `/var/log/loghound-install.log`.
- `.gitignore` excludes `config/loghound.php`, `var/`, `*.db` and `*.log`.

---

## Known limitations

Stated plainly, because a security document that only lists strengths is marketing.

- **The panel has no rate limiting on login.** There is a randomised delay on failure and
  nothing more — no lockout, no fail2ban integration. Put it behind an IP allowlist or a
  VPN if that matters to you.
- **No audit log of panel actions.** There is no record of who looked at what.
- **`keep_raw` stores complete log lines**, including any credential that ended up in a
  query string on your site. That is your data and your risk; the toggle exists so you can
  decide.
- **Enrichment responses are parsed, not verified.** A compromised geo or whois provider
  could inject a value. It is escaped at every output sink, but it can still make a field
  say something untrue.
- **`ja4_s` is defined and never populated.** The field exists for HAProxy-sourced JA4
  fingerprints; nothing in v1 produces one.
- **The beacon can be blocked, and it can be replayed within its token window.** The HMAC
  proves the token was issued by us, not that this particular client is the one it was
  issued to. Session hijacking of a beacon token gets an attacker the ability to lie about
  dwell time for that session, which is why forged timings are recorded as a signal rather
  than trusted or dropped.
- **No formal third-party security audit has been performed.** If you do one, the results
  are very welcome.
