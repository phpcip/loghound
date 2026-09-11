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
- **HMAC token, bound to the Origin it was issued to.** The first call is issued
  `HMAC(secret, session_id \0 origin | issued_at)`, and verification recomputes with the
  `Origin` of the request presenting it. Missing, invalid, expired (> 12h), future-dated or
  presented from a different origin is rejected. The binding is what makes
  `Access-Control-Allow-Origin: *` safe here: the endpoint must be reachable from origins
  we do not know in advance, so the credential is tied to the origin instead of the
  allow-list doing the work.
- **The hello branch never returns an existing session id.** It always mints a fresh random
  provisional id, and it never creates a session row. Returning the real id would let any
  page on the internet make a CORS-simple POST from a visitor's browser, read the session
  credentials off the response headers, and then submit whatever it liked about that
  visitor's real session — in a bot-detection product, "report this human as headless".
  `loghound-score` re-attaches the staged rows to the real session by `client_key`.
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

- **Authentication is required and fails closed, in both directions.** With
  `auth.mode = 'none'`, `Security::requireAuth()` returns HTTP 503 and refuses to serve. A
  mode with no implementation behind it is refused rather than waved through, and an attempt
  counter that cannot be read or written is refused too — a check that cannot be performed is
  a failed check, never a passed one. An analytics dashboard left open on the internet is a
  data breach, and defaults decide outcomes.
- **Two modes exist and no others.** `basic` is the browser's own password prompt: every
  tool that speaks HTTP can sign in the same way, and there is no way to sign out short of
  closing the browser. `session` is Loghound's own sign-in page with a real Sign out button,
  an idle timeout (default 30 min) and an absolute one (default 12 h); it works only in a
  browser, so a monitoring check against the panel has to use Basic or be dropped. Both
  timeouts are read from config on every request and clamped, so a hand-edited value cannot
  switch them off.
- Passwords are stored with `password_hash(PASSWORD_DEFAULT)`. The username is compared with
  `hash_equals` so it cannot be enumerated by timing, and a failed Basic attempt sleeps a
  randomised 150–400 ms to blunt online guessing.
- **Failed sign-ins are rate limited per address**, by a ledger in
  `var/login-attempts.json`: 8 attempts in a 15-minute window by default, both clamped. The
  address comes from `Security::clientIp()`, so `X-Forwarded-For` counts only when the
  immediate peer is a configured trusted proxy — otherwise a guesser could reset their own
  counter with a header. Signing in successfully clears the counter.
- The sign-in POST carries a CSRF token like every other state-changing request, and the
  session id is regenerated on sign-in so a fixated cookie is worthless. The session holds a
  username and timestamps — never the password or its hash.
- **CSRF token on every state-changing request**, enforced before the handler runs.
- A strict Content-Security-Policy, in full:
  `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'
  data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none';
  frame-ancestors 'none'; form-action 'self'`. No inline `<script>`, no inline handlers, no
  `eval`, no `new Function`, no dynamic `import()`, no third-party origins. **ECharts is
  self-hosted precisely so this policy can stay closed** — and so the panel works on an
  air-gapped box. Even the theme bootstrap, normally the one place people cheat because an
  unthemed page flashes white, is an external synchronous file.
- **`'unsafe-inline'` applies to styles only, and that is a real relaxation worth naming.**
  The panel sets chart and bar heights with `style=` attributes; every value in one is a
  constant or an integer that has been through `Security::clampInt()`, and no log-derived
  string reaches a style attribute. It does not weaken `script-src`, but a reviewer should
  know it is there rather than discover it.
- Plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin` and a restrictive
  `Permissions-Policy`. Every panel response, HTML and JSON alike, carries
  `Cache-Control: no-store, private`.
- **Long panel operations are stepped jobs** (`src/Panel/Jobs.php`), and every one of the
  three endpoints is a POST behind the CSRF check. Job ids are 96 bits of `random_bytes`
  and every lookup is scoped to an owner derived from the authenticated session, with a job
  that is not yours reported *identically* to one that does not exist, so ids cannot be
  probed. Nothing in a job payload is a secret: step details, persisted errors and log
  lines all pass through `Jobs::redact()` first, because the Opensolr API key travels in a
  query string and a transport error can quote the URL it failed on. See
  [PANEL.md](PANEL.md).

### The browser installer

`src/Setup/` serves any request that arrives at an installation not yet ready to serve.
That makes it, briefly, an unauthenticated surface, and it is treated as one.

- **It is unreachable once setup is finished.** `Installer::isNeeded()` runs at the top of
  every request, before authentication, and returns false the moment the configuration file
  exists, carries `auth.mode` and `auth.password_hash`, and names both indexes. There is no
  flag, no query parameter and no "re-run setup" button that gets past it.
- **That gate is deliberately structural, and does not call `Config::validate()`.** Because
  it runs before `requireAuth()`, whatever makes it return true hands an unauthenticated
  visitor the installer — so it must depend only on facts that mean "setup never finished".
  It previously returned `validate() !== []`, and `validate()` reports an error for a log
  directory it cannot resolve, which is the normal state of a panel process under
  `open_basedir`. A correctly installed instance therefore looked unconfigured forever: the
  status page disclosed the environment, paths, index names and `open_basedir` value to
  anyone who asked, and re-minted a live setup token on a machine where it had already been
  destroyed. Configuration problems that are *not* "setup never finished" belong in the
  panel's own warning banner, which is where they now go.
- **Filesystem proof before any write.** Nothing reaches the configuration until the
  operator pastes the token from `var/install-token` (mode 0600), which requires shell
  access as the service user or root. Guessing is rate limited by a fixed-window ledger next
  to the token file, and the file is deleted the moment setup completes. The status page
  itself is readable without the token, deliberately — you have to be able to *see* a
  permission problem in order to go and fix it.
- **CSRF on everything that changes anything**, through the same `Security::requireCsrf()`
  the panel uses. No privileged action is reachable with a GET, and a step whose
  prerequisites are unmet redirects to the first incomplete one rather than letting a
  guessed URL skip ahead.
- **No secret is ever rendered** — not the Opensolr API key, the beacon secret, the IP salt
  or the password, and not into a hidden field, a URL, a job payload, a log line or an error
  message. Presence is shown; values never are.
- Log sample lines are attacker-chosen bytes by definition and are displayed on the review
  screen on purpose; every one goes through `Security::esc()`. A hand-typed log path is
  resolved with `realpath()` and refused unless it is inside `allowed_log_roots` — the
  installer will not widen that list for you, because it is a security control. A custom
  pattern is refused unless it compiles and runs fast (`Security::validateUserRegex()`).

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
- [ ] **Decide whether the panel's own vhost is traffic you want to measure.** Loghound's
      own beacon script and collector are never counted wherever their log comes from —
      they are matched on host *and* path, from `base_url`, so a site's own
      `/collect.php` is left alone — so pointing Loghound at its own access log no longer
      inflates anything with its own instrumentation. What remains is real visits to a
      real site: your own. Keep them to measure the panel like any other site, or set
      `'enabled' => false` on that source in `config/loghound.php` to leave them out.
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

- **The login lockout is per address, and only per address.** That is deliberate, not an
  oversight: a global cap on a login form is a denial-of-service primitive handed to anyone
  who can reach it — a few thousand wrong passwords from a botnet would trip it, and the
  legitimate operator, whose password is correct and whose address has zero failures, would
  be locked out of their own panel for as long as the attacker cared to keep going. Per
  address, an attacker can only lock out the address they are attacking from. The cost is
  that a distributed guesser is not slowed by the lockout at all, only by the randomised
  delay and by whatever entropy is in the password. (`Setup\Token` makes the opposite trade
  on purpose, because it guards a one-time, takeover-shaped window where refusing everybody
  is the safer failure.) Put the panel behind an IP allowlist or a VPN if that matters to
  you.
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
  proves the token was issued by us, for that session id and that Origin — not that this
  particular client is the one it was issued to. Origin binding stops a third-party page
  obtaining credentials for somebody else's session, but anyone who can read a token out of
  a browser they already control can keep using it until it expires. What that buys them is
  the ability to lie about dwell time for their own session, which is why forged timings are
  recorded as a signal rather than trusted or dropped.
- **The panel counts daily rollup documents as sessions.** The rollup lives in the sessions
  core discriminated by `doc_type_s`, and no panel query filters on it, so every session
  total is high by up to one document per day in the selected range. Not a security issue;
  listed here because it is a wrong number the product presents as evidence. See
  [PANEL.md](PANEL.md).
- **No formal third-party security audit has been performed.** If you do one, the results
  are very welcome.
