# Changelog

All notable changes to Loghound are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — unreleased

First public release.

### Added

**Ingestion**

- `bin/loghound-tail` — systemd ingest daemon. Tail, parse, enrich, sessionise and batch
  into Solr. `softCommit` only.
- Rotation-safe tailing (`src/Tail.php`), handling all five real-world cases:
  rename-and-create (the old inode is drained to EOF **before** switching, which is the
  number-one source of silent nightly data loss in log tailers), `copytruncate`, rotation
  that happened while the daemon was stopped (the previous inode is located by inode
  number, never by filename), **outright deletion while the file is held open** (detected
  by re-stat'ing the path and by the link count — on Linux a deleted file that a process
  holds open keeps reading forever with no error, so a naive tailer looks perfectly
  healthy while ingesting nothing), and a path that disappears with no replacement.
- **Inode-recycling detection.** On ext4 a rotate-and-recreate cycle routinely gives the
  new file the inode number the old one just freed, so a stored `(dev, inode, offset)`
  cursor matches a file that no longer exists and resuming at it silently skips the start
  of the new file. A valid cursor always sits immediately after a newline, because only
  complete lines are ever committed; checking that one byte distinguishes a genuine resume
  from a recycled inode. The source restarts at 0 and the event is counted, never hidden.
- Partial-line safety: the committed offset only ever advances past a byte that has a
  terminating newline, so a half-written line cannot corrupt itself or the document id of
  the next one.
- Source globs are re-evaluated on every poll cycle, so a newly created log file is picked
  up without a daemon restart. A path absent for more than an hour is released.
- Unparseable lines are counted and sampled to `var/badlines.log` (capped by
  `ingest.badline_sample`), with source and byte offset — never silently dropped. Control
  characters are stripped, because that file will be read in a terminal.
- Over-long lines are dropped and reported rather than buffered without bound.
- Graceful `SIGTERM` (flush the batch, checkpoint every cursor) and `SIGHUP` (reload the
  config without losing a byte of position; a config that fails validation is refused and
  the daemon keeps running on the previous one).
- `loghound-tail --status [--human]` reports lag in bytes, ingest rate, parse errors, Solr
  errors, and per-source rotation, truncation, deletion and missed-rotation counts. Reads
  a status file rather than signalling the daemon, so a status query can never disturb
  ingestion. Reports STALE rather than showing stale numbers as if they were live.
- Documents are idempotent: `id = sha1(source + byte offset)`, so re-ingesting a file
  overwrites rather than duplicates.
- Log files are opened read-only, always. Loghound never writes to, truncates, rotates,
  renames or deletes a log file it reads, and there is a test asserting it.

**Setup**

- `bin/loghound-setup` — the wizard. Reads your Apache or nginx configuration for
  `LogFormat`/`CustomLog` and `log_format`/`access_log` pairs, falls back to scoring
  candidate files against the built-in format library, and falls back again to proposing a
  pattern from the sample. Shows the detected mapping with **five of your own log lines
  rendered as parsed records and a confidence percentage**, and requires confirmation.
  Nothing is ever ingested with a silently guessed format.
- Managed-Opensolr provisioning: region list, index creation, configset push, verification.
  **The API key is read with terminal echo off and never printed back, not even masked.**
- Own-Solr configuration: base URL, optional HTTP basic auth, core names.
- Generates the beacon HMAC secret and the IP salt with `random_bytes`, sets up panel
  authentication with `password_hash`, and writes `config/loghound.php` at mode 0640.
- Idempotent and re-runnable: every prompt offers the current value, existing secrets are
  kept unless you ask to rotate them, and an index that already exists is verified rather
  than recreated.
- Fully non-interactive mode driven by `LOGHOUND_*` environment variables, for Ansible and
  CI. Switches on automatically when stdin is not a terminal.

**Enrichment**

- Geolocation (ezcmd), ASN and network type (Team Cymru), RIR netname (whois), reverse DNS
  with forward confirmation, and local User-Agent parsing. Each is individually switchable;
  with all four off and your own Solr, nothing leaves the machine.
- Every lookup is cached in SQLite, **including negative results** (geo/ASN/whois ≥ 30 days,
  rDNS ≥ 7), so a repeat visitor costs one lookup per cache window rather than one per
  request.
- **Enrichment failure never blocks indexing.** The field is simply absent, and an absent
  field is never rendered as zero or as an empty string.

**Detection and scoring**

- `bin/loghound-score` — systemd timer, every 60 s. Closes idle sessions, merges beacon
  data, computes `fp_ips_24h_i` with one Solr JSON Facet per distinct fingerprint in the
  batch, scores, upserts the session document and recomputes the daily rollup.
- Seventeen weighted rules across the transport, behavioural and execution planes, 0–100,
  capped. **Every point added carries a reason code**: `bot_score_f` is always accompanied
  by `bot_reasons_ss`, and a clean session carries `no_bot_signals` rather than an empty
  list. Weights and thresholds are config-overridable and `rule_version_i` is written onto
  every session so a historical verdict stays traceable.
- `fp_hash_s` — the cross-IP header fingerprint, **excluding the IP by design**, which is
  what collapses a rotating-proxy fleet back into one row. `fp_cluster_proxy_fleet` (80)
  is the signal the project is built around; it excludes `as_type_s = mobile` because
  carrier-grade NAT genuinely puts thousands of real users behind a handful of addresses.
- **Declared crawlers are classified, not conflated.** Googlebot, Bingbot, GPTBot,
  ClaudeBot and the rest get `bot_verdict_s = bot` with `bot_class_s` of `declared_crawler`
  or `ai_crawler`, and the separation is enforced in `Rules::classify()` rather than by a
  UI checkbox, so every consumer sees the same split. A self-declared crawler that fails
  forward-confirmed rDNS is `rdns_claim_failed` (95), class `spoofed_ua`, which is a
  different fact entirely.
- The daily rollup is **recomputed** from one facet query rather than incremented. An
  atomic `inc` would double-count whenever a retried request's first response was lost.

**The beacon**

- `public/b.js` — dependency-free, no build step, no cookies, passive and throttled
  listeners, and completely inert for the host page if the collector is unreachable.
- **Three clocks, never conflated**: `wall_ms` (the page existed), `visible_ms`
  (`visibilityState === 'visible'` **and** the window focused), `engaged_ms` (visible and
  within 30 s of a real interaction). All from `performance.now()` deltas — never
  `Date.now()`, because an NTP step or a DST change would otherwise be added to somebody's
  reading time. Segments are closed before the state changes, so accumulation is exact
  rather than sampled.
- **Flushes on `pagehide` and `visibilitychange → hidden` with `navigator.sendBeacon()`,
  which is what lets Loghound measure the last page of a session** — the one a log-only
  tool structurally cannot see. `unload` is never used: it disables the back/forward cache
  and does not fire reliably on mobile. A bfcache restore starts a fresh pageview rather
  than carrying frozen time forward.
- Heartbeats only while engaged time is advancing, so an idle tab produces one beat rather
  than 240.
- Execution-plane signal codes: definitive automation markers, headless-browser tells
  graded by how much genuine human population sits behind each, UA-claim verification
  against a probe table of Chrome-version-to-feature (a spoofed User-Agent cannot retrofit
  V8), consistency cross-checks, and human-presence evidence including mouse-path linearity.
  Only the four strong headless tells plus any automation marker set `headless_b`.
- Guards that exist to protect real people: the polyfill guard (a probe must report
  `[native code]`, or a site loading core-js would get its own visitors flagged), the iOS
  exclusion (Chrome, Edge, Firefox and Opera on iOS are WebKit in a Chrome-shaped UA), a
  two-major-version grace, and display checks that stay silent when the payload reported no
  screen size at all — "no data" must never be read as "a window with no size".
- `public/collect.php` — public, unauthenticated write path, treated as hostile. POST only,
  8 KB cap, HMAC token issued by the server, per-IP and per-session token buckets, always
  `204` with no body so it can never be used as an oracle. **It never touches Solr**: it
  writes one SQLite staging row, which keeps an indexing round trip off every pageview and
  keeps Solr credentials out of the most exposed file in the project.
- Impossible timings are clamped and recorded as `beacon_forged` (90) rather than
  discarded — **the lie is the evidence**, and dropping it would make the session
  indistinguishable from a visitor on a slow connection.
- **When no beacon arrived the timing fields are absent, never zero.** A zero enters every
  average as a genuine "0 seconds engaged" observation.

**The panel**

- Seven views: Overview, Bot forensics, Fingerprint clusters, Networks, Session explorer,
  Performance, Settings. Vanilla JS, no framework, no build step, ECharts self-hosted so
  the CSP can stay closed and the panel works air-gapped.
- **Authentication fails closed.** With `auth.mode` unset the panel returns 503 and refuses
  to serve; there is no localhost bypass. CSRF on every state-changing request, strict CSP
  with no inline script, and a dedicated PHP-FPM pool.
- `src/Panel/Gateway.php` is the only path to Solr and every query is built server-side
  from constants and allowlists. **There is no generic Solr passthrough** and there will
  not be one. `Gateway::facet()` forces `rows=0` so an aggregate call cannot ship documents
  by accident.
- Every chart and stat block carries a visible population caption naming what it counts,
  as a `<p>` rather than a tooltip, so it survives being screenshotted. A metric with no
  data renders as an em-dash, never as zero.
- Opt-in demo mode (`LOGHOUND_DEMO=1`) with a fixed-seed synthetic world, banner-labelled
  on every page. A Solr that is merely unreachable produces an error banner and empty
  states — never fabricated data.

**Solr schema and retention**

- Two configsets, heavily commented, with `stored="false"` by default and retrieval from
  docValues; the stock `_text_` catchall and the stock dynamic fields are deleted.
- No `<lib/>` directives and no `/stream`, `/sql`, `/export`, `/replication`,
  `/update/extract`, `/debug/dump`, `/terms`, `/tvrh`, `/analysis/*`, `/spell`, `/suggest`,
  `/browse` or `/elevate` handlers. Each removal is annotated with what it would hand an
  attacker.
- `autoSoftCommit maxTime=5000` with `autoCommit maxTime=60000 openSearcher=false`, and
  cache settings that differ per core because the two workloads are mirror images —
  autowarm 0 throughout the write-heavy `hits` core, warming on the read-heavy `sessions`
  core.
- `bin/loghound-retention` — daily systemd timer issuing a real `delete-by-query` against
  both cores, plus the SQLite caches. `privacy.rollup_forever` keeps the aggregate daily
  documents, which carry no per-visitor field, so long-range charts survive the deletion of
  the detail underneath them. `retention_days = 0` disables deletion and is a supported
  configuration, not an oversight.

**Installation**

- `install/install.sh` — one command from a bare box to a working install: preflight,
  system user, files, permissions, verification, systemd units, TLS, FPM pool, vhost,
  configuration, start, and a check that documents are actually arriving.
- **Non-destructive by construction.** Records pre-install state; never overwrites a file
  it did not write; validates with `apache2ctl configtest` / `nginx -t` / `php-fpm -t`
  **before** enabling anything; rolls back automatically on failure and re-runs validation
  to prove the host is back where it started; uses `reload`, never `restart`.
- The vhost filename sorts last on purpose. Apache treats the first vhost matching an
  address:port as the default for unmatched requests, so a file sorting ahead of an
  existing catch-all would silently hijack every unmatched request on the machine.
- **Permission model that actually works, and is verified.** Prefix `0751` (traverse, no
  listing), `public/` `0755`, `config/` and `var/sessions/` `0700`, `var/`, `src/`, `bin/`
  `0750`. Then tested as the real users: the web server user must be able to traverse the
  prefix and read `public/index.php`, and must **not** be able to read `config/`. All
  three results are printed. A `0750` prefix produces Apache's opaque `AH00035: access
  denied because search permissions are missing on a component of the path`; adding the
  web server user to the service group instead would require an Apache *restart*, which is
  unacceptable on a box with live sites.
- Log readability is tested with a real process, not by reading `/etc/group`, because
  group membership added moments earlier applies only to new processes.
- **TLS certificates are verified before deployment**: the private key is matched against
  the certificate by public key (works for EC as well as RSA), expiry and hostname are
  checked, and the chain must verify against the system trust store. A Let's Encrypt
  *staging* certificate — valid dates, correct hostname, untrusted root — is refused,
  because deploying one produces `unable to get local issuer certificate` in every browser.
  Offers certbot, self-signed (with a loud warning), or plain HTTP instead.
- Platform detection throughout: PHP version and FPM service name, pool and socket
  directories, Debian-style versus RHEL-style Apache, Apache versus nginx (asks when both
  are present), required Apache modules, systemd versus cron.
- Configurable install location: `--prefix=DIR` or `LOGHOUND_PREFIX`. Every generated
  artefact follows it — vhost `DocumentRoot`, FPM `open_basedir` and `session.save_path`,
  systemd `WorkingDirectory`/`ExecStart`/`ReadWritePaths`, deny rules, the final summary —
  and the installer greps its own output afterwards to prove nothing kept the default.
- `--dry-run`, `--upgrade`, `--uninstall`, `--non-interactive`, `--yes`, `--skip-tests`.
- `--upgrade` is git-aware: if the prefix is a working copy it does a fast-forward pull in
  place. It will never run `git reset --hard` or `git clean`, both of which would delete
  `config/loghound.php` and `var/state.db`.
- `--uninstall` finds the prefix from the installed unit rather than assuming the default,
  and prompts separately before deleting the directory or touching any index.
- Everything logged in plain text to `/var/log/loghound-install.log`.
- Hardened systemd units: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, empty `CapabilityBoundingSet`, restricted
  `RestrictAddressFamilies`, `SystemCallFilter=@system-service`, `MemoryMax`, with
  `<prefix>/var` the only writable path and `/var/log` explicitly read-only.
- Vhost and FPM pool examples for hand installation, denying `config/`, `src/`, `var/`,
  `bin/`, `tests/`, `.git` and a long list of dangerous extensions — twice, by directory
  and by URL path. `b.js` cacheable with a version query; `collect.php` never cached.

**Tests**

- `tests/run.php` — dependency-free runner. Discovers `tests/test_*.php`, each returning
  an array of name to closure. Coloured TTY output, a summary, non-zero exit on failure,
  and no network access anywhere.
- A test file or test that fails because a dependency has not landed yet is reported as
  **skipped**, not failed, and does not affect the exit code. The missing-symbol match is
  deliberately narrow: a runner that turns red into green is worse than no runner.
- `tests/test_tail.php` — 20 tests covering rotation, deletion, truncation, partial lines,
  byte offsets, over-long lines, CRLF, and the read-only guarantee, against real files on
  a real filesystem.

**Documentation**

- `README.md` — the two reasons this exists, a text architecture diagram, quickstart, an
  honest "what this does NOT catch" section, and a comparison against GoAccess, Matomo,
  Plausible and GA4 that includes a column for where each of them is better than Loghound.
- `docs/INSTALL.md` — the recommended `LogFormat`, a per-header table of exactly which
  detection signals each extra header buys, a log-retention warning, the read-only
  guarantee, unattended installs, troubleshooting, and a manual-install appendix for people
  who will not run a script as root.
- `docs/DETECTION.md` — the three-plane model, all seventeen rules with weights and
  rationale, worked examples on the real captured fixtures, and frank sections on evasion
  and false positives.
- `docs/SECURITY.md` — threat model, controls by surface, hardening checklist, secrets, a
  known-limitations section, and how to report a vulnerability.
- `docs/PRIVACY.md` — exactly what is collected field by field, what is never collected,
  the three IP modes with their detection cost, what leaves your server, retention, GDPR
  posture, data subject requests, and draft privacy-notice text.
- `docs/BEACON.md` — the three clocks and why they differ, a worked example, the flush
  strategy, every field the beacon sends, every signal code with its weight, the wire
  protocol and anti-forgery scheme, how to extend the UA-claim probe table, and a section
  on what the beacon cannot detect.
- `docs/PANEL.md` — the panel's request flow, the notes a security reviewer wants, demo
  mode, and a frank list of the places `SPEC.md` is wrong or silent and what that cost.
- `docs/SCHEMA.md` — both cores field by field with the reason each one is indexed,
  docValued or stored and what it costs, the fingerprint's honest limitation on plain
  `combined`, index-size arithmetic shown as a breakdown rather than a single number, what
  to turn off first, and the deliberate omissions from the configsets.
- `CONTRIBUTING.md` — what the project is for, the rules that are not negotiable, how to
  write a test, fixture anonymisation rules, and an explicit list of what will be declined.

### Notes

- No Composer, no npm, no build step. PHP 8.1+ with `curl`, `json`, `pcre`, `sqlite3` and
  `mbstring`, and Solr 9.

---

[1.0.0]: https://github.com/phpcip/loghound/releases/tag/v1.0.0
