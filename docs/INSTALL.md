# Installing Loghound

- [The short version](#the-short-version)
- [Two installers, one result](#two-installers-one-result)
- [What the installer actually does](#what-the-installer-actually-does)
- [Where it installs, and why you might change it](#where-it-installs-and-why-you-might-change-it)
- [The recommended LogFormat](#the-recommended-logformat)
- [What each extra header buys you](#what-each-extra-header-buys-you)
- [nginx](#nginx)
- [The beacon](#the-beacon)
- [Solr, and where the two indexes come from](#solr-and-where-the-two-indexes-come-from)
- [Log retention: what Loghound can and cannot see](#log-retention-what-loghound-can-and-cannot-see)
- [Loghound and your other log tooling](#loghound-and-your-other-log-tooling)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Unattended installs](#unattended-installs)
- [Troubleshooting](#troubleshooting)
- [Appendix: installing by hand](#appendix-installing-by-hand)

---

## The short version

```bash
git clone https://github.com/phpcip/loghound.git
cd loghound

# Look before you leap. This changes nothing at all.
sudo ./install/install.sh --dry-run

sudo ./install/install.sh
```

That is the whole thing. The installer creates the system user, lays out the tree with
the right ownership and modes, installs and enables the systemd units, writes a dedicated
PHP-FPM pool and a vhost for whichever web server you already run, validates both before
enabling them, runs the setup wizard, starts the ingest daemon, and waits for the first
documents to land before telling you it worked.

Requirements: PHP 8.1+ with `curl`, `json`, `pcre`, `sqlite3` and `mbstring`; an Opensolr
account, whose API provisions and holds the two indexes Loghound writes to; systemd (or
cron, with one caveat — see below). No Composer, no npm, no build step.

### A word about running an installer as root

This script creates a user, writes to `/etc/systemd/system`, writes a vhost and reloads
your web server. It cannot do those things without root, and you should not run *any*
script as root on a production box without looking at it first.

So: **run it with `--dry-run` first.** It prints every command it would execute and every
file it would write, and changes nothing. Read that output. Then read the script — it is
one file, heavily commented, and the reasons for each decision are written down next to
the decision. If you would rather not run it at all, the
[manual appendix](#appendix-installing-by-hand) is the same steps by hand.

---

## Two installers, one result

`install/install.sh` prepares the machine — user, files, modes, systemd units, TLS, the
FPM pool, the vhost. *Configuring* Loghound is a separate thing, and there are two ways to
do it:

| | |
|---|---|
| **In a browser** | Point a vhost at `public/`, open the URL, follow three screens. This is the path most people take, and it has its own document: **[INSTALL-WEB.md](INSTALL-WEB.md)**. |
| **In a shell** | `bin/loghound-setup` over SSH. This is what `install/install.sh` hands over to, and what unattended installs drive from `LOGHOUND_*` environment variables. This document. |

`install/install.sh` hands over to the shell wizard by default. Pass **`--skip-setup`** to
stop once the machine is ready and configure in the browser instead; the final report then
prints the URL and the command that reads the setup token back. The flag exists because
"either front end" has to be true of the installer as well, not only of the code beneath it.

**Neither is a lesser version of the other.** Both call the same code in `src/Setup/` to
decide which log files to read, how to grade a format, how to provision the indexes, what a
valid password is and what happens next — so a configuration written by one is
indistinguishable from one written by the other. You can start in the browser and finish in
the shell, or the reverse.

The practical difference is reach, and it goes both ways. The shell wizard is not subject
to the panel's `open_basedir`, so it can always read `/var/log` and your webserver
configuration. The browser installer can, provided the FPM pool allows it — the shipped
`install/php-fpm-pool.conf.example` includes `/var/log`, `/etc/apache2` and `/etc/nginx` in
`open_basedir` for exactly that reason, and the system check says so plainly when they are
missing rather than reporting a permission problem that does not exist.

Anything not ready to serve lands on the browser installer: no configuration, half a
configuration, or a configuration with no way to sign in. Loghound never answers a request
by printing a configuration error and stopping. The moment the configuration file exists,
carries a username and a password hash, and names both indexes, every installer route is
dead and the panel serves instead.

---

## What the installer actually does

In order, and it stops at the first problem:

**1. Preflight — before a single change is made.** PHP version and every required
extension, systemd or cron, the `adm` group, write access to the target, a complete source
tree, the web server and its runtime user, the PHP-FPM pool directory, the Apache modules
it needs, and a check for any file it would collide with. Prints a PASS/FAIL table and
exits non-zero on any failure. Nothing has changed at this point.

**2. The system user.** `loghound`, system account, no login shell, no home directory,
added to `adm` for read access to `/var/log`. If the user already exists it is left alone;
`usermod -aG` only ever *adds* a group.

**3. Files and permissions.** See the next section. The modes here are the single most
common cause of a broken install and they are verified, not assumed.

**4. Verification, as the actual users.** Three checks matter, and all three are printed:

```
test -x <prefix>                    as the web server user   must PASS
test -r <prefix>/public/index.php   as the web server user   must PASS
test -r <prefix>/config             as the web server user   must FAIL
```

Plus: can the service user read the application code, write to `var/`, and — tested with
a real process, not by reading `/etc/group` — actually **read your access log files**.

**5. systemd units.** `loghound-tail.service` plus the score and retention services and
timers, hardened (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
an empty `CapabilityBoundingSet`, `MemoryMax`). The two timers are enabled. If there is
no systemd, cron fallbacks are installed for score and retention instead — and the
installer says clearly that the ingest daemon then needs your own supervisor, because it
is a long-running process and cron's one-minute floor is exactly what it exists to beat.

**6. TLS.** Looks for an existing certificate for your hostname in the usual places
(`/etc/letsencrypt/live`, `/root/.acme.sh`, `/etc/ssl`). Every candidate is checked:

- does the private key match the certificate (compared by **public key**, so it works for
  EC keys as well as RSA — the usual modulus comparison silently produces two empty
  strings for EC and "passes");
- is it still valid for at least another day;
- does it list your hostname;
- and **does it chain to a trusted root**.

That last check is not paranoia. On the first box this was deployed to,
`/root/.acme.sh/<domain>/` held a Let's Encrypt **staging** certificate — newer than the
real one, perfectly valid dates, correct hostname, issuer `(STAGING) Dastardly Durum` —
and deploying it produced `unable to get local issuer certificate` in every browser. A
certificate that does not verify against the system trust store is never deployed. If
nothing usable is found you are offered certbot, a self-signed certificate (with a loud
warning), or plain HTTP.

**7. PHP-FPM pool.** A **dedicated** pool at `<pool.d>/loghound.conf`, running as the
service user, on its own socket. Never the shared `www-data` pool: that would make every
other site on the box execute as a user that can read your API key. Validated with
`php-fpm -t` **before** anything is reloaded, and then `reload`ed, never restarted.

`open_basedir` on that pool is `<prefix>:/var/log:/etc/apache2:/etc/nginx:/tmp`. The last
three are there because the browser installer's first screen reads them: it parses your
Apache or nginx configuration to find the access logs and their exact format, and shows you
real sample lines so you can confirm the field mapping before anything is ingested. Leave
them out and setup still completes, but that screen finds nothing and you are asked to type
paths by hand. Both directories are **read-only to the pool user by file permissions** —
`open_basedir` widens what PHP may *attempt*, not what the kernel will allow — and the
comment in `install/php-fpm-pool.conf.example` says which line to drop for a server that
does not run one of them. Also on that pool: `file_uploads = off` and a `disable_functions`
list covering every process-spawning function.

**8. Vhost.** Generated for Apache or nginx with your hostname, prefix, certificate paths
and socket already filled in. Written as `zzz-loghound.conf` — the name sorts last on
purpose, because Apache treats the *first* vhost matching an address:port as the default
for unmatched requests, and a Loghound file sorting ahead of an existing catch-all would
silently hijack every unmatched request on the machine. Validated with
`apache2ctl configtest` / `nginx -t` **before** being enabled. If validation fails, the
files this run created are removed, the site is disabled, and validation is re-run to
prove your host is back exactly where it started.

**9. The setup wizard.** Hands over to `bin/loghound-setup`, running as the service user:
detects your logs, shows you the mapping, asks you to confirm, provisions Solr, generates
the secrets, sets up panel authentication. If it does not complete, the install stops and
tells you how to re-run it; you can also just open the site in a browser and finish there,
because an unconfigured install serves the installer. See
[INSTALL-WEB.md](INSTALL-WEB.md).

**10. Start, and prove it.** Starts `loghound-tail`, then waits up to 60 seconds for the
first documents to reach Solr. If none arrive it says so and prints the diagnostic
commands, rather than declaring success because a unit happens to be `active`.

Everything is logged, in plain text, to `/var/log/loghound-install.log`.

### What it never does

- modify an existing vhost, FPM pool, cron entry, systemd unit or any file it did not write
- `restart` (as opposed to `reload`) your web server or PHP-FPM
- deploy a TLS certificate it has not verified
- write to, truncate, rotate or delete any log file it reads
- overwrite `config/loghound.php`

---

## Where it installs, and why you might change it

Default is `/opt/loghound`. Change it with `--prefix=DIR`, or the `LOGHOUND_PREFIX`
environment variable:

```bash
sudo ./install/install.sh --prefix=/var/www/loghound
```

Everything follows: the vhost `DocumentRoot`, the FPM pool's `open_basedir` and
`session.save_path`, the systemd `WorkingDirectory` / `ExecStart` / `ReadWritePaths`, the
config file path, the deny rules and the paths in the final summary. The installer greps
its own generated files afterwards to prove nothing kept the default, and aborts if
anything did.

A concrete reason to move it: some server-management platforms auto-discover applications
by scanning subdirectories of a configured base directory, and an app that lives there
gets git deploy, backups, restore, vhost and FPM management and log viewing from that
platform's UI for free — with no registration file to lose. Plenty of people also simply
prefer `/srv` or `/var/www` to `/opt`.

### The permission model

This is the part that decides whether the panel works at all.

| Path | Mode | Owner | Why |
|---|---|---|---|
| `<prefix>` | `0751` | `root:loghound` | The web server user must **traverse** it to reach `public/`. It must not be able to **list** it. |
| `<prefix>/public` | `0755` | `root:loghound` | World-readable, and it holds no secrets. nginx and Apache serve `b.js` and `assets/` directly, as themselves, not through the FPM pool. |
| `<prefix>/config` | `0700` | `loghound:loghound` | The API key and the HMAC secret. The web server user must **not** be able to read this. |
| `<prefix>/var` | `0750` | `loghound:loghound` | SQLite state, status file, bad-line sample. |
| `<prefix>/var/sessions` | `0700` | `loghound:loghound` | A PHP session file *is* a login. |
| `<prefix>/src`, `bin`, `solr` | `0750` | `root:loghound` | Code is root-owned and only read by the service user: a compromise of the daemon must not be able to rewrite the code that runs next time. |

If `<prefix>` is `0750`, Apache fails with:

```
AH00035: access denied because search permissions are missing on a component
of the path /opt/loghound/public/index.php
```

The tempting fix — adding `www-data` to the `loghound` group — is **wrong on a live box**.
Supplementary groups are read once, at process start, so it requires a full Apache
**restart**, not a reload, and a restart drops in-flight requests on every other site on
the machine. Grant the traversal by mode instead. That is what `0751` is for.

---

## The recommended LogFormat

**Loghound works out of the box on plain `combined`.** Detection is materially better if
you log a few more headers, and this is the block to use.

Add it to `/etc/apache2/apache2.conf` (or `/etc/httpd/conf/httpd.conf`) and reference the
nickname from your vhost's `CustomLog`:

```apache
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O %D \"%{Referer}i\" \"%{User-Agent}i\" \
\"%{Accept}i\" \"%{Accept-Language}i\" \"%{Accept-Encoding}i\" \
\"%{Sec-CH-UA}i\" \"%{Sec-CH-UA-Platform}i\" \"%{Sec-CH-UA-Mobile}i\" \
\"%{Sec-Fetch-Site}i\" \"%{Sec-Fetch-Mode}i\" \"%{Sec-Fetch-Dest}i\" \"%{Sec-Fetch-User}i\" \
\"%{X-Forwarded-For}i\" \"%H\" \"%{SSL_PROTOCOL}x\" \"%{SSL_CIPHER}x\"" loghound
```

```apache
CustomLog ${APACHE_LOG_DIR}/example_com_access.log loghound
```

Then `apache2ctl configtest && systemctl reload apache2`, and re-run
`loghound-setup` so it picks up the new format.

**Be honest with yourself about the trade.** These lines are roughly two to three times
longer than `combined`. On a site doing ten million requests a day that is real disk. On
most sites it is not. Decide with `du`, not with a feeling.

You do not have to take all of it. Every header is independent, and the table below says
exactly what each one is worth.

### What you get with plain `combined`

`combined` gives Loghound: IP, timestamp, method, path, protocol, status, bytes, referer
and User-Agent. From those alone it still does everything on the behavioural plane —
asset ratio, session shape, inter-request timing, request-rate periodicity — and,
combined with the beacon, the entire execution plane. The fingerprint is built from
User-Agent plus protocol only, so it is coarser: distinct clients that happen to send the
same User-Agent collapse into one fingerprint, which makes the cluster signal noisier in
both directions.

What you lose is the header-consistency family of rules. `ua_secch_mismatch` and
`platform_mismatch` cannot fire at all, and they are two of the cheapest, most reliable
signals in the whole ruleset — a spoofed User-Agent that forgets to spoof `Sec-CH-UA`
consistently is caught in one comparison.

---

## What each extra header buys you

| Log this | Field | What becomes possible | Rule(s) |
|---|---|---|---|
| `%v:%p` | `host_s` | Per-vhost separation. Without it, every site sharing a log file is one dataset. | — |
| `%D` | `dur_us_l` | The whole Performance view: p50/p95/p99 by path. Also lets you see a scraper hammering your most expensive endpoint. | — |
| `%O` | `bytes_l` | Bytes actually sent, rather than `%b`'s response-body size. More accurate bandwidth attribution per bot. | — |
| `Accept` | `accept_s` | Sharpens the fingerprint considerably: `Accept` strings vary a lot between real browser versions and are almost always wrong or absent in scripted clients. | strengthens `fp_cluster_proxy_fleet` |
| `Accept-Language` | `accept_lang_s` | Fingerprint, plus the visitor hash. A whole fleet sharing one `Accept-Language` while claiming to be spread across a dozen countries is a strong tell. | strengthens `fp_cluster_proxy_fleet`, `tz_mismatch` |
| `Accept-Encoding` | `accept_enc_s` | Fingerprint. Scripted clients routinely send a short or unusual list. | strengthens `fp_cluster_proxy_fleet` |
| **`Sec-CH-UA`** | `sec_ch_ua_s` | **The single most valuable addition.** A Chrome UA claim can be verified against the client hint Chrome itself sends. Spoofers change the User-Agent string and forget this one constantly. | **`ua_secch_mismatch` (75)** |
| **`Sec-CH-UA-Platform`** | `sec_ch_platform_s` | Cross-check the claimed OS. "Windows" in the UA and `"Linux"` in the hint is a headless container on a Linux host wearing a Windows costume. | **`platform_mismatch` (70)** |
| `Sec-CH-UA-Mobile` | `sec_ch_mobile_b` | Same cross-check for the mobile claim. | `platform_mismatch` |
| `Sec-Fetch-Site` | `sec_fetch_site_s` | Distinguishes a real navigation from a sub-resource fetch and from a cross-site request. Catches direct asset fetching that never loaded the page. | strengthens `no_assets` |
| `Sec-Fetch-Mode` | `sec_fetch_mode_s` | `navigate` vs `cors` vs `no-cors`. A "browser" whose HTML fetch is not a navigation is not browsing. | fingerprint |
| `Sec-Fetch-Dest` | `sec_fetch_dest_s` | `document` / `script` / `image` / `font`. Lets asset classification come from the browser rather than from guessing at file extensions. | improves `asset_ratio_f` |
| `Sec-Fetch-User` | `sec_fetch_user_s` | Present only when a navigation was triggered by a real user activation. Its absence on a top-level HTML request is meaningful. | contributes to `no_interaction` |
| `X-Forwarded-For` | `xff_s` | **Essential if you are behind a proxy or load balancer.** Without it every visitor appears to come from the proxy and IP-based clustering and geo become meaningless. Configure `trusted_proxies` too. | all IP-based rules |
| `%H` | `proto_s` | HTTP/1.1 vs HTTP/2 vs HTTP/3. Part of the fingerprint, and a client claiming a modern Chrome while speaking HTTP/1.1 to an HTTP/2-capable server is worth a look. | fingerprint |
| `SSL_PROTOCOL` `SSL_CIPHER` | `tls_proto_s` `tls_cipher_s` | A coarse TLS fingerprint. Not JA4, but the cipher a client offers still separates browser families from Go, curl and Python clients. | fingerprint |

**If you only add two things, add `Sec-CH-UA` and `Sec-CH-UA-Platform`.** They cost about
40 bytes a line and they are worth 145 points of the ruleset.

### JA4 / JA3

`ja4_s` is defined in the schema and nothing populates it. Apache and nginx cannot produce
it; it comes from a TLS-terminating proxy such as HAProxy. If you have one, log it into a
header and map it — the field is waiting. Nothing in v1 depends on it.

---

## nginx

The equivalent, in the `http {}` block:

```nginx
log_format loghound '$host:$server_port $remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent $request_time '
                    '"$http_referer" "$http_user_agent" '
                    '"$http_accept" "$http_accept_language" "$http_accept_encoding" '
                    '"$http_sec_ch_ua" "$http_sec_ch_ua_platform" "$http_sec_ch_ua_mobile" '
                    '"$http_sec_fetch_site" "$http_sec_fetch_mode" '
                    '"$http_sec_fetch_dest" "$http_sec_fetch_user" '
                    '"$http_x_forwarded_for" "$server_protocol" '
                    '"$ssl_protocol" "$ssl_cipher"';

access_log /var/log/nginx/example_com_access.log loghound;
```

Then `nginx -t && systemctl reload nginx`, and re-run `loghound-setup`.

JSON log formats are first-class — if you already emit JSON, point Loghound at it and the
detector will recognise it.

---

## The beacon

One line on your site. Put it anywhere — `<head>` is earliest, before `</body>` works too:

```html
<script src="https://loghound.example.com/b.js?v=1" defer></script>
```

No dependencies, no cookies by default, passive and throttled event listeners. It ships as
readable, commented source — 33 KB on disk, about 12 KB gzipped.

**Check that your server compresses it.** The shipped vhost examples set the beacon's cache
and CORS headers but deliberately do not touch compression, because on both Debian-family
Apache (`mods-enabled/deflate.conf`) and stock nginx (`gzip on` in `nginx.conf`) it is a
global setting and a per-vhost override is the kind of thing that surprises people. Confirm
it rather than assume it:

```bash
curl -sI -H 'Accept-Encoding: gzip' https://loghound.example.com/b.js | grep -i content-encoding
```

No `Content-Encoding: gzip` in that output means every visitor is downloading 33 KB instead
of 12 KB. Turn compression on for `application/javascript` in your server's global config.

**Without it, plane 3 is blind.** Loghound still works — it still does everything on the
transport and behavioural planes — but headless automation is *inferred* rather than
*proven*, and time-on-site falls back to `log_span_ms`, the weak log-derived number every
other log analyser reports. The two things this project exists to do both need the beacon.

The `?v=` matters: `b.js` is served with `max-age=604800, immutable`, so the only thing
that reaches a returning visitor after an upgrade is a new URL. The panel's Settings page
builds the snippet for you with the beacon file's own modification time in that slot, which
means there is nothing to remember to bump; if you hand-write the tag instead, bump the
number yourself when you upgrade.

Everything the beacon sends, every signal code it can emit, and the exact wire protocol
are in [BEACON.md](BEACON.md).

---

## Solr, and where the two indexes come from

The wizard asks nothing about where the index lives: there is one answer. Loghound provisions
and manages its own two indexes on your Opensolr account, and **an Opensolr account is a hard
requirement.**

Opensolr is **free forever to start — no credit card, no expiry date**.
[Create an account](https://opensolr.com/register) ·
[Sign in](https://opensolr.com/users/login) ·
[What the plans hold](https://opensolr.com/solr-hosting)

Setup asks for the account email and the API key, which is under **Account** in the Opensolr
control panel, and does the rest itself. Retention scales with the plan rather than being cut
off by it — Loghound trims its oldest data before the account reaches its disk limit, so the
free tier keeps running and simply holds less history.

Pointing Loghound at a Solr you run yourself used to be an option and was removed. Loghound
does not merely read and write these two indexes, it owns them: it creates them, uploads the
configsets, reloads the cores and verifies them, and later reports and trims them against your
plan. On a Solr you administer it has no route to create a core or install a configset and no
way to keep the schema right — so the option promised something the product cannot deliver.
See [An older configuration on `solr.mode: custom`](#an-older-configuration-on-solrmode-custom)
if you are upgrading one.

### What it provisions

You give it the email address and API key from your Opensolr control panel and pick a
region from the list the platform returns — nothing is hardcoded, so a region added by
Opensolr shows up without a Loghound release. It then creates both indexes, pushes the
configset to each (**schema first, then `solrconfig.xml`** — reversed, the core reloads
against a config referencing field types the old schema does not define and the reload
fails), reads the connection URL and credentials back, writes them into
`config/loghound.php`, and verifies. You see `Index created`, `Rebuilt`, `Healthy`, and
never have to learn what a configset is.

**The index names are generated, not fixed.** Opensolr index names are unique across the
whole platform, so a hardcoded `loghound_hits` would collide for the second person who
ever installed this. Both cores share one 8-hex install id:

```
loghound_9f3c17ab_hits
loghound_9f3c17ab_sessions
```

If either name is already taken, **the whole pair is retried with a fresh id** — a
mismatched pair is confusing to find in an account holding hundreds of indexes — and any
index the failed attempt already created is deleted before the retry, so a collision
cannot leave orphans on an account you are billed for. After five attempts it gives up
with a clear error rather than looping.

**The API key is an account credential**, not a per-index one: it can create, reconfigure
and delete every index on the account. It is read with terminal echo off, never printed
back — not even masked, because a masked key in a scrollback is still a key in a
scrollback — never written to `/var/log/loghound-install.log`, and stripped out of any
error message the platform echoes back. It lives in `config/loghound.php`, mode `0640`,
in a `0700` directory the web server user cannot reach.

### The configsets

The two configsets under `solr/hits/conf/` and `solr/sessions/conf/` are real, shipped, and
still the schema Loghound runs on. They are what the wizard **uploads to Opensolr** for you —
schema first, then `solrconfig.xml` — rather than something you install by hand.

Solr 9.x. They deliberately load no contrib jars and define no `/stream`, `/sql`, `/export`,
`/replication`, `/update/extract`, `/terms` or `/browse` handlers; [SCHEMA.md](SCHEMA.md) §6
says what each of those would hand an attacker.

**Nothing hardcodes a core name.** Both are read from `solr.hits_core` and
`solr.sessions_core` in the config, and both are generated by `Config::coreName()`; there is no
setting, prompt or environment variable that lets you supply one.

### An older configuration on `solr.mode: custom`

An installation made before the option was removed still has `solr.mode => 'custom'` in
`config/loghound.php`. It is refused, loudly and on purpose: `bin/loghound-tail`,
`bin/loghound-score` and `bin/loghound-retention` all validate the configuration at startup and
**refuse to start**, printing what changed, why, and what to do; the panel's Settings page says
the same at the top of the Solr connection card.

To move: set `solr.mode` to `'opensolr'` and run `bin/loghound-setup`, which provisions the two
indexes on your Opensolr account. **Nothing migrates your existing documents** — the new
indexes start empty, and Loghound backfills only as far as your own log retention reaches (see
below). Your old cores are untouched; delete them when you no longer want them.

---

## Log retention: what Loghound can and cannot see

**Loghound can only ever see as far back as your own log retention.** It reads the files
that exist. There is no historical backfill beyond them, and there is no way to
reconstruct a log line that has been deleted.

Check what your box actually does. It is often not what you assume:

```bash
cat /etc/logrotate.d/apache2         # or /etc/logrotate.d/httpd, nginx
sudo crontab -l | grep -i log
ls -la /etc/cron.d/ | grep -i log
```

Rotation configs commonly keep 14 or 52 files. But a cron entry can also just delete them,
and that is not visible in the logrotate config at all. On the first box Loghound was
deployed to, the crontab held:

```cron
@daily /usr/bin/find /var/log/apache2/ -type f -mtime +10 -exec /usr/bin/rm -f {} +
```

Ten days. Everything older simply does not exist.

**So if you care about long-range history, keep it in Loghound, not in your web server.**
Set `privacy.retention_days` to the window you actually want, and let `loghound-retention`
enforce it. Setup does not ask: the default is 90 days, and it is changed under **Settings →
Privacy** in the panel, alongside how visitor IP addresses are stored (the default keeps the
full address). A Solr document is roughly an
order of magnitude smaller than the raw log line it came from once `keep_raw` is off, and
it is indexed, which the raw log is not.

Two consequences worth planning for:

- **Backfill is one-shot and bounded by what is on disk.** To ingest history you already
  have, run the tailer once with `--from-start`, before your rotation window discards it.
  A newly watched log file is otherwise read from its **end**, so a first install does not
  spend a day replaying a 4 GB backlog.
- **`logrotate` with `delaycompress` is worth setting.** If a rotated file is compressed
  immediately and the daemon was stopped when it happened, the original inode is gone and
  the last few lines of that file are unrecoverable. `delaycompress` leaves a plain `.1`
  for one cycle, which the tailer can find by inode and drain. The daemon reports this
  honestly either way: `loghound-tail --status --human` shows a `MISSED ROTATIONS` count
  when it happens.

---

## Loghound and your other log tooling

You are probably already running something against these files — fail2ban, an
abusive-IP scanner, a log shipper, your own scripts. So, plainly:

**Loghound opens every source log file read-only, and never writes to, truncates, rotates,
renames or deletes one.** Source files are opened with `fopen($path, 'rb')` and no other
mode string appears anywhere near a source path in the codebase. There is a test in the
suite that asserts a source file's size is unchanged after a full read.

Everything Loghound writes goes into `<prefix>/var/`: the SQLite state database, the
status file, the capped bad-line sample. Its own vhost logs to its own files, and you
should **not** point Loghound at those — it would ingest its own beacon traffic and
inflate every number it reports.

Reading the same file from several processes is safe. Loghound holds an open descriptor
and reads forward from a recorded offset; it takes no locks and does not care who else is
reading.

The one interaction worth knowing about: if another tool *rotates or deletes* the files
(as opposed to reading them), Loghound handles it — inode changes are detected on every
poll, the old inode is drained to EOF before being released, and an outright `rm` while
the file is open is detected via the path re-stat and the link count. That last case is
the subtle one: on Linux an unlinked file that a process holds open keeps reading forever
with no error, so a naive tailer looks perfectly healthy while ingesting nothing.

**Inode recycling is handled too, and it is the nastiest case of the lot.** On ext4, a
rotation that renames `access.log` to `access.log.1`, compresses it, unlinks the original
and creates a fresh `access.log` routinely hands the new file the inode number the old one
just freed. The stored `(dev, inode, offset)` cursor then *matches* — a file that no
longer exists — and resuming at that offset silently skips the beginning of the new file.
The tailer looks healthy and quietly drops lines, which is the worst failure this class
can have. So the cursor is validated rather than trusted: a valid offset always sits
immediately after a newline, because only complete lines are ever committed. Reading the
single byte before the cursor is enough to tell a genuine resume from a recycled inode,
it costs one byte per startup, and when it fails the source restarts at 0 and the event is
counted in `MISSED ROTATIONS` rather than hidden.

---

## Upgrading

```bash
sudo ./install/install.sh --upgrade
```

Refreshes the code. `config/loghound.php` and `var/` are never touched.

**If the prefix is a git working copy** — which is a supported and, on some boxes, the
preferred layout — the upgrade is a fast-forward pull in place:

```
git fetch --prune origin
git merge --ff-only @{upstream}
```

It will **never** run `git reset --hard` or `git clean`. Both would delete
`config/loghound.php` (untracked, holds your API key) and `var/state.db`. If the checkout
has diverged and cannot fast-forward, the upgrade stops and tells you, leaving everything
exactly as it was. Local modifications to *tracked* files are reported but never
discarded.

If the prefix is not a checkout, it is a plain file copy instead. The installer says which
one it is doing.

---

## Uninstalling

```bash
sudo ./install/uninstall.sh --dry-run    # print the whole teardown, change nothing
sudo ./install/uninstall.sh              # do it
```

`install/uninstall.sh` is a thin wrapper around `install/install.sh --uninstall` — the same
code path under an obvious name, so there is only one implementation to keep correct. Use
whichever you prefer; every flag is the same.

**Do the `--dry-run` first.** It prints every file it would remove, every service it would
touch, every question it would ask and the exact answer it would take, and changes nothing
at all. That is the flag to use to decide whether to trust it.

It finds the prefix from the installed systemd unit rather than assuming the default, so an
install to `/var/www/loghound` is uninstalled from `/var/www/loghound`. Before anything
under that prefix is touched, the directory has to look like a Loghound install — an
absolute path, not a system directory, containing at least one file only this installer
puts there. If it does not, the system integration is still unwound and the directory is
left strictly alone.

### The order, and why

1. **Units and both timers** stop first, so nothing re-creates the files about to be
   removed or holds the service user open.
2. **The Opensolr indexes**, while `config/loghound.php` still exists — the API key that
   authorises the deletion is in it.
3. **The vhost**, after `apachectl -t` / `nginx -t` passes without it. If the test fails,
   the server is **not** reloaded and keeps serving its last good configuration. This runs
   on boxes with other people's sites on them.
4. **The FPM pool**, then its socket.
5. **The command links**, the cron fallback, any logrotate fragment.
6. **The credentials**, overwritten before they are unlinked.
7. **The install tree**, if you say yes.
8. **The system user** last, with its `adm` membership dropped first and separately — so a
   `userdel` that fails still leaves an account that can no longer read `/var/log`.

### What it destroys, and what it asks first

Each of these is a separate question, asked by name:

- **Overwrite and remove the credentials?** Default **yes**. This is `config/loghound.php`
  (the Opensolr API key and account email, the beacon HMAC secret, `privacy.ip_salt`, any
  Solr password and the panel password hash), `config/.loghound.*.tmp` (the same file
  mid-write, if `save()` was ever interrupted), the self-signed TLS private key,
  `var/install-token` and its attempt ledger, the panel's lockout ledger, `var/state.db`,
  `var/panel-jobs.db` and both their write-ahead logs, `var/setup/*.json`, and every PHP
  session file — a session file *is* a signed-in panel session.

  Overwriting a file is not a guarantee. On a copy-on-write filesystem (btrfs, ZFS), an
  overlayfs, a snapshotted volume or any SSD with wear levelling, the write lands in new
  blocks and the originals remain on the media. Backups and VM snapshots are untouched by
  definition. **If this box is being decommissioned, sold or handed on, rotate the Opensolr
  API key.** That is the only reliable remedy.

- **Delete `<prefix>`?** Default **no**.

- **Delete the two Opensolr indexes?** Default **no**, and this one is not something
  `--yes` can answer — it takes the literal word `DELETE` typed at the prompt, or
  `LOGHOUND_UNINSTALL_DELETE_INDEXES=yes`. Deleting an index destroys its data and burns
  its name: Opensolr index names are unique across the entire platform and are never
  released, so **neither name can ever be created again**, by you or by anyone else.

  Only the two indexes *this installation provisioned* are ever offered. The names are
  derived from `solr.install_id` by the same function that created them, checked against
  `^loghound_[a-f0-9]{8}_(hits|sessions)$`, required to match what is stored in the config,
  and then cross-checked against your account's own index list. No name is ever read from
  the command line, no prefix is ever swept, and nothing else in your account is touched.

  If any part of that cannot be checked — the control plane is unreachable, the credentials
  are gone, the config is unreadable, the listing comes back empty — **nothing is deleted.**
  A check that could not be performed is a failed check. The two names are printed instead,
  so you can remove them in the Opensolr control panel if you want to.

  On a `solr.mode = custom` install, no core is touched at all: Loghound will not unload a
  core from a Solr it does not manage.

- **Remove the system user?** Default **yes**.

### What it deliberately does not remove

Printed at the end of every run, so you never have to guess:

- **The beacon `<script>` tag on your site.** Only you can take that out of your templates.
- **A certbot certificate for the panel hostname.** Never deleted silently: other vhosts may
  be using it, and re-issuing after a mistake runs into Let's Encrypt rate limits. You get
  `certbot delete --cert-name <host>` and the decision.
- **The panel's own `loghound_access.log` / `loghound_error.log`** in your web server's log
  directory. Your logrotate owns those.
- Anything you added by hand — a supervisor unit, a firewall rule, a reverse proxy entry, a
  monitoring check, a backup job. The uninstaller removes what the installer created and
  refuses to guess at the rest.
- **Your source log files**, which were never written to in the first place.

A half-finished install — no config, no user, units copied in but never enabled — uninstalls
cleanly rather than aborting on the first missing thing.

### Unattended

```bash
sudo LOGHOUND_UNINSTALL_DELETE_TREE=yes \
     LOGHOUND_UNINSTALL_REMOVE_USER=yes \
     ./install/uninstall.sh --non-interactive
```

| Variable | Default | Effect |
|---|---|---|
| `LOGHOUND_UNINSTALL_SHRED_SECRETS` | `yes` | set to `no` to leave the credentials on disk |
| `LOGHOUND_UNINSTALL_DELETE_TREE` | `no` | set to `yes` to remove the install directory |
| `LOGHOUND_UNINSTALL_REMOVE_USER` | `yes` | set to `no` to keep the service user |
| `LOGHOUND_UNINSTALL_REMOVE_LOG` | `no` | set to `yes` to remove `/var/log/loghound-install.log` |
| `LOGHOUND_UNINSTALL_DELETE_INDEXES` | `no` | set to `yes` to permanently delete the two indexes |

---

## Unattended installs

Everything is answerable from the environment:

```bash
sudo LOGHOUND_HOSTNAME=loghound.example.com \
     LOGHOUND_PANEL_USER=admin \
     LOGHOUND_PANEL_PASSWORD='...' \
     LOGHOUND_OPENSOLR_EMAIL=you@example.com \
     LOGHOUND_OPENSOLR_API_KEY='...' \
     LOGHOUND_OPENSOLR_REGION=FINLAND9 \
     LOGHOUND_IP_MODE=truncate \
     LOGHOUND_RETENTION_DAYS=90 \
     ./install/install.sh --non-interactive --tls-mode existing \
       --tls-cert /etc/letsencrypt/live/loghound.example.com/fullchain.pem \
       --tls-key  /etc/letsencrypt/live/loghound.example.com/privkey.pem
```

The full list of `LOGHOUND_*` variables is in the header comment of `bin/loghound-setup`.
The API key is never echoed to the terminal and never written to the install log.

`LOGHOUND_IP_MODE` and `LOGHOUND_RETENTION_DAYS` are overrides with no prompt behind them —
the wizard does not ask about either, interactively or otherwise. Leave them out and the
defaults stand: the full address, 90 days, changed afterwards under **Settings → Privacy**.
Either works on its own; the one you do not set keeps whatever the configuration already holds.

There is **no variable that supplies a Solr address, HTTP credentials or a core name**. The
connection details come back from Opensolr and the two index names are generated, so an
unattended install needs the three `LOGHOUND_OPENSOLR_*` answers and nothing else about
storage. Re-running the wizard on a box that already has both indexes leaves them alone —
`LOGHOUND_RECONFIGURE_STORAGE=yes` if you really do want provisioning to run again.

`--non-interactive` also switches on automatically when stdin is not a terminal, because
a wizard that blocks forever on a closed stdin is the worst possible failure mode inside
an automated deploy.

---

## Troubleshooting

**`AH00035: access denied because search permissions are missing`**
`<prefix>` is not traversable by the web server user. `chmod 0751 <prefix>`. Do **not**
add the web server user to the `loghound` group — that needs an Apache restart, not a
reload. Re-run the installer and read the permission-verification block.

**`unable to get local issuer certificate` in the browser**
You are serving a certificate that does not chain to a trusted root — very often a Let's
Encrypt **staging** certificate. Check:

```bash
openssl x509 -in /path/to/fullchain.pem -noout -issuer -dates
openssl verify -untrusted /path/to/fullchain.pem /path/to/fullchain.pem
```

Re-issue without `--staging` / `--test-cert`, then re-run with `--tls-mode existing`.

**The daemon is running but nothing is indexed**

```bash
loghound-tail --status --human
```

Look at `lag`, `parse errors` and `solr errors`. Then:

```bash
sudo -u loghound php <prefix>/bin/loghound-tail --once --from-start --dry-run --verbose
```

That replays the whole file, parses it and indexes nothing. If it reports documents, the
pipeline works and the issue is Solr connectivity or the fact that a newly watched file
starts at EOF.

**Parse errors climbing**

```bash
sudo tail <prefix>/var/badlines.log
```

Every unparseable line is counted and a capped sample is written there with its source
file and byte offset — never silently dropped. Usually it means the configured format no
longer matches the file, which happens when someone changes `LogFormat` without re-running
`loghound-setup`.

**`loghound-tail --status` says STALE**
The status file has not been updated for more than ten seconds; the daemon has probably
died. `journalctl -u loghound-tail -n 50 --no-pager`.

**The service user cannot read the logs**

```bash
ls -ld /var/log/apache2 /var/log/nginx
sudo -u loghound test -r /var/log/apache2/access.log && echo ok || echo denied
```

The directory usually needs to be group `adm` and group-readable. Note that group
membership added a moment ago applies only to **new** processes — which is why the
installer tests with a fresh one rather than trusting `id`.

**No documents after 60 seconds on a quiet site**
Probably correct behaviour: there were no requests, and a newly watched file is read from
its end. Generate some traffic, or use `--from-start`.

---

## Appendix: installing by hand

If you would rather not run a script as root, here is the same thing step by step. This is
also the path to follow on a distribution the installer does not recognise.

**1. Dependencies**

```bash
# Debian / Ubuntu
sudo apt-get install -y php-cli php-curl php-sqlite3 php-mbstring php-fpm

# RHEL family
sudo dnf install -y php-cli php-curl php-pdo php-mbstring php-fpm
```

**2. User and files**

```bash
sudo useradd --system --home-dir /opt/loghound --no-create-home \
             --shell /usr/sbin/nologin --comment Loghound loghound
sudo usermod -aG adm loghound

sudo mkdir -p /opt/loghound
sudo cp -a bin src public solr docs install tests SPEC.md README.md LICENSE /opt/loghound/
sudo mkdir -p /opt/loghound/var /opt/loghound/config /opt/loghound/var/sessions
```

**3. Permissions — get these exactly right**

```bash
sudo chown -R root:loghound /opt/loghound/bin /opt/loghound/src /opt/loghound/public /opt/loghound/solr
sudo chown -R loghound:loghound /opt/loghound/var /opt/loghound/config

sudo chmod 0751 /opt/loghound                 # traverse, no listing
sudo chmod 0700 /opt/loghound/config          # secrets
sudo chmod 0750 /opt/loghound/var
sudo chmod 0700 /opt/loghound/var/sessions
sudo find /opt/loghound/src /opt/loghound/bin /opt/loghound/solr -type d -exec chmod 0750 {} +
sudo find /opt/loghound/src /opt/loghound/bin /opt/loghound/solr -type f -exec chmod 0640 {} +
sudo chmod 0750 /opt/loghound/bin/loghound-*
sudo find /opt/loghound/public -type d -exec chmod 0755 {} +
sudo find /opt/loghound/public -type f -exec chmod 0644 {} +
```

Verify, as the users themselves — do not skip this:

```bash
sudo -u www-data test -x /opt/loghound                  && echo "traverse ok"
sudo -u www-data test -r /opt/loghound/public/index.php && echo "docroot ok"
sudo -u www-data test -r /opt/loghound/config           && echo "SECRETS EXPOSED — fix it" || echo "config protected ok"
sudo -u loghound test -r /var/log/apache2/access.log    && echo "logs readable"
```

**4. PHP-FPM pool**

```bash
sudo cp install/php-fpm-pool.conf.example /etc/php/8.3/fpm/pool.d/loghound.conf   # adjust version
sudo $EDITOR /etc/php/8.3/fpm/pool.d/loghound.conf     # set listen.owner to your web server user
sudo php-fpm8.3 -t                                     # VALIDATE FIRST
sudo systemctl reload php8.3-fpm                       # reload, never restart
```

**5. vhost**

```bash
sudo cp install/apache-vhost.conf.example /etc/apache2/sites-available/zzz-loghound.conf
sudo $EDITOR /etc/apache2/sites-available/zzz-loghound.conf   # ServerName, cert paths, socket
sudo a2enmod ssl rewrite headers proxy_fcgi
sudo a2ensite zzz-loghound
sudo apache2ctl configtest                              # VALIDATE FIRST
sudo systemctl reload apache2
```

Name it so it sorts **after** any existing catch-all vhost. `apache2ctl -S` shows you
which vhost is currently the default for each address:port; make sure it is still that one
afterwards.

**6. systemd units**

```bash
sudo cp install/loghound-*.service install/loghound-*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now loghound-score.timer loghound-retention.timer
```

**7. Configure and start**

```bash
sudo -u loghound php /opt/loghound/bin/loghound-setup
sudo systemctl enable --now loghound-tail.service
loghound-tail --status --human
```

**8. Beacon** — add the one-line snippet to your site.
