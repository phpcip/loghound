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

## Signing in to the panel

The panel shows every visitor, page and address on your site, so it is never served without
a password. With no credentials configured it answers **503 and refuses to serve** — an
analytics dashboard left open on the internet is a data breach, and defaults decide
outcomes.

### The two sign-in methods

Chosen during setup, changeable afterwards in **Settings › Sign-in**. Changing it applies to
the next request and does not touch your username or password.

| | |
|---|---|
| **The browser's own password prompt** (`auth.mode: basic`) | HTTP Basic. Every tool that speaks HTTP can sign in the same way, so `curl --user` and monitoring checks work. The prompt cannot be styled, and there is no way to sign out short of closing the browser. |
| **A sign-in page** (`auth.mode: session`) | Loghound's own form, a real session, and a Sign out button that destroys the session on the server. Required for two-factor and for "stay signed in". It only works in a browser: `curl` cannot sign in to it, so move any monitoring check to Basic or drop it. |

Session mode keeps its session files in the directory named by `session.save_path` in the
FPM pool — `<prefix>/var/sessions` in a standard install. If you switch to it on a host
where it has never been used, create that directory and give it to the service user first.

### Timeouts

Session mode only, both enforced by the application on every request rather than left to
PHP's session garbage collector, which is best-effort by design and runs on somebody else's
request:

- `auth.idle_timeout` — 30 minutes. Ends a session that has done nothing for that long.
- `auth.absolute_timeout` — 12 hours. Ends one that long after sign-in, however busy.

An expired session is destroyed on the spot and the operator lands back on the sign-in
page, so a timeout is a door that reopens rather than a dead end.

### The lockout

`auth.lockout_attempts` failed sign-ins from **one address** inside `auth.lockout_window`
seconds lock that address out until the window passes. Eight in fifteen minutes by default.

It is per address and deliberately has no global cap: a global counter on a login form is a
denial-of-service primitive handed to anyone who can reach it — a few thousand wrong
passwords from a botnet would trip it and lock the legitimate operator out of their own
panel. Per address, an attacker can only lock out the address they are attacking from.

The counter is a **file**, `var/login-attempts.json`, with addresses stored hashed. Nothing
clears it faster than the window except deleting that file; restarting PHP-FPM does nothing
to it, whatever other software may have told you.

It applies to HTTP Basic, to the sign-in form, to the two-factor step, and to a request
arriving with a "stay signed in" cookie. A stolen cookie is not a way round it. If the
ledger cannot be written, sign-in is **refused** rather than allowed: a check that cannot be
performed is a failed check.

### Stay signed in

The sign-in form offers **Stay signed in on this browser**, off by default. A browser that
takes it is signed in with **no idle timeout and no maximum session age**: the session
survives closing the browser, restarting the machine, and any amount of inactivity, and ends
only when somebody presses Sign out.

**What that costs, plainly:** whoever holds that browser profile has this panel,
indefinitely. There is no timeout to save you from a lost laptop. Leave the box unticked on
a shared or portable machine.

It is not just a long-lived cookie, because a long-lived cookie does not work: PHP deletes
session files on a schedule of its own, and a cookie that outlives the file it names signs
you out by accident — the exact thing the option is for. The cookie instead carries a
lookup id and a secret, of which only a **hash** of the secret is stored, in
`var/persistent-logins.json` at mode 0600. The secret is **replaced every time the cookie is
used**, so a copy taken from a backup or a synced profile stops working the moment the real
browser makes one more request; and because the lookup id does not change, a secret that
turns up twice is unambiguously a **replay**. When that happens every token for the account
is destroyed, every browser has to sign in again, and the sign-in page says so.

Five things revoke it:

- **Sign out** — revokes every token, not just this browser's.
- **Signing in with the box unticked** — you said you did not want to be remembered.
- **Settings › Sign-in › Sign every remembered browser out** — which also reports how many
  there are.
- **Changing the password** (`bin/loghound-setup`) or **changing the sign-in method**.
- **Turning two-factor on** — a token issued on the strength of one factor cannot survive as
  a way past two.
- Deleting `var/persistent-logins.json`.

`auth.persistent_lifetime` caps how long a token can live, renewed on every use. The default
is ten years, which for a browser in daily use is indistinguishable from permanent; the
number exists so an abandoned token can be pruned rather than accumulate. It is clamped to a
day at the bottom.

### Two-factor authentication

Standard TOTP — the six-digit codes every authenticator app produces (RFC 6238: HMAC-SHA1,
six digits, a 30-second step). Off by default; existing installations are untouched. Needs
`auth.mode: session`, because HTTP Basic has no second step to put a code in.

Set it up in **Settings › Two-factor**, not by hand:

1. **Set up two-factor authentication** mints a fresh secret and shows a QR code. The QR
   code is drawn **on your own server**, by Loghound, in pure PHP — no chart-server URL, no
   CDN'd encoder. Sending the shared secret to a third party to have a picture of it drawn
   would hand somebody else your second factor.
2. Scan it with any standard app (Google Authenticator, Aegis, 1Password, Bitwarden,
   FreeOTP), or type the key in by hand — it is shown grouped in fours for exactly that.
3. **Enter the code the app shows now.** Nothing is stored until this is accepted, so
   closing the tab half way through leaves two-factor off and locks nobody out.
4. **Save the ten recovery codes.** They are shown once, and downloadable as a text file,
   because only their hashes are stored. Each works once, in place of a code from the app.
   They are the only way back in if you lose the phone. You can issue a fresh set at any
   time, which invalidates the old one.

An unconfirmed enrollment **expires 15 minutes after you press the button**, on the clock
and not on the session. Walk away from that screen and the candidate secret is discarded;
come back and you start again with a fresh QR code. The distinction matters because "Stay
signed in" means a session can now last forever, and a pending secret must not inherit that
— the expiry is swept on every authenticated request, so it happens whether or not anybody
reloads the page.

A code is accepted within one 30-second step either side of now, for clock drift, and
**once**: the last accepted step is recorded in `var/auth-state.json` and anything at or
below it is refused, so a code read over your shoulder is worth thirty seconds of nothing.

**Every place a code is checked is rate limited, on the same per-address ledger as the
sign-in form** — the sign-in page's second step, the enrollment confirmation, turning
two-factor off, and reissuing recovery codes. `auth.lockout_attempts` wrong codes inside
`auth.lockout_window` (eight in fifteen minutes by default) lock the address out, and a
recovery code counts the same as a six-digit one. A wrong code costs exactly what a wrong
password costs, including the delay, so no endpoint is the cheaper place to guess; and
because there is one ledger rather than one per endpoint, alternating between them buys no
extra attempts. Six digits is a million possibilities, and that limiter is the only thing
between a stolen password and a guessed code.

**Turning two-factor off requires a current code or a recovery code**, and so does
**reissuing recovery codes** — never just being signed in. If a stolen session cookie were
enough to strip the second factor, the second factor would be protecting nothing; and ten
fresh recovery codes are a standing way past the phone, so minting them is the same act by
a quieter route.

**Lost the phone and the recovery codes?** Run `bin/loghound-setup` on the server and set a
new password. That turns two-factor off and revokes every remembered browser. Being able to
run it is already proof of who you are — which is also why there is no reset by email:
Loghound has no mail path and would not use one for this.

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

Then reload and re-run the wizard so it picks up the new format:

```sh
apache2ctl configtest && systemctl reload apache2
sudo -u loghound php /opt/loghound/bin/loghound-setup
```

### Three ways this silently does nothing, in the order people hit them

Every one of these leaves you with a correct-looking config, a clean reload, and no
duration in the panel. None of them writes anything to any error log.

**1. Do not reuse the name `combined`.** Debian and Ubuntu already define that nickname in
`apache2.conf`, and redefining it inside a virtual host does not reliably win. You edit the
file, you reload, the config is correct, and the lines keep coming out in the old shape
with nothing anywhere to tell you why. Give your format its own name, as above. If all you
want is the duration for the Performance view, `combined_d` is a fine name for it:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %O %D \"%{Referer}i\" \"%{User-Agent}i\"" combined_d
CustomLog ${APACHE_LOG_DIR}/example_com_access.log combined_d
```

A format that nothing references changes nothing, so the `CustomLog` line is not optional.

**2. Reload, and check that the reload really happened.** A graceful reload keeps the same
master process, so the process start time does not move and the server looks untouched
whether or not you ran it. Compare the modification time of the vhost against the last
`AH00493: SIGUSR1 received.  Doing graceful restart` in `error.log`. A config edited hours
ago on a server that was never reloaded is the most common version of this.

**3. Tell Loghound the shape changed.** This is the one that bites after you have done the
first two correctly. Loghound compiles and **stores the log format per source**, so the
moment a line gains a field the stored format has no column for, every new line becomes a
parse error. The lines are still being written and still being read; the parse-error
counter climbs and nothing new appears in the panel. Re-run `bin/loghound-setup`, or
rescan the source under **Settings › Log sources**, and check
`bin/loghound-tail --status --human` afterwards — parse errors should be back to zero
within a minute.

Loghound does not yet detect this for you. It could: the condition is a source that was
parsing cleanly and suddenly is not, right after its lines changed shape. It is not
shipped because the tailer's `parse_errors` is a single process-wide counter with no
per-source attribution, and a warning derived from it could not tell "this source changed
format" from "somebody pointed a vulnerability scanner at the site" — which would teach
you to ignore the warning that is right. Until it exists, the rescan is yours to remember,
and every place in the panel that suggests a format change says so.

**The quickest way to see which of the three you are in:** look at one real line in the
log file. If it has no duration in it, you are in 1 or 2. If it has one and the panel is
still empty, you are in 3.

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

The three failures above apply here too, with one difference: nginx defines `combined`
itself and refuses a second definition outright, so cause 1 is a startup error rather than
silence. Causes 2 and 3 are identical — reload for real, then rescan the source, because
Loghound stores the format per source and a line that gained `$request_time` no longer
matches the one it stored.

JSON log formats are first-class — if you already emit JSON, point Loghound at it and the
detector will recognise it.

---

## The beacon

One line on your site, in `<head>`. With `defer` it never blocks rendering wherever it
sits, so the only thing placement changes is when the browser starts fetching it: in
`<head>` that is immediately, before `</body>` not until the parser has walked the whole
document. Both work; one starts sooner.

```html
<script src="https://loghound.example.com/b.js?v=1757000000" defer></script>
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

**The `?v=` matters, and it is not a number you choose.** `b.js` is served with
`max-age=604800, immutable`, so a browser that already has the file will not ask for it
again for a week whatever changes on the server — the only thing that reaches a returning
visitor after an upgrade is a different URL. Loghound fills the slot in from the beacon
file's own modification time everywhere it prints a snippet: the panel's Settings page, the
installer's last screen, `install.sh`'s closing report and `bin/loghound-setup`. Copy the
snippet one of those gives you rather than the example above, and do not pin it to a number
of your own.

**The tag takes more than a `src`.** Six attributes and two globals: `data-ident` and
`data-signed-in` to say who the visitor is, `data-params` to keep named search terms,
`data-hb` and `data-idle` to change the two clocks, `data-endpoint` for a collector that is
not a sibling of the script, `window.LoghoundIdent` / `window.LoghoundSignedIn` for a
template that cannot add an attribute, and `window.loghound.identify()` for a sign-in that
happens after the page loaded. What each one defaults to, what it accepts, and whether
*this* installation stores what it sends:

```
bin/loghound-setup --beacon-doc
```

The same reference is on the panel under Settings → Beacon, and the long form — every field
the beacon sends, every signal code it can emit, the standalone contract and the exact wire
protocol — is in [BEACON.md](BEACON.md).

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

### Which account, then which indexes

**These are two questions and they are always asked in that order.** Naming an Opensolr account
is one decision; saying where this site's traffic should land is another. Step one takes the
account email and the API key and saves them on their own, with nothing asked about indexes and
nothing refused because of what the account does or does not hold. Step two, separately, asks
which indexes to use.

Between the two there is a moment where the configuration names indexes the new account does not
hold — that is normal, it is not an error, and both the wizard and **Settings → Solr connection**
say so in those words, with the list to pick from right beside the sentence. It survives closing
the tab: an account saved is an account saved, and the choice is still waiting when you come
back.

Step two reads your account once and shows what is there — how many indexes it holds, which
pairs of Loghound indexes are already on it, and anything a half-finished setup run left behind
— then offers **one list**: every pair the account holds, plus one more option meaning *make a
new pair for this site*. You pick one.

**One pair of indexes can serve several sites.** Every record Loghound writes carries the
virtual host it came from, so a pair collecting traffic from six machines stays separable in
the panel by its **Virtual host** dimension. If you are installing Loghound on your third
site, joining the pair the first two report into is usually what you want — and on a plan with
a small index limit it is the only thing that will work.

Pairs are listed and chosen as pairs, never as halves:

```
Which indexes this installation uses:

    This account holds one pair of Loghound indexes. Pick it and this site records into
    it alongside whatever is already there, or have Loghound make a pair of its own for
    this site.

      aaaa1111   loghound_aaaa1111_hits + loghound_aaaa1111_sessions
      new        Make a new pair for this site

Which indexes should this installation use (aaaa1111|new) [new]:
```

A single pair is still something you pick. Loghound does not adopt the only pair on the account
on your behalf — you have said which account to use and have not yet said anything about
indexes.

The same list, the same options in the same order and the same sentences appear in the browser
installer and in **Settings → Solr connection**, because all three render one decision rather
than three descriptions of it. Changing accounts and moving onto a different pair are the same
flow: Settings has no separate pair-switcher.

Choosing a pair confirms it is still on the account, reads the connection details, **checks
the indexes have the shape this version writes** — by comparing their live schema against the
one in this release, field by field — and queries both. **Reusing joins; it never overwrites.**
Nothing is cleared, reshaped or reloaded, and what this installation records is added alongside
what is already there.

If the indexes were made by an older Loghound and are missing fields this version writes, the
run stops and names the missing fields, having changed nothing. Answer yes to *"add the fields
this version writes"* (or set `LOGHOUND_OPENSOLR_UPGRADE_SCHEMA=yes`) to have them added — that
only ever adds fields and never alters a document already in the index.

An **unmatched half** — a `_hits` with no `_sessions` — is what a run that died between the two
creates leaves behind. It is reported as exactly that, with the name of the index and the name
of the one it is missing. It cannot be joined and it holds no usable data on its own, but it
still counts against your plan.

### Starting over

There are two different things here, and the difference is whether your data survives.

**`bin/loghound-setup --reset` is the narrow one.** It clears the log sources, the index names
and the sign-in and walks you back through setup. It is not an uninstall: your indexes, every
document in them and your log files are untouched, and the Opensolr account is kept so setup can
offer the pair you were already using.

**The Start over card at the bottom of Settings deletes everything.** Both Opensolr indexes and
every document in them go from your account, and the card proves it by reading the account
listing again afterwards; the configuration goes with your Opensolr email, API key and region in
it; every persistent-login token is revoked and everything under `var/` is deleted. You land on
the installer and provide all of it again, exactly as on a first install. The only way to keep
the data is an Opensolr backup taken **before** you press it, which is a separately billed
feature. It costs a typed `DELETE EVERYTHING` and a current second factor where two-factor is on.

Your access log files and the `LogFormat` line in your own vhost are untouched by both.

From the panel it does not lock you out: confirming in a signed-in session is a stronger proof
than the token file, so that proof is carried to that browser for half an hour, once. Anyone else
reaching the installer still has to read `var/install-token` over a shell.

`install/uninstall.sh` removes Loghound from the machine as well — the units, the vhost, the
PHP-FPM pool, the command links, the service user and the install tree — and deletes the indexes
through the same code the panel uses.

### Your plan has to have room, and that is checked first

Opensolr plans limit how many indexes an account may hold, and Loghound needs **two**.
Discovering that halfway through provisioning means one index created, one refused, and a bill
for the orphan — so the account is counted **before** the first create, and when the allowance
is known and too small the wizard stops with the numbers and does not create anything:

```
Your Opensolr plan allows 4 indexes and 4 are already in use, so there is room for
none more and Loghound needs 2.

xx  There is nothing to pick here yet: this account holds no pair of Loghound indexes,
    and there is no room to create one. Your Opensolr plan allows 4 indexes and 4 are
    already in use, so there is room for none more and Loghound needs 2.
    Two ways on from here:
      - Delete an index you no longer need, which frees a slot immediately. https://opensolr.com/solr_manager/admin
      - Move to a plan that allows more indexes. https://opensolr.com/solr-hosting
```

That is the dead end, and it is the only case with no way through inside Loghound. When the plan
is full but the account **does** hold a pair, the list still has that pair on it — joining
creates nothing, so the limit does not apply to it — and only the *make a new pair* option is
withheld, with the numbers saying why.

The allowance comes from Opensolr's `get_account_summary`, which reports how many indexes the
plan allows, how many exist and how many more can be created — from the same two figures the
platform's own create gate uses, so what you are told and what it enforces cannot disagree. It
is read every time rather than remembered, because a plan can change.

Asking costs an existing index: the endpoint is scoped to one core you own. An account with no
indexes at all therefore has no readable allowance, and Loghound says that plainly instead of
assuming there is room.

A check is a check, not a promise — another machine can take the last slot between the check and
the create — so if the **second** index is the one refused, the first is deleted and you are told
that nothing was left behind:

```
ok    Creating the hits index — Created loghound_9ce6e3c9_hits.
xx    Creating the sessions index:
      Your Opensolr plan allows 4 indexes and 3 are in use, so there is room for the 2
      Loghound needs. ...
      Removing loghound_9ce6e3c9_hits, which this attempt created and will not be using …
      Removed loghound_9ce6e3c9_hits. Nothing has been left behind on your account.
```

### What it provisions

If you are creating a new pair, you pick a region from the list the platform returns — nothing
is hardcoded, so a region added by Opensolr shows up without a Loghound release. It then
creates both indexes, pushes the
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
status file, the capped bad-line sample.

Loghound's own vhost logs to its own files, and pointing Loghound at those is a choice rather
than a mistake. **Its own instrumentation is never counted, wherever the log comes from**:
`/b.js` and the collector are matched on host *and* path, derived from `base_url`, and excluded
from the session aggregate — the path list, the unique-path and hit counts, the asset counts and
ratio, the status classes and the gap series. A measured site's own `/collect.php` is a
different URL and is untouched. What remains is people browsing the panel, which is ordinary
traffic to a real site: keep it if you want to see who is using Loghound, or leave it out if you
would rather the numbers were only about the sites you are measuring. To leave it out, switch
the source off rather than deleting it:

```php
[
    'path'    => '/var/log/apache2/loghound_access.log',
    'format'  => 'apache_combined',
    'host'    => 'loghound.example.com',
    'enabled' => false,
],
```

`enabled` is optional and absent means enabled, so every configuration written before it existed
behaves exactly as it did. A value that is not readable as a boolean is a configuration error
rather than a silently dead source.

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
php ./bin/loghound-schema                # then this, every time
```

Refreshes the code. `config/loghound.php` and `var/` are never touched.

### The second line is not optional

Your two indexes keep running the configset that was uploaded when they were created.
A release that adds a field therefore ships code that writes a field the live schema does
not declare — and the only dynamic field in either schema is `*` mapped to the `ignored`
type, so **Solr accepts the document, discards that value, and answers 200**. Nothing
raises an error: not the tailer, not the platform, not the panel. The first symptom is a
facet that is permanently empty, months later, and the values that were dropped are gone.

`bin/loghound-schema` is the supported fix. It reads the schema each index is actually
running, compares it field by field against the configsets in this checkout, and tells you
exactly what is missing:

```
$ php bin/loghound-schema
Loghound schema check
  installation : /opt/loghound
  release      : 187edea2d4fb8de4

  hits      loghound_9f3c17ab_hits           BEHIND        3 missing: planes_s, search_terms_ss, install_s
  sessions  loghound_9f3c17ab_sessions       CURRENT       106 fields, all present

Out of date. […]
Fix it with:
  php /opt/loghound/bin/loghound-schema --apply
```

`--apply` uploads this release's configsets — schema first, then `solrconfig.xml`, then a
core reload, the same call and the same order the installer uses. It is **additive**: it
adds the missing fields and does not touch a document already in the index.

| Flag | What it does |
|---|---|
| *(none)* or `--check` | Compare and report. Changes nothing, anywhere. |
| `--apply` | Push this release's configsets to any index that is missing fields, then re-read the live schemas and report what is there now. |
| `--quiet` | Print only what is wrong, and the verdict. |

| Exit code | Meaning |
|---|---|
| `0` | Up to date — both live schemas declare every field this release writes. |
| `1` | Unusable configuration, unknown flag, or no indexes provisioned yet. |
| `2` | Failed — a schema could not be read, or an upload was rejected. |
| `3` | Out of date — an index is missing a field (`--check` only). |
| `4` | Needs migrating — an index still declares Solr's **managed** schema factory. |

`4` is deliberately not `2`. `2` means the check could not be made and running it again may
answer; `4` means the check was made, the answer is known, and it will not change on its own.
An index whose `solrconfig.xml` still declares `ManagedIndexSchemaFactory` is one where **Solr
owns the schema file**: the `schema.xml` Loghound uploads sits in the configset unused, and
every schema upload to it reports success and changes nothing — including the ones you have
already run. `--apply` resolves it by uploading the whole configset in dependency order, which
ends with the `solrconfig.xml` that switches the index to the classic factory.

```bash
php bin/loghound-schema || php bin/loghound-schema --apply
```

**A field your index has and this release does not write is not an error** and is never
"fixed": that is a newer schema, or a field a later release dropped, and it costs nothing.

**A schema that cannot be read is never reported as matching.** If the control plane does
not hand one back, the command says so and exits 2 — and `--apply` refuses to push to that
index, because a push replaces the whole configset and pushing blind over a schema that
might be newer would delete the fields that newer release writes. Run it again when the
platform answers.

**Three states, not two.** `--check` can also report that an index is still running Solr's
**managed** schema factory. That is the one an operator cannot diagnose alone: in that state the
`schema.xml` this release uploads is ignored, every schema push reports success and changes
nothing, and no field ever arrives. `--apply` fixes it by uploading the whole configset in
dependency order, ending with the `solrconfig.xml` that switches the factory.

A push that only half lands says which file was rejected and what state that leaves the index
in. The three halting points are three different situations:

- **`mapping-ISOLatin1Accent.txt` rejected** — nothing reached the index at all.
- **`schema.xml` rejected** — the support file is on the index and unused; the schema in force is
  unchanged. Re-running is completely safe.
- **`solrconfig.xml` rejected** — the support file and the new `schema.xml` are both on the index,
  but the index is still on the managed factory, so `schema.xml` is being **ignored** and the
  fields this release writes are **not** there however successful the schema upload looked. The
  index still serves everything it held. Run it again to finish.

The verdict is written to `var/schema-check.json`, which is what the **Solr** card on the
panel's Settings page reads — so running this over SSH updates what the browser shows. The
panel never fetches a live schema while a page renders; it shows the saved verdict, states
how old it is, and offers a button that runs the same check as a background job. A verdict
taken before an upgrade is reported as saying nothing about the release running now, rather
than being shown as a clean bill of health.

It refuses to run under a web SAPI, wherever the file is copied to.

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

The run prints eleven numbered steps — `==> [3/11] Deleting the Loghound indexes` — so a
terminal watched over SSH always says where it is, and a step that bails out early still
prints, as a skip, rather than leaving a gap you have to assume was fine. Colour is optional
and nothing depends on the terminal being wide.

**It is the same eleven, under the same names, that the panel runs.** The list lives once, in
`Loghound\Setup\Teardown::STEPS`, and a test asserts the shell script prints exactly it, in
order. Two front ends that disagree about what a teardown *is* are two front ends nobody can
check against each other.

1. **Services and timers** stop first, so nothing re-creates the files about to be removed
   or holds the service user open.
2. **Proving your account owns these indexes**, while `config/loghound.php` still exists —
   the API key that authorises the deletion is in it.
3. **Deleting the Loghound indexes**, and only on the confirmation described below.
4. **Confirming they are gone from your account.** The account listing is re-read and each
   name is reported `GONE` or `PRESENT`. *The proof is the listing, not the delete
   response*: a control plane that answered `status: true` has told you it accepted the
   request, which is a weaker claim than the index being gone — and you are about to stop
   being billed for it on the strength of that claim.
5. **The vhost**, after `apachectl -t` / `nginx -t` passes without it. If the test fails,
   the server is **not** reloaded and keeps serving its last good configuration. This runs
   on boxes with other people's sites on them.
6. **The FPM pool**, then its socket.
7. **The command links**, the cron fallback, any logrotate fragment.
8. **The credentials and local data**, overwritten before they are unlinked.
9. **The install tree**, if you say yes.
10. **The system user**, with its `adm` membership dropped first and separately — so a
    `userdel` that fails still leaves an account that can no longer read `/var/log`.
11. **What was NOT removed**, printed in full, so you never have to guess.

### From the panel instead

Settings → **Remove Loghound entirely** runs the same eleven steps as a job you can watch,
and performs the five it can: proving ownership, deleting, confirming absence, emptying
`var/`, and removing the configuration. The other six need root, and the panel does not
pretend otherwise — there is no `exec`, `shell_exec`, `proc_open` or SSH anywhere in `src/`,
`bin/` or `public/`, and that is not being traded for a button that stops a systemd unit.
Each of those six is still shown in its place, saying why it needs a shell, and the run ends
by naming the command that finishes the job.

It costs a typed `DELETE EVERYTHING` and, where two-factor is on, a current code — the same
price as turning two-factor off, for an action that is strictly more destructive. When it
finishes you land on the installer, carrying a one-time grant so you are not asked for
`var/install-token` on a machine you have just wiped. A fresh visitor still has to read that
file over a shell.

**`var/state.db` holds the reader's `(dev, inode, offset)` for every log file.** Deleting the
indexes without clearing those would leave the daemon believing it had already read those
bytes, so a rebuilt index would hold only traffic from the moment of the rebuild onwards.
Both paths remove it.

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

  Afterwards the account is listed **again**, and each name is reported `GONE` or `PRESENT`.
  A name still present means the platform accepted a delete it has not acted on, and you are
  told so rather than left believing you are finished. An account that now lists nothing at
  all is reported as *unproven* rather than as success: it is what an account holding only
  these two indexes looks like the moment after they go, and it is also what a listing that
  did not work looks like, and neither reading is available from here. Both names are
  printed so you can check them.

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

The full list of `LOGHOUND_*` variables is `bin/loghound-setup --help`, which prints every one
of them. The API key is never echoed to the terminal and never written to the install log.

`LOGHOUND_IP_MODE` and `LOGHOUND_RETENTION_DAYS` are overrides with no prompt behind them —
the wizard does not ask about either, interactively or otherwise. Leave them out and the
defaults stand: the full address, 90 days, changed afterwards under **Settings → Privacy**.
Either works on its own; the one you do not set keeps whatever the configuration already holds.

There is **no variable that supplies a Solr address, HTTP credentials or a core name**. The
connection details come back from Opensolr and the two index names are generated, so an
unattended install needs the `LOGHOUND_OPENSOLR_*` answers and nothing else about storage.
Re-running the wizard on a box that already has both indexes leaves them alone —
`LOGHOUND_RECONFIGURE_STORAGE=yes` if you really do want storage to be settled again.

**To have a machine join a pair of indexes that already exists** rather than creating two,
give it the pair's installation id:

```bash
sudo LOGHOUND_HOSTNAME=shop.example.com \
     LOGHOUND_OPENSOLR_EMAIL=you@example.com \
     LOGHOUND_OPENSOLR_API_KEY='...' \
     LOGHOUND_OPENSOLR_REUSE=aaaa1111 \
     ./install/install.sh --non-interactive
```

That is how several sites report into one pair; they are told apart in the panel by the
hostname on every record. The id is the 8 hex characters in the middle of the index names, and
the wizard prints the account's pairs with their ids before it asks. `LOGHOUND_OPENSOLR_REUSE`
answers the one question step two asks, so it takes either an installation id or `new`, and it
defaults to `new` — an unattended re-run never adopts another site's indexes merely because it
found some. When a new pair is **not** available (a full plan) there is no safe default left, so
an unattended run with this variable unset stops and says so rather than falling through to
whichever pair happened to be listed first. Add `LOGHOUND_OPENSOLR_UPGRADE_SCHEMA=yes` only if
you accept that indexes made by an older Loghound may have the fields this version writes added
to them; without it, a mismatch stops the run and changes nothing.

`LOGHOUND_OPENSOLR_REGION` applies only to indexes this run **creates**. Reusing a pair asks no
region question, because the indexes are already wherever they were made.

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
```

**7. Configure and start**

```bash
sudo -u loghound php /opt/loghound/bin/loghound-setup
sudo systemctl enable --now loghound-tail.service loghound-score.timer loghound-retention.timer
loghound-tail --status --human
```

One command enables and starts all three units and brings them back after a reboot. The
panel repeats it under **Settings → Finish setting up**, with whether ingestion is actually
running, read from the same status document `--status` reads.

**8. Beacon** — add the one-line snippet to your site.
