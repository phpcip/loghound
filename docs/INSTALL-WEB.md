# Installing Loghound from a browser

There are two ways to set Loghound up, and they produce the same result:

| | |
|---|---|
| **In a browser** | Point a vhost at `public/`, open the URL, follow four screens. This document. |
| **In a shell** | `bin/loghound-setup` over SSH. See [INSTALL.md](INSTALL.md). |

Neither is a lesser version of the other. Both call the same code in `src/Setup/` to decide
which log files to read, how to grade a format, how to provision the indexes, what a valid
password is and what happens next — so a configuration written by one is indistinguishable
from one written by the other, and you can start in the browser and finish in the shell.

---

## Before you start

You need:

* PHP 8.1 or newer with `curl`, `json`, `pcre`, `sqlite3` and `mbstring`
* a webserver whose document root points at `loghound/public`
* shell access to the machine — the installer asks you to prove it (see [The setup token](#the-setup-token))
* either an Opensolr account, or a Solr 9 you already run

`install/install.sh` sets all of this up including a dedicated PHP-FPM pool. If you would
rather do it by hand, `install/apache-vhost.conf.example` and
`install/nginx-vhost.conf.example` are the vhosts, and `install/php-fpm-pool.conf.example`
is the pool.

---

## Opening it

Open the site. Anything that is not ready to serve lands on the installer — no
configuration, half a configuration, or a configuration with no way to sign in. Loghound
never answers a request by printing a configuration error and stopping.

The first screen is a **system check**: one row per requirement, with the exact command
that fixes anything that is not passing, written for the user PHP is actually running as
on this machine. For example, if the service user cannot read your access logs:

```
setfacl -m u:loghound:rx /var/log/apache2
setfacl -m u:loghound:r  /var/log/apache2/example_com_access.log
```

Read that table before continuing. A green install here is the difference between "the
daemon is running" and "the daemon is running and indexing something".

### If you are behind `open_basedir`

The reference PHP-FPM pool restricts the panel to the application directory and `/tmp`,
which is correct hardening — and it means this page physically cannot see `/var/log` or
`/etc/apache2`. The system check says so explicitly rather than reporting a permission
problem that does not exist. Either widen `open_basedir` for those two directories, or run
`bin/loghound-setup` in a shell, where the restriction does not apply. The ingest daemon is
never affected: it is a CLI process.

---

## The setup token

Before the installer accepts anything that will be written to the configuration, it asks
you to paste a token from a file only this server's administrator can read:

```
sudo cat /opt/loghound/var/install-token
```

This is the same thing Grafana, Matomo and phpMyAdmin do, and it is the only thing standing
between a fresh install and the internet. Until DNS points somewhere else, your URL is
reachable by anyone; without the token, whoever found it first could point Loghound at a
Solr they control and set the password.

The status page itself is readable without the token — you need to be able to SEE a
permission problem in order to go and fix it — but nothing can be saved until it is
entered. Guessing is rate limited, and the token file is deleted the moment setup finishes.

---

## The four steps

Each one writes its answers straight into `config/loghound.php` as you go. There is no
hidden wizard state: reload, change browser, or switch to the shell wizard, and you pick up
exactly where you were.

### 1. Access logs

Loghound reads your webserver's own log files. It works out the format in this order:

1. **From your webserver configuration.** Parsing `apache2.conf` / `httpd.conf` /
   `nginx.conf` and their includes gives the exact format string, the exact file list and
   the virtual host each log belongs to. Nothing is guessed.
2. **By scoring real lines** against the built-in format library when the configuration is
   not readable — structurally, so a field only counts as an IP address if it parses as one.
3. **By proposing a pattern** generated from your log when nothing matches.

Whichever rung it lands on, you see the file, where the format came from, the confidence
percentage, the token-to-field mapping, and **five real lines rendered as parsed records**.
Read them. If a value is in the wrong column, the format is wrong, and confirming it would
fill your index with nonsense. Nothing is ever ingested with a silently guessed format.

The screen also lists what your format does NOT log and what each gap costs you — the
scoring rules that will stay silent. Plain `combined` works; it just detects less.
`docs/INSTALL.md` has a copy-paste `LogFormat` that closes all of them.

You can also name a file by hand. It must sit inside `allowed_log_roots` (`/var/log` by
default); the browser installer refuses anything outside and will not widen that list for
you, because it is a security control. A custom pattern is checked for catastrophic
backtracking before it is stored, not the first time the daemon meets a hostile line.

### 2. Storage

Two answers, and most people want the first.

**Let Opensolr host it.** You do not need to run Solr. Enter your account email and API key
(in the Opensolr control panel, under Account) and the installer:

1. checks the credentials by listing the regions your account can use;
2. lets you pick one of those regions — nothing is hardcoded;
3. creates both indexes with generated names;
4. uploads the schema and solrconfig to each and reloads them;
5. queries each one to prove Loghound can reach and authenticate to it.

Every one of those is a separate step with its own result, so a failure names the step it
failed on. The index names are generated rather than chosen because an Opensolr index name
is unique across the whole platform and permanent once created — a fixed `loghound_hits`
would work for exactly one person. If a generated name is taken, both names are abandoned
and retried with a fresh installation id, and anything created during the failed attempt is
deleted first so you are not billed for an orphan.

Your API key goes into `config/loghound.php` (mode 0640, outside the document root) and
nowhere else. It is never shown again, never placed in a hidden field, never written to a
log, and never included in an error message.

**Use a Solr you already run.** Solr 9 or newer: a base URL, optional HTTP auth, and the
two core names. Create the cores with the configuration in `solr/hits/conf` and
`solr/sessions/conf` first. The installer tests the connection and tells you precisely what
went wrong if it cannot — "Connection refused to `fi.solrcluster.com:443`", not "could not
connect".

### 3. Privacy

What you keep about your visitors: the full address, the network only, or a daily-rotating
hash. Each is one plain sentence, and each says what it costs the bot detection as well as
what it protects. Then a retention window, which a real timer job enforces.

### 4. Sign-in

A username and a password of at least ten characters, stored as a hash. Loghound shows
every visitor, page and address on your site, so it is never served without one.

Copy the commands on this screen before you finish — the installer disappears when setup
completes:

```
sudo systemctl enable --now loghound-tail.service
sudo systemctl enable --now loghound-score.timer loghound-retention.timer
```

Finishing takes you to the dashboard, where your browser asks for the username and password
you just chose.

---

## Long operations

Provisioning two Opensolr indexes takes tens of seconds, and PHP-FPM will not hold a request
open that long. So the slow parts — credential checks, index creation, configset uploads,
connectivity tests and log detection — run as **jobs**: a list of small named steps whose
state lives in `var/setup/`. The browser advances them a budget at a time and polls for
progress, so you see which step is running, how long it has been going and what it is doing
right now.

Refreshing mid-provision reattaches to the running job rather than starting a second one.
Two indexes are never created because somebody double-clicked. A job that fails can be
retried, and the steps that already succeeded are skipped.

The installer needs JavaScript for these screens, and says so. The shell wizard runs the
identical steps with no JavaScript involved.

---

## When the installer disappears

The moment `config/loghound.php` exists, has a username and password, and passes validation,
every installer route is dead and the panel serves instead. There is no flag, no query
parameter and no "re-run setup" button that gets past that check.

To change something afterwards:

* **Settings** in the panel covers log sources, privacy, scoring weights and the beacon.
* `bin/loghound-setup` re-runs the whole wizard; every prompt defaults to the current value
  and an existing secret is kept unless you ask for a new one.

Deleting `config/loghound.php` brings the installer back, with a fresh setup token. That is
a deliberate escape hatch, and it needs shell access twice over — once to delete the file
and once to read the new token.

---

## What it does with your answers

| Screen | Configuration it writes |
|---|---|
| Access logs | `sources`, and `allowed_log_roots` when you explicitly agree to widen it |
| Storage (managed) | `solr.mode`, `solr.install_id`, `solr.hits_core`, `solr.sessions_core`, `solr.base_url`, `solr.http_user`, `solr.http_pass`, `opensolr.email`, `opensolr.api_key`, `opensolr.region` |
| Storage (your Solr) | `solr.mode`, `solr.base_url`, `solr.http_user`, `solr.http_pass`, `solr.hits_core`, `solr.sessions_core` |
| Privacy | `privacy.ip_mode`, `privacy.retention_days`, `privacy.ip_salt`, `beacon.secret` |
| Sign-in | `auth.mode`, `auth.user`, `auth.password_hash`, `base_url` |

`config/loghound.example.php` documents every setting, including the ones neither installer
asks about.

---

## Security summary

* The installer is unreachable once a valid configuration exists.
* Nothing is written until the setup token — a 0600 file — has been pasted.
* Every state-changing request carries a CSRF token; no privileged action happens on a GET.
* Steps cannot be reached out of order by guessing a URL.
* No secret is rendered anywhere: not the API key, the beacon signing key, the address salt
  or the password. Where it matters that one is set, the screen says "stored".
* Sample log lines are attacker-controlled by definition and are escaped on the way out;
  the page's Content-Security-Policy is `script-src 'self'` with no inline scripts.
* A hand-typed log path is resolved with `realpath()` and refused unless it is inside
  `allowed_log_roots`; a custom pattern is refused unless it compiles and runs fast.

`docs/SECURITY.md` covers the rest of the application.
