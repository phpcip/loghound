# Loghound

**Solr-based traffic analytics and bot forensics for Apache, nginx and Caddy.**

Loghound reads the access logs you already have, correlates them with a small JavaScript
beacon, and tells you two things that nothing else tells you honestly.

---

## Why this exists

There are exactly two reasons. Everything else in here — the charts, the geo map, the
facets — is table stakes that a dozen tools already do well.

### 1. It is a serious bot detector, not a User-Agent blocklist

Every analytics tool "filters bots". What they actually do is match a list of strings
like `Googlebot` and `AhrefsBot` against the User-Agent header, which catches exactly the
crawlers that were polite enough to identify themselves and nothing else.

Modern scraping does not look like that. It looks like **headless Chrome on rotating
residential proxies**: a real browser engine, executing your JavaScript, fetching your
CSS and images, presenting a perfectly ordinary Windows Chrome User-Agent, arriving from
a different consumer ISP every request. Every existing analytics product counts that as a
human visit, because from the inside of any single plane of observation, it is
indistinguishable from one.

Loghound observes three planes and cross-checks them. A scraper has to defeat all three
simultaneously, and defeating the JavaScript plane without also defeating the behavioural
plane is exactly what gives it away.

### 2. It measures real time-on-site

When Clicky, GA4 or Matomo tell you "average time on page: 4m 12s", they are usually
reporting how long a tab existed. Not how long it was visible. Not how long anyone was
looking at it. A tab left open in a background window for an hour is an hour of
"engagement" in almost every analytics product on the market.

Loghound reports **four separate numbers and never conflates them**:

| Number | What it actually means |
|---|---|
| `log_span_ms` | Last request minus first request. This is what log-only tools call "time on site". It is a lower bound and it misses the last page of every session entirely. |
| `wall_ms` | The page was open this long. This is the number everyone else reports. |
| `visible_ms` | The tab was visible **and** the window was focused. |
| `engaged_ms` | Someone was actually interacting — within 30 seconds of a real scroll, click, keypress or pointer movement, while visible. **The honest number.** |

Because the beacon flushes on `pagehide` with `navigator.sendBeacon()`, Loghound measures
the **last page of the session** — which log-based tools structurally cannot see, because
there is no subsequent request to measure against.

---

## Screenshots

> **PLACEHOLDER.** No screenshots have been captured yet. The intended hero image is the
> **Fingerprint clusters** view: one row per header fingerprint, with the count of
> distinct IP addresses that shared it, expanding to the member IPs and their ASNs.
>
> - `docs/img/overview.png` — overview: human / bot / AI-crawler by hour
> - `docs/img/clusters.png` — fingerprint clusters (hero)
> - `docs/img/forensics.png` — bot forensics: reason-code facet bars
> - `docs/img/session.png` — session explorer with the beacon timeline overlay

---

## The three-plane model

```
                      ┌───────────────────────────────────────────┐
   your visitors ────►│  Apache / nginx / Caddy                   │
                      └──────┬─────────────────────┬──────────────┘
                             │                     │
                    access log lines        HTML with <script src="b.js">
                             │                     │
      PLANE 1 + 2 ───────────▼──────────           ▼────────── PLANE 3
      ┌────────────────────────────────┐   ┌──────────────────────────┐
      │ loghound-tail (systemd daemon) │   │ public/collect.php       │
      │                                │   │  HMAC-token checked      │
      │  tail  ─ rotation-safe         │   │  rate limited per IP     │
      │  parse ─ compiled LogFormat    │   │  timing sanity checked   │
      │  enrich─ geo / ASN / rDNS / UA │   │  writes SQLite only      │
      │  session ─ ip_net + ua_hash    │   └───────────┬──────────────┘
      │  batch ─ softCommit only       │               │
      └───────────────┬────────────────┘               │
                      │                                │
                      ▼                                ▼
             ┌──────────────────┐            ┌──────────────────────┐
             │ Solr core `hits` │            │ var/state.db         │
             │ one doc per line │            │ offsets, sessions,   │
             └────────┬─────────┘            │ beacon staging,      │
                      │                      │ enrichment caches    │
                      │      ┌───────────────┴──────┐
                      │      │                      │
                      ▼      ▼                      │
             ┌──────────────────────────────────────▼───────┐
             │ loghound-score  (systemd timer, every 60s)   │
             │                                              │
             │  close idle sessions                         │
             │  merge beacon timings                        │
             │  fp_ips_24h ─ ONE facet per hour bucket      │
             │  Score/Rules ─ weights ─► verdict + reasons  │
             └────────────────────┬─────────────────────────┘
                                  ▼
                    ┌─────────────────────────────┐
                    │ Solr core `sessions`        │
                    │ one doc per session         │
                    │ this is what the panel reads│
                    └─────────────┬───────────────┘
                                  ▼
                    ┌─────────────────────────────┐
                    │ public/index.php ─ the panel│
                    │ auth-gated, CSP-locked,     │
                    │ ECharts self-hosted         │
                    └─────────────────────────────┘

             loghound-retention (systemd timer, daily)
                    delete-by-query past privacy.retention_days
```

**The verdict matrix** is the core idea:

| Plane 1 (the log) | Plane 3 (the beacon) | Verdict |
|---|---|---|
| HTML 200 served | no beacon ever arrived | `bot` — non-JS client |
| HTML 200 served | beacon arrived, headless signals positive | `bot` — headless automation |
| HTML 200 served | beacon arrived, zero interaction, left in under 15s | `likely_bot` |
| HTML 200 served | beacon + interaction + plausible timing distribution | `human` |

GoAccess and AWStats only ever see plane 1. Clicky, GA4, Plausible and Matomo-JS only
ever see plane 3 — **and they trust it**. A client that runs JavaScript is a human, as
far as they are concerned. Loghound sees all three and cross-checks them.

---

## Quickstart

```bash
git clone https://github.com/phpcip/loghound.git
cd loghound

# Look before you leap. This changes nothing.
sudo ./install/install.sh --dry-run

sudo ./install/install.sh
```

### Two installers, one result

Setup happens either in a browser or in a shell, and **neither is a lesser version of the
other**. Both drive the same code in `src/Setup/` — the same log detection, the same format
grading, the same index provisioning, the same password rules — so a configuration written
by one is indistinguishable from one written by the other, and you can start in the browser
and finish over SSH.

| | |
|---|---|
| **In a browser** — the normal path | Open the site and you land on the installer: a system check with the exact command for anything that is not passing, then three screens — access logs, storage, sign-in. **[docs/INSTALL-WEB.md](docs/INSTALL-WEB.md)** |
| **In a shell** | `bin/loghound-setup` over SSH. This is what `install/install.sh` hands over to, and what unattended installs use. **[docs/INSTALL.md](docs/INSTALL.md)** |

`install.sh` hands over to the shell wizard by default; **`--skip-setup`** stops once the
machine is ready so you can finish in the browser.

Anything not ready to serve lands on the browser installer — no configuration, half a
configuration, or a configuration with no way to sign in. Loghound never answers a request
by printing a configuration error and stopping. Once the configuration is complete every
installer route is dead.

Installs to `/opt/loghound` by default; `--prefix=/srv/loghound` (or anywhere else) works
and every generated artefact follows it — the vhost docroot, the FPM pool, the systemd
units, the deny rules. If the prefix is a git working copy, `--upgrade` is a fast-forward
pull in place.

The installer:

- checks PHP ≥ 8.1 and the five extensions it needs, and refuses clearly if any is missing;
- creates the `loghound` system user and adds it to `adm` for read access to `/var/log`;
- lays out `/opt/loghound` with the code owned by root and only `var/` writable;
- installs and enables the hardened systemd units and the two timers;
- writes a **dedicated** PHP-FPM pool and a vhost for whichever web server you already
  run, **validates both before enabling them**, and rolls back if validation fails;
- verifies the TLS certificate actually chains to a trusted root before deploying it
  (a Let's Encrypt *staging* certificate is refused — it has valid dates and the right
  hostname, and produces `unable to get local issuer certificate` in every browser);
- hands over to the setup wizard, starts the daemon, and waits for the first documents to
  arrive before telling you it worked.

It never modifies an existing vhost, pool, cron entry or service, never overwrites a file
it did not write, and uses `reload` rather than `restart` so other sites on the box are
undisturbed. `--dry-run` prints every action and changes nothing.

`sudo ./install/uninstall.sh` reverses it — a thin wrapper around
`install.sh --uninstall`, so there is one implementation rather than two that drift. It
stops and removes the units and both timers, removes the vhost only after proving the web
server still validates without it, removes the FPM pool, overwrites the credentials before
unlinking them, and drops the service user's `adm` membership before trying `userdel`.
It offers, as a separate question defaulting to **no**, to delete the two Opensolr indexes
*this installation provisioned* — names derived from `solr.install_id`, matched against
`^loghound_[a-f0-9]{8}_(hits|sessions)$`, and cross-checked against your account's own
index list. If ownership cannot be proven it deletes nothing and prints the names instead;
nothing else in your account is ever touched. `--dry-run` walks the whole teardown and
changes nothing, and the run ends with a list of what it deliberately left behind —
including the beacon `<script>` tag, which only you can remove. See
[docs/INSTALL.md](docs/INSTALL.md#uninstalling).

**Your log files are opened read-only and are never written to, truncated, rotated,
renamed or deleted.** Every source path is opened `'rb'` and no other mode string appears
near one anywhere in the codebase; there is a test in the suite that asserts a source
file's size is unchanged after a full read. Whatever else is already reading those files —
fail2ban, a log shipper, your own scripts — is unaffected, and so is logrotate.

Ingest is a **systemd daemon**, not a cron job. Cron's floor is sixty seconds, and the
point of the tailer is that a request shows up in the panel about five seconds after it
was served. The scorer and the retention job are systemd timers. On a box with no systemd
the installer falls back to cron for those two and tells you plainly that the daemon then
needs a supervisor of your own.

Either installer reads your Apache or nginx configuration, finds your `LogFormat` and
`CustomLog` directives, and shows you the mapping **with five of your own log lines
rendered as parsed records and a confidence percentage**, then asks you to confirm.
Nothing is ever ingested with a silently guessed format.

Then:

```bash
sudo systemctl enable --now loghound-tail.service
loghound-tail --status --human
```

And add one line to your site — anywhere in the page, `<head>` earliest:

```html
<script src="https://loghound.example.com/b.js?v=1" defer></script>
```

The panel's Settings page hands you that snippet with your own URL and a `?v=` taken from
the file's modification time, so an upgrade reaches returning visitors on its own.

No Composer. No npm. No build step. `git clone` and `install.sh` on a bare box.

Full details, including the `LogFormat` block that makes detection substantially
stronger: **[docs/INSTALL.md](docs/INSTALL.md)**.

---

## What this does NOT catch

An honest limitations section, because a bot detector that oversells itself is worse than
none — you would stop looking.

**A well-funded, careful scraper.** If an operator gives every session a genuinely unique
header fingerprint, runs a real (non-headless) browser, drives it with synthesised mouse
movement and scrolling, paces requests with human-like variance, and never reuses an exit
IP, Loghound will classify it as human. Everything here raises the cost of scraping. None
of it makes scraping impossible, and anyone claiming otherwise is selling something.

**Privacy-conscious humans get flagged.** This is the single biggest source of false
positives and it deserves to be first. A visitor running uBlock Origin, NoScript, Brave's
shields or Safari's Lockdown Mode may never load `b.js`. From plane 1 they look exactly
like a non-JS client: HTML 200 served, no beacon, real browser UA. The `no_js_on_html`
rule is weighted at 70 rather than 100 precisely because of this, and it is not enough on
its own to reach the `bot` threshold. Read the false-positives section of
[docs/DETECTION.md](docs/DETECTION.md) before you act on any single verdict.

**Traffic that never reaches your origin.** Loghound reads *your* access logs. A request
served from a CDN edge cache, from Cloudflare, or from Varnish in front of you produces
no origin log line and does not exist as far as Loghound is concerned. If you run a CDN,
you are analysing your cache misses.

**Requests behind a proxy that does not forward the client IP.** If `X-Forwarded-For` is
not logged, or the proxy is not in your `trusted_proxies` list, every visitor appears to
come from the proxy. IP-based clustering and geo become meaningless. Loghound will not
silently pretend otherwise, but it also cannot fix it.

**Low-and-slow scrapers.** One page, one IP, one fingerprint, once a day, from a
residential ASN. It is below every threshold in the ruleset by construction. The
fingerprint-cluster signal — the strongest thing here — needs a *fleet* to detect a fleet.

**API and mobile-app traffic**, unless you also point Loghound at that vhost's log. There
is no beacon in a native app, so plane 3 is permanently blind there and every client
looks non-JS.

**Carrier-grade NAT.** Thousands of real mobile users share a small pool of addresses.
That is why `fp_cluster_proxy_fleet` explicitly excludes `as_type_s = mobile`, and it is
why an ASN misclassification turns into a batch of false positives.

**It is not a WAF and it blocks nothing.** Loghound observes and reports. It does not
issue challenges, it does not rate-limit, it does not write firewall rules. Deciding what
to do about what it finds is your job, and the reason every verdict ships with its
reasons attached.

**It does not do product analytics.** No funnels, no goals, no A/B tests, no revenue
attribution, no cohort retention. If you need those, use Matomo or GA4 — and see below.

---

## How it compares

Written to be fair. Each of these tools is good at what it set out to do, and for most
people one of them is the right answer.

| | **Loghound** | **GoAccess** | **Matomo** | **Plausible** | **GA4** |
|---|---|---|---|---|---|
| Data source | logs **+** JS beacon | logs only | JS (log importer available) | JS only | JS only |
| Bot detection | 3-plane correlation, 17 weighted rules, every verdict carries its reasons | UA blocklist | UA/IP blocklist, some heuristics | UA blocklist | undisclosed, not inspectable |
| Detects headless Chrome on residential proxies | yes, that is the point | no | no | no | no |
| Cross-IP fingerprint clustering | yes — the primary signal | no | no | no | no |
| Time-on-site | 4 distinct numbers incl. engaged time and the last page | request span only | tab-open time | tab-open time | tab-open time |
| Storage | Opensolr (managed Solr 9) | in-memory / on-disk report | MySQL/MariaDB | ClickHouse | Google |
| Install | `git clone` + `install.sh`, no Composer/npm | one binary, apt/dnf | PHP app + DB, or cloud | Docker/Postgres, or cloud | none |
| Real-time | yes (softCommit, ~5s) | yes, genuinely instant | near | near | delayed |
| Cost | free, MIT | free, MIT | free self-hosted, paid cloud | paid cloud, free self-hosted | free |

Loghound is narrow on purpose. If your question is "how many people read my blog post",
use Plausible. If your question is "which campaign drove revenue", use GA4 or Matomo. If
your question is "**how much of this traffic is actually real, and can you prove it**",
that is the one Loghound was built to answer.

Loghound also works alongside them. It reads logs the web server is already writing; the
beacon is independent of whatever other analytics you run.

---

## Documentation

| | |
|---|---|
| [docs/INSTALL-WEB.md](docs/INSTALL-WEB.md) | Setting up from a browser: the system check, the setup token, the three screens, how the long operations run as jobs, and what each screen writes into the configuration |
| [docs/INSTALL.md](docs/INSTALL.md) | Installation and the shell wizard: what `install.sh` does, the permission model, the recommended `LogFormat`, exactly which signals each extra header buys you, Solr and Opensolr setup, upgrading, troubleshooting |
| [docs/DETECTION.md](docs/DETECTION.md) | The three planes, every rule with its weight and rationale, a worked example on real captured traffic, and a frank section on evasion and false positives |
| [docs/BEACON.md](docs/BEACON.md) | The beacon: the three clocks, every field it sends, every signal code, the wire protocol, and what it cannot detect |
| [docs/PANEL.md](docs/PANEL.md) | The web panel: the async contract every card follows, stepped jobs, request flow, the notes a security reviewer wants, the design system, demo mode |
| [docs/SCHEMA.md](docs/SCHEMA.md) | Both Solr cores field by field, why each is indexed/docValued/stored, index-size arithmetic, and what to turn off first |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, controls by surface, hardening checklist, known limitations, how to report a vulnerability |
| [docs/PRIVACY.md](docs/PRIVACY.md) | Exactly what is collected, the three IP modes, retention, GDPR posture, and what to tell your users |
| [SPEC.md](SPEC.md) | The full technical specification, including the Solr schema |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What will and will not be merged, the test runner, fixture rules |

---

## Requirements

- PHP 8.1 or newer with `curl`, `json`, `pcre`, `sqlite3`, `mbstring`. **No Composer.**
- An [Opensolr](https://opensolr.com) account, and it is a hard requirement. Loghound
  provisions and manages its own two indexes there — it creates them, uploads their
  configsets, reloads the cores and verifies them — and it cannot do that on a Solr it does
  not administer, so there is no option to point it at one you run yourself.

  **Opensolr is free forever to start — no credit card, no expiry date.**
  [Create an account](https://opensolr.com/register) · [Sign in](https://opensolr.com/users/login)
  · [What the plans hold](https://opensolr.com/solr-hosting)

  Retention scales with the plan rather than being cut off by it: Loghound trims its oldest
  data before the account reaches its disk limit, so it keeps running on the free tier and
  simply holds less history. More disk buys more history. Setup asks for the account email
  and the API key from **Account** in the control panel, and provisions both indexes itself.
- systemd, for the daemon and the two timers.
- Read access to your access logs. The installer puts the service user in `adm`.

---

## Status

v1.0.0. See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `php tests/run.php` before opening a pull
request; it needs no network access and no dependencies.

## License

MIT. See [LICENSE](LICENSE).
