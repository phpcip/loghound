# Attacks — what Loghound detects, and what it refuses to claim

This document covers the **Attacks** view and the detector behind it
(`src/Score/Attacks.php`, `src/Panel/Attacks.php`).

Read the first section before the rest. It is not a disclaimer; it is the design.

---

## 1. Loghound is not a firewall

Loghound reads an access log **after the fact**. It sits nowhere near the request path. It
blocked nothing, it could not have blocked anything, and nothing in this product is worded as
though it had. Every request on the Attacks view was served — or refused — by your webserver,
minutes or hours before Loghound read the line.

If you want something in the request path, you want a WAF. This tells you what has been
happening to a site that already has whatever protection it has.

### The status code is the whole point

Every other tool in this category prints a list of alarming-looking request strings and leaves
you to panic. That list is almost entirely noise. Any address on the public internet collects
thousands of `../../etc/passwd` attempts a day and the webserver answers all of them with a
404, which is the webserver working correctly.

What matters is the handful that got a **2xx** or a **3xx**. That is the first card on the
page, on its own, before anything else — and every table on the page is **ordered by it**, not
by volume. A high-severity pattern answered 404 ranks below a medium-severity one answered 200.

### And a 200 does not prove a disclosure

This matters just as much, in the other direction.

A site whose error page is served with a **200 status** — a single-page-app shell, a CMS
catch-all route, a misconfigured `ErrorDocument` — is *indistinguishable in a log* from one
that handed over `/etc/passwd`. The log records a status and a byte count, not a body.

So the panel says **"the server answered these with a body"** and never "disclosed". The
correct next step is always the same: fetch the URL yourself and look at what comes back.

### What an access log cannot see

- **Request bodies.** A POST body is not in the log, so injection through a form — which is
  where most real injection goes — is invisible here.
- **Headers**, unless your `LogFormat` captures them. Most Log4Shell payloads arrive in a
  header, not a URL.
- **The response body.** Only its size.
- **Anything the server never logged.** A request dropped by a firewall upstream leaves no line.

Nothing on this page is a survey of what was attempted. It is a survey of what was attempted
**where a log can see it**.

---

## 2. Where detection runs, and why it has to

Detection runs **at ingest**, in `bin/loghound-tail`, between enrichment and the sessionizer.
It writes a list of pattern codes to `hit_flags_ss` on the hit document.

It cannot run at query time, and this is not a preference:

1. **`query_s` is not indexed.** The hits schema stores the query string and deliberately gives
   it no index and no docValues — it is unbounded attacker-controlled text with a near-unique
   value per request, and a term dictionary over it would be the size of the corpus. SQL,
   template and command-injection probes live almost entirely in the query string, so **no Solr
   query can find them**. Only the code holding the request while it parses it can.
2. **`path_s` is a `string` field with no analysis.** Finding `../` inside it at query time means
   a leading wildcard across a term dictionary of every distinct URL your site has ever served,
   which is the single most expensive query shape Solr has.
3. **The work is free where it is done.** `Parser::normalize()` already has the path and the
   query string in local variables.

The cost is a bounded set of substring tests over at most 4 KB of request surface, per line.
Measured in the suite: twenty thousand ordinary requests in well under a second, and fifty
800 KB hostile query strings in under half a second — the surface is truncated *before* it is
decoded, so a crafted request cannot become measurable ingest cost.

### Three states, and why the third one exists

`hit_flags_ss` being absent means two different things, and confusing them would make this page
report a deployment gap as a quiet week. So every evaluated document also carries
**`hit_rules_i`**, the version of the rule table that judged it:

| `hit_rules_i` | `hit_flags_ss` | means |
|---|---|---|
| absent | absent | **never evaluated.** This document predates the detector. NOT "clean". |
| present | absent | evaluated under that version; nothing matched. |
| present | present | those patterns matched. |

The first card on the Attacks view prints the split and says, in a sentence, how much of the
selected range the page can actually speak for.

Bump `Attacks::RULE_VERSION` whenever a pattern changes, so a historical finding can be read
against the ruleset that produced it. Same contract as `rule_version_i` on the session document.

### The session copy

`Sessionizer` folds the union of a session's hit flags onto the session document, under the same
field name (`hit_flags_ss`), exactly as `paths_ss` is the union of the hits' `path_s`.

The two grains answer different questions and neither substitutes for the other:

- **"Which requests were answered with a 200"** is a *hits* question. The path and the status
  have to be read off the same document; a session that recorded one 2xx and one 4xx tells you
  nothing about which of its requests was the hostile one.
- **"Who was doing it, from which network, sharing which fingerprint"** is a *sessions* question.

---

## 3. The patterns

Every rule carries three sentences, and all three are rendered on the page itself as well as
here: **what it matches**, **what it misses**, and **what it over-reports**. A security page
that implies completeness is worse than one that admits its edges.

Severity describes what a **match** is worth *before* the status code is known. It is never a
verdict on its own.

### File disclosure

#### Path traversal — `atk_traversal` (high)

**Matches** a `../` or `..\` sequence in the path or the query string, in any encoding: raw,
percent-encoded (`%2e%2e%2f`), double percent-encoded (`%252e`), overlong UTF-8 (`%c0%ae`) and
the backslash forms Windows accepts.

**Misses** traversal that reaches its target without a dot-dot segment — an absolute path passed
to a file parameter, a symlink the application follows, a path the application builds from an
id. Those look like ordinary requests and no log-reading tool can see them.

**Over-reports** legitimate URLs containing a literal `..`: some documentation sites and package
registries publish paths with version ranges in them, and a few JavaScript bundlers emit
source-map URLs containing `../`.

#### Sensitive file request — `atk_sensitive_file` (high)

**Matches** a request naming a file that holds credentials or process state: `.env`,
`/proc/self/environ`, `.git/config`, `.git/HEAD`, `wp-config.php`, `.aws/credentials`,
`.ssh/id_rsa`, `.htpasswd`, `.npmrc`, `.dockercfg`, `docker-compose.yml`, `web.config`.

**Misses** a secret in a file this list does not name. The list is the well-known set that
scanners try, not an inventory of your secrets.

**Over-reports** a documentation site that serves a page *about* `.env` files, and a developer
fetching their own `.env` over HTTP — which is worth knowing either way.

#### Backup or dump file — `atk_backup_file` (med)

**Matches** `.sql`, `.sql.gz`, `.bak`, `.old`, `.orig`, `.save`, `.swp`, a trailing `~`, and
archive names like `backup.zip` or `site.zip`.

**Misses** a backup under a name that reveals nothing — `a.gz`, a random eight-character name.

**Over-reports** sites that legitimately publish archives: a downloads directory, a release
page, a project shipping `.sql` schema files as documentation. If the 200s on this row are all
one path under `/downloads/`, that is your own site working.

### Injection

All four of these read the **request line only**. None of them can see a POST body.

#### SQL injection probe — `atk_sql_injection` (high)

**Matches** SQL grammar where a value belongs: `union select`, `or 1=1`, `' or ''='`,
`information_schema`, `sleep(`, `benchmark(`, `waitfor delay`, `pg_sleep(`, `xp_cmdshell`,
`sp_executesql`, `concat(0x`, and the MySQL executable-comment form `/*!`.

**Misses** blind injection carried in a value with no SQL keyword in it, and **everything in a
POST body**, which is where most real injection goes.

**Over-reports** on any site whose users legitimately type or search for SQL: documentation
sites, developer forums, query builders, analytics tools with a query box.

#### Command injection probe — `atk_command_injection` (high)

**Matches** shell metacharacters combined with a shell verb: `$(`, a matched backtick pair,
`;cat `, `|id`, `&&whoami`, `/bin/sh`, `nc -e`, `wget http`, `curl http`.

**Misses** injection into a language runtime rather than a shell, and POST bodies.

**Over-reports** on documentation and paste sites (the `wget`/`curl` halves), and on URLs that
legitimately contain `$(`.

#### Template or expression injection — `atk_template_injection` (high)

**Matches** `${...}`, `{{...}}`, `#{...}`, `<%= %>`, `T(java.lang`, `__import__`, `getRuntime`.

**Misses** engines with custom delimiters, and payloads assembled across several parameters.

**Over-reports** front ends that put an un-rendered template into a URL — a broken share link, a
mail client rewriting a `{{name}}` placeholder, a preview URL from a page builder.

#### JNDI lookup probe — `atk_log4shell` (high)

**Matches** `${jndi:`, or `ldap://` / `rmi://` / `dns://` / `iiop://` inside a `${...}`.

**Misses** heavily obfuscated forms that split the word across nested lookups, and everything in
a header — which is where most Log4Shell payloads arrive.

**Over-reports** almost nothing. This is the highest-precision pattern in the table: no ordinary
application puts `${jndi:` in a URL. A match is worth looking at even with a 404 beside it,
because it tells you your address is on somebody's list.

When it fires, the generic template-injection rule stands down, so one probe is one row.

#### SSRF or metadata probe — `atk_ssrf` (high)

**Matches** an address that only makes sense if the *server* fetches it: `169.254.169.254`,
`metadata.google.internal`, `/latest/meta-data`, `127.0.0.1`, `localhost`, `[::1]`, or a
`file://`, `gopher://` or `dict://` scheme.

**Misses** an SSRF target that is an ordinary public hostname, or a DNS-rebinding name.

**Over-reports** development and preview traffic: a staging front end with
`http://localhost:3000` in a redirect parameter, an OAuth callback to `127.0.0.1`, a
health-check URL. If the matching requests come from your own address space, that is what this
is.

#### XSS payload — `atk_xss` (med)

**Matches** `<script`, `javascript:`, `onerror=`, `onload=`, `onmouseover=`, `<svg`, `<iframe`,
`document.cookie`, `alert(1)`, `String.fromCharCode(`, raw or percent-encoded.

**Misses** DOM-based XSS delivered through a fragment, which never reaches the server at all.
And POST bodies.

**Over-reports** on any site running a bug-bounty programme — reflected XSS testing is what
researchers do all day — and on any search box that gets pasted-in HTML. The status code is the
separator: an XSS string answered 200 means the string came back in a page, which is worth ten
minutes with view-source.

### Known exploits

#### Known exploit path — `atk_known_exploit` (high)

**Matches** the recurring CVE probe paths every public server sees: the PHPUnit
`eval-stdin.php` RCE, Spring Boot `/actuator/gateway/routes`, Laravel
`/_ignition/execute-solution`, `/HNAP1`, `/boaform/admin/formLogin`, `/cgi-bin/luci`, Liferay
`/api/jsonws/invoke`, ThinkPHP, Exchange `/autodiscover/autodiscover.json`,
`/console/login/LoginForm.jsp`.

**Misses** every CVE published after this table was written, and every exploit whose entry point
is an ordinary application URL. A list of known paths is by construction always behind.

**Over-reports** very little, with one real exception: **if you actually run the software being
probed**, the same path is a legitimate request from your own tooling. A Solr admin endpoint hit
from your own monitoring is the obvious case.

### Reconnaissance

#### Admin panel probe — `atk_admin_probe` (low)

**Matches** `/wp-admin`, `/wp-login.php`, `/administrator/`, `/phpmyadmin`, `/pma/`,
`/adminer.php`, `/manager/html`, `/server-status`, `/xmlrpc.php`, `/solr/#/`.

**Misses** an admin panel on a custom path, which is the whole point of mounting it on one.

**Over-reports enormously, and deliberately.** This is the loudest and least alarming row in the
table. If you run WordPress, every `/wp-login.php` from your own editors lands here. It is
severity **low** for that reason and is worth reading only through the status column:
`/phpmyadmin` answered 404 ten thousand times is the background radiation of the internet; the
same path answered 200 is a finding.

#### Installer probe — `atk_installer_probe` (med)

**Matches** `/install.php`, `/setup.php`, `/wp-admin/install.php`, `/setup-config.php`,
`/upgrade.php`, `/installer/`.

**Misses** framework installers on application-specific routes.

**Over-reports** a site that is genuinely being installed or upgraded right now. Read the
timestamps: a burst from one address during your own deployment window is you.

#### Unregistered `/.well-known` path — `atk_wellknown_abuse` (med)

**Matches** a request under `/.well-known/` whose first segment is not one of the ordinary
registered ones (`acme-challenge`, `security.txt`, `change-password`,
`apple-app-site-association`, `assetlinks.json`, `openid-configuration`, `host-meta`,
`webfinger`, `nodeinfo`, `traffic-advice`, `dnt-policy.txt`, `matrix`, `discord`, `gpc.json`,
`mta-sts.txt`, `pki-validation`, `caldav`, `carddav`, `appspecific`).

That directory is world-readable and frequently world-**writable** because ACME needs it to be,
which makes it the favourite place to leave a web shell.

**Misses** a shell anywhere else, and one named to impersonate a registered suffix.

**Over-reports** any `.well-known` suffix registered after this list was written, and any private
convention your own stack uses. A row here answered 200 by a path *you recognise* means this
rule needs a new entry, not that you have an incident.

#### Scanner User-Agent — `atk_scanner_ua` (med)

**Matches** a User-Agent naming a scanner outright: sqlmap, nikto, nmap, masscan, zgrab, nuclei,
wpscan, acunetix, netsparker, dirbuster, gobuster, feroxbuster, ffuf, wfuzz, arachni, openvas,
qualys, zaproxy, burp, commix, whatweb, joomscan, droopescan, metasploit, hydra, havij, xray,
dirsearch, nessus, w3af, skipfish.

**Misses** every scanner run with `--user-agent "Mozilla/5.0 …"`, which is the default advice in
every tutorial.

**Over-reports** your own security testing and any commercial scanning service you pay for.
Nothing in a log distinguishes an authorised scan from an unauthorised one except the address.

#### Unexpected HTTP method — `atk_method_abuse` (low)

**Matches** TRACE, TRACK, DEBUG, CONNECT, and the WebDAV verbs PROPFIND, PROPPATCH, MKCOL, MOVE,
COPY, LOCK, UNLOCK, SEARCH.

**Misses** nothing within its own definition — the method is recorded verbatim. It says nothing
about what the request was *for*.

**Over-reports** completely if you actually serve WebDAV: a CalDAV or CardDAV endpoint, a
Nextcloud install, SVN over HTTP. Filter it out by path if so.

#### Open-proxy probe — `atk_proxy_probe` (med)

**Matches** a request line carrying an **absolute URI** — `GET http://example.com/ HTTP/1.1` —
naming a host this server does not answer for. A normal browser sends an origin-form path.

**Misses** a proxy probe sent in origin form with only a forged `Host:` header.

**Over-reports** if this machine *is* a forward proxy, in which case every request is
absolute-form and this row is the whole log. Also fires on some cache-poisoning research and on
monitoring pointed at the wrong origin.

> Requires `%v` in your `LogFormat`. Without it Loghound has nothing to compare the absolute
> host against and the rule stays silent — which is the safe direction.

### Credential attacks

#### Login endpoint request — `atk_login_probe` (info)

**Matches** a POST or PUT to a path shaped like a sign-in endpoint: `/login`, `/signin`,
`/user/login`, `/wp-login.php`, `/admin/login`, `/auth`, `/api/login`, `/oauth/token`,
`/session`, `/xmlrpc.php`.

**Misses** credential attacks against an endpoint on a custom path, and credential **stuffing**
that spreads a handful of attempts across thousands of addresses so no single session looks busy.

**Over-reports by construction**: one of these is a person signing in, and this code marks every
one of them. It is severity **info** and it is the only row whose meaning is entirely in the
**count**. The view groups it by session and by address, so the finding is "four hundred POSTs to
`/login` from one address, 401 every time" — never the single request. Read this row on its own
and you will read your own users.

### Impersonation

#### Crawler impersonation — `atk_crawler_impersonation` (high)

**This is the rule the whole feature came from.**

**Matches** a User-Agent claiming a major named **search or AI** crawler, arriving from an
address whose reverse DNS is a *general-purpose cloud tenant* name:
`*.bc.googleusercontent.com`, `*.compute.amazonaws.com`, `*.cloudapp.azure.com`,
`*.your-server.de`, `*.ovh.net`, `*.digitalocean.com`, `*.vultr.com`,
`*.linodeusercontent.com`, `*.contabo.net` and their kin.

Every crawler on that list runs on its operator's own infrastructure and publishes reverse DNS
to prove it. Googlebot answers from `*.googlebot.com`, **never** from `*.googleusercontent.com`
— which is where somebody's rented VM lives.

The real case: `OAI-SearchBot` requesting `/proc/self/environ` and `.env` from
`7.32.89.34.bc.googleusercontent.com`. OpenAI's crawler does not run on a Compute Engine
instance. Somebody rented a machine, wore a crawler's name, and went looking for credentials.

**Misses** an impersonator on an address with no reverse DNS at all, on a residential proxy, or
on a cloud this list does not name. It also does not cover the case the scorer already owns: a
crawler whose operator publishes verifiable reverse DNS and **failed** the check fires
`rdns_claim_failed` on the *session* instead. The Attacks view counts both, in separate columns,
because they are found by different means.

**Over-reports** a legitimate crawler that genuinely runs on rented cloud capacity and left its
reverse DNS at the provider default. None of the operators on the claimed-name list does that
today, which is what makes the rule safe — but if one starts, this is where it will show up as a
wrong answer.

**Three conditions, all required**, and the third is what keeps it honest: the UA must name a
crawler, that crawler must be in a category whose operators run their own infrastructure
(`search` or `ai` — not `seo`, `monitor`, `social` or `other`), and the reverse DNS must be
**present** and be a tenant name. Absent reverse DNS yields *false*: an enrichment that did not
run is not evidence.

---

## 4. The view, card by card

| # | Card | Plane | What it answers |
|---|---|---|---|
| 01 | What the server answered | hits | The 2xx/3xx count, first and alone, plus how much of the range has been evaluated at all |
| 02 | What is being tried | hits | Patterns, grouped, **ordered by what was answered** |
| 03 | The requests the server answered | hits | The individual URLs — the only card that reads documents |
| 04 | Who is doing it | hits | Addresses and networks, ordered by what was answered |
| 05 | Crawlers that are not what they say | **sessions** | Declared crawlers, verified / rDNS failed / cloud tenant |
| 06 | When | hits | Matched and answered over time, so a burst is visible as a burst |
| 07 | Pattern by status class | hits | The cross-tab that is the page's whole claim in one grid |
| 08 | What this page does not claim | — | The limits, and every rule's misses and over-reports |

Every row drills through to the session detail dialog that already exists, and every value in
every row is a filter link like any other dimension in the panel.

### Filtering

Two new dimensions are available on the **hits** plane:

- **Status class** (`status_class_s`) — `2xx` / `3xx` / `4xx` / `5xx`. What an operator asks.
- **Status code** (`status_i`) — the exact integer. What an investigator asks.

and one on **both** planes:

- **Attack pattern** (`hit_flags_ss`) — the rule codes above. Multi-valued, so the "All of"
  operator works: "traversal AND sensitive file" is a real question.

Status is **hits-only** on purpose. A status belongs to a request; the sessions core does not
define either field, and a filter naming a field a core does not define matches nothing while
looking like it merely narrowed.

### Exports

`patterns`, `actors`, `requests` and the cross-tab are all exportable as CSV. The `requests`
file carries the full path *and* query string, because that is the row you forward to somebody
else. Both are attacker-chosen text: they are neutralised against spreadsheet formula execution
on the way into the file, and **you should not paste one into a shell**.

---

## 5. Tuning

There is no configuration for this. The rule table is code
(`src/Score/Attacks.php`, `Attacks::RULES`), deliberately — a rule that can be turned off from
the panel is a rule whose absence nobody can explain six months later, and the table's whole
value is that the three sentences describing each rule are maintained beside the pattern that
implements it.

To change a pattern:

1. Edit `Attacks::RULES` and the matching needle list.
2. Bump `Attacks::RULE_VERSION`, so findings can be read against the ruleset that produced them.
3. Add a must-fire and a must-not-fire case to `tests/test_attacks.php`.
4. Re-ingest if you want the change applied to history — flags are written at ingest and are not
   recomputed on existing documents.

If a rule is unusable on your site — you serve WebDAV, you run a bug-bounty programme, you host
a downloads directory — filter it out with the **Attack pattern** dimension set to "None of"
rather than removing the rule. That keeps the row available on the day you want it.
