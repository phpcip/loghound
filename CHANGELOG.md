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

**Setup — in a browser**

- `src/Setup/` — a **browser installer**. Point a vhost at `public/`, open the URL, follow
  four screens: access logs, storage, privacy, sign-in. It is not a lesser path than the
  shell wizard and it is not a wrapper around it — **both drive the same code** in
  `src/Setup/Detector`, `Storage` and `Steps`, so a configuration written by one is
  indistinguishable from one written by the other, and you can start in the browser and
  finish over SSH. Documented in `docs/INSTALL-WEB.md`.
- **Any not-ready state lands there.** No configuration, half a configuration, or a
  configuration with no way to sign in — all of them render the installer, at the step that
  fixes them, with the exact command for anything that has to be done in a shell, written
  for the user PHP is actually running as. The application never answers a request by
  printing a configuration error and stopping.
- **The installer is unreachable once setup is finished**, and the gate that decides is
  deliberately *structural*: the configuration file exists, carries `auth.mode` and
  `auth.password_hash`, and names both indexes. It does **not** call `Config::validate()`,
  because it runs before authentication and `validate()` reports an error for a log
  directory the panel process cannot resolve under `open_basedir` — which made a correctly
  installed instance look unconfigured forever, disclose its environment and paths to
  anyone who asked, and re-mint a live setup token on a machine where it had been
  destroyed. It does not probe Solr either: an outage must not re-open the installer.
- **Filesystem proof before any write.** Nothing reaches the configuration until the
  operator pastes the token from `var/install-token` (mode 0600), which needs shell access
  as the service user or root. Guessing is rate limited; the file is deleted the moment
  setup completes. The status page is readable without it, deliberately — you have to be
  able to *see* a permission problem to go and fix it.
- **The slow parts are stepped jobs**, state in `var/setup/`: credential checks, index
  creation, configset uploads, connectivity tests and log detection. Refreshing mid-provision
  reattaches rather than starting a second one, so two indexes are never created because
  somebody double-clicked.
- **"Try again" after a failed provision no longer abandons the index the failed attempt
  created.** A failed job is not resumed — it cannot be, because it is no longer running — so
  the button starts a fresh job and every step runs again. The installation id is persisted and
  both index names are derived from it, so the retry re-derives the same names and Opensolr
  answers `ERROR_CORE_NAME_TAKEN`. That was read as "somebody else holds this name", which
  rewound onto a brand-new installation id and left the previous attempt's indexes in the
  operator's account, referenced by nothing and billed for, once per retry. Ownership is now
  established against the platform rather than against the job's own memory: an index this
  account already holds is **reused**, and only a name a stranger holds abandons the pair.
  Should the control plane be unreachable at that moment, the step fails with that as the
  reason and changes nothing, because guessing in that direction is exactly what costs money.
- CSRF on everything that changes anything; no privileged action on a GET; a step whose
  prerequisites are unmet redirects to the first incomplete one rather than letting a guessed
  URL skip ahead. No secret is rendered anywhere — not into HTML, a hidden field, a URL, a
  job payload, a log line or an error message.
- A hand-typed log path is resolved with `realpath()` and refused unless it is inside
  `allowed_log_roots`; the installer will not widen that list for you, because it is a
  security control. A custom pattern is refused unless it compiles and runs fast.
- The shipped PHP-FPM pool now includes `/var/log`, `/etc/apache2` and `/etc/nginx` in
  `open_basedir`, because the first screen reads the real webserver configuration to find
  the access logs and their exact format. Both are read-only to the pool user by file
  permissions; the comment in the file says what to drop for a server that does not run one
  of them.

**Setup — in a shell**

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
  data, computes `fp_ips_24h_i`, scores, upserts the session document and recomputes the
  daily rollup. Fingerprint clustering is deliberately batched: sessions are bucketed by the
  hour they ended, the whole bucket shares one ±12h window, and a single terms facet on
  `fp_hash_s` with a nested `unique(ip_s)` answers every fingerprint in it — chunked to stay
  under `termsFilter`'s 512-value cap. A batch of four hundred fingerprints is a handful of
  queries, not four hundred.
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

- Twelve views: Overview, Bot forensics, Fingerprint clusters, Networks, Session explorer,
  Performance, Virtual hosts, Index analytics, Query analysis, Who is querying, Plan usage,
  Settings. Vanilla JS, no framework, no build step, ECharts 5.6.0 self-hosted so the CSP can
  stay closed and the panel works air-gapped.
- **Virtual hosts, as a dimension the whole dashboard understands.** `host_s` is on every hit
  and every session document, and nothing filtered on it — so a machine serving six sites added
  six sites' traffic together and presented it as one number. "Which of my sites takes the most
  bot traffic" could not be asked. There is now a Virtual hosts view comparing every host on
  one row each — the five populations side by side, sorted by evasive-bot share, computed in
  **one** faceted request with the population queries nested inside a terms facet on `host_s`,
  so the cost does not grow with the number of sites — and a host selector that scopes *every*
  view. Selecting one adds `f[host_s][]` to the URL, which `Controller::filterFqs()` already
  applies to every query everywhere, so scoping is one mechanism rather than seven. On a
  single-site install the selector is never inserted into the page at all, and a log format
  that does not record a vhost is reported as exactly that — a different problem, fixed by
  logging `%v` — rather than as an empty list.
- **Two ways to sign in, chosen during setup and changeable afterwards.** `basic` is the
  browser's own prompt: scriptable, so `curl --user` and monitoring checks work, but
  unstyleable and with no way to sign out short of closing the browser. `session` is Loghound's
  own sign-in page at `?login` with a real `?logout`, an idle timeout and an absolute one — and
  it works only in a browser. Both costs are stated on the screen that asks, because neither is
  discoverable afterwards without an afternoon of confusion. `auth.mode = 'session'` was
  previously a value the configuration accepted and nothing implemented: choosing it produced a
  panel that answered 403 forever with no form to sign in with and no route back.
- The sign-in page regenerates the session id before writing the identity, has no `next`
  parameter to smuggle an off-site destination through, and returns **one** message for a bad
  username and a bad password alike so it cannot be used to enumerate account names. It is
  rendered without the panel layout, because a sign-in page that loads the dashboard's
  application code ships its own attack surface.
- **Failed sign-ins are rate limited per address in both modes**, by one shared fixed-window
  ledger in `var/`, and the limiter is consulted *before* the password is looked at. Too many
  attempts and that address is refused with `429` and a `Retry-After` naming the wait, plus the
  path of the file to delete to clear it now. It fails closed: a ledger that cannot be read or
  written refuses the sign-in rather than skipping the check, and says which directory to fix.
  A refused request in session mode is redirected to the sign-in page rather than answered with
  a bare 403 — except an `?api=` request, which gets 401 JSON, because redirecting an XHR to an
  HTML form produces a parse error instead of a clear "sign in again".
- **The panel is fully asynchronous. No view issues a Solr query while PHP renders.** A
  view's `body()` emits headings, captions, table headers and empty states and nothing else;
  every number arrives afterwards over `fetch()`. Two places used to break that and no
  longer do: the layout pinged Solr on every page render, so *every* page blocked on a
  network round trip before emitting a byte, and the Settings page ran the beacon-coverage
  facet inline. First paint is now independent of Solr entirely — a dead backend still
  renders the whole page, its navigation and its captions.
- **Every card is its own request, with its own progress strip, its own retry and its own
  failure.** A card that fails renders the error inside itself with a Retry button that
  re-runs that one loader; every other card keeps its data. Overview went from one request
  feeding three cards to four independent ones, Bot forensics from one to six, Networks to
  five, Performance to four, and the session table and its facet sidebar are separate
  requests so rows appear without waiting on eight terms facets.
- **Loading states say what is happening, in words** — "Faceting signal codes", "Computing
  per-path percentiles" — not a bare spinner. Elapsed seconds appear after 5s; at 20s the
  label becomes "still working" and the counter takes the accent colour. Skeletons are flat
  blocks with an opacity pulse, and the reduced-motion media query replaces the sweeping bar
  with a static one.
- Transport failures become sentences an operator can act on: a timeout, an unresolvable
  hostname, a refused connection, rejected credentials and a 404 on a core name are five
  different problems with five different fixes. The first one to occur also reveals a
  page-level banner, once, with a link to the connection check.
- Browser request timeout of 50s, deliberately longer than the server's 20s Solr timeout, so
  a slow query reports *its own* diagnosis rather than being cut off client-side.
- **Long operations are stepped jobs** (`src/Panel/Jobs.php`): the Solr connection check,
  the Opensolr credential check and the retention preview. Each poll executes exactly one
  bounded step and returns, so no request can time out however long the whole job takes.
  No background process, no `exec()`, no worker daemon — state is in SQLite, which is what
  makes a job survive a refresh. Progress is a real fraction of known steps, never a guess.
  Starting a job that is already running returns the running one, so a double-click cannot
  run the work twice, and a lease stops two tabs executing the same step.
- **Any view can host a job, and a view that does not opt in cannot be POSTed to.** The front
  controller used to route POST by naming one concrete class, and the list of job kinds was a
  closed constant — so a view that grew an asynchronous operation was dead on arrival: its
  button posted, the router answered 405, and the only clue was in the browser console.
  Routing is now on a capability, the new `src/Panel/JobHost.php` interface, and `Jobs` takes a
  registry of extra kinds from the view hosting them. `Jobs::KINDS` still lists only the
  built-ins; the instance method `kinds()` returns everything. A registered kind must be a
  plain lowercase identifier and may not shadow a built-in, both refused in the constructor.
  Implementing the interface is a deliberate act, so read-only views stay read-only by default
  rather than by remembering to say so — and there is a test asserting that six of them do not
  implement it.
- **Jobs take parameters, and idempotency is per kind *and* target.** `start()` normalises its
  parameters to a flat, key-sorted, bounded scalar map and hashes them into a `target` column,
  so starting a scan of one index no longer hands back the job still scanning a different one —
  which reported the wrong index's progress under the right index's heading. A malformed
  parameter refuses the job rather than starting one that silently dropped the field naming its
  target. Ownership of a named target is validated by the hosting view **before** the job
  exists, because a job that starts and then discovers it may not read its target has already
  put that target in the store, in a step note and in a poll envelope.
- Job ids are 96 bits of `random_bytes` and every lookup is scoped to an owner derived from
  the authenticated session; **a job that is not yours is reported identically to one that
  does not exist**, so the id space cannot be probed. Every statement is prepared. Step
  details, persisted errors and log lines all pass through a redactor first, because the
  Opensolr API key travels in a query string and a transport error can quote the URL it
  failed on. Nothing in a job deletes anything: the retention preview counts,
  `bin/loghound-retention` acts.
- The panel follows the Opensolr editorial design system — ink `#111111`, muted `#4a4540`,
  hairline `#d9d4cc`, band `#fbfaf8`, chip `#f4f1ec`, and a single accent `#c05520`. Flat,
  2px corners, no gradients, no shadows, no semantic colour palette, 14px font floor, hex
  codes only, nothing above the H1. Dark mode is a faithful inversion of the same system
  rather than a second palette, and `charts.js` reads its colours out of the stylesheet so a
  chart cannot drift out of step with the interface around it.
- **Authentication fails closed.** With `auth.mode` unset the panel returns 503 and refuses
  to serve; there is no localhost bypass. CSRF on every state-changing request, strict CSP
  with no inline script, and a dedicated PHP-FPM pool.
- `src/Panel/Gateway.php` is the only path to **Loghound's own two indexes**, and every query
  is built server-side from constants and allowlists. **There is no generic Solr passthrough**
  and there will not be one. `Gateway::facet()` forces `rows=0` so an aggregate call cannot
  ship documents by accident. The Opensolr analytics views do not go through Gateway at all —
  they read the platform API — and taken together those two facts give the property that
  matters: **Loghound never contacts a Solr server belonging to a user.**
- Every chart and stat block carries a visible population caption naming what it counts,
  as a `<p>` rather than a tooltip, so it survives being screenshotted. A metric with no
  data renders as an em-dash, never as zero.
- Opt-in demo mode (`LOGHOUND_DEMO=1`) with a fixed-seed synthetic world, banner-labelled
  on every page. A Solr that is merely unreachable produces an error banner and empty
  states — never fabricated data.

**Analytics over your own Opensolr search indexes**

- **A second plane, and the reason the two together are worth more than either.** Loghound
  already knows, for every address in a web log, whether it is a bot, what network it sits on
  and which fingerprint cluster it belongs to. Opensolr already knows, for every request that
  reached one of your search indexes, what was asked, how long it took and how many results
  came back. Three views read the second plane and one of them crosses it with the first.
- **The architectural rule, and it is not open for redesign: Loghound never touches a Solr
  server for any of this.** No agent, no log file on a node, no SSH, no log4j2 parsing, no
  direct connection to a `solrcluster.com` host. Everything on the Solr side is read from the
  Opensolr platform API, which already holds the data in its analytics shards and already
  enforces ownership on it. So there is no format to detect, no volume problem, no second copy
  of anybody's query log, no tenant isolation for Loghound to get wrong, and nothing Loghound
  can be blamed for on a customer's node. The only Solr it speaks to is the pair of indexes it
  provisioned for itself.
- **Index analytics** — what one index is being asked and how well it answers: request volume
  over time with the zero-result share drawn underneath it, QTime distribution, handlers, and
  which node served what. Every card is an aggregate; not one of them fetches a request
  document, because a facet answers all of it and shipping a query log through the panel to
  count it would be slower and a larger privacy surface for no gain. The QTime percentiles are
  read off a fixed-width histogram and labelled "at most" a bucket edge, because the platform's
  endpoint strips braces and quotes out of dotted-parameter values and JSON Facet — with it
  Solr's exact `percentile()` — cannot survive the trip. An approximate number labelled
  approximate is honest; a precise-looking number that is not precise is not.
- **Query analysis, grouped by shape rather than by string.** A request log grouped by exact
  query is useless: a search box produces a different string for every visitor, so "top
  queries" is a list of one-hit wonders and the expensive pattern underneath never surfaces.
  `src/OpensolrShape.php` strips the literals and keeps the structure — quoted phrases become
  `"?"`, bare terms `?`, numbers `#`, range endpoints `[# TO #]`, while field names, boolean
  operators, parentheses, local parameters, boosts and the parameter set itself are kept — so
  two requests share a shape when your application would have built them the same way. That
  makes the single most actionable number in search visible, and nothing else surfaces it:
  **which shapes return nothing.** A shape that runs ten thousand times a day and matches zero
  documents every time is a broken filter, a renamed field, or a UI asking a question the
  schema cannot answer, and on an ungrouped list it is invisible because every one of those
  requests looks unique.
- A shape cannot be faceted — it has to be computed from the recorded request — so the scan is
  a **stepped job**: twenty bounded pages of 400 documents, folded server-side into mergeable
  aggregates, one page per poll. It survives a page refresh by re-attaching rather than
  restarting, stops early when it reaches the end of the log, and is capped at eight thousand
  requests and 250 distinct shapes with the remainder reported as an overflow count. Every card
  states the population it covers, because a capped scan covers a sample and a number that does
  not say what it counted is a lie. Nothing scanned is stored. The slowest-requests table is
  the exception and is exact, because sorting is something the platform can do itself.
- **Who is querying — the view that needs both planes and could not be built with one.** The
  addresses hitting your search indexes, lined up against the web traffic Loghound has already
  classified, answering two questions: how much of your search capacity is being spent on
  clients you had already decided were not people, and **which Solr traffic has no matching web
  traffic at all** — an address that queries the index but never appears in the web log did not
  come through the site, which is a leaked API key, a scraper that found the endpoint, or an
  integration somebody forgot about. It is two calls whatever the number of addresses: one
  facet on the platform, one faceted query against Loghound's own sessions index. A lookup per
  address would be the obvious implementation and the wrong one.
- **Three states, all of which had to read well.** With credentials and Loghound on the web
  server, everything works including the correlation. With credentials but Loghound installed
  elsewhere, the search-side analytics are shown in full and the correlation card explains
  concretely what installing Loghound at the web server would add — the specific question, not
  a vague upsell. With no Opensolr credentials there are no broken cards and no failed
  requests: the view explains what the section is for and where the two values go. **Loghound
  is a complete product without Opensolr and never implies otherwise.**
- Failure is a state with a sentence, never an exception: an index the account does not own, an
  unreachable control plane, a missing credential and a garbled response are four different
  things an operator has to be told apart. Demo mode makes no platform calls at all — there is
  no fabricated Opensolr data, because the alternatives are inventing somebody's query log or
  quietly making a real billed API call from a session showing a "these numbers are fake"
  banner.
- The API key never reaches this layer's output. It is added to a request in one place per
  client, and every string that can escape those classes is redacted first — the platform
  echoes request parameters back in some error bodies, and one of them is the key.

**Plan awareness and size-based retention**

- **`src/Quota.php` — Loghound stops itself filling your plan and switching its own dashboard
  off.** An Opensolr index over either its disk or its bandwidth quota is not throttled and
  does not merely refuse writes: the platform denies every request to it, `/select` included,
  reads as well as writes, and access returns by itself roughly seventeen minutes after usage
  is back under the limit.
- **Disk is managed, not dangerous.** A rolling trim runs *before* a write, so the index never
  reaches its disk quota and the blackout never triggers on disk. It deletes by **date**, never
  by document count — one cheap delete-by-query, and an answer a human understands ("you have
  data from this date onward") where "the oldest N documents" would need a sort, a page and an
  id list. Every guard maps to a way the operator could lose data they wanted: an unknown plan
  limit, an empty index, a clock that moved, a bounds query that came back inverted, a target
  that would take the whole index. Any one of them refuses the trim rather than guessing.
  Nothing deletes without a plan limit to justify it, nothing deletes inside the protected
  recent window, and no single step may take more than a bounded slice of the data's timespan
  however far over quota the index is.
- Presented accordingly: disk is a fact about how far back the data goes, not an alarm, because
  warning about it would be warning about the one thing the feature makes impossible. The
  single exception is a trim that **failed** while the index is genuinely near the limit — then
  the blackout really is coming, and that is loud.
- **Bandwidth is the hard limit and gets the meter**, because it cannot be reclaimed by
  deleting anything: it accrues with use and resets on the 1st. Warning and critical states
  arrive well before the limit, since after it the panel that would have shown them is dark.
  The two cores have independent quotas and are reported separately, with the **worst** of them
  driving the page strip — an operator told they are fine because the average of a blocked index
  and an idle one looks fine has been lied to.
- The control-plane call behind these numbers is expensive — the platform derives the index
  size from a live Solr status request — and batches arrive every couple of seconds, so it is
  cached on disk against both a clock and a document count, and between refreshes the size is
  projected locally from the bytes of log actually read using an expansion factor learned from
  the platform's own reported growth. Every projected figure is flagged as an estimate and says
  so on screen. No page render ever waits on it.

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
- `docs/INSTALL.md` — what `install.sh` does step by step, the permission model, the
  recommended `LogFormat`, a per-header table of exactly which detection signals each extra
  header buys, a log-retention warning, the read-only guarantee, unattended installs,
  troubleshooting, and a manual-install appendix for people who will not run a script as
  root.
- `docs/INSTALL-WEB.md` — setting up from a browser: the system check, the setup token, the
  four screens including the two ways to sign in and what each costs, how the long operations
  run as stepped jobs, what "Try again" actually does and why it does not resume the failed
  job, exactly which configuration keys each screen writes, and what happens when the
  installer disappears.
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
- `docs/PANEL.md` — the two planes and precisely what talks to which, the async contract every
  card follows and what it buys, the anatomy of a card, a request map per view, stepped jobs
  and their security model including how a view hosts one, the request flow and the installer
  gate, the notes a security reviewer wants, the design system and its palette, demo mode, a
  frank list of the places `SPEC.md` is wrong or silent, and a known-limitations section.
- `docs/SCHEMA.md` — both cores field by field with the reason each one is indexed,
  docValued or stored and what it costs, the fingerprint's honest limitation on plain
  `combined`, index-size arithmetic shown as a breakdown rather than a single number, what
  to turn off first, and the deliberate omissions from the configsets.
- `CONTRIBUTING.md` — what the project is for, the rules that are not negotiable, how to
  write a test, fixture anonymisation rules, and an explicit list of what will be declined.

### Removed

- **The "use a Solr you already run" storage option, and the choice it was half of.** An
  Opensolr account is now a hard requirement, and provisioning through Opensolr is the only
  path to storage.

  The reason, plainly: Loghound does not merely read and write its two indexes, it owns them.
  It creates them, uploads the configsets under `solr/hits/conf` and `solr/sessions/conf`,
  reloads the cores, verifies them, and later reports and trims them against the account's
  plan. On a Solr the operator administers, it has no route to create a core or install a
  configset and no way to keep the schema right — so the option promised something the product
  cannot deliver, and the failure surfaced late, after ingestion had already begun against a
  schema nobody had checked.

  What went with it:

  - The second panel on the `?setup=storage` screen. That screen is one flow now, not a fork.
  - `Setup\Storage::saveCustom()` and the `storage:custom` POST action in `Setup\Installer`
    — the only doors an operator-supplied Solr base URL, HTTP credentials or core name could
    come through. There is no longer any code path that accepts one.
  - The `custom` arm of the Solr card on the panel's Settings page.
  - `LOGHOUND_SOLR_CHOICE`, `LOGHOUND_SOLR_BASE_URL`, `LOGHOUND_SOLR_HTTP_AUTH`,
    `LOGHOUND_SOLR_HTTP_USER`, `LOGHOUND_SOLR_HTTP_PASS`, `LOGHOUND_HITS_CORE` and
    `LOGHOUND_SESSIONS_CORE` from `bin/loghound-setup`, along with the choice prompt and the
    own-Solr questions. The three `LOGHOUND_OPENSOLR_*` variables are unaffected.

  What deliberately stayed:

  - `solr.base_url`, `solr.http_user` and `solr.http_pass` are still configuration keys.
    Managed setup fills them in from `Opensolr::connectionDetails()`, and `src/Solr.php` stays
    mode-agnostic: it talks to a node it has credentials for and does not care how they got
    there.
  - `solr.hits_core` and `solr.sessions_core` still hold the provisioned names from
    `Config::coreName()`.
  - Both configsets. They are real, shipped, and still the schema Loghound runs on — they are
    what setup pushes to Opensolr. `docs/SCHEMA.md` now says how they get there rather than
    describing an installation you do by hand.
  - `Security::safeUrl()`'s refusal of URL userinfo, which is also what protects referer
    rendering and `Steps::applyBaseUrl()`, and `Security::isSafeCoreName()`, which still
    guards every core name reaching `Solr`, `Opensolr`, `Quota` and the panel.

- **`solr.mode` collapsed to the constant `'opensolr'`, and the key was kept rather than
  deleted.** A configuration written before this change still carries `mode: custom` on disk,
  and only a key that is still read can refuse it — deleting the key would have meant the
  stale value was silently ignored and the panel quietly pointed at a Solr Loghound can no
  longer manage. So `Config::validate()` refuses anything but `'opensolr'`, and refuses
  `'custom'` with a paragraph naming what changed, why, and what to run. All three daemons
  validate at startup and abort on any error, so the operator meets that sentence on upgrade;
  the Settings page carries the same message for anyone who reaches the panel first. Nothing
  migrates: the new indexes start empty and the old cores are left untouched.

### Security

Findings from a full pre-release audit of every surface that touches untrusted input, and
the hardening they produced. Nothing here was reported by a third party; all of it was found
in review.

- **Beacon tokens are bound to the Origin they were issued to.** The signed material is
  `session_id \0 origin`, and verification recomputes with the `Origin` of the request
  presenting the token. A token minted for one site is refused from another, and the refusal
  is indistinguishable from any other rejection — same `204`, no staging row, no
  diagnostics. This is what makes `Access-Control-Allow-Origin: *` safe on the collector: it
  has to be reachable from origins we cannot know in advance, so the credential is tied to
  the origin instead of the allow-list doing work it cannot do.
- **The collector never returns an existing session id.** The hello branch always mints a
  fresh random provisional id, and it never creates a session row. Returning the real id was
  a serious hole: any page on the internet can make a CORS-simple POST from a visitor's
  browser — their IP, their User-Agent, therefore their `client_key` — read the session
  credentials off the response headers, and then submit whatever it liked about that
  visitor's *real* session. In a bot-detection product the obvious abuse is to report a
  human as headless automation. The provisional id costs nothing, because the staging row
  carries `client_key` and `loghound-score` re-attaches it to the real session once the log
  line has been tailed.
- **Chart tooltips escape every interpolated value.** Tooltips are the one place the panel
  builds markup from data, because ECharts renders a formatter's return value as HTML and
  there is no DOM node to set `textContent` on. Every dynamic value in every formatter now
  goes through `esc()` — series names, bucket names, treemap labels, AS organisation names.
  The CSP would stop an injected payload executing, but a defence resting entirely on one
  header is not a defence, and an AS organisation name is chosen by whoever holds the
  netblock the traffic came from.
- **The installer gate is structural rather than validation-based.** See the Setup section:
  routing an unauthenticated visitor on `Config::validate()` turned a normal `open_basedir`
  condition into a permanent information disclosure and a re-minted setup token.
- Job endpoints are POSTs behind the CSRF check, with ids that cannot be probed for
  existence and payloads that pass through a secret redactor at every boundary.
- Panel JSON responses carry the same `JSON_HEX_*` flags as the HTML escaper, so a
  User-Agent containing `</script>` cannot do anything if a payload is ever rendered
  somewhere it should not be. Every panel response, HTML and JSON alike, is `no-store`.
- Exception messages never reach the browser on any path — JSON, HTML or POST — because a
  Solr exception can contain a URL, a credential fragment or a filesystem path. The detail
  goes to the error log and the browser gets a generic sentence.
- `tests/scan-secrets.php` and `tests/test_secrets.php` scan the tree for anything
  secret-shaped, so a key cannot reach a public repository unnoticed. `.gitignore` excludes
  `config/loghound.php`, `var/`, `*.db` and `*.log`.

### Known issues

Recorded rather than quietly carried, per the project's own honesty rule.

- **The panel counts daily rollup documents as sessions.** The rollup lives in the sessions
  core discriminated by `doc_type_s`, and the schema comment says every dashboard query must
  carry `fq=doc_type_s:session`. No panel query does, and a rollup document carries
  `ts_start`, so it matches the range filter. Every session total in the panel is therefore
  high by up to one document per day in the selected range — bounded, but it also means the
  five population counts do not sum to the headline total.
- **Retention does not purge the SQLite state database.** `bin/loghound-retention` deletes
  from Solr only. The purge routines exist in `src/State.php` and nothing calls them, so the
  enrichment caches, closed sessions, merged beacon rows and rate-limit buckets in
  `var/state.db` outlive the retention window. Documented in `docs/PRIVACY.md`.
- **Eleven session fields are written and silently dropped.** `Sessionizer::identityOf()`
  collects `accept_s`, `accept_enc_s`, the `sec_ch_*` set, the `sec_fetch_*` set and the
  `tls_*` pair onto the session document, and the sessions schema does not define them, so
  the catch-all `ignored` dynamic field swallows them. Nothing depends on them at the
  session level, so the cost is bytes on the wire rather than a wrong number. Documented in
  `docs/SCHEMA.md` §3.
- **`ja4_s` is defined and never populated.** Apache and nginx cannot produce a JA4
  fingerprint; it needs a TLS-terminating proxy. The field is waiting and nothing in v1
  depends on it.
- **The vhost examples do not enable compression.** They set the beacon's cache and CORS
  headers, but gzip is a global setting on both Debian-family Apache and stock nginx and
  overriding it per vhost surprises people. The "12 KB over the wire" figure for `b.js`
  assumes it is on; `docs/INSTALL.md` now says how to check.
- **No formal third-party security audit has been performed.**

### Notes

- No Composer, no npm, no build step. PHP 8.1+ with `curl`, `json`, `pcre`, `sqlite3` and
  `mbstring`, and Solr 9.

---

[1.0.0]: https://github.com/phpcip/loghound/releases/tag/v1.0.0
