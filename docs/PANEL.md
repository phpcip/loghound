# The web panel

Everything under `public/index.php`, `src/Panel/` and `public/assets/`. No framework, no
build step, no Composer, no npm. Open `public/index.php` and you can follow every request
from the front door to Solr and back.

---

## Running it

The panel authenticates every request and **fails closed**: with `auth.mode` unset it
refuses to serve at all, because an analytics dashboard left open on the internet is a
data breach. There is no bypass for localhost, for demo mode, or for anything else.

To look at it without provisioning Solr:

```sh
php tools/panel-preview.php        # writes a throwaway config, prints a password
php -S 127.0.0.1:8099 -t public    # or point any vhost at public/
```

`tools/panel-preview.php` sets `auth.mode = basic` with a random password and turns demo
mode on. It refuses to overwrite an existing `config/loghound.php`, because that file
holds the Opensolr API key and the beacon HMAC secret.

### Demo mode

Demo mode is **opt-in** and never inferred. It is on when `LOGHOUND_DEMO=1` is in the
environment or `ui.demo => true` is in the config, and every page carries a banner saying
the numbers are fabricated. A Solr that is merely unreachable produces an error banner and
empty states — never fake data.

`src/Panel/Fixtures.php` generates a fixed-seed synthetic world (1,400 sessions over 30
days, plus their hits) and runs a miniature JSON-Facet engine over it. It answers with
Solr-shaped facet blocks, so demo responses go through exactly the same PHP shaping code
as real ones and a bug in the shaping shows up in the demo instead of hiding there.

The demo world contains, deliberately: a rotating-proxy fleet of 47 addresses sharing one
header fingerprint, a headless-Chrome cluster on six rented boxes, self-declaring crawlers
including the AI ones, scripted clients, and human sessions whose four timing numbers
differ the way real ones do.

---

## Request flow

```
public/index.php
  Security::sendSecurityHeaders()      CSP: script-src 'self' — no inline JS anywhere
  Config::load(config/loghound.php)    outside the docroot
  Security::requireAuth()              fails closed
  Security::requireCsrf()              anything that is not GET/HEAD
  route  ?v=<slug>                     static map, never a class name from the URL
    POST                → Settings::post() → 303 redirect (POST/Redirect/GET)
    ?api=<action>       → Controller::api() → JSON
    otherwise           → Layout::render() → Controller::body()
```

`src/Panel/Gateway.php` is the only route to Solr. It owns demo-mode substitution and turns
transport failure into a UI state rather than an exception. `Gateway::facet()` forces
`rows=0`, so an aggregate call cannot ship documents by accident.

**There is no generic Solr passthrough.** Every query is built server-side from constants
and allowlists in `src/Panel/Query.php`. The browser sends a view name, a range token,
allowlisted facet selections and free search text — nothing that is query syntax.

---

## Security notes for a reviewer

| Concern | Where it is handled |
|---|---|
| Free text → Solr | Bound as `uq`, referenced by `{!edismax v=$uq}`. `Gateway::search()` prefers `Solr::queryText()`. `Solr::assertSafeQuery()` accepts that one literal and `*:*` and nothing else. No `defType` (it is in `Solr::DENIED_PARAMS` — setting it makes edismax read the braces as text and silently return nothing). |
| Facet filters from the URL | `Controller::readFilters()` drops any field not in `Query::filterFields()`; values are quoted by `Query::quote()` and length-capped. |
| Sort | `Query::sorts()` maps an allowlisted key to a literal sort string. A field plus a direction is never assembled from input. |
| `rows` / `start` | `Security::clampInt` on every request, under `Security::MAX_ROWS` / `MAX_START`. |
| `fl` | Explicit lists (`Query::sessionFl()`, `hitFl()`), never `*`. |
| Output escaping | PHP: `Security::esc()` for HTML, `Security::escJs()` for the boot JSON island. Client: DOM built with `textContent`; `core.js` exposes `esc()` for the handful of authored-markup paths and it is never given API data. |
| Referer links | `Security::safeUrl()` runs **server-side**; the client only ever uses the pre-validated `referer_href`. |
| CSP | `script-src 'self'`. No inline `<script>`, no `onclick=`, no `eval`, no `new Function`, no dynamic `import()`. The theme bootstrap — normally the one place people cheat — is an external synchronous file. |
| ECharts | Vendored at `public/assets/vendor/echarts.min.js` (5.5.1, Apache-2.0, licence alongside it). No CDN; the panel works air-gapped. |
| Secrets | Never echoed. The Opensolr API key and the beacon secret are reported as present/absent only. |
| Errors | Exception messages go to the error log; the browser gets a generic message, because a Solr exception can contain a URL or a credential fragment. |

Every panel query has been run through the real `Loghound\Solr` sanitisers using its
injectable transport, with hostile `$_GET` input, and all pass.

---

## Things in SPEC.md that the panel had to work around

These are the places the spec is wrong, incomplete, or in tension with itself. None of
them are blocking; all of them cost the panel something.

### 1. `geo_p` cannot feed the map

SPEC §4.1 gives `geo_p` **indexed, no docValues**. Solr can search it but cannot facet on
it or return it, so there is no way to aggregate coordinates. The Networks map is
therefore built from `country_s` counts plotted at country centroids shipped in
`public/assets/js/geo.js`, and is labelled country-resolution on screen.

**Fix:** add docValues to `geo_p`, or add a `lat_d` / `lon_d` pair. Either makes the map
city-accurate. Until then the caption also reports how many sessions had a country value
the shipped table cannot place.

### 2. The catchall is only on `hits`, but the explorer searches `sessions`

SPEC §4.1 defines `text_all` and its copyFields on the `hits` core. SPEC §10 says the
session explorer searches "the catchall" — but the dashboard queries `sessions`, and §4.2
does not define a catchall there.

**Fix:** give the sessions configset the same `text_all` field and copyFields (from
`path_txt`/`paths_ss`, `ua_txt`, `as_org_txt`, `netname_txt`, `rdns_txt`, `city_txt`,
`country_txt`). Until then free-text search on the explorer only matches whatever analysed
copies the sessions schema happens to have.

### 3. `bot_verdict_s` is not on `hits`, but Performance wants to filter by it

The verdict lives on the session document (§4.2). The Performance view's "Humans only"
toggle needs it per-request. The panel handles this by counting how many matched hits
carry a verdict at all and telling the operator plainly when the filter cannot be applied,
rather than showing an empty chart.

**Fix:** have `bin/loghound-score` copy `bot_verdict_s` (and ideally `bot_class_s`) down
onto the session's hit documents when it closes a session.

### 4. Percentile latency has to query `hits`

SPEC §10 says the dashboard queries `sessions` and `rollup_daily` and "essentially never"
`hits`, with the session drill-down as the one exception. But `dur_us_l` is per-request and
lives on `hits` (§4.1), so p50/p95/p99 by path cannot come from anywhere else.

The Performance view therefore aggregates over `hits` — facets only, `rows=0`, no documents
— which respects the intent (no document fetches) if not the letter. Worth writing into
§10 explicitly.

### 5. `rollup_daily` is referenced but never defined

SPEC §5 says the scorer writes "the daily rollup doc" and §10 says the dashboard queries
`rollup_daily`, but §4 defines only `hits` and `sessions` — no third core, no field list.
The panel queries `sessions` for every range including 90d. That is correct but gets
expensive on a busy site over long ranges.

**Fix:** define the rollup core (fields, granularity, which core it lives in) and the panel
can use it for the 30d and 90d ranges.

### 6. `Solr::ping()` takes a core

The brief for this panel specified `ping(): bool`; the implementation is
`ping(string $core): bool`, which is correct — Solr's ping handler is per-core.
`Gateway::ping()` supports both shapes and probes the sessions core.

### 7. JSON Facet `domain` is restricted

`Solr::sanitiseFacet()` accepts only `domain.excludeTags`, not `domain.filter` — correct,
since a domain filter is a query fragment the client did not build. Anywhere the panel
wanted a scoped facet it uses a nested `query` facet instead, which expresses the same
thing through a `q` the client does validate. Worth stating in the spec, because
`domain.filter` is the obvious first reach.

### 8. `unique()` is approximate and the spec does not say so

`fp_ips_24h_i` and every "distinct IPs" column come from Solr's `unique()`, which is exact
below about 100 and approximate above it. That matters for a number the product presents
as evidence, so the panel says so in the fingerprint view's caption. §4.2 should say it too.

---

## Front-end layout

```
public/assets/
  css/panel.css            all design tokens; the only place a hex code is written
  js/theme.js              classic script, sync in <head>, no flash of the wrong theme
  js/core.js               boot payload, DOM building, formatting, fetch, theme, copy
  js/charts.js             ECharts wrapper: reads tokens from CSS, re-renders on theme flip
  js/geo.js                country centroids for the Networks map
  js/app.js                static view map, one entry point
  js/views/*.js            one module per view
  vendor/echarts.min.js    5.5.1, Apache-2.0
```

Design rules, applied everywhere: monospace for all data, one accent colour, flat (no
gradients, no shadows, 3px corners), 14px minimum font size, no emoji, hex colours only,
dark and light from `prefers-color-scheme` with a manual override in `localStorage`,
responsive to ~400px with tables scrolling inside their own container and the page body
never scrolling sideways.

Every chart and every stat block carries a visible `population` caption naming what it
counts. That is a SPEC §10 requirement and it is a `<p>`, not a tooltip, so it survives
being screenshotted.

Absent stays absent: a metric with no data renders as an em-dash, never as zero. A session
with no beacon shows a log span and three em-dashes, because nothing measured the other
three (SPEC §1).
