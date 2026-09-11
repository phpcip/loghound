# The web panel

- [Running it](#running-it)
- [A section is a page](#a-section-is-a-page)
- [Two planes, and what talks to which](#two-planes-and-what-talks-to-which)
- [Nothing blocks: the async contract](#nothing-blocks-the-async-contract)
- [Anatomy of a card](#anatomy-of-a-card)
- [What each view requests](#what-each-view-requests)
- [Long operations are stepped jobs](#long-operations-are-stepped-jobs)
- [Request flow](#request-flow)
- [Security notes for a reviewer](#security-notes-for-a-reviewer)
- [Design system](#design-system)
- [Front-end layout](#front-end-layout)
- [Where SPEC.md is wrong or silent](#where-specmd-is-wrong-or-silent)
- [Known limitations](#known-limitations)

Everything under `public/index.php`, `src/Panel/` and `public/assets/`. No framework, no
build step, no Composer, no npm. Open `public/index.php` and you can follow every request
from the front door to Solr and back.

---

## Running it

The panel authenticates every request and **fails closed**: with `auth.mode` unset it
refuses to serve at all, because an analytics dashboard left open on the internet is a
data breach. There is no bypass for localhost, for demo mode, or for anything else.

Two modes exist. `basic` is the browser's own password prompt — scriptable, unstyleable, no
way to sign out. `session` is Loghound's own sign-in page, reached at `?login` with `?logout`
to end it, with an idle timeout and an absolute one; it works only in a browser. Failed
attempts are rate limited per address either way. `docs/SECURITY.md` has the details.

To look at it without provisioning Solr:

```sh
php tools/panel-preview.php        # writes a throwaway config, prints a password
php -S 127.0.0.1:8099 -t public    # or point any vhost at public/
```

`tools/panel-preview.php` sets `auth.mode = basic` with a random password and turns demo
mode on. It refuses to overwrite an existing `config/loghound.php`, because that file
holds the Opensolr API key and the beacon HMAC secret.

### Demo mode

Demo mode is **opt-in and never inferred**. It is on when `LOGHOUND_DEMO=1` is in the
environment or `ui.demo => true` is in the config, and every page carries a banner saying
the numbers are fabricated. A Solr that is merely unreachable produces an error inside the
card that failed and an empty state — never fake data.

`src/Panel/Fixtures.php` generates a fixed-seed synthetic world (1,400 sessions spread
over the last 30 days, plus their hits) and runs a miniature JSON-Facet engine over it. It
answers with Solr-shaped facet blocks, so demo responses go through exactly the same PHP
shaping code as real ones and a bug in the shaping shows up in the demo instead of hiding
there.

The demo world contains, deliberately: a rotating-proxy fleet of addresses sharing one
header fingerprint, a headless-Chrome cluster on rented boxes, self-declaring crawlers
including the AI ones, scripted clients, and human sessions whose four timing numbers
differ the way real ones do.

Demo mode is also the one case where the browser installer stands aside: `Installer::isNeeded()`
returns false for a demo configuration, because that is exactly what `panel-preview.php`
writes.

---

## A section is a page

Every section a view declares is its own page, with its own URL, reached from the left
navigation. `?v=attacks&s=patterns` is one page carrying one card.

**The list is a class constant.** `Controller::SECTIONS` on each view — `[card id, short nav
label]`, in render order — and it drives four things at once: the sub-items under that view in
the navigation, the URL that names each page, the number printed on the card, and, where the
view chooses, the order `body()` walks. `Layout::nav()` reads the constant off the class, so
building the navigation constructs nothing and renders nothing.

**No view file had to be rewritten for it.** `body()` still emits the whole view;
`Controller::renderOnlySection()` gates `cardOpen()`/`cardClose()`, which every card in the
product is built from, and `Layout` keeps the one the URL names. Output *outside* a card is
kept — the layout wrappers a view opens around a pair of cards are balanced, and the Settings
page's flash after a save is page-level and has to survive. A section whose card never rendered
falls back to the whole body, which is what makes the "no Opensolr credentials" explainer reach
the reader whichever section they asked for.

**On the front end, one line does it.** `loadCard()` returns early when the card is not in the
document, so a view module's `refresh()` can keep listing every card it has and only the one on
screen is fetched.

**The one exception is the session explorer.** Its search box, its facet rail and its results
are one instrument, so its `SECTIONS` is deliberately empty and the whole body renders.

**Old deep links still land.** Every section used to be an anchor — `?v=attacks#atk-patterns-card`
— and `assets/js/app.js` matches the fragment against the view's section list in the boot payload
and replaces the URL with the page that holds it.

### The top bar

One sticky row, rendered by `Panel\Layout::topBar()` from what the view declares in
`Controller::toolbar()`, containing four controls and nothing else: applied filters (a button
with a count, shown only when something is applied, opening a dialog that lists every value on
both filter planes and removes them), duration, hostname, and Opensolr resources. It is a GET
form, so duration and hostname work with scripting off; `assets/js/topbar.js` submits it on
change.

It replaced a jump bar plus a toolbar that `assets/js/responsive.js` assembled at runtime by
moving whatever furniture it found into a strip and condensing it on scroll — four different
layouts across four pages, one of which clipped its own last control off the right edge.

### Scope is remembered

`src/Panel/Scope.php`, in the session. The rule, per namespace: **the URL wins when it speaks;
the session fills the silence.** A namespace the URL names is taken from the URL and stored; one
the URL says nothing about is restored. `fx=1`/`lfx=1` are how a URL states an *empty* filter set
rather than an absent one, so clearing the last filter is not undone on the next page load. What
is restored is put back in the address bar with one redirect, because the JSON endpoint each card
fetches and every CSV export link read the query string and cannot be reached from PHP.

---

## Two planes, and what talks to which

The panel draws on two completely separate sources, and keeping them straight is the single
most load-bearing fact about this codebase.

| | **The web plane** | **The search plane** |
|---|---|---|
| What it is | Your webserver's access logs, parsed and indexed by Loghound | The request log of the Opensolr search indexes your account owns |
| Where it lives | Loghound's **own two indexes**, `solr.hits_core` and `solr.sessions_core` | Opensolr's analytics shards, on the platform |
| How the panel reads it | `src/Panel/Gateway.php` → `src/Solr.php` → `solr.base_url` | `src/OpensolrLog.php` / `src/Opensolr.php` → `https://opensolr.com/solr_manager/api` |
| Views | Overview, Where they came from, Pages, Site search, Engagement, When they come, Bot forensics, Attacks, Fingerprint clusters, Networks, Session explorer, Performance, Virtual hosts | Solr (Index analytics) |

### Gateway is the only route to Loghound's own Solr — and nothing else has a route to Solr at all

The old one-line version of this ("Gateway is the only route to Solr") is now only half the
statement, and the missing half is the more important one.

**Still exactly true:** `src/Panel/Gateway.php` is the only way any view reaches Loghound's
own two indexes. It owns demo-mode substitution, it turns transport failure into a UI state
rather than an exception, and `Gateway::facet()` forces `rows=0` so an aggregate call cannot
ship documents by accident. The base URL it uses is `solr.base_url` and nothing else, and the
core it queries is always `Gateway::hitsCore()` or `Gateway::sessionsCore()` — never a name
that came from a request.

**Newly true, and not covered by that sentence:** the Solr view does not go through Gateway.
`Indexes` extends `src/Panel/OpensolrView.php`, which reads the search plane through
`src/OpensolrLog.php` (`GET /solr_manager/api/request_log`) and `src/Opensolr.php`
(`get_index_list`), both against the Opensolr platform API. `Plan usage` reaches the platform
the same way, through `src/Quota.php` → `get_core_info`.

The property that matters to a customer follows from both halves together, and it is stronger
than either:

> **Loghound never contacts a Solr server belonging to a user.** Not over SSH, not by shell,
> not by reading a log file off a node, not by opening an HTTP connection to a
> `solrcluster.com` host. The only Solr it ever speaks to is the pair of indexes it
> provisioned for itself. Everything it knows about *your* search indexes it learned by
> asking the Opensolr platform, which already holds that data and already enforces ownership
> on it.

There is no agent to install, no log4j2 format to detect, no volume problem, no second copy
of anybody's query log, and no way for Loghound to be blamed for something happening on a
customer's node. `Opensolr::connectionDetails()` — the one method that returns a Solr URL for
an arbitrary index — has exactly one caller in the repository, `Setup\Storage::fetchConnection()`,
which uses it to learn where **Loghound's own** indexes live during provisioning. Nothing in
`src/Panel/` references it.

---

## Nothing blocks: the async contract

**No view issues a Solr query while PHP renders the page.** `Controller::body()` emits
headings, captions, table headers and empty states and nothing else; every number arrives
afterwards over `fetch()`. The rule is absolute, and the two places that used to break it
are called out in the code where they were removed:

- `Layout::banners()` used to ping Solr on every page render, so *every* page in the panel
  blocked on a network round trip before it emitted a byte. It no longer contacts Solr at
  all. The two checks left are free — demo mode is a config flag and `Config::validate()`
  touches no network.
- The Settings page used to run the beacon-coverage facet inside `body()`. It is now the
  `?v=settings&api=beacon` action, fetched after the page has painted.

What that buys, concretely:

| | |
|---|---|
| First paint | Independent of Solr. A dead backend still renders the whole page, its navigation and its captions. |
| Failure blast radius | One card. A card that fails renders its error inside itself with a Retry button; every other card on the page is untouched and keeps its data. |
| Slow queries | Visible. Each card names what it is doing in words, and after five seconds starts counting elapsed time. |
| Retry | Per card. Retrying re-runs one request, not the page. |

### The progress strip

Every async card carries the same three-part loading state, emitted server-side by
`Controller::skeleton()` so it is in the DOM from the first byte:

1. a flat 3px indeterminate bar (`.progress-indeterminate`; a bar, not a spinner, and no
   gradient, because the design system bans them);
2. a **worded label** — "Faceting signal codes", "Computing per-path percentiles",
   "Bucketing sessions by hour" — because a bare spinner tells an operator nothing about
   whether to keep waiting;
3. an elapsed-seconds counter that appears **after 5 seconds** (`SHOW_ELAPSED_AFTER` in
   `core.js`), and at **20 seconds** the label changes to "… — still working" and the
   counter picks up the `.loading-slow` accent.

Under `prefers-reduced-motion: reduce` the sweep animation is replaced by a static filled
bar. In print, the progress strip and the loading line are hidden entirely.

### Timeouts, in both directions

| Limit | Value | Where |
|---|---|---|
| Server-side Solr query timeout | `ui.query_timeout`, clamped 3–45s, default **20s** | `Gateway::queryTimeout()` |
| Browser request timeout | **50s** | `REQUEST_TIMEOUT_MS` in `core.js` |

The browser limit is deliberately longer than the server one, so a slow query reports
*its own* diagnosis ("Solr did not answer within the panel query timeout while running
`bots.reasons`…") rather than being cut off client-side with a generic message. Both sit
under the reference install's PHP-FPM `max_execution_time = 60`.

### Errors are diagnoses, not stack traces

`Gateway::explain()` turns a transport exception into a sentence naming the fix — a
timeout, an unresolvable hostname, a refused connection, rejected credentials and a 404
(wrong core name, or the index has not been created yet) are five different problems with
five different answers, and "Solr query failed" tells them apart for nobody. The query tag
is included, so a slow view can be identified without turning on debug logging.

When a card's error looks like a transport problem, `core.js` also reveals the page-level
`#lh-conn` banner **once**, with the first real diagnosis and a link to the connection
check under Settings. The banner markup is rendered by `Layout::banners()` and starts
hidden; nothing pinged anything to decide that.

### A failure is an artefact, not an escaped stack trace

`src/Diagnostics.php`. When something breaks, an operator should be able to copy **one block**
and post it so the bug gets found quickly. So a failure carries what was being attempted in
the product's own words, which step it died on, the complete underlying error including
whatever the platform or the system returned, and the context to reproduce — release, PHP
version, operating system, web server, which front end, which index or file. One row per fact,
aligned on a colon, no colour, timestamps in `mm/dd/yyyy hh:mm:ss UTC` like every other date
in the panel.

In the browser it is rendered through `snippet()` with a copy button, so it scrolls inside
itself and cannot widen the page. In a terminal it is the same block, printed.

**It is designed to be pasted in public, so redaction is the hard requirement.** Gathering
everything into one place creates a new sink, and a sink is where secrets leak. Two passes:
by SHAPE (`api_key=…`, `secret=…`, `https://user:pass@host`, and the rest of the
credential-shaped parameter names) and by VALUE — every secret this installation actually
holds, replaced by name, which catches the same key arriving without a label. The Opensolr
API key, the beacon signing key, the address salt, the panel password hash, the index HTTP
auth password, the account email and any session token are all on the list, and
`tests/test_diagnostics.php` plants each one in a failure path and asserts none reaches the
block.

**Redaction happens here, at the sink, and never where a value is read.** That distinction is
load bearing on this platform: Opensolr sets a new index's HTTP auth password *to the account
API key*, so an earlier attempt that scrubbed API-key-shaped strings out of control-plane
responses replaced the credential Loghound needs with a marker and every authenticated query
afterwards failed 401. A response carries its values through intact
(`tests/test_secret_boundaries.php`); containment belongs to each place a value is shown.

---

## Anatomy of a card

`Controller::cardOpen()` / `skeleton()` / `cardClose()` emit a fixed set of ids from one
base id, and `core.js` addresses them by convention. For a card with base id `ov-pages`:

| Element | Purpose |
|---|---|
| `[data-card="ov-pages"]`, `#ov-pages-card` | The `<section>`. What `loadCard()` inserts an error box into. |
| `#ov-pages-pop` | The "population covered" caption. Rendered server-side so it is never missing; `setPop()` refines it once the real denominators are known. |
| `#ov-pages-status` | The progress strip: bar, worded label, elapsed counter. |
| `#ov-pages-skel` | The skeleton — flat blocks with a slow opacity pulse. Removed, not hidden, once the load settles. |
| `#ov-pages-content` | The real content, present in the DOM from the first byte and merely `hidden`. Table headers and captions are therefore already escaped and laid out before any data arrives; the front end only fills in cells. |
| `#ov-pages-empty` | The empty state. `showEmpty()` / `noDataYet()` reveal it and hide the content. |
| `#ov-pages` (bare id) | The chart container, for a card whose body is one chart. |

A card whose content is rendered server-side — the Settings forms, the fingerprint
explainer, the session search box — calls `cardOpen()` and then `cardEnd()`, skipping
`skeleton()` entirely, so a static card can never sit there showing a progress bar for
data it was never going to fetch.

`loadCard(id, label, loader)` in `core.js` is the only way a card loads. It de-duplicates
re-entrant loads through an in-flight set, drives the ticker, removes the skeleton, reveals
the content, and on a throw renders `.card-error` with a Retry button that re-runs *that*
loader and nothing else.

---

## Filtering: one component, every section

Every filter in the panel goes through `src/Panel/Facets.php`. Filter state, the boolean
operator, the Solr tag, the exclusion, the URL encoding and the payload shape live there and
nowhere else. No view keeps a private copy, and the two copies that existed — the sidebar builder
inside `Sessions.php` and the whole second implementation inside `OpensolrView.php` — are gone.

### The bug it exists to fix

A filter used to be applied as an ordinary `fq`, and the facet over the same field was computed
inside it. So the moment you picked `host_s=opensolr.com`, the VIRTUAL HOST facet listed exactly
one value: every other host had been filtered out of its own facet. Same for the verdict, the
country, the browser. The interface removed the options a multi-select needs — you could not see
what else existed and you could not add a second value. Measured against a real Solr node:

```
fq={!tag=f_ct}content_type:("text/html")
  facet with no exclusion   → text/html 483                        (one option, and no way back)
  facet with excludeTags    → text/html 483, application/pdf 2     (both, with honest counts)
  facets.count in both      → 483, the fully filtered total
```

### Tag, then exclude

Each dimension's `fq` carries a tag this component generates — `f_` plus the field name, never
anything derived from a request. That dimension's own terms facet is asked for with
`domain.excludeTags` naming its own tag **and no other**, so:

- the dimension keeps listing every value it has, with the count each would have if **this**
  dimension's filter were lifted;
- every other dimension still narrows normally;
- `facets.count`, the headline total, stays the fully filtered figure.

One Solr round trip answers a whole sidebar, however many dimensions it has.

### Three operators, chosen per dimension

| Operator | Solr | Offered on |
|---|---|---|
| **Any of** (default) | `field:("a" OR "b")` | every dimension |
| **All of** | `field:("a" AND "b")` | multi-valued fields only — `paths_ss`, `bot_reasons_ss` |
| **None of** | `-field:("a" OR "b")` | every dimension |

"All of" is **withheld**, not shown-and-disabled, on a single-valued field: `a AND b` over one
value per document is empty by construction, and a control whose only possible answer is zero
results is worse than no control. The arity comes from `Query::multiValuedFilterFields()`, and a
test reads `solr/sessions/conf/schema.xml` and fails if the two disagree.

"None of" is the one the product was missing. `-as_type_s:("hosting")` is "everything except
hosting"; it works for one value and for a set. It is also what finally expresses an **absent**
field: `signed_in_b` is written only when the measured site said something, so "not reported" is
`-signed_in_b:(true OR false)` — a real, selectable filter rather than a read-only number with an
apology attached.

**A field with no schema default must be asked for by exclusion**, and two dimensions now depend on
it. `signed_in_b` is written only when the measured site said something. `planes_s` — which
transport planes have seen a session — has no default either, so every session indexed before the
field existed carries no value at all; the correct "has a transport plane" filter is
`-planes_s:beacon_only` (`Query::HAS_LOG_PLANE`), which keeps that history, and `planes_s:log_only`
would silently drop it while looking like a measurement. It is the same trap as `provisional_b`.
The interface spells both with "None of", and the remainder is offered as its own **Not reported**
row with the count behind it, so a reader can see how much history predates the field rather than
having it folded into one of the named values.

The operator is a control on the dimension, showing its own state. It is deliberately **not** a
sentence somewhere else on the page: the paragraph that used to explain "values within one
dimension OR, dimensions AND" is gone and must not come back.

### The URL is the state

Values are unchanged — `f[field][]=value`, repeated. The operator rides in the same array under a
reserved key:

```
?v=networks&range=7d
 &f[as_type_s][]=hosting&f[as_type_s][]=vpn&f[as_type_s][op]=none
 &f[paths_ss][]=/pricing&f[paths_ss][]=/docs&f[paths_ss][op]=all
```

One parameter family carries a dimension's whole state. **A URL with no `op` means "any of"**, so
everything already bookmarked or shared behaves byte-for-byte as it did. Numeric keys are values,
`op` is the operator, any other key is ignored. The Opensolr request-log plane uses the same shape
under `lf[…]`, which stays a separate namespace because those field names exist on the platform's
analytics shards and none of Loghound's own fields does.

### Counts say what they count

With exclusions in play it is easy to render a number that answers a different question than its
label claims, so every group carries the sentence that says which:

- `basis: excluded` — "Counts are what each value would match with the *virtual host* filter
  lifted, so a second value can be added."
- `basis: filtered` — "Counts are what each value matches on this page as filtered."
- `overlaps: true` on a multi-valued dimension — one session holds several values, so the buckets
  **do not sum to the total**. Measured: three buckets of a multi-valued field totalled 398 inside
  a population of 485.
- A selected value that has fallen out of the top N is still listed, with a **null** count rather
  than a fabricated one, so the filter always has a control that turns it off.

### Two planes, two exclusion strategies

Loghound's own cores take `{!tag=}` and `domain.excludeTags` and answer a view in one request.
The Opensolr request-log plane cannot: `OpensolrLog::assertSafeFq()` refuses any `{!` outright,
and the platform endpoint sanitises the value of every underscored parameter — `facet_field`
among them — down to a class with no braces, so `{!ex=…}` could not arrive intact even if the
filter could carry it. There the same semantics come from **lifting one dimension's clause and
asking again**: one extra call per *filtered* dimension, at most four because that plane has four
filterable fields, and none at all when nothing is filtered.

### Values are spoken in words

`bot_verdict_s` holds `likely_human`; `bot_reasons_ss` holds `fp_cluster_proxy_fleet`;
`as_type_s` holds `hosting`. Those are the right things to store, to filter on, to put in a URL
and to grep for, and the wrong things to print at somebody who has not read `src/Score/Rules.php`.

- The words for a fired signal live with the rules that produce them, in
  `Score\Rules::REASONS` — slug, short label, one sentence saying what the rule actually tests,
  and a severity. A test fails if any code the scorer can emit has no entry.
- The other closed vocabularies are `src/Panel/Vocabulary.php`, which also reads the reason table
  rather than copying it.
- **`Panel\Vocabulary` is authoritative for the value set and the words. `assets/js/icons.js` is
  authoritative for the mark drawn in front of a value and for nothing else** — it has a generic
  fallback per dimension and never enumerates what exists.
- The slug stays: it is the filter value, it stays visible beside the label, and filtering,
  multi-select and the operators all still work on it. Only the presentation changed.
- An unrecognised value renders as itself. Never a wrong-but-plausible label, never blank.

**A value that cannot be filtered is shown and says so.** This starts to matter with
`search_terms_ss`, the first dimension whose values are text a person typed: a real search term can
contain `{!` or `_query_`, and `Solr::assertSafeFilter()` refuses those anywhere in a filter — by
throwing — even though `Query::quote()` has already made them inert (measured: `field:("{!frange
l=0 u=100}")` matches 0 documents, and an escaped break-out attempt matches 0 too; only the
*unquoted* form is dangerous). So the value is counted, listed, and drawn as a static row with the
reason, rather than as a link that silently does nothing or hidden as though nobody searched for
it. Relaxing the blunt check to permit those bytes inside a properly quoted literal would make them
filterable and is a deliberate decision about a shared security primitive, not a tidy-up.

The tables are shipped once in the boot payload, like the country names, so no JavaScript module
keeps a second copy. `boot.dimensions` replaced the hand-kept `FILTER_LABELS` in `identity.js`,
which had drifted: five fields the server filtered were missing from it, so the browser refused to
draw chips the server was honouring.

### Cross-tabulations

Four, each answering a question its view cannot otherwise answer, each asked as a nested JSON
facet folded into a request the view was already making — no extra round trip:

| View | Pivot | The question |
|---|---|---|
| Overview | country × verdict | which countries send people and which send automation |
| Bot forensics | bot class × network type | a declared crawler on hosting is ordinary; a headless browser on consumer broadband is not |
| Networks | network type × verdict | should I rate-limit this address space |
| Attacks | attack pattern × status class | what the server actually **answered** each kind of probe with — the same probe answered 404 and answered 200 are a non-event and an incident |

Every cell links through to the view filtered by **both** dimensions at once, each keeping the
operator it already had. The inner facet is limited, so the cells of a row do **not** add up to
the row total; the shortfall is printed as its own muted cell rather than left to be inferred.

`Query::pivots()` records the omissions and why: Virtual hosts and Fingerprints already carry the
cross-tab in their own tables, Performance would need `status_i` which cannot be in the filter
allowlist, Sessions has the dimension dialog, and the Opensolr views cannot nest a facet at all.

### The long tail

Two controls, applied by one rule everywhere rather than on three dimensions and not the rest:

- an **inline filter box** above any list longer than ten values. Focusing it warms the full value
  list for that dimension (one request per dimension per page load, cached); typing then narrows
  across every value the dimension has, not only the rows on screen, matching both the stored value
  and its label. Without the cache it falls back to hiding rows, silently.
- a **value browser** dialog behind "Show all N values": a search box, an A–Z index with the empty
  letters visibly inactive and a `#` bucket, values grouped under letter headings in columns, each
  with its count. It reuses the panel's one dialog shell.

The browser **stages** its selection: clicking a value toggles it in a pending set and the dialog
stays open, because the reason to open it is to pick several; Apply navigates once. Each row is
still a real `<a href>` carrying the result of applying the pending set plus that row, so a
middle-click, a copied link and a scripting-off click all land somewhere coherent. The sidebar
keeps one-click-navigates, which is right for one decision with the result already on screen.

The **listing** is bounded at 2,000 values, sorted by count, with `numBuckets` requested, so a
dimension with more distinct values than that says "listing the 2,000 most common of 48,391".

The **search is not bounded to that listing** — it covers every value the dimension has. The two
are different populations and the dialog says which one is on screen, because they look identical
otherwise: a listing note reads "the search box is not limited to these", and a search result reads
"every value of this dimension was searched, not only the ones listed".

Typing sends one request after a 250 ms pause, or immediately on Enter for somebody who types
faster than that. An answer overtaken by a newer one is dropped — `searchToken` for searches within
one open dialog, `isCurrent(generation)` for a dialog that has since been closed or replaced. Below
two characters, and on any dimension whose values are *entirely* in the page already, it filters
locally instead: a dimension with twelve values must not round-trip to narrow twelve values. Search
results are capped at 200, which is read from the top down — nobody scrolls to the two hundredth
match, they type another character.

The same rule applies to the sidebar's inline `Filter…` box: local while the whole dimension is in
the page, server-side once the list on screen is only the head of a longer one. Filtering a capped
list locally is what made it report "no match" for values that exist.

#### Why the search is a classic facet and not a JSON one

**The JSON Facet API has no substring filter.** `contains` and `containsIgnoreCase` belong to the
classic facet component; inside a `json.facet` block they are neither honoured nor rejected, they
are silently dropped. Measured against a live Solr node:

```
json.facet {"type":"terms","field":"keywords_sm","contains":"Feature"}
  → numBuckets 897; buckets: Solr, Opensolr Changelog, New Feature, REST API …
json.facet {"type":"terms","field":"keywords_sm","bogusparam":"x"}
  → numBuckets 897; the same buckets, byte for byte
json.facet {"type":"terms","field":"keywords_sm","prefix":"New"}
  → numBuckets 8, all beginning "New"                          (prefix IS supported)

facet=true&facet.field=keywords_sm&facet.contains=feature&facet.contains.ignoreCase=true
  → New Feature (74), AI And Vector Features … (1)             (this is the one that works)
```

Allowlisting `contains` in `Solr::sanitiseFacet()` would therefore have shipped a search box that
returned the dimension's most common values *whatever was typed*, and was believed. So the search
goes through `Solr::facetContains()`, which is the one classic-facet call in the panel. Tag
exclusion still applies and is spelled on the field name there — `facet.field={!ex=f_host_s}host_s`
— and `sanitiseQueryParams()` skips exactly that one block before the field-name allowlist, so
`{!frange}`, `{!join}` and `{!xmlparser}` are still refused in the same parameter.

The substring is request text — the first facet parameter that is — so it is capped at 64
characters, rejected outright if it holds a control character, and refused when empty. It is **not**
rejected for containing `{!`, `_query_` or `_val_`, unlike a filter value, and that difference is
measured rather than assumed: with the rest of the query held constant at 485 documents,
`facet.contains={!frange l=0 u=100}`, `_query_:"*:*"` and `") OR (""="` each returned `numFound 485`
and zero matching terms. Solr compares the string literally and never parses it, and a path or a
User-Agent can legitimately contain any of them.

## What each view requests

Each row is one independent `fetch()` with its own progress strip, its own retry and its
own failure. Where two cards share a row they share one in-flight promise, because they
are two renderings of one facet rather than two questions.

### Overview — 4 requests, 4 cards

| Card | Action | What it asks Solr |
|---|---|---|
| 01 Who was here | `totals` | Five mutually exclusive population counts, plus `unique(visitor_s)` and sums for the human half |
| 02 How long they actually stayed | `timing` | The four clocks as `avg` + `percentile(…,50)` over human-with-beacon sessions, and the log-only figure over all human sessions |
| 03 Sessions over time | `series` | One range facet on `ts_start` with the five populations nested per bucket |
| 04 Top pages | `toppages` | Terms facet on `path_s` in the HITS core, counting REQUESTS, with `unique(session_id_s)` beside each row. Re-run when the pages/every-request toggle changes. It is on the request plane because a session count cannot rank paths — `paths_ss` is a set per session, so every row reads 1 on a short window — and the population toggle went with it, because a verdict is a session-level conclusion that the hits core does not carry. |

Overview was one request feeding three cards. It is now four: the timing block appears the
moment it is ready instead of waiting on the hourly series.

### Bot forensics — 6 requests, 6 cards

`split`, `reasons`, `verdicts`, `histogram`, `classes`, `crawlers`. The `bot_reasons_ss`
facet is the expensive one; separating it means the declared/evasive split, the verdict
donut and the crawler roll-call are on screen long before it lands.

### Attacks — 6 requests, 8 cards

`answered`, `patterns`, `requests`, `who`, `impersonation`, `when`. Five of the six read the
**hits** core, because a status and a path have to come off the same document — a session that
recorded one 2xx and one 4xx says nothing about which of its requests was the hostile one.
`impersonation` is the exception and reads **sessions**, because identity is a session property.

The pattern facet feeds two cards (the table and the cross-tab) from one request. The
answered-requests card is the only card in the panel outside the session explorer that reads
documents rather than facets, and it is bounded twice: by the population (answered attempts
only, which is a handful on a healthy site) and by a 200-row clamp.

Ordering is the point of the page. Both ranked tables sort by **what the server answered**
first and by volume last, which is the opposite of every other tool in this category. See
[ATTACKS.md](ATTACKS.md) for the rule table and, per rule, what it misses and what it
over-reports.

### Networks — 5 requests, 6 cards

`totals`, `asns`, `types`, `netnames`, `geo`. The ASN treemap and its table come from
`asns`; the map (04) and the country table (06) both come from `geo`, issued once and
rendered into both.

### Performance — 4 requests, 4 cards

`headline`, `latency`, `paths`, `status`. All four carry the current `kind` and `who`
toggle values, and changing either re-runs all four — they describe one scope and must not
disagree about it.

### Session explorer — 2 requests on load

The result table (`list`) and the facet sidebar (`facets`) are **separate** requests, so
rows appear as soon as the documents are back rather than waiting on eight terms facets.
Opening a session issues a third (`detail`) into the drill-down panel. The search form
itself is a plain GET form and is rendered server-side, so a search is a bookmarkable URL
and the view degrades to a working table with JavaScript off.

### Fingerprint clusters — 1 request, plus expansions

`clusters` fills the table; expanding a row issues `members` for that fingerprint only.
Re-sorting or changing the minimum-IP floor re-runs the one card. The explainer card above
it is prose and is rendered server-side — making it wait on a request would be theatre.

### Virtual hosts — 2 requests

`list` and `compare`. On a machine serving one site this view has nothing to say; on one
serving six it is the difference between a dashboard and a blur, because `host_s` is on every
hit and every session document.

`compare` is **one** faceted request — a terms facet on `host_s` with the five population
queries nested inside it — so the cost does not grow with the number of sites. One row per
host, sorted by evasive-bot share, capped at 50 hosts.

`list` is the odd one out: it is deliberately cheap and deliberately reachable from **every**
view (`?v=hosts&api=list`), because the host selector it fills is page furniture rather than a
control on one card. Picking a host adds `f[host_s][]` to the URL, and `Controller::filterFqs()`
already applies that to every query on every view — so scoping the whole dashboard to one site
is one mechanism, not seven. `list` removes the host filter from its own filters before it
runs; without that, picking a host would reduce the selector to the host you picked and there
would be no way back. Its `multi` flag is what the front end acts on: with one host or none the
selector is never inserted into the page at all.

### Plan usage — 2 requests

`meter` and `plan`, both from `src/Quota.php` against the Opensolr control plane
(`get_core_info`), not from Solr.

`meter` is the small one. It answers from the quota cache on all but one call in
`quota.refresh_sec` (default 300s), which matters because the panel's own queries consume the
bandwidth it reports. The two cores have independent quotas and are reported separately; the
**worst** of them is the one a summary shows, because averaging a blocked index with an idle
one tells the operator they are fine when they are not.

`account` is what the top bar's **Opensolr resources** control opens: `plan` plus the index
allowance from `get_account_summary`, so one dialog carries every quota the account has rather
than the one figure a header strip had room for.

The two dimensions are given deliberately different weight. **Bandwidth** is the hard limit:
it cannot be reclaimed by deleting anything, it resets on the 1st, and going over it makes
Opensolr answer 403 to every request against that index — reads included — until an upgrade
or the monthly reset, with access returning by itself about 17 minutes after usage is back
under. So it gets the meter, a warning state well before the limit, and an upgrade link; the
warning has to arrive early, because after the limit the panel that would have shown it is
dark — which is why it is reachable from the top bar of every page. **Disk** is not presented as
a risk at all, because the rolling trim in `src/Quota.php`
runs *before* a write and the index therefore never reaches its disk quota. It is reported as
a fact about how far back the data goes. The single exception is a trim that **failed** while
the index is genuinely near the limit — then the blackout really is coming, and that is loud.

### Solr — 4 requests, plus the index picker

`headline`, `volume`, `qtime`, `handlers`, and the shared `indexes` action that fills the
picker. What one Opensolr search index is being asked and how well it answers. Each of them is
its own page; the chosen index is kept in the session, so it survives moving between them.

Everything on this page is an **aggregate**. Not one card fetches a request document: a facet
answers all of it, and shipping a customer's query log through the panel in order to count it
would be both slower and a larger privacy surface for no gain. Nothing is stored — the
platform already holds this data.

The QTime histogram is bucketed and the page says so. The platform's request-log endpoint
rewrites any parameter name containing an underscore into a dotted Solr parameter and strips
braces and quotes out of its value, so a JSON Facet — and with it Solr's exact `percentile()`
— cannot survive the trip. Classic range faceting can, so the distribution is a fixed-width
histogram and the percentiles read off it are reported as "at most" a bucket edge. An
approximate number labelled approximate is honest; a precise-looking number that is not
precise is not.

### The two states of an Opensolr view

`src/Panel/OpensolrView.php` handles both, and both have to read well:

| State | What the page does |
|---|---|
| Credentials configured | Everything works. |
| No Opensolr credentials | `noCredentials()` renders instead of the cards: what this section is for and where the two values go. No broken cards, no failed requests. **Loghound is a complete product without Opensolr and must never imply otherwise.** |

Two more conditions are handled once, in `OpensolrView::fetch()`, rather than in each card:

- **Demo mode** returns a stub. There is no fabricated Opensolr data and there should not be:
  the alternatives are inventing somebody's query log, or quietly making a real billed API call
  from a session showing a "these numbers are fake" banner.
- **No index chosen yet** returns a stub too. The picker is filled from the platform, so the
  first render of a card can legitimately have nothing selected.

Both stubs have exactly the shape of a real result, so a caller reads facets off them without a
second code path.

Ownership of the named index is **not** re-derived locally. The platform answers
`ERROR_NOT_CORE_OWNER` for an index this account does not hold, and that is handled as an
ordinary outcome with a sentence rather than as a failure — a second API call per request to
answer a question the first call already answers would buy nothing. The index name is validated
for *shape* (`Security::isSafeCoreName()`) before it is sent.

### Settings — no card fetches, two async paths

The forms are server-rendered and post normally. What JavaScript adds is the beacon-status
fetch and the job controls; everything else on the page works with scripting disabled. That
line matters for the source list: confirming a source and removing one are plain forms and
work without scripting, while **rescanning is a job** and therefore needs it.

Settings registers job kinds of its own alongside the three built-ins: `source_rescan`,
`schema_check` and `destructive_uninstall`. Discovery walks the Apache and nginx config trees
following every `Include`, then tails and grades up to twenty files, so it is exactly the
shape of work that must not run inside one request. Demo mode withholds the kinds rather than
hiding the buttons, which refuses them at start, poll and cancel in one place.

#### Critical errors

The second card on the page, because it is the answer to a question the product could not
previously answer: *why is my panel empty?* The tailer's parse errors, a rejected configset, a
failed schema push, a source it cannot read and an unreachable control plane were each a
separate counter in a separate file, and each needed knowing to go and look.

**Critical only — no levels, no severities, no filters.** Every level control turns the
question into "which one should I be looking at", and the answer to that is always "all of
them", which is how a list of errors becomes a list nobody reads. The admission test is not
"was this an error" but "is something not working because of this". In: the tailer stopped or
cannot read a source, a configset rejected, a schema push failed, the control plane
unreachable, Solr refusing writes, a job died, nowhere to write. Out: a single parse error,
one slow query, a retried request that then succeeded, a warning, anything informational,
anything that resolved itself.

The one real edge is parsing. A single unparsed line is nothing — logs contain rubbish and
the parser drops it on purpose. An *entire source* failing to parse is the product silently
ingesting nothing, which is indistinguishable from an empty panel and has no other symptom,
so it is in.

`src/Panel/Incidents.php` supplies two things under one heading: what is broken **now**,
derived from evidence the product already writes (the tailer's status document, the saved
schema verdict, the configuration, the writability of `var/`), and a bounded **ledger** of
things that happened and are over, which no later probe could rediscover. A derived entry
disappears by itself when the condition clears; a recorded one can be cleared by hand and
anything still true comes straight back, which is what stops the card being a place a real
problem can be dismissed. The ledger is `var/incidents.json`, mode 0600, never under the
document root, capped, pruned on every write, identical failures coalesced, and redacted both
on the way in and on the way back out. Each entry carries the copyable block described above.

An empty card is the normal state and says so.

#### Remove Loghound entirely

`destructive_uninstall`, 11 steps — the same eleven `install/uninstall.sh` prints, from
`Loghound\Setup\Teardown::STEPS`, so the browser and the terminal show the same run. The panel
performs the five that need no root (prove ownership, delete, confirm absence from the account
listing, empty `var/`, remove the configuration) and shows the other six in their place with
the reason and the command. See [docs/INSTALL.md](INSTALL.md#uninstalling).

It is armed by a POST carrying the typed words and a current second factor, which records a
one-time grant in that session; `job_start` spends it. Registering the kind is what makes a
run pollable and cancellable after the grant is gone — it is not permission to start one, and
an unarmed start is refused in the same words as an unknown operation.

---

## Long operations are stepped jobs

`src/Panel/Jobs.php`. The reference install runs PHP-FPM with `max_execution_time = 60`,
and real operations exceed that. An action that does its work inside one request is a
gateway timeout waiting to happen, and the operator is left with a dead tab and no idea
whether it ran.

**A job is a list of named steps, and each poll executes exactly one step and returns.**
Every individual step is bounded far below the execution limit, so no single request can
time out however long the whole job takes.

There is **no background process, no `exec()` and no worker daemon**, because the product
has to install on a bare box with no toolchain. State lives in SQLite (`var/panel-jobs.db`,
mode 0640, WAL) rather than in a process, which is what makes a job resumable across a
refresh.

### Any view can host one

The mechanism used to be reachable from exactly one view. The front controller routed POST by
naming a concrete class, and the list of kinds was a closed constant — so a view that grew an
asynchronous operation was dead on arrival: its button posted, the router answered 405, and
nothing said why. Two changes fixed that, and both are pinned as contracts by
`tests/test_jobs.php`.

**1. Routing is on a capability, not on an identity.** `src/Panel/JobHost.php` is an interface
with one method, `post(): string`. `public/index.php` routes POST on `$view instanceof JobHost`,
so any view can host an asynchronous operation. A view that does not implement it **cannot be
POSTed to at all** — the router answers 405 with an `Allow` header — which keeps the default
fail-closed: read-only views stay read-only without anyone having to remember to say so. There
is a test asserting that Overview, Bots, Fingerprints, Networks, Sessions and Performance do
*not* implement it.

Implementing `JobHost` is a deliberate act, and the implementer owns the checks the front
controller does not do for it: authentication, the CSRF token, and validating every field it
reads out of the body. `OpensolrView::post()` re-enforces CSRF itself even though the front
controller already has, because that method is the boundary deciding whether a scan starts, and
a control applied only by the caller is one refactor away from being gone.

**2. Kinds are extensible.** `Jobs::__construct()` takes a third argument, `array $extraPlans`,
mapping a kind name to a planner. `Jobs::KINDS` still lists **only the built-ins**; the instance
method `kinds()` returns the built-ins plus whatever the hosting view registered, and that is
what `start()` and `latest()` check against. A registered kind name must match
`/^[a-z][a-z0-9_]{2,31}$/` and may not shadow a built-in — both are refused with a throw in the
constructor, before the store is touched.

`OpensolrView` exposes three hooks a subclass overrides: `jobKinds()`, `jobPlans()` and
`jobParams()`. The base class returns nothing from all three, so a view that inherits the POST
endpoints without opting in refuses every `job_start` before the store is opened.

**3. Jobs take parameters, and idempotency is per kind *and* target.** `start(string $kind,
array $params = [])` normalises its parameters to a flat, bounded, key-sorted scalar map and
hashes them into a `target` column. Starting a scan of one index no longer hands back the job
that is still scanning a different one — which would report the wrong index's progress under
the right index's heading. Sorting by key makes the hash stable regardless of the order the
browser sent the fields in, so a genuine double-click still converges on one job.

`normaliseParams()` refuses rather than partially accepting: at most 12 fields, keys matching
`/^[a-z][a-z0-9_]{0,31}$/`, values scalar-or-null, strings at most 256 bytes. A malformed
parameter refuses the job instead of starting one that silently dropped the field naming its
target. A planner is re-run on every poll and handed the job's stored context, which on the
first call is exactly the parameters `start()` was given — so a poll cannot run against a
different target than the one the job was created for. **The plan length must not vary between
polls**, because the store fixed `total` at creation and the progress fraction is read against
it; a planner returning no steps refuses the job rather than storing one that can never finish.

**Ownership is decided by the view, and nowhere else.** `Jobs` re-checks that parameters are
flat, small and well-named; it does not and cannot know whether this account owns the index
being named. A view taking an index name must check it against the account's own list *before*
returning it from `jobParams()`. Refusing before the job exists is the point: a job that starts
and then discovers it may not read its target has already put that target in the store, in a
step note and in a poll envelope. If the index list cannot be read, the start is refused — a
check that cannot be performed is a failed check.

### The kinds that exist

`Jobs::KINDS` — the built-ins, available to any view:

| Kind | Steps | What it does |
|---|---|---|
| `solr_connection` | 5 | Check the configuration · ping the sessions core · count session docs · count hit docs · report how fresh the newest session is |
| `opensolr_check` | 3 | Credentials present · contact the API and list regions · match the configured region. **Read-only** — provisioning is the installer's job and lives in `src/Setup/` |
| `retention_preview` | 4 | Read the policy · count sessions past it · count hits past it · summarise. **Counts only.** The panel never deletes; `bin/loghound-retention` does |

Registered by `src/Panel/Queries.php`, the query-shape scan:

| Kind | Steps | What it does |
|---|---|---|
| `shape_scan` | 20 | Reads the request log for one index in pages of 400, folding each page into per-shape aggregates |
| `empty_scan` | 20 | The same, filtered to requests that matched zero documents |

Its parameters are `core` (validated for shape, then checked against the account's own index
list) and `range` (checked against `Query::ranges()`). The range travels as a parameter rather
than being read from the query string because a poll is a POST to the bare view URL and carries
no range at all — and because that is what makes two ranges two jobs rather than one job
answering for whichever range happened to start it. Demo mode refuses the start outright: there
is no fabricated Opensolr data to scan.

Twenty steps of 400 documents is a ceiling of **eight thousand requests per scan**, which is
the honest cost of the feature: twenty bounded reads of somebody else's platform, about fifteen
seconds of polling, and a job context that stays under a megabyte. It is a cap, not a target —
a step that reaches the end of the log sets `stop` and finishes the job early, so a quiet index
completes in one step and only a busy one pays the full twenty. Distinct shapes retained in the
context are capped at 250; past that, an unseen shape increments an overflow counter instead of
being added, so the numbers on screen never go backwards and the page can say how many were
left out. Every card states the population it covers, because a capped scan covers a sample and
a number that does not say what it counted is a lie.

The aggregates are chosen to be **mergeable**, because the context is folded step by step:
counts and sums merge by addition, the maximum by comparison, and the latency histogram bucket
for bucket. A list of samples would either grow without bound across twenty pages or need a
caveat nobody reads, and a percentile computed per page cannot be combined with another page's
at all.

Because the scan is a job, it survives a page refresh: `job_latest` re-attaches to the newest
job of a kind for this operator and the table picks up where it was, rather than restarting
eight thousand reads. Nothing scanned is stored beyond the job's own context, which is swept
with the job.

### Behaviour that matters

- **Idempotent start.** `start()` returns the job already running for this kind, owner **and
  target** rather than launching a second, so a double-clicked button, a refreshed tab and a
  second window converge on one job id.
- **Honest progress.** The steps are known in advance, so `percent` is a real fraction of
  known steps, never a guess. `elapsed` lets the UI show seconds so the operator can tell
  working from hung.
- **Cancellable at boundaries.** Cancel sets a flag; it is honoured *before* a step starts
  and never during one, because a half-executed step is the one state nobody can reason
  about.
- **Leases.** A compare-and-set on the lease column (45s) stops two tabs polling the same
  job from executing the same step twice.
- **Reattach.** `?v=<view>&api=job_latest&kind=…` finds the newest job of a kind for this
  operator, so a reloaded page picks up what it was watching without the browser having had
  to remember an id. The kind is checked against the *view's own* list before the store is
  touched. `settings.js` does this on load for every `[data-job]` button; the query-shape
  tables do it for their two kinds.
- **Swept.** Finished jobs older than an hour are deleted on the next store open.

### Job security

- **Ids are 96 bits** of `random_bytes` (`bin2hex(random_bytes(12))`, 24 hex characters),
  shape-checked with `/^[a-f0-9]{24}$/` before the id reaches the store.
- **Every lookup is scoped to an owner** derived from a per-session random secret combined
  with the authenticated username. A job that is not yours is reported *exactly* as one
  that does not exist — one message, `NOT_AVAILABLE`, for both — so the id space cannot be
  probed for existence. Changing user inside a session changes the owner, which makes
  earlier jobs invisible rather than inherited.
- Where no session can be established (CLI, or headers already sent) the owner secret is
  minted per process instead, so jobs become unreachable across requests rather than
  collapsing into one shared identity every caller would inherit. Denying is the safe
  direction.
- **Every statement is prepared with bound values.** No SQL is built by concatenation.
- **`Jobs::redact()` runs at every boundary** — step details, persisted errors and anything
  sent to the error log — because the Opensolr API key travels in a query string and a
  transport error can quote the URL it failed on. HTTP basic credentials inside a Solr base
  URL are stripped the same way.
- **Nothing here deletes.** `Solr::deleteByQuery()` is documented internal-only and no HTTP
  path reaches it.
- The three job endpoints are **POSTs** (`action=job_start|job_poll|job_cancel` on the hosting
  view's own URL), so they go through the front controller's CSRF check like any other
  state-changing request, and answer JSON via `Controller::sendJson()` with the same
  `JSON_HEX_*` flags as `Security::escJs()`. A view that does not implement `JobHost` has no
  POST route at all, so these endpoints do not exist on it.
- **A registered kind cannot shadow a built-in**, and a kind name that is not a plain lowercase
  identifier is refused in the constructor — before the store is opened, not when a job is
  started. `tests/test_jobs.php` asserts both, plus that a job started by one operator is
  invisible to another and that a parameterised job replans from its *stored* parameters on
  every poll.
- Every outbound HTTP call has an explicit short timeout (5s connect, 15s total) with TLS
  verification on and redirects off.

---

## Request flow

```
public/index.php
  Security::sendSecurityHeaders()      CSP: script-src 'self' — no inline JS anywhere
  Config::load(config/loghound.php)    outside the docroot
  session_set_cookie_params()          HttpOnly, SameSite=Strict, Secure only under TLS
  Installer::isNeeded($cfg)            → hand over to the browser installer, or fall through
  ?login / ?logout                     → the sign-in page, in session mode only
  Security::requireAuth()              fails closed, in both directions
  Security::requireCsrf()              anything that is not GET/HEAD
  route  ?v=<slug>                     static map, never a class name from the URL
    POST                → $view instanceof JobHost ? $view->post() : 405
                            → 303 redirect, or job JSON
    ?api=<action>       → Controller::api() → JSON
    otherwise           → Layout::render() → Controller::body()   (no Solr call)
```

The route table has twelve entries: `overview`, `bots`, `fingerprints`, `networks`,
`sessions`, `performance`, `hosts`, `indexes`, `queries`, `callers`, `usage`, `settings`.

**A view accepts POST only if it implements `JobHost`**; every other view answers `405` with
an `Allow` header. Today that is `Settings` (its forms and its own `source_rescan` job) and the
three Opensolr views (their job endpoints, via `OpensolrView`). The router no longer names a class — it routes on the
capability, so adding an asynchronous operation to a view is one interface away and forgetting
to opt in fails closed rather than silently. An unhandled throw from `post()` is logged and
answered with a generic 500; the message never reaches the browser.

The `api` action name is checked against `/^[a-z_]{1,32}$/` at the front door and
then matched against the view's own allowlist, which returns `Unknown action` for anything
else. An exception message never reaches the browser — it can contain a Solr URL, a
credential fragment or a filesystem path — and goes to the error log instead. The HTML
POST path is held to the same rule, because an unhandled throw there would surface as a
PHP fatal and, with `display_errors` on, render that message straight into the page.

`src/Panel/Gateway.php` is the only route to **Loghound's own Solr**, and the search plane
does not go through it at all — see [Two planes](#two-planes-and-what-talks-to-which) for the
full statement, which is the one a reviewer should read.

**There is no generic Solr passthrough**, on either plane. Every Solr query is built
server-side from constants and allowlists in `src/Panel/Query.php`; the browser sends a view
name, a range token, allowlisted facet selections and free search text — nothing that is query
syntax. Every platform request is built by `src/OpensolrLog.php` from validated structure, not
from Solr parameters a caller handed over: the endpoint passes `q`, `fq`, `sort`, `fl` and
`rows` through untouched, so those are assembled from constants and escaped literals, and
`rows`, `start` and facet limits are clamped to hard ceilings (500 / 20000 / 200).

### The installer gate

`Installer::isNeeded()` runs *before* `requireAuth()`, so whatever makes it return true
hands an unauthenticated visitor the installer. It is therefore deliberately **structural**
and does **not** call `Config::validate()`:

- no configuration file at all → installer;
- a file with no `auth.mode` or no `auth.password_hash` → installer;
- a file with credentials but no `solr.hits_core` / `solr.sessions_core` → installer;
- demo mode → panel, always;
- anything else → panel, and every installer route is dead.

It used to return `validate() !== []`, and `validate()` reports an error for a log
directory it cannot resolve — which is the *normal* state of the panel process wherever the
FPM pool's `open_basedir` excludes the log directory. A correctly installed instance
therefore looked unconfigured forever: the status page disclosed the environment, the
paths, the index names and the `open_basedir` value to anyone who asked, re-minted a live
setup token on a machine where it had already been destroyed, and locked the operator out
of their own dashboard. Configuration problems that are not "setup never finished" belong
in the panel's own warning banner, which `Layout::banners()` already renders from
`validate()` with a link to Settings.

The gate deliberately does not probe Solr either: routing on a live network call would mean
a momentary outage bounced the operator out of their dashboard and re-opened the installer.

---

## Security notes for a reviewer

| Concern | Where it is handled |
|---|---|
| Free text → Solr | Bound as `uq`, referenced by `{!edismax v=$uq}`. `Gateway::search()` prefers `Solr::queryText()`. `Solr::assertSafeQuery()` accepts that one literal and `*:*` and nothing else. No `defType` (it is in `Solr::DENIED_PARAMS` — setting it makes edismax read the braces as text and silently return nothing). Any leading `{!localparam}` block is stripped first. |
| Facet filters from the URL | `Controller::readFilters()` drops any field not in `Query::filterFields()`, re-checks it with `Security::isSafeFieldName()`, caps each value at 256 characters and each field at 20 values; values are quoted by `Query::quote()`. |
| Sort | `Query::sorts()` maps an allowlisted key to a literal sort string. A field plus a direction is never assembled from input. |
| `rows` / `start` | `Security::clampInt` on every request, under `Security::MAX_ROWS` (500) / `MAX_START` (100000), with a lower per-view ceiling. |
| `fl` | Explicit lists (`Query::sessionFl()`, `hitFl()`), never `*`. |
| Ids from the browser | Session id `/^[A-Za-z0-9_-]{8,128}$/`, fingerprint hash `/^[a-f0-9]{8,64}$/i`, job id `/^[a-f0-9]{24}$/` — all checked before they reach a query or the job store. |
| Output escaping | PHP: `Security::esc()` for HTML, `Security::escJs()` for the boot JSON island. Client: DOM built with `textContent`; `core.js` exposes `esc()` for the handful of authored-markup paths and it is never given API data. |
| Chart tooltips | The one place the client builds markup from data, because ECharts renders a formatter's return value as HTML and there is no node to set `textContent` on. **Every interpolated value in every formatter in `charts.js` goes through `esc()`** — series names, bucket names, treemap labels, AS organisation names. The CSP would stop an injected payload executing, but a defence resting entirely on one header is not a defence, and an AS organisation name is chosen by whoever holds the netblock. |
| Referer links | `Security::safeUrl()` runs **server-side**; the client only ever uses the pre-validated `referer_href`. |
| CSP | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. No inline `<script>`, no `onclick=`, no `eval`, no `new Function`, no dynamic `import()`. The theme bootstrap — normally the one place people cheat — is an external synchronous file. `'unsafe-inline'` on **styles only** is the one relaxation: the panel sets chart and bar heights with `style=` attributes, and every value in one is either a constant or an integer through `Security::clampInt()`. |
| ECharts | Vendored at `public/assets/vendor/echarts.min.js` (5.6.0, Apache-2.0, licence alongside it). No CDN; the panel works air-gapped. Loaded as a classic UMD script with `defer`, so it is guaranteed to have executed before the module body runs. |
| World outline | `public/assets/geo/world.json` (Natural Earth 110m Admin 0, **public domain**, provenance and the exact reductions in `public/assets/geo/README.md`). 155 KB, committed rather than fetched from a tile server, for the same air-gapped reason as ECharts. Loaded **only** by the Networks view, by the card that needs it, and a failed load falls back to the plain lon/lat grid rather than an empty card. Every feature carries one property: the country's ISO 3166-1 alpha-2 code. |
| Country names | `src/Geo/Countries.php` is the one table, in PHP, and it reaches the browser once in the boot payload. There is no second copy in a module. A code the table does not carry renders as itself — geolocation data is third-party and incomplete, and a guess would be worse than a code. |
| Icons | `public/assets/js/icons.js`, drawn inline with `createElementNS` from paths in that file. No icon font, no sprite request, no CDN. Neutral category shapes rather than vendor logos, because this repository is MIT and ships publicly. `currentColor` throughout, so there is no colour in the file and both themes follow the text. |
| Index name from the URL or a POST | `Security::isSafeCoreName()` for shape, then — for anything that starts a job — checked against the account's own index list before the job exists. Ownership for a *read* is left to the platform, which answers `ERROR_NOT_CORE_OWNER` and is rendered as a sentence. |
| Free text → the platform | Never. Callers of `src/OpensolrLog.php` hand over a validated structure, not Solr parameters; `q`/`fq`/`sort`/`fl`/`rows` are built from constants and escaped literals, `fq` is length-capped and re-asserted by `assertSafeFq()`, and `sort` is a map lookup. |
| `full_request` in a shape row | Chosen byte for byte by whoever queried the index. Truncated to 600 characters server-side and escaped at every render site. |
| Secrets | Never echoed. The Opensolr API key, the Solr password and the beacon secret are reported as present/absent only, never masked into a value attribute. The API key is added to a request in exactly one place per client (`Opensolr::call()`, `OpensolrLog::buildUrl()`) and every string that can escape those classes passes through their `redact()` first — the platform echoes request parameters back in some error bodies, and one of those parameters is the key. |
| Errors | Exception messages go to the error log; the browser gets a generic message. |
| Caching | `Cache-Control: no-store, private` on the HTML and on every JSON response. The panel renders live operational data behind authentication; caching any of it — in a browser, a proxy or the back/forward cache — is wrong in every case. |

---

## Design system

The panel follows the Opensolr editorial system, so it reads as part of Opensolr rather
than as a separate product. `public/assets/css/panel.css` is the single source of truth and
the only file in the panel where a hex code is written; `charts.js` reads the tokens out of
the stylesheet with `getComputedStyle`, so a chart can never drift out of step with the
interface around it and dark mode needs no second palette.

### The palette

| Token | Light | Role |
|---|---|---|
| `--ink` | `#111111` | Body text |
| `--muted` | `#4a4540` | Secondary text, axis labels |
| `--faint` | `#6b6560` | Tertiary text, elapsed counters |
| `--hairline` | `#d9d4cc` | Every rule and border |
| `--band` | `#fbfaf8` | Sectioning band |
| `--chip` | `#f4f1ec` | Chips, skeletons, progress track |
| `--accent` | `#c05520` | The **single** accent |
| `--accent-ink` | `#9e340f` | The accent when it has to be text or a link |

### The rules, and they are not negotiated per view

1. **2px corners.** Never a pill, never an 8/10/14/50px radius.
2. **No gradients, no box-shadows, no hover-lift.** Flat only. Hover is a colour swap
   between the accent and ink. The single exception is the focus ring, which the system
   specifies as a shadow because there is nowhere else to put it.
3. **One accent, `#c05520`.** No semantic blue/green/amber/purple palette. Error is an
   accent left rule; success is an ink left rule. Never a tinted fill.
4. **Nothing above the H1.** No eyebrow, kicker or badge.
5. **Typography does the work.** Big H1, a grey lead, then hairline-ruled sections numbered
   `01`, `02`, `03`. Hairlines instead of boxes.
6. **Font floor 14px.** Nothing in the stylesheet goes below it.
7. **Hex codes only.** Never a colour name.

Two adaptations are documented rather than silently invented:

- **Dark mode.** The editorial system is a white page; the panel is an operations console
  people stare at at 3am. Dark is a faithful *inversion* of the same system — the same
  single accent, the same hairlines, the same flatness — not a second palette. It is
  selected by `prefers-color-scheme` with a manual `auto → light → dark` override in
  `localStorage`, applied by `theme.js` synchronously in `<head>` so there is no flash of
  the wrong theme.
- **Accent as text.** `#c05520` is 4.1:1 on the light band and fails a contrast audit, so
  `--accent` is the fill and rule colour and `--accent-ink` (`#9e340f`) is used when the
  accent has to be text or a link. Same accent, tone-corrected for its job.

The five population colours are a greyscale ramp with the accent reserved for *evasive*:
humans, unknown and declared crawlers are progressively darker greys, AI crawlers darker
still, and evasive bots are the only coloured band on the chart. That is the whole point
of the Overview series — the eye goes to the one thing that matters.

Responsive to ~400px: tables scroll inside their own container and the page body never
scrolls sideways. The navigation becomes a horizontal bar under ~900px.

---

## Front-end layout

```
public/assets/
  css/panel.css            all design tokens; the only place a hex code is written
  js/theme.js              classic script, sync in <head>, no flash of the wrong theme
  js/core.js               boot payload, DOM building, formatting, fetch, loadCard,
                           jobs, URL helpers, theme, copy buttons
  js/charts.js             ECharts wrapper: reads tokens from CSS, re-renders on theme flip
  js/geo.js                country centroids for the Networks map
  js/icons.js              the mark in front of a value: one closed vocabulary per dimension
  js/responsive.js         the phone drawer, the icon rail, stacked tables, the facet column
  css/mobile.css           the rules that exist only because a screen is narrow
  geo/world.json           Natural Earth 110m outline, public domain (see its README)
  js/app.js                static view map, one entry point (ES module)
  js/views/*.js            one module per view
  js/setup.js              the browser installer's own script (src/Setup/View.php)
  vendor/echarts.min.js    5.6.0, Apache-2.0
```

`app.js` is loaded as `type="module"`; the view map is static and the imports are static on
purpose. A dynamic import built from a URL parameter would be a way to ask the browser to
fetch an arbitrary path, and the whole point of the CSP is that no such mechanism exists
anywhere in the panel.

Every asset URL carries `?v=<filemtime>`, generated in `Layout::render()`, so an upgrade
reaches a browser that cached the old file and there is nothing to remember to bump.

Every chart and every stat block carries a visible `population` caption naming what it
counts. That is a SPEC §10 requirement and it is a `<p>`, not a tooltip, so it survives
being screenshotted. The caption is rendered server-side so it is never missing, and
refined by `setPop()` once the real denominators are known.

Absent stays absent: a metric with no data renders as an em-dash, never as zero. A session
with no beacon shows a log span and three em-dashes, because nothing measured the other
three (SPEC §1). Every formatter that touches a locale passes `en-US` explicitly —
`toLocaleString()` with no locale silently produces a different string on every machine,
which makes screenshots, bug reports and copy-paste unreliable. Timestamps render as
`mm/dd/yyyy hh:mm:ss`, built from `Intl.DateTimeFormat().formatToParts()` in the configured
display timezone; Solr stores UTC.

---

## Where SPEC.md is wrong or silent

These are the places the spec is wrong, incomplete, or in tension with itself. Each has
been re-checked against the code as it stands. None is blocking; all of them cost the
panel something.

### 1. `geo_p` cannot feed the map — still true

SPEC §4.1 gives `geo_p` **indexed, no docValues**, and both shipped configsets implement it
that way (`solr/hits/conf/schema.xml:221`, `solr/sessions/conf/schema.xml:153`).
Solr can search such a field but cannot facet on it or return it, so there is no way to
aggregate coordinates. The Networks map is therefore built from `country_s` counts plotted
at country centroids shipped in `public/assets/js/geo.js`, and is labelled
country-resolution on screen.

**Fix:** add docValues to `geo_p`, or add a `lat_d` / `lon_d` pair. Either makes the map
city-accurate.

### 2. The catchall on `sessions` — RESOLVED in the configset, still absent from the spec

SPEC §4.1 defines `text_all` and its copyFields on the `hits` core only. SPEC §10 says the
session explorer searches "the catchall", but the dashboard queries `sessions`, and §4.2
does not define one there.

The shipped sessions configset closes the gap: `text_all` plus the full `path_txt`,
`ua_txt`, `as_org_txt`, `netname_txt`, `rdns_txt`, `city_txt`, `country_txt` set with their
copyFields (`solr/sessions/conf/schema.xml:353-378`), which is exactly what
`Query::QF_FIELDS` searches. Free-text search on the explorer works.

**Still worth fixing in the spec:** §4.2 should say so, or the next person to build a
sessions configset from the spec alone will ship one where the search box matches nothing.
The note in `Query::QF_FIELDS` still warns about it and should be read as a spec gap, not a
code gap.

### 3. `bot_verdict_s` is not on `hits`, but Performance wants to filter by it — still true

The verdict lives on the session document (§4.2) and appears in the sessions schema only
(`solr/sessions/conf/schema.xml:277`). The Performance view's "Humans only" toggle
needs it per-request. `Performance::scoped()` handles this by counting, over the *unscoped*
domain, how many matched hits carry a verdict at all, and telling the operator plainly when
the filter cannot be applied — rather than drawing an empty chart.

**Fix:** have `bin/loghound-score` copy `bot_verdict_s` (and ideally `bot_class_s`) down
onto the session's hit documents when it closes a session.

### 4. Percentile latency has to query `hits` — still true

SPEC §10 says the dashboard queries `sessions` and `rollup_daily` and "essentially never"
`hits`, with the session drill-down as the one exception. But `dur_us_l` is per-request and
lives on `hits` (§4.1), so p50/p95/p99 by path cannot come from anywhere else.

The Performance view therefore aggregates over `hits` — facets only, `rows=0`, no documents
— which respects the intent (no document fetches) if not the letter. Worth writing into
§10 explicitly.

### 5. `rollup_daily` — defined in the configset, and the panel does not filter it out

SPEC §5 says the scorer writes "the daily rollup doc" and §10 says the dashboard queries
`rollup_daily`, but SPEC §4 defines only `hits` and `sessions` — no third core, no field
list. The configset resolved that by making the rollup a **document type inside the
sessions core**, discriminated by `doc_type_s` (`session` or `rollup_daily`), with its own
`r_*` aggregate fields. `bin/loghound-score` writes one such document per day.

The schema comment states the consequence plainly: *"Every dashboard query must therefore
carry `fq=doc_type_s:session` (or `:rollup_daily`)."* **The panel does not.** No panel query
filters on `doc_type_s`, so a rollup document — which carries `ts_start` and therefore
matches `Query::rangeFq()` — is counted as a session in every total on every view. The
error is one document per day in range: bounded, but it means the five population counts do
not sum to the headline total, and it grows with the range (up to 90 on `90d`).

This is a **known bug, not a documented trade-off**. The fix is a `doc_type_s:session`
clause in `Controller::sessionFqs()`; adding it is out of scope for this document.

Once the panel does filter, the rollup becomes what it was meant to be: the cheap source
for the 30d and 90d ranges, which currently facet over full session documents and get
expensive on a busy site.

### 6. `Solr::ping()` takes a core — cosmetic

The brief for this panel specified `ping(): bool`; the implementation is
`ping(string $core): bool` (`src/Solr.php:204`), which is correct — Solr's ping handler is
per-core. `Gateway::ping()` supports both shapes by reflection and probes the sessions core.

### 7. JSON Facet `domain` is restricted — still true, and it shapes three views

`Solr::sanitiseFacet()` accepts only `domain.excludeTags`, not `domain.filter` — correct,
since a domain filter is a query fragment the client did not build. Anywhere the panel
wanted a scoped facet it uses a nested `query` facet instead, which expresses the same
thing through a `q` the client does validate: `Bots::reasons()` and `Bots::classes()` scope
to bot-like sessions that way, and `Performance::scoped()` wraps its whole facet body in
one. Worth stating in the spec, because `domain.filter` is the obvious first reach.

### 8. `unique()` is approximate and the spec does not say so — still true

`fp_ips_24h_i` and every "distinct IPs" column come from Solr's `unique()`, which is exact
below about 100 and approximate above it. That matters for a number the product presents as
evidence, so the panel says so in the fingerprint view's caption, in the Networks stat hint
and in the Overview visitor caption. §4.2 should say it too.

---

## Known limitations

Stated here rather than left for someone to discover.

- **Rollup documents are counted as sessions.** See item 5 above. Every session total in
  the panel is high by up to one document per day in the selected range.
- **The panel needs JavaScript for its numbers.** The page, its navigation, the range
  picker, the session search form and every Settings form work without it — they are
  server-rendered and post normally — but the cards fill in over `fetch()` and stay in their
  loading state if scripting is off. That is the price of never blocking first paint on
  Solr, and it is a deliberate trade.
- **No per-card cache.** Changing the range or a filter is a full page navigation and every
  card refetches. Nothing is memoised across navigations.
- **The debug footer counts only server-side queries.** `Gateway::queryLog()` is per
  request, and the page render now issues none, so the footer's query count is empty on a
  normal page load and reflects a single API call when you look at one. It is not a total
  for the page.
- **Job state is per session.** Signing in as a different user, or losing the session
  cookie, makes a running job invisible rather than transferring it. That is the fail-closed
  choice, and it means a job started in one browser cannot be watched from another.
- **A query-shape scan covers at most 8,000 requests.** Twenty steps of 400. On an index busier
  than that the tables describe a sample of the most recent traffic in the range, and every
  card says how many requests it read out of how many. Distinct shapes are capped at 250, with
  the remainder reported as an overflow count. The slowest-requests table is the exception and
  is exact, because sorting is something the platform can do itself.
- **The Opensolr views have no demo data, deliberately.** Demo mode fabricates web traffic only.
  Inventing somebody's query log, or making a real billed API call from a session showing a
  "these numbers are fake" banner, are both worse than saying so.
- **Bucketed percentiles on Index analytics.** The platform's request-log endpoint strips braces
  and quotes out of any dotted-parameter value, so JSON Facet — and Solr's exact `percentile()`
  — cannot reach it. The QTime distribution is a fixed-width histogram and its percentiles are
  labelled "at most" a bucket edge.
- **`unique()` is approximate above ~100.** See item 8.
- **The map is country resolution.** See item 1.
