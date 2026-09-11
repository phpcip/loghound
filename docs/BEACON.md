# The Loghound beacon

`public/b.js` is a dependency-free script that a site embeds in one line. It ships as
commented source — there is no build step anywhere in this project — which is 33 KB on
disk and **about 12 KB gzipped**. It does two things, and refuses to do anything else:

1. **Measures how long a visitor was actually there.** Not "the page was open" —
   three separate clocks, never conflated.
2. **Acts as Loghound's execution plane**: it reports whether JavaScript ran at
   all, whether the JS engine matches the version the User-Agent claims, and
   whether a human plausibly drove the pointer.

It sets no cookies, reads nothing out of the page, and if the collector is
unreachable the host page is completely unaffected.

---

## 1. Installation

```html
<script src="https://loghound.example.com/b.js?v=1" defer></script>
```

That is the whole installation, and it is the snippet the panel's Settings page
hands you. Put it anywhere — `<head>` or before `</body>`. `defer` never blocks
rendering and starts the clocks at parse time rather than after the last image has
loaded; `async` works too and is marginally earlier, at the cost of a
non-deterministic start point. The collector URL is derived from the script's own
`src` (`.../b.js` → `.../collect.php`), so there is no second URL to keep in sync.

The `?v=` query string is the cache buster: `b.js` is served with a long
`Cache-Control`, so bumping the number makes an upgrade a new URL that visitors
actually fetch. The Settings page fills it in from the file's own modification
time.

Optional attributes:

| Attribute | Default | Meaning |
|---|---|---|
| `data-endpoint` | `<script src>` with `b.js` → `collect.php` | Collector URL, if it is not a sibling of `b.js` |
| `data-hb` | `15000` | Heartbeat interval, ms. Clamped to 2 000–300 000 |
| `data-idle` | `30000` | How long after an interaction a visitor still counts as engaged, ms. Clamped to 1 000–600 000 |

These correspond to `beacon.heartbeat_ms` and `beacon.idle_timeout_ms` in
`config/loghound.php`. The panel's Settings page renders the snippet with your
configured values already filled in.

**Serving `b.js`.** Serve it from the Loghound vhost with a long `Cache-Control`
and a version query string (`b.js?v=3`) so an upgrade actually reaches visitors.
Both shipped vhost examples do that — `max-age=604800, immutable` — and they also
set `Access-Control-Allow-Origin: *` and `Timing-Allow-Origin: *` on it, because
the beacon is embedded on other origins by design.

**Compression is not set by those examples**, deliberately: on both
Debian-family Apache and stock nginx it is a global setting, and overriding it
per vhost surprises people. The 12 KB figure above assumes it is on. Check with
`curl -sI -H 'Accept-Encoding: gzip' https://…/b.js` and look for
`Content-Encoding: gzip`; without it every visitor downloads 33 KB.

**Content-Security-Policy.** If the host site runs a CSP it needs
`script-src https://loghound.example.com` and `connect-src
https://loghound.example.com`. The beacon uses no `eval`, no `new Function`, no
inline handlers and no `innerHTML`, so nothing else has to be relaxed. (This is
also why the UA-claim probes test for *functions* rather than for syntax
features — detecting optional chaining or class fields would require `eval`.)

---

## 2. The three time numbers, and why they differ

This is the reason the project exists, so it is worth being precise.

| Number | Field | Accumulates while… |
|---|---|---|
| **wall** | `wall_ms_l` | the page exists. Nothing else. |
| **visible** | `visible_ms_l` | `document.visibilityState === 'visible'` **and** `document.hasFocus()` |
| **engaged** | `engaged_ms_l` | visible **and** the last interaction was less than `data-idle` (30 s) ago |

A fourth number, `log_span_ms_l`, comes from the access log alone: last request
minus first request.

Worked example. A visitor opens your article in a background tab at 09:00, gets
distracted, comes back at 09:20, reads for four minutes with regular scrolling,
then switches to another window and leaves the tab open until 10:00.

| | |
|---|---|
| `log_span_ms_l` | ~0 — the log saw one request |
| `wall_ms_l` | **60 minutes** — this is what Clicky, GA and Plausible report |
| `visible_ms_l` | **4 minutes** |
| `engaged_ms_l` | **4 minutes** |

The industry number is fifteen times the true one. That gap is not an edge case;
it is what a browser with tabs does all day.

Three implementation details that make these numbers trustworthy:

- **Only `performance.now()` deltas.** Never `Date.now()`. A wall-clock jump — an
  NTP step, a DST change, a user correcting their clock — would otherwise be
  silently added to somebody's reading time.
- **Exact accumulation, not sampling.** Every event that can change the state
  (`visibilitychange`, `blur`, `focus`, and every interaction) closes the current
  time segment *before* the state changes, so a segment is always attributed to
  the state it was really in. Engaged time is computed as the overlap of the
  segment with the 30-second window that follows the last interaction, so the
  boundary is exact rather than rounded to the nearest heartbeat.
- **A page that starts hidden accrues nothing.** Prerendered pages and pages
  opened in a background tab start at zero visible time and stay there until they
  are actually shown.

### Flushing — how we see the last page of a session

Log-based analytics structurally cannot measure the final pageview of a visit:
the visitor leaves and there is no further request to time against. The beacon
sends:

- a **heartbeat** every 15 s, but *only while engaged time is advancing* — an idle
  tab produces one beat, not 240 — so a tab killed by the OS still leaves data up
  to the last beat;
- a final **`navigator.sendBeacon()`** on `visibilitychange → hidden` and on
  `pagehide`. The browser queues that request and delivers it after the document
  is gone.

`unload` is **never** used. It disables the back/forward cache in every modern
browser, which measurably slows the site down for real visitors, and it does not
fire reliably on mobile at all.

**bfcache restores start a new pageview.** When a page comes back from the
back/forward cache, the clocks reset and a fresh pageview id is generated.
Carrying the old clocks over would count time spent frozen in the bfcache as time
on site — exactly the class of lie this beacon exists to stop telling.

---

## 3. Exactly what is collected

One JSON object per POST. Every field, with nothing omitted:

| Key | Meaning |
|---|---|
| `v` | Wire protocol version (currently `1`) |
| `e` | `h` hello, `b` heartbeat, `x` final flush |
| `s` `k` | Session id and HMAC token, both issued by the server |
| `p` `n` | Pageview id (random, per pageview) and beat number |
| `w` `vi` `en` | wall / visible / engaged milliseconds |
| `ic` | Number of interactions counted |
| `im` | Bitmask of *which* interaction types occurred: 1 mousemove, 2 scroll, 4 keydown, 8 click, 16 pointerdown, 32 touchstart, 64 wheel |
| `sp` | Deepest scroll position reached, 0–100 % |
| `a` | Array of signal codes (section 4) |
| `uo` | UA-claim result: `1` matched, `0` contradicted, `-1` not testable |
| `tz` | IANA timezone from `Intl.DateTimeFormat()` |
| `gl` | WebGL `UNMASKED_RENDERER`, or empty |
| `u` | **Path only** of the current URL |
| `pl` | `navigator.platform` / `userAgentData.platform` |
| `mt` | Touch points supported |
| `dp` | `devicePixelRatio` |
| `sw` `sh` | Screen size |
| `aw` `ah` | Available screen size (screen minus taskbar/dock) |
| `ow` `oh` | Browser window outer size |

**What is deliberately NOT collected:** no cookies, no `localStorage`, no canvas
or audio fingerprint, no font enumeration, no battery/gamepad/WebRTC probing, no
page content, no form values, no keystrokes (we count `keydown` events; we never
look at which key), no query string, no hash fragment, no clipboard, no mouse
coordinates in the payload (they are analysed on the client and discarded), and
no third-party requests of any kind.

**Where the query string goes.** It is dropped before the payload is built. Real
sites routinely carry session tokens, email addresses and password-reset codes in
query strings, and an analytics tool that collects them has created a breach that
its customer did not agree to.

**What the server ignores.** The collector reads the IP, User-Agent, host and
referer **off the connection**, never from the payload. A client that sends them
is wasting its bytes.

**IP handling** follows `privacy.ip_mode`: `full`, `truncate` (v4 /24, v6 /48), or
`hash` (keyed, rotated daily). See `docs/PRIVACY.md`.

---

## 4. The signal codes

Codes land in `automation_ss` on the session document and are facetted in the
panel. **A code is an observation, not a verdict.** `Score/Rules.php` correlates
them with the transport and behaviour planes and owns `bot_score_f`; the weight
column below is only this plane's contribution to `client_score_f`.

### Definitive automation markers — a driver announced itself

| Code | Weight | What it means |
|---|---|---|
| `automation_webdriver` | 100 | `navigator.webdriver === true` |
| `automation_cdc` | 100 | chromedriver's `cdc_…` / `$cdc_…` property on window or document |
| `automation_playwright` | 100 | `__playwright*` / `__pw_*` binding |
| `automation_puppeteer` | 100 | `__puppeteer*` binding |
| `automation_selenium` | 100 | `__selenium*`, `__webdriver*`, `__driver_*`, `__fxdriver*` |
| `automation_nightmare` | 100 | `__nightmare` |
| `automation_phantom` | 100 | `_phantom`, `callPhantom`, `__phantomas` |
| `automation_domauto` | 100 | `domAutomation`, `domAutomationController` |

Presence is certainty. **Absence means nothing at all** — hiding these is a
one-line patch that every serious scraper applies. They are cheap, they catch the
lazy majority, and they are the reason the *other* planes exist.

### Headless-browser tells

| Code | Weight | What it means | Why the weight is what it is |
|---|---|---|---|
| `headless_renderer` | 90 | WebGL renderer is SwiftShader, llvmpipe, Mesa OffScreen or Microsoft Basic Render | A consumer desktop browser with no GPU is a container |
| `headless_notif_contradiction` | 45 | `Notification.permission === 'denied'` while the Permissions API says `prompt` | No real profile is in both states at once |
| `headless_no_window_chrome` | 40 | No `window.chrome` under a Chrome UA | Strong, but trivially faked |
| `headless_zero_outer` | 40 | `outerWidth` or `outerHeight` is 0 | Also legitimately 0 in some cross-origin iframes |
| `headless_no_languages` | 25 | `navigator.languages` missing or empty | Real browsers always populate it |
| `headless_no_plugins` | 20 | Zero plugins under a desktop Chrome UA | Modern Chrome exposes five PDF entries |
| `headless_no_concurrency` | 15 | `hardwareConcurrency` is 0 or absent under a Chrome UA | Brave and Safari clamp this value |
| `headless_screen_eq_avail` | 10 | `availWidth/Height` exactly equal `width/height` on a desktop UA | Also true of Linux kiosks and full-screen presentations |
| `headless_no_chrome_runtime` | 10 | No `window.chrome.runtime` under a Chrome UA | Its presence on ordinary pages has changed across Chrome releases |

Only the **strong** four (`headless_renderer`, `headless_no_window_chrome`,
`headless_notif_contradiction`, `headless_zero_outer`) plus any `automation_*`
code set `headless_b`. The weak ones each have a real population of genuine humans
behind them, and a boolean that is wrong for real visitors is worse than no
boolean.

### UA-claim verification

| Code | Weight | What it means |
|---|---|---|
| `ua_older_engine` | 85 | The UA claims a Chrome version whose features the engine does not have |
| `ua_newer_engine` | 85 | The engine has features that shipped *after* the claimed version |
| `ua_probe_<major>` | 0 | Which probe caught it — diagnostic only |

A scraper can set any User-Agent string it likes, but it cannot retrofit V8.
`uo` / `ua_claim_ok_b` carries the result. See section 6 for how to extend the
probe table.

### Consistency cross-checks (evaluated **on the server**)

| Code | Weight | What it means |
|---|---|---|
| `platform_mismatch` | 35 | `navigator.platform` contradicts the OS in the UA |
| `touch_missing_mobile` | 30 | A phone or tablet UA on a device with no touch support |
| `screen_outer_impossible` | 25 | The window is larger than the screen it sits on |
| `dpr_odd` | 10 | `devicePixelRatio` is absent, zero or non-finite |
| `tz_mismatch` | — | Browser timezone ≠ the timezone derived from the IP (also sets `tz_match_b`) |
| `tz_unknown` | 5 | `Intl` gave no timezone |

The beacon reports the raw measurements and **the server does the comparing.**
Three reasons, and byte count is the least of them:

1. The server holds the authoritative User-Agent, read off the connection. Half of
   these checks compare something *against the UA*, and the UA the client hands us
   is precisely the thing we do not trust.
2. A client cannot suppress a comparison it never performs.
3. Thresholds can be tuned server-side without asking every customer to re-deploy
   a script tag.

Two conservatism rules apply here:

- The reverse of `touch_missing_mobile` is deliberately not checked: a desktop UA
  *with* touch would flag every touchscreen laptop.
- The display checks (`headless_zero_outer`, `screen_outer_impossible`,
  `headless_screen_eq_avail`, `dpr_odd`) only run when the payload actually
  reported a screen size. A truncated write, an older client or a browser that
  exposed nothing sends zeroes, and "no data" must never be read as "a window
  with no size" — which would set `headless_b` on a genuine visitor.

### Human-presence evidence

| Code | Weight | What it means |
|---|---|---|
| `human_mouse_natural` | **−25** | Sampled pointer positions vary in a way a straight line cannot explain |
| `mouse_linear` | 40 | ≥90 % of sampled triples are *exactly* collinear — what an interpolating driver produces and a hand never does |
| `mouse_static` | 25 | The pointer fired move events but never changed pixel |
| `no_interaction` | 20 | Zero interactions across the whole session (added server-side, since only the server knows the session ended) |
| `no_scroll_tall_page` | 10 | A page 1.5× taller than the viewport that was never scrolled |

Mouse positions are sampled at most once per second, up to 16 points, and the
classifier stays silent below 6 samples: somebody who nudged the mouse twice is
not evidence of anything. The coordinates never leave the browser.

### The lie itself

| Code | Weight | What it means |
|---|---|---|
| `beacon_forged` | 90 | The payload claimed time that provably did not exist |

---

## 5. The wire protocol

### The hello exchange

The beacon's first call carries no session id and no token, because it has
neither. That branch **mints; it does not authorise**, and it is protected by the
rate limiter alone — which is why the limiter runs before it. The collector
returns:

```
HTTP/1.1 204 No Content
X-LH-S: <session id>
X-LH-T: <issued_at>.<hmac>
Access-Control-Expose-Headers: X-LH-S, X-LH-T
```

Every later call presents both, and a missing, malformed, forged, expired (>12 h)
or future-dated token is dropped.

**The id it mints is always a fresh random value, never the id of the session
already open for this client.** That is a deliberate change from an earlier design
in which the collector looked the real session up by `client_key`
(`ip_net + sha1(ua)`) and returned it. Returning the real id is a serious hole:
this endpoint answers with `Access-Control-Allow-Origin: *`, so any page on the
internet can make a CORS-simple POST from a visitor's browser — their IP, their
User-Agent, therefore their `client_key` — read `X-LH-S` and `X-LH-T` off the
response, and then submit whatever it likes about that visitor's *real* session.
In a bot-detection product the obvious abuse is to report a human as headless
automation.

A provisional id costs nothing, because the staging row carries `client_key` as
well as the session id and `State::beaconsFor()` matches on both:
`loghound-score` re-attaches the staged rows to the real session once the log line
has been tailed. **No open session is ever created here either** — a public
endpoint must not be able to insert rows into `sessions_open`. The provisional id
exists only to bind the HMAC token to something.

> **A note on where SPEC.md is silent.** §6.3 requires the collector to answer
> `204` with no body, always, so that it can never be used as an oracle for
> whether a token or a session id is valid. §6.3 also requires the server to issue
> the token. A bodiless response leaves exactly one channel for that, so the token
> travels in response headers and the first call uses `fetch()` (which can read
> them) rather than `sendBeacon()` (which cannot). Every subsequent call uses
> `sendBeacon`.

The request is a CORS *simple* request — `POST` with `Content-Type:
text/plain;charset=UTF-8` — so there is no preflight and no OPTIONS round trip.
It is sent with `credentials: 'omit'`, which matters most when Loghound is hosted
on the same domain as the site being measured: the browser's default would
otherwise attach that site's cookies to every beacon.

### Anti-forgery

The token is `HMAC(secret, session_id \0 origin | issued_at)` with `issued_at`
carried in the clear and signed. That gives the collector a server-attested "this
session began no earlier than X" without keeping per-beacon state, and it is what
makes the timing check possible:

```
ceiling = (now - issued_at + 60s slack)
wall_ms  must be <= ceiling
visible_ms must be <= wall_ms
engaged_ms must be <= visible_ms
```

Overshoot up to 5 seconds is clamped **silently** — one-second token resolution
plus a heartbeat queued behind a busy main thread produces honest overshoot, and
flagging that would be a false accusation. Beyond it, the numbers are clamped and
`beacon_forged` is recorded.

**The record is kept, not discarded.** Dropping a forged payload would leave the
session looking exactly like every other session with no beacon — that is,
indistinguishable from a visitor on a slow connection. The lie is far more
informative than the absence: nothing that is not deliberately inflating its dwell
time ever does this.

### The token is bound to an Origin

`Origin` is part of the signed material, and `verifyToken()` recomputes with the
`Origin` of the request presenting the token. A token minted for
`https://example.com` is refused when presented from `https://attacker.example`,
and the refusal is indistinguishable from any other rejection: same `204`, no
staging row, no diagnostics.

This is what closes the hole `Access-Control-Allow-Origin: *` would otherwise
leave open. The endpoint has to be reachable from origins we do not know in
advance — that is the whole point of a beacon on customer sites — so the allow-list
cannot do the work, and binding the credential to the origin it was issued to does
it instead.

The value is lower-cased and capped at 255 bytes so a header differing only in case
or padded to absurd length cannot mint two tokens that ought to be one. An absent
`Origin` — a same-origin request, or a client that sends none — normalises to the
empty string, which is a value like any other: consistent between mint and verify,
and therefore still bound.

### Rate limiting

Token buckets on two keys, default 120/min each (`beacon.rate_per_min`):

- per IP — keyed by a **hash** of the address, never the address itself, so the
  rate-limit table cannot quietly undo the configured privacy mode;
- per session id — so one session cannot flood on its own, and a fleet behind one
  NAT cannot exhaust a shared IP budget by accident.

### The collector never touches Solr

Writes go to the SQLite `beacon_staging` table and nowhere else; `loghound-score`
merges them into the session document out of band. Two reasons:

1. **Cost.** A Solr write per beacon would put an indexing round trip in front of
   every visitor on every page, several times per pageview.
2. **Credentials.** The Solr/Opensolr credentials never enter the request path of
   the most exposed file in the project.

### How heartbeats are folded

Each POST carries *cumulative* counters for its pageview, not deltas. The merge is
therefore: **maximum per pageview, then sum across pageviews.** Summing the rows
directly would multiply a ten-minute pageview by its number of heartbeats.

**When no beacon arrived, the timing fields are ABSENT from the session document —
never zero.** A zero is a value: it would enter every average, median and
percentile as a genuine "0 seconds engaged" observation, and ten thousand
beacon-less bot sessions would drag a site's reported engagement to nearly
nothing. Confidently wrong is worse than missing. Absent means an aggregate simply
covers a smaller population, which every chart in the panel is required to state.

---

## 6. Extending the UA-claim probe table

The table lives near the top of section 4.3 in `b.js`:

```js
var UA_PROBES = [
    63,  'Promise.prototype.finally',
    69,  'Array.prototype.flat',
    73,  'Object.fromEntries',
    85,  'String.prototype.replaceAll',
    93,  'Object.hasOwn',
    98,  'structuredClone',
    110, 'Array.prototype.toSorted',
    122, 'Set.prototype.union'
];
```

Each pair is a Chrome major version and a dotted path to a function that first
shipped natively in it. Given a UA claiming Chrome *N*:

- every entry with `major <= N - 2` **must** be present, or the engine is older
  than claimed;
- every entry with `major >= N + 2` **must** be absent, or the engine is newer
  than claimed.

The grace of 2 majors means a browser mid-upgrade, an enterprise pin, or one of
Chrome's own UA-reduction quirks is never flagged.

**To add a row as Chrome advances**, roughly every 10 releases, pick a feature
that is:

1. shipped in a *known* Chrome version — look it up on caniuse or in the V8
   release notes, never guess; a wrong version number here manufactures false
   accusations against real people;
2. a **function** reachable by a dotted path from `window` (the probe resolves the
   path and checks `Function.prototype.toString` for `[native code]`);
3. not commonly polyfilled.

**Never remove old rows** — they are what catches ancient engines.

Two guards you must not remove either:

- **The polyfill guard.** `has()` requires the function to report `[native code]`.
  A site loading core-js would otherwise make an old engine look new and get its
  own visitors flagged.
- **The iOS exclusion.** Chrome, Edge, Firefox and Opera on iOS are all WebKit
  wearing a Chrome-shaped UA. Their feature set has nothing to do with the Chrome
  version in the string, so they are skipped outright. Skipping them costs us
  nothing; flagging them would be a pure false positive on millions of real
  iPhones.

---

## 7. What this beacon canNOT detect

Honest limits. If a competing product claims otherwise, it is guessing.

**A well-built headless browser.** Every marker in section 4 can be patched out —
`puppeteer-extra-plugin-stealth`, `undetected-chromedriver`, Playwright with an
init script, or simply a patched Chromium build — and a scraper that runs a real
GPU-backed Chrome on a residential IP with a stealth plugin will produce a payload
indistinguishable from a human's on this plane alone. **This is expected, and it is
why the plane exists in a correlation and not on its own.** Such a client still has
to survive the transport plane (ASN, rDNS, header order, TLS) and the behaviour
plane (asset ratio, cache behaviour, inter-request timing, and above all
`fp_ips_24h_i` — the same fingerprint appearing across many IPs). Defeating all
three at once is the actual bar.

**Anything, when the beacon does not run.** An ad blocker, a strict CSP, a
corporate proxy, JS disabled, a network failure, a `NoScript` install — all of
them produce "no beacon" for a genuine human. Loghound treats no-beacon-on-HTML as
a *70-point* signal rather than a verdict, precisely because a meaningful share of
real people look exactly like that. If your audience is technical, expect a
noticeably larger `unknown` bucket and read the transport plane instead.

**Which human.** There is no cookie and no cross-site identifier. `visitor_s` is a
coarse derived hash and is intended to be coarse.

**Time in a non-focused but visible window.** By design, `visible_ms` requires
focus. A visitor reading your page in a small window while typing in another
application accrues no visible time. We consider that the right trade — "attention"
without focus is not measurable — but it means `visible_ms` is a *lower* bound.

**Interaction inside cross-origin iframes.** Events inside a third-party iframe do
not reach us, so a page whose only interactive element is an embedded widget can
look interaction-free.

**Sub-second precision on `wall_ms` after a bfcache restore**, and nothing at all
between `pagehide` and the restore. The clocks restart deliberately.

**A visitor who leaves in the first few hundred milliseconds.** The hello POST is
fired immediately, but a browser that tears the page down before the request
leaves the socket produces nothing. Those visits appear as no-beacon.

**Anything about a request that never reached your webserver** — served from a
CDN edge, from the browser cache, or from a service worker. Loghound sees the
origin's log; the beacon partially compensates by firing on cache hits too, which
is one of the few places where the two planes usefully disagree.

**Non-Chromium engine version claims.** The UA-claim check only tests Chrome-family
claims. A Firefox or Safari UA yields `ua_claim_ok_b` absent, not `false`.

**Every "unknown" is recorded as unknown.** Throughout this file and throughout
`b.js`, a probe whose API is missing, blocked or throwing records nothing at all.
A false "this human is a bot" is far worse than a missed bot, and every ambiguous
case in this codebase is resolved in that direction.
