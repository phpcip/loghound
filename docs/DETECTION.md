# How Loghound detects bots

- [The three-plane model](#the-three-plane-model)
- [The verdict matrix](#the-verdict-matrix)
- [The fingerprint](#the-fingerprint)
- [The rules](#the-rules)
- [Thresholds and verdicts](#thresholds-and-verdicts)
- [Worked example: a real proxy fleet](#worked-example-a-real-proxy-fleet)
- [Worked example: a real human](#worked-example-a-real-human)
- [Honest crawlers are not the enemy](#honest-crawlers-are-not-the-enemy)
- [Evasion](#evasion)
- [False positives](#false-positives)
- [Tuning](#tuning)

---

## The three-plane model

Detection happens on three independent planes. Each one alone is defeatable, and every
existing tool uses exactly one of them. The power is entirely in **correlating** them.

| Plane | Source | What it sees |
|---|---|---|
| **1. Transport** | the access log line | headers, ASN, rDNS, protocol, status, timing |
| **2. Behaviour** | correlation across log lines | asset ratio, cache behaviour, session shape, inter-request timing, cross-IP fingerprint clusters |
| **3. Execution** | our own JavaScript beacon | does JS run at all, does the engine match what the UA claims, is a human driving |

GoAccess and AWStats see plane 1. Clicky, GA4, Plausible and Matomo-JS see plane 3 — **and
they trust it**: a client that runs their JavaScript is a human, as far as they are
concerned. Nothing widely used correlates the two, which is why headless Chrome on
residential proxies is counted as human traffic essentially everywhere.

A scraper now has to defeat all three at once. Defeating plane 3 without also defeating
plane 2 is exactly what gives it away, and the two are defeated by opposite things:
looking more like a browser makes plane 3 easier and plane 2 harder.

---

## The verdict matrix

The core idea of the product, in four rows:

| Plane 1 (log) | Plane 3 (beacon) | Verdict |
|---|---|---|
| HTML 200 served | no beacon ever arrived | `bot` — non-JS client, certain |
| HTML 200 served | beacon arrived, headless signals positive | `bot` — headless automation, certain |
| HTML 200 served | beacon arrived, zero interaction, single page, left in under 10s | `unknown` — 55 points, and deliberately short of a verdict |
| HTML 200 served | beacon + interaction + plausible timing distribution | `human` |

---

## The fingerprint

`fp_hash_s` is the SHA-1 of a normalised header tuple:

```
user-agent + accept + accept-language + accept-encoding
          + sec-ch-ua + sec-ch-ua-platform
          + sec-fetch-site + sec-fetch-mode + sec-fetch-dest + sec-fetch-user
          + protocol
```

**It deliberately excludes the IP address.** That is the entire point. A rotating-proxy
fleet changes its exit IP on every request and changes nothing else, because the whole
value of the fleet is that it is one automation stack wearing many addresses. Hashing
everything *except* the address is what collapses the fleet back into a single row.

`fp_ips_24h_i` is the number of distinct IPs that shared a fingerprint within ±12 hours —
a 24-hour window, which is where the field name comes from. It is the single strongest
signal in the system.

It is computed in **as few Solr queries as possible, not one per fingerprint**: sessions
are bucketed by the hour they ended, every fingerprint in a bucket shares one window, and
the whole bucket is answered by a single terms facet on `fp_hash_s` with a nested
`unique(ip_s)`, chunked to stay well under `termsFilter`'s cap of 512 values. A batch of
four hundred fingerprints is a handful of queries, not four hundred.

How much it is worth depends directly on how many headers you log. With the recommended
`LogFormat` the tuple has eleven components and is highly discriminating. With plain
`combined` it collapses to user-agent plus protocol, which is far coarser — see
[docs/INSTALL.md](INSTALL.md) for the trade-off, and the worked example below for what it
looks like in practice.

---

## The rules

Weighted, additive, 0–100, capped at 100. **Every point added carries a reason code, and a
verdict with no reasons is a bug** — `bot_score_f` is always accompanied by
`bot_reasons_ss`. `rule_version_i` is bumped on every change to the weights so historical
scores stay traceable and can be recomputed.

Weights are overridable in `scoring.weights`.

### Execution plane — the definitive ones

| Code | Weight | Fires when | Why it is worth that much |
|---|---|---|---|
| `automation_marker` | **100** | `navigator.webdriver === true`, a `cdc_`/`$cdc_asdjflasutopfhvcZLmcfl_` property, `__playwright*`, `__puppeteer*`, `__selenium*`, `__nightmare`, `_phantom`, `callPhantom`, `domAutomationController` | These properties do not exist in a browser a person is using. There is no false positive: a page cannot acquire `navigator.webdriver === true` by accident. It is one rule, and on its own it is a verdict. |
| `beacon_forged` | **90** | The claimed timings are impossible against the HMAC token's issue time — `engaged_ms > visible_ms`, `visible_ms > wall_ms`, or `wall_ms > (now − issued_at + 60s)` — **by more than a 5-second tolerance**. Within that tolerance the number is clamped silently and nothing fires: one-second token resolution plus a heartbeat queued behind a busy main thread produces honest overshoot, and flagging that would be a false accusation. | A client claiming four hours of engagement thirty seconds after being issued a token is lying, and **the lie is the evidence**. The payload is recorded rather than discarded, because something that bothers to forge dwell time is not a browser having a bad day. |
| `headless_renderer` | **90** | WebGL `UNMASKED_RENDERER` matches `SwiftShader`, `llvmpipe`, `Mesa OffScreen` or `Microsoft Basic Render` | Software rasterisers. Real desktops have a GPU. Not quite 100 because a VM, a remote desktop session, or a machine with broken graphics drivers can legitimately land here — hence 90, which still reaches `bot` alone but leaves room for the verdict to be argued with. |
| `ua_claim_failed` | **85** | The engine lacks a feature that shipped in the Chrome major version the UA claims, or has one that shipped *after* it — **with a grace of two majors in each direction**, so a browser mid-upgrade, an enterprise pin or one of Chrome's own UA-reduction quirks never fires it. Chrome-family claims only; iOS browsers are skipped outright, because they are all WebKit in a Chrome-shaped UA. | **A spoofed User-Agent cannot retrofit V8.** Changing the UA string is one line; changing what the JavaScript engine implements is not possible at all. `b.js` carries a table of eight `chrome_version → feature probe` pairs across a wide version span and reports the specific mismatch code. Cheap, and very close to definitive. |

### Transport plane

| Code | Weight | Fires when | Why |
|---|---|---|---|
| `rdns_claim_failed` | **95** | The UA declares Googlebot / Bingbot / etc. and forward-confirmed reverse DNS fails | This is impersonation, not automation. Forward-confirmed rDNS is the mechanism Google and Microsoft themselves document for verifying their crawlers, and failing it while claiming to be one is a deliberate act. |
| `ua_secch_mismatch` | **75** | `Sec-CH-UA` is absent from, or contradicts, a Chrome UA claim | Chrome always sends `Sec-CH-UA` on a secure origin. A "Chrome 152" that does not, or that says something else, has been dressed up. Requires the header to be logged. |
| `platform_mismatch` | **70** | `Sec-CH-UA-Platform` contradicts the OS the UA claims | "Windows NT 10.0" in the UA and `"Linux"` in the client hint is a headless container in a Windows costume. |
| `hosting_asn_browser_ua` | **45** | `as_type_s = hosting` with a consumer-browser UA | People do browse from VPSes, so this is not decisive. But a consumer browser arriving from AWS, Hetzner or DigitalOcean is unusual enough to be worth 45 points stacked with anything else. |
| `tz_mismatch` | **35** | The browser's `Intl` timezone disagrees with the timezone derived from the IP's geolocation | Travellers, VPN users and anyone with a deliberately-set timezone trip this legitimately, so it is low. It is a *stacking* signal: meaningless alone, meaningful next to a fingerprint cluster. |

### Behavioural plane

| Code | Weight | Fires when | Why |
|---|---|---|---|
| `fp_cluster_proxy_fleet` | **80** | `fp_ips_24h_i >= 5` (tunable: `scoring.fp_fleet_min_ips`) **and** `as_type_s != mobile` **and** not a self-declared crawler whose forward-confirmed rDNS passed | **The signal this project is built around.** Five or more distinct IPs, on different networks, presenting a byte-identical header fingerprint within a 24-hour window is not a coincidence — it is one automation stack behind a rotating proxy pool. The `mobile` exclusion exists because carrier-grade NAT genuinely puts thousands of real users behind a handful of addresses. The third guard exists because a verified Googlebot legitimately crawls from a large address pool with one fingerprint; verified crawlers already carry `ua_declared_bot` and must not also be accused of hiding behind proxies. |
| `no_js_on_html` | **70** | An HTML 200 was served, the UA claims a real browser, and no beacon ever arrived — **and the beacon is known to be deployed on this site** | A browser that renders HTML runs JavaScript. The deployment gate is not optional: on a site that has never installed the snippet, *every* session looks like this, and the rule would condemn the entire audience. Weighted 70 rather than 100 for the same reason in miniature — uBlock Origin, NoScript, Brave shields and Lockdown Mode all produce exactly this pattern from a real human. 70 is below the `bot` threshold, so this cannot condemn anyone on its own. |
| `periodic_timing` | **45** | **Four or more inter-request gaps** (so five or more requests), a **median gap of at least 1 second**, and a **coefficient of variation below 0.10** — that is, the spread relative to the median, not an absolute `gap_stddev_ms_l` threshold | Humans are irregular. A client whose inter-request gaps vary by less than 10% of their own median is on a timer. Relative rather than absolute, because a 200 ms rhythm and a 30 s rhythm are equally mechanical; the median floor keeps a burst of asset fetches from looking like a metronome. |
| `no_interaction` | **40** | A beacon arrived, the session ended, and there were zero interaction events of any kind | Not one scroll, mousemove, keypress, click or touch across a whole session. Possible for a human — a page read on a static screen — which is why it is 40 and not 80. |
| `no_304_on_repeat` | **30** | **At least two** assets were re-requested, no conditional request was ever sent, **and this site is known to answer `304` at all** | Browsers cache. A client that re-fetches the same CSS file with a fresh 200 every time has no cache, which means it is not a browser session. Both extra conditions exist to avoid blaming the client for the server's behaviour: a site that never returns `304` gives every visitor this pattern, and a single re-fetch is noise. |
| `no_assets` | **25** | HTML was fetched and zero sub-resources followed | The classic `curl`/`requests` signature. Only 25, because a 304-heavy warm cache, a text-only browser or a prefetch can all look like this. |
| `single_page_10s` | **15** | One page, 10 seconds or less | Weak alone and it is *supposed* to be weak — plenty of humans bounce. It exists to push a session that has already accumulated other signals over a threshold. |

### Declared crawlers

| Code | Weight | Fires when |
|---|---|---|
| `ua_declared_bot` | **100** | The UA honestly identifies itself as a crawler |

Verdict `bot`, class `declared_crawler` or `ai_crawler`. **Not a threat** — see below.

---

## Thresholds and verdicts

| `bot_score_f` | `bot_verdict_s` |
|---|---|
| ≥ 80 | `bot` |
| 60–79 | `likely_bot` |
| 40–59 | `unknown` |
| 20–39 | `likely_human` |
| < 20 | `human` |

`bot_class_s` says *what kind*: `headless`, `scripted`, `declared_crawler`, `ai_crawler`,
`monitor`, `spoofed_ua`, `proxy_fleet`, `none`.

`unknown` is a real answer and it is used. A session with 45 points is not "probably a
bot"; it is a session Loghound does not have enough evidence about, and saying so is more
useful than guessing.

---

## Worked example: a real proxy fleet

`tests/fixtures/apache_combined_bot_fleet.log` is captured production traffic from
`opensolr.com`, in plain Apache `combined` format. It is in the repository, so every
number below can be reproduced.

### What is in the file

75 requests, 13 distinct IP addresses, every one in a different `/24`:

```
195.64.119.253   192.171.94.85    104.165.210.40   48.47.31.126
48.47.33.68      192.177.172.117  82.22.90.194     104.164.218.244
45.38.234.214    31.132.55.58     136.22.145.11    64.251.160.100
103.3.32.69
```

**Every single one of the 13 fetches exactly one HTML page**, then leaves. Never two.

### What makes this hard

This is the case that defeats every existing tool, and it is worth being precise about
why. This fleet does *everything right*:

- **It fetches sub-resources.** Images, CSS, JavaScript, the favicon. `no_assets` does not
  fire.
- **It executes JavaScript.** Every one of the 13 IPs requests the site's third-party
  analytics beacon (`/c5b2e40505eb5bcd7?...`) with a full payload — screen resolution
  `1920x1080`, `lang=en-US`, a timezone. That endpoint is only ever reached by code that
  ran in a JS engine. So `no_js_on_html` does not fire either, and — this is the important
  part — **the site's own analytics counted all 13 of these as human visitors.**
- **The User-Agents are ordinary.** `Chrome/147`–`Chrome/152` on Windows 10 and on X11
  Linux. Nothing in any blocklist.
- **The IPs are spread across unrelated networks**, which defeats any per-IP rate limit.
- **One of them even sends a heatmap event and downloads a 10 MB file** — engagement, by
  any conventional measure.

Plane 1 alone: clean. Plane 3 alone: JavaScript ran, therefore human. Every widely-used
analytics product stops here and reports 13 visitors.

### What Loghound sees

**Plane 2, the fingerprint cluster.** Under plain `combined` the fingerprint reduces to
User-Agent plus protocol. Grouping the 13 IPs by it:

| Fingerprint (UA family) | Distinct IPs | `fp_cluster_proxy_fleet`? |
|---|---|---|
| `Windows NT 10.0 … Chrome/147.0.0.0` | **5** | **fires** (≥ 5) |
| `X11; Linux x86_64 … Chrome/150.0.0.0` | 3 | no |
| `Windows NT 10.0 … Chrome/150.0.0.0` | 2 | no |
| `Windows NT 10.0 … Chrome/151.0.0.0` | 1 | no |
| `X11; Linux x86_64 … Chrome/152.0.0.0` | 1 | no |
| `X11; Linux x86_64 … Chrome/148.0.0.0` | 1 | no |

The largest cluster — five IPs in five different `/24`s, byte-identical header
fingerprint — crosses the threshold and `fp_cluster_proxy_fleet` fires at **80 points**,
reaching `bot` / `proxy_fleet` on that signal alone.

**The timestamps make it worse for them.** Those five Chrome/147 requests are not spread
across the day:

```
192.177.172.117   10/Sep/2026:06:50:43
82.22.90.194      10/Sep/2026:06:50:43     <- same second
104.164.218.244   10/Sep/2026:06:50:43     <- same second
45.38.234.214     10/Sep/2026:06:57:47
31.132.55.58      10/Sep/2026:06:57:47     <- same second
```

Three different IPs on three different networks beginning a session in the *same second*
with an identical fingerprint, then two more doing it again seven minutes later. Five
independent humans do not do that.

**And every one of the 13 fetches exactly one page.** `single_page_10s` (15) applies to
each session, and the session shape is identical across all 13 — a fetch, its assets, the
analytics ping, gone.

**Scored:** the Chrome/147 group reaches `bot`, class `proxy_fleet`, with
`bot_reasons_ss = [fp_cluster_proxy_fleet, single_page_10s]`. The eight IPs in the smaller
clusters are **not detectable at all** on plane 1 and 2 alone under `combined`: below the
five-IP floor the only rule that fires on them is `single_page_10s` (15), which scores them
`human`. Not "unknown" — **human**, with the same verdict a real reader gets. That is the
honest outcome, it is the worst case in this whole document, and it is exactly the argument
for logging more headers.

### What the recommended LogFormat would have added

Nothing here proves it — those headers are not in this capture, and we are not going to
invent them. But mechanically:

- `Sec-CH-UA` would be checked against each Chrome major claim. A fleet whose UA rotates
  through 147/148/150/151/152 while its client hints do not follow suit fires
  `ua_secch_mismatch` (75) on every mismatched session, and rotating the UA *is* the
  thing this fleet is doing.
- `Sec-CH-UA-Platform` versus the UA's OS claim would fire `platform_mismatch` (70) on any
  Linux-hosted node presenting a Windows UA — and half this fleet claims Windows while the
  other half claims X11 Linux, from the same operation.
- `Accept`, `Accept-Language` and `Accept-Encoding` would make each fingerprint far more
  specific. That cuts both ways: it can split a cluster that the coarse fingerprint
  merged, and it can merge sessions the coarse fingerprint could not tell apart.

### What the beacon would have added

The fleet already executes JavaScript — it hit a third-party analytics endpoint. So the
useful question is not "does JS run" but "**what is running it**", and that is plane 3's
actual job:

- `navigator.webdriver`, `cdc_`, `__playwright*` → `automation_marker`, 100, done.
- WebGL renderer `SwiftShader` or `llvmpipe`, which is what headless Chrome in a container
  reports → `headless_renderer`, 90.
- Feature probes against the claimed Chrome major → `ua_claim_failed`, 85, and a UA
  rotating across five major versions (147, 148, 150, 151, 152) has five chances to fail
  this. Note the two-major grace: 147 against a real 148 engine would pass, but 147 against
  a 152 engine would not, and the fleet spans exactly that far.
- Zero interaction events across the session → `no_interaction`, 40.

Any one of the first three is a `bot` verdict on its own.

### Reproducing this

```bash
php tests/run.php --filter=fixture
grep -c '' tests/fixtures/apache_combined_bot_fleet.log        # 75 lines
awk '{print $1}' tests/fixtures/apache_combined_bot_fleet.log | sort -u | wc -l   # 13 IPs
```

---

## Worked example: a real human

`tests/fixtures/apache_combined_human.log` is the same site, same format, real sessions.
The contrast is the point.

One visitor (`198.51.100.18`, anonymised) over about three minutes:

```
08:13:49  GET /                                  <- entry, referer google.com
08:13:50  GET /img/opensolr-logo-simple.webp
08:13:50  GET /img/menu-mobile.webp
08:13:50  GET /5743e5a1927f1ec29.js
08:13:50  GET /addons/.../favicon.ico
08:13:50  beacon: pageview
08:13:57  beacon: heatmap  (scroll at y=961)
08:14:21  beacon: ping
08:14:34  GET /img/opensolr-apk-qr-styled.png    <- lazy-loaded, 44s in
08:14:51  beacon: heatmap  (y=8146 — scrolled a long way down)
08:15:29  GET /learn/opensolr-wiki-q-a/137/...   <- second page
08:16:05  GET /learn/billing/149/...             <- third page
08:16:23  GET /pricing                           <- fourth page
```

Everything the fleet lacks:

- **Four pages, not one.** `single_page_10s` cannot fire.
- **Irregular gaps** — 1s, 7s, 24s, 13s, 38s, 36s, 18s. `gap_stddev_ms_l` is large, so
  `periodic_timing` does not fire.
- **Scroll events at increasing depth** (y=961 → 8146 → 10062): someone is reading. The
  beacon reports interactions, so `no_interaction` does not fire.
- **A lazy-loaded image at +44s**, which only happens if content actually scrolled into
  view.
- **One IP, one fingerprint.** `fp_ips_24h_i` is 1, nowhere near the threshold of 5.
- **A referer chain that makes sense**: Google → homepage → wiki → billing → pricing. A
  person following their own question.

Scored: no rule fires. `bot_score_f = 0`, `bot_verdict_s = human`, and
`bot_reasons_ss = [no_bot_signals]`. **The reasons list is never empty** — a session with
nothing against it says so explicitly, so "no signals fired" and "the scorer did not run"
are different states on the document rather than the same absence.

The second fixture session (`198.51.100.186`) is even more clearly human — it fills in a
form, POSTs it, follows a 302, and polls a job status endpoint while waiting. Automation
does not usually wait for its own job to finish.

---

## Honest crawlers are not the enemy

Googlebot, Bingbot, GPTBot, ClaudeBot, PerplexityBot and the rest identify themselves.
They get `bot_verdict_s = bot` — they are bots, and counting them as human traffic is how
analytics dashboards end up lying to you — with `bot_class_s` of `declared_crawler` or
`ai_crawler`.

**The UI presents them separately from evasive traffic, always.** Conflating "Googlebot
indexed 400 pages" with "someone is scraping you from 200 residential IPs" is precisely
what makes existing tools useless for this. They are opposite facts: one is a service you
want, the other is a cost you are paying.

`ai_crawler_b` is set for around thirty named agents — GPTBot, OAI-SearchBot, ChatGPT-User,
ClaudeBot, Claude-Web, Claude-SearchBot, anthropic-ai, PerplexityBot, Perplexity-User,
Google-Extended, Bytespider, Amazonbot, Applebot-Extended, meta-externalagent,
meta-externalfetcher, FacebookBot, CCBot, Diffbot, Omgili, Omgilibot, cohere-ai,
cohere-training-data-crawler, ImagesiftBot, YouBot, Timpibot, Webzio-Extended, AI2Bot,
DuckAssistBot, MistralAI-User and PetalBot — so "how much of my content is being taken for
model training" is one facet away. The authoritative list is the table in
`src/Enrich/Ua.php`; adding a name there is the whole change.

Note that several of these are *user-triggered fetchers* rather than training crawlers —
`ChatGPT-User`, `Perplexity-User`, `Claude-Web`, `MistralAI-User` fetch a page because a
person asked an assistant about it. They are grouped here because operators consistently
want them in the same bucket, but "an AI crawler visited" and "somebody asked an AI about
your page" are not the same event.

An honest crawler that **fails** forward-confirmed rDNS is a different matter entirely:
that is `rdns_claim_failed` at 95, class `spoofed_ua`. Claiming to be Googlebot when you
are not is the single most common form of crawler impersonation.

---

## Evasion

Written for someone who wants to defeat this, because that is the only useful way to
describe a detector's limits.

**What is cheap to defeat**

- `no_assets` — fetch the CSS and images. Costs bandwidth, nothing else.
- `single_page_10s` — fetch two pages and wait. Costs time.
- `tz_mismatch` — set the browser timezone from the exit IP's geolocation. Perhaps twenty
  lines of code.
- `hosting_asn_browser_ua` — use residential proxies. This is already the default for
  anyone serious, and it is what the fixture fleet does.
- `no_js_on_html` — run a real browser engine. Also already the default.

**What is expensive to defeat**

- `automation_marker` — you must patch the browser. Patched Chromium builds that hide
  `navigator.webdriver` and the `cdc_` properties exist and are actively maintained, so
  this is *possible*, but it means building and shipping a custom browser rather than
  installing a library.
- `headless_renderer` — you must give the container a real GPU, or convincingly spoof the
  WebGL renderer string without breaking anything else WebGL reports.
- `ua_claim_failed` — **you must stop lying about your User-Agent.** There is no cheap fix:
  the engine either implements the feature or it does not. You can only pass by making the
  UA honest, which then makes you trivially identifiable by that honest UA.
- `no_interaction` — you must synthesise plausible mouse movement, scroll and timing.
  Doable, and detectably wrong when done badly (straight-line mouse paths, uniform scroll
  velocity), which is what the mousemove-entropy signal looks at.
- **`fp_cluster_proxy_fleet` — you must give every session a genuinely distinct header
  fingerprint.** This is the expensive one, and it is expensive for a structural reason:
  the fingerprint is eleven correlated header values, and they have to be *mutually
  consistent* as well as distinct. Randomising them independently produces impossible
  combinations — a Chrome 152 `Sec-CH-UA` with a Chrome 120 `Accept` — which fires the
  mismatch rules instead. Getting it right means maintaining a table of real, complete,
  self-consistent browser profiles and rotating whole profiles rather than fields.

**The honest summary.** A well-funded operator who runs real (non-headless) browsers on
residential IPs, gives each session a complete and self-consistent fingerprint, and drives
them with human-like input, will be classified as human by Loghound. Everything here
raises the cost of scraping by a large factor. None of it makes scraping impossible, and
any tool claiming otherwise is selling something.

The realistic goal is to make *cheap* scraping visible, and to make expensive scraping
expensive enough that it stops being worth doing to you specifically.

---

## False positives

Every one of these is a real human who may be scored as a bot. Read this before acting on
any single verdict.

**Privacy-conscious visitors. This is the big one.** uBlock Origin, NoScript, Brave
shields, Safari Lockdown Mode, Firefox strict tracking protection and corporate proxies
all block `b.js`. From plane 1 that is indistinguishable from a non-JS client: HTML 200
served, real browser UA, no beacon. `no_js_on_html` is weighted 70 — deliberately below
the 80 threshold — so it cannot condemn on its own, but it will push someone into
`likely_bot` if anything else fires. If a meaningful share of your audience is technical,
expect this and lower the weight.

**Corporate NAT and shared exits.** A large office, a university, a VPN provider or a
mobile carrier can put hundreds of real people behind a few addresses with similar
browser builds. `fp_cluster_proxy_fleet` excludes `as_type_s = mobile` for exactly this
reason — which means an **ASN misclassification turns into a batch of false positives**.
If a whole organisation is showing up as a fleet, check `as_type_s` for their ASN first.

**Accessibility tools.** Screen readers, magnifiers and keyboard-only navigation produce
interaction patterns that do not look like mouse-driven browsing. Low mousemove entropy is
a signal here, and a blind user generates none at all. Treat `no_interaction` with care.

**Old and unusual browsers.** The `ua_claim_failed` probe table assumes Chrome-family
version-to-feature mapping. A forked Chromium, an embedded WebView, a browser that
deliberately freezes its UA, or a genuinely old build can fail a probe honestly. The rule
reports *which* probe failed for exactly this reason — look at the code before believing
the score.

**Traveller and VPN timezones.** `tz_mismatch` fires on anyone whose browser timezone does
not match their exit IP, which describes every VPN user and everybody on a plane. It is
weighted 35 because it is nearly useless alone.

**Prefetch and preconnect.** Browsers and browser extensions speculatively fetch pages the
user never visits. Those look like single-page, no-asset, no-interaction sessions.

**Your own monitoring.** Uptime checks, synthetic monitors and health probes are bots and
will be scored as bots, correctly. Filter them by IP or by UA rather than wondering why
your bot rate is 4% on a site nobody visits.

**How to work with this.** The reason codes are not decoration. Never act on
`bot_score_f` alone — look at `bot_reasons_ss` and ask whether that specific combination
describes a person you would recognise. A session that is `bot` on `automation_marker` is
not arguable. A session that is `likely_bot` on `no_js_on_html` + `tz_mismatch` is a
privacy-conscious VPN user until proven otherwise.

---

## Tuning

Weights live in `scoring.weights` in `config/loghound.php`, keyed by rule code:

```php
'scoring' => [
    // Ships as 1. Bump it yourself when you change a weight by hand.
    'rule_version' => 1,
    'weights' => [
        // A technical audience blocks the beacon far more often than average.
        'no_js_on_html' => 40,
        // We are behind a corporate VPN; everyone's timezone is wrong.
        'tz_mismatch'   => 0,
    ],
    'thresholds' => [
        'bot' => 80, 'likely_bot' => 60, 'unknown' => 40, 'likely_human' => 20,
    ],
    // The five-IP floor for fp_cluster_proxy_fleet. Raise it on a site with a
    // large NATed corporate audience; lower it only if you like false positives.
    'fp_fleet_min_ips' => 5,
],
```

An **unknown rule code in `weights` is a hard error** — `Rules` throws rather than start
with a typo'd key that silently does nothing, so a misspelt override stops the scorer
instead of quietly leaving a rule at its default. A weight is clamped to 0–200, so a
deliberate override can exceed 100 when you want one signal decisive on its own.
`fp_fleet_min_ips` has a floor of 2 and is not in `config/loghound.example.php`; add the
key yourself if you want it.

The Settings page in the panel edits weights and thresholds through a form, but its number
inputs cap at 100 and it does not expose `fp_fleet_min_ips`; anything beyond that has to be
set in the file. Thresholds must descend (`bot > likely_bot > unknown > likely_human`) or
the form refuses the save.

**Bump `rule_version` whenever you change a weight.** It ships as `1`, it is written onto
every session document, and it is what lets you tell which ruleset produced a verdict and
re-score a window under the new one instead of comparing incomparable numbers. Saving
weights through the panel bumps it for you. **Existing documents are not rescored** by
either route.

Setting a weight to `0` disables a rule. The reason code stops being emitted, which is the
intended behaviour: a rule contributing nothing should not appear in the explanation.

**How to tune, in order:**

1. Run for a week without changing anything.
2. Open the Bot forensics view and look at the `bot_reasons_ss` facet. The reason codes
   are ranked by how often they fire.
3. Take the most frequent one and pull twenty sessions that fired it. Read them.
4. If they are humans, lower that weight. If they are bots, leave it alone.
5. Bump `rule_version`. Write down what you changed and why.

**Do not tune towards a bot percentage you expected.** There is no correct number. Sites
in the same industry, of the same size, legitimately differ by an order of magnitude, and
tuning until the number looks reasonable is how you end up with a detector that reports
whatever you already believed.
