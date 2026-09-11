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
<script src="https://loghound.example.com/b.js?v=1757000000" defer></script>
```

That is the whole installation, and it is the snippet the panel's Settings page
hands you. Put it in `<head>`. `defer` never blocks
rendering and starts the clocks at parse time rather than after the last image has
loaded; `async` works too and is marginally earlier, at the cost of a
non-deterministic start point. The collector URL is derived from the script's own
`src` (`.../b.js` → `.../collect.php`), so there is no second URL to keep in sync.

**The `?v=` is the cache buster, and it is not a number you choose.** `b.js` is
served `max-age=604800, immutable`, so a browser that already has the file will not
ask for it again for a week whatever changes on the server — the only thing that
makes a beacon fix reach a returning visitor is a different URL. Loghound fills the
slot in from the beacon file's own modification time, everywhere it prints a
snippet: the panel, the installer's last screen, `install.sh`'s closing report and
`bin/loghound-setup`. Copy the snippet you are given rather than the one above, and
do not pin it to a number of your own.

Every surface builds that tag from one place, `src/Beacon/Doc.php`, which is also
what this section is rendered from. To read the whole reference on a machine with
no browser open:

```
bin/loghound-setup --beacon-doc
```

### 1.1 The complete option reference

**Every option `b.js` reads.** Nine of them: six attributes on the script tag, two
globals, one function. Nothing else is looked at.

The **Stored** column is the one to read first. An option can be set perfectly and
still have its value discarded server-side, because storing a *declaration* is a
policy decision the operator makes and storing a *measurement* is not. The panel's
Settings → Beacon card renders this same table with that column answered from
**your** configuration, and so does `--beacon-doc`; those are the only two places
it can be answered concretely.

| Option | Kind | What it does | Default | Accepted | In code | Stored |
|---|---|---|---|---|---|---|
| `data-endpoint` | attribute | Collector URL, when it is not a sibling of `b.js`. | the script’s own `src` with `b.js` → `collect.php` | Any URL. Set it only if you serve the script from a CDN or a different path. | `data-endpoint="https://loghound.example.com/collect.php"` | always — the script uses it itself |
| `data-hb` | attribute | Heartbeat interval, in milliseconds. A beat is sent only when engaged time actually advanced, so an idle tab produces one, not hundreds. | 15000 | Integer, clamped to 2 000–300 000. Anything else is ignored and the default is used. | `data-hb="30000"` | always — the script uses it itself |
| `data-idle` | attribute | How long after a real interaction a visitor still counts as engaged, in milliseconds. This is the definition of the **Engaged** clock. | 30000 | Integer, clamped to 1 000–600 000. | `data-idle="60000"` | always — the script uses it itself |
| `data-ident` | attribute | An identity **your site** attaches to the session — an email address, a customer number, whatever you call the person. Never guessed. | absent, and absent is not empty | Free text, truncated to 128 bytes. Control characters stripped, invalid UTF-8 repaired. | `data-ident="<?= htmlspecialchars($user->email, ENT_QUOTES) ?>"` | **`beacon.store_identity`** |
| `data-signed-in` | attribute | Whether the visitor was signed in. Splits every number in the panel into signed-in and anonymous. | absent — which means **not reported**, never “no”. An attribute that is present but empty is an answer, and the answer is **no** | `1`/`0` or `true`/`false`. An empty attribute — the usual shape of a template that renders nothing for a visitor who is not signed in — is read as **false**, so `data-signed-in="{{ user.id }}"` works unchanged for both. Any other value is read as not reported. | `data-signed-in="<?= $user->isSignedIn() ? '1' : '0' ?>"` | **`beacon.store_signed_in`** |
| `data-params` | attribute | URL query parameter **names** whose values are kept as search terms. Nothing else in the query string is read. | absent — no parameter is collected | Comma separated. At most 8 names, each at most 40 characters of `a-z 0-9 _ - . [ ]`. Each value is capped at 96 characters and dropped, not truncated, if longer. | `data-params="q,category,sort"` | **`beacon.query_params`** |
| `window.LoghoundIdent` | global | The same value as `data-ident`, for a template where adding an attribute to the tag is awkward but setting a variable above it is not. | unset | A string. Must be set **before** b.js executes — with `defer` that means anywhere in the document. The attribute wins if both are present. | `<script>window.LoghoundIdent = "ada@example.com";</script>` | **`beacon.store_identity`** |
| `window.LoghoundSignedIn` | global | The same value as `data-signed-in`. | unset — not reported | A real boolean, or the same strings the attribute accepts. Must be set before b.js executes. | `<script>window.LoghoundSignedIn = true;</script>` | **`beacon.store_signed_in`** |
| `window.loghound.identify(ident, signedIn)` | function | Attach either value **after** the page has loaded — a single-page application that signs somebody in without a navigation, which no attribute can express. | never called | Both arguments optional and independent. **Makes no request of its own:** the values ride the heartbeat that is already scheduled. Safe to call with anything — it cannot throw into your code. | `window.loghound.identify(user.email, true);` | **`beacon.store_identity`** / **`beacon.store_signed_in`** |

### What has to be in the page before b.js runs

The six `data-` attributes are read off the script tag itself, so where they sit in the document cannot be wrong. The two globals can be: `window.LoghoundIdent` and `window.LoghoundSignedIn` are read **once**, at the moment b.js executes, so a script that sets them after that has set them for nothing — the beacon has already sent its first payload and neither value is in it. With `defer` on the tag, b.js runs only after the document is parsed, which means anywhere in the page is early enough.

For a value that genuinely is not known until later — a single-page application that signs somebody in without a navigation — the globals are the wrong instrument and `window.loghound.identify(ident, signedIn)` is the right one. It may be called at any point after b.js has run, and it sends nothing by itself: the values ride the next heartbeat.

`beacon.store_identity` is `false` in a new installation and `beacon.query_params`
is empty, so a snippet carrying `data-ident` or `data-params` has those values
dropped by the collector until you change that — the tag loads, the collector
answers `204`, and nothing appears in the panel. `beacon.store_signed_in` is on.
Section 3.1 covers the two identity switches and section 3.2 the parameter list.

`data-hb` and `data-idle` mirror `beacon.heartbeat_ms` and `beacon.idle_timeout_ms`
in `config/loghound.php`. Those two settings govern what the **server** accepts;
the attributes govern what the page does, and the snippet the Settings page prints
leaves both out, so a page that says nothing gets the defaults in the table above.

### 1.2 Attaching an identity — three routes, three situations

These are not alternatives to choose on taste. Each is the only one that works in
its situation.

**1. Attributes on the script tag — when your server knows who it is at render
time.** The normal case. The template that renders the page renders the tag, in the
same response: no second request, no extra script, no ordering problem.

```html
<script src="https://loghound.example.com/b.js?v=1757000000"
        data-ident="ada@example.com" data-signed-in="1" defer></script>
```

You would not write the address literally, of course — it comes out of whatever
object your framework already has. **WordPress:**

```php
// wp-content/mu-plugins/loghound.php — a must-use plugin, so it survives a theme change.
add_action('wp_head', static function (): void {
    $attrs = ' data-signed-in="0"';
    if (is_user_logged_in()) {
        $attrs = ' data-ident="' . esc_attr(wp_get_current_user()->user_email) . '"'
            . ' data-signed-in="1"';
    }
    echo '<script src="https://loghound.example.com/b.js?v=1757000000"' . $attrs . ' defer></script>' . "\n";
}, 99);
```

A signed-out visitor gets `data-signed-in="0"` and **no** `data-ident` at all —
which is right: they are anonymous, and that is a different statement from "we were
not told". `esc_attr()` is what stops an address containing a quote from breaking
the tag.

> **If you run a page cache** (WP Rocket, W3 Total Cache, LiteSpeed, Cloudflare
> APO), the rendered tag is cached with the page, so the first visitor's identity
> would be served to everyone else. Exclude logged-in users from the cache — every
> one of those plugins does so by default — or use route 3 below from an uncached
> request.

**Drupal:**

```php
# your_theme.theme  (or a small custom module)
function your_theme_page_attachments(array &$attachments): void {
  $account = \Drupal::currentUser();

  $tag = [
    '#type' => 'html_tag',
    '#tag' => 'script',
    '#attributes' => [
      'src' => 'https://loghound.example.com/b.js?v=1757000000',
      'defer' => TRUE,
      'data-signed-in' => $account->isAuthenticated() ? '1' : '0',
    ],
  ];
  if ($account->isAuthenticated()) {
    $tag['#attributes']['data-ident'] = $account->getEmail();
  }

  $attachments['#attached']['html_head'][] = [$tag, 'loghound'];
  $attachments['#cache']['contexts'][] = 'user';
}
```

`html_head` rather than a library, because a library is declared once in YAML and
cannot carry a value that changes per request. **The `user` cache context is not
optional**: without it Drupal's render cache serves the first authenticated
visitor's address to every other one. Use `getAccountName()` instead of
`getEmail()` if a username is the identifier you want. Run `drush cr` afterwards.

**2. Globals — when adding an attribute to the tag is awkward but setting a
variable above it is not.** A tag manager, a templating system that owns the
`<script>` element, a CMS block you cannot edit. They must be set *before* `b.js`
executes, which with `defer` means anywhere in the document.

```html
<script>window.LoghoundIdent = "ada@example.com"; window.LoghoundSignedIn = true;</script>
<script src="https://loghound.example.com/b.js?v=1757000000" defer></script>
```

In **Google Tag Manager**, that is a Custom HTML tag with Data Layer variables,
because a tag manager runs in the browser and cannot know who is signed in — the
value has to reach it from your own page:

```html
<script>
  window.LoghoundIdent = "{{Loghound Ident}}";
  window.LoghoundSignedIn = "{{Loghound Signed In}}";
</script>
<script src="https://loghound.example.com/b.js?v=1757000000" defer></script>
```

**3. `window.loghound.identify()` — when the identity arrives after the page
loaded.** A single-page application that signs somebody in without a navigation,
which no attribute can express.

```js
window.loghound.identify('ada@example.com', true);
```

It **makes no request of its own**: the values ride the heartbeat that is already
scheduled, so attaching an identity costs your site nothing extra. Both arguments
are optional and independent — pass only an identity, only a signed-in state, or
both.

**Loghound never guesses either value.** No cookie is read, no form is scraped, no
meta tag is looked for, no `window` variable is hunted through. If your site does
not say, the field does not exist on the session. And a site that says nothing is
**not reported**, not anonymous: `signed_in_b` is written only when a page actually
said one or the other, so a site that has not adopted the attribute cannot be read
as a site full of anonymous visitors.

**Serving `b.js`.** Serve it from the Loghound vhost with a long `Cache-Control`
and a version query string (`b.js?v=<mtime>`) so an upgrade actually reaches visitors.
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
Section 3.3 says what goes wrong when `connect-src` is missed, which is the
commonest way a beacon install silently reports nothing.

**The measured site does not have to be on this machine.** The snippet above is
the whole installation on a host with no Loghound and no shared access log — a
search page, a marketing site, anything on another server. The page reports its
own hostname and the session is created from the beacon alone, provided that
hostname is on `beacon.allowed_hosts`. That is **section 3.3**, and it includes an
honest account of what the allowlist does and does not protect against.

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
| `xi` | Identity your site declared, if any. Absent otherwise. Section 3.1 |
| `xs` | `1` signed in, `0` anonymous. **Absent** when your site said nothing. Section 3.1 |
| `hn` | `location.hostname` — the **host only**, never the URL. Section 3.3 |
| `qp` | Values of the query parameters named in `data-params`, as a name → value map. **Absent** when none was named or none was present. Section 3.2 |

**What is deliberately NOT collected:** no cookies, no `localStorage`, no canvas
or audio fingerprint, no font enumeration, no battery/gamepad/WebRTC probing, no
page content, no form values, no keystrokes (we count `keydown` events; we never
look at which key), no hash fragment, no clipboard, no mouse coordinates in the
payload (they are analysed on the client and discarded), and no third-party
requests of any kind.

**The query string is not collected either, with one narrow exception you switch
on yourself.** `qp` carries the values of parameters you have *named*, and the
rest of the URL is never read. That is section 3.2, and it is the one place
Loghound stores something a person typed.

`xi`, `xs` and `qp` are the only fields in the table above that Loghound does not
measure. **Nothing guesses them.** No cookie is read, no form is scraped, no meta
tag is looked for, no `window` variable is hunted through. They exist only when
your own template declares them, and sections 3.1 and 3.2 say what happens to
them.

`hn` is the one field with no server-side source. The collector reads the IP,
User-Agent and referer off the connection and ignores whatever the payload claims
about them — but the page is frequently on a *different machine* from the
collector, so `HTTP_HOST` there names the Loghound host and says nothing about
the measured site. Section 3.3 is about how that value is made trustworthy enough
to act on, and about exactly how far that goes.

---

## 3.1 Identity your site supplies

Two facts only your site can know, and Loghound will not invent either:

- **an identity string** — whatever you call the person: an email address, a
  customer number, an account id;
- **whether they were signed in** — a boolean.

**They are independent, and that is the point.** You may pass an identity for a
visitor who is not authenticated. You may want "this was a signed-in session"
recorded without handing over who it was. Neither implies the other and neither
is derived from the other.

### How to send them

The recommended channel is two attributes on the tag you already have. Your
template renders them in the same response as the page, so there is **no second
request**, no extra script and no ordering problem:

```html
<script src="https://loghound.example.com/b.js?v=1757000000"
        data-ident="ada@example.com" data-signed-in="1" defer></script>
```

Two globals are accepted as an exact equivalent, for templating systems where
adding an attribute to a third-party tag is awkward but setting a variable above
it is not. Set them anywhere in the document when the tag is `defer`red:

```html
<script>window.LoghoundIdent='ada@example.com';window.LoghoundSignedIn=true;</script>
```

And for an application that signs somebody in *after* the page loaded — a
single-page app, where no attribute can express it — the beacon exposes:

```js
window.loghound.identify('ada@example.com', true);
```

Both arguments are optional, so `identify(null, true)` records the signed-in
state and no identity. **It makes no request of its own:** the values ride the
heartbeat that is already scheduled, or the final flush.

For an anonymous visitor, send `data-signed-in="0"` and no `data-ident`. To say
nothing at all, omit both.

### Three states, not two

`signed_in_b` on the session document is written **only when your site actually
said one or the other.** A site that never sends `data-signed-in` leaves the
field *absent*, and the panel reports that population as "not reported" — never
as anonymous.

This matters more than it sounds. A boolean defaulting to `false` would invent an
anonymous population out of every site that has not adopted the attribute, and
the signed-in-versus-anonymous split — the reason the field exists — would be a
fabrication over traffic nobody classified. Absent is not false, here and
everywhere else in Loghound.

Where several payloads in one session disagree, the resolution follows what
happened: the **last** non-empty identity wins, because somebody who signs in
halfway through a visit is that person by the end of it; and signed-in beats
anonymous, because a session that was authenticated at any point was an
authenticated session.

### Storage, and the two switches

| Setting | Default | What it stores |
|---|---|---|
| `beacon.store_identity` | **`false`** | `ident_s` on the session document: the string your site sent, at most 128 bytes |
| `beacon.store_signed_in` | `true` | `signed_in_b` on the session document: a boolean, or nothing when unreported |

**`store_identity` is off by default and that is a deliberate policy default,
not an oversight.** Everything else this beacon collects is a measurement of a
browser. This is a name. With it on, an email address is written to the session
document, appears in the panel, lives in the Solr index, and is in every backup
of that index until `privacy.retention_days` deletes the session. That is a
decision about personal data and only you can make it.

With it off, `Beacon::normalise()` discards the string **before anything is
written** — it never reaches the SQLite staging table, let alone Solr. Switching
it off stops collection; it does not merely hide what was collected. Existing
documents keep what they have until retention removes them.

`store_signed_in` is on by default because the boolean identifies nobody, and
because the split it enables — engaged time, paths taken, bounce and bot verdict
for signed-in versus anonymous traffic — is one of the most useful things the
panel can show and nothing else can compute it. **The two switches are
independent:** storing the split while storing no identities at all is a
perfectly ordinary configuration, and probably the right one for most sites.

### In the panel

Both appear on the session detail dialog, in a strip flagged with the accent
because they are the only facts there that Loghound did not derive for itself.
The signed-in split appears as a dimension in the filter bar with all three
buckets counted. The identity string is rendered with `textContent` at every
sink, like every other value that came off the wire — it is caller-supplied
input on a public endpoint, and it is treated as hostile regardless of how
trustworthy the site that sent it is.

**Where the query string goes.** It is dropped before the payload is built, except
for the parameters you name in `data-params` — see section 3.2. Real sites
routinely carry session tokens, email addresses and password-reset codes in query
strings, and an analytics tool that collects them wholesale has created a breach
that its customer did not agree to. That is why the exception is a whitelist of
names rather than a switch.

**What the server ignores.** The collector reads the IP, User-Agent and referer
**off the connection**, never from the payload. A client that sends them is
wasting its bytes. The hostname is the exception, for the reason in section 3.3.

**IP handling** follows `privacy.ip_mode`: `full`, `truncate` (v4 /24, v6 /48), or
`hash` (keyed, rotated daily). See `docs/PRIVACY.md`.

---

## 3.2 Search terms — the one thing Loghound stores that somebody typed

**Off unless you configure it. This is a named decision with a consequence, not a
feature toggle, and it is the only place in the product where a literal string a
visitor typed is stored and indexed.** Everything else Loghound keeps is a
measurement, a status code, a hashed identifier or a path. A search term is
content.

### What you get

`search_terms_ss` on both the hit and the session document: a **facetable,
indexed, multi-valued** field. So "what did people search for" becomes a real
dimension — countable, filterable, drillable, reachable from the value browser —
exactly like Country or Browser. The Overview page has a *What they searched for*
card, and any value in it scopes the whole dashboard when you click it.

This is a deliberate contrast with `query_s`, which has always been on the hits
core as **stored-only, not indexed, no docValues**. `query_s` is the whole query
string; you can see it on one document and you can facet on none of it, because a
query string is unbounded attacker-controlled text with a near-unique value per
request and indexing it would build a term dictionary the size of the corpus.
`search_terms_ss` is its opposite by construction: a handful of values, pulled out
**by name**, from a list you wrote.

### How you switch it on

```php
'beacon' => [
    'query_params' => ['q'],
],
```

and, on the measured page, the matching attribute — which the Settings page
already fills in for you once the configuration is set:

```html
<script src="https://loghound.example.com/b.js?v=1757000000" data-params="q" defer></script>
```

Both sides matter and they do different jobs:

- **`data-params` is a privacy measure.** It keeps the rest of the URL — the
  session token, the reset code — from leaving the visitor's browser at all.
- **`beacon.query_params` is the decision about what is stored.** The payload is
  attacker-chosen, so the server applies its own whitelist on arrival regardless
  of what the page sent. A parameter you have not named is discarded before
  anything is written anywhere.

`beacon.query_params` also feeds the **log parser**, which is the half that needs
no beacon at all: for a host whose access log this installation reads,
`Parser::normalize()` pulls the same named parameters out of the request line. So
a search page on this machine and a search page on another one both fill the same
field, and a mixed install compares like with like.

### What a term looks like by the time it is stored

| Rule | Why |
|---|---|
| Control characters stripped, invalid UTF-8 repaired | It travels into a Solr document, a JSON response and an HTML table |
| Internal whitespace collapsed | `solr   hosting` and `solr hosting` are one value, not two that look identical on screen |
| **Lower-cased** | The field exists to be *counted*. A dimension listing `Solr`, `solr` and `SOLR` as three rows answers the question worse than one that lists it once. The original casing is not kept anywhere |
| Longer than 96 characters → **dropped, not truncated** | Truncating would coin a facet value nobody ever searched for, and the value browser would then show it as though somebody had |
| At most 8 per payload or log line, 20 distinct per session | A visitor who runs four hundred searches must not make one session document four hundred values wide |
| Always a **bound value**, never spliced into a Solr parameter | Same rule as every other untrusted string in the product |

Counted **per session**, not per search: a visitor who ran the same search six
times contributes one. That is the number worth having ("how many people looked
for this") rather than the one that flatters ("how many times was this typed"),
and the card says which it is showing.

### The consequence, stated plainly

Turning this on widens what Loghound keeps from *metadata about requests* to
*content from requests*. A search term can be a person's own name, a medical
question or a competitor's name typed into your site by their employee. It lands
on the session document, appears in the panel, lives in the search index and sits
in every backup of it until retention deletes the session — the same lifecycle as
`ident_s`, and for the same reason it is off by default. Name only the parameters
your search box actually uses, and never a parameter that could carry anything
else.

---

## 3.3 Standalone mode — a site on another server

**The beacon works on a host this Loghound has no access log for.** Paste the same
snippet. Nothing else is installed there: no agent, no log shipping, no second
Loghound. This is how a hosted search page at `search.example.com`, running on a
different machine from the one Loghound is on, appears in the same panel as
everything else.

### Two modes, and the server decides which

| Mode | When | Behaviour |
|---|---|---|
| **Merge** | An access log source in *this* installation covers the hostname | Unchanged from every earlier version: the log is the authority on facts, the beacon on time, and the beacon's rows merge onto the session the scorer built from log lines |
| **Standalone** | No log source here covers the hostname | The beacon is the only plane. It creates the session itself, carrying the hostname, the search terms and everything it measured |

You do not declare the mode. `beacon.allowed_hosts` says which hosts may report
at all; whether a host is *already covered* is **derived from evidence** — has
this installation actually ingested log lines for that hostname in the last seven
days. Configuration says what somebody intended; evidence says what is true, and
only the second is safe to act on. Asking you to state the mode in a second place
would guarantee the two drifted the first time a site moved.

### The hostname becomes the virtual host

A standalone session's `host_s` is the hostname the page reported, so it sits in
the **Virtual host** dimension beside hosts that came from `%v` in a log line, and
filters identically. On the Virtual hosts page the two kinds are in one table,
each row marked with which it is.

### Permission: `beacon.allowed_hosts`

```php
'beacon' => [
    'allowed_hosts' => ['search.example.com', 'shop.example.com'],
],
```

**Empty by default**, so an installation that says nothing behaves exactly as it
did before this existed. A beacon from a hostname that is not on the list keeps
today's behaviour precisely: a fresh provisional session id, a staged row,
merge-only, **no session created**, and no hostname and no search term recorded
anywhere.

Being on the list buys four things and nothing else:

1. its beacons may **create** a session when no log source covers the host;
2. its reported hostname is recorded as `host_s`;
3. the parameters from section 3.2 are kept as `search_terms_ss`;
4. its beacons may contribute **signal codes** — the execution-plane evidence that
   sets `headless_b` and `client_score_f`.

### Why the fourth one is on the list, and what it costs an empty list

A beacon from an unlisted host contributes its **timings** exactly as before —
wall, visible and engaged time, interactions, scroll, pageviews, `beacon_b`,
`js_b` — and **no signal code at all**, in either direction.

That is not tidiness. The staged row is re-attached to a session by `client_key`
as well as by session id, and `client_key` is the address block plus the
User-Agent hash, both read off the connection. So a hostile page loaded in a
visitor's browser — an advert, an iframe, any site they happen to open — shares
that key with them exactly. It does one CORS-simple POST, is handed a perfectly
valid provisional session and a token bound to **its own** origin, posts
`automation_webdriver`, and the merge folds that into the visitor's real
log-backed session. In a bot-detection product that is the whole game: a stranger
marking a person as automation, on somebody else's dashboard. Binding the token
to an `Origin` never touched it, because the attacker never needed the victim's
session.

Refusing only the *client-reported* codes would not close it either, because the
server derives `headless_zero_outer` and `screen_outer_impossible` from screen
numbers that are also in the payload. The blunt rule is the only one that is
provably complete.

**So if you want headless detection from the beacon, list your hosts.** One line,
and it is the same line that already gates the hostname, the search terms and the
stored identity.

### How a listed host is told apart from the open internet

Three facts have to agree, and the collector checks all three (`lh_site()` in
`public/collect.php`):

1. **What the page says it is** — `location.hostname`, in `hn`. Entirely
   attacker-chosen, so on its own it is worth nothing.
2. **What the browser says it is** — the `Origin` header. A user agent sets this
   on every cross-origin request and **page script cannot change it**: a page on
   `evil.example` cannot make a browser send `Origin: search.example.com`. This is
   the fact that makes the first one worth reading. They are required to agree,
   and a disagreement is refused rather than reconciled — it means the request was
   not built by a browser running on the page it claims. A request with **no**
   `Origin` is refused for this purpose too, because the beacon is cross-origin by
   construction and a browser running it always sends one.
3. **What you said** — the hostname is on `beacon.allowed_hosts`.

### What this does NOT stop — read this part

**The allowlist is a permission, not an authentication, and this documentation is
not going to imply otherwise.**

`Origin` binds *browsers*. Anything that is not a browser — `curl`, a script, a
load generator — sends whatever headers it is told to. So **somebody who knows a
hostname is on your list can fabricate sessions attributed to it.** They can make
up dwell times, invent visitors, and report a human as headless automation.

What bounds that:

- It reaches only the hostnames **you listed**. It cannot touch another host's
  data and it cannot invent a hostname you did not name.
- It **reads nothing**. The collector answers `204` with an empty body to every
  request, success or failure, so it is not an oracle for anything.
- It cannot reach the **log-backed planes**. A forged beacon cannot create a log
  line, a status code, a byte count or a reverse DNS result, and it cannot alter a
  session that has those — the beacon merge never overwrites a fact the log
  supplied.
- Rate limits apply per address, per session **and per hostname**, so a listed
  host is not a way around the limiter.

This is the same exposure every client-side analytics product carries — Clicky,
Plausible, GA and the rest all accept a beacon whose only claim to authenticity is
a site identifier visible in the page source. Loghound's answer is not to pretend
the problem is solved. It is to **mark what the evidence actually is**, which is
the next section.

### A beacon-only session is marked, and never claims a log fact

A standalone session has **no transport plane**. No status code, no bytes, no
server timing, no conditional-request behaviour, no inter-request rhythm, no
reverse DNS from a log line. Two guarantees, and both are needed:

**On the document.** None of those fields is written. Not zero — **absent**. A
zero in any of them is a measurement, and `asset_ratio_f: 0.0` reads as "this
client fetched only markup", which is a bot signal, about a visitor whose asset
fetching was never observable from here.

**In the ruleset.** Five rules are silenced (`Rules::TRANSPORT_CODES`):
`no_js_on_html`, `no_assets`, `no_304_on_repeat`, `single_page_10s`,
`periodic_timing`. Without that, `assets == 0` would be read back as evidence
against **every single visitor** of a standalone site — `no_assets` is 25 points,
`no_304_on_repeat` 30 and `single_page_10s` 15, all three reading counters that
were never collected here. Each of those rules also has a guard of its own that
declines on a beacon-only session today; the list is what makes that a guarantee
rather than a coincidence of predicates written for another purpose.
`no_interaction` is deliberately *not* silenced: it reads the beacon's own
interaction count, which a beacon-only session has.

The session carries:

- **`planes_s`** — `log_only`, `log_beacon` or `beacon_only`. A facetable
  dimension, so every count that mixes populations can be split on it.
- **`beacon_only_session`** in `bot_reasons_ss` — worth no points, present so that
  the verdict explains itself in the session dialog and in the *Signal fired*
  facet.

And in the panel: the Virtual hosts table marks each row, and the Overview timing
card reveals a note about the mixture whenever the selected range actually
contains beacon-only sessions.

**Asking for sessions that have a transport plane is `-planes_s:beacon_only`, not
`planes_s:log_only`.** The field is newer than the product, so every session
indexed before it existed has no value for it — and every one of those came from a
log. The negation includes that history; the positive form would silently exclude
all of it. This is the same three-state discipline as `provisional_b` and
`signed_in_b`: true, false, and **absent means not reported**, with no schema
default that makes an old document assert something it never said.

### Content-Security-Policy on the measured site

Two directives, and the second is the one people forget:

```
script-src  https://loghound.example.com;
connect-src https://loghound.example.com;
```

Without `connect-src` the script loads, runs, measures — and the browser blocks
the POST. There is no error anywhere you would look: the page is fine, the console
shows a CSP violation nobody is watching, and the panel simply shows nothing for
that host. Both are needed even though the beacon prefers
`navigator.sendBeacon`, because a browser that lacks it or refuses the call falls
back to `fetch` and `connect-src` governs both.

Nothing else has to be relaxed: the beacon uses no `eval`, no `new Function`, no
inline handlers and no `innerHTML`.

### The cross-origin path, end to end

There is no preflight, and that is by design rather than by luck. The beacon sends
`Content-Type: text/plain;charset=UTF-8` with no custom headers, which makes the
POST a **CORS-simple request** — byte-identical to what `navigator.sendBeacon`
sends. An `OPTIONS` should therefore never happen; the collector answers one
anyway, because a proxy or a CSP on the measured site can turn a simple request
into a preflight and answering costs nothing.

Response headers on every reply:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
Access-Control-Expose-Headers: X-LH-S, X-LH-T
Access-Control-Max-Age: 86400
```

`Access-Control-Expose-Headers` is the load-bearing one: a `204` has no body, so
the session id and token can only come back in headers, and without that header
the page's JavaScript cannot read them — the hello succeeds, the beacon gets no
credentials, and every later payload is silently dropped. Section 5 has the
exchange in full.

`credentials: 'omit'` is set explicitly, so the wildcard origin is safe: the
endpoint takes no credentials, has no cookies to send in the first place, returns
no body, and performs no action on behalf of a signed-in user. There is nothing a
hostile origin gains by making this request that it could not get from `curl`.

### When a standalone host later gains a log source

You add the vhost, or move the site onto the Loghound machine. From that moment
both planes describe the same visit, and this produces **one** session, not two:

1. The coverage check flips as soon as hits appear for that hostname, so nothing
   new is promoted to standalone.
2. Beacons for a visit already in flight are claimed by the log-backed session
   through the **client key** (`ip_net + ua_hash`) — the mechanism that has always
   existed for a beacon arriving before its log line.
3. Any *provisional* standalone document already published for those rows is
   **deleted by id before** the run indexes anything. Deleting first means a
   failure leaves a gap, never a double count.

History is untouched. A session that really was beacon-only when it happened stays
beacon-only, because a reconfiguration today is not evidence about last week.

### Several installations, one pair of indexes

A pair of Solr indexes may be shared by more than one Loghound installation on
more than one machine, some contributing a log plane and some only a beacon, told
apart by `host_s`. Three things make that safe:

- **Session ids cannot collide.** A log-backed id is
  `sha1(client_key | first_ts | 16 random bytes)` and a beacon-minted one is
  `b` + 20 random bytes. Both carry enough entropy that independent installations
  will not produce the same value.
- **Hit ids cannot collide either, but only because the installation id is in
  them.** It is `sha1(install_id \0 src:offset)`. Two machines both tailing
  `/var/log/apache2/access.log` produce identical `src:offset` pairs, and a Solr
  update with a duplicate `uniqueKey` is a delete-and-add — so without the
  installation id each machine would silently have overwritten the other's
  traffic, one request at a time, with no error anywhere.
- **`install_s`** on both cores names the installation that wrote each document.
  It is not how the panel separates sites (that is `host_s` — a shared pair is
  meant to read as one dashboard). It exists so a **destructive** operation can be
  scoped: `bin/loghound-retention` detects a shared pair from this field and, when
  it finds one, deletes only its own documents. An installation with a 90-day
  policy must not be able to delete a neighbour's 365 days, and if it cannot name
  its own documents it refuses to run rather than guessing.

Two consequences worth stating:

- **Fingerprint clustering spans the whole pair.** `fp_ips_24h_i` counts distinct
  addresses per fingerprint across every site in the index, deliberately: a
  rotating proxy fleet working through your sites in turn is exactly the pattern
  that is invisible from inside any one of them. It does mean
  `fp_cluster_proxy_fleet` fires more readily on a shared pair — and it is worth
  **80 points**, which reaches the `bot` threshold on its own, so that is a
  consequence to size before you share a pair rather than after. What bounds it is
  not the weight but the rule's three guards: a five-IP floor, the `as_type_s =
  mobile` exclusion, and the exemption for a self-declared crawler whose
  forward-confirmed rDNS passed. On a shared pair, raise the floor with
  `scoring.fp_fleet_min_ips`.
- **The daily rollup converges rather than forking.** Every installation
  recomputes a whole day from every session document in the index and writes it at
  the same deterministic id, so they all compute the same numbers and the last
  writer wins with a value identical to the one it replaced. An atomic increment —
  the design deliberately rejected — would have each installation add its own
  sessions to a shared counter and inflate the day by the number of writers. The
  rollup carries no `install_s`, because it describes the index rather than an
  installation.

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
