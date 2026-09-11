/*!
 * Loghound beacon — public/b.js — MIT licensed.
 *
 * ============================================================================
 * WHAT THIS FILE IS
 * ============================================================================
 * Two jobs, and only two:
 *
 *   1. Measure REAL time on site. Every other analytics product reports "the page
 *      was open for N minutes". That number is wrong the moment a tab is left open
 *      in a background window: a visitor who left after four seconds is reported as
 *      seven minutes of "engagement". We report three separate clocks and never
 *      conflate them:
 *
 *        wall_ms     the page existed for this long        (what Clicky/GA report)
 *        visible_ms  the tab was visible AND focused       (honest attention window)
 *        engaged_ms  visible AND a human touched something (the honest number)
 *
 *   2. Act as the execution plane of Loghound's three-plane bot detection: does JS
 *      run at all, does the JS engine actually match the version the User-Agent
 *      claims, and is a human plausibly driving the pointer.
 *
 * ============================================================================
 * THE ONE PRINCIPLE THAT OVERRIDES EVERYTHING ELSE IN THIS FILE
 * ============================================================================
 * A false "this human is a bot" is far worse than a missed bot.
 *
 * Therefore EVERY environment probe here goes through T() or Q() below. If an API
 * is absent, disabled by a privacy extension, blocked by a Content Security Policy,
 * or simply throws, the result is UNKNOWN — never evidence of automation, and never
 * an exception escaping into the host page. Real browsers are weird: Firefox hides
 * the WebGL renderer, Brave lies about hardwareConcurrency, corporate proxies strip
 * APIs, old Safari is missing half of this. None of that may produce a bot verdict.
 *
 * For the same reason most individual signals below are deliberately WEAK. The
 * server correlates them with the transport and behaviour planes; a single code in
 * `automation_ss` is a hint, never a verdict.
 *
 * ============================================================================
 * EVERY DURATION IS A performance.now() DELTA
 * ============================================================================
 * Date.now() is NOT an acceptable substitute anywhere in this file: it jumps on NTP
 * steps, DST changes and manual clock edits, and one jump would silently corrupt
 * every number we publish. An engine with no monotonic clock therefore gets no
 * beacon at all — we would rather report nothing than report a number we do not
 * trust.
 *
 * The three accumulators only ever move forward, and only ever inside accrue().
 * accrue() closes the segment [last, now]. Within one segment the visibility/focus
 * state is constant, because every event that could change it calls accrue() BEFORE
 * it updates the state. That is what makes these numbers exact rather than "sampled
 * once a second".
 *
 * ============================================================================
 * WHY THIS IS ES5, NOT MODERN JS
 * ============================================================================
 * No arrow functions, no const/let, no template literals, no optional chaining.
 * A SyntaxError on an old engine means the whole script never runs, which means no
 * beacon arrives, which the server would read as "no JS at all" — the strongest
 * bot signal we have. Being unparseable is therefore not a cosmetic failure here;
 * it is a false accusation. ES5 costs a few hundred bytes and removes that class
 * of bug entirely.
 *
 * ============================================================================
 * PRIVACY
 * ============================================================================
 * No cookies. No localStorage. No canvas or audio fingerprinting. Nothing is read
 * out of the page: no content, no form values, no keystrokes (we count keydown
 * events, we never look at which key). The URL path is sent — never the query
 * string, which on real sites carries session tokens and password-reset codes — so
 * a session's pageviews can be told apart in the panel, and the server treats even
 * that as untrusted. Full field-by-field list: docs/BEACON.md.
 *
 * A SECOND EXCEPTION, ALSO THE SITE'S OWN DOING, was added for search pages: the
 * operator may NAME query parameters to collect, through `data-params`, and only
 * those named parameters are read out of the URL. The rest of the query string is
 * still never looked at. That is a deliberate widening of what Loghound stores —
 * a search term is a literal string somebody typed, where everything else here is
 * a measurement or a hash — and it is off unless configured, on both sides.
 *
 * THE ONE EXCEPTION, AND IT IS THE SITE'S OWN DOING. A site may DECLARE an identity
 * for the session — an email, a customer number — and whether the visitor was signed
 * in, through the two data- attributes documented at the top of section 2. Nothing
 * here guesses either: no cookie is read, no form is scraped, no meta tag is looked
 * for. If the site does not say, the fields are absent. The identity is off by
 * default on the server as well (`beacon.store_identity`), and the two can be
 * switched independently, because a split between signed-in and anonymous traffic is
 * worth having without storing anybody's address.
 *
 * ============================================================================
 * GRACEFUL DEGRADATION
 * ============================================================================
 * If the collector is unreachable, slow, 404, 500, blocked by an ad blocker or
 * behind a dead DNS name, the host page is completely unaffected: every network
 * call is fire-and-forget, no response body is ever parsed, no promise rejection is
 * left unhandled, and every entry point sits inside a try/catch.
 *
 * ============================================================================
 * INSTALLATION
 * ============================================================================
 *   <script src="https://loghound.example.com/b.js?v=1" defer></script>
 *
 * `defer` is what the panel's Settings page emits: it never blocks rendering and
 * starts the clocks at parse time. `async` also works. The ?v= is the cache buster —
 * b.js is served with a long Cache-Control, so a new version must be a new URL.
 *
 * Optional attributes: data-endpoint (collector URL), data-hb (heartbeat ms),
 * data-idle (engagement idle timeout ms), data-ident (an identity the site attaches
 * to the session), data-signed-in (1 or 0) and data-params (URL query parameters to
 * collect, comma separated — see section 2b). The collector is assumed to live next
 * to b.js unless data-endpoint says otherwise, so the install snippet is one line
 * with no second URL to keep in sync.
 *
 * ============================================================================
 * A SITE ON ANOTHER SERVER
 * ============================================================================
 * This file works unchanged on a host that has no Loghound and no shared access log
 * with the one that does. Everything it needs is either measured in the page or read
 * off the connection by the collector; nothing is read from a file on the monitored
 * machine. The page reports its own hostname, the collector cross-checks it against
 * the Origin the browser set and against the operator's allowlist, and the scorer
 * publishes a session for it marked as having one plane rather than three. The
 * mechanics are in docs/BEACON.md under "Standalone mode".
 *
 * A site with a Content-Security-Policy needs `script-src` to allow the Loghound
 * origin and `connect-src` to allow it too — the second is the one people forget,
 * and without it the browser blocks the POST silently and the operator sees nothing
 * at all. docs/BEACON.md gives the exact directives.
 */
(function (w, d) {
    'use strict';

    var P = w.performance;

    if (!d || !P || typeof P.now !== 'function' || w.__lh) { return; }
    w.__lh = 1;

    /** Aliases. These are read constantly and a minifier cannot shorten a global. */
    var NV = w.navigator || {};
    var SC = w.screen || {};

    /**
     * Probe wrapper: returns the probe's value, or undefined when the API is
     * missing or throws. THE safety net described in the header.
     */
    function T(f) {
        try { return f(); } catch (e) { return undefined; }
    }

    /** Push signal code `c` when probe f() is truthy. A throw pushes nothing. */
    function Q(f, c) {
        try { if (f()) { push(c); } } catch (e) { }
    }

    /** Monotonic milliseconds. Never wall-clock. */
    function now() { return P.now(); }

    /** Attach a passive, capturing listener without ever throwing. */
    function on(t, n, h) {
        T(function () { t.addEventListener(n, h, { capture: true, passive: true }); });
    }

    var SELF = d.currentScript || T(function () {
        var a = d.getElementsByTagName('script');
        return a[a.length - 1];
    });

    /** Read one attribute off our own script tag, or undefined. */
    function attr(n) { return T(function () { return SELF.getAttribute(n); }); }

    var EP = attr('data-endpoint') ||
        T(function () { return SELF.src.replace(/\/b\.js(\?.*)?$/, '/collect.php'); });
    if (!EP) { return; }

    /** Read a numeric data- attribute, refusing values outside a sane range. */
    function attrInt(n, def, min, max) {
        var v = parseInt(attr(n), 10);
        return (isFinite(v) && v >= min && v <= max) ? v : def;
    }

    var HB   = attrInt('data-hb', 15000, 2000, 300000);
    var IDLE = attrInt('data-idle', 30000, 1000, 600000);

    /**
     * ============================================================================
     * WHICH SITE THIS IS, AND WHAT WAS SEARCHED FOR
     * ============================================================================
     * Two things the page knows and the collector cannot find out for itself, because the
     * page and the collector are on DIFFERENT MACHINES. That is the whole point of a
     * standalone beacon: `search.opensolr.com` is not the Loghound host, its access log is
     * not one of Loghound's sources, and the only party that can say which site this
     * pageview belongs to is the page.
     *
     *   hn  location.hostname. Sent on every payload. The server does not take our word
     *       for it — it cross-checks the value against the Origin header the BROWSER set,
     *       which page script cannot forge, and then against the operator's own allowlist.
     *       See lh_site() in public/collect.php. Sending it is therefore free of any
     *       decision on our part: it either agrees with what the browser said and is
     *       listed, or it is ignored.
     *
     *   qp  the URL's query parameters, restricted to the names in `data-params`. This is
     *       how "what did people search for" reaches Loghound from a search page whose log
     *       lives on another host.
     *
     * WHY `data-params` IS A WHITELIST AND NEVER "SEND THE QUERY STRING". The URL of a real
     * page carries password-reset codes, session tokens, invitation keys and email
     * addresses. The privacy note at the top of this file says the query string is never
     * sent, and this does not retract it: what is sent is the value of parameters the
     * operator NAMED, and nothing else in the URL is read. The server applies its own
     * whitelist again on arrival (`beacon.query_params`), so this side is a promise to the
     * visitor and that side is the decision about what is stored.
     *
     *   <script src="/b.js?v=1" data-params="q" defer></script>
     *
     * Empty by default. An installation that does not ask for parameters sends none, so
     * upgrading b.js cannot start shipping URLs that were not being shipped before.
     */
    var HOST = T(function () { return (w.location.hostname || '').toLowerCase(); }) || '';

    var PARAMS = (function () {
        var raw = attr('data-params');
        if (!raw || typeof raw !== 'string') { return []; }
        var out = [], parts = raw.toLowerCase().split(','), i, n;
        for (i = 0; i < parts.length && out.length < 8; i++) {
            n = parts[i].replace(/^\s+|\s+$/g, '');
            if (n && n.length <= 40 && /^[a-z0-9_\-.[\]]+$/.test(n)) { out.push(n); }
        }
        return out;
    }());

    /**
     * The whitelisted parameters of the CURRENT url, as a name => value map.
     *
     * Read at send time rather than at load, so a single-page application that navigates
     * from one search to the next reports each one. URLSearchParams is not used: this file
     * is ES5 for the reasons in the header, and a beacon that throws on an old engine
     * reports nothing at all, which reads as a bot.
     *
     * Values are capped here as well as on the server. The cap on this side is about not
     * making a visitor's browser upload a long string; the cap on that side is about not
     * being made to store one.
     */
    function urlParams() {
        var out = {};
        if (!PARAMS.length) { return out; }
        T(function () {
            var q = (w.location.search || '').replace(/^\?/, '');
            if (!q || q.length > 8192) { return; }
            var pairs = q.split('&'), i, eq, name, val;
            for (i = 0; i < pairs.length; i++) {
                eq = pairs[i].indexOf('=');
                if (eq < 1) { continue; }
                name = T(function () {
                    return decodeURIComponent(pairs[i].slice(0, eq)).toLowerCase();
                });
                if (!name) { continue; }
                for (var j = 0; j < PARAMS.length; j++) {
                    if (PARAMS[j] !== name || out[name] !== undefined) { continue; }
                    val = T(function () {
                        return decodeURIComponent(pairs[i].slice(eq + 1).replace(/\+/g, ' '));
                    });
                    if (val) { out[name] = String(val).slice(0, 96); }
                }
            }
        });
        return out;
    }

    /**
     * ============================================================================
     * IDENTITY THE SITE SUPPLIES — the one thing in this file we do not measure
     * ============================================================================
     * Two facts only the measured site knows, both optional and INDEPENDENT of each
     * other:
     *
     *   xi  an identity string of the site's own choosing — an email address, a
     *       customer number, an account id. Whatever it calls the person.
     *   xs  whether the visitor was signed in: 1 yes, 0 no, OMITTED when the site
     *       did not say. Omitted is not "no". A site may pass an identity without
     *       the visitor being authenticated, and may want the signed-in split
     *       recorded without handing over who it was, so neither implies the other.
     *
     * HOW A SITE SUPPLIES THEM, and why this shape. The primary channel is two
     * attributes on the script tag, because the site's own template renders that tag
     * in the same response as the page: no second request, no extra script, no
     * ordering problem, and the value cannot be missed by a beacon that started
     * before some later snippet ran. `d.currentScript` is already being read for the
     * endpoint, so reading two more attributes costs nothing:
     *
     *   <script src="/b.js?v=1" data-ident="ada@example.com" data-signed-in="1" defer></script>
     *
     * Two globals are accepted as an equivalent, for templating systems where adding
     * an attribute to a third-party tag is awkward but setting a variable above it is
     * not. They must be set BEFORE b.js executes, which with `defer` means anywhere
     * in the document:
     *
     *   <script>window.LoghoundIdent='ada@example.com';window.LoghoundSignedIn=true;</script>
     *
     * And `window.loghound.identify(ident, signedIn)` exists for an application that
     * signs somebody in AFTER the page loaded, which no attribute can express. It
     * makes NO request of its own: the values ride the heartbeat that is already
     * scheduled, and the server folds the latest non-empty identity onto the session.
     *
     * WE NEVER GUESS. Nothing here reads a cookie, a form field, a meta tag or the
     * DOM looking for an email. If the site does not say, the fields are absent, and
     * the server treats absent as absent.
     */
    var xIdent = String(attr('data-ident') || T(function () { return w.LoghoundIdent; }) || '').slice(0, 128);
    var xSigned = tri(attr('data-signed-in'), T(function () { return w.LoghoundSignedIn; }));

    /**
     * Collapse the two possible sources into 1, 0 or undefined.
     *
     * The attribute is a string and the global may be a real boolean, so both spellings of
     * each state are accepted. An attribute that is present but empty is an answer and reads
     * as 0. Anything else — a typo, a value neither spelling covers, an attribute the site
     * never wrote — is undefined, which the payload omits and the server reads as "not
     * reported" rather than as "anonymous".
     */
    function tri(a, b) {
        /* AN EMPTY ATTRIBUTE IS AN ANSWER, AND THE ANSWER IS NO. A template that renders
           `data-signed-in="{{ user.signed_in }}"` writes an empty string for a visitor who is
           not signed in — the site DID answer, and collapsing that into "not reported" threw
           away the one case the boolean exists for. Absent is still absent: an attribute the
           site never wrote falls through to the global and then to undefined, which is the
           third state the panel shows as "not reported". */
        if (a === '') { return 0; }
        var v = (a === null || a === undefined) ? b : a;
        if (v === true || v === 1 || v === '1' || v === 'true') { return 1; }
        if (v === false || v === 0 || v === '0' || v === 'false') { return 0; }
        return undefined;
    }

    var t0, last, visMs, engMs, lastInt, visNow;
    var pv, beat, sentEng, ended;
    var itMask, itCount, mmPts, mmLast, scLast, scrollPct, scrolled;

    /**
     * Is the page really being looked at right now?
     *
     * visibilityState alone is not enough: a visible but unfocused window (the
     * visitor is in another application, or another window is on top) is not
     * attention. document.hasFocus() is absent on some very old engines — the call
     * then throws, T() returns undefined, and we fall back to "visible" rather than
     * reporting a false zero.
     *
     * 'prerender' and 'hidden' both mean nobody is looking, so a page that starts
     * prerendered or in a background tab accrues no visible time at all until it is
     * actually shown. That is the entire point of the metric.
     */
    function computeVisible() {
        if (d.visibilityState && d.visibilityState !== 'visible') { return false; }
        var f = T(function () { return d.hasFocus(); });
        return f === undefined ? true : !!f;
    }

    /**
     * Close the open segment and add its duration to the right accumulators.
     *
     * Engaged time is the OVERLAP of the segment with the window
     * [lastInt, lastInt + IDLE]. Because accrue() also runs on every interaction,
     * lastInt is always <= the segment start, so the overlap is simply
     * min(segEnd, lastInt + IDLE) - segStart clamped into [0, dt]. Exact, with no
     * polling timer, and it never credits the 15 seconds that follow a
     * 30-second-old interaction.
     *
     * A non-positive delta — a clock anomaly, or two events inside one millisecond —
     * contributes nothing rather than something negative.
     */
    function accrue() {
        var t = now(), dt = t - last;
        last = t;
        if (!(dt > 0) || !visNow) { return; }
        visMs += dt;
        if (lastInt >= 0) {
            var ov = Math.min(t, lastInt + IDLE) - (t - dt);
            if (ov > 0) { engMs += (ov > dt ? dt : ov); }
        }
    }

    /**
     * Reset every per-pageview accumulator. Called once at load, and again on a
     * bfcache restore, which really is a new pageview (see the pageshow handler).
     *
     * The pageview id only has to be locally unique, so that the server can collapse
     * this pageview's heartbeats onto one row. It is not a security value and it is
     * not an identifier of the visitor, so Math.random is the right tool.
     */
    function reset() {
        t0 = last = now();
        visMs = engMs = 0;
        lastInt = -1;
        visNow = computeVisible();
        pv = (Math.random() + '.' + Math.random()).replace(/\D/g, '').slice(0, 16);
        beat = 0;
        sentEng = -1;
        ended = false;
        itMask = itCount = 0;
        mmPts = [];
        mmLast = scLast = -1;
        scrollPct = 0;
        scrolled = false;
    }
    reset();

    /**
     * Count one interaction of the given type and re-arm the engagement window.
     *
     * The segment is closed BEFORE lastInt moves, so the time just elapsed is
     * attributed to the engagement state it was actually in.
     *
     * Interaction types are reported to the server as a bit mask, so it can see WHICH
     * types occurred and not merely how many: 0 mousemove, 1 scroll, 2 keydown,
     * 3 click, 4 pointerdown, 5 touchstart, 6 wheel.
     */
    function mark(i) {
        accrue();
        lastInt = now();
        itMask |= (1 << i);
        itCount++;
    }

    'keydown click pointerdown touchstart wheel'.split(' ').forEach(function (n, i) {
        on(w, n, function () { mark(i + 2); });
    });

    /**
     * Pointer movement, throttled to one sample per second.
     *
     * An unthrottled mousemove handler is the classic way an analytics script shows
     * up in a performance profile; this one does almost nothing, and does it rarely.
     * Only clientX/clientY are kept: viewport-relative, no page content, no identity.
     */
    function onMouseMove(e) {
        var t = now();
        if (mmLast >= 0 && t - mmLast < 1000) { return; }
        mmLast = t;
        mark(0);
        if (mmPts.length < 16) { mmPts.push([e.clientX | 0, e.clientY | 0]); }
    }
    on(w, 'mousemove', onMouseMove);

    /** Full document height, for scroll depth and for the "tall page" test. */
    function docH() {
        var de = d.documentElement || {};
        return Math.max(de.scrollHeight || 0, (d.body && d.body.scrollHeight) || 0);
    }

    /** Viewport height. */
    function vpH() {
        return w.innerHeight || (d.documentElement && d.documentElement.clientHeight) || 0;
    }

    /** Scroll depth, throttled to four samples a second and one cheap layout read. */
    function onScroll() {
        var t = now();
        scrolled = true;
        if (scLast >= 0 && t - scLast < 250) { return; }
        scLast = t;
        mark(1);
        var pct = T(function () {
            var h = docH(), vh = vpH();
            if (h <= 0 || vh <= 0) { return 0; }
            return ((w.pageYOffset || d.documentElement.scrollTop || 0) + vh) / h * 100;
        });
        if (pct > scrollPct) { scrollPct = pct > 100 ? 100 : pct; }
    }
    on(w, 'scroll', onScroll);

    /**
     * Visibility and focus changed: accrue() first, THEN change the state, so the
     * segment that just ended is attributed to the state it was actually in.
     */
    function stateChanged() {
        accrue();
        visNow = computeVisible();
    }

    /**
     * Visibility changed. Hidden is the most reliable "the visitor is leaving" moment
     * on mobile, where pagehide and unload frequently never fire at all, so it also
     * flushes.
     */
    function onVisibilityChange() {
        stateChanged();
        if (!visNow) { flush(); }
    }
    on(d, 'visibilitychange', onVisibilityChange);
    on(w, 'blur', stateChanged);
    on(w, 'focus', stateChanged);

    /**
     * Classify pointer movement from the sampled points. Three deliberately
     * conservative outcomes:
     *
     *   human_mouse_natural  points vary in a way a straight line cannot explain
     *   mouse_linear         >=90% of sampled triples are EXACTLY collinear, which
     *                        is what a driver interpolating between two points
     *                        produces and what a hand never produces
     *   mouse_static         the pointer "moved" but never actually changed pixel
     *
     * Below 6 samples we say nothing at all: a visitor who nudged the mouse twice
     * is not evidence of anything.
     *
     * Collinearity is the cross product AB x AC: exactly zero means the three points
     * are on one line.
     */
    function mouseCodes(out) {
        var n = mmPts.length, i, col = 0, tri = 0, moved = 0, a, b, c;
        if (n < 6) { return; }
        for (i = 2; i < n; i++) {
            a = mmPts[i - 2];
            b = mmPts[i - 1];
            c = mmPts[i];
            tri++;
            if ((b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0]) === 0) { col++; }
            if (b[0] !== a[0] || b[1] !== a[1]) { moved++; }
        }
        out.push(!moved ? 'mouse_static' : (col / tri >= 0.9 ? 'mouse_linear' : 'human_mouse_natural'));
    }

    /**
     * Execution-plane state.
     *
     * Every probe below runs once, off the critical path, and appends short string
     * codes to `sig`, which the server reads as automation_ss. The server scores the
     * codes; this file assigns no weights.
     *
     *   sig      signal codes
     *   uaClaim  1 the engine matches the UA claim, 0 it does not, -1 unknown
     *   webgl    UNMASKED_RENDERER, '' when unavailable
     *   tz       IANA timezone from Intl, '' when unavailable
     */
    var sig     = [];
    var uaClaim = -1;
    var webgl   = '';
    var tz      = '';

    /** Record a signal code once. Hard cap so nothing can inflate the payload. */
    function push(c) {
        if (sig.length < 32 && sig.indexOf(c) < 0) { sig.push(c); }
    }

    /**
     * A rough device class from the UA, used only to decide which probes are
     * meaningful at all. The server has a real UA parser; this is a local shortcut.
     */
    var ua = NV.userAgent || '';
    var uaMobile = /Android|iPhone|iPad|iPod|Mobile|Windows Phone/i.test(ua);
    var uaChrome = /Chrom(e|ium)\/\d/.test(ua);

    /**
     * Definitive automation markers: the flags a driver leaves behind when nobody
     * bothered to hide them.
     *
     * Rows are "code prefix prefix ...", matched as PREFIXES of the global object's
     * own enumerable property names. chromedriver's marker is a randomised name such
     * as cdc_adoQpoasnfa76pfcZLmcfl_, and it lands on document as well as on window,
     * which is why both are scanned.
     */
    var DRV = ('cdc cdc_ $cdc_|playwright __playwright __pw_|puppeteer __puppeteer|'
        + 'selenium __selenium __webdriver __driver_ __fxdriver|nightmare __nightmare|'
        + 'phantom _phantom callPhantom __phantomas|domauto domAutomation')
        .split('|').map(function (r) { return r.split(' '); });

    /**
     * Scan one object's own enumerable property names for the DRV prefixes.
     *
     * Prefix matching rather than a scan for "anything suspicious" is deliberate: a
     * site that happens to define a similar-looking variable must not be able to
     * frame its own visitors.
     */
    function scan(o) {
        var k, i, j, r;
        for (k in o) {
            for (i = 0; i < DRV.length; i++) {
                r = DRV[i];
                for (j = 1; j < r.length; j++) {
                    if (k.indexOf(r[j]) === 0) { push('automation_' + r[0]); }
                }
            }
        }
    }

    /**
     * Look for the definitive automation markers.
     *
     * Present means certainty; ABSENT MEANS NOTHING AT ALL, because hiding them is a
     * one-line patch that every serious scraper applies.
     */
    function markers() {
        Q(function () { return NV.webdriver === true; }, 'automation_webdriver');
        T(function () { scan(w); });
        T(function () { scan(d); });
    }

    /** Record a headless tell. */
    function hl(c) { push('headless_' + c); }

    /**
     * Headless-Chrome tells. Individually weak to medium.
     *
     * The renderer string is the strong one: a software rasteriser under a UA claiming
     * a consumer desktop browser means the "browser" has no GPU, which is what a
     * container looks like. Firefox and several privacy extensions block the
     * debug-renderer extension entirely, so its absence is UNKNOWN, not a signal. The
     * WebGL context is released at once, because holding a GPU surface open for the
     * life of the page would be a real cost to a real visitor.
     *
     * The weaker tells, and why each is weak:
     *
     *   - No plugins at all under a desktop Chrome UA. Modern Chrome still exposes a
     *     fixed list of five PDF entries; headless historically exposed none.
     *   - navigator.languages missing or empty. Real browsers always populate it.
     *   - window.chrome absent under a Chrome UA is strong; window.chrome.runtime
     *     absent is WEAK, because its presence on ordinary pages has changed several
     *     times across Chrome releases and it is trivially faked.
     *   - The classic contradiction: the Notification API says permission is already
     *     denied while the Permissions API says the user was never asked. No real
     *     profile is in both states at once. This one is async, so it lands in a later
     *     heartbeat rather than in the first payload.
     *   - hardwareConcurrency zero or absent under a UA claiming a real browser. Brave
     *     and Safari clamp the value, so only 0/absent is reported.
     */
    function headless() {
        T(function () {
            var c = d.createElement('canvas');
            var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
            if (!gl) { return; }
            var ext = gl.getExtension('WEBGL_debug_renderer_info');
            if (ext) {
                webgl = String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '').slice(0, 120);
            }
            var lose = gl.getExtension('WEBGL_lose_context');
            if (lose) { lose.loseContext(); }
        });
        if (webgl && /SwiftShader|llvmpipe|Mesa OffScreen|Microsoft Basic Render/i.test(webgl)) {
            hl('renderer');
        }

        Q(function () { return !uaMobile && uaChrome && NV.plugins.length === 0; }, 'headless_no_plugins');

        Q(function () { return !NV.languages || !NV.languages.length; }, 'headless_no_languages');

        if (uaChrome) {
            if (!w.chrome) {
                hl('no_window_chrome');
            } else {
                Q(function () { return !w.chrome.runtime; }, 'headless_no_chrome_runtime');
            }
        }

        T(function () {
            if (w.Notification && w.Notification.permission === 'denied' && NV.permissions) {
                NV.permissions.query({ name: 'notifications' }).then(function (r) {
                    if (r && r.state === 'prompt') { hl('notif_contradiction'); }
                })['catch'](function () {});
            }
        });

        Q(function () { return uaChrome && !NV.hardwareConcurrency; }, 'headless_no_concurrency');
    }

    /**
     * The UA-claim probe table: flat pairs of [chrome_major, dotted path to a function
     * that first shipped natively in that Chrome release], resolved against `window`.
     *
     * GRACE = 2 means a UA that is one or two majors out of step — a browser
     * mid-upgrade, an enterprise pin, Chrome's own UA-reduction quirks — is never
     * flagged.
     *
     * HOW TO EXTEND AS CHROME ADVANCES: add one pair roughly every 10 Chrome releases,
     * using a feature that (a) shipped in a known Chrome version — look it up on
     * caniuse or in the V8 release notes, never guess — (b) is a FUNCTION reachable by
     * a dotted path from window, and (c) is not commonly polyfilled. NEVER remove old
     * rows: they are what catches ancient engines. Syntax-only features (optional
     * chaining, class fields) cannot be used here at all, since detecting them requires
     * eval, which our own CSP and most customers' CSPs forbid.
     */
    var GRACE = 2;
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

    /**
     * True only when the dotted path resolves to genuine native code.
     *
     * This is the false-positive guard for the whole UA-claim check: a page loading
     * core-js would otherwise make an old engine look new and get its visitors
     * flagged. A non-native function reads as "feature absent", which is the safe
     * direction.
     */
    function has(path) {
        return T(function () {
            var o = w, s = path.split('.'), i;
            for (i = 0; i < s.length; i++) { o = o[s[i]]; }
            return typeof o === 'function' &&
                /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(o));
        }) === true;
    }

    /**
     * Verify the engine against the Chrome version the User-Agent claims.
     *
     * The cheapest near-definitive check available. A scraper can set any User-Agent
     * string it likes, but it cannot retrofit V8: the engine either has the features
     * that shipped in the Chrome version the UA claims, or it does not.
     *
     *   major <= claimed - GRACE : the feature MUST be present. Missing means the
     *   engine is OLDER than claimed -> `ua_older_engine`. (An old engine wearing a
     *   fresh UA: the classic scraper.)
     *
     *   major >= claimed + GRACE : the feature MUST be absent. Present means the
     *   engine is NEWER than claimed -> `ua_newer_engine`. (A current engine wearing
     *   an old UA, to dodge feature gates or to look like a long-lived install.)
     *
     * The specific mismatching probe is reported as `ua_probe_<major>`.
     *
     * Chrome-, Edge-, Firefox- and Opera-on-iOS are all WebKit wearing a Chrome-shaped
     * UA. Their feature set has nothing to do with the Chrome version in the string, so
     * they are excluded outright: skipping them costs us nothing, flagging them would
     * be a pure false positive on millions of real iPhones. Safari, Firefox, curl and
     * anything else make no Chrome claim, so there is nothing to test, and a nonsense
     * major is unknown rather than a provable lie.
     */
    function uaClaimCheck() {
        if (/CriOS|EdgiOS|FxiOS|OPiOS|Firefox\//.test(ua)) { return; }
        var m = /Chrom(?:e|ium)\/(\d+)/.exec(ua);
        if (!m) { return; }
        var claimed = +m[1];
        if (!(claimed >= 40 && claimed <= 400)) { return; }

        var bad = 0, i, min, have;
        for (i = 0; i < UA_PROBES.length && !bad; i += 2) {
            min = UA_PROBES[i];
            have = has(UA_PROBES[i + 1]);
            if (min <= claimed - GRACE && !have) { bad = -1; }
            else if (min >= claimed + GRACE && have) { bad = 1; }
            if (bad) { push('ua_probe_' + min); }
        }
        uaClaim = bad ? 0 : 1;
        if (bad) { push(bad < 0 ? 'ua_older_engine' : 'ua_newer_engine'); }
    }

    /**
     * Read the environment's own IANA timezone.
     *
     * This is the client half of the consistency cross-checks, which compare two
     * things the environment states about itself: a genuine browser agrees with
     * itself, a patched one usually forgets one of the two.
     *
     * THE CLIENT REPORTS THE MEASUREMENTS; THE SERVER DOES THE COMPARING.
     * Beacon::derive() in src/Beacon.php turns the raw numbers in the payload into the
     * codes `platform_mismatch`, `touch_missing_mobile`, `dpr_odd`,
     * `screen_outer_impossible`, `headless_zero_outer` and `headless_screen_eq_avail`.
     * Three reasons this split is right and not merely a way to save bytes:
     *
     *   1. The server holds the AUTHORITATIVE User-Agent, read off the connection
     *      by the collector. Half of these checks compare something against the UA,
     *      and the UA the client hands us is exactly the thing we do not trust.
     *   2. A client cannot suppress a comparison it never performs.
     *   3. The comparison thresholds can be tuned on the server without asking
     *      every customer to re-deploy a script tag on their site.
     *
     * The timezone follows the same pattern and always has: the beacon reports the
     * IANA zone, the server compares it against the IP's geolocation to set
     * tz_match_b, because the beacon must never be told where the server thinks
     * the visitor is.
     */
    function consistency() {
        tz = T(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }) || '';
        if (!tz) { push('tz_unknown'); }
    }

    /**
     * Run the probes off the critical path: requestIdleCallback where available,
     * otherwise a zero timeout. Either way the host page's first paint and its own
     * scripts go first, and nothing above depends on this having finished.
     */
    function scheduleProbes() {
        var run = function () { T(markers); T(headless); T(uaClaimCheck); T(consistency); };
        if (typeof w.requestIdleCallback === 'function') {
            w.requestIdleCallback(run, { timeout: 2000 });
        } else {
            setTimeout(run, 0);
        }
    }
    scheduleProbes();

    /**
     * Transport state.
     *
     *   sid   session id, issued by the server
     *   tok   HMAC token, issued by the server
     *   dead  collector unreachable: go quiet, leave the page alone
     */
    var sid  = '';
    var tok  = '';
    var dead = false;

    /**
     * Build the payload. Keys are short because this goes out several times per
     * pageview under an 8 KB server-side cap. The mapping from these keys to Solr
     * fields is documented in docs/BEACON.md and implemented in src/Beacon.php.
     *
     * `e` is the event: 'h' hello, 'b' heartbeat, 'x' final. `w` is wall_ms. `u` is the
     * path ONLY, never the query string — `qp` carries the NAMED parameters and nothing
     * else, so the two together still never amount to the whole URL. `hn` is the hostname
     * the page is on, and `qp` is omitted entirely when no parameter was collected rather
     * than sent as an empty object, because an absent key costs nothing and an empty one
     * would have to be distinguished from a real one on the far side. The
     * `pl`/`mt`/`dp`/`sw`/`sh`/`aw`/`ah`/`ow`/`oh`
     * group is the raw environment measurement the SERVER cross-checks: navigator.platform
     * or the modern userAgentData.platform, and touch capability as a count, with
     * 'ontouchstart' covering older engines.
     *
     * Human-presence evidence is computed at send time so that it describes the whole
     * pageview so far rather than the state at load. `no_interaction` is deliberately
     * NOT emitted here: whether zero interactions is damning depends on how the session
     * ended, which only the server knows (see Beacon::derive()). The "tall page that was
     * never scrolled" test is here rather than on the server for the opposite reason —
     * on a short page it means nothing, and this is the only side of the wire that can
     * see the document height.
     */
    function payload(ev) {
        accrue();
        var codes = sig.slice(0);
        mouseCodes(codes);
        if (!scrolled && docH() > vpH() * 1.5) { codes.push('no_scroll_tall_page'); }

        var out = {
            v: 1,
            e: ev,
            s: sid,
            k: tok,
            p: pv,
            n: ++beat,
            w: Math.round(now() - t0),
            vi: Math.round(visMs),
            en: Math.round(engMs),
            ic: itCount,
            im: itMask,
            sp: Math.round(scrollPct),
            a: codes,
            uo: uaClaim,
            tz: tz,
            gl: webgl,
            u: (w.location.pathname || '').slice(0, 512),
            pl: ((NV.userAgentData && NV.userAgentData.platform) || NV.platform || '').slice(0, 32),
            mt: (NV.maxTouchPoints | 0) || ('ontouchstart' in w ? 1 : 0),
            dp: +w.devicePixelRatio || 0,
            sw: SC.width | 0,
            sh: SC.height | 0,
            aw: SC.availWidth | 0,
            ah: SC.availHeight | 0,
            ow: w.outerWidth | 0,
            oh: w.outerHeight | 0
        };

        if (xIdent) { out.xi = xIdent; }
        if (xSigned !== undefined) { out.xs = xSigned; }

        if (HOST) { out.hn = HOST; }

        var qp = urlParams();
        for (var k in qp) {
            if (Object.prototype.hasOwnProperty.call(qp, k)) { out.qp = qp; break; }
        }

        return out;
    }

    /**
     * The site's own hook for identity that arrives after the page has loaded.
     *
     * A single-page application signs somebody in without a navigation, so no script-tag
     * attribute can carry it. Both arguments are optional and independent: pass only an
     * identity, only a signed-in state, or both.
     *
     * IT SENDS NOTHING BY ITSELF. The values are stored and travel on the heartbeat that is
     * already scheduled, or on the final flush — which is what keeps the documented promise
     * that attaching identity costs the site no extra request. The heartbeat only fires when
     * engaged time advanced, so the sign-in itself is nudged along by clearing the last-sent
     * marker rather than by opening a socket.
     *
     * Wrapped in a try/catch like everything else that a host page can reach: a site calling
     * this with nonsense must not take an exception into its own code path.
     */
    function identify(ident, signedIn) {
        T(function () {
            if (typeof ident === 'string' && ident !== '') {
                xIdent = ident.slice(0, 128);
            }
            var state = tri(undefined, signedIn);
            if (state !== undefined) {
                xSigned = state;
            }
            sentEng = -1;
        });
    }

    w.loghound = w.loghound || {};
    w.loghound.identify = identify;

    /**
     * POST a body. `cb` receives the Response when one is available.
     *
     * keepalive lets the request outlive the document, which is what makes the
     * LAST pageview of a session measurable — the thing log-only analytics
     * structurally cannot do. text/plain keeps this a CORS "simple request": no
     * preflight, no OPTIONS round trip, byte-identical to what sendBeacon sends.
     * credentials:'omit' is stated explicitly because "this never sends cookies" is
     * a promise we make in the privacy documentation.
     */
    function post(body, cb) {
        var ok = T(function () {
            w.fetch(EP, {
                method: 'POST',
                body: body,
                headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
                credentials: 'omit',
                keepalive: true
            }).then(cb || function () {})['catch'](function () { dead = true; });
            return 1;
        });
        if (!ok) { dead = true; }
    }

    /**
     * Send a payload, preferring sendBeacon: the browser queues it and delivers it
     * even after the document is torn down.
     *
     * One try/catch covers building the payload as well as sending it: a throw anywhere
     * in here must cost us a data point, never break the host page.
     *
     * The body is wrapped in an explicit text/plain Blob, because some browsers send
     * application/octet-stream for a bare string and the collector accepts text/plain
     * and JSON only.
     */
    function send(ev) {
        if (dead || !sid || !tok) { return; }
        var body = T(function () { return JSON.stringify(payload(ev)); });
        if (!body) { return; }
        sentEng = engMs;
        if (T(function () {
            return NV.sendBeacon(EP, new Blob([body], { type: 'text/plain;charset=UTF-8' }));
        }) !== true) { post(body); }
    }

    /**
     * Final flush for this pageview. Sent at most once per pageview.
     *
     * It is wired to `pagehide`, which is the correct end-of-page event. `unload` is
     * NEVER used: it disables the back/forward cache in every modern browser —
     * measurably slowing the site down for real visitors — and it does not fire
     * reliably on mobile.
     */
    function flush() {
        if (!ended) { ended = true; send('x'); }
    }

    /**
     * Heartbeat, armed once the server has issued a session id and token.
     *
     * Only sends when engaged time actually advanced since the last send, so a tab
     * idling for an hour produces one beat, not 240. The heartbeat exists so that a tab
     * killed by the OS — or by a phone running out of memory — still leaves us data up
     * to the last beat.
     */
    function heartbeat() {
        T(function () {
            accrue();
            if (!ended && !dead && engMs > sentEng + 500) { send('b'); }
        });
    }

    /**
     * Handle the response to the first call.
     *
     * That call uses fetch rather than sendBeacon because it is the one call whose
     * RESPONSE we need: the collector answers 204 with no body (it must never reveal
     * whether a token was valid) and returns the session id and HMAC token in headers,
     * which is the only channel a bodiless response leaves open.
     *
     * If it fails for any reason we go quiet permanently rather than retrying in a loop
     * against a dead endpoint.
     */
    function onHello(r) {
        var s = T(function () { return r.headers.get('X-LH-S'); });
        var t = T(function () { return r.headers.get('X-LH-T'); });
        if (!s || !t) { dead = true; return; }
        sid = s;
        tok = t;
        setInterval(heartbeat, HB);
    }

    post(T(function () { return JSON.stringify(payload('h')); }) || '{}', onHello);

    on(w, 'pagehide', flush);

    /**
     * A bfcache restore: the page is alive again after being frozen, so this is a NEW
     * pageview with fresh clocks. Keeping the old ones would count time spent frozen in
     * the bfcache as time on site, which is exactly the class of lie this beacon exists
     * to stop telling.
     */
    function onPageShow(e) {
        if (e && e.persisted) { reset(); }
    }
    on(w, 'pageshow', onPageShow);
}(window, document));
