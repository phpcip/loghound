<?php
/**
 * Loghound — beacon collector.
 *
 * ============================================================================
 * THIS IS A PUBLIC, UNAUTHENTICATED WRITE PATH. EVERY BYTE IS HOSTILE.
 * ============================================================================
 * Anyone on the internet can POST here as often as they can open sockets. The
 * rules this file lives by:
 *
 *   - It NEVER trusts a value in the payload for anything that has a
 *     server-side source. IP, User-Agent and referer are read off the
 *     connection; a payload that supplies them is ignored. The one value with
 *     no server-side source is the hostname of the page the beacon is running
 *     on — the page is on a different machine, so `HTTP_HOST` here names the
 *     Loghound host and not the measured site — and it is cross-checked against
 *     the Origin header the browser sets and required to be on a configured
 *     allowlist before it counts for anything. See lh_site().
 *   - It NEVER trusts client-supplied timings. Every number is bounded against
 *     the HMAC token we minted, and an impossible claim is recorded as evidence
 *     rather than believed (see Beacon::checkTimings).
 *   - It ALWAYS answers 204 with an empty body, whatever happened. Success,
 *     bad token, rate limit, malformed JSON, disabled beacon: identical
 *     response. An attacker must not be able to use this endpoint as an oracle
 *     for whether a session id exists or a token is valid.
 *   - It NEVER touches Solr. Two reasons, and both matter:
 *       1. COST. A Solr write per beacon would put an indexing round-trip in
 *          front of every visitor on every page, several times per pageview.
 *          A local SQLite insert is microseconds; loghound-score batches the
 *          real indexing out of band, on our schedule, not the visitor's.
 *       2. CREDENTIALS. The Solr/Opensolr credentials live in the config that
 *          the daemons read. The public endpoint never loads a code path that
 *          needs them, so a remote-code-execution bug HERE — the most exposed
 *          file in the project — does not hand over the search backend.
 *     Writes go to the SQLite `beacon_staging` table and nowhere else.
 *   - It NEVER emits output. No echo, no var_dump, no warnings. Anything this
 *     file prints would land inside a 204 and break the contract above.
 *     Warnings and notices must never reach the response body; errors go to the
 *     PHP error log where an operator can see them, and the visitor sees a 204.
 *     Anything a bug upstream managed to print is thrown away rather than
 *     corrupting the response.
 *
 * ----------------------------------------------------------------------------
 * THE REQUEST, STEP BY STEP
 * ----------------------------------------------------------------------------
 *
 * 1. RESPONSE HEADERS THAT APPLY TO EVERY OUTCOME. The beacon runs on customer
 *    sites, that is on origins we do not know in advance, so the allow-list is
 *    open. That is safe here and only here: the endpoint takes no credentials
 *    (the beacon sends credentials:'omit', and there are no cookies to send in
 *    the first place), it returns no body, and it performs no action on behalf
 *    of a logged-in user. There is nothing for a hostile origin to steal by
 *    making this request that it could not achieve with curl.
 *    Access-Control-Expose-Headers is required or the beacon's fetch() cannot
 *    read the two headers it needs. A collector response has no content and
 *    must never be sniffed as anything. A preflight should not happen, since
 *    the beacon sends only CORS-simple requests, but a customer's CSP or a
 *    proxy may turn one into a preflight and answering it costs nothing.
 *
 * 2. CONTENT TYPE AND SIZE, checked before any parsing work.
 *    navigator.sendBeacon sends text/plain and the fetch fallback sends the
 *    same; JSON is accepted too so the endpoint can be driven by a normal HTTP
 *    client in tests. Everything else — multipart, form-encoded, octet-stream —
 *    is refused, because those content types imply a request that was not built
 *    by our beacon. An over-sized body is refused from its declared length
 *    before being read, so a large upload is rejected at the front door rather
 *    than buffered first, and the read itself takes at most one byte more than
 *    the cap: enough to know it was exceeded, bounded enough that a lying
 *    Content-Length cannot make us allocate.
 *
 * 3. CONFIGURATION GATES. Without a secret there is no anti-forgery at all, and
 *    a collector that accepts unsigned timing claims is worse than no collector:
 *    it would publish numbers a stranger chose. Fail closed and stay silent.
 *
 * 4. PARSE AND NORMALISE THE PAYLOAD.
 *
 * 5. FACTS ABOUT THE REQUEST, taken from the connection and nowhere else.
 *    X-Forwarded-For is honoured only when the immediate peer is a proxy the
 *    operator configured; otherwise any visitor could forge their own source
 *    address and walk straight through the rate limiter.
 *
 * 6. RATE LIMITING. The bucket key is a keyed hash of the address, never the
 *    address itself: the rate-limit table would otherwise hold raw IPs of every
 *    visitor regardless of the configured privacy mode, quietly undoing that
 *    setting. THREE buckets, catching three different abuses: per address, per
 *    session, and per measured HOSTNAME. The third exists because a listed
 *    hostname is the only kind of beacon that can cause a session to be written,
 *    so a registered site must not be a way around the limiter — it is the one
 *    place where a flood costs index writes rather than a discarded row. It is
 *    hashed for the same reason the address is, and it is applied before the
 *    token exchange so it bounds hellos too.
 *
 * 6b. WHICH SITE IS THIS, IF ANY (lh_site()). The hostname the page reported, the
 *    Origin the browser set and the operator's allowlist all have to agree before
 *    the hostname or the search terms are recorded at all. Everything that does
 *    not agree keeps today's behaviour exactly, which is what makes this change
 *    additive rather than a loosening.
 *
 * 7. THE TOKEN EXCHANGE. On the FIRST call the beacon has no session id, so it
 *    cannot present a token and there is nothing to verify: that branch mints,
 *    it does not authorise, and it is protected by the rate limiter alone —
 *    which is why the limiter runs before it. The id it mints is ALWAYS a fresh
 *    random value, never the id of the session already open for this client_key.
 *    Returning the real id would be a serious hole: this endpoint answers with
 *    Access-Control-Allow-Origin: *, so any page on the internet can make a
 *    CORS-simple POST from a visitor's browser — their IP, their User-Agent,
 *    therefore their client_key — read X-LH-S and X-LH-T off the response, and
 *    then submit whatever it likes about that visitor's real session. In a
 *    bot-detection product the obvious abuse is to report a human as headless
 *    automation. A provisional id costs nothing, because State::beaconsFor()
 *    matches on client_key as well as session id: loghound-score re-attaches
 *    the staged rows to the real session once the log line has been tailed.
 *    No open session is ever CREATED here either — a public endpoint must not
 *    be able to insert rows into sessions_open. The provisional id exists only
 *    to bind the HMAC token to something.
 *    A 204 has no body and SPEC.md §6.3 requires that it never has one, so the
 *    only channel left for handing the client its credentials is response
 *    headers, exposed to the page's JS by Access-Control-Expose-Headers above.
 *    SPEC.md is silent there and a choice had to be made; it is documented in
 *    docs/BEACON.md. On SUBSEQUENT calls a missing, malformed, forged, expired
 *    or future-dated token is rejected, and rejected means: no staging row, no
 *    diagnostics in the response, the same 204 as success. A per-session limit
 *    applies as well as the per-IP one — a fleet behind one NAT must not be able
 *    to exhaust a shared IP budget, and one session must not be able to flood on
 *    its own; the two limits catch different abuses.
 *
 * 8. TIMING SANITY AND SERVER-SIDE CROSS-CHECKS. The codes merged onto the row
 *    are the client's own, plus the impossible-timing flag, plus the consistency
 *    checks the server performs because it — not the client — holds the real UA.
 *
 * 9. STAGE THE ROW. SQLite only, never Solr, for the reasons above. The session
 *    id and the client key are columns and everything else is the JSON payload
 *    blob; the client key is stored so loghound-score can re-attach a beacon
 *    that arrived before the matching log line was tailed (SPEC.md §6.4).
 *    Until it does, that session is `planes_s: beacon_only` — an observation about
 *    which planes have seen it, never a suspicion. The path the beacon reports is
 *    informational only: the
 *    access log is the authority on what was actually served (SPEC.md §6.4 —
 *    "the log wins on facts, the beacon wins on time"). The address is stored
 *    under the configured privacy mode, exactly like a log hit.
 *    Two fields on the row come from the measured SITE rather than from the
 *    browser: the identity string it chose to attach, and whether the visitor
 *    was signed in. Both are caller-supplied and therefore hostile — they are
 *    bounded, stripped of control characters and validated by
 *    Beacon::normalise() before they reach here, and either can be switched off
 *    in configuration, in which case normalise() empties the field and nothing
 *    is staged at all. The signed-in state is three-state: `null` means the site
 *    said nothing, and it must never be stored as "anonymous".
 *    Three more come from the site's IDENTITY rather than from the browser, and
 *    all three are written only when lh_site() returned a hostname: the hostname
 *    itself, the whitelisted URL parameters kept as search terms, and the
 *    User-Agent. The User-Agent is read off the connection like always — what
 *    the gate decides is whether it is STORED, and it is stored only for a site
 *    that may produce a standalone session, because that session has no log line
 *    to take a User-Agent from and would otherwise have no browser, OS or device
 *    at all. For every other beacon nothing but the hash is staged, exactly as
 *    before.
 *
 * ----------------------------------------------------------------------------
 * STATE ACCESS
 * ----------------------------------------------------------------------------
 * This file uses exactly two State methods, and no other part of the system:
 *
 *   State::rateLimit(string $key, int $perMinute): bool
 *   State::stageBeacon(?string $sessionId, ?string $clientKey, array $payload): void
 *
 * findOpenSession() is deliberately NOT among them. The hello branch used to look up the
 * client's real open session so it could hand back its id, and the fix for that hole — mint
 * a provisional id instead, always — left the lookup with no caller. Reinstating it would
 * reinstate the hole: this endpoint answers every origin, so anything it returns about a
 * visitor's real session is returned to whoever asked, not to whoever owns it.
 *
 * Every call is wrapped so that a locked, corrupt or read-only database degrades
 * to "no data recorded" instead of a 500 with a stack trace in it. On a public
 * endpoint a fatal error is an information leak, not just a bug — and losing a
 * beacon is a far smaller loss than telling the internet about our filesystem.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Beacon;
use Loghound\Config;
use Loghound\Exclusions;
use Loghound\Security;

require_once dirname(__DIR__) . '/src/autoload.php';

ini_set('display_errors', '0');

/**
 * End the request.
 *
 * Always 204, always empty, whatever happened above. Optional headers carry the
 * session id and token on the beacon's first call — see the note on the token
 * exchange in the file header for why a bodiless response forces us to use headers.
 *
 * Anything a bug upstream managed to print is discarded rather than allowed to
 * corrupt the response.
 *
 * @param array<string,string> $headers
 */
function lh_end(array $headers = []): void
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code(204);
    foreach ($headers as $k => $v) {
        header($k . ': ' . $v);
    }
    exit;
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Expose-Headers: X-LH-S, X-LH-T');
header('Access-Control-Max-Age: 86400');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');
header_remove('Content-Type');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'OPTIONS') {
    lh_end();
}
if ($method !== 'POST') {
    lh_end();
}

$ctype = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
if ($ctype !== '' && !str_starts_with($ctype, 'text/plain') && !str_starts_with($ctype, 'application/json')) {
    lh_end();
}

$config = Config::load(dirname(__DIR__) . '/config/loghound.php');
$beacon = new Beacon($config);
$maxPayload = $beacon->maxPayload();

$declared = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($declared > $maxPayload) {
    lh_end();
}

$raw = (string) file_get_contents('php://input', false, null, 0, $maxPayload + 1);
if ($raw === '' || strlen($raw) > $maxPayload) {
    lh_end();
}

if (!$config->get('beacon.enabled', true)) {
    lh_end();
}
if (strlen((string) $config->get('beacon.secret', '')) < 32) {
    lh_end();
}

$decoded = $beacon->decode($raw);
if ($decoded === null) {
    lh_end();
}
$payload = $beacon->normalise($decoded);

$ip = Security::clientIp((array) $config->get('trusted_proxies', []));
$ua = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512);
$clientKey = Beacon::clientKey($ip, $ua);

$state = lh_state();

$perMin = $beacon->ratePerMin();

/* THE BUCKET IS PER NETWORK, NOT PER ADDRESS. Keyed on the full address it was no limit at
   all in one very ordinary case: the default allocation on essentially every VPS is an IPv6
   /64, which is 2^64 distinct buckets each with its own full budget, and every request that
   is even REFUSED writes a row into the ratelimit table (State::rateLimit upserts before it
   decides). Security::ipNetwork with a /32 for v4 and a /64 for v6 gives an attacker exactly
   one bucket per allocation they actually had to obtain, and leaves a v4 visitor's bucket
   precisely where it was. */
$ipKey = 'ip:' . substr(
    hash_hmac('sha256', Security::ipNetwork($ip, 32, 64), (string) $config->get('beacon.secret', '')),
    0,
    24
);
if ($state !== null && !lh_allow($state, $ipKey, $perMin)) {
    lh_end();
}

$origin = lh_origin();

$site = lh_site($beacon, $payload, $origin);

if ($site !== '' && $state !== null) {
    $hostKey = 'host:' . substr(hash_hmac('sha256', $site, (string) $config->get('beacon.secret', '')), 0, 24);
    if (!lh_allow($state, $hostKey, $beacon->ratePerMinHost())) {
        lh_end();
    }
}

/* EXCLUDED ON BOTH PLANES OR ON NEITHER. The same rules the tailer applies to a log line are
   applied here to a beacon payload, because an operator who excludes /health and still sees
   beacon sessions for it has been told something untrue by the settings card. Refused before
   anything is staged, so the payload leaves no trace at all — and answered with the same 204
   as every other outcome, because the collector never tells a visitor's browser what this
   installation does or does not keep. */
$exclusions = Exclusions::fromConfig($config);
if (!$exclusions->isEmpty() && $exclusions->excludes($site, [
    'path' => (string) ($payload['path'] ?? ''),
    'ip'   => $ip,
    'ua'   => $ua,
])) {
    lh_end();
}

$sessionId = (string) $payload['session_id'];
$token     = (string) $payload['token'];
$isHello   = ($sessionId === '' || $token === '');
$respond   = [];

if ($isHello) {
    $sessionId = 'b' . bin2hex(random_bytes(20));
    $issuedAt = time();
    $token = $beacon->issueToken($sessionId, $issuedAt, $origin);

    $respond['X-LH-S'] = $sessionId;
    $respond['X-LH-T'] = $token;
} else {
    $issuedAt = $beacon->verifyToken($sessionId, $token, $origin);
    if ($issuedAt === null) {
        lh_end();
    }
}

/* NOT ON THE HELLO BRANCH. The id there was minted three lines ago from random_bytes, so its
   bucket is always brand new and always full: the check could never refuse, and its only
   effect was to write one ratelimit row per hello keyed by a value nothing will ever present
   again — an unbounded table fed by the most cheaply-repeatable request this endpoint takes,
   purged only by the daily retention pass. Hellos are bounded by the address bucket above,
   which is where a request with no session to speak of belongs. */
if (!$isHello && $state !== null && !lh_allow($state, 'sess:' . $sessionId, $perMin)) {
    lh_end($respond);
}

[$payload, $timingFlags] = $beacon->checkTimings($payload, $issuedAt);

$signals = $beacon->signalsFor($payload, $ua, $site, $timingFlags);

if ($state !== null) {
    lh_stage($state, $sessionId, $clientKey, [
        'pv'          => $payload['pv'],
        'beat'        => $payload['beat'],
        'event'       => $payload['event'],
        'wall_ms'     => $payload['wall_ms'],
        'visible_ms'  => $payload['visible_ms'],
        'engaged_ms'  => $payload['engaged_ms'],
        'interactions' => $payload['interactions'],
        'itypes_mask' => $payload['itypes_mask'],
        'scroll_pct'  => $payload['scroll_pct'],
        'signals'     => json_encode($signals, JSON_UNESCAPED_SLASHES),
        'ua_claim'    => $payload['ua_claim'],
        'tz'          => $payload['tz'],
        'webgl'       => $payload['webgl'],
        'path'        => $payload['path'],
        'ident'       => $payload['ident'],
        'signed_in'   => $payload['signed_in'],
        'host'        => $site,
        'terms'       => $site === '' ? [] : $payload['terms'],
        'ip'          => Security::applyIpPrivacy(
            $ip,
            (string) $config->get('privacy.ip_mode', 'full'),
            (string) $config->get('privacy.ip_salt', '')
        ),
        'ua'          => $site === '' ? '' : $ua,
        'ua_hash'     => sha1($ua),
    ]);
}

lh_end($respond);

/**
 * Open the SQLite state database, or return null if that is not possible.
 */
function lh_state(): ?object
{
    static $state = false;
    if ($state !== false) {
        return $state;
    }
    $state = null;
    try {
        $state = new \Loghound\State(dirname(__DIR__) . '/var/state.db');
    } catch (\Throwable $e) {
        error_log('loghound/collect.php: state open failed: ' . $e->getMessage());
        $state = null;
    }
    return $state;
}

/**
 * Consume one token from a bucket. Returns true when the request may proceed.
 *
 * FAILS OPEN by design. If the limiter itself is broken, dropping every beacon
 * would silently destroy the product's headline metric, whereas the worst case of
 * failing open is that a flood reaches an INSERT that is already cheap and is
 * additionally bounded by the webserver's own connection limits.
 */
function lh_allow(object $state, string $key, int $perMinute): bool
{
    try {
        return (bool) $state->rateLimit($key, $perMinute);
    } catch (\Throwable $e) {
        error_log('loghound/collect.php: rateLimit failed: ' . $e->getMessage());
    }
    return true;
}

/**
 * The Origin this request came from, normalised for use as signed token material.
 *
 * A cross-origin fetch always carries an Origin header, and the beacon is cross-origin
 * by construction: it runs on the monitored site and posts to the Loghound host. Binding
 * the token to this value is what stops a third-party page from obtaining credentials for
 * somebody else's session, since the token it is handed is only ever valid when presented
 * from the same origin again.
 *
 * Lower-cased and length-capped so that a header differing only in case or padded to
 * absurd length cannot be used to mint two tokens that ought to be one, or to bloat the
 * hashed material. An absent header — a same-origin request, or a client that sends none —
 * normalises to the empty string, which is a value like any other: consistent between mint
 * and verify, and therefore still bound.
 */
function lh_origin(): string
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if (!is_string($origin) || $origin === '') {
        return '';
    }
    return strtolower(substr($origin, 0, 255));
}

/**
 * Which of the operator's sites is this beacon running on, if any.
 *
 * Returns the hostname when the beacon may speak for a site the operator listed, and the
 * EMPTY STRING for everything else — which is not an error and is by far the commonest
 * answer. An empty result means the request keeps precisely the behaviour this endpoint has
 * always had: a provisional id, a staged row, merge-only, no session created, no hostname and
 * no search term recorded anywhere.
 *
 * THREE FACTS, AND ALL THREE HAVE TO AGREE.
 *
 * 1. What the PAGE says it is. `location.hostname`, carried in the payload. It is the only
 *    party that knows, because the page is on a different machine from this collector and
 *    `$_SERVER['HTTP_HOST']` here names the Loghound host. It is also entirely
 *    attacker-chosen, so on its own it is worth nothing.
 *
 * 2. What the BROWSER says it is. The Origin header, set by the user agent on every
 *    cross-origin request and NOT settable by page script: a page on evil.example cannot
 *    make a browser send `Origin: search.opensolr.com`. This is the fact that makes the
 *    first one worth reading. The two are required to agree, and a disagreement is
 *    interesting rather than merely wrong — it means the request was not built by a browser
 *    running on the page it claims — so it is refused rather than reconciled.
 *
 *    A request with no Origin at all is refused for this purpose too. The beacon is
 *    cross-origin by construction, so a browser running it always sends one; a request
 *    without one is either a same-origin call (the Loghound host measuring itself, which has
 *    a log source and does not need this path) or something that is not a browser.
 *
 * 3. What the OPERATOR says. The hostname has to be on `beacon.allowed_hosts`. This is the
 *    permission, and it is the only one: see Beacon::allowedHosts() for what being on it does
 *    and does not buy, and docs/BEACON.md for the same thing in the words an operator reads.
 *
 * WHAT THIS DOES NOT STOP, stated here because the code is where it matters. Nothing that is
 * not a browser is bound by rule 2 — curl sends whatever headers it is told to — so somebody
 * who knows a hostname is on the list can forge beacons attributed to it. The allowlist is a
 * permission, not an authentication, and the product's answer to that is not to pretend
 * otherwise: it is that a session with no transport plane behind it is published MARKED as
 * having none (`planes_s:beacon_only`), so no number that includes it can be read as though
 * three planes agreed.
 *
 * @param array<string,mixed> $payload A normalised payload.
 * @param string              $origin  The Origin header, already normalised by lh_origin().
 */
function lh_site(Beacon $beacon, array $payload, string $origin): string
{
    $claimed = (string) ($payload['hostname'] ?? '');
    if ($claimed === '') {
        return '';
    }

    $fromOrigin = Beacon::originHost($origin);
    if ($fromOrigin === '' || $fromOrigin !== $claimed) {
        return '';
    }

    return $beacon->hostAllowed($claimed) ? $claimed : '';
}

/**
 * Insert one staging row.
 *
 * @param array<string,mixed> $payload
 */
function lh_stage(object $state, string $sessionId, string $clientKey, array $payload): void
{
    try {
        $state->stageBeacon($sessionId, $clientKey, $payload);
    } catch (\Throwable $e) {
        error_log('loghound/collect.php: stageBeacon failed: ' . $e->getMessage());
    }
}
