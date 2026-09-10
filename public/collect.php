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
 *     server-side source. IP, User-Agent, host and referer are read off the
 *     connection; a payload that supplies them is ignored.
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
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Beacon;
use Loghound\Config;
use Loghound\Security;

require_once dirname(__DIR__) . '/src/autoload.php';

// Warnings and notices must never reach the response body. Errors are logged to
// the PHP error log where an operator can see them; the visitor sees a 204.
ini_set('display_errors', '0');

/**
 * End the request.
 *
 * Always 204, always empty, whatever happened above. Optional headers carry the
 * session id and token on the beacon's first call — see the note on the hello
 * exchange further down for why a bodiless response forces us to use headers.
 *
 * @param array<string,string> $headers
 */
function lh_end(array $headers = []): void
{
    // Anything a bug upstream managed to print is thrown away rather than
    // corrupting the response.
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code(204);
    foreach ($headers as $k => $v) {
        header($k . ': ' . $v);
    }
    exit;
}

/* ---------------------------------------------------------------------- *
 * 1. Response headers that apply to every outcome
 * ---------------------------------------------------------------------- */

// The beacon runs on customer sites, i.e. on origins we do not know in advance,
// so the allow-list is open. This is safe here and only here: the endpoint takes
// no credentials (the beacon sends credentials:'omit', and there are no cookies
// to send in the first place), it returns no body, and it performs no action on
// behalf of a logged-in user. There is nothing for a hostile origin to steal by
// making this request that it could not achieve with curl.
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
// Without this the beacon's fetch() cannot read the two headers it needs.
header('Access-Control-Expose-Headers: X-LH-S, X-LH-T');
header('Access-Control-Max-Age: 86400');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');
// A collector response has no content and must never be sniffed as anything.
header_remove('Content-Type');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// A preflight should not happen — the beacon sends only CORS-simple requests —
// but a customer's CSP or a proxy may turn one into a preflight, and answering
// it costs nothing.
if ($method === 'OPTIONS') {
    lh_end();
}
if ($method !== 'POST') {
    lh_end();
}

/* ---------------------------------------------------------------------- *
 * 2. Content type and size, checked before any parsing work
 * ---------------------------------------------------------------------- */

$ctype = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
// navigator.sendBeacon sends text/plain; the fetch fallback sends the same. JSON
// is accepted so the endpoint can be driven by a normal HTTP client in tests.
// Everything else — multipart, form-encoded, octet-stream — is refused: those
// content types imply a request that was not built by our beacon.
if ($ctype !== '' && !str_starts_with($ctype, 'text/plain') && !str_starts_with($ctype, 'application/json')) {
    lh_end();
}

$config = Config::load(dirname(__DIR__) . '/config/loghound.php');
$beacon = new Beacon($config);
$maxPayload = $beacon->maxPayload();

// Refuse an over-sized body from the declared length before reading it, so a
// large upload is rejected at the front door rather than buffered first.
$declared = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($declared > $maxPayload) {
    lh_end();
}

// Read at most one byte more than the cap: enough to know it was exceeded,
// bounded enough that a lying Content-Length cannot make us allocate.
$raw = (string) file_get_contents('php://input', false, null, 0, $maxPayload + 1);
if ($raw === '' || strlen($raw) > $maxPayload) {
    lh_end();
}

/* ---------------------------------------------------------------------- *
 * 3. Configuration gates
 * ---------------------------------------------------------------------- */

if (!$config->get('beacon.enabled', true)) {
    lh_end();
}
// Without a secret there is no anti-forgery at all, and a collector that accepts
// unsigned timing claims is worse than no collector: it would publish numbers a
// stranger chose. Fail closed and stay silent.
if (strlen((string) $config->get('beacon.secret', '')) < 32) {
    lh_end();
}

/* ---------------------------------------------------------------------- *
 * 4. Parse and normalise the payload
 * ---------------------------------------------------------------------- */

$decoded = $beacon->decode($raw);
if ($decoded === null) {
    lh_end();
}
$payload = $beacon->normalise($decoded);

/* ---------------------------------------------------------------------- *
 * 5. Facts about the request, taken from the connection and nowhere else
 * ---------------------------------------------------------------------- */

// X-Forwarded-For is honoured only when the immediate peer is a proxy the
// operator configured. Otherwise any visitor could forge their own source
// address and walk straight through the rate limiter.
$ip = Security::clientIp((array) $config->get('trusted_proxies', []));
$ua = substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 512);
$clientKey = Beacon::clientKey($ip, $ua);

$state = lh_state();
$idleSec = Security::clampInt($config->get('ingest.session_idle_sec', 1800), 60, 86400, 1800);

/* ---------------------------------------------------------------------- *
 * 6. Rate limiting
 * ---------------------------------------------------------------------- */

$perMin = $beacon->ratePerMin();

// The bucket key is a keyed hash of the address, never the address itself: the
// rate-limit table would otherwise hold raw IPs of every visitor regardless of
// the configured privacy mode, which would quietly undo that setting.
$ipKey = 'ip:' . substr(hash_hmac('sha256', $ip, (string) $config->get('beacon.secret', '')), 0, 24);
if ($state !== null && !lh_allow($state, $ipKey, $perMin)) {
    lh_end();
}

/* ---------------------------------------------------------------------- *
 * 7. The token exchange
 * ---------------------------------------------------------------------- */

$sessionId = (string) $payload['session_id'];
$token     = (string) $payload['token'];
$isHello   = ($sessionId === '' || $token === '');
$respond   = [];

if ($isHello) {
    // FIRST CALL. The beacon has no session id yet, so it cannot present a token
    // and there is nothing to verify: this branch mints, it does not authorise.
    // It is protected by the rate limiter alone, which is why the limiter runs
    // before it.
    //
    // SPEC.md §6.4: the collector derives the same client_key the tailer uses
    // (ip_net + ua_hash) and attaches to the session already open for it. When
    // the log line has not been tailed yet — a race we lose often, because the
    // beacon fires while the access log entry is still buffered — we mint a
    // provisional id and store client_key alongside it, so loghound-score can
    // re-attach the rows to the real session once it appears.
    $sessionId = $state !== null ? (lh_open_session($state, $clientKey, $idleSec) ?? '') : '';
    if ($sessionId === '') {
        // No open session yet. We deliberately do NOT create one here: a public
        // endpoint must not be able to insert rows into sessions_open, and it does
        // not need to. The row is staged with its client_key, and State::beaconsFor()
        // matches on client_key as well as session id precisely so the scorer can
        // re-attach these payloads once the tailer opens the real session.
        // The provisional id exists only to bind the HMAC token to something.
        $sessionId = sha1($clientKey . '|' . time() . '|' . bin2hex(random_bytes(16)));
    }
    $issuedAt = time();
    $token = $beacon->issueToken($sessionId, $issuedAt);

    // A 204 has no body, and SPEC.md §6.3 requires that it never has one, so the
    // only channel left for handing the client its credentials is response
    // headers. They are exposed to the page's JS by Access-Control-Expose-Headers
    // above. This is a place where SPEC.md is silent and a choice had to be made;
    // it is documented in docs/BEACON.md.
    $respond['X-LH-S'] = $sessionId;
    $respond['X-LH-T'] = $token;
} else {
    // SUBSEQUENT CALLS. Reject a missing, malformed, forged, expired or
    // future-dated token. Rejected here means: no staging row, no diagnostics in
    // the response, same 204 as success.
    $issuedAt = $beacon->verifyToken($sessionId, $token);
    if ($issuedAt === null) {
        lh_end();
    }
}

// Per-session limit as well as per-IP. A fleet behind one NAT must not be able to
// exhaust a shared IP budget, and one session must not be able to flood on its
// own; the two limits catch different abuses.
if ($state !== null && !lh_allow($state, 'sess:' . $sessionId, $perMin)) {
    lh_end($respond);
}

/* ---------------------------------------------------------------------- *
 * 8. Timing sanity and server-side cross-checks
 * ---------------------------------------------------------------------- */

[$payload, $timingFlags] = $beacon->checkTimings($payload, $issuedAt);

// Merge: the client's own codes, the impossible-timing flag, and the consistency
// checks the server performs because it — not the client — holds the real UA.
$signals = array_values(array_unique(array_merge(
    (array) $payload['signals'],
    $timingFlags,
    $beacon->derive($payload, $ua)
)));

/* ---------------------------------------------------------------------- *
 * 9. Stage the row. SQLite only — never Solr, see the file header.
 * ---------------------------------------------------------------------- */

if ($state !== null) {
    // The session id and the client key are columns; everything else is the JSON
    // payload blob. The client key is stored so loghound-score can re-attach a
    // beacon that arrived before the matching log line was tailed (SPEC.md §6.4,
    // beacon_orphan_b).
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
        // The beacon's idea of the path. Informational only: the access log is the
        // authority on what was actually served (SPEC.md §6.4 — "the log wins on
        // facts, the beacon wins on time").
        'path'        => $payload['path'],
        // Stored under the configured privacy mode, exactly like a log hit.
        'ip'          => Security::applyIpPrivacy(
            $ip,
            (string) $config->get('privacy.ip_mode', 'full'),
            (string) $config->get('privacy.ip_salt', '')
        ),
        'ua_hash'     => sha1($ua),
    ]);
}

lh_end($respond);

/* ====================================================================== *
 * State access.
 *
 * ---------------------------------------------------------------------- *
 * This file uses exactly three State methods, and no other part of the system:
 *
 *   State::rateLimit(string $key, int $perMinute): bool
 *   State::findOpenSession(string $clientKey, int $idleSec, int $nowMs): ?array
 *   State::stageBeacon(?string $sessionId, ?string $clientKey, array $payload): void
 *
 * Every call is wrapped so that a locked, corrupt or read-only database degrades
 * to "no data recorded" instead of a 500 with a stack trace in it. On a public
 * endpoint a fatal error is an information leak, not just a bug — and losing a
 * beacon is a far smaller loss than telling the internet about our filesystem.
 * ---------------------------------------------------------------------- */

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
 * Look up the open session for a client key, if the tailer has already opened one.
 *
 * Read-only: this never creates a session. See the hello branch for why.
 */
function lh_open_session(object $state, string $clientKey, int $idleSec): ?string
{
    try {
        $row = $state->findOpenSession($clientKey, $idleSec, (int) (microtime(true) * 1000));
        $id = is_array($row) ? (string) ($row['session_id'] ?? '') : '';
        return $id !== '' ? $id : null;
    } catch (\Throwable $e) {
        error_log('loghound/collect.php: findOpenSession failed: ' . $e->getMessage());
    }
    return null;
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
