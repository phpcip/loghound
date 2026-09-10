<?php
/**
 * Loghound — Beacon server-side logic.
 *
 * Everything the server does with a beacon payload lives here: validating and
 * normalising what arrived on the wire, minting and checking the anti-forgery
 * token, catching impossible timing claims, deriving the consistency cross-checks
 * the client deliberately does NOT perform, and folding the staged rows into the
 * session document that the dashboard queries.
 *
 * WHERE THIS SITS IN THE PIPELINE
 *
 *   public/b.js            measures, probes, POSTs
 *   public/collect.php     public write path; validates via this class, then
 *                          stages a row in SQLite. Never touches Solr.
 *   bin/loghound-score     closes the session, calls mergeIntoSession() and
 *                          upserts the `sessions` document.
 *
 * TRUST BOUNDARY. Every value that reaches this class from a payload is
 * attacker-chosen. The only inputs that are trustworthy are the ones the collector
 * reads off the connection itself (IP, User-Agent) and the HMAC token we minted.
 * Nothing here interpolates a payload value into SQL, a shell command, a Solr
 * parameter or HTML: it returns plain PHP scalars for the caller to bind.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Beacon
{
    /** Wire protocol version. Bumped only on an incompatible payload change. */
    public const PROTOCOL = 1;

    /**
     * Hard ceilings. A payload claiming more than this is clamped, not believed.
     *
     * MAX_MS is 24 hours, longer than any honest pageview. MAX_SIGNALS is how many codes are
     * accepted from one payload and MAX_CODE_LEN the length of one code. MAX_STR bounds the
     * tz, webgl and platform fields.
     */
    public const MAX_MS          = 86400000;
    public const MAX_SIGNALS     = 40;
    public const MAX_CODE_LEN    = 40;
    public const MAX_STR         = 128;
    public const MAX_PATH        = 512;
    public const MAX_INTERACTIONS = 100000;

    /**
     * Slack allowed between a claimed wall_ms and the time actually elapsed since
     * the token was issued.
     *
     * The token's issued-at has one-second resolution and the beacon's clock starts
     * fractionally before the token is minted, so a few seconds of overshoot is
     * ordinary. Sixty seconds is the figure SPEC.md §6.3 fixes.
     */
    public const CLOCK_SLACK_SEC = 60;

    /**
     * Overshoot beyond the slack that is treated as a deliberate lie.
     *
     * Below this we clamp quietly (rounding, scheduling jitter, a heartbeat that
     * queued behind a busy main thread). Above it, the client is claiming time that
     * provably did not exist, and we record it.
     */
    public const FORGERY_TOLERANCE_MS = 5000;

    /**
     * Codes that, on their own, mean the "browser" is not a browser a person is
     * sitting in front of. Only these set `headless_b`.
     *
     * The weaker headless hints (no plugins, screen == availScreen, no
     * hardwareConcurrency) deliberately do NOT set it: each has a real-world
     * population of genuine humans behind it, and a boolean that is wrong for real
     * visitors is worse than no boolean at all. They still contribute to
     * `client_score_f` and are still listed in `automation_ss`.
     */
    public const HEADLESS_STRONG = [
        'headless_renderer',
        'headless_no_window_chrome',
        'headless_notif_contradiction',
        'headless_zero_outer',
    ];

    /**
     * Client-plane score contributions, 0-100 after clamping.
     *
     * This is NOT the verdict. `Score/Rules.php` owns `bot_score_f` and correlates
     * this plane with the transport and behaviour planes; `client_score_f` is one
     * input among many, recorded so the panel can show what the browser alone said.
     * Negative weights exist because positive evidence of a human is evidence.
     *
     * The table is grouped, in order: the definitive markers, where a driver announced
     * itself; the engine tells; the consistency cross-checks, which are derived server-side
     * in derive(); the human-presence evidence, or its absence; and finally the lie itself,
     * beacon_forged.
     */
    public const WEIGHTS = [
        'automation_webdriver'         => 100,
        'automation_cdc'               => 100,
        'automation_playwright'        => 100,
        'automation_puppeteer'         => 100,
        'automation_selenium'          => 100,
        'automation_nightmare'         => 100,
        'automation_phantom'           => 100,
        'automation_domauto'           => 100,
        'headless_renderer'            => 90,
        'ua_older_engine'              => 85,
        'ua_newer_engine'              => 85,
        'headless_notif_contradiction' => 45,
        'headless_no_window_chrome'    => 40,
        'headless_zero_outer'          => 40,
        'headless_no_languages'        => 25,
        'headless_no_plugins'          => 20,
        'headless_no_concurrency'      => 15,
        'headless_screen_eq_avail'     => 10,
        'headless_no_chrome_runtime'   => 10,
        'platform_mismatch'            => 35,
        'touch_missing_mobile'         => 30,
        'screen_outer_impossible'      => 25,
        'dpr_odd'                      => 10,
        'tz_unknown'                   => 5,
        'mouse_linear'                 => 40,
        'mouse_static'                 => 25,
        'no_interaction'               => 20,
        'no_scroll_tall_page'          => 10,
        'human_mouse_natural'          => -25,
        'beacon_forged'                => 90,
    ];

    /** @var array<string,mixed> The 'beacon' config section. */
    private array $cfg;

    private string $secret;

    /**
     * @param Config $config Full config; only the beacon section is read.
     */
    public function __construct(Config $config)
    {
        $this->cfg = (array) $config->get('beacon', []);
        $this->secret = (string) ($this->cfg['secret'] ?? '');
    }

    /** Maximum accepted request body size, in bytes. */
    public function maxPayload(): int
    {
        return Security::clampInt($this->cfg['max_payload'] ?? 8192, 256, 65536, 8192);
    }

    /** Requests per minute allowed from one bucket key. */
    public function ratePerMin(): int
    {
        return Security::clampInt($this->cfg['rate_per_min'] ?? 120, 1, 10000, 120);
    }

    /** Seconds after which a token is refused. */
    public function tokenMaxAge(): int
    {
        return Security::clampInt($this->cfg['token_max_age'] ?? 43200, 60, 604800, 43200);
    }

    /**
     * Mint a token for a session, bound to the Origin that asked for it.
     *
     * Thin wrapper over Security::mintToken so that callers never have to know the
     * token format, and so the format can change in exactly one place.
     *
     * The Origin is part of the signed material, which is what stops a third-party page
     * from speaking for somebody else's visit. The collector answers with
     * Access-Control-Allow-Origin: *, so any site on the internet can make a CORS-simple
     * POST from a visitor's browser — their IP, their User-Agent, therefore their
     * client_key — and read the response headers. Without this binding, the token it
     * received would be accepted on later calls and that page could report whatever it
     * liked about a real person's session; in a bot-detection product the obvious abuse is
     * to have a human recorded as headless automation. With it, a token minted for
     * https://evil.example is refused the moment it is presented from anywhere else, and
     * the rows it staged are attributable to the origin that staged them.
     *
     * A NUL separator is used because it cannot occur in either a session id or an Origin
     * header, so no pair of values can be made to collide by moving the boundary.
     */
    public function issueToken(string $sessionId, ?int $now = null, string $origin = ''): string
    {
        return Security::mintToken($this->secret, $sessionId . "\0" . $origin, $now ?? time());
    }

    /**
     * Verify a token against a session id and the Origin it was minted for.
     *
     * The Origin must be the same one issueToken() saw. A mismatch is indistinguishable
     * from a forged token and is refused the same way.
     *
     * @return int|null The issued-at timestamp, or null when the token is missing,
     *                  malformed, forged, expired, dated in the future, or presented
     *                  from a different Origin.
     */
    public function verifyToken(string $sessionId, string $token, string $origin = ''): ?int
    {
        if ($sessionId === '' || $token === '' || $this->secret === '') {
            return null;
        }
        return Security::verifyToken(
            $this->secret,
            $sessionId . "\0" . $origin,
            $token,
            $this->tokenMaxAge()
        );
    }

    /**
     * Decode a raw request body into an array, or null when it is not usable.
     *
     * Rejects, in order: an over-sized body (checked on the raw bytes, before any
     * parsing work is done on attacker-controlled data), anything that is not valid
     * JSON, and any JSON that is not an object — a bare array, string or number
     * would sail through later isset() checks as "empty payload".
     *
     * JSON_THROW_ON_ERROR is deliberately not used; a malformed body is an expected
     * condition on a public endpoint, not an exceptional one.
     *
     * The decode depth is 8, far more than the flat payload needs and low enough that a
     * deeply nested body cannot cost us stack while being parsed.
     */
    public function decode(string $raw): ?array
    {
        if ($raw === '' || strlen($raw) > $this->maxPayload()) {
            return null;
        }
        $data = json_decode($raw, true, 8);
        if (!is_array($data) || array_is_list($data)) {
            return null;
        }
        return $data;
    }

    /**
     * Normalise a decoded payload into canonical, typed, clamped fields.
     *
     * Nothing from the wire survives this function unexamined: every scalar is cast,
     * every string is length-limited and stripped of control characters, every
     * number is clamped into a possible range, and unknown keys are dropped. The
     * result is safe to bind into SQLite and safe to hand to mergeIntoSession().
     *
     * Note what is NOT taken from the payload: IP, User-Agent, host and referer. The
     * collector reads those from the connection. A client that sends them is ignored.
     *
     * Values are read once into a local before being tested. Testing the value and then
     * re-reading the key would let a null slip through the strict in_array() as -1 and then
     * cast to 0, meaning "the engine FAILED its UA check" — an accusation manufactured out of
     * a missing field. For the same reason the engine-check field is 1 for matched, 0 for not
     * matched and -1 for unknown, and anything else is unknown: an unparseable answer must
     * never read as "failed".
     *
     * The event kind is 'h' for hello, 'b' for heartbeat and 'x' for the final flush.
     * Anything else becomes 'b', the harmless interpretation. The pageview id is
     * client-generated and only ever used to group one pageview's heartbeats, so a
     * restrictive charset costs nothing. The environment measurements are stored raw here;
     * derive() is what turns them into codes.
     *
     * @param array<string,mixed> $in
     * @return array<string,mixed>
     */
    public function normalise(array $in): array
    {
        $wall    = $this->num($in['w']  ?? 0, 0, self::MAX_MS);
        $visible = $this->num($in['vi'] ?? 0, 0, self::MAX_MS);
        $engaged = $this->num($in['en'] ?? 0, 0, self::MAX_MS);

        $uaClaim = $in['uo'] ?? -1;

        return [
            'protocol'    => (int) $this->num($in['v'] ?? 0, 0, 1000),
            'event'       => in_array($in['e'] ?? '', ['h', 'b', 'x'], true) ? (string) $in['e'] : 'b',
            'session_id'  => $this->token($in['s'] ?? '', 64),
            'token'       => $this->token($in['k'] ?? '', 128),
            'pv'          => $this->token($in['p'] ?? '', 32),
            'beat'        => (int) $this->num($in['n'] ?? 0, 0, 100000),

            'wall_ms'     => (int) $wall,
            'visible_ms'  => (int) $visible,
            'engaged_ms'  => (int) $engaged,

            'interactions' => (int) $this->num($in['ic'] ?? 0, 0, self::MAX_INTERACTIONS),
            'itypes_mask'  => (int) $this->num($in['im'] ?? 0, 0, 127),
            'scroll_pct'   => (int) $this->num($in['sp'] ?? 0, 0, 100),

            'signals'      => $this->codes($in['a'] ?? []),
            'ua_claim'     => in_array($uaClaim, [0, 1, -1], true) ? (int) $uaClaim : -1,
            'tz'           => $this->text($in['tz'] ?? '', self::MAX_STR),
            'webgl'        => $this->text($in['gl'] ?? '', self::MAX_STR),
            'path'         => $this->text($in['u'] ?? '', self::MAX_PATH),

            'platform'     => $this->text($in['pl'] ?? '', self::MAX_STR),
            'touch'        => (int) $this->num($in['mt'] ?? 0, 0, 32),
            'dpr'          => round((float) $this->num($in['dp'] ?? 0, 0, 32), 3),
            'screen_w'     => (int) $this->num($in['sw'] ?? 0, 0, 100000),
            'screen_h'     => (int) $this->num($in['sh'] ?? 0, 0, 100000),
            'avail_w'      => (int) $this->num($in['aw'] ?? 0, 0, 100000),
            'avail_h'      => (int) $this->num($in['ah'] ?? 0, 0, 100000),
            'outer_w'      => (int) $this->num($in['ow'] ?? 0, 0, 100000),
            'outer_h'      => (int) $this->num($in['oh'] ?? 0, 0, 100000),
        ];
    }

    /**
     * Apply the timing sanity rules from SPEC.md §6.3.
     *
     * Two independent impossibilities are checked:
     *
     *   1. The clocks must nest: engaged <= visible <= wall. They are accumulated by
     *      the same code path in b.js, so an inversion cannot happen honestly.
     *   2. wall_ms cannot exceed the time that has actually passed since we minted
     *      the token, plus slack. This is the one the forger always trips: a client
     *      claiming four hours of engagement thirty seconds after being issued a
     *      token is asserting time that did not exist.
     *
     * WHY WE KEEP THE RECORD INSTEAD OF DROPPING IT. Discarding a forged payload
     * would leave the session looking like every other session with no beacon —
     * that is, indistinguishable from a visitor on a slow connection. The lie is
     * far more informative than the absence: nothing that is not deliberately
     * inflating its dwell time ever does this. So we clamp the numbers to what is
     * possible and attach `beacon_forged`, which Score/Rules.php weights at 90.
     *
     * Small overshoots are clamped SILENTLY: one-second token resolution plus a
     * heartbeat queued behind a busy main thread produces a couple of seconds of
     * honest overshoot, and flagging that would be a false accusation.
     *
     * The wall-clock ceiling is computed first, floored at zero, because a token issued in
     * the future — clock skew between two machines — would otherwise make it negative. The
     * other two clocks are then nested under the corrected wall clock, with an inversion
     * large enough to be deliberate recorded and a small one simply clamped.
     *
     * @param array<string,mixed> $p        A normalised payload.
     * @param int                 $issuedAt Token issue time (unix seconds).
     * @param int|null            $now      Injectable clock, for tests.
     * @return array{0:array<string,mixed>,1:string[]} Corrected payload, extra codes.
     */
    public function checkTimings(array $p, int $issuedAt, ?int $now = null): array
    {
        $now = $now ?? time();
        $flags = [];

        $wall    = (int) ($p['wall_ms'] ?? 0);
        $visible = (int) ($p['visible_ms'] ?? 0);
        $engaged = (int) ($p['engaged_ms'] ?? 0);

        $elapsed = max(0, $now - $issuedAt);
        $ceiling = ($elapsed + self::CLOCK_SLACK_SEC) * 1000;

        if ($wall > $ceiling + self::FORGERY_TOLERANCE_MS) {
            $flags[] = 'beacon_forged';
        }
        if ($wall > $ceiling) {
            $wall = $ceiling;
        }

        if ($visible > $wall) {
            if ($visible - $wall > self::FORGERY_TOLERANCE_MS && !in_array('beacon_forged', $flags, true)) {
                $flags[] = 'beacon_forged';
            }
            $visible = $wall;
        }
        if ($engaged > $visible) {
            if ($engaged - $visible > self::FORGERY_TOLERANCE_MS && !in_array('beacon_forged', $flags, true)) {
                $flags[] = 'beacon_forged';
            }
            $engaged = $visible;
        }

        $p['wall_ms']    = $wall;
        $p['visible_ms'] = $visible;
        $p['engaged_ms'] = $engaged;

        return [$p, $flags];
    }

    /**
     * Derive the consistency cross-checks that b.js deliberately does not perform.
     *
     * The beacon reports raw measurements and the server compares them, for three
     * reasons documented at length in b.js §4.4: the server holds the authoritative
     * User-Agent (read off the connection, not out of the payload), a client cannot
     * suppress a comparison it never performs, and the thresholds can be tuned
     * without redeploying a script tag to every customer's site.
     *
     * Every check below is conservative by construction: when the measurement is
     * missing (0 / empty) nothing is emitted, because "unknown" must never become
     * "guilty".
     *
     * The platform check compares navigator.platform against the OS the UA claims. Android
     * reports its platform as "Linux armv8l", so Linux is an acceptable answer for an Android
     * UA — but not the reverse. The touch check fires on a UA claiming a phone or tablet from
     * a device with no touch support at all; the reverse is NOT checked, because that would
     * flag every touchscreen laptop.
     *
     * Everything after that compares display measurements against each other, so it needs the
     * payload to have carried display measurements at all. A truncated write, an older client
     * or a browser that exposed nothing reports zeroes, and "no data" must never be read as
     * "a window with no size", which is a strong signal that sets headless_b. Unknown is not
     * guilty.
     *
     * Within those: a window with no outer dimensions is not on a screen, though it is
     * legitimately zero inside some cross-origin iframes, which is why it is a hint rather
     * than proof. A window cannot be meaningfully larger than the screen it sits on, with
     * slack for multi-monitor setups and browser chrome. A screen with no taskbar or window
     * chrome anywhere is common on Linux kiosks and full-screen presentations too, hence
     * weak. And devicePixelRatio absent or zero on a client that DID report a screen counts,
     * while fractional values do not: those are normal under Windows display scaling, so only
     * impossible values are treated as evidence.
     *
     * @param array<string,mixed> $p  A normalised payload.
     * @param string $connUa The User-Agent read from the connection.
     * @return string[] Extra signal codes.
     */
    public function derive(array $p, string $connUa): array
    {
        $out = [];

        $uaOs     = self::osOf($connUa);
        $uaMobile = (bool) preg_match('/Android|iPhone|iPad|iPod|Mobile|Windows Phone/i', $connUa);

        $platOs = self::osOf((string) ($p['platform'] ?? ''));
        if ($uaOs !== '' && $platOs !== '' && $uaOs !== $platOs && !($uaOs === 'a' && $platOs === 'l')) {
            $out[] = 'platform_mismatch';
        }

        if ($uaMobile && (int) ($p['touch'] ?? 0) === 0) {
            $out[] = 'touch_missing_mobile';
        }

        $sw = (int) ($p['screen_w'] ?? 0);
        $sh = (int) ($p['screen_h'] ?? 0);
        $ow = (int) ($p['outer_w'] ?? 0);
        $oh = (int) ($p['outer_h'] ?? 0);

        if ($sw <= 0 || $sh <= 0) {
            return $out;
        }

        if ($ow === 0 || $oh === 0) {
            $out[] = 'headless_zero_outer';
        } elseif ($ow > $sw + 64 || $oh > $sh + 128) {
            $out[] = 'screen_outer_impossible';
        }

        if (!$uaMobile
            && (int) ($p['avail_w'] ?? 0) === $sw
            && (int) ($p['avail_h'] ?? 0) === $sh) {
            $out[] = 'headless_screen_eq_avail';
        }

        if ((float) ($p['dpr'] ?? 0) <= 0) {
            $out[] = 'dpr_odd';
        }

        return $out;
    }

    /**
     * Fold staged beacon rows into a session document.
     *
     * Each row is one POST. A pageview normally produces several — a hello, some
     * heartbeats and a final flush — and every one of them carries the CUMULATIVE
     * counters for that pageview, not a delta. So the fold is:
     *
     *     per pageview: take the MAXIMUM of each counter (the latest beat wins,
     *                   and an out-of-order or lost beat cannot reduce the total)
     *     per session:  SUM those per-pageview maxima
     *
     * Summing the rows directly instead would multiply a ten-minute pageview by its
     * number of heartbeats, which is exactly the kind of quietly wrong number this
     * project exists to stop publishing.
     *
     * WHEN NO BEACON ARRIVED the timing fields are ABSENT from the returned
     * document — not zero. SPEC.md §1 forbids zero-filling, and the reason is
     * arithmetic: a zero is a value, so it enters every average, every median and
     * every percentile as a real "0 seconds engaged" observation. Ten thousand
     * beacon-less bot sessions would then drag the site's average engagement to
     * nearly nothing and the number would be worse than useless — it would be
     * confidently wrong. Absent means the aggregate simply covers a smaller
     * population, which every chart is required to state.
     *
     * ROW SHAPE. State::beaconsFor() returns
     * `['id' => int, 'received_at' => int, 'payload' => array]`, where the payload
     * is the JSON blob collect.php staged. A flat row — the fields at the top level
     * — is also accepted, so a caller reading the table directly, and every test in
     * tests/test_beacon.php, works without an adapter in between.
     *
     * When no rows arrived, plane 3 says nothing was received. That is itself a fact worth
     * recording — it is what drives the `no_js_on_html` rule — but it is the ONLY thing that
     * may be recorded: no timings, no counters, no score.
     *
     * A row with no pageview id, from an ancient client or a truncated write, still counts;
     * it gets its own bucket keyed by the row id. Signals are stored as a JSON array in the
     * staging row. Codes come back in a stable order so that a re-merge produces an identical
     * document.
     *
     * Zero interactions across the whole session is a session-level judgement, which is why
     * b.js does not emit it: only the server knows the session is over. Score/Rules.php
     * weights it at 40 once the session has ended.
     *
     * Two fields are deliberately absent rather than false. The engine check is absent when
     * every payload said "unknown", because a browser we could not test is not a browser that
     * failed the test. tz_match_b compares the browser's IANA zone against the one derived
     * from the IP's geolocation and is absent when either side is unknown — a session with no
     * geo data has neither passed nor failed.
     *
     * @param array<string,mixed>        $session    The session doc built from the log.
     * @param array<int,array<string,mixed>> $beaconRows Rows from `beacon_staging`.
     * @return array<string,mixed> The session doc with beacon fields folded in.
     */
    public function mergeIntoSession(array $session, array $beaconRows): array
    {
        if ($beaconRows === []) {
            $session['beacon_b'] = false;
            $session['js_b'] = false;
            return $session;
        }

        /** @var array<string,array<string,mixed>> $pvs Latest state per pageview. */
        $pvs = [];
        $codes = [];
        $uaClaimFailed = false;
        $uaClaimSeen = false;
        $tz = '';
        $webgl = '';

        foreach ($beaconRows as $row) {
            $rowId = $row['id'] ?? null;
            if (isset($row['payload']) && is_array($row['payload'])) {
                $row = $row['payload'];
                $row['id'] = $rowId;
            }

            $pv = (string) ($row['pv'] ?? '');
            if ($pv === '') {
                $pv = '#' . (string) ($row['id'] ?? count($pvs));
            }
            if (!isset($pvs[$pv])) {
                $pvs[$pv] = [
                    'wall_ms' => 0, 'visible_ms' => 0, 'engaged_ms' => 0,
                    'interactions' => 0, 'scroll_pct' => 0,
                ];
            }
            foreach (['wall_ms', 'visible_ms', 'engaged_ms', 'interactions', 'scroll_pct'] as $k) {
                $v = (int) ($row[$k] ?? 0);
                if ($v > $pvs[$pv][$k]) {
                    $pvs[$pv][$k] = $v;
                }
            }

            $sig = $row['signals'] ?? [];
            if (is_string($sig)) {
                $decoded = json_decode($sig, true);
                $sig = is_array($decoded) ? $decoded : [];
            }
            foreach ((array) $sig as $c) {
                if (is_string($c) && $c !== '') {
                    $codes[$c] = true;
                }
            }

            $claim = (int) ($row['ua_claim'] ?? -1);
            if ($claim === 0) {
                $uaClaimFailed = true;
                $uaClaimSeen = true;
            } elseif ($claim === 1) {
                $uaClaimSeen = true;
            }

            if ($tz === '' && !empty($row['tz'])) {
                $tz = (string) $row['tz'];
            }
            if ($webgl === '' && !empty($row['webgl'])) {
                $webgl = (string) $row['webgl'];
            }
        }

        $wall = $visible = $engaged = $interactions = $maxScroll = 0;
        foreach ($pvs as $pvTotals) {
            $wall         += $pvTotals['wall_ms'];
            $visible      += $pvTotals['visible_ms'];
            $engaged      += $pvTotals['engaged_ms'];
            $interactions += $pvTotals['interactions'];
            if ($pvTotals['scroll_pct'] > $maxScroll) {
                $maxScroll = $pvTotals['scroll_pct'];
            }
        }

        if ($interactions === 0) {
            $codes['no_interaction'] = true;
        }

        $session['beacon_b']         = true;
        $session['js_b']             = true;
        $session['wall_ms_l']        = $wall;
        $session['visible_ms_l']     = $visible;
        $session['engaged_ms_l']     = $engaged;
        $session['interactions_i']   = $interactions;
        $session['max_scroll_pct_i'] = $maxScroll;
        $session['pageviews_i']      = count($pvs);

        $codeList = array_keys($codes);
        sort($codeList);
        $session['automation_ss'] = $codeList;

        $session['headless_b'] = false;
        foreach ($codeList as $c) {
            if (in_array($c, self::HEADLESS_STRONG, true) || str_starts_with($c, 'automation_')) {
                $session['headless_b'] = true;
                break;
            }
        }

        if ($uaClaimSeen) {
            $session['ua_claim_ok_b'] = !$uaClaimFailed;
        }

        if ($webgl !== '') {
            $session['webgl_s'] = $webgl;
        }

        $geoTz = (string) ($session['tz_s'] ?? '');
        if ($tz !== '' && $geoTz !== '') {
            $session['tz_match_b'] = ($tz === $geoTz);
            if ($tz !== $geoTz) {
                $codeList[] = 'tz_mismatch';
                $session['automation_ss'] = $codeList;
            }
        }

        $session['client_score_f'] = self::clientScore($codeList);

        return $session;
    }

    /**
     * Score the execution plane alone, 0-100.
     *
     * Additive over WEIGHTS, clamped. Not a verdict: Score/Rules.php combines this
     * with the transport and behaviour planes and owns `bot_score_f`. Codes with no
     * weight contribute nothing, so adding a new signal to b.js can never change an
     * existing score until a weight is chosen for it deliberately.
     *
     * @param string[] $codes
     */
    public static function clientScore(array $codes): float
    {
        $score = 0.0;
        foreach ($codes as $c) {
            $score += (float) (self::WEIGHTS[$c] ?? 0);
        }
        return (float) max(0, min(100, round($score, 1)));
    }

    /**
     * Count the distinct interaction types in the bitmask b.js sends as `im`.
     *
     * Bits: 0 mousemove, 1 scroll, 2 keydown, 3 click, 4 pointerdown,
     * 5 touchstart, 6 wheel. The mask is carried rather than a count so the panel
     * can show WHICH kinds of interaction occurred: a session with only mousemove
     * looks very different from one with keydown and click.
     */
    public static function interactionTypes(int $mask): int
    {
        $n = 0;
        for ($i = 0; $i < 7; $i++) {
            if ($mask & (1 << $i)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * The client key used to match a beacon to the session the tailer opened.
     *
     * MUST stay identical to Sessionizer.php's definition (SPEC.md §5.4:
     * `client_key = ip_net + ua_hash`), or beacons and log lines will never meet
     * and every session will look like a `beacon_orphan_b`.
     */
    public static function clientKey(string $ip, string $ua): string
    {
        return Security::ipNetwork($ip) . '|' . sha1($ua);
    }

    /**
     * Collapse an OS name or a UA string to a single letter: a/i/w/m/l, or ''.
     *
     * Android is tested first because an Android UA also contains "Linux", and iOS
     * before Mac because iPadOS UAs contain "Mac OS X".
     */
    public static function osOf(string $s): string
    {
        if (preg_match('/Android/i', $s)) {
            return 'a';
        }
        if (preg_match('/iPhone|iPad|iPod|iOS/i', $s)) {
            return 'i';
        }
        if (preg_match('/Win/i', $s)) {
            return 'w';
        }
        if (preg_match('/Mac/i', $s)) {
            return 'm';
        }
        if (preg_match('/Linux|X11|CrOS/i', $s)) {
            return 'l';
        }
        return '';
    }

    /**
     * Coerce to a number inside [min, max]. Non-numeric input becomes $min rather
     * than throwing: a public endpoint receives garbage as a matter of routine.
     *
     * NAN and INF are rejected explicitly, because they survive is_numeric() when they arrive
     * as strings.
     *
     * @param mixed $v
     */
    private function num($v, float $min, float $max): float
    {
        if (is_bool($v) || !is_numeric($v)) {
            return $min;
        }
        $n = (float) $v;
        if (!is_finite($n)) {
            return $min;
        }
        return max($min, min($max, $n));
    }

    /**
     * An opaque identifier: base64url-ish characters only, length-capped.
     *
     * Session ids and tokens are compared with hash_equals and stored in SQLite as
     * bound parameters, so this is defence in depth rather than the only guard —
     * but it also means a session id can never carry a newline into a log line or a
     * quote into a panel template.
     *
     * @param mixed $v
     */
    private function token($v, int $max): string
    {
        if (!is_string($v)) {
            return '';
        }
        $v = substr($v, 0, $max);
        return preg_match('/^[A-Za-z0-9._\-]*$/', $v) ? $v : '';
    }

    /**
     * Free text from the client: control characters removed, length-capped, valid
     * UTF-8 enforced.
     *
     * Invalid UTF-8 is not a curiosity here — it is how a payload gets a string
     * past one layer's escaping and into another's. mb_convert_encoding replaces
     * the bad sequences rather than rejecting the whole field.
     *
     * @param mixed $v
     */
    private function text($v, int $max): string
    {
        if (!is_string($v) || $v === '') {
            return '';
        }
        $v = substr($v, 0, $max);
        $v = preg_replace('/[\x00-\x1F\x7F]/u', '', $v) ?? '';
        if (!mb_check_encoding($v, 'UTF-8')) {
            $v = mb_convert_encoding($v, 'UTF-8', 'UTF-8');
        }
        return $v;
    }

    /**
     * The signal-code array: strings from a restricted charset, de-duplicated and
     * capped in both count and length.
     *
     * These codes are facetted in Solr and rendered in the panel, so the charset is
     * locked to what a code may legitimately contain. A payload inventing its own
     * codes can therefore pollute a facet with junk names but can never inject
     * anything, and unknown codes carry zero weight in clientScore().
     *
     * An over-length code is DROPPED, not truncated. Truncating would coin a brand-new facet
     * value out of a hostile string and leave it sitting in the panel's signal list looking
     * like something we defined.
     *
     * @param mixed $v
     * @return string[]
     */
    /**
     * Is this a signal code the SERVER decides, rather than one the client reports?
     *
     * The collector is public and unauthenticated, so every code arriving from the wire is
     * an assertion by an untrusted party about itself. Most are harmless measurements —
     * "no plugins", "zero outer height" — and the scoring engine treats them as evidence,
     * not proof. A few carry decisive weight: `automation_*` alone sets headless_b and a
     * client_score of 100, which in a bot-detection product is the difference between a
     * visitor being counted and a visitor being accused.
     *
     * Those are exactly the codes Beacon::derive() computes here from measurements the
     * server can check, so accepting the client's version buys nothing and costs the
     * ability to be lied to. A page could otherwise submit `automation_webdriver` for a
     * real person and have them recorded as a headless bot.
     *
     * Scoped to exactly the codes derive() produces, and no wider. The automation_* and
     * most headless_* codes are NOT in this list on purpose: they can only be observed from
     * inside the page — navigator.webdriver, the chromedriver globals, the WebGL renderer
     * string — and refusing them from the wire would delete the strongest detection signals
     * the product has. They are defended by binding the token to an Origin instead, so a
     * third-party page cannot obtain credentials for a visitor's session in the first place.
     *
     * What this stops is narrower and still worth stopping: a client pre-empting or
     * contradicting a verdict the server reaches from its own measurements, which would let
     * a page suppress a finding by asserting the opposite before derive() runs.
     */
    private static function isServerDerivedCode(string $code): bool
    {
        return in_array($code, [
            'platform_mismatch',
            'touch_missing_mobile',
            'headless_zero_outer',
            'screen_outer_impossible',
            'beacon_forged',
        ], true);
    }

    private function codes($v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $c) {
            if (!is_string($c) || $c === '' || strlen($c) > self::MAX_CODE_LEN) {
                continue;
            }
            if (!preg_match('/^[a-z0-9_]+$/', $c)) {
                continue;
            }
            if (self::isServerDerivedCode($c)) {
                continue;
            }
            $out[$c] = true;
            if (count($out) >= self::MAX_SIGNALS) {
                break;
            }
        }
        return array_keys($out);
    }
}
