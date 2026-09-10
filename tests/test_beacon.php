<?php
/**
 * Loghound — beacon tests.
 *
 * Returns an array of named closures; tests/run.php discovers every
 * tests/test_*.php and executes them. A closure signals failure by throwing and
 * signals success by returning true, which satisfies both a throw-based and a
 * boolean-based runner.
 *
 * What these prove, in the order the file is written:
 *   - the HMAC token accepts exactly one thing and rejects everything else
 *     (tampered, truncated, wrong session, expired, dated in the future)
 *   - an impossible timing claim is CAUGHT, CLAMPED and FLAGGED rather than
 *     silently accepted or silently dropped
 *   - honest overshoot is clamped without an accusation
 *   - oversized and malformed payloads never reach the staging path
 *   - normalise() turns hostile input into typed, bounded values
 *   - mergeIntoSession() leaves every timing field ABSENT when no beacon arrived,
 *     and folds heartbeats per pageview instead of summing them
 *
 * No network, no filesystem writes, no SQLite: everything here is pure functions
 * over arrays, which is why Beacon.php was written to keep them that way.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/src/autoload.php';

use Loghound\Beacon;
use Loghound\Config;
use Loghound\Security;

/**
 * Build a Beacon with a known secret. Config::load() on a path that does not
 * exist yields the defaults, which is exactly the fixture we want.
 */
$lhBeacon = static function (): Beacon {
    $cfg = Config::load('/nonexistent/loghound-test-config.php');
    $cfg->set('beacon.secret', str_repeat('k', 48));
    return new Beacon($cfg);
};

/** Throw unless $cond holds. */
$ok = static function (bool $cond, string $msg): void {
    if (!$cond) {
        throw new RuntimeException($msg);
    }
};

/** Throw unless the two values are identical. */
$eq = static function ($expected, $actual, string $msg): void {
    if ($expected !== $actual) {
        throw new RuntimeException(sprintf(
            '%s — expected %s, got %s',
            $msg,
            var_export($expected, true),
            var_export($actual, true)
        ));
    }
};

return [

    /* ================================================================== *
     * Token flow
     * ================================================================== */

    'beacon: a freshly minted token verifies' => static function () use ($lhBeacon, $ok, $eq) {
        $b = $lhBeacon();
        $now = time();
        $sid = 'sess-abc123';
        $token = $b->issueToken($sid, $now);
        $issued = $b->verifyToken($sid, $token);
        $ok($issued !== null, 'a token minted one moment ago must verify');
        $eq($now, $issued, 'verifyToken must return the issued-at it was minted with');
        return true;
    },

    'beacon: a tampered token is rejected' => static function () use ($lhBeacon, $ok) {
        $b = $lhBeacon();
        $now = time();
        $sid = 'sess-abc123';
        $token = $b->issueToken($sid, $now);

        // Flip one character of the MAC. hash_equals must not care where.
        $mac = substr($token, -1) === 'a' ? 'b' : 'a';
        $tampered = substr($token, 0, -1) . $mac;
        $ok($b->verifyToken($sid, $tampered) === null, 'a token with an altered MAC must be refused');

        // Move the issued-at without re-signing: the classic way to extend a token.
        $parts = explode('.', $token, 2);
        $moved = ((int) $parts[0] - 7200) . '.' . $parts[1];
        $ok($b->verifyToken($sid, $moved) === null, 'a token with a rewritten issued-at must be refused');

        // The same token presented for a different session must not work, or one
        // stolen token would authorise every session on the site.
        $ok($b->verifyToken('sess-other', $token) === null, 'a token is bound to its session id');

        // Structural garbage.
        foreach (['', 'x', 'abc.def', '.', '12345', str_repeat('a', 200)] as $junk) {
            $ok($b->verifyToken($sid, $junk) === null, 'malformed token accepted: ' . $junk);
        }
        return true;
    },

    'beacon: expired and future-dated tokens are rejected' => static function () use ($lhBeacon, $ok) {
        $b = $lhBeacon();
        $sid = 'sess-abc123';

        // One second past the 12h maximum age.
        $expired = $b->issueToken($sid, time() - ($b->tokenMaxAge() + 1));
        $ok($b->verifyToken($sid, $expired) === null, 'an expired token must be refused');

        // Still valid one second inside the window — the boundary must not be
        // so tight that a long-lived tab is thrown away early.
        $fresh = $b->issueToken($sid, time() - ($b->tokenMaxAge() - 10));
        $ok($b->verifyToken($sid, $fresh) !== null, 'a token just inside the window must verify');

        // Dated in the future. A token from the future is as broken as an expired
        // one, and is what a client that rewound the clock would produce.
        $future = $b->issueToken($sid, time() + 3600);
        $ok($b->verifyToken($sid, $future) === null, 'a future-dated token must be refused');

        // ...but a little clock slack is allowed, because two machines never agree.
        $slack = $b->issueToken($sid, time() + 5);
        $ok($b->verifyToken($sid, $slack) !== null, '5s of clock skew must not break a token');
        return true;
    },

    'beacon: an empty secret verifies nothing' => static function ($_ = null) use ($ok) {
        // A misconfigured install must not silently accept every token. collect.php
        // refuses to run at all in this state; this is the belt to that braces.
        $cfg = Config::load('/nonexistent/loghound-test-config.php');
        $b = new Beacon($cfg); // secret defaults to ''
        $token = Security::mintToken('', 'sess', time());
        $ok($b->verifyToken('sess', $token) === null, 'no secret configured must mean no valid tokens');
        return true;
    },

    /* ================================================================== *
     * Timing sanity — the anti-forgery rule
     * ================================================================== */

    'beacon: four hours of engagement thirty seconds after the token is a lie' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            $issuedAt = 1_700_000_000;
            $now = $issuedAt + 30;      // the token is thirty seconds old

            $p = $b->normalise([
                'w'  => 4 * 3600 * 1000,   // four hours of wall clock
                'vi' => 4 * 3600 * 1000,
                'en' => 4 * 3600 * 1000,   // ...all of it "engaged"
            ]);
            [$fixed, $flags] = $b->checkTimings($p, $issuedAt, $now);

            $ok(in_array('beacon_forged', $flags, true), 'an impossible dwell claim must raise beacon_forged');

            // Clamped to what could actually have happened: 30s elapsed + 60s slack.
            $ceiling = (30 + Beacon::CLOCK_SLACK_SEC) * 1000;
            $eq($ceiling, $fixed['wall_ms'], 'wall_ms must be clamped to the token ceiling');
            $eq($ceiling, $fixed['visible_ms'], 'visible_ms must not exceed wall_ms');
            $eq($ceiling, $fixed['engaged_ms'], 'engaged_ms must not exceed visible_ms');

            // The record is kept, not discarded: the lie is evidence. A dropped
            // record would be indistinguishable from a visitor on a bad connection.
            $ok($fixed['wall_ms'] > 0, 'a forged payload is corrected and kept, never zeroed away');
            return true;
        },

    'beacon: honest overshoot is clamped without an accusation' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            $issuedAt = 1_700_000_000;
            $now = $issuedAt + 30;
            $ceiling = (30 + Beacon::CLOCK_SLACK_SEC) * 1000;

            // Two seconds over the ceiling: one-second token resolution plus a
            // heartbeat that queued behind a busy main thread. Flagging this would
            // be a false accusation against a real visitor.
            $p = $b->normalise(['w' => $ceiling + 2000, 'vi' => 1000, 'en' => 500]);
            [$fixed, $flags] = $b->checkTimings($p, $issuedAt, $now);

            $eq([], $flags, 'a small overshoot must not be called forgery');
            $eq($ceiling, $fixed['wall_ms'], 'a small overshoot is still clamped');
            $eq(1000, $fixed['visible_ms'], 'an in-range visible_ms must be left alone');
            $eq(500, $fixed['engaged_ms'], 'an in-range engaged_ms must be left alone');
            return true;
        },

    'beacon: inverted clocks are clamped into their nesting order' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            $issuedAt = 1_700_000_000;
            $now = $issuedAt + 600;

            // engaged > visible > wall is impossible by construction in b.js.
            $p = $b->normalise(['w' => 50000, 'vi' => 60000, 'en' => 70000]);
            [$fixed, $flags] = $b->checkTimings($p, $issuedAt, $now);

            $eq(50000, $fixed['wall_ms'], 'wall_ms was inside the ceiling and must survive');
            $eq(50000, $fixed['visible_ms'], 'visible_ms must be clamped down to wall_ms');
            $eq(50000, $fixed['engaged_ms'], 'engaged_ms must be clamped down to visible_ms');
            $ok(in_array('beacon_forged', $flags, true), 'a 10s inversion is deliberate and must be flagged');
            $eq(1, count($flags), 'beacon_forged must be recorded once, not once per inverted pair');

            // A one-millisecond inversion is rounding, not fraud.
            $p2 = $b->normalise(['w' => 50000, 'vi' => 50001, 'en' => 50000]);
            [$fixed2, $flags2] = $b->checkTimings($p2, $issuedAt, $now);
            $eq([], $flags2, 'a 1ms inversion must not be called forgery');
            $eq(50000, $fixed2['visible_ms'], 'a 1ms inversion is still clamped');
            return true;
        },

    'beacon: a negative or absurd duration cannot get past normalise' =>
        static function () use ($lhBeacon, $eq) {
            $b = $lhBeacon();
            $p = $b->normalise([
                'w'  => -5000,
                'vi' => 'NaN',
                'en' => 1e30,
                'ic' => -1,
                'sp' => 1000,
                'im' => 99999,
            ]);
            $eq(0, $p['wall_ms'], 'a negative duration must floor at zero');
            $eq(0, $p['visible_ms'], 'a non-numeric duration must floor at zero');
            $eq(Beacon::MAX_MS, $p['engaged_ms'], 'an absurd duration must clamp to the 24h ceiling');
            $eq(0, $p['interactions'], 'a negative interaction count must floor at zero');
            $eq(100, $p['scroll_pct'], 'scroll depth must clamp to 100%');
            $eq(127, $p['itypes_mask'], 'the interaction mask must clamp to its seven bits');
            return true;
        },

    /* ================================================================== *
     * Payload validation
     * ================================================================== */

    'beacon: oversized payloads are rejected' => static function () use ($lhBeacon, $ok) {
        $b = $lhBeacon();
        $max = $b->maxPayload();

        // Valid JSON, one byte too long. Structure must not buy an exemption.
        $filler = str_repeat('a', $max);
        $big = json_encode(['v' => 1, 'tz' => $filler]);
        $ok(strlen($big) > $max, 'test fixture must actually exceed the cap');
        $ok($b->decode($big) === null, 'an oversized body must be refused');

        // Exactly at the cap is accepted: the limit is a limit, not a trap.
        $pad = $max - strlen(json_encode(['v' => 1, 'tz' => '']));
        $atCap = json_encode(['v' => 1, 'tz' => str_repeat('a', $pad)]);
        $ok(strlen($atCap) === $max, 'test fixture must sit exactly on the cap');
        $ok($b->decode($atCap) !== null, 'a body exactly at the cap must be accepted');
        return true;
    },

    'beacon: malformed payloads are rejected' => static function () use ($lhBeacon, $ok) {
        $b = $lhBeacon();
        $bad = [
            ''                    => 'an empty body',
            'not json at all'     => 'plain text',
            '{'                   => 'truncated JSON',
            '[1,2,3]'             => 'a JSON array rather than an object',
            '"just a string"'     => 'a bare JSON string',
            '12345'               => 'a bare JSON number',
            'null'                => 'JSON null',
            '{"a":' . str_repeat('[', 40) . '}' => 'a deeply nested body',
        ];
        foreach ($bad as $body => $why) {
            $ok($b->decode((string) $body) === null, 'decode must refuse ' . $why);
        }
        // A minimal well-formed object is accepted.
        $ok($b->decode('{"v":1}') !== null, 'a well-formed object must be accepted');
        return true;
    },

    'beacon: hostile strings are neutralised, never trusted' => static function () use ($lhBeacon, $ok, $eq) {
        $b = $lhBeacon();
        $p = $b->normalise([
            's'  => "sess'; DROP TABLE beacon_staging;--",
            'k'  => "tok\nX-Injected: 1",
            'p'  => '../../etc/passwd',
            'tz' => "Europe/\x00Bucharest\r\n",
            'gl' => '<script>alert(1)</script>',
            'u'  => str_repeat('/deep', 400),
            'a'  => ['good_code', 'BAD-CODE', '<script>', 'x', str_repeat('z', 100)],
            'e'  => 'evil',
        ]);

        // Identifiers are charset-restricted: anything outside it is discarded
        // whole rather than half-cleaned, because a half-cleaned identifier is
        // still an identifier somebody chose.
        $eq('', $p['session_id'], 'a session id with SQL in it must be discarded');
        $eq('', $p['token'], 'a token containing CRLF must be discarded');
        $eq('', $p['pv'], 'a pageview id containing a path must be discarded');

        // Free text keeps its meaning but loses its control characters.
        $ok(!str_contains($p['tz'], "\x00"), 'NUL must not survive in free text');
        $ok(!str_contains($p['tz'], "\r"), 'CR must not survive in free text');
        $eq('Europe/Bucharest', $p['tz'], 'the readable part of the timezone must survive');

        // The WebGL renderer is stored verbatim; escaping is the panel's job at the
        // point of output, and doing it here would corrupt legitimate renderer
        // strings. What matters is that it is length-capped and control-free.
        $ok(strlen($p['webgl']) <= Beacon::MAX_STR, 'the renderer string must be length-capped');
        $ok(strlen($p['path']) <= Beacon::MAX_PATH, 'the path must be length-capped');

        // Signal codes are what the panel facets on, so the charset is locked and
        // an over-length code is dropped rather than truncated into a new one.
        $eq(['good_code', 'x'], $p['signals'], 'only well-formed signal codes may survive');

        // An unknown event kind becomes the harmless one.
        $eq('b', $p['event'], 'an unknown event kind must degrade to a heartbeat');
        return true;
    },

    'beacon: an unparseable ua_claim reads as unknown, never as failed' =>
        static function () use ($lhBeacon, $eq) {
            $b = $lhBeacon();
            // A false "the engine does not match its UA" is an accusation. Anything
            // that is not literally 0 or 1 must land on -1 (unknown).
            foreach ([null, 'yes', 2, -5, [], 1.5] as $junk) {
                $eq(-1, $b->normalise(['uo' => $junk])['ua_claim'], 'junk ua_claim must read as unknown');
            }
            $eq(0, $b->normalise(['uo' => 0])['ua_claim'], 'an explicit failure must survive');
            $eq(1, $b->normalise(['uo' => 1])['ua_claim'], 'an explicit pass must survive');
            return true;
        },

    /* ================================================================== *
     * Server-side cross-checks
     * ================================================================== */

    'beacon: consistency cross-checks fire on contradiction and stay silent on unknowns' =>
        static function () use ($lhBeacon, $ok) {
            $b = $lhBeacon();
            $win = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                 . 'Chrome/122.0.0.0 Safari/537.36';
            $iphone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 '
                    . '(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

            // A Windows UA on a machine that says it is a Mac.
            $codes = $b->derive($b->normalise([
                'pl' => 'MacIntel', 'dp' => 2, 'sw' => 1920, 'sh' => 1080,
                'aw' => 1920, 'ah' => 1040, 'ow' => 1600, 'oh' => 900, 'mt' => 0,
            ]), $win);
            $ok(in_array('platform_mismatch', $codes, true), 'Windows UA + MacIntel platform must be flagged');

            // An honest Windows desktop must be entirely clean.
            $clean = $b->derive($b->normalise([
                'pl' => 'Win32', 'dp' => 1.25, 'sw' => 1920, 'sh' => 1080,
                'aw' => 1920, 'ah' => 1040, 'ow' => 1600, 'oh' => 900, 'mt' => 0,
            ]), $win);
            $ok($clean === [], 'an ordinary Windows desktop must raise nothing: ' . implode(',', $clean));

            // Android reports platform "Linux armv8l"; that must NOT be a mismatch.
            $android = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) '
                     . 'Chrome/122.0.0.0 Mobile Safari/537.36';
            $codes = $b->derive($b->normalise([
                'pl' => 'Linux armv8l', 'dp' => 2.625, 'sw' => 412, 'sh' => 915,
                'aw' => 412, 'ah' => 915, 'ow' => 412, 'oh' => 915, 'mt' => 5,
            ]), $android);
            $ok(!in_array('platform_mismatch', $codes, true), 'Android on Linux platform must not be flagged');
            // availScreen == screen is normal on a phone, so it must not fire there.
            $ok(!in_array('headless_screen_eq_avail', $codes, true), 'a phone must not trip the taskbar check');

            // A phone UA with no touch support at all.
            $codes = $b->derive($b->normalise([
                'pl' => 'iPhone', 'dp' => 3, 'sw' => 390, 'sh' => 844,
                'aw' => 390, 'ah' => 844, 'ow' => 390, 'oh' => 844, 'mt' => 0,
            ]), $iphone);
            $ok(in_array('touch_missing_mobile', $codes, true), 'a phone UA without touch must be flagged');

            // A payload that carried NO environment data at all must be completely
            // silent. This is the rule the whole file turns on: "no data" must never
            // read as "a window with no size", which would set headless_b on a
            // truncated write or an older client. Unknown is not guilty.
            $codes = $b->derive($b->normalise([]), '');
            $ok($codes === [], 'an empty payload must raise nothing at all: ' . implode(',', $codes));

            // ...but a client that DID report a screen and then claims a zero-sized
            // window is saying something, and that is recorded.
            $codes = $b->derive($b->normalise([
                'pl' => 'Win32', 'dp' => 1, 'sw' => 1920, 'sh' => 1080,
                'aw' => 1920, 'ah' => 1040, 'ow' => 0, 'oh' => 0, 'mt' => 0,
            ]), $win);
            $ok(in_array('headless_zero_outer', $codes, true), 'a real screen with a zero window is a signal');
            return true;
        },

    /* ================================================================== *
     * mergeIntoSession
     * ================================================================== */

    'beacon: with no beacon, every timing field is ABSENT, never zero' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            $session = ['id' => 's1', 'hits_i' => 4, 'tz_s' => 'Europe/Bucharest'];
            $out = $b->mergeIntoSession($session, []);

            // This is the rule SPEC.md §1 states and the reason it exists: a zero is
            // a value. It would enter every average as a genuine "0 seconds engaged"
            // observation, and ten thousand beacon-less bot sessions would then drag
            // the site's reported engagement to nearly nothing — confidently wrong,
            // which is worse than missing.
            foreach ([
                'wall_ms_l', 'visible_ms_l', 'engaged_ms_l', 'interactions_i',
                'max_scroll_pct_i', 'pageviews_i', 'client_score_f', 'automation_ss',
                'headless_b', 'ua_claim_ok_b', 'tz_match_b', 'webgl_s',
            ] as $field) {
                $ok(!array_key_exists($field, $out), $field . ' must be absent when no beacon arrived');
            }

            // The two things we DO know are recorded.
            $eq(false, $out['beacon_b'], 'beacon_b must be false, not absent');
            $eq(false, $out['js_b'], 'js_b must be false when nothing ever executed');
            // And nothing already on the session was disturbed.
            $eq(4, $out['hits_i'], 'merging must not damage the log-derived fields');
            return true;
        },

    'beacon: heartbeats fold per pageview and sum across them' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();

            // Two pageviews. The first sent three cumulative beats; summing rows
            // instead of taking the per-pageview maximum would report 15s of wall
            // clock for a 9s pageview, which is the class of quietly-wrong number
            // this project exists to stop publishing.
            $rows = [
                ['id' => 1, 'pv' => 'a', 'wall_ms' => 1000, 'visible_ms' => 900, 'engaged_ms' => 800,
                 'interactions' => 1, 'scroll_pct' => 10, 'signals' => '["human_mouse_natural"]',
                 'ua_claim' => 1, 'tz' => 'Europe/Bucharest', 'webgl' => 'Apple M2'],
                ['id' => 2, 'pv' => 'a', 'wall_ms' => 5000, 'visible_ms' => 4000, 'engaged_ms' => 3000,
                 'interactions' => 4, 'scroll_pct' => 55, 'signals' => '["human_mouse_natural"]',
                 'ua_claim' => 1, 'tz' => 'Europe/Bucharest', 'webgl' => 'Apple M2'],
                ['id' => 3, 'pv' => 'a', 'wall_ms' => 9000, 'visible_ms' => 6000, 'engaged_ms' => 4500,
                 'interactions' => 9, 'scroll_pct' => 80, 'signals' => '["human_mouse_natural"]',
                 'ua_claim' => 1, 'tz' => 'Europe/Bucharest', 'webgl' => 'Apple M2'],
                ['id' => 4, 'pv' => 'b', 'wall_ms' => 2000, 'visible_ms' => 2000, 'engaged_ms' => 1500,
                 'interactions' => 3, 'scroll_pct' => 30, 'signals' => '[]',
                 'ua_claim' => 1, 'tz' => 'Europe/Bucharest', 'webgl' => ''],
            ];
            $out = $b->mergeIntoSession(['id' => 's1', 'tz_s' => 'Europe/Bucharest'], $rows);

            $eq(11000, $out['wall_ms_l'], 'wall: max per pageview (9000) plus the second pageview (2000)');
            $eq(8000, $out['visible_ms_l'], 'visible: 6000 + 2000');
            $eq(6000, $out['engaged_ms_l'], 'engaged: 4500 + 1500');
            $eq(12, $out['interactions_i'], 'interactions: 9 + 3');
            $eq(80, $out['max_scroll_pct_i'], 'scroll depth is a maximum, never a sum');
            $eq(2, $out['pageviews_i'], 'two distinct pageview ids');
            $eq(true, $out['beacon_b'], 'a beacon arrived');
            $eq(true, $out['js_b'], 'JS demonstrably ran');
            $eq(true, $out['ua_claim_ok_b'], 'every payload said the engine matched its UA');
            $eq(true, $out['tz_match_b'], 'the browser and the IP agree on the timezone');
            $eq('Apple M2', $out['webgl_s'], 'the first non-empty renderer wins');
            $eq(false, $out['headless_b'], 'nothing here says headless');
            $ok(in_array('human_mouse_natural', $out['automation_ss'], true), 'client codes must survive');

            // Positive human evidence must not produce a positive bot score.
            $eq(0.0, $out['client_score_f'], 'a plainly human session must score zero on the client plane');
            return true;
        },

    'beacon: a headless session is scored and flagged from its codes' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            $rows = [[
                'id' => 1, 'pv' => 'a', 'wall_ms' => 900, 'visible_ms' => 900, 'engaged_ms' => 0,
                'interactions' => 0, 'scroll_pct' => 0,
                'signals' => '["automation_webdriver","headless_renderer","ua_older_engine"]',
                'ua_claim' => 0, 'tz' => 'UTC', 'webgl' => 'Google SwiftShader',
            ]];
            $out = $b->mergeIntoSession(['id' => 's2', 'tz_s' => 'Europe/Bucharest'], $rows);

            $eq(true, $out['headless_b'], 'a definitive automation marker must set headless_b');
            $eq(false, $out['ua_claim_ok_b'], 'a failed engine check must set ua_claim_ok_b false');
            $eq(false, $out['tz_match_b'], 'UTC against a Bucharest IP must not match');
            $ok(in_array('tz_mismatch', $out['automation_ss'], true), 'a timezone mismatch must be recorded');
            $ok(in_array('no_interaction', $out['automation_ss'], true), 'zero interactions is a session-level code');
            $eq(100.0, $out['client_score_f'], 'the client plane must saturate on this evidence');

            // The verdict itself is never decided here — Score/Rules.php owns it.
            $ok(!array_key_exists('bot_verdict_s', $out), 'mergeIntoSession must not decide a verdict');
            return true;
        },

    'beacon: weak headless hints alone do not set headless_b' =>
        static function () use ($lhBeacon, $ok, $eq) {
            $b = $lhBeacon();
            // Every one of these has a real population of genuine humans behind it:
            // a locked-down enterprise browser, a Linux kiosk, a privacy extension.
            // A boolean that is wrong for real visitors is worse than no boolean.
            $rows = [[
                'id' => 1, 'pv' => 'a', 'wall_ms' => 30000, 'visible_ms' => 28000, 'engaged_ms' => 20000,
                'interactions' => 40, 'scroll_pct' => 90,
                'signals' => '["headless_no_plugins","headless_screen_eq_avail","headless_no_concurrency"]',
                'ua_claim' => 1, 'tz' => '', 'webgl' => '',
            ]];
            $out = $b->mergeIntoSession(['id' => 's3'], $rows);
            $eq(false, $out['headless_b'], 'weak hints must not assert headless');
            $ok($out['client_score_f'] < 60.0, 'weak hints must not reach a bot threshold on their own');
            // No geo timezone on the session, so the comparison has no answer.
            $ok(!array_key_exists('tz_match_b', $out), 'tz_match_b must be absent when either side is unknown');
            return true;
        },

    'beacon: an all-unknown ua_claim leaves ua_claim_ok_b absent' =>
        static function () use ($lhBeacon, $ok) {
            $b = $lhBeacon();
            // Safari and Firefox are not tested at all by the UA-claim probes. A
            // browser we could not test is not a browser that failed the test, and
            // recording `false` here would libel every non-Chromium visitor.
            $rows = [[
                'id' => 1, 'pv' => 'a', 'wall_ms' => 5000, 'visible_ms' => 5000, 'engaged_ms' => 4000,
                'interactions' => 6, 'scroll_pct' => 40, 'signals' => '[]',
                'ua_claim' => -1, 'tz' => 'Europe/Bucharest', 'webgl' => '',
            ]];
            $out = $b->mergeIntoSession(['id' => 's4', 'tz_s' => 'Europe/Bucharest'], $rows);
            $ok(!array_key_exists('ua_claim_ok_b', $out), 'an untested engine must leave the field absent');
            return true;
        },

    'beacon: staging rows in State::beaconsFor shape merge identically' =>
        static function () use ($lhBeacon, $eq) {
            $b = $lhBeacon();
            // State stores the counters inside a JSON payload blob and returns rows
            // as ['id','received_at','payload']. The merge must read that shape as
            // well as a flat row, or the scorer and the tests would disagree about
            // what a beacon row even is.
            $flat = [
                ['id' => 1, 'pv' => 'a', 'wall_ms' => 4000, 'visible_ms' => 3000, 'engaged_ms' => 2000,
                 'interactions' => 5, 'scroll_pct' => 60, 'signals' => ['human_mouse_natural'],
                 'ua_claim' => 1, 'tz' => 'Europe/Bucharest', 'webgl' => 'Apple M2'],
            ];
            $wrapped = [
                ['id' => 1, 'received_at' => 1_700_000_000, 'payload' => $flat[0]],
            ];
            $a = $b->mergeIntoSession(['id' => 's6', 'tz_s' => 'Europe/Bucharest'], $flat);
            $c = $b->mergeIntoSession(['id' => 's6', 'tz_s' => 'Europe/Bucharest'], $wrapped);
            $eq($a, $c, 'both row shapes must produce an identical session document');
            $eq(4000, $c['wall_ms_l'], 'the wrapped payload must actually be read');
            $eq(1, $c['pageviews_i'], 'the wrapped payload must keep its pageview id');
            return true;
        },

    'beacon: rows with no pageview id are not collapsed into one bucket' =>
        static function () use ($lhBeacon, $eq) {
            $b = $lhBeacon();
            // A truncated write or an ancient client can lose the pageview id. Those
            // rows must not silently merge with each other, or two pageviews would
            // be reported as one and the longer would swallow the shorter.
            $rows = [
                ['id' => 1, 'pv' => '', 'wall_ms' => 1000, 'visible_ms' => 1000, 'engaged_ms' => 500],
                ['id' => 2, 'pv' => '', 'wall_ms' => 3000, 'visible_ms' => 3000, 'engaged_ms' => 900],
            ];
            $out = $b->mergeIntoSession(['id' => 's5'], $rows);
            $eq(2, $out['pageviews_i'], 'two id-less rows are two pageviews, not one');
            $eq(4000, $out['wall_ms_l'], 'their durations must add');
            return true;
        },

    'beacon: the interaction-type mask decodes to a count' => static function () use ($eq) {
        $eq(0, Beacon::interactionTypes(0), 'no bits, no types');
        $eq(1, Beacon::interactionTypes(1), 'mousemove only');
        $eq(3, Beacon::interactionTypes(0b0001101), 'mousemove + keydown + click');
        $eq(7, Beacon::interactionTypes(127), 'all seven types');
        return true;
    },

    'beacon: the client key matches the sessionizer definition' => static function () use ($eq) {
        // SPEC.md §5.4: client_key = ip_net + ua_hash. If this ever drifts from
        // Sessionizer.php, no beacon will ever meet its log session again.
        $eq(
            Security::ipNetwork('203.0.113.45') . '|' . sha1('curl/8.0'),
            Beacon::clientKey('203.0.113.45', 'curl/8.0'),
            'client_key must be ip_net|sha1(ua)'
        );
        return true;
    },

    'beacon: a token is bound to the Origin it was minted for' => static function () use ($eq, $lhBeacon) {
        $beacon = $lhBeacon();
        $sid = 'b' . str_repeat('a', 40);

        $token = $beacon->issueToken($sid, time(), 'https://good.example');

        if ($beacon->verifyToken($sid, $token, 'https://good.example') === null) {
            throw new \RuntimeException('a token must verify from the origin it was issued to');
        }
        if ($beacon->verifyToken($sid, $token, 'https://evil.example') !== null) {
            throw new \RuntimeException(
                'a token issued to one origin must NOT verify from another; without this any '
                . 'third-party page can obtain credentials for a visitor session and report '
                . 'a real person as headless automation'
            );
        }
        if ($beacon->verifyToken($sid, $token, '') !== null) {
            throw new \RuntimeException('an absent origin must not satisfy a bound token');
        }
        return true;
    },

    'beacon: the client cannot assert a verdict the server derives' => static function () use ($eq, $lhBeacon) {
        $beacon = $lhBeacon();

        $payload = $beacon->normalise([
            'v' => Beacon::PROTOCOL,
            's' => 'b' . str_repeat('a', 40),
            'k' => 'x',
            'a' => [
                'platform_mismatch',
                'headless_zero_outer',
                'beacon_forged',
                'automation_webdriver',
                'headless_renderer',
            ],
        ]);

        $codes = $payload['signals'] ?? $payload['automation'] ?? [];

        foreach (['platform_mismatch', 'headless_zero_outer', 'beacon_forged'] as $derived) {
            if (in_array($derived, $codes, true)) {
                throw new \RuntimeException(
                    "the client must not be able to assert '{$derived}' — the server derives it, "
                    . 'and accepting the client version lets a page pre-empt or contradict the '
                    . 'measurement'
                );
            }
        }

        foreach (['automation_webdriver', 'headless_renderer'] as $observed) {
            if (!in_array($observed, $codes, true)) {
                throw new \RuntimeException(
                    "'{$observed}' must still be accepted from the client — it can only be seen "
                    . 'from inside the page, and refusing it would delete the strongest '
                    . 'detection signals the product has'
                );
            }
        }
        return true;
    },
];
