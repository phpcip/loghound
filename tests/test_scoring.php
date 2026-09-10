<?php
/**
 * Loghound — tests for the scoring engine.
 *
 * Three layers, in increasing order of what they prove:
 *
 *  1. PER-RULE. Every one of the seventeen rules in SPEC §7, twice: once with the minimal
 *     signal that must make it fire, once with the neighbouring signal that must NOT.
 *     False positives on humans are the worst failure this product can have, so the
 *     "does not misfire" half is the half that matters.
 *
 *  2. REAL FIXTURES. tests/fixtures/*.log are captured lines, not synthesised ones:
 *     75 lines from a headless-Chrome fleet on rotating residential proxies across 13 IPs,
 *     and 189 lines from genuine visitors. They are run through the real Sessionizer and
 *     the real ruleset.
 *
 *  3. INVARIANTS. A verdict always carries a reason. Honest crawlers never land in the
 *     evasive bucket. Unknown is never read as false.
 *
 * NO NETWORK. The fp_ips_24h_i facet is computed locally by Tests\FpCluster, which does
 * exactly what the Solr JSON Facet does, over the same parsed hits.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/support/LogFixtures.php';

use Loghound\Score\Rules;
use Loghound\Score\Signals;
use Loghound\Sessionizer;
use Loghound\Tests\CombinedLogReader;
use Loghound\Tests\FpCluster;
use Loghound\Tests\TempState;

// ============================================================================================
// Helpers
// ============================================================================================

$ok = static function (bool $cond, string $message): void {
    if (!$cond) {
        throw new \RuntimeException('FAILED: ' . $message);
    }
};

$same = static function ($expected, $actual, string $message): void {
    if ($expected !== $actual) {
        throw new \RuntimeException(
            'FAILED: ' . $message
            . "\n  expected: " . var_export($expected, true)
            . "\n  actual:   " . var_export($actual, true)
        );
    }
};

$throws = static function (callable $fn, string $needle, string $message): void {
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($needle !== '' && stripos($e->getMessage(), $needle) === false) {
            throw new \RuntimeException('FAILED: ' . $message . ' — threw: ' . $e->getMessage());
        }
        return;
    }
    throw new \RuntimeException('FAILED: ' . $message . ' — nothing was thrown.');
};

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    . '(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';

/**
 * A session aggregate on which NOT ONE rule fires.
 *
 * The baseline for every per-rule test: apply the single change the rule is about and
 * nothing else, so a rule that fires can only have fired for that reason.
 *
 * Shaped like an ordinary human visit — several pages, plenty of sub-resources, irregular
 * gaps, a warm cache producing a 304, from consumer ISP address space.
 *
 * @param array<string,mixed> $overrides   Top-level session fields.
 * @param array<string,mixed> $firstOverrides Fields on the first hit (identity/network/client).
 * @return array<string,mixed>
 */
function baseSession(array $overrides = [], array $firstOverrides = []): array
{
    $first = [
        'ip_s'          => '203.0.113.10',
        'ip_net_s'      => '203.0.113.0/24',
        'asn_i'         => 64500,
        'as_type_s'     => 'isp',
        'as_org_s'      => 'Example Broadband',
        'ua_s'          => CHROME_UA,
        'ua_hash_s'     => sha1(CHROME_UA),
        'browser_s'     => 'Chrome',
        'browser_ver_i' => 152,
        'os_s'          => 'Windows',
        'device_s'      => 'desktop',
        'ua_bot_b'      => false,
        'ai_crawler_b'  => false,
        'proto_s'       => 'HTTP/2',
        'fp_hash_s'     => 'fp-baseline',
    ];

    $session = [
        'session_id'    => 'sess-baseline',
        'ts_start'      => 1_760_000_000,
        'ts_end'        => 1_760_000_120,
        'log_span_ms'   => 120000,
        'hits'          => 12,
        'pages'         => 3,
        'assets'        => 7,
        'favicons'      => 1,
        'sub_resources' => 8,
        'beacons'       => 1,
        'bytes'         => 450000,
        'st2'           => 11,
        'st3'           => 1,
        'st4'           => 0,
        'st5'           => 0,
        'got_304'       => true,
        'html_200'      => true,
        'entry_path'    => '/',
        'exit_path'     => '/pricing',
        'uniq_paths'    => 11,
        'paths'         => ['/', '/pricing'],
        'repeat_assets' => 0,
        // Deliberately irregular: this is what a human looks like.
        'gaps'          => [1200, 8000, 300, 45000, 900, 21000],
        'gap_p50_ms'    => 1050,
        'gap_stddev_ms' => 16000,
        'asset_ratio'   => 0.67,
    ];

    return array_merge($session, $overrides, ['first' => array_merge($first, $firstOverrides)]);
}

/**
 * Build a signal map from the baseline with overrides applied.
 *
 * @param array<string,mixed> $sessionOverrides
 * @param array<string,mixed> $firstOverrides
 * @param array<string,mixed> $beacon
 */
function sig(
    array $sessionOverrides = [],
    array $firstOverrides = [],
    array $beacon = [],
    ?int $fpIps = 1
): array {
    return Signals::fromSession(baseSession($sessionOverrides, $firstOverrides), $beacon, $fpIps);
}

/**
 * Run a fixture log through the real Sessionizer and score every session.
 *
 * The scoring CONTEXT is derived from evidence exactly the way bin/loghound-score derives
 * it, rather than being asserted by the test:
 *
 *   beacon_deployed  at least one session in the batch actually reported
 *   site_sends_304   at least one session in the batch actually received a 304
 *
 * That is deliberate. Both flags gate a rule that would otherwise misfire on an entire
 * audience, so a test that hardcoded them to true would be testing a configuration nobody
 * runs and would hide the very false positives these tests exist to catch.
 *
 * @param callable|null       $beaconFor fn(array $session): array — per-session beacon data.
 * @param array<string,mixed> $ctxOverride Force a context flag (used to prove a rule can fire).
 * @return array<int,array{session:array,signals:array,verdict:array}>
 */
function scoreFixture(
    string $file,
    ?callable $beaconFor = null,
    array $ctxOverride = [],
    array $scoringCfg = []
): array {
    $cfg = [
        'ingest'  => ['session_idle_sec' => 1800],
        'privacy' => ['ip_mode' => 'full', 'ip_salt' => ''],
    ];

    // The REAL src/State.php on a throwaway SQLite database, not an imitation of it.
    $temp        = new TempState();
    $sessionizer = new Sessionizer($temp->state(), $cfg);
    $rules       = new Rules($scoringCfg);

    // Feed every line through assign(), exactly as bin/loghound-tail does, and keep the
    // enriched hits so the fingerprint facet can be reproduced locally.
    $hits = [];
    foreach (CombinedLogReader::read(__DIR__ . '/fixtures/' . $file) as $hit) {
        $hits[] = $sessionizer->assign($hit);
    }

    $sessions = $sessionizer->closeAll();

    // ---- context, derived from the batch (see bin/loghound-score) -----------------------
    $beacons = [];
    $beaconDeployed = false;
    $siteSends304   = false;
    foreach ($sessions as $session) {
        $b = $beaconFor !== null ? $beaconFor($session) : [];
        $beacons[(string) $session['session_id']] = $b;
        if (!empty($b['beacon_b'])) {
            $beaconDeployed = true;
        }
        if (!empty($session['got_304'])) {
            $siteSends304 = true;
        }
    }
    $ctx = array_merge(
        ['beacon_deployed' => $beaconDeployed, 'site_sends_304' => $siteSends304],
        $ctxOverride
    );

    $out = [];
    foreach ($sessions as $session) {
        $fp     = (string) ($session['first']['fp_hash_s'] ?? '');
        $centre = (int) (($session['ts_start'] + $session['ts_end']) / 2);
        $fpIps  = FpCluster::distinctIps($hits, $fp, $centre);

        $signals = Signals::fromSession($session, $beacons[(string) $session['session_id']], $fpIps);

        $out[] = [
            'session' => $session,
            'signals' => $signals,
            'verdict' => $rules->score($signals, $ctx),
            'ctx'     => $ctx,
        ];
    }
    return $out;
}

/**
 * The beacon payload a headless-Chrome fleet node actually produces.
 *
 * Used by the "with the execution plane" fixture test. Labelled clearly: these values are
 * SYNTHETIC, standing in for what public/b.js would report. The log lines they accompany
 * are real; this is not.
 *
 * @return array<string,mixed>
 */
function headlessBeacon(): array
{
    return [
        'beacon_b'         => true,
        'js_b'             => true,
        'headless_b'       => true,
        'automation_ss'    => ['webdriver', 'cdc_props'],
        'webgl_s'          => 'Google SwiftShader',
        'ua_claim_ok_b'    => true,
        'tz_match_b'       => true,
        'interactions_i'   => 0,
        'max_scroll_pct_i' => 0,
        'pageviews_i'      => 1,
        'wall_ms_l'        => 1400,
        'visible_ms_l'     => 1400,
        'engaged_ms_l'     => 0,
    ];
}

/**
 * The beacon payload an ordinary visitor produces.
 *
 * @return array<string,mixed>
 */
function humanBeacon(): array
{
    return [
        'beacon_b'         => true,
        'js_b'             => true,
        'headless_b'       => false,
        'automation_ss'    => [],
        'webgl_s'          => 'ANGLE (Apple, Apple M2 Pro, OpenGL 4.1)',
        'ua_claim_ok_b'    => true,
        'tz_match_b'       => true,
        'interactions_i'   => 47,
        'max_scroll_pct_i' => 82,
        'pageviews_i'      => 3,
        'wall_ms_l'        => 214000,
        'visible_ms_l'     => 168000,
        'engaged_ms_l'     => 94000,
    ];
}

// ============================================================================================
// Tests
// ============================================================================================

$tests = [];
$rules = new Rules([]);

// --------------------------------------------------------------------------------------------
// LAYER 0 — the baseline must be clean, or every per-rule test below is meaningless.
// --------------------------------------------------------------------------------------------

$tests['baseline: an ordinary human session fires nothing at all'] =
    static function () use ($rules, $same) {
        // Log plane only: no beacon installed, so the execution-plane rules stay silent.
        $v = $rules->score(sig(), ['beacon_deployed' => false, 'site_sends_304' => true]);
        $same(0.0, $v['score'], 'the baseline must score zero on the log plane');
        $same('human', $v['verdict'], 'the baseline must be human');
        $same('none', $v['class'], 'the baseline must have no class');
        $same(['no_bot_signals'], $v['reasons'], 'the baseline must carry the positive reason code');

        // And again with the execution plane live and a person driving.
        $v = $rules->score(sig([], [], humanBeacon()), ['beacon_deployed' => true, 'site_sends_304' => true]);
        $same(0.0, $v['score'], 'the baseline must score zero with beacon data too');
        $same(['no_bot_signals'], $v['reasons'], 'the beaconed baseline must trip nothing');
    };

// --------------------------------------------------------------------------------------------
// LAYER 1 — the seventeen rules, each fired and each not misfired.
// --------------------------------------------------------------------------------------------

$tests['rule automation_marker: fires on a definitive marker, not on an empty list'] =
    static function () use ($rules, $ok, $same) {
        $s = sig([], [], ['beacon_b' => true, 'automation_ss' => ['webdriver']]);
        $ok($rules->fired('automation_marker', $s) !== null, 'webdriver must fire');
        $ok(str_contains((string) $rules->fired('automation_marker', $s), 'webdriver'), 'the reason must name the marker');

        // A beacon that reported an unrecognised code is not a definitive marker.
        $s2 = sig([], [], ['beacon_b' => true, 'automation_ss' => ['slow_cpu', 'no_plugins']]);
        $same(null, $rules->fired('automation_marker', $s2), 'a non-definitive code must not fire');
        $same(null, $rules->fired('automation_marker', sig()), 'no beacon must not fire');
    };

$tests['rule ua_declared_bot: fires on a self-declared crawler, not on a browser'] =
    static function () use ($rules, $ok, $same) {
        $s = sig([], ['ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search']);
        $ok($rules->fired('ua_declared_bot', $s) !== null, 'a declared crawler must fire');
        $same(null, $rules->fired('ua_declared_bot', sig()), 'a browser must not fire');
    };

$tests['rule rdns_claim_failed: fires only on a verifiable crawler whose check actually failed'] =
    static function () use ($rules, $ok, $same) {
        $fails = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
            'rdns_ok_b' => false, 'rdns_s' => 'host.example-scraper.net',
        ]);
        $ok($rules->fired('rdns_claim_failed', $fails) !== null, 'a failed Googlebot claim must fire');

        // Passed the check.
        $passes = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
            'rdns_ok_b' => true,
        ]);
        $same(null, $rules->fired('rdns_claim_failed', $passes), 'a verified crawler must not fire');

        // NULL is not false. rDNS disabled must not accuse anyone.
        $unknown = sig([], ['ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search']);
        $same(null, $rules->fired('rdns_claim_failed', $unknown), 'an unperformed rDNS lookup must not fire');

        // A crawler whose identity nobody publishes cannot fail a check we cannot run.
        $unverifiable = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'somerandombot', 'ua_bot_cat_s' => 'other',
            'rdns_ok_b' => false,
        ]);
        $same(null, $rules->fired('rdns_claim_failed', $unverifiable), 'an unverifiable crawler must not fire');
    };

$tests['rule headless_renderer: fires on a software rasteriser, not on a real GPU'] =
    static function () use ($rules, $ok, $same) {
        foreach (['Google SwiftShader', 'Mesa/X.org llvmpipe (LLVM 15)', 'Mesa OffScreen', 'Microsoft Basic Render Driver'] as $renderer) {
            $s = sig([], [], ['beacon_b' => true, 'webgl_s' => $renderer]);
            $ok($rules->fired('headless_renderer', $s) !== null, $renderer . ' must fire');
        }
        $real = sig([], [], ['beacon_b' => true, 'webgl_s' => 'ANGLE (NVIDIA GeForce RTX 4070)']);
        $same(null, $rules->fired('headless_renderer', $real), 'a real GPU must not fire');
        $same(null, $rules->fired('headless_renderer', sig()), 'no WebGL report must not fire');
    };

$tests['rule beacon_forged: fires when the collector flagged an impossible timing claim'] =
    static function () use ($rules, $ok, $same) {
        $s = sig([], [], ['beacon_b' => true, 'beacon_forged_b' => true]);
        $ok($rules->fired('beacon_forged', $s) !== null, 'a forged beacon must fire');
        $same(null, $rules->fired('beacon_forged', sig([], [], humanBeacon())), 'an honest beacon must not fire');
    };

$tests['rule ua_claim_failed: fires on a false engine claim, never on an unknown one'] =
    static function () use ($rules, $ok, $same) {
        $s = sig([], [], ['beacon_b' => true, 'ua_claim_ok_b' => false]);
        $ok($rules->fired('ua_claim_failed', $s) !== null, 'a failed UA claim must fire');
        $same(null, $rules->fired('ua_claim_failed', sig([], [], ['beacon_b' => true, 'ua_claim_ok_b' => true])), 'a passed claim must not fire');
        $same(null, $rules->fired('ua_claim_failed', sig()), 'an unprobed claim must not fire');
    };

$tests['rule fp_cluster_proxy_fleet: fires at 5 IPs, not at 4, never on mobile, never on a verified crawler'] =
    static function () use ($rules, $ok, $same) {
        $ok($rules->fired('fp_cluster_proxy_fleet', sig([], [], [], 5)) !== null, '5 IPs must fire');
        $ok($rules->fired('fp_cluster_proxy_fleet', sig([], [], [], 40)) !== null, '40 IPs must fire');
        $same(null, $rules->fired('fp_cluster_proxy_fleet', sig([], [], [], 4)), '4 IPs must not fire');

        // A phone on a carrier network genuinely changes address repeatedly.
        $mobile = sig([], ['as_type_s' => 'mobile'], [], 12);
        $same(null, $rules->fired('fp_cluster_proxy_fleet', $mobile), 'mobile address space must not fire');

        // THE SPEC CORRECTION: Googlebot crawls from hundreds of addresses with one
        // fingerprint. Without this guard every verified search and AI crawler is a
        // "proxy fleet", which is exactly the conflation SPEC §7 says makes tools useless.
        $googlebot = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
            'rdns_ok_b' => true,
        ], [], 300);
        $same(null, $rules->fired('fp_cluster_proxy_fleet', $googlebot), 'a verified crawler must never be a fleet');

        // But the exemption has to be EARNED. A UA claim alone does not buy it.
        $fake = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
            'rdns_ok_b' => false,
        ], [], 300);
        $ok($rules->fired('fp_cluster_proxy_fleet', $fake) !== null, 'an unverified Googlebot claim must still fire');

        // Unknown is not one. A Solr outage must not manufacture a clean bill of health,
        // and must not manufacture an accusation either.
        $same(null, $rules->fired('fp_cluster_proxy_fleet', sig([], [], [], null)), 'an uncomputed cluster must not fire');
    };

$tests['rule ua_secch_mismatch: fires only when the header is actually logged'] =
    static function () use ($rules, $ok, $same) {
        // Logged (declared via _logged) and absent on a Chrome 152 claim: a mismatch.
        $missing = sig([], ['_logged' => ['sec_ch_ua_s', 'sec_ch_platform_s']]);
        $ok($rules->fired('ua_secch_mismatch', $missing) !== null, 'a missing Sec-CH-UA on Chrome must fire');

        // Present and consistent.
        $consistent = sig([], [
            '_logged'     => ['sec_ch_ua_s'],
            'sec_ch_ua_s' => '"Chromium";v="152", "Not(A:Brand";v="24", "Google Chrome";v="152"',
        ]);
        $same(null, $rules->fired('ua_secch_mismatch', $consistent), 'a consistent Sec-CH-UA must not fire');

        // Present and contradicting.
        $contradicting = sig([], [
            '_logged'     => ['sec_ch_ua_s'],
            'sec_ch_ua_s' => '"Chromium";v="120", "Not(A:Brand";v="24"',
        ]);
        $ok($rules->fired('ua_secch_mismatch', $contradicting) !== null, 'a contradicting version must fire');

        // THE CRITICAL NON-MISFIRE: apache `combined` does not log client hints. Firing
        // here would flag 100% of Chrome traffic on most sites on the internet.
        $same(null, $rules->fired('ua_secch_mismatch', sig()), 'an unlogged header must never fire');

        // Firefox does not send Sec-CH-UA at all.
        $firefox = sig([], ['_logged' => ['sec_ch_ua_s'], 'browser_s' => 'Firefox', 'browser_ver_i' => 131]);
        $same(null, $rules->fired('ua_secch_mismatch', $firefox), 'Firefox must never fire');

        // Chrome older than 89 predates the header.
        $old = sig([], ['_logged' => ['sec_ch_ua_s'], 'browser_ver_i' => 70]);
        $same(null, $rules->fired('ua_secch_mismatch', $old), 'pre-89 Chrome must not fire');
    };

$tests['rule platform_mismatch: fires on a genuine contradiction only'] =
    static function () use ($rules, $ok, $same) {
        $bad = sig([], [
            '_logged'           => ['sec_ch_platform_s'],
            'sec_ch_platform_s' => '"Linux"',
            'os_s'              => 'Windows',
        ]);
        $ok($rules->fired('platform_mismatch', $bad) !== null, 'Linux hint on a Windows UA must fire');

        $good = sig([], [
            '_logged'           => ['sec_ch_platform_s'],
            'sec_ch_platform_s' => '"Windows"',
            'os_s'              => 'Windows',
        ]);
        $same(null, $rules->fired('platform_mismatch', $good), 'a matching platform must not fire');

        $same(null, $rules->fired('platform_mismatch', sig()), 'an unlogged header must not fire');

        $unknownPlatform = sig([], ['_logged' => ['sec_ch_platform_s'], 'sec_ch_platform_s' => '"Unknown"']);
        $same(null, $rules->fired('platform_mismatch', $unknownPlatform), 'an unmodelled platform must not fire');
    };

$tests['rule no_js_on_html: fires only when the beacon is demonstrably deployed'] =
    static function () use ($rules, $ok, $same) {
        $ctxLive = ['beacon_deployed' => true];
        $ctxDark = ['beacon_deployed' => false];

        $silent = sig(['html_200' => true]);
        $ok($rules->fired('no_js_on_html', $silent, $ctxLive) !== null, 'a silent browser must fire when the beacon is live');

        // THE CRITICAL NON-MISFIRE: on a site with no beacon installed, silence means
        // nothing, and firing would score EVERY visitor 70.
        $same(null, $rules->fired('no_js_on_html', $silent, $ctxDark), 'a site without the beacon must never fire this');

        $reported = sig(['html_200' => true], [], humanBeacon());
        $same(null, $rules->fired('no_js_on_html', $reported, $ctxLive), 'a browser that reported must not fire');

        // A crawler that never claimed to be a browser is not contradicting itself.
        $crawler = sig(['html_200' => true], ['ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot']);
        $same(null, $rules->fired('no_js_on_html', $crawler, $ctxLive), 'a declared crawler must not fire');

        // No HTML was served: nothing to run a script in.
        $assetsOnly = sig(['html_200' => false]);
        $same(null, $rules->fired('no_js_on_html', $assetsOnly, $ctxLive), 'a session with no HTML 200 must not fire');
    };

$tests['rule hosting_asn_browser_ua: fires on a browser in a datacentre, not on an ISP'] =
    static function () use ($rules, $ok, $same) {
        $dc = sig([], ['as_type_s' => 'hosting']);
        $ok($rules->fired('hosting_asn_browser_ua', $dc) !== null, 'Chrome from hosting space must fire');

        $same(null, $rules->fired('hosting_asn_browser_ua', sig()), 'consumer ISP space must not fire');

        // A crawler from a datacentre is where crawlers live. This rule is about the
        // CONTRADICTION of claiming to be a consumer browser.
        $crawler = sig([], ['as_type_s' => 'hosting', 'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot']);
        $same(null, $rules->fired('hosting_asn_browser_ua', $crawler), 'a declared crawler must not fire');

        // Unenriched: as_type absent. Unknown is not "hosting".
        $unenriched = sig([], ['as_type_s' => null]);
        $same(null, $rules->fired('hosting_asn_browser_ua', $unenriched), 'an unknown network type must not fire');
    };

$tests['rule periodic_timing: fires on a schedule, NOT on a page-load burst'] =
    static function () use ($rules, $ok, $same) {
        // A monitor polling every 60s, ±1%.
        $scheduled = sig(['gaps' => [60000, 60100, 59900, 60050, 60000, 59950]]);
        $ok($rules->fired('periodic_timing', $scheduled) !== null, 'a 60s poll must fire');

        // THE CRITICAL NON-MISFIRE. Every browser page load looks like this: six
        // sub-resources inside the same second. Standard deviation near zero, and it is a
        // burst, not a schedule. A naive low-stddev rule fires on every human on the web.
        $burst = sig(['gaps' => [0, 0, 0, 0, 1000]]);
        $same(null, $rules->fired('periodic_timing', $burst), 'an asset burst must NEVER fire');

        // Human browsing: wildly irregular.
        $same(null, $rules->fired('periodic_timing', sig()), 'irregular human timing must not fire');

        // Too few samples to call anything regular.
        $short = sig(['gaps' => [30000, 30000]]);
        $same(null, $rules->fired('periodic_timing', $short), 'two gaps are not a rhythm');
    };

$tests['rule no_interaction: fires on a measured absence, not on a missing measurement'] =
    static function () use ($rules, $ok, $same) {
        $idle = sig([], [], ['beacon_b' => true, 'interactions_i' => 0]);
        $ok($rules->fired('no_interaction', $idle) !== null, 'a beacon reporting zero interactions must fire');

        $same(null, $rules->fired('no_interaction', sig([], [], humanBeacon())), 'an interacting human must not fire');

        // No beacon at all is not "zero interactions" — it is "we did not look".
        $same(null, $rules->fired('no_interaction', sig()), 'no beacon must not fire');

        // The beacon arrived but did not carry a count.
        $noCount = sig([], [], ['beacon_b' => true]);
        $same(null, $rules->fired('no_interaction', $noCount), 'a beacon with no interaction count must not fire');
    };

$tests['rule tz_mismatch: fires on a false match, never on an absent one'] =
    static function () use ($rules, $ok, $same) {
        $bad = sig([], [], ['beacon_b' => true, 'tz_match_b' => false]);
        $ok($rules->fired('tz_mismatch', $bad) !== null, 'a timezone contradiction must fire');
        $same(null, $rules->fired('tz_mismatch', sig([], [], ['beacon_b' => true, 'tz_match_b' => true])), 'a match must not fire');
        $same(null, $rules->fired('tz_mismatch', sig()), 'no timezone data must not fire');
    };

$tests['rule no_304_on_repeat: fires only where the site demonstrably serves 304s'] =
    static function () use ($rules, $ok, $same) {
        $ctxOn  = ['site_sends_304' => true];
        $ctxOff = ['site_sends_304' => false];

        $noCache = sig(['repeat_assets' => 4, 'got_304' => false]);
        $ok($rules->fired('no_304_on_repeat', $noCache, $ctxOn) !== null, 'a cacheless client must fire');

        // THE CRITICAL NON-MISFIRE. A 304 needs the SERVER to send a validator. On a site
        // that sends none, this rule measures the server and blames the client — and it
        // fires on four of the five real human sessions in the fixture.
        $same(null, $rules->fired('no_304_on_repeat', $noCache, $ctxOff), 'a site without validators must never fire this');

        $cached = sig(['repeat_assets' => 4, 'got_304' => true]);
        $same(null, $rules->fired('no_304_on_repeat', $cached, $ctxOn), 'a client that got a 304 must not fire');

        $onlyOne = sig(['repeat_assets' => 1, 'got_304' => false]);
        $same(null, $rules->fired('no_304_on_repeat', $onlyOne, $ctxOn), 'a single repeat is noise');

        $same(null, $rules->fired('no_304_on_repeat', sig(), $ctxOn), 'no repeats must not fire');
    };

$tests['rule no_assets: fires on markup-only, and the favicon counts as a sub-resource'] =
    static function () use ($rules, $ok, $same) {
        $bare = sig(['assets' => 0, 'favicons' => 0, 'sub_resources' => 0, 'html_200' => true]);
        $ok($rules->fired('no_assets', $bare) !== null, 'HTML with no sub-resources must fire');

        // A client that fetched /favicon.ico did go back for something the markup
        // referenced. Counting only kind_s=asset misfires on a real fleet session whose
        // only sub-resource was the favicon.
        $faviconOnly = sig(['assets' => 0, 'favicons' => 1, 'sub_resources' => 1, 'html_200' => true]);
        $same(null, $rules->fired('no_assets', $faviconOnly), 'a favicon fetch must count as a sub-resource');

        $same(null, $rules->fired('no_assets', sig()), 'a normal page load must not fire');

        $noHtml = sig(['html_200' => false, 'assets' => 0, 'favicons' => 0, 'sub_resources' => 0]);
        $same(null, $rules->fired('no_assets', $noHtml), 'a session that got no HTML must not fire');
    };

$tests['rule single_page_10s: fires on a fast one-page visit, at 15 points only'] =
    static function () use ($rules, $ok, $same) {
        $bounce = sig(['pages' => 1, 'log_span_ms' => 4000]);
        $ok($rules->fired('single_page_10s', $bounce) !== null, 'a 4-second single-page visit must fire');

        $same(null, $rules->fired('single_page_10s', sig(['pages' => 2, 'log_span_ms' => 4000])), 'two pages must not fire');
        $same(null, $rules->fired('single_page_10s', sig(['pages' => 1, 'log_span_ms' => 60000])), 'a minute on one page must not fire');

        // It must never be able to reach a non-human verdict alone: a human bounce looks
        // exactly like this, and there are millions of them every day.
        $v = $rules->score($bounce, ['beacon_deployed' => false, 'site_sends_304' => false]);
        $same(15.0, $v['score'], 'the weight must be 15');
        $same('human', $v['verdict'], 'fifteen points alone must stay human');
    };

// --------------------------------------------------------------------------------------------
// LAYER 2 — the real captured fixtures.
// --------------------------------------------------------------------------------------------

$tests['FIXTURE fleet: the shared-fingerprint sub-fleet scores bot / proxy_fleet from the log alone'] =
    static function () use ($ok, $same) {
        // No beacon, no ASN enrichment, no client hints — apache `combined` and nothing
        // else. This is the headline claim: the fleet's own evasion (one browser, many
        // residential addresses) is what exposes it.
        $scored = scoreFixture('apache_combined_bot_fleet.log');

        $fleet = array_values(array_filter(
            $scored,
            static fn(array $r): bool => ($r['signals']['fp_ips_24h'] ?? 0) >= Rules::FP_FLEET_MIN_IPS
        ));

        $ok(count($fleet) >= 5, 'at least five sessions must share a fingerprint across >=5 IPs, got ' . count($fleet));

        foreach ($fleet as $r) {
            $ip = (string) ($r['session']['first']['ip_s'] ?? '?');
            $same('bot', $r['verdict']['verdict'], "fleet member $ip must be a bot");
            $same('proxy_fleet', $r['verdict']['class'], "fleet member $ip must be classified proxy_fleet");
            $ok(
                in_array('fp_cluster_proxy_fleet', $r['verdict']['reasons'], true),
                "fleet member $ip must cite the fingerprint cluster as a reason"
            );
        }
    };

$tests['FIXTURE fleet: every one of the 13 nodes is a bot once the execution plane reports'] =
    static function () use ($ok, $same) {
        // The eight fleet nodes whose Chrome major version puts them in a cluster below the
        // ≥5 threshold are NOT detectable from apache `combined` alone — see the limitation
        // note in Signals::fingerprint(). They are trivially detectable the moment the
        // beacon plane exists, which is the whole point of SPEC §0's three-plane model.
        $scored = scoreFixture(
            'apache_combined_bot_fleet.log',
            static fn(array $session): array => headlessBeacon()
        );

        $same(13, count($scored), 'the fixture must produce 13 sessions, one per proxy exit');

        foreach ($scored as $r) {
            $ip = (string) ($r['session']['first']['ip_s'] ?? '?');
            $same('bot', $r['verdict']['verdict'], "fleet node $ip must be a bot with the beacon plane");
            $ok(
                in_array($r['verdict']['class'], ['proxy_fleet', 'headless'], true),
                "fleet node $ip must be classified proxy_fleet or headless, got " . $r['verdict']['class']
            );
            $ok($r['verdict']['reasons'] !== [], "fleet node $ip must carry reasons");
        }

        // At least the five-IP cluster must still be named a fleet rather than merely headless.
        $fleets = array_filter($scored, static fn(array $r): bool => $r['verdict']['class'] === 'proxy_fleet');
        $ok(count($fleets) >= 5, 'the fingerprint cluster must still be classified proxy_fleet, got ' . count($fleets));
    };

$tests['FIXTURE human: every real human session scores human, with NO rule misfiring'] =
    static function () use ($ok, $same) {
        // The worst failure this product can have. 189 real lines from genuine visitors.
        $scored = scoreFixture('apache_combined_human.log');

        $ok(count($scored) >= 5, 'the human fixture must produce at least five sessions');

        foreach ($scored as $r) {
            $ip = (string) ($r['session']['first']['ip_s'] ?? '?');
            $same('human', $r['verdict']['verdict'], "human session $ip must be human (score {$r['verdict']['score']})");
            $same(
                ['no_bot_signals'],
                $r['verdict']['reasons'],
                "human session $ip must trip no rule at all, tripped: " . implode(',', $r['verdict']['reasons'])
            );
        }
    };

$tests['FIXTURE human: still human when the beacon confirms a person is driving'] =
    static function () use ($ok, $same) {
        $scored = scoreFixture(
            'apache_combined_human.log',
            static fn(array $session): array => humanBeacon()
        );

        foreach ($scored as $r) {
            $ip = (string) ($r['session']['first']['ip_s'] ?? '?');
            $same('human', $r['verdict']['verdict'], "human session $ip must be human with beacon data");
            $same('none', $r['verdict']['class'], "human session $ip must have no bot class");
        }
    };

$tests['FIXTURE human: the fingerprint cluster signal does not fire on shared consumer UAs'] =
    static function () use ($ok) {
        // Three of the five human visitors run the identical Mac Chrome build. That is
        // three addresses on one fingerprint — genuinely how a popular browser behaves —
        // and it must stay well under the fleet threshold.
        $scored = scoreFixture('apache_combined_human.log');
        foreach ($scored as $r) {
            $n = (int) ($r['signals']['fp_ips_24h'] ?? 0);
            $ok(
                $n < Rules::FP_FLEET_MIN_IPS,
                'a human fingerprint reached ' . $n . ' IPs, at or above the fleet threshold'
            );
        }
    };

$tests['FIXTURE: session shapes are what the log actually says'] =
    static function () use ($ok, $same) {
        // Guards the sessionizer itself: a regression that miscounted pages would silently
        // change every verdict above.
        $fleet = scoreFixture('apache_combined_bot_fleet.log');
        foreach ($fleet as $r) {
            $ip = (string) ($r['session']['first']['ip_s'] ?? '?');
            // Every fleet node fetches exactly one page. The analytics beacon each of them
            // fires must NOT be counted as a second pageview — if it were, the whole
            // single_page_10s family would be silently disarmed on this traffic.
            $same(1, (int) $r['session']['pages'], "fleet node $ip must have exactly one pageview");
            $ok((int) $r['session']['log_span_ms'] <= 10000, "fleet node $ip must be in and out inside 10s");
        }

        $human = scoreFixture('apache_combined_human.log');
        foreach ($human as $r) {
            $ok((int) $r['session']['pages'] > 1, 'a real human session must have more than one pageview');
        }
    };

// --------------------------------------------------------------------------------------------
// LAYER 3 — invariants and classification.
// --------------------------------------------------------------------------------------------

$tests['invariant: a verdict always carries at least one reason'] =
    static function () use ($rules, $ok) {
        $cases = [
            sig(),
            sig([], [], headlessBeacon()),
            sig([], ['ua_bot_b' => true, 'ua_bot_name_s' => 'gptbot', 'ua_bot_cat_s' => 'ai', 'ai_crawler_b' => true]),
            sig([], [], [], 9),
            sig(['pages' => 1, 'log_span_ms' => 3000, 'assets' => 0, 'favicons' => 0, 'sub_resources' => 0]),
        ];
        foreach ($cases as $i => $s) {
            $v = $rules->score($s, ['beacon_deployed' => true, 'site_sends_304' => true]);
            $ok($v['reasons'] !== [], "case $i produced a verdict with no reasons");
            foreach ($v['reasons'] as $code) {
                $ok(isset($v['detail'][$code]), "case $i: reason $code has no explanation");
                $ok(strlen((string) $v['detail'][$code]['why']) > 20, "case $i: reason $code has no readable explanation");
            }
        }
    };

$tests['invariant: honest crawlers are bots but are NEVER in the evasive buckets'] =
    static function () use ($rules, $same, $ok) {
        $ctx = ['beacon_deployed' => true, 'site_sends_304' => true];

        // GPTBot: an AI crawler, honest, and it must be presentable on its own.
        $gpt = sig(
            ['pages' => 1, 'log_span_ms' => 2000, 'assets' => 0, 'favicons' => 0, 'sub_resources' => 0, 'html_200' => true],
            ['ua_bot_b' => true, 'ua_bot_name_s' => 'gptbot', 'ua_bot_cat_s' => 'ai', 'ai_crawler_b' => true, 'as_type_s' => 'hosting'],
            [],
            80
        );
        $v = $rules->score($gpt, $ctx);
        $same('bot', $v['verdict'], 'GPTBot is a bot');
        $same('ai_crawler', $v['class'], 'GPTBot must be classified ai_crawler, not headless or proxy_fleet');

        // Googlebot, forward-confirmed, crawling from hundreds of addresses.
        $goog = sig(
            ['pages' => 1, 'log_span_ms' => 1000, 'assets' => 0, 'favicons' => 0, 'sub_resources' => 0, 'html_200' => true],
            [
                'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
                'rdns_ok_b' => true, 'rdns_s' => 'crawl-66-249-66-1.googlebot.com', 'as_type_s' => 'hosting',
            ],
            [],
            300
        );
        $v = $rules->score($goog, $ctx);
        $same('bot', $v['verdict'], 'Googlebot is a bot');
        $same('declared_crawler', $v['class'], 'a verified Googlebot must be declared_crawler');
        $ok(!in_array('fp_cluster_proxy_fleet', $v['reasons'], true), 'a verified crawler must not be accused of being a fleet');

        // An uptime monitor.
        $mon = sig(
            ['gaps' => [60000, 60000, 60000, 59900, 60100]],
            ['ua_bot_b' => true, 'ua_bot_name_s' => 'uptimerobot', 'ua_bot_cat_s' => 'monitor', 'as_type_s' => 'hosting']
        );
        $same('monitor', $rules->score($mon, $ctx)['class'], 'an uptime monitor must be classified monitor');

        // Something CLAIMING to be Googlebot from space Google does not own.
        $fake = sig(
            [],
            [
                'ua_bot_b' => true, 'ua_bot_name_s' => 'googlebot', 'ua_bot_cat_s' => 'search',
                'rdns_ok_b' => false, 'rdns_s' => 'vps-1234.cheaphost.example',
            ]
        );
        $v = $rules->score($fake, $ctx);
        $same('bot', $v['verdict'], 'a fake Googlebot is a bot');
        $same('spoofed_ua', $v['class'], 'a fake Googlebot must be spoofed_ua, never declared_crawler');
    };

$tests['invariant: an unverifiable declared crawler is taken at its word'] =
    static function () use ($rules, $same) {
        // Nobody publishes rDNS for it, so we cannot check — and inability to verify is
        // not evidence of dishonesty.
        $s = sig([], [
            'ua_bot_b' => true, 'ua_bot_name_s' => 'ahrefsbot', 'ua_bot_cat_s' => 'seo',
            'as_type_s' => 'hosting',
        ]);
        $v = $rules->score($s, ['beacon_deployed' => true, 'site_sends_304' => true]);
        $same('declared_crawler', $v['class'], 'an unverifiable crawler must stay in the honest bucket');
    };

$tests['invariant: a headless client with no fleet is classified headless, with a fleet is proxy_fleet'] =
    static function () use ($rules, $same) {
        $ctx = ['beacon_deployed' => true, 'site_sends_304' => true];

        $lone = sig([], [], headlessBeacon(), 1);
        $same('headless', $rules->score($lone, $ctx)['class'], 'a lone headless browser is headless');

        // proxy_fleet outranks headless: it names an operation, not a client, and that is
        // what an operator can act on.
        $fleet = sig([], [], headlessBeacon(), 30);
        $same('proxy_fleet', $rules->score($fleet, $ctx)['class'], 'a headless browser in a fleet is a fleet');
    };

$tests['config: weights are overridable and a zero weight disables a rule'] =
    static function () use ($same, $throws) {
        $s = sig(['pages' => 1, 'log_span_ms' => 3000]);

        $loud = new Rules(['weights' => ['single_page_10s' => 90]]);
        $v = $loud->score($s, ['beacon_deployed' => false, 'site_sends_304' => false]);
        $same(90.0, $v['score'], 'an overridden weight must be used');
        $same('bot', $v['verdict'], 'the raised weight must change the verdict');

        $off = new Rules(['weights' => ['single_page_10s' => 0]]);
        $v = $off->score($s, ['beacon_deployed' => false, 'site_sends_304' => false]);
        $same(0.0, $v['score'], 'a zero weight must disable the rule');
        $same(['no_bot_signals'], $v['reasons'], 'a disabled rule must not appear in the reasons');

        // A typo in a config weight must be loud, not silently ignored — an operator who
        // thinks they disabled a rule and did not is worse off than one who got an error.
        $throws(
            static fn() => new Rules(['weights' => ['single_page_15s' => 0]]),
            'unknown rule code',
            'an unknown rule code must be refused'
        );
    };

$tests['config: verdict thresholds are overridable'] =
    static function () use ($same) {
        $strict = new Rules(['thresholds' => ['bot' => 40, 'likely_bot' => 30, 'unknown' => 20, 'likely_human' => 10]]);
        $s = sig(['pages' => 1, 'log_span_ms' => 3000, 'assets' => 0, 'favicons' => 0, 'sub_resources' => 0]);
        // no_assets (25) + single_page_10s (15) = 40
        $v = $strict->score($s, ['beacon_deployed' => false, 'site_sends_304' => false]);
        $same(40.0, $v['score'], 'the stacked score must be 40');
        $same('bot', $v['verdict'], 'a lowered bot threshold must apply');
    };

$tests['config: the fleet threshold is overridable'] =
    static function () use ($rules, $ok, $same) {
        $tight = new Rules(['fp_fleet_min_ips' => 3]);
        $s = sig([], [], [], 3);
        $ok($tight->fired('fp_cluster_proxy_fleet', $s) !== null, 'a lowered threshold must fire at 3 IPs');
        $same(null, $rules->fired('fp_cluster_proxy_fleet', $s), 'the default threshold must not fire at 3 IPs');
    };

$tests['scoring: the score is clamped to 0-100 even when weights stack past it'] =
    static function () use ($rules, $same) {
        // automation_marker 100 + headless_renderer 90 + ua_claim_failed 85 + more.
        $s = sig([], [], array_merge(headlessBeacon(), ['ua_claim_ok_b' => false]), 40);
        $v = $rules->score($s, ['beacon_deployed' => true, 'site_sends_304' => true]);
        $same(100.0, $v['score'], 'the published score must stay within 0-100');
    };

// --------------------------------------------------------------------------------------------
// Signals unit tests
// --------------------------------------------------------------------------------------------

$tests['signals: the fingerprint excludes the IP address by design'] =
    static function () use ($same, $ok) {
        $a = ['ua_s' => CHROME_UA, 'proto_s' => 'HTTP/2', 'ip_s' => '1.2.3.4'];
        $b = ['ua_s' => CHROME_UA, 'proto_s' => 'HTTP/2', 'ip_s' => '203.0.113.9'];
        $same(Signals::fingerprint($a), Signals::fingerprint($b), 'the address must not affect the fingerprint');

        // ...but a header difference must.
        $c = $a + ['accept_lang_s' => 'ro-RO'];
        $ok(Signals::fingerprint($a) !== Signals::fingerprint($c), 'a header difference must change the fingerprint');

        // An absent component and an empty one must not collide with a shifted tuple.
        $d = ['ua_s' => CHROME_UA, 'accept_s' => 'HTTP/2'];
        $ok(Signals::fingerprint($a) !== Signals::fingerprint($d), 'component positions must be fixed');
    };

$tests['signals: request classification separates pages, sub-resources and beacons'] =
    static function () use ($same) {
        $k = static fn(array $hit): string => Signals::classifyRequest($hit)['kind_s'];

        $same('html', $k(['path_s' => '/pricing']), 'an extensionless path is a page');
        $same('html', $k(['path_s' => '/index.php']), 'a .php path is a page');
        $same('asset', $k(['path_s' => '/app.css']), 'a stylesheet is an asset');
        $same('asset', $k(['path_s' => '/img/logo.webp']), 'an image is an asset');
        $same('favicon', $k(['path_s' => '/favicon.ico']), 'the favicon has its own kind');
        $same('robots', $k(['path_s' => '/robots.txt']), 'robots.txt has its own kind');
        $same('api', $k(['path_s' => '/api/v1/things']), 'an /api/ path is an api call');
        $same('other', $k(['path_s' => '/opensolr.apk', 'query_s' => 'v=4.5']), 'a download is neither page nor asset');

        // The generic analytics-beacon heuristic: an obfuscated path with beacon-shaped
        // query parameters and a tiny response. Counting this as a page would turn every
        // one-page visit into a two-page one and disarm single_page_10s.
        $same('beacon', $k([
            'path_s'  => '/c5b2e40505eb5bcd7',
            'query_s' => 'site_id=X&href=%2Fpricing&title=Pricing&res=1920x1080&lang=en-US&tz=America%2FDenver',
            'bytes_l' => 1010,
        ]), 'an analytics beacon must be recognised');

        // A real page that happens to carry a couple of familiar parameters is NOT a
        // beacon: the response is far too big.
        $same('html', $k([
            'path_s'  => '/search',
            'query_s' => 'lang=en-US&ref=x&title=y',
            'bytes_l' => 152381,
        ]), 'a large response must not be mistaken for a beacon');
    };

$tests['signals: median and stddev behave on empty and tiny inputs'] =
    static function () use ($same) {
        $same(0, Signals::median([]), 'the median of nothing is zero, not an error');
        $same(0, Signals::stddev([]), 'the stddev of nothing is zero');
        $same(0, Signals::stddev([5]), 'the stddev of one sample is zero');
        $same(3, Signals::median([1, 3, 5]), 'odd-length median');
        $same(3, Signals::median([1, 2, 4, 8]), 'even-length median rounds');
    };

$tests['signals: headless renderer detection returns null when nothing was reported'] =
    static function () use ($same) {
        $same(null, Signals::isHeadlessRenderer(null), 'no report is unknown, not false');
        $same(null, Signals::isHeadlessRenderer(''), 'an empty report is unknown');
        $same(true, Signals::isHeadlessRenderer('Google SwiftShader'), 'SwiftShader is a software rasteriser');
        $same(false, Signals::isHeadlessRenderer('ANGLE (Intel Iris Xe)'), 'a real GPU is not');
    };

$tests['signals: visitor hash changes daily in hash privacy mode'] =
    static function () use ($ok) {
        $hit = ['ip_net_s' => '203.0.113.0/24', 'ua_hash_s' => sha1(CHROME_UA), 'accept_lang_s' => 'en-US'];
        $plain = Signals::visitorHash($hit, 'full', '');
        $salted = Signals::visitorHash($hit, 'hash', 'a-long-enough-salt');
        $ok($plain !== $salted, 'hash mode must produce a different identifier');
        $ok(strlen($salted) === 24, 'the visitor hash must be a fixed short length');
    };

// ============================================================================================
// Standalone runner
// ============================================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    $pass = 0;
    $fail = 0;
    foreach ($tests as $name => $test) {
        try {
            $test();
            $pass++;
            fwrite(STDOUT, "  ok   $name\n");
        } catch (\Throwable $e) {
            $fail++;
            fwrite(STDOUT, "  FAIL $name\n       " . str_replace("\n", "\n       ", $e->getMessage()) . "\n");
        }
    }
    fwrite(STDOUT, "\n$pass passed, $fail failed\n");
    exit($fail === 0 ? 0 : 1);
}

return $tests;
