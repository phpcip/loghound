<?php
/**
 * Loghound — tests against real captured production traffic.
 *
 * Two fixtures, both real lines from opensolr.com, not synthesised:
 *
 *   apache_combined_bot_fleet.log   75 lines from a headless-Chrome scraping fleet running
 *                                   on rotating proxies — 13 distinct addresses.
 *   apache_combined_human.log      189 lines from genuine visitors, addresses pseudonymised.
 *
 * The assertions here are the product's floor. In particular:
 *
 *   **`fp_hash_s` must be identical across the fleet's different addresses.** That is the
 *   core detection primitive of the whole project (SPEC §4.1: "THE cluster key… Excludes IP
 *   by design — that is the point"). A scraper rotating through residential proxies changes
 *   its address on every request but keeps sending byte-identical headers; if those requests
 *   do not collapse onto one fingerprint, `fp_ips_24h_i` counts nothing, the
 *   `fp_cluster_proxy_fleet` rule never fires, and Loghound is just another log viewer.
 *   If this test fails, the product does not work.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\LogDetect;
use Loghound\Parser;

/**
 * Parse a whole fixture into hit documents with a real source path and byte offsets.
 *
 * @return array<int,array<string,mixed>>
 */
function lh_fixture_hits(string $fixture, array $opts = []): array
{
    $fmt    = LogDetect::formatByName('apache_combined');
    $parser = new Parser($opts + ['keep_raw' => false, 'host' => 'opensolr.com']);

    $hits   = [];
    $offset = 0;
    foreach (lh_fixture_lines($fixture) as $line) {
        $hit = $parser->parseLine($fmt, $line, '/var/log/apache2/' . $fixture, $offset);
        if ($hit !== null) {
            $hits[] = $hit;
        }
        // Byte offsets are what make the hit id idempotent across a re-ingest.
        $offset += strlen($line) + 1;
    }
    return $hits;
}

return [

    'every line of both fixtures parses with apache_combined' => function (): void {
        $fmt = LogDetect::formatByName('apache_combined');

        foreach (['apache_combined_bot_fleet.log', 'apache_combined_human.log'] as $fixture) {
            $lines = lh_fixture_lines($fixture);
            lh_true(count($lines) > 0, "$fixture has lines");

            foreach ($lines as $i => $line) {
                $rec = $fmt->parse($line);
                if ($rec === null) {
                    lh_fail("$fixture line " . ($i + 1) . " failed to parse: " . substr($line, 0, 160));
                }
            }
        }
    },

    'the format library picks apache_combined for both fixtures with high confidence' => function (): void {
        foreach (['apache_combined_bot_fleet.log', 'apache_combined_human.log'] as $fixture) {
            $ranked = LogDetect::detectFromSample(lh_fixture_lines($fixture));

            lh_true($ranked !== [], "$fixture produced candidates");
            lh_same('apache_combined', $ranked[0]['name'], "$fixture winner");
            lh_true(
                $ranked[0]['confidence'] >= 95.0,
                "$fixture confidence should be >= 95, got " . $ranked[0]['confidence']
            );
            lh_same($ranked[0]['parsed'], $ranked[0]['total'], "$fixture full parse rate");
            // The setup UI shows five parsed records for the operator to confirm.
            lh_same(5, count($ranked[0]['samples']), "$fixture sample records");
        }
    },

    'every fixture line becomes a complete, well-formed hit document' => function (): void {
        foreach (['apache_combined_bot_fleet.log', 'apache_combined_human.log'] as $fixture) {
            $hits = lh_fixture_hits($fixture);
            lh_same(count(lh_fixture_lines($fixture)), count($hits), "$fixture hit count");

            $seenIds = [];
            foreach ($hits as $i => $hit) {
                foreach (['id', 'ts', 'src_s', 'ip_s', 'ip_net_s', 'path_s', 'kind_s',
                          'status_i', 'ua_hash_s', 'fp_hash_s'] as $field) {
                    lh_has_key($hit, $field, "$fixture hit $i");
                }
                // The id is sha1(file+offset), so it must be unique within a file — that is
                // what makes a re-ingest overwrite rather than duplicate.
                lh_false(isset($seenIds[$hit['id']]), "$fixture hit $i has a unique id");
                $seenIds[$hit['id']] = true;

                lh_true((bool) preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/', $hit['ts']),
                    "$fixture hit $i ts is a UTC Solr instant, got " . $hit['ts']);
                lh_true($hit['status_i'] >= 100 && $hit['status_i'] <= 599,
                    "$fixture hit $i status is a real HTTP status");
            }
        }
    },

    'timestamps normalise correctly across a whole fixture' => function (): void {
        $hits = lh_fixture_hits('apache_combined_bot_fleet.log');

        // The fixture was captured on 2026-09-10 with a +0000 offset, so the UTC instants
        // must be that same wall-clock time on that same date.
        lh_same('2026-09-10T09:57:08.000Z', $hits[0]['ts'], 'first bot hit');

        // Strongest possible assertion: for EVERY line, the normalized `ts` must be exactly
        // the bracketed Apache timestamp converted to UTC. The fixture was captured with a
        // +0000 offset and spans two calendar days, so this checks the conversion rather
        // than a single hard-coded date.
        $lines = lh_fixture_lines('apache_combined_bot_fleet.log');
        foreach ($lines as $i => $line) {
            lh_true(
                (bool) preg_match('/\[([^\]]+)\]/', $line, $m),
                "bot line $i has a bracketed timestamp"
            );
            $expected = Parser::parseTimestamp($m[1]);
            lh_true($expected !== null, "bot line $i timestamp parses");
            lh_same(
                $expected->format('Y-m-d\TH:i:s.v\Z'),
                $hits[$i]['ts'],
                "bot hit $i ts matches the logged instant in UTC"
            );
            // And the epoch round-trip used by the sessionizer must agree with it.
            lh_same(
                (int) $expected->format('U') * 1000,
                Parser::epochMs($hits[$i]['ts']),
                "bot hit $i epochMs"
            );
        }

        $human = lh_fixture_hits('apache_combined_human.log');
        lh_same('2026-09-10T00:49:05.000Z', $human[0]['ts'], 'first human hit');
    },

    'fp_hash_s is IDENTICAL across the bot fleet addresses that share headers' => function (): void {
        // THE test. If this fails, the product does not work.
        $hits = lh_fixture_hits('apache_combined_bot_fleet.log');
        lh_true(count($hits) > 50, 'fixture loaded');

        // Group the fleet's hits by fingerprint and count the distinct addresses per group.
        $ipsPerFp = [];
        $uasPerFp = [];
        foreach ($hits as $hit) {
            $fp = $hit['fp_hash_s'];
            $ipsPerFp[$fp][$hit['ip_s']] = true;
            $uasPerFp[$fp][$hit['ua_s'] ?? ''] = true;
        }

        // 1. A fingerprint must never span two different header sets — that would be a
        //    collision and would make the cluster counts meaningless.
        foreach ($uasPerFp as $fp => $uas) {
            lh_same(1, count($uas), "fingerprint $fp covers exactly one header set");
        }

        // 2. The whole point: at least one fingerprint must be shared by several DIFFERENT
        //    addresses. In this capture the largest cluster spans five proxy exits.
        $largest = 0;
        foreach ($ipsPerFp as $ips) {
            $largest = max($largest, count($ips));
        }
        lh_true(
            $largest >= 5,
            'the largest fingerprint cluster should span >= 5 distinct IPs, got ' . $largest
        );

        // 3. And explicitly: rewriting only the address must not change the fingerprint.
        $line = lh_fixture_lines('apache_combined_bot_fleet.log')[0];
        $fmt  = LogDetect::formatByName('apache_combined');
        $parser = new Parser(['keep_raw' => false, 'host' => 'opensolr.com']);

        $original = $parser->parseLine($fmt, $line, 'x', 0);
        $moved    = $parser->parseLine(
            $fmt,
            preg_replace('/^\S+/', '198.51.100.222', $line, 1),
            'x',
            1
        );

        lh_true($original['ip_s'] !== $moved['ip_s'], 'the address really did change');
        lh_same($original['fp_hash_s'], $moved['fp_hash_s'], 'fp_hash_s ignores the address');
    },

    'the bot fleet shows the shape a fleet has and the humans do not' => function (): void {
        $bots   = lh_fixture_hits('apache_combined_bot_fleet.log');
        $humans = lh_fixture_hits('apache_combined_human.log');

        $distinctIps = static function (array $hits): int {
            $ips = [];
            foreach ($hits as $h) {
                $ips[$h['ip_s']] = true;
            }
            return count($ips);
        };
        $maxCluster = static function (array $hits): int {
            $per = [];
            foreach ($hits as $h) {
                $per[$h['fp_hash_s']][$h['ip_s']] = true;
            }
            $max = 0;
            foreach ($per as $ips) {
                $max = max($max, count($ips));
            }
            return $max;
        };

        // The fleet: many addresses, few fingerprints, so the biggest cluster is wide.
        lh_true($distinctIps($bots) >= 10, 'the fleet uses many addresses');
        lh_true($maxCluster($bots) >= 5, 'and collapses onto few fingerprints');

        // Real visitors: each browser is one person on one connection, so the widest
        // fingerprint cluster is narrow. This is the control that shows the signal is not
        // just "any traffic looks like a fleet".
        lh_true(
            $maxCluster($humans) < $maxCluster($bots),
            'humans cluster less widely than the fleet: '
            . $maxCluster($humans) . ' vs ' . $maxCluster($bots)
        );
    },

    'real traffic is classified into the SPEC kinds' => function (): void {
        $hits = array_merge(
            lh_fixture_hits('apache_combined_bot_fleet.log'),
            lh_fixture_hits('apache_combined_human.log')
        );

        $kinds = [];
        foreach ($hits as $hit) {
            $kinds[$hit['kind_s']] = ($kinds[$hit['kind_s']] ?? 0) + 1;
            // Every kind must be one of the seven SPEC §4.1 allows — nothing invented.
            lh_true(
                in_array($hit['kind_s'], ['html', 'asset', 'api', 'beacon', 'robots', 'favicon', 'other'], true),
                'kind_s ' . $hit['kind_s'] . ' is a SPEC value'
            );
            if ($hit['kind_s'] === 'asset') {
                lh_true(
                    in_array($hit['asset_kind_s'] ?? '', ['js', 'css', 'img', 'font', 'media'], true),
                    'asset_kind_s ' . ($hit['asset_kind_s'] ?? '(absent)') . ' is a SPEC value'
                );
            } else {
                lh_no_key($hit, 'asset_kind_s', 'non-asset hit');
            }
        }

        // Real captured traffic contains pages and sub-resources; if it did not, the
        // asset-ratio behavioural signal would have nothing to work with.
        lh_true(($kinds['html'] ?? 0) > 0, 'some HTML was served');
        lh_true(($kinds['asset'] ?? 0) > 0, 'some assets were served');
    },

    'combined logs no headers beyond UA and Referer, and none are invented' => function (): void {
        // The honest-degradation check: on plain `combined` the client-hint and timing
        // fields must simply not exist, which is what makes "how many hits had no Accept
        // header" an answerable question instead of a fabricated zero.
        foreach (lh_fixture_hits('apache_combined_human.log') as $i => $hit) {
            foreach ([
                'accept_s', 'accept_lang_s', 'accept_enc_s', 'sec_ch_ua_s',
                'sec_ch_platform_s', 'sec_ch_mobile_b', 'sec_fetch_site_s',
                'sec_fetch_mode_s', 'sec_fetch_dest_s', 'sec_fetch_user_s',
                'xff_s', 'tls_proto_s', 'tls_cipher_s', 'ja4_s', 'dur_us_l',
            ] as $field) {
                lh_no_key($hit, $field, "human hit $i");
            }
        }
    },

    'ingesting a fixture twice produces the same ids' => function (): void {
        // Idempotence: after a crash the tailer may re-read from a stale offset, and the
        // documents it re-emits must overwrite rather than duplicate.
        $first  = lh_fixture_hits('apache_combined_bot_fleet.log');
        $second = lh_fixture_hits('apache_combined_bot_fleet.log');

        lh_same(count($first), count($second), 'hit counts match');
        foreach ($first as $i => $hit) {
            lh_same($hit['id'], $second[$i]['id'], "hit $i id is stable");
            lh_same($hit['fp_hash_s'], $second[$i]['fp_hash_s'], "hit $i fingerprint is stable");
        }
    },
];
