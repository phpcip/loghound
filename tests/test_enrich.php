<?php
/**
 * Loghound — tests for src/Enrich/Geo.php and src/Enrich/Asn.php.
 *
 * SPEC §12 requires the suite to pass with NO network access, so nothing here makes an
 * outbound request: the geolocation HTTP call and the whois socket are both replaced with
 * scripted transports, and a Geo built without one refuses to call out at all while
 * LOGHOUND_TEST is set. What is tested is everything that runs after the bytes come back —
 * the response mapping, the precedence between the two geography sources, the timezone
 * derivation, the Kansas-centroid guard, the network-type classification table, and the
 * guarantee that a disabled or impossible lookup returns an empty array rather than
 * inventing fields.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Enrich\Asn;
use Loghound\Enrich\Geo;

/**
 * A fake Opensolr API key, planted so the tests can prove it never leaves the request body.
 *
 * SENTINEL marks it as deliberately fake for tests/scan-secrets.php; a real credential is
 * never this shape, so the allowance does not blind the scanner to one.
 */
const LH_GEO_KEY_SENTINEL = 'GEO_API_KEY_SENTINEL_MUST_NOT_LEAK';

/**
 * Build a Geo whose HTTP transport is a scripted list of responses.
 *
 * Each entry is returned in order for successive lookups, in the transport's real contract
 * shape (status / body / error), and every request is recorded so a test can assert what was
 * actually sent — and, just as importantly, that nothing was sent when nothing should have
 * been. Running out of scripted responses THROWS, which is how "this must not call out again"
 * is pinned rather than hoped for.
 *
 * @param array<string,mixed>              $enrich    Overrides for the enrich section.
 * @param array<int,array<string,mixed>>   $responses Scripted transport answers.
 * @param array<int,array<string,mixed>>   $calls     Out: the requests that were made.
 */
function lh_geo(array $enrich, array $responses, array &$calls, ?Asn $asn = null): Geo
{
    $transport = static function (array $req) use (&$responses, &$calls): array {
        $calls[] = $req;
        $next = array_shift($responses);
        if ($next === null) {
            throw new \RuntimeException('Scripted geo transport ran out of responses for ' . $req['url']);
        }
        return $next;
    };

    return new Geo(
        $enrich + ['geo_enabled' => true, 'asn_enabled' => false, 'lookup_timeout' => 2],
        null,
        [
            'api_base' => 'https://opensolr.test/solr_manager/api',
            'email'    => 'test@example.com',
            'api_key'  => LH_GEO_KEY_SENTINEL,
        ],
        $transport,
        $asn
    );
}

/** One scripted transport answer carrying a JSON body, exactly as scripted. */
function lh_geo_ok(array $doc): array
{
    return ['status' => 200, 'body' => (string) json_encode($doc), 'error' => ''];
}

/**
 * One scripted answer in the shape geo_lookup actually returns.
 *
 * The endpoint answers a batch: an envelope declaring its contract version, and a `results`
 * map keyed by the address as sent. Building it here rather than at each call site keeps the
 * wire format in one place in the tests, the same way Geo::platformLookup() keeps it in one
 * place in the code — so a contract change is two edits, not thirty.
 *
 * @param array<string,mixed> $entry Fields of the resolved entry; `found` is added.
 */
function lh_geo_found(array $entry, string $ip = '203.0.113.9'): array
{
    return lh_geo_ok([
        'status'           => true,
        'contract_version' => 1,
        'results'          => [$ip => ['found' => true, 'ip' => $ip] + $entry],
    ]);
}

/** One scripted transport answer standing for an endpoint that could not be reached. */
function lh_geo_dead(): array
{
    return ['status' => 0, 'body' => '', 'error' => 'Could not resolve host'];
}

/**
 * Build an Asn whose whois socket is a scripted Team Cymru answer reporting $cc.
 *
 * The shape is Cymru's real bulk-mode reply: a header row told apart from the data by its
 * first column, then seven pipe-separated columns of which the fourth is the country.
 */
function lh_asn_cymru(string $cc, array &$queries): Asn
{
    $whois = static function (string $host, int $port, string $query, int $timeout) use ($cc, &$queries): ?string {
        $queries[] = $host . ':' . $port . ' ' . trim(str_replace("\n", ' ', $query));
        return "Bulk mode; whois.cymru.com [2026-09-11 00:00:00 +0000]\n"
            . "AS      | IP       | BGP Prefix  | CC | Registry | Allocated  | AS Name\n"
            . "15169   | 8.8.8.8  | 8.8.8.0/24  | " . $cc . " | arin     | 1992-12-01 | GOOGLE, " . $cc . "\n";
    };

    return new Asn(
        ['asn_enabled' => true, 'whois_enabled' => false, 'lookup_timeout' => 1],
        null,
        $whois
    );
}

/**
 * Load a Config from a throwaway file holding exactly $data.
 *
 * Written to a temp directory and read back through the real loader, so the defaults merge
 * and the dotted-path reads under test are the ones production uses.
 */
function lh_cfg_from(array $data): Config
{
    $dir  = lh_tmpdir('lhcfg');
    $path = $dir . '/loghound.php';
    file_put_contents($path, "<?php\nreturn " . var_export($data, true) . ";\n");
    $cfg = Config::load($path);
    lh_rmtree($dir);
    return $cfg;
}

/** Does any validate() message mention this setting? */
function lh_complains_about(array $errors, string $needle): bool
{
    foreach ($errors as $e) {
        if (str_contains((string) $e, $needle)) {
            return true;
        }
    }
    return false;
}

return [

    'a platform response becomes the five geo fields' => function (): void {
        $calls = [];
        $geo = lh_geo([], [lh_geo_found([
            'country_code' => 'kw',
            'country_name' => 'Kuwait',
            'region'       => 'Al Asimah',
            'city'         => 'Kuwait City',
            'latitude'     => '29.3706',
            'longitude'    => '47.9697',
            'timezone'     => 'Asia/Kuwait',
        ])], $calls);

        $fields = $geo->lookup('203.0.113.9');

        lh_same('KW', $fields['country_s'], 'country_s is uppercased ISO-3166');
        lh_same('Al Asimah', $fields['region_s'], 'region_s');
        lh_same('Kuwait City', $fields['city_s'], 'city_s');
        lh_same('29.3706,47.9697', $fields['geo_p'], 'geo_p');
        lh_same('Asia/Kuwait', $fields['tz_s'], 'tz_s');

        lh_same(1, count($calls), 'exactly one request was made');
        lh_same('https://opensolr.test/solr_manager/api/geo_lookup', $calls[0]['url'], 'derived endpoint');
    },

    'one lookup serves a burst of hits from the same address' => function (): void {
        $calls = [];
        $geo = lh_geo([], [lh_geo_found(['country_code' => 'FR'])], $calls);

        lh_same('FR', $geo->lookup('203.0.113.9')['country_s'], 'first lookup');
        lh_same('FR', $geo->lookup('203.0.113.9')['country_s'], 'second lookup, from the memo');
        lh_same(1, count($calls), 'one scripted answer, so a second request would have thrown');
    },

    'the Opensolr API key never leaves the request body' => function (): void {
        $calls = [];
        $geo = lh_geo([], [lh_geo_found(['country_code' => 'DE', 'city' => 'Berlin'])], $calls);
        $fields = $geo->lookup('203.0.113.9');

        lh_contains($calls[0]['body'], 'api_key=', 'the credential is a POST field');
        lh_same('POST', $calls[0]['method'], 'POST, so the key is not in a proxy access log');
        lh_false(str_contains($calls[0]['url'], LH_GEO_KEY_SENTINEL), 'the key is not in the URL');
        lh_false(
            str_contains(var_export($fields, true), LH_GEO_KEY_SENTINEL),
            'the key is not in anything returned'
        );
    },

    'the Kansas centroid is recognised and never plotted' => function (): void {
        lh_true(Geo::isKansasCentroid(37.751, -97.822), 'exact centroid');
        lh_true(Geo::isKansasCentroid(37.7510, -97.8220), 'same point, more decimals');
        lh_false(Geo::isKansasCentroid(37.7749, -122.4194), 'San Francisco is not the centroid');

        $fields = Geo::compose([
            'cc'  => 'US',
            'lat' => '37.751',
            'lon' => '-97.822',
            'tz'  => 'America/Chicago',
        ]);

        lh_same('US', $fields['country_s'], 'the country WAS known, so it is kept');
        lh_same('America/Chicago', $fields['tz_s'], 'and so is the timezone the service gave');
        lh_no_key($fields, 'geo_p', 'a country-level fallback point is absent, not wrong');
        lh_no_key($fields, 'city_s', 'geo fields');
    },

    'a city beside the centroid is a real answer and is kept' => function (): void {
        $fields = Geo::compose([
            'cc'     => 'US',
            'city'   => 'Wichita',
            'region' => 'Kansas',
            'lat'    => '37.751',
            'lon'    => '-97.822',
        ]);

        lh_same('Wichita', $fields['city_s'], 'city_s');
        lh_same('Kansas', $fields['region_s'], 'region_s');
        lh_same('37.751,-97.822', $fields['geo_p'], 'a named city means the point is not the fallback');
    },

    'null island and out-of-range coordinates are refused' => function (): void {
        foreach ([['0', '0'], ['0.0', '-0.0'], ['91', '10'], ['10', '-181']] as [$lat, $lon]) {
            $fields = Geo::compose(['cc' => 'DE', 'lat' => $lat, 'lon' => $lon]);
            lh_no_key($fields, 'geo_p', "geo_p for $lat,$lon");
            lh_same('DE', $fields['country_s'], 'country still kept');
        }
    },

    'the platform lookup wins the country and Team Cymru is the floor' => function (): void {
        $both = Geo::compose(['cc' => 'DE', 'city' => 'Berlin'], 'NL');
        lh_same('DE', $both['country_s'], 'the platform lookup wins');

        $floor = Geo::compose(['city' => 'Somewhere'], 'nl');
        lh_same('NL', $floor['country_s'], 'the network country is the floor, and is uppercased');
        lh_same('Europe/Amsterdam', $floor['tz_s'], 'and carries its own timezone with it');

        lh_same([], Geo::compose([], null), 'nothing from either source');
        lh_same([], Geo::compose(['cc' => 'not-a-code'], 'also-not'), 'garbage from both sources');
    },

    'a timezone is never taken from one country while another is on the document' => function (): void {
        $coherent = Geo::compose(['cc' => 'US', 'tz' => 'America/Denver'], 'NL');
        lh_same('US', $coherent['country_s'], 'the country and the zone came together, so both land');
        lh_same('America/Denver', $coherent['tz_s'], 'the service knows which US zone');

        $mixed = Geo::compose(['tz' => 'America/Denver'], 'NL');
        lh_same('NL', $mixed['country_s'], 'country_s comes from Cymru');
        lh_same('Europe/Amsterdam', $mixed['tz_s'], 'and the timezone is derived from THAT country');

        $lone = Geo::compose(['tz' => 'America/Denver'], null);
        lh_no_key($lone, 'country_s', 'geo fields');
        lh_same('America/Denver', $lone['tz_s'], 'a lone zone contradicts nothing, so it is reported');
    },

    'a country with exactly one timezone gets one, and a multi-zone country gets none' => function (): void {
        $single = [
            'FR' => 'Europe/Paris',
            'NL' => 'Europe/Amsterdam',
            'GB' => 'Europe/London',
            'RO' => 'Europe/Bucharest',
            'KW' => 'Asia/Kuwait',
            'IN' => 'Asia/Kolkata',
            'JP' => 'Asia/Tokyo',
            'PL' => 'Europe/Warsaw',
        ];
        foreach ($single as $cc => $zone) {
            lh_same($zone, Geo::timezoneForCountry($cc), 'timezoneForCountry(' . $cc . ')');
            lh_same($zone, Geo::compose(['cc' => $cc])['tz_s'], 'derived onto the document for ' . $cc);
        }

        foreach (['US', 'RU', 'CA', 'AU', 'BR', 'MX', 'ID', 'KZ', 'CN', 'DE'] as $cc) {
            lh_same(null, Geo::timezoneForCountry($cc), 'timezoneForCountry(' . $cc . ')');
            lh_no_key(Geo::compose(['cc' => $cc]), 'tz_s', 'geo fields for ' . $cc);
        }

        foreach (['EU', 'AP', 'ZZ', 'QQ', 'x', '', 'USA', '12'] as $cc) {
            lh_same(null, Geo::timezoneForCountry($cc), 'timezoneForCountry(' . lh_show($cc) . ')');
        }

        $resolved = 0;
        for ($a = 65; $a <= 90; $a++) {
            for ($b = 65; $b <= 90; $b++) {
                if (Geo::timezoneForCountry(chr($a) . chr($b)) !== null) {
                    $resolved++;
                }
            }
        }
        lh_true(
            $resolved >= 200,
            'a floor, not an exact count, because tzdata releases move it; resolved ' . $resolved
        );
    },

    'a supranational registry code is reported but yields no timezone' => function (): void {
        $fields = Geo::compose([], 'EU');
        lh_same('EU', $fields['country_s'], 'what the registry said is what is reported');
        lh_no_key($fields, 'tz_s', 'geo fields');
    },

    'remote strings are cleaned before they can reach a document' => function (): void {
        $fields = Geo::compose([
            'cc'     => 'FR',
            'city'   => "Pa\x00ris\x07",
            'region' => str_repeat('x', 400),
        ]);
        lh_same('Paris', $fields['city_s'], 'control characters are stripped');
        lh_same(128, strlen($fields['region_s']), 'and the value is length capped');
    },

    'a failed or empty platform response yields no fields at all' => function (): void {
        lh_same([], Geo::compose([]), 'nothing mapped');

        foreach ([
            ['status' => false],
            ['success' => '0'],
            ['ok' => 0],
            ['status' => true, 'contract_version' => 1, 'results' => []],
            ['status' => true, 'contract_version' => 1, 'results' => ['203.0.113.9' => ['found' => true, 'country_code' => 'not-a-code']]],
        ] as $i => $doc) {
            $calls = [];
            $geo = lh_geo([], [lh_geo_ok($doc)], $calls);
            lh_same([], $geo->lookup('203.0.113.9'), 'response ' . $i);
        }

        foreach (['GMT+2', 'Europe/Nonesuch', 'UTC+03:00', '../../etc/passwd'] as $tz) {
            lh_no_key(
                Geo::compose(['cc' => 'DE', 'tz' => $tz]),
                'tz_s',
                'a zone the database does not have: ' . lh_show($tz)
            );
        }
    },

    'an unparseable or oversized body is not mistaken for an answer' => function (): void {
        foreach ([
            ['status' => 200, 'body' => 'not json at all', 'error' => ''],
            ['status' => 200, 'body' => str_repeat('x', 300000), 'error' => ''],
            ['status' => 500, 'body' => '{"status":false}', 'error' => ''],
        ] as $i => $response) {
            $calls = [];
            $geo = lh_geo([], [$response], $calls);
            lh_same([], $geo->lookup('203.0.113.9'), 'response ' . $i);
        }
    },

    'Team Cymru carries the country when the platform lookup is unavailable' => function (): void {
        $queries = [];
        $calls   = [];
        $geo = lh_geo(
            ['asn_enabled' => true],
            [lh_geo_dead()],
            $calls,
            lh_asn_cymru('NL', $queries)
        );

        $fields = $geo->lookup('203.0.113.9');

        lh_same('NL', $fields['country_s'], 'country_s survives a dead endpoint');
        lh_same('Europe/Amsterdam', $fields['tz_s'], 'and so does the tz_mismatch rule');
        lh_no_key($fields, 'city_s', 'geo fields');
        lh_no_key($fields, 'geo_p', 'geo fields');
        lh_same(1, count($queries), 'one whois query');
    },

    'turning the ASN source off also removes the country it carried' => function (): void {
        $queries = [];
        $calls   = [];
        $geo = lh_geo(
            ['asn_enabled' => false],
            [lh_geo_dead()],
            $calls,
            lh_asn_cymru('NL', $queries)
        );

        lh_same([], $geo->lookup('203.0.113.9'), 'no geography at all');
        lh_same(0, count($queries), 'and no whois query was made');
    },

    'geo_enabled off means no geographic field and no outbound call of any kind' => function (): void {
        $queries = [];
        $calls   = [];
        $geo = lh_geo(
            ['geo_enabled' => false, 'asn_enabled' => true],
            [],
            $calls,
            lh_asn_cymru('NL', $queries)
        );

        lh_same([], $geo->lookup('8.8.8.8'), 'disabled');
        lh_same(0, count($calls), 'no geolocation request');
        lh_same(0, count($queries), 'and no whois query either');
    },

    'a Geo with no injected transport makes no request during the test run' => function (): void {
        $geo = new Geo(
            ['geo_enabled' => true, 'asn_enabled' => false],
            null,
            ['api_base' => 'https://opensolr.test/api', 'email' => 'a@b.c', 'api_key' => LH_GEO_KEY_SENTINEL]
        );
        lh_same([], $geo->lookup('8.8.8.8'), 'LOGHOUND_TEST=1 and no transport means nothing to send');
    },

    'an endpoint that is not https is refused rather than called' => function (): void {
        foreach ([
            'http://opensolr.test/api/ip_location',
            'https://user:pass@opensolr.test/api/ip_location',
            'https://opensolr.test/api/ip_location?already=here',
            'file:///etc/passwd',
            'not a url at all',
        ] as $endpoint) {
            $calls = [];
            $geo = lh_geo(['geo_endpoint' => $endpoint], [], $calls);
            lh_same([], $geo->lookup('203.0.113.9'), 'endpoint ' . lh_show($endpoint));
            lh_same(0, count($calls), 'nothing was sent to ' . lh_show($endpoint));
        }
    },

    'without account credentials the platform lookup is simply unavailable' => function (): void {
        $calls = [];
        $transport = static function (array $req) use (&$calls): array {
            $calls[] = $req;
            return lh_geo_found(['country_code' => 'FR']);
        };

        $geo = new Geo(
            ['geo_enabled' => true, 'asn_enabled' => false],
            null,
            ['api_base' => 'https://opensolr.test/api', 'email' => '', 'api_key' => ''],
            $transport
        );

        lh_same([], $geo->lookup('203.0.113.9'), 'no credentials, no answer');
        lh_same(0, count($calls), 'and nothing was sent');
    },

    'a dead endpoint stops being called after a bounded number of failures' => function (): void {
        $calls = [];
        $geo = lh_geo([], array_fill(0, 5, lh_geo_dead()), $calls);

        foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4', '203.0.113.5'] as $ip) {
            lh_same([], $geo->lookup($ip), 'failure for ' . $ip);
        }
        lh_same(5, count($calls), 'five attempts');

        lh_same([], $geo->lookup('203.0.113.6'), 'the sixth address is not looked up at all');
        lh_same(5, count($calls), 'and no sixth request was made');
    },

    'private, reserved and invalid addresses are never looked up' => function (): void {
        foreach ([
            '10.0.0.1', '192.168.1.1', '172.16.5.9', '127.0.0.1', '169.254.1.1',
            '::1', 'fd00::1', 'not-an-ip', '',
        ] as $ip) {
            lh_false(Geo::isPublicIp($ip), 'isPublicIp(' . lh_show($ip) . ')');
        }
        foreach (['8.8.8.8', '203.0.113.9', '2a01:4f8:c17:2b::1'] as $ip) {
            lh_true(Geo::isPublicIp($ip), 'isPublicIp(' . $ip . ')');
        }

        $calls = [];
        $geo = lh_geo([], [], $calls);
        lh_same([], $geo->lookup('10.0.0.1'), 'private address');
        lh_same([], $geo->lookup('garbage'), 'invalid address');
        lh_same(0, count($calls), 'nothing was sent');
    },

    'Team Cymru reports a country and lookup() never leaks it as a field' => function (): void {
        $queries = [];
        $asn = lh_asn_cymru('US', $queries);

        lh_same('US', $asn->country('8.8.8.8'), 'the CC column is parsed and exposed');

        $fields = $asn->lookup('8.8.8.8');
        lh_same(15169, $fields['asn_i'], 'asn_i');
        lh_same('GOOGLE', $fields['as_org_s'], 'as_org_s, with the trailing country stripped');
        lh_same('hosting', $fields['as_type_s'], 'as_type_s');

        foreach (array_keys($fields) as $k) {
            lh_false(str_starts_with((string) $k, '_'), 'no carried key on the document: ' . $k);
        }

        lh_same('US', $asn->country('8.8.8.9'), 'same /24, same answer');
        lh_same(1, count($queries), 'one query served every read');
    },

    'a malformed country column is refused rather than cached' => function (): void {
        $whois = static function (): ?string {
            return "AS      | IP      | BGP Prefix | CC | Registry | Allocated | AS Name\n"
                . "15169   | 8.8.8.8 | 8.8.8.0/24 | <script> | arin | 1992-12-01 | GOOGLE\n";
        };
        $asn = new Asn(['asn_enabled' => true, 'whois_enabled' => false], null, $whois);

        lh_same(null, $asn->country('8.8.8.8'), 'a country that is not two letters is dropped');
        lh_same(15169, $asn->lookup('8.8.8.8')['asn_i'], 'the rest of the answer still stands');
    },

    'as_type_s classification follows the documented precedence' => function (): void {
        $cases = [
            // [AS org, netname, expected type]
            ['GOOGLE',                          'GOOGLE',            'hosting'],
            ['AMAZON-02',                       'AMAZON-IAD',        'hosting'],
            ['Hetzner Online GmbH',             'HETZNER-nbg1-dc1',  'hosting'],
            ['DIGITALOCEAN-ASN',                'DIGITALOCEAN-2',    'hosting'],
            ['OVH SAS',                         'OVH-CUST',          'hosting'],
            ['M247 Europe SRL',                 'M247-LTD',          'hosting'],
            ['Comcast Cable Communications',    'CCCH-3',            'isp'],
            ['Deutsche Telekom AG',             'DTAG-DIAL',         'isp'],
            ['Virgin Media Limited',            'NTL',               'isp'],
            // "T-Mobile" contains "mobile"; mobile must beat hosting AND isp, because a
            // carrier is the one network where many humans legitimately share an address.
            ['T-Mobile USA, Inc.',              'TMOBILE-USA',       'mobile'],
            ['Vodafone Kabel Deutschland',      'VF-DE-MOBILE',      'mobile'],
            ['Massachusetts Institute of Technology', 'MIT-NET',     'edu'],
            ['University of Oxford',            'OXFORD-UNIV',       'edu'],
            ['US Department of Defense',        'DOD-NET',           'gov'],
            ['NordVPN',                         'NORDVPN-NET',       'vpn'],
            // A VPN hosted on somebody else's cloud is a VPN, not hosting.
            ['Amazon Technologies Inc.',        'MULLVAD-VPN-EXIT',  'vpn'],
            // A leased proxy range inside an ISP allocation: the netname is what gives it away.
            ['Consolidated Communications',     'BRIGHTDATA-RESI',   'vpn'],
            ['',                                '',                  'unknown'],
            ['Zzzz Qqqq',                       'ZQ-1',              'unknown'],
        ];

        foreach ($cases as [$org, $netname, $expected]) {
            lh_same(
                $expected,
                Asn::classifyOrg($org, $netname),
                'classifyOrg(' . lh_show($org) . ', ' . lh_show($netname) . ')'
            );
        }
    },

    'ASN and rDNS lookups are no-ops when disabled or impossible' => function (): void {
        $off = new Asn(['asn_enabled' => false, 'rdns_enabled' => false]);
        lh_same([], $off->lookup('8.8.8.8'), 'asn disabled');
        lh_same(null, $off->country('8.8.8.8'), 'and no country either');
        lh_same([], $off->rdns('8.8.8.8'), 'rdns disabled');

        // Enabled, but the address can never have a public ASN, so no network call happens.
        $on = new Asn(['asn_enabled' => true, 'rdns_enabled' => true, 'lookup_timeout' => 1]);
        lh_same([], $on->lookup('10.0.0.1'), 'private address');
        lh_same([], $on->lookup('not-an-ip'), 'invalid address');
        lh_same(null, $on->country('10.0.0.1'), 'no country for a private address');
        lh_same([], $on->rdns('not-an-ip'), 'invalid address for rdns');
    },

    'enrich.geo_key is no longer a supported setting' => function (): void {
        $enrich = Config::defaults()['enrich'];
        lh_no_key($enrich, 'geo_key', 'the enrich defaults');
        lh_same('', $enrich['geo_endpoint'], 'geo_endpoint is derived from opensolr.api_base');
    },

    'a configuration still carrying a geo_key is refused, and the message never echoes it' => function (): void {
        $errors = lh_cfg_from(['enrich' => ['geo_key' => LH_GEO_KEY_SENTINEL]])->validate();

        lh_true(
            lh_complains_about($errors, 'enrich.geo_key'),
            'a stale credential that nothing reads must not pass in silence'
        );
        lh_false(
            str_contains(implode("\n", $errors), LH_GEO_KEY_SENTINEL),
            'validate() output reaches a setup page and a log, so the value is never in it'
        );
    },

    'an empty or absent geo_key upgrades without a word' => function (): void {
        foreach ([[], ['geo_key' => ''], ['geo_key' => '  ']] as $i => $enrich) {
            $errors = lh_cfg_from(['enrich' => $enrich])->validate();
            lh_false(
                lh_complains_about($errors, 'enrich.geo_key'),
                'case ' . $i . ': the placeholder every install inherited is not a problem'
            );
        }
    },
];
