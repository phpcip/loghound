<?php
/**
 * Loghound — tests for src/Enrich/Geo.php and src/Enrich/Asn.php.
 *
 * SPEC §12 requires the suite to pass with NO network access, so nothing here makes an
 * outbound request. What is tested is everything that runs after the bytes come back — the
 * response parsing, the Kansas-centroid guard, the network-type classification table, and
 * the guarantee that a disabled or impossible lookup returns an empty array rather than
 * inventing fields.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Enrich\Asn;
use Loghound\Enrich\Geo;

return [

    'a normal ezcmd response becomes the five geo fields' => function (): void {
        $fields = Geo::extract([
            'success' => true,
            'ip_info' => [
                'country_code' => 'kw',
                'country_name' => 'Kuwait',
                'region_name'  => 'Al Asimah',
                'city'         => 'Kuwait City',
                'latitude'     => '29.3706',
                'longitude'    => '47.9697',
                'time_zone'    => 'Asia/Kuwait',
            ],
            'remaining_lookups' => 999999000000,
        ]);

        lh_same('KW', $fields['country_s'], 'country_s is uppercased ISO-3166');
        lh_same('Al Asimah', $fields['region_s'], 'region_s');
        lh_same('Kuwait City', $fields['city_s'], 'city_s');
        lh_same('29.3706,47.9697', $fields['geo_p'], 'geo_p');
        lh_same('Asia/Kuwait', $fields['tz_s'], 'tz_s');
    },

    'the Kansas centroid is recognised and never reported as a location' => function (): void {
        // MaxMind's country-level fallback point. Every naive consumer plots a fake city in
        // rural Kansas here; SPEC §1 forbids fabricating a metric, so we drop it.
        lh_true(Geo::isKansasCentroid(37.751, -97.822), 'exact centroid');
        lh_true(Geo::isKansasCentroid(37.7510, -97.8220), 'same point, more decimals');
        lh_false(Geo::isKansasCentroid(37.7749, -122.4194), 'San Francisco is not the centroid');

        $fields = Geo::extract([
            'success' => true,
            'ip_info' => [
                'country_code' => 'US',
                'city'         => 'Wichita',
                'region_name'  => 'Kansas',
                'latitude'     => '37.751',
                'longitude'    => '-97.822',
                'time_zone'    => 'America/Chicago',
            ],
        ]);

        // The country WAS known, so it is kept.
        lh_same('US', $fields['country_s'], 'country_s');
        // Everything that was only implied by the fake point is dropped.
        lh_no_key($fields, 'city_s', 'geo fields');
        lh_no_key($fields, 'region_s', 'geo fields');
        lh_no_key($fields, 'geo_p', 'geo fields');
        // The timezone is derived from the country, not from the point, so it survives.
        lh_same('America/Chicago', $fields['tz_s'], 'tz_s');
    },

    'null island and out-of-range coordinates are refused' => function (): void {
        foreach ([['0', '0'], ['0.0', '-0.0'], ['91', '10'], ['10', '-181']] as [$lat, $lon]) {
            $fields = Geo::extract([
                'success' => true,
                'ip_info' => ['country_code' => 'DE', 'latitude' => $lat, 'longitude' => $lon],
            ]);
            lh_no_key($fields, 'geo_p', "geo_p for $lat,$lon");
            lh_same('DE', $fields['country_s'], 'country still kept');
        }
    },

    'a failed or empty ezcmd response yields no fields at all' => function (): void {
        lh_same([], Geo::extract(['success' => false]), 'success false');
        lh_same([], Geo::extract(['success' => '0']), 'success "0"');
        lh_same([], Geo::extract([]), 'empty document');
        lh_same([], Geo::extract(['ip_info' => []]), 'empty ip_info');
        // A garbage country code must not become a facet value.
        lh_same([], Geo::extract(['ip_info' => ['country_code' => 'not-a-code']]), 'bad country');
        // A timezone that is not an IANA identifier is dropped rather than stored.
        lh_no_key(
            Geo::extract(['ip_info' => ['country_code' => 'DE', 'time_zone' => 'GMT+2']]),
            'tz_s',
            'geo fields'
        );
    },

    'a flat (unwrapped) response is still understood' => function (): void {
        $fields = Geo::extract([
            'country_code' => 'FR',
            'city'         => 'Paris',
            'lat'          => 48.8566,
            'lon'          => 2.3522,
        ]);
        lh_same('FR', $fields['country_s'], 'country_s');
        lh_same('Paris', $fields['city_s'], 'city_s');
        lh_same('48.8566,2.3522', $fields['geo_p'], 'geo_p');
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

        // And the guard is enforced in lookup(), which must not touch the network for these.
        $geo = new Geo(['geo_enabled' => true, 'geo_endpoint' => 'https://x/%s/%s', 'geo_key' => 'k']);
        lh_same([], $geo->lookup('10.0.0.1'), 'private address');
        lh_same([], $geo->lookup('garbage'), 'invalid address');
    },

    'geo lookup is a no-op when disabled or unconfigured' => function (): void {
        $off = new Geo(['geo_enabled' => false]);
        lh_same([], $off->lookup('8.8.8.8'), 'disabled');

        // Enabled but with no API key: must return nothing rather than calling out with none.
        $noKey = new Geo(['geo_enabled' => true, 'geo_endpoint' => 'https://x/%s/%s', 'geo_key' => '']);
        lh_same([], $noKey->lookup('8.8.8.8'), 'no key');
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
        lh_same([], $off->rdns('8.8.8.8'), 'rdns disabled');

        // Enabled, but the address can never have a public ASN, so no network call happens.
        $on = new Asn(['asn_enabled' => true, 'rdns_enabled' => true, 'lookup_timeout' => 1]);
        lh_same([], $on->lookup('10.0.0.1'), 'private address');
        lh_same([], $on->lookup('not-an-ip'), 'invalid address');
        lh_same([], $on->rdns('not-an-ip'), 'invalid address for rdns');
    },
];
