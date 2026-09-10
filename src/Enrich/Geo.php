<?php
/**
 * Loghound — IP geolocation via the ezcmd lookup service.
 *
 * Populates `country_s`, `region_s`, `city_s`, `geo_p` and `tz_s` (SPEC §4.1).
 *
 * ## What this service does and does NOT return — verified, not assumed
 *
 * The ezcmd endpoint (`api_ezip_locator/lookup/{key}/1/{ip}`) answers with:
 *
 *     {"success":true,
 *      "ip_info":{"country_code":"KW","country_name":"Kuwait","city":"Kuwait City",
 *                 "latitude":"29.3706","longitude":"47.9697", ...},
 *      "nearest_postal_code_info":{...},
 *      "remaining_lookups":999999000000}
 *
 * It carries **no ASN and no hosting/VPN classification**. That is why `asn_i`, `as_org_s`,
 * `as_type_s` and `netname_s` come from `Enrich\Asn` (Team Cymru + RIR whois) instead, and
 * why nothing in the bot score is allowed to depend on this class. Geo feeds the map. That
 * is its whole job.
 *
 * ## The Kansas problem
 *
 * When the underlying MaxMind database can only resolve an address to a country, it still
 * returns coordinates: the geographic centre of the contiguous United States, **37.751,
 * -97.822**, a field near Cheney Reservoir in Kansas. Every naive consumer of that data
 * plots a fake city there — it is why so many "where are my visitors" maps show a mysterious
 * concentration in rural Kansas.
 *
 * Reporting that as a location would be fabricating a metric, which SPEC §1 forbids outright.
 * So this class detects that exact centroid and drops `city_s`, `region_s` AND `geo_p`,
 * keeping only the country, which is the part that was actually known.
 *
 * ## Never blocking ingestion
 *
 * `enrich.lookup_timeout` is a hard ceiling on the whole request, redirects are refused, and
 * any failure returns an EMPTY array — the fields are simply absent from the hit document
 * (SPEC §5.3). Results are cached in SQLite, including negative results, so an unroutable or
 * unknown address is not looked up again on every one of its hits.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Enrich;

use Loghound\State;

final class Geo
{
    /**
     * MaxMind's country-level fallback point for the United States.
     *
     * Compared with a small epsilon rather than for exact float equality, because the value
     * arrives as a decimal string and the round-trip through float is not bit-exact.
     */
    private const KANSAS_LAT = 37.751;
    private const KANSAS_LON = -97.822;
    private const KANSAS_EPS = 0.002;

    /** @var array<string,mixed> The 'enrich' section of the config. */
    private array $cfg;

    private ?State $state;

    /** In-process memo, so a burst of hits from one address makes at most one DB read. */
    private array $memo = [];

    /**
     * @param array<string,mixed> $enrichCfg Config::get('enrich')
     * @param State|null          $state     Cache backing store; without it, only the
     *                                       in-process memo applies (used by tests).
     */
    public function __construct(array $enrichCfg, ?State $state = null)
    {
        $this->cfg   = $enrichCfg;
        $this->state = $state;
    }

    /**
     * Look up an address and return the Solr geo fields it justifies.
     *
     * @return array<string,mixed> Empty when geolocation is disabled, impossible or unknown.
     *                             Never contains a key whose value we had to invent.
     */
    public function lookup(string $ip): array
    {
        if (empty($this->cfg['geo_enabled'])) {
            return [];
        }
        // Only real, routable addresses. A private or reserved address has no location, and
        // asking about one wastes a request and leaks the internal topology to a third party.
        if (!self::isPublicIp($ip)) {
            return [];
        }

        if (isset($this->memo[$ip])) {
            return $this->memo[$ip];
        }

        // --- Cache ----------------------------------------------------------
        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('geo', $ip, $hit);
            if ($hit) {
                // A negative cache entry yields [] — deliberately, so we do not re-ask.
                return $this->memo[$ip] = ($cached ?? []);
            }
        }

        // --- Live lookup -----------------------------------------------------
        $raw = $this->fetch($ip);
        $fields = $raw === null ? [] : self::extract($raw);

        if ($this->state !== null) {
            $this->state->cachePut(
                'geo',
                $ip,
                $fields === [] ? null : $fields,
                ((int) ($this->cfg['geo_ttl_days'] ?? 30)) * 86400
            );
        }

        return $this->memo[$ip] = $fields;
    }

    /**
     * Perform the HTTP request, returning the decoded JSON or null.
     *
     * Hardened deliberately: no redirect following (a redirect from a third-party service is
     * an SSRF primitive we have no reason to accept), a hard total timeout, and a response
     * size cap so a hostile or broken endpoint cannot stream gigabytes into the tail daemon.
     *
     * @return array<string,mixed>|null
     */
    private function fetch(string $ip): ?array
    {
        $endpoint = (string) ($this->cfg['geo_endpoint'] ?? '');
        $key      = (string) ($this->cfg['geo_key'] ?? '');
        if ($endpoint === '' || $key === '') {
            return null;
        }

        // The template is operator-supplied and takes the key then the IP. Both are
        // rawurlencoded: the IP has already been validated as an address, but encoding it
        // costs nothing and removes the whole class of "what if that changes" bugs.
        $url = sprintf($endpoint, rawurlencode($key), rawurlencode($ip));
        if (!preg_match('~^https?://~i', $url)) {
            return null;
        }

        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));

        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(2, $timeout),
            CURLOPT_FOLLOWLOCATION => false,   // no redirect chasing — SSRF hygiene
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_PROTOCOLS_STR  => 'http,https',
            CURLOPT_USERAGENT      => 'Loghound/1.0 (+https://github.com/loghound)',
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_ENCODING       => '',
        ]);

        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if (!is_string($body) || $code < 200 || $code >= 300) {
            return null;
        }
        // 256 KB is orders of magnitude more than a geolocation answer needs.
        if (strlen($body) > 262144) {
            return null;
        }

        $doc = json_decode($body, true);
        return is_array($doc) ? $doc : null;
    }

    /**
     * Turn a decoded ezcmd response into Solr fields.
     *
     * Written tolerantly on purpose: the verified shape nests everything under `ip_info`,
     * but the service has spare keys ("...") whose names vary, so region and timezone are
     * looked for under several spellings. A key we do not find simply does not appear in the
     * output — it is never defaulted.
     *
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    public static function extract(array $doc): array
    {
        // The service signals failure with success:false / "0"; anything else is not data.
        if (array_key_exists('success', $doc)) {
            $ok = $doc['success'];
            if ($ok === false || $ok === 0 || $ok === '0' || $ok === 'false') {
                return [];
            }
        }

        // Locate the payload: ip_info is the documented location, the others are defensive.
        $info = null;
        foreach (['ip_info', 'data', 'result', 'location'] as $wrapper) {
            if (isset($doc[$wrapper]) && is_array($doc[$wrapper])) {
                $info = $doc[$wrapper];
                break;
            }
        }
        if ($info === null) {
            $info = $doc;   // a flat response
        }

        $out = [];

        $country = self::pick($info, ['country_code', 'countryCode', 'country_code2', 'country']);
        if ($country !== null && preg_match('/^[A-Za-z]{2}$/', $country)) {
            // ISO-3166-1 alpha-2, uppercased so the facet has one bucket per country.
            $out['country_s'] = strtoupper($country);
        }

        $region = self::pick($info, ['region_name', 'region', 'subdivision', 'state', 'region_code']);
        $city   = self::pick($info, ['city', 'city_name']);
        $tz     = self::pick($info, ['time_zone', 'timezone', 'tz', 'time_zone_name']);

        $lat = self::pickNumeric($info, ['latitude', 'lat']);
        $lon = self::pickNumeric($info, ['longitude', 'lon', 'lng', 'long']);

        // --- The Kansas centroid check ---------------------------------------
        // A country-only match still comes back with coordinates. Plotting them, or naming
        // the city they happen to sit in, would be inventing a location we do not have.
        $countryOnly = $lat !== null && $lon !== null && self::isKansasCentroid($lat, $lon);

        if (!$countryOnly) {
            if ($region !== null && $region !== '') {
                $out['region_s'] = self::clean($region, 128);
            }
            if ($city !== null && $city !== '') {
                $out['city_s'] = self::clean($city, 128);
            }
            if ($lat !== null && $lon !== null && self::plausibleCoords($lat, $lon)) {
                // Solr's `location` type wants "lat,lon".
                $out['geo_p'] = round($lat, 5) . ',' . round($lon, 5);
            }
        }

        // The timezone survives the Kansas check when it is a real IANA identifier: it is
        // derived from the country/registry rather than from the fake point, and the
        // beacon's tz_match_b cross-check needs it.
        if ($tz !== null && preg_match('~^[A-Za-z]+/[A-Za-z0-9_+\-/]+$~', $tz)) {
            $out['tz_s'] = $tz;
        }

        // Drop empty-string leftovers so nothing zero-filled reaches the document.
        return array_filter($out, static fn($v): bool => $v !== null && $v !== '');
    }

    /**
     * Is this the MaxMind country-level fallback point in Kansas?
     *
     * Public so the setup UI and the tests can assert on it directly, and so an operator
     * reading the code can see exactly which magic numbers are being special-cased.
     */
    public static function isKansasCentroid(float $lat, float $lon): bool
    {
        return abs($lat - self::KANSAS_LAT) < self::KANSAS_EPS
            && abs($lon - self::KANSAS_LON) < self::KANSAS_EPS;
    }

    /**
     * Reject coordinates that are out of range or are the null-island (0,0) placeholder.
     */
    private static function plausibleCoords(float $lat, float $lon): bool
    {
        if ($lat < -90.0 || $lat > 90.0 || $lon < -180.0 || $lon > 180.0) {
            return false;
        }
        // Exactly (0,0) is in the Gulf of Guinea and is always a missing-data placeholder.
        return !(abs($lat) < 0.0001 && abs($lon) < 0.0001);
    }

    /**
     * Read the first present, non-empty string value among several candidate keys.
     *
     * @param array<string,mixed> $info
     * @param string[]            $keys
     */
    private static function pick(array $info, array $keys): ?string
    {
        foreach ($keys as $k) {
            if (!isset($info[$k])) {
                continue;
            }
            $v = $info[$k];
            if (is_scalar($v)) {
                $v = trim((string) $v);
                if ($v !== '' && $v !== '-') {
                    return $v;
                }
            }
        }
        return null;
    }

    /**
     * Read the first present numeric value among several candidate keys.
     *
     * ezcmd returns latitude and longitude as decimal STRINGS ("29.3706"), so is_numeric
     * rather than is_float is the correct test.
     *
     * @param array<string,mixed> $info
     * @param string[]            $keys
     */
    private static function pickNumeric(array $info, array $keys): ?float
    {
        foreach ($keys as $k) {
            if (isset($info[$k]) && is_numeric($info[$k])) {
                return (float) $info[$k];
            }
        }
        return null;
    }

    /**
     * Trim, length-cap and strip control characters from a third-party string.
     *
     * The response is not attacker-controlled the way a log line is, but it IS remote input
     * that ends up in a Solr document and then in the panel, so it gets the same treatment.
     */
    private static function clean(string $s, int $max): string
    {
        $s = (string) preg_replace('/[\x00-\x1F\x7F]/', '', trim($s));
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        return mb_strlen($s, 'UTF-8') > $max ? mb_substr($s, 0, $max, 'UTF-8') : $s;
    }

    /**
     * Is this a real, publicly routable address worth asking a third party about?
     *
     * Also the SSRF guard: the address goes into an outbound URL, and loopback / private /
     * link-local / reserved ranges must never be sent anywhere.
     */
    public static function isPublicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }
}
