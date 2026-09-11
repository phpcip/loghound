<?php
/**
 * Loghound — IP geolocation.
 *
 * Populates `country_s`, `region_s`, `city_s`, `geo_p` and `tz_s` (SPEC §4.1) from TWO
 * sources with a fixed precedence, and derives a timezone from the country when it can.
 *
 * ## The two sources, and which one wins
 *
 * 1. **The Opensolr platform geolocation endpoint** — city-level. Authenticated with the
 *    `opensolr.email` / `opensolr.api_key` pair the installation already has, because an
 *    Opensolr account is a hard requirement and a second credential for a service that is
 *    also Opensolr's would be one more thing to configure and one more thing to leak. This
 *    source answers with a region, a city, coordinates and sometimes a timezone.
 * 2. **Team Cymru's `CC` column** — country-level, free, already on the wire. `Enrich\Asn`
 *    queries Cymru for every address to get the ASN, and that same answer carries the country
 *    of the announced prefix. See Asn::country().
 *
 * **The platform lookup wins, field by field, wherever it has an answer.** It is the more
 * specific source: it reports where the address IS, while Cymru reports where the prefix is
 * REGISTERED, and the two differ for every leased range, every anycast prefix and every
 * multinational carrier. Cymru is the floor, not a tie-breaker: it fills the country in when
 * the platform lookup is disabled, unconfigured, rate-limited or down, so a country and a
 * timezone survive conditions in which the paid path produces nothing.
 *
 * The two never mix within a document: a country and the timezone derived from it always come
 * from the same source, because a timezone taken from one country while the other country is
 * on the document would be an internally contradictory record. Geo::compose() is where that is
 * enforced, and it is the only place the two sources meet.
 *
 * ## Why this class talks to Cymru at all
 *
 * Because the alternative is worse. Letting the ingestion pipeline merge two enrichers'
 * countries independently produces exactly the contradiction above — the pipeline's merge is
 * per-key and blind, so it cannot keep a pair coherent. Owning both sources here costs one
 * extra read of a cache `Enrich\Asn` is about to populate anyway (the asn cache is keyed per
 * netblock and shared through SQLite), and buys a single, auditable precedence rule.
 *
 * ## The timezone, and the rule it resurrects
 *
 * `tz_s` feeds `tz_match_b` (Beacon.php), which feeds `Score\Rules`'s `tz_mismatch`, weight
 * 35 — the rule that catches a headless browser reporting UTC from a residential address.
 * With no `tz_s` the rule can never fire, so the timezone is worth deriving rather than only
 * reading.
 *
 * Most countries have exactly one IANA zone, and PHP's own timezone database knows which:
 * `DateTimeZone::listIdentifiers(PER_COUNTRY, $cc)`. On the host that shipped this code that
 * is 216 of the 247 territories the database covers. The remaining 31 — the United States,
 * Russia, Canada, Australia, Brazil, Mexico, Indonesia, Kazakhstan and the rest — are left
 * with NO derived timezone, because picking the most populous zone would be inventing a fact
 * and `tz_match_b` is an exact string comparison, so a wrong zone is a false mismatch on a
 * weight-35 rule. Germany is in that group too, on the strength of Büsingen; the honest
 * answer for a country with two zone identifiers is "unknown". See timezoneForCountry().
 *
 * Deriving from the database rather than from a table in this file means the answer tracks
 * tzdata updates and there is no 250-row list to maintain or get wrong.
 *
 * ## The Kansas problem
 *
 * When the underlying MaxMind database can only resolve an address to a country, it still
 * returns coordinates: the geographic centre of the contiguous United States, **37.751,
 * -97.822**, a field near Cheney Reservoir in Kansas. Writing that into `geo_p` puts a false
 * spike in the middle of the United States for every address whose city was unknown — it is
 * why so many "where are my visitors" maps show a mysterious concentration in rural Kansas.
 *
 * Reporting it would be fabricating a metric, which SPEC §1 forbids. So when the point is that
 * centroid AND no city came back, `geo_p` is omitted while the country and the timezone are
 * kept: an absent field is honest, a wrong point is not. `(0,0)` — a real place in the Gulf of
 * Guinea and never anybody's location — and out-of-range pairs are refused the same way.
 *
 * ## Never blocking ingestion
 *
 * `enrich.lookup_timeout` bounds the request, redirects are refused, the response is size
 * capped, and any failure yields an EMPTY array so the fields are simply absent (SPEC §5.3).
 * Results are cached in SQLite per address with negative caching, so ten thousand requests
 * from one scraper cost one lookup. A run of transport failures — an endpoint that is not
 * reachable at all — trips a breaker that stops the upstream call for the rest of the
 * process, so a dead endpoint costs a bounded number of timeouts instead of one per address.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Enrich;

use Loghound\Opensolr;
use Loghound\Security;
use Loghound\Solr;
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

    /** Path appended to `opensolr.api_base` when `enrich.geo_endpoint` is not set. */
    private const ENDPOINT_PATH = 'geo_lookup';

    /**
     * The response contract this client was written against.
     *
     * The endpoint states its own shape version so a provider change on the platform side is
     * detectable rather than silent. A different major version is not parsed: a field that
     * moved would otherwise be read as absent, and absent geography looks exactly like a
     * visitor the service has never heard of.
     */
    private const CONTRACT_VERSION = 1;

    /** A geolocation answer is a few hundred bytes. This much means something is wrong. */
    private const MAX_BODY_BYTES = 262144;

    /**
     * Consecutive transport failures after which the upstream lookup is abandoned.
     *
     * Enrichment must never block ingestion, and an endpoint that refuses every connection
     * would otherwise cost one full `lookup_timeout` for every distinct address in the log.
     * After this many failures in a row the process stops calling out and falls back to the
     * Cymru country, which needs no call of its own. A single success resets the counter.
     */
    private const MAX_UPSTREAM_FAILURES = 5;

    /** @var array<string,mixed> The 'enrich' section of the config. */
    private array $cfg;

    /** @var array<string,mixed> The 'opensolr' section: api_base, email, api_key. */
    private array $opensolr;

    private ?State $state;

    /** @var callable fn(array $req): array{status:int,body:string,error:string} */
    private $transport;

    /** Country-of-last-resort source; built on first use from the same config and cache. */
    private ?Asn $asn = null;

    /** In-process memo, so a burst of hits from one address makes at most one DB read. */
    private array $memo = [];

    /** Breaker state; see MAX_UPSTREAM_FAILURES. */
    private int $upstreamFailures = 0;
    private bool $upstreamOff = false;

    /**
     * The default transport is the Solr client's curl transport, reused rather than
     * reimplemented: identical shape, identical hardening — no redirect following,
     * certificate verification on — and one implementation to audit.
     *
     * The Opensolr section is a separate argument rather than something read out of the
     * enrich section, because the credentials belong to the account and not to enrichment.
     * Without it the upstream lookup is unavailable and only the Cymru-derived country and
     * timezone appear, which is a documented degradation rather than an error.
     *
     * @param array<string,mixed> $enrichCfg   Config::get('enrich')
     * @param State|null          $state       Cache backing store; without it, only the
     *                                         in-process memo applies (used by tests).
     * @param array<string,mixed> $opensolrCfg Config::get('opensolr')
     * @param callable|null       $transport   HTTP transport override, for tests.
     * @param Asn|null            $asn         Country-of-last-resort source override.
     */
    public function __construct(
        array $enrichCfg,
        ?State $state = null,
        array $opensolrCfg = [],
        ?callable $transport = null,
        ?Asn $asn = null
    ) {
        $this->cfg       = $enrichCfg;
        $this->opensolr  = $opensolrCfg;
        $this->state     = $state;
        $this->transport = $transport ?? [Solr::class, 'curlTransport'];
        $this->asn       = $asn;

        if ($transport === null && getenv('LOGHOUND_TEST') === '1') {
            $this->upstreamOff = true;
        }
    }

    /**
     * Look up an address and return the Solr geo fields it justifies.
     *
     * Only real, routable addresses are looked up. A private or reserved address has no
     * location, and asking about one would waste a request and leak the internal topology to
     * a third party. A negative cache entry yields an empty result deliberately, so that a
     * known-unanswerable address is not asked about again.
     *
     * A result is cached whenever it is a real answer — the upstream service replied, or the
     * network country gave us something. A TRANSPORT failure with nothing to fall back on is
     * NOT cached: a thirty-day negative entry written while the endpoint happened to be
     * unreachable would blind the installation for a month after it came back. The in-process
     * memo still holds, so the failure costs one attempt per address per process and not one
     * per hit.
     *
     * @return array<string,mixed> Empty when geolocation is disabled, impossible or unknown.
     *                             Never contains a key whose value we had to invent.
     */
    public function lookup(string $ip): array
    {
        if (empty($this->cfg['geo_enabled'])) {
            return [];
        }
        if (!self::isPublicIp($ip)) {
            return [];
        }

        if (isset($this->memo[$ip])) {
            return $this->memo[$ip];
        }

        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('geo', $ip, $hit);
            if ($hit) {
                return $this->memo[$ip] = ($cached ?? []);
            }
        }

        $upstream = $this->platformLookup($ip);
        $fields   = self::compose($upstream['data'], $this->networkCountry($ip));

        if ($this->state !== null && ($upstream['status'] !== 'failed' || $fields !== [])) {
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
     * Ask the Opensolr platform where this address is.
     *
     * This is the ONLY place in Loghound that knows the endpoint's wire format. Everything
     * else — the caching, the precedence between this and the network country, the centroid
     * guard, the timeouts, the failure behaviour — is written against the normalised internal
     * shape returned below and does not care what arrives on the wire. Swapping the provider
     * is this method and nothing else.
     *
     *   Request:  POST {opensolr.api_base}/geo_lookup
     *             body: ip=<address>&email=<account>&api_key=<key>, form-urlencoded
     *
     *             POST rather than GET so the API key does not land in an intermediate
     *             proxy's access log. The endpoint accepts a batch of up to fifty addresses
     *             through `ips`; one address per call is used here because enrichment is
     *             driven one log line at a time and a per-address cache already collapses a
     *             scraper's ten thousand requests into one lookup.
     *
     *   Response: {"status":true, "contract_version":1, "results":{"<ip>":{...}}}, where the
     *             entry carries `found` plus `country_code`, `country_name`, `region`,
     *             `city`, `latitude`, `longitude` and `timezone`. Only `found` and
     *             `country_code` are guaranteed on a resolved entry — every other key is
     *             OMITTED when unknown, never sent as an empty string or a zero, so each is
     *             read as absent rather than compared against a placeholder.
     *
     * `results` is keyed by the address as sent, and the endpoint reduces that key to safe
     * characters, so the lookup is by exact key with a single-entry response as the fallback.
     * An entry whose `found` is not true is an answer: the service replied and does not know.
     *
     * A `contract_version` other than the one this was written against stops the client
     * calling out at all rather than parsing a shape it does not understand — a field that
     * moved would be read as absent, and absent geography is indistinguishable from a visitor
     * nobody has heard of, which would quietly disable the timezone rule instead of failing.
     *
     * The coordinates come back already filtered by the platform: the country-level centroid
     * and the null-island placeholder are withheld there. The same guards run again in
     * compose(), because a client that trusts a remote service to have sanitised its own
     * output is one provider change away from plotting a false spike.
     *
     * The normalised internal shape every other method works from. Every member is optional
     * and null when the service did not say:
     *
     *     cc     string  country, ISO-3166-1 alpha-2, any case
     *     region string  first-level subdivision name
     *     city   string  city name
     *     lat    float   latitude, degrees
     *     lon    float   longitude, degrees
     *     tz     string  IANA timezone identifier
     *
     * The status tells lookup() how to cache: `answered` means the service replied and its
     * answer — including "I do not know" — is worth remembering; `failed` means we could not
     * get an answer and must not record one; `off` means no call was made at all.
     *
     * The API key reaches a request field and nothing else. It is never logged, never put in
     * an exception and never returned, because this method returns only mapped geography.
     *
     * @return array{status:string,data:array<string,mixed>}
     */
    private function platformLookup(string $ip): array
    {
        $none = ['status' => 'off', 'data' => []];

        if ($this->upstreamOff) {
            return $none;
        }

        $email  = (string) ($this->opensolr['email'] ?? '');
        $apiKey = (string) ($this->opensolr['api_key'] ?? '');
        $url    = $this->endpointUrl();
        if ($email === '' || $apiKey === '' || $url === null) {
            return $none;
        }

        $timeout = Security::clampInt($this->cfg['lookup_timeout'] ?? 3, 1, 30, 3);

        $res = ($this->transport)([
            'method'          => 'POST',
            'url'             => $url,
            'headers'         => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json',
            ],
            'body'            => http_build_query(
                ['ip' => $ip, 'email' => $email, 'api_key' => $apiKey],
                '',
                '&',
                PHP_QUERY_RFC3986
            ),
            'timeout'         => $timeout,
            'connect_timeout' => min(2, $timeout),
            'user'            => '',
            'pass'            => '',
        ]);

        $status = (int) ($res['status'] ?? 0);
        $body   = (string) ($res['body'] ?? '');

        if ($status < 200 || $status >= 300 || $body === '' || strlen($body) > self::MAX_BODY_BYTES) {
            $this->upstreamFailures++;
            if ($this->upstreamFailures >= self::MAX_UPSTREAM_FAILURES) {
                $this->upstreamOff = true;
            }
            return ['status' => 'failed', 'data' => []];
        }
        $this->upstreamFailures = 0;

        $doc = json_decode($body, true);
        if (!is_array($doc)) {
            return ['status' => 'answered', 'data' => []];
        }

        if (($doc['status'] ?? null) === false) {
            return ['status' => 'answered', 'data' => []];
        }

        $version = (int) ($doc['contract_version'] ?? self::CONTRACT_VERSION);
        if ($version !== self::CONTRACT_VERSION) {
            $this->upstreamOff = true;
            return ['status' => 'failed', 'data' => []];
        }

        $results = $doc['results'] ?? null;
        if (!is_array($results)) {
            return ['status' => 'answered', 'data' => []];
        }

        $info = $results[$ip] ?? (count($results) === 1 ? reset($results) : null);
        if (!is_array($info) || ($info['found'] ?? false) !== true) {
            return ['status' => 'answered', 'data' => []];
        }

        return ['status' => 'answered', 'data' => [
            'cc'     => self::pick($info, ['country_code']),
            'region' => self::pick($info, ['region']),
            'city'   => self::pick($info, ['city']),
            'lat'    => self::pickNumeric($info, ['latitude']),
            'lon'    => self::pickNumeric($info, ['longitude']),
            'tz'     => self::pick($info, ['timezone']),
        ]];
    }

    /**
     * Turn the two sources into the Solr geo fields, and nothing else.
     *
     * The precedence rule in one sentence: **the upstream lookup wins field by field, the
     * network country fills in the country when the upstream lookup has none, and the
     * timezone always comes from whichever country actually landed on the document.**
     *
     * That last clause is the part worth stating twice. A timezone derived from Cymru's
     * country while the upstream lookup's country is on the document would be a record that
     * contradicts itself — a German address with an Amsterdam timezone because the prefix
     * happens to be registered in the Netherlands. So an upstream timezone is accepted only
     * when the upstream lookup also supplied the country (or when no country is known at all,
     * in which case there is nothing for it to contradict); otherwise the timezone is derived
     * from the country that landed, and it is absent when that country has more than one zone.
     *
     * Region and city are reported whenever the service named them. They are the service's own
     * claims, not inferences from the coordinates, so a fallback point does not discredit them.
     * The point itself is withheld when it is the country-level centroid with no city beside
     * it, when it is null island, and when it is out of range.
     *
     * Every string is control-character stripped, UTF-8 checked and length capped before it can
     * reach a document or a panel: an upstream response is remote input.
     *
     * @param array<string,mixed> $up        Normalised upstream shape; see platformLookup().
     * @param string|null         $networkCc Team Cymru's country; see Asn::country().
     * @return array<string,mixed>
     */
    public static function compose(array $up, ?string $networkCc = null): array
    {
        $upCc = self::iso2(self::text($up, 'cc'));
        $cc   = $upCc ?? self::iso2($networkCc);
        $upTz = self::iana(self::text($up, 'tz'));

        $region = self::clean((string) self::text($up, 'region'), 128);
        $city   = self::clean((string) self::text($up, 'city'), 128);

        $lat = isset($up['lat']) && is_numeric($up['lat']) ? (float) $up['lat'] : null;
        $lon = isset($up['lon']) && is_numeric($up['lon']) ? (float) $up['lon'] : null;

        $out = [];

        if ($cc !== null) {
            $out['country_s'] = $cc;
        }
        if ($region !== '') {
            $out['region_s'] = $region;
        }
        if ($city !== '') {
            $out['city_s'] = $city;
        }

        $countryLevelPoint = $lat !== null
            && $lon !== null
            && $city === ''
            && self::isKansasCentroid($lat, $lon);

        if ($lat !== null && $lon !== null && !$countryLevelPoint && self::plausibleCoords($lat, $lon)) {
            $out['geo_p'] = round($lat, 5) . ',' . round($lon, 5);
        }

        if ($upTz !== null && ($upCc !== null || $cc === null)) {
            $out['tz_s'] = $upTz;
        } elseif ($cc !== null) {
            $derived = self::timezoneForCountry($cc);
            if ($derived !== null) {
                $out['tz_s'] = $derived;
            }
        }

        return $out;
    }

    /**
     * The one IANA timezone a country has, or null when it has none or more than one.
     *
     * Read out of PHP's own timezone database rather than a table in this file, so it tracks
     * tzdata releases and there is nothing to hand-maintain. On the host that shipped this
     * code, 216 of the 247 territories the database covers have exactly one zone.
     *
     * "More than one" means unknown, never "the biggest one". `tz_match_b` compares the
     * browser's zone identifier against this one as an exact string, so guessing
     * `America/New_York` for the United States would report a false mismatch for most of the
     * country on a weight-35 rule. The same logic rules out Germany, whose second identifier
     * `Europe/Busingen` covers about 1500 people and keeps the same clock as Berlin: the rule
     * is mechanical and does not make exceptions for how small the exception is.
     *
     * A registry pseudo-code (`EU`, `AP`) and an unassigned code both have no zones and
     * therefore no timezone, which is the correct answer for both.
     */
    public static function timezoneForCountry(string $cc): ?string
    {
        $cc = strtoupper(trim($cc));
        if (!preg_match('/^[A-Z]{2}$/', $cc)) {
            return null;
        }

        $zones = \DateTimeZone::listIdentifiers(\DateTimeZone::PER_COUNTRY, $cc);
        if (!is_array($zones) || count($zones) !== 1) {
            return null;
        }
        return (string) $zones[0];
    }

    /**
     * Is this the MaxMind country-level fallback point in Kansas?
     *
     * Public so the tests can assert on it directly, and so an operator reading the code can
     * see exactly which magic numbers are being special-cased.
     */
    public static function isKansasCentroid(float $lat, float $lon): bool
    {
        return abs($lat - self::KANSAS_LAT) < self::KANSAS_EPS
            && abs($lon - self::KANSAS_LON) < self::KANSAS_EPS;
    }

    /**
     * Is this a real, publicly routable address worth asking a third party about?
     *
     * Also the SSRF guard: the address goes into an outbound request, and loopback / private /
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

    /**
     * The country Team Cymru reports for this address's prefix, or null.
     *
     * Gated on `asn_enabled` as well as on `geo_enabled`, and the gate is not redundant: the
     * country comes out of the Cymru query, so an operator who has turned the ASN source off
     * must not have Cymru queried on geolocation's behalf. With ASN on, this costs no outbound
     * request of its own — `Enrich\Asn` is about to make the same query for the same netblock
     * and the answer is shared through the SQLite cache.
     *
     * A failure here is not an error: geolocation simply falls back to whatever the upstream
     * lookup produced, which may be nothing.
     */
    private function networkCountry(string $ip): ?string
    {
        if (empty($this->cfg['asn_enabled'])) {
            return null;
        }
        if ($this->asn === null) {
            $this->asn = new Asn($this->cfg, $this->state);
        }

        try {
            return $this->asn->country($ip);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * The absolute URL to POST a lookup to, or null when there is not a usable one.
     *
     * `enrich.geo_endpoint` overrides; empty means "derive from `opensolr.api_base`", so an
     * installation pointed at a staging control plane geolocates against the same staging
     * platform without a second setting to remember.
     *
     * Fails closed. The value is operator configuration rather than visitor input, but it
     * decides where an account credential is sent, so it is checked rather than trusted: https
     * only, a host present, no embedded credentials, and no query or fragment of its own —
     * the query string is built here and appending to one that already exists would silently
     * produce a different request than the operator wrote.
     */
    private function endpointUrl(): ?string
    {
        $explicit = trim((string) ($this->cfg['geo_endpoint'] ?? ''));

        $url = $explicit !== ''
            ? $explicit
            : rtrim((string) ($this->opensolr['api_base'] ?? Opensolr::DEFAULT_API_BASE), '/')
                . '/' . self::ENDPOINT_PATH;

        $parts = parse_url($url);
        if (!is_array($parts)) {
            return null;
        }
        if (strtolower((string) ($parts['scheme'] ?? '')) !== 'https') {
            return null;
        }
        if ((string) ($parts['host'] ?? '') === '') {
            return null;
        }
        if (isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            return null;
        }
        return $url;
    }

    /**
     * Reject coordinates that are out of range or are the null-island (0,0) placeholder.
     *
     * Exactly (0,0) is a point in the Gulf of Guinea and is always a missing-data placeholder
     * rather than a location anybody was at.
     */
    private static function plausibleCoords(float $lat, float $lon): bool
    {
        if ($lat < -90.0 || $lat > 90.0 || $lon < -180.0 || $lon > 180.0) {
            return false;
        }
        return !(abs($lat) < 0.0001 && abs($lon) < 0.0001);
    }

    /**
     * Read one member of the normalised shape as a string, or null.
     *
     * compose() is public and static, so it is reachable with whatever a caller hands it. A
     * nested array or an object where a name was expected is not data, and casting one to
     * string would produce "Array" and a warning rather than a refusal.
     *
     * @param array<string,mixed> $shape
     */
    private static function text(array $shape, string $key): ?string
    {
        if (!isset($shape[$key]) || !is_scalar($shape[$key])) {
            return null;
        }
        return (string) $shape[$key];
    }

    /**
     * Normalise a country code to uppercase ISO-3166-1 alpha-2, or null.
     *
     * Shape only. A code the tz database does not know — a registry pseudo-code like `EU` for
     * a supranational allocation — is still reported, because it is what the source said and
     * inventing a different answer would be worse; it simply yields no timezone.
     */
    private static function iso2(?string $cc): ?string
    {
        if ($cc === null) {
            return null;
        }
        $cc = strtoupper(trim($cc));
        return preg_match('/^[A-Z]{2}$/', $cc) === 1 ? $cc : null;
    }

    /**
     * Accept a timezone only if it is an identifier the timezone database actually has.
     *
     * A shape check alone would let `GMT+2`, `Europe/Nonesuch` or anything else an upstream
     * response happened to contain become a `tz_s` facet value and a false input to
     * `tz_match_b`. Membership in `listIdentifiers(ALL_WITH_BC)` is the real test; the regex
     * in front of it only keeps obviously hostile strings away from the lookup.
     *
     * An identifier newer than the host's tzdata is refused, so `tz_s` is absent rather than
     * wrong. That is the correct trade for a field a scoring rule reads.
     */
    private static function iana(?string $tz): ?string
    {
        if ($tz === null) {
            return null;
        }
        $tz = trim($tz);
        if ($tz === '' || strlen($tz) > 64) {
            return null;
        }
        if (!preg_match('~^[A-Za-z][A-Za-z0-9_+\-]*(?:/[A-Za-z0-9_+\-]+){0,2}$~', $tz)) {
            return null;
        }

        static $known = null;
        if ($known === null) {
            $known = [];
            foreach (\DateTimeZone::listIdentifiers(\DateTimeZone::ALL_WITH_BC) as $id) {
                $known[$id] = true;
            }
        }
        return isset($known[$tz]) ? $tz : null;
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
     * Coordinates arrive as decimal STRINGS from more than one geolocation service, so
     * is_numeric rather than is_float is the correct test.
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
}
