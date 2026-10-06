<?php
/**
 * Loghound — Network ownership enrichment: ASN, netname, network type and rDNS.
 *
 * Populates `asn_i`, `as_org_s`, `as_type_s`, `netname_s`, `rdns_s` and `rdns_ok_b`
 * (SPEC §4.1). Three independent sources, because no single one answers the question:
 *
 *  - **Team Cymru's IP-to-ASN whois service** (`whois.cymru.com`, bulk `begin`/`verbose`
 *    mode) gives the ASN, the AS name, the country and — importantly — the BGP prefix the
 *    address falls in. That prefix is the natural cache key: one lookup covers every address
 *    in the announcement. The country is exposed by country(): it is the cheapest geography
 *    in the product, because this query is already being made for the ASN, and `Enrich\Geo`
 *    uses it as its country of last resort.
 *  - **RIR whois** (ARIN / RIPE / APNIC / LACNIC / AFRINIC, selected from Cymru's registry
 *    field) gives the `netname` and the org that actually holds the range. This is what
 *    catches LEASED ranges: a /24 rented out of a big ISP's allocation to a proxy provider
 *    keeps the ISP's ASN but gets its own netname, so the ASN alone would call it consumer
 *    broadband. That distinction is the difference between catching a residential-proxy
 *    fleet and not catching it.
 *  - **Forward-confirmed reverse DNS**: resolve the PTR, then resolve THAT name back and
 *    check the original address is among the answers. This is the mechanism that catches
 *    fake Googlebot — anyone can put "Googlebot" in a User-Agent, nobody can make
 *    `crawl-66-249-66-1.googlebot.com` resolve back to their own address. It is what the
 *    `rdns_claim_failed` rule (SPEC §7, weight 95) runs on.
 *
 * ## Never blocking ingestion
 *
 * `enrich.lookup_timeout` bounds every network operation here. The DNS work uses a small
 * hand-rolled UDP resolver rather than `gethostbyaddr()` precisely because the PHP builtins
 * have NO timeout control at all — a single unresponsive PTR zone would otherwise stall the
 * tail daemon for the resolver's full retry schedule, which on a default glibc box is 20
 * seconds per lookup. On any failure the corresponding fields are simply absent (SPEC §5.3).
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Enrich;

use Loghound\Security;
use Loghound\State;

final class Asn
{
    /** Cymru's bulk whois endpoint. Bulk mode is one connection per batch, not per address. */
    private const CYMRU_HOST = 'whois.cymru.com';
    private const CYMRU_PORT = 43;

    /**
     * Key under which Cymru's country travels inside the cached payload.
     *
     * Underscore-prefixed because it is not a `hits` field; documentFields() removes it before
     * anything can index it, and country() is the only reader.
     */
    private const CARRIED_CC = '_cc';

    /** Addresses per Cymru bulk connection. */
    private const CYMRU_BULK = 500;

    /** Concurrent connections allowed to any one RIR whois server. */
    private const WHOIS_PER_HOST = 4;

    /** DNS questions in flight at once against one resolver. */
    private const DNS_IN_FLIGHT = 128;

    /** A whois answer is a few kilobytes; more than this means something is wrong. */
    private const WHOIS_MAX_BYTES = 262144;

    /** Cymru's `registry` column => the RIR whois server that holds the netname. */
    private const RIR_SERVERS = [
        'arin'     => 'whois.arin.net',
        'ripencc'  => 'whois.ripe.net',
        'ripe'     => 'whois.ripe.net',
        'apnic'    => 'whois.apnic.net',
        'lacnic'   => 'whois.lacnic.net',
        'afrinic'  => 'whois.afrinic.net',
        'jpnic'    => 'whois.nic.ad.jp',
        'krnic'    => 'whois.krnic.net',
    ];

    /**
     * Keyword tables for `as_type_s`.
     *
     * Applied to the AS organisation name and the RIR netname, both lowercased, in the ORDER
     * BELOW. Order is the algorithm and each precedence decision is deliberate:
     *
     *  - `gov` and `edu` first: they are unambiguous and their names often also contain a
     *    generic word like "network" or "communications" that would otherwise capture them.
     *  - `vpn` next: a VPN provider hosted on AWS should be reported as a VPN, not as hosting,
     *    because the two mean completely different things for a bot verdict.
     *  - `mobile` before `hosting`: "T-Mobile" contains "mobile", and a mobile carrier is the
     *    one network type where many users legitimately share an address, which is exactly
     *    why the `fp_cluster_proxy_fleet` rule excludes it (SPEC §7).
     *  - `hosting` before `isp`: a datacentre operator's name almost always also contains
     *    "networks" or "telecom".
     *
     * This is a heuristic over free text and it is wrong sometimes. It is documented as a
     * heuristic, it is easy to extend, and — importantly — no rule in SPEC §7 treats it as
     * proof on its own: `hosting_asn_browser_ua` is weight 45, well below the bot threshold.
     *
     * @var array<string,string[]>
     */
    private const TYPE_KEYWORDS = [
        'gov' => [
            'government', 'gov ', ' gov', 'govt', 'ministry', 'ministerio', 'municipal',
            'municipality', 'federal', 'county of', 'city of', 'state of', 'department of',
            'defense', 'defence', 'military', 'army', 'navy', 'air force', 'nato',
            'parliament', 'europa.eu', 'public sector',
        ],
        'edu' => [
            'university', 'universit', 'universidad', 'universite', 'universiteit',
            'college', 'school', 'education', 'educational', 'academ', 'institute of technology',
            'polytechnic', 'research and education', 'national research', 'cnrs', 'jisc',
            'renater', 'dfn', 'geant', 'surfnet', 'internet2', 'campus',
        ],
        'vpn' => [
            'vpn', 'nordvpn', 'expressvpn', 'mullvad', 'private internet access',
            'surfshark', 'cyberghost', 'protonvpn', 'proton ag', 'ivpn', 'windscribe',
            'hide.me', 'purevpn', 'torguard', 'tor exit', 'tor network', 'anonym',
            'proxy', 'smartproxy', 'oxylabs', 'brightdata', 'bright data', 'luminati',
            'packetstream', 'iproyal', 'soax', 'netnut', 'rayobyte', 'zenrows',
            'private relay', 'icloud relay',
        ],
        'mobile' => [
            'mobile', 'wireless', 'cellular', 'gsm', ' lte', '3g', '4g', '5g network',
            't-mobile', 'vodafone', 'orange ', 'telefonica moviles', 'movistar', 'airtel',
            'reliance jio', 'verizon wireless', 'at&t mobility', 'telenor', 'telia',
            'three uk', 'o2 ', 'tim ', 'claro', 'vivo ', 'mtn ', 'safaricom', 'du telecom',
            'etisalat', 'turkcell', 'megafon', 'beeline', 'tele2',
        ],
        'hosting' => [
            'hosting', 'webhost', 'web host', 'cloud', 'server', 'servers', 'datacenter',
            'data center', 'datacentre', 'data centre', 'colocation', 'colo ', 'vps',
            'dedicated', 'cdn', 'content delivery',
            'amazon', 'aws', 'google llc', 'google cloud', 'microsoft', 'azure',
            'digitalocean', 'linode', 'akamai', 'vultr', 'choopa', 'ovh', 'hetzner',
            'contabo', 'scaleway', 'online s.a.s', 'leaseweb', 'oracle', 'alibaba',
            'tencent', 'huawei cloud', 'rackspace', 'equinix', 'm247', 'packet host',
            'upcloud', 'ionos', '1&1', 'godaddy', 'namecheap', 'hostinger', 'bluehost',
            'dreamhost', 'softlayer', 'fastly', 'cloudflare', 'stackpath', 'bunny',
            'hostgator', 'siteground', 'a2 hosting', 'inmotion', 'liquidweb', 'nforce',
            'worldstream', 'serverius', 'hostwinds', 'interserver', 'buyvm', 'frantech',
            'psychz', 'quadranet', 'zenlayer', 'datacamp', 'g-core', 'gcore', 'aeza',
            'vdsina', 'timeweb', 'selectel', 'yandex.cloud', 'ovhcloud', 'netcup',
        ],
        'isp' => [
            'telecom', 'telecommunication', 'communications', 'broadband', 'cable',
            'internet service', 'internet provider', 'fiber', 'fibre', 'dsl', 'adsl',
            'kabel', 'telekom', 'comcast', 'charter', 'spectrum', 'cox communications',
            'centurylink', 'lumen', 'frontier', 'british telecom', 'bt group', 'sky uk',
            'virgin media', 'deutsche telekom', 'free sas', 'bouygues', 'sfr ', 'kpn',
            'telstra', 'optus', 'rostelecom', 'mts ', 'ziggo', 'upc ', 'telenet',
            'proximus', 'swisscom', 'a1 telekom', 'orange polska', 'netia', 'digi ',
            'rcs & rds', 'vodafone kabel', 'shaw', 'rogers', 'bell canada', 'telus',
            'ntt communications', 'kddi', 'softbank', 'chinanet', 'china unicom',
            'china mobile', 'bsnl', 'isp', 'net ltd',
        ],
    ];

    /**
     * Specific phrases whose correct type contradicts the generic keyword tables.
     *
     * Checked BEFORE the keyword scan. Kept deliberately tiny — this is not a second
     * classifier, it is a short list of names where a generic word would give the wrong
     * answer and the right answer is not in doubt.
     *
     * The three groups in it are: consumer fibre ISPs whose names contain a hosting keyword;
     * mobile carriers whose names contain no mobile keyword at all, of which "cellco
     * partnership" is Verizon Wireless's registered name; and cloud providers whose AS name is
     * just the brand, with no keyword in it.
     *
     * @var array<string,string>
     */
    private const TYPE_OVERRIDES = [
        'google fiber'      => 'isp',
        'amazon connect'    => 'isp',
        'sprint'            => 'mobile',
        'cellco partnership' => 'mobile',
        'google'            => 'hosting',
        'microsoft'         => 'hosting',
        'apple inc'         => 'hosting',
        'meta platforms'    => 'hosting',
        'facebook'          => 'hosting',
        'twitter inc'       => 'hosting',
        'fastly'            => 'hosting',
        'cloudflare'        => 'hosting',
        'akamai'            => 'hosting',
        'linode'            => 'hosting',
        'vultr'             => 'hosting',
        'hetzner'           => 'hosting',
        'digitalocean'      => 'hosting',
        'ovh'               => 'hosting',
    ];

    /** @var array<string,mixed> The 'enrich' section of the config. */
    private array $cfg;

    private ?State $state;

    /**
     * @var callable|null Whois transport override.
     *                    fn(string $host, int $port, string $query, int $timeout): ?string
     *
     * Exists so the test suite can exercise the Cymru and RIR response parsing — including
     * the country column — against recorded answers rather than against the network, which
     * SPEC §12 forbids the suite from touching. Null means the real TCP socket below.
     */
    private $whois;

    /**
     * Most entries either in-process memo will hold.
     *
     * THE CAP IS THE WHOLE POINT, because the key is an address an attacker chooses and the
     * tail daemon is a long-lived process. Uncapped, `memoRdns` grows by one entry per
     * distinct source address for the lifetime of the daemon, which an IPv6 scanner rotating
     * /64s or any botnet drives without limit — a slow memory exhaustion that looks like a
     * leak rather than an attack. `Enrich\Ua` and `Parser::loggedFields` already bound their
     * caches for exactly this reason; these two did not.
     *
     * Eviction is "drop the oldest half when full". A memo is a speed-up over a store that is
     * still there (the SQLite cache), so forgetting an entry costs one read and can never
     * change an answer.
     */
    private const MEMO_MAX = 16384;

    /** @var array<string,array> In-process memo keyed by netblock / address. */
    private array $memoAsn = [];
    private array $memoRdns = [];

    /** @var string[]|null Resolvers from /etc/resolv.conf, parsed once. */
    private ?array $resolvers = null;

    /** @var callable|null  Called while waiting on the network; keeps the daemon's status fresh. */
    private $tick = null;

    /** When true, lookups answer from memo and cache only; the network is the Resolver's job. */
    private bool $offline = false;

    /** Answer lookups from memo and cache only (the async Resolver does the network part). */
    public function setOffline(bool $offline): void
    {
        $this->offline = $offline;
    }

    /** Set the heartbeat called while lookups wait on the network. */
    public function setTick(?callable $tick): void
    {
        $this->tick = $tick;
    }

    /**
     * @param array<string,mixed> $enrichCfg Config::get('enrich')
     * @param State|null          $state     Cache backing store.
     * @param callable|null       $whois     Whois transport override; see $whois.
     */
    public function __construct(array $enrichCfg, ?State $state = null, ?callable $whois = null)
    {
        $this->cfg   = $enrichCfg;
        $this->state = $state;
        $this->whois = $whois;
    }

    /**
     * Look up ASN, AS org, network type and RIR netname for an address.
     *
     * @return array<string,mixed> `asn_i`, `as_org_s`, `as_type_s`, `netname_s`. Empty on
     *                             failure; individual keys absent when unknown. Never
     *                             contains a carried key — see documentFields().
     */
    public function lookup(string $ip): array
    {
        return self::documentFields($this->cached($ip));
    }

    /**
     * The country Team Cymru reports for the prefix this address is announced in.
     *
     * This is the `CC` column of the bulk whois answer, which the parser has always read and
     * the enrichment output has always thrown away. It costs NOTHING to use: the query is
     * already being made for the ASN, so there is no extra credential, no extra dependency
     * and no extra outbound request. `Enrich\Geo` uses it as its country of last resort, which
     * is what keeps country-level geography — and, through it, `tz_s` and the `tz_mismatch`
     * rule — working when the upstream geolocation lookup is unconfigured, disabled or down.
     *
     * It is the country of the ALLOCATION, not of the host: a German prefix leased by a US
     * company can be registered as US. Geo therefore treats it as the weaker of its two
     * sources and lets the geolocation service override it. See Geo::compose().
     *
     * Cymru also uses registry pseudo-codes for supranational allocations (`EU`, `AP`). Those
     * are passed through as-is, because they are what the registry says; they simply have no
     * single timezone, so no `tz_s` is derived from them.
     *
     * An entry cached by a build that predates this method has no country in it and answers
     * null until its TTL expires. That is a cold-start cost measured in days, not a bug.
     *
     * @return string|null Uppercase ISO-3166-1 alpha-2, or a registry pseudo-code, or null.
     */
    public function country(string $ip): ?string
    {
        $cc = $this->cached($ip)[self::CARRIED_CC] ?? null;
        if (!is_string($cc) || !preg_match('/^[A-Z]{2}$/D', $cc)) {
            return null;
        }
        return $cc;
    }

    /** The netblock cache key for an address, or null when ASN lookups do not apply to it. */
    public function asnKey(string $ip): ?string
    {
        if (empty($this->cfg['asn_enabled']) || !Geo::isPublicIp($ip)) {
            return null;
        }
        return Security::ipNetwork($ip, 24, 48);
    }

    /** Is the netblock already answered, from the memo or the cache (loaded into the memo)? */
    public function hasAsn(string $key): bool
    {
        if (isset($this->memoAsn[$key])) {
            return true;
        }
        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('asn', $key, $hit);
            if ($hit) {
                $this->remember($this->memoAsn, $key, $cached ?? []);
                return true;
            }
        }
        return false;
    }

    /** Does this address still need a reverse DNS lookup? Loads a cached answer into the memo. */
    public function wantsRdns(string $ip): bool
    {
        if (empty($this->cfg['rdns_enabled']) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (isset($this->memoRdns[$ip])) {
            return false;
        }
        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('rdns', $ip, $hit);
            if ($hit) {
                $this->remember($this->memoRdns, $ip, $cached ?? []);
                return false;
            }
        }
        return self::reverseName($ip) !== null;
    }

    /** Record a netblock answer; $cache false keeps a failed lookup out of the cache. */
    public function storeAsn(string $key, array $fields, bool $cache): void
    {
        if ($cache && $this->state !== null) {
            $this->state->cachePut(
                'asn',
                $key,
                $fields === [] ? null : $fields,
                ((int) ($this->cfg['asn_ttl_days'] ?? 30)) * 86400
            );
        }
        $this->remember($this->memoAsn, $key, $fields);
    }

    /** Record a reverse DNS answer; $cache false keeps a failed lookup out of the cache. */
    public function storeRdns(string $ip, array $fields, bool $cache): void
    {
        if ($cache && $this->state !== null) {
            $this->state->cachePut(
                'rdns',
                $ip,
                $fields === [] ? null : $fields,
                ((int) ($this->cfg['rdns_ttl_days'] ?? 7)) * 86400
            );
        }
        $this->remember($this->memoRdns, $ip, $fields);
    }

    /** Enrichment setting, as configured. */
    public function setting(string $key, $default = null)
    {
        return $this->cfg[$key] ?? $default;
    }

    /**
     * The cached Cymru/RIR payload for an address, including carried non-document keys.
     *
     * Cached per NETBLOCK rather than per address (SPEC §5.3 "cached per netblock"): the key
     * is the /24 for IPv4 and the /48 for IPv6. A /24 that straddles two autonomous systems
     * is rare enough that the cost — one mislabelled ASN on a handful of hits — is far below
     * the cost of doing a whois round trip for every distinct address on a scanned server.
     *
     * lookup() and country() both read through here, so asking for both costs one lookup.
     *
     * @return array<string,mixed>
     */
    private function cached(string $ip): array
    {
        if (empty($this->cfg['asn_enabled']) || !Geo::isPublicIp($ip)) {
            return [];
        }
        $key = Security::ipNetwork($ip, 24, 48);
        if (!isset($this->memoAsn[$key])) {
            if ($this->offline) {
                $this->hasAsn($key);
            } else {
                $this->prefetch([$ip]);
            }
        }
        return $this->memoAsn[$key] ?? [];
    }

    /**
     * Look up the netblocks of many addresses at once, into the memo and the cache.
     *
     * One Cymru bulk connection per CYMRU_BULK addresses (the mode Cymru asks automated
     * clients to use), then the RIR whois requests concurrently. A netblock whose lookup
     * failed in transport is kept in the memo only and never cached, so an outage does not
     * blind the installation for the cache TTL.
     *
     * @param string[] $ips
     */
    public function prefetch(array $ips): void
    {
        if (empty($this->cfg['asn_enabled'])) {
            return;
        }

        $want = [];
        foreach ($ips as $ip) {
            $ip = (string) $ip;
            if (!Geo::isPublicIp($ip)) {
                continue;
            }
            $key = Security::ipNetwork($ip, 24, 48);
            if (isset($want[$key]) || isset($this->memoAsn[$key])) {
                continue;
            }
            if ($this->state !== null) {
                $hit = false;
                $cached = $this->state->cacheGet('asn', $key, $hit);
                if ($hit) {
                    $this->remember($this->memoAsn, $key, $cached ?? []);
                    continue;
                }
            }
            $want[$key] = $ip;
        }
        if ($want === []) {
            return;
        }

        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));
        $ttl = ((int) ($this->cfg['asn_ttl_days'] ?? 30)) * 86400;

        foreach (array_chunk($want, self::CYMRU_BULK, true) as $chunk) {
            if ($this->tick !== null) {
                ($this->tick)();
            }
            $body = $this->whoisQuery(
                self::CYMRU_HOST,
                self::CYMRU_PORT,
                "begin\nverbose\n" . implode("\n", $chunk) . "\nend\n",
                $timeout * (1 + intdiv(count($chunk), 100))
            );
            if ($body === null) {
                foreach ($chunk as $key => $_) {
                    $this->remember($this->memoAsn, (string) $key, []);
                }
                continue;
            }

            $rows = self::parseCymru($body);
            $found = [];
            $jobs = [];
            foreach ($chunk as $key => $ip) {
                $bin = @inet_pton($ip);
                $row = $rows[$bin === false ? $ip : (string) inet_ntop($bin)] ?? null;
                if ($row === null) {
                    if ($this->state !== null) {
                        $this->state->cachePut('asn', (string) $key, null, $ttl);
                    }
                    $this->remember($this->memoAsn, (string) $key, []);
                    continue;
                }
                $found[$key] = $row;
                if (!empty($this->cfg['whois_enabled'])) {
                    $job = self::rirJob($ip, $row['registry']);
                    if ($job !== null) {
                        $jobs[$key] = $job;
                    }
                }
            }

            $replies = $jobs === [] ? [] : $this->whoisMany($jobs);

            foreach ($found as $key => $row) {
                $key = (string) $key;
                $reply = $replies[$key] ?? null;
                $failed = isset($jobs[$key]) && $reply === null;
                $fields = self::payload($row, $reply === null ? null : self::parseRir($reply));
                if (!$failed && $this->state !== null) {
                    $this->state->cachePut('asn', $key, $fields, $ttl);
                }
                $this->remember($this->memoAsn, $key, $fields);
            }
        }
    }

    /**
     * Write one entry into a bounded memo and return it.
     *
     * @param array<string,array> $memo
     * @param array<string,mixed> $fields
     * @return array<string,mixed>
     */
    private function remember(array &$memo, string $key, array $fields): array
    {
        if (count($memo) >= self::MEMO_MAX) {
            $memo = array_slice($memo, intdiv(self::MEMO_MAX, 2), null, true);
        }
        $memo[$key] = $fields;
        return $fields;
    }

    /**
     * Strip the carried keys, leaving only fields the `hits` schema defines.
     *
     * The payload holds one value that is NOT a document field: Cymru's country, which
     * `Enrich\Geo` consumes and which the schema has no `_cc` field for. It travels inside the
     * cached payload rather than in a second cache entry so that one whois answer serves both
     * readers, and it is removed here so that no caller of lookup() can accidentally index it.
     * The underscore prefix matches the convention bin/loghound-tail already uses for
     * pipeline-internal keys.
     *
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private static function documentFields(array $payload): array
    {
        $out = [];
        foreach ($payload as $k => $v) {
            if (!is_string($k) || $k === '' || $k[0] !== '_') {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    /**
     * Build the cached payload for one netblock from its Cymru row and optional RIR reply.
     *
     * Cymru's country is carried out under CARRIED_CC for Geo to read, validated to the
     * two-letter shape here so a malformed whois line cannot put anything else into the cache.
     *
     * @param array{asn:int,prefix:string,cc:string,registry:string,as_name:string} $cymru
     * @param array{netname:string,org:string}|null $rir
     * @return array<string,mixed>
     */
    public static function payload(array $cymru, ?array $rir): array
    {
        $out = [];
        if ($cymru['asn'] > 0) {
            $out['asn_i'] = $cymru['asn'];
        }
        if (preg_match('/^[A-Za-z]{2}$/D', $cymru['cc'])) {
            $out[self::CARRIED_CC] = strtoupper($cymru['cc']);
        }
        if ($cymru['as_name'] !== '') {
            $out['as_org_s'] = self::clean($cymru['as_name'], 255);
        }

        $netname = $rir['netname'] ?? '';
        $orgName = $rir['org'] ?? '';
        if ($netname !== '') {
            $out['netname_s'] = self::clean($netname, 255);
        }
        if (!isset($out['as_org_s']) && $orgName !== '') {
            $out['as_org_s'] = self::clean($orgName, 255);
        }

        $out['as_type_s'] = self::classifyOrg(($cymru['as_name'] . ' ' . $orgName), $netname);

        return $out;
    }

    /**
     * Parse a Cymru bulk whois answer into rows keyed by the address they answer.
     *
     *   AS      | IP            | BGP Prefix    | CC | Registry | Allocated  | AS Name
     *   15169   | 8.8.8.8       | 8.8.8.0/24    | US | arin     | 1992-12-01 | GOOGLE, US
     *
     * A data row starts with a number, the header with "AS". The trailing country code on the
     * AS name is noise and is dropped.
     *
     * @return array<string,array{asn:int,prefix:string,cc:string,registry:string,as_name:string}>
     */
    public static function parseCymru(string $body): array
    {
        $rows = [];
        foreach (preg_split('/\r\n|\n/', $body) ?: [] as $line) {
            if (!str_contains($line, '|')) {
                continue;
            }
            $cols = array_map('trim', explode('|', $line));
            if (count($cols) < 7 || !ctype_digit($cols[0])) {
                continue;
            }
            $bin = @inet_pton($cols[1]);
            $key = $bin === false ? $cols[1] : (string) inet_ntop($bin);
            $rows[$key] = [
                'asn'      => (int) $cols[0],
                'prefix'   => $cols[2],
                'cc'       => $cols[3],
                'registry' => strtolower($cols[4]),
                'as_name'  => (string) preg_replace('/,\s*[A-Z]{2}$/', '', $cols[6]),
            ];
        }
        return $rows;
    }

    /**
     * The whois request that asks the right RIR for the netname and org of an address.
     *
     * ARIN needs the 'n +' flag to return the network record with its NetName; the other RIRs
     * answer a bare address directly.
     *
     * @param string $registry Cymru's registry column ('arin', 'ripencc', ...).
     * @return array{0:string,1:int,2:string}|null [host, port, query]
     */
    public static function rirJob(string $ip, string $registry): ?array
    {
        $server = self::RIR_SERVERS[$registry] ?? null;
        if ($server === null) {
            return null;
        }
        $query = $server === 'whois.arin.net' ? ('n + ' . $ip . "\r\n") : ($ip . "\r\n");
        return [$server, 43, $query];
    }

    /**
     * Read the netname and org out of an RIR whois reply.
     *
     * `netname` for RIPE, APNIC, AFRINIC and ARIN alike, matched case-insensitively;
     * `orgname` for ARIN, `org-name` for RIPE and `owner` for LACNIC; and the free-text
     * `descr` field that RIPE and APNIC share, as the usual fallback.
     *
     * @return array{netname:string,org:string}|null
     */
    public static function parseRir(string $body): ?array
    {
        $netname = '';
        $org     = '';
        $descr   = '';

        foreach (preg_split('/\r\n|\n/', $body) ?: [] as $line) {
            $pos = strpos($line, ':');
            if ($pos === false) {
                continue;
            }
            $field = strtolower(trim(substr($line, 0, $pos)));
            $value = trim(substr($line, $pos + 1));
            if ($value === '') {
                continue;
            }

            switch ($field) {
                case 'netname':
                    $netname = $netname === '' ? $value : $netname;
                    break;
                case 'orgname':
                case 'org-name':
                case 'organization':
                case 'owner':
                    $org = $org === '' ? $value : $org;
                    break;
                case 'descr':
                    $descr = $descr === '' ? $value : $descr;
                    break;
            }
        }

        if ($org === '') {
            $org = $descr;
        }
        if ($netname === '' && $org === '') {
            return null;
        }
        return ['netname' => $netname, 'org' => $org];
    }

    /**
     * One whois request over a raw TCP socket, with a hard timeout on every phase.
     *
     * `fsockopen` covers the connect timeout, `stream_set_timeout` the read timeout, and the
     * accumulated-byte cap covers a server that never stops talking. Together that is the
     * "MUST NOT block ingestion" guarantee for the whois half of this class.
     *
     * The connect is @-suppressed: an unreachable whois server is an ordinary, expected
     * condition here, not something worth emitting a PHP warning into the daemon's log for. A
     * whois answer is a few kilobytes, so the 256 KB cap means something is wrong.
     *
     * An injected transport replaces the socket entirely, which is how the suite pins the
     * response parsing without making a request. It is held to the same contract: a string or
     * null, never an empty string standing in for a failure.
     */
    private function whoisQuery(string $host, int $port, string $query, ?int $timeout = null): ?string
    {
        $timeout = $timeout ?? max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));

        if ($this->whois !== null) {
            $body = ($this->whois)($host, $port, $query, $timeout);
            return is_string($body) && $body !== '' ? $body : null;
        }

        $errno  = 0;
        $errstr = '';
        $fp = @fsockopen($host, $port, $errno, $errstr, (float) $timeout);
        if ($fp === false) {
            return null;
        }
        stream_set_timeout($fp, $timeout);

        if (@fwrite($fp, $query) === false) {
            fclose($fp);
            return null;
        }

        $body     = '';
        $deadline = microtime(true) + $timeout;
        while (!feof($fp)) {
            $chunk = @fread($fp, 8192);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $body .= $chunk;
            if ($this->tick !== null) {
                ($this->tick)();
            }
            if (strlen($body) > self::WHOIS_MAX_BYTES || microtime(true) > $deadline) {
                break;
            }
            $meta = stream_get_meta_data($fp);
            if (!empty($meta['timed_out'])) {
                break;
            }
        }
        fclose($fp);

        return $body === '' ? null : $body;
    }

    /**
     * Many whois requests at once, at most WHOIS_PER_HOST open to any one server.
     *
     * @param array<string,array{0:string,1:int,2:string}> $jobs key => [host, port, query]
     * @return array<string,string|null> key => body, null on failure.
     */
    private function whoisMany(array $jobs): array
    {
        $out = [];
        if ($this->whois !== null) {
            foreach ($jobs as $k => $j) {
                $out[$k] = $this->whoisQuery($j[0], $j[1], $j[2]);
            }
            return $out;
        }

        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));
        $queue = $jobs;
        $active = [];
        $perHost = [];

        while ($queue !== [] || $active !== []) {
            foreach ($queue as $k => $j) {
                if (($perHost[$j[0]] ?? 0) >= self::WHOIS_PER_HOST) {
                    continue;
                }
                unset($queue[$k]);
                $errno = 0;
                $errstr = '';
                $fp = @stream_socket_client(
                    'tcp://' . $j[0] . ':' . $j[1],
                    $errno,
                    $errstr,
                    (float) $timeout,
                    STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
                );
                if ($fp === false) {
                    $out[$k] = null;
                    continue;
                }
                stream_set_blocking($fp, false);
                $active[(int) $fp] = [
                    'key' => $k, 'fp' => $fp, 'host' => $j[0], 'query' => $j[2],
                    'sent' => false, 'body' => '', 'deadline' => microtime(true) + $timeout,
                ];
                $perHost[$j[0]] = ($perHost[$j[0]] ?? 0) + 1;
            }
            if ($active === []) {
                continue;
            }

            $read = [];
            $write = [];
            foreach ($active as $id => $a) {
                if ($a['sent']) {
                    $read[$id] = $a['fp'];
                } else {
                    $write[$id] = $a['fp'];
                }
            }
            $e = null;
            if ($this->tick !== null) {
                ($this->tick)();
            }
            $ready = @stream_select($read, $write, $e, 0, 100000);

            $done = [];
            if ($ready > 0) {
                foreach ($write as $fp) {
                    $id = (int) $fp;
                    if (@fwrite($fp, $active[$id]['query']) === false) {
                        $done[$id] = true;
                    } else {
                        $active[$id]['sent'] = true;
                    }
                }
                foreach ($read as $fp) {
                    $id = (int) $fp;
                    $chunk = @fread($fp, 8192);
                    if ($chunk === false || $chunk === '') {
                        if ($chunk === false || feof($fp)) {
                            $done[$id] = true;
                        }
                        continue;
                    }
                    $active[$id]['body'] .= $chunk;
                    if (strlen($active[$id]['body']) > self::WHOIS_MAX_BYTES) {
                        $done[$id] = true;
                    }
                }
            }

            $now = microtime(true);
            foreach ($active as $id => $a) {
                if (isset($done[$id]) || $now > $a['deadline']) {
                    fclose($a['fp']);
                    $out[$a['key']] = $a['body'] === '' ? null : $a['body'];
                    $perHost[$a['host']]--;
                    unset($active[$id]);
                }
            }
        }

        return $out;
    }

    /**
     * Classify a network from its AS organisation name and RIR netname.
     *
     * Both strings are searched, because the two disagree in exactly the interesting case:
     * a leased /24 inside a consumer ISP's allocation carries the ISP's AS name and the
     * lessee's netname, and the lessee is who we actually care about.
     *
     * Returns one of: isp | hosting | vpn | edu | gov | mobile | unknown (SPEC §4.1).
     *
     * Separators are normalised first, so that "T-MOBILE-NL" matches both the "t-mobile" and
     * the "mobile" needles. A VPN or proxy brand then wins over everything, including an
     * override: "MULLVAD-VPN-EXIT" inside an Amazon allocation is a VPN exit, not a cloud
     * instance, and that case is the whole reason the netname is consulted at all. The
     * override table comes next, for names whose correct type contradicts the generic keyword
     * tables, and the keyword scan last.
     */
    public static function classifyOrg(string $asOrg, string $netname = ''): string
    {
        $haystack = ' ' . strtolower(trim($asOrg . ' ' . $netname)) . ' ';
        if (trim($haystack) === '') {
            return 'unknown';
        }
        $haystack = str_replace(['_', '/', '.', ','], ' ', $haystack);

        foreach (self::TYPE_KEYWORDS['vpn'] as $needle) {
            if (str_contains($haystack, $needle)) {
                return 'vpn';
            }
        }

        foreach (self::TYPE_OVERRIDES as $phrase => $type) {
            if (str_contains($haystack, $phrase)) {
                return $type;
            }
        }

        foreach (self::TYPE_KEYWORDS as $type => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($haystack, $needle)) {
                    return $type;
                }
            }
        }
        return 'unknown';
    }

    /**
     * Resolve the PTR for an address and forward-confirm it.
     *
     * "Forward-confirmed" means: PTR(ip) gives a name, then A/AAAA(name) must include the
     * original address. Only then is `rdns_ok_b` true. It is what separates a real Googlebot
     * from a scraper that only claims to be one (`rdns_claim_failed`, SPEC §7).
     *
     * @return array<string,mixed> `rdns_s` and `rdns_ok_b`, or empty when nothing resolved.
     */
    public function rdns(string $ip): array
    {
        if (empty($this->cfg['rdns_enabled']) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return [];
        }
        if (!isset($this->memoRdns[$ip])) {
            if ($this->offline) {
                $this->wantsRdns($ip);
            } else {
                $this->prefetchRdns([$ip]);
            }
        }
        return $this->memoRdns[$ip] ?? [];
    }

    /**
     * Resolve and forward-confirm many addresses concurrently, into the memo and the cache.
     *
     * A lookup that could not be answered (every resolver timed out) is kept in the memo only,
     * never in the cache, and a forward check that could not be answered leaves `rdns_ok_b`
     * absent (unknown) rather than false (failed).
     *
     * @param string[] $ips
     */
    public function prefetchRdns(array $ips): void
    {
        if (empty($this->cfg['rdns_enabled'])) {
            return;
        }

        $ptr = [];
        foreach ($ips as $ip) {
            $ip = (string) $ip;
            if (isset($ptr[$ip]) || isset($this->memoRdns[$ip]) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
                continue;
            }
            if ($this->state !== null) {
                $hit = false;
                $cached = $this->state->cacheGet('rdns', $ip, $hit);
                if ($hit) {
                    $this->remember($this->memoRdns, $ip, $cached ?? []);
                    continue;
                }
            }
            $qname = self::reverseName($ip);
            if ($qname === null) {
                continue;
            }
            $ptr[$ip] = [$qname, 12];
        }
        if ($ptr === []) {
            return;
        }

        $names = [];
        $failed = [];
        foreach ($this->dnsMany($ptr) as $ip => $answers) {
            $ip = (string) $ip;
            if ($answers === null) {
                $failed[$ip] = true;
                continue;
            }
            $name = $answers === [] ? null : self::validName((string) $answers[0]);
            if ($name !== null) {
                $names[$ip] = $name;
            }
        }

        $fwd = [];
        foreach ($names as $ip => $name) {
            $fwd[$ip] = [$name, str_contains($ip, ':') ? 28 : 1];
        }
        $confirm = $fwd === [] ? [] : $this->dnsMany($fwd);

        $ttl = ((int) ($this->cfg['rdns_ttl_days'] ?? 7)) * 86400;
        foreach ($ptr as $ip => $_) {
            $ip = (string) $ip;
            if (isset($failed[$ip])) {
                $this->remember($this->memoRdns, $ip, []);
                continue;
            }
            $fields = [];
            $complete = true;
            if (isset($names[$ip])) {
                $fields['rdns_s'] = self::clean($names[$ip], 255);
                $answers = $confirm[$ip] ?? null;
                if ($answers === null) {
                    $complete = false;
                } else {
                    $fields['rdns_ok_b'] = self::addressIn($ip, $answers);
                }
            }
            if ($complete && $this->state !== null) {
                $this->state->cachePut('rdns', $ip, $fields === [] ? null : $fields, $ttl);
            }
            $this->remember($this->memoRdns, $ip, $fields);
        }
    }

    /**
     * A PTR answer as a hostname, or null.
     *
     * Anything outside the restricted hostname grammar came from a hostile PTR zone and must
     * not reach a Solr document or the panel.
     */
    public static function validName(string $name): ?string
    {
        $name = rtrim($name, '.');
        if (!preg_match('/^[A-Za-z0-9]([A-Za-z0-9\-._]{0,252}[A-Za-z0-9])?$/D', $name)) {
            return null;
        }
        return strtolower($name);
    }

    /** Is $ip among the A/AAAA answers? */
    public static function addressIn(string $ip, array $answers): bool
    {
        $target = @inet_pton($ip);
        if ($target === false) {
            return false;
        }
        foreach ($answers as $addr) {
            $bin = @inet_pton((string) $addr);
            if ($bin !== false && $bin === $target) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build the in-addr.arpa / ip6.arpa query name for an address.
     *
     * IPv4 reverses the octets; IPv6 reverses every nibble, dot-separated.
     */
    public static function reverseName(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            $parts = array_reverse(explode('.', $ip));
            return implode('.', $parts) . '.in-addr.arpa';
        }
        $hex = bin2hex($bin);
        $nibbles = array_reverse(str_split($hex));
        return implode('.', $nibbles) . '.ip6.arpa';
    }

    /**
     * Resolve many name/type questions at once over UDP, each with a hard timeout.
     *
     * All questions are in flight together against one resolver; whatever timed out or failed
     * is asked again of the next. A valid empty answer (NXDOMAIN/NODATA) is a real result.
     *
     * @param array<string,array{0:string,1:int}> $queries key => [qname, qtype]
     * @return array<string,string[]|null> key => answers, [] when empty, null when no resolver answered.
     */
    private function dnsMany(array $queries): array
    {
        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));
        $out = [];
        $todo = $queries;

        foreach ($this->resolvers() as $server) {
            if ($todo === []) {
                break;
            }
            $target = str_contains($server, ':') ? '[' . $server . ']' : $server;
            $queue = $todo;
            $todo = [];
            $flight = [];

            while ($queue !== [] || $flight !== []) {
                while ($queue !== [] && count($flight) < self::DNS_IN_FLIGHT) {
                    $k = array_key_first($queue);
                    $q = $queue[$k];
                    unset($queue[$k]);

                    $packet = self::buildQuery($q[0], $q[1]);
                    if ($packet === null) {
                        $out[$k] = [];
                        continue;
                    }
                    $errno = 0;
                    $errstr = '';
                    $sock = @stream_socket_client('udp://' . $target . ':53', $errno, $errstr, (float) $timeout);
                    if ($sock === false) {
                        $todo[$k] = $q;
                        continue;
                    }
                    stream_set_blocking($sock, false);
                    if (@fwrite($sock, $packet) === false) {
                        fclose($sock);
                        $todo[$k] = $q;
                        continue;
                    }
                    $flight[(int) $sock] = [$k, $sock, $packet, microtime(true) + $timeout, $q];
                }
                if ($flight === []) {
                    continue;
                }

                $read = [];
                foreach ($flight as $id => $f) {
                    $read[$id] = $f[1];
                }
                $w = null;
                $e = null;
                if ($this->tick !== null) {
                    ($this->tick)();
                }
                if (@stream_select($read, $w, $e, 0, 100000) > 0) {
                    foreach ($read as $sock) {
                        $id = (int) $sock;
                        [$k, , $packet, , $q] = $flight[$id];
                        $response = @fread($sock, 4096);
                        fclose($sock);
                        unset($flight[$id]);

                        if (!is_string($response) || strlen($response) < 12) {
                            $todo[$k] = $q;
                            continue;
                        }
                        $answers = self::parseAnswers($response, $packet, $q[1]);
                        if ($answers !== []) {
                            $out[$k] = $answers;
                        } elseif (self::responseIsAuthoritativeEmpty($response, $packet)) {
                            $out[$k] = [];
                        } else {
                            $todo[$k] = $q;
                        }
                    }
                }

                $now = microtime(true);
                foreach ($flight as $id => $f) {
                    if ($now >= $f[3]) {
                        fclose($f[1]);
                        unset($flight[$id]);
                        $todo[$f[0]] = $f[4];
                    }
                }
            }
        }

        foreach ($todo as $k => $_) {
            $out[$k] = null;
        }
        return $out;
    }

    /**
     * Read the system resolvers from /etc/resolv.conf, once.
     *
     * If the file is missing or lists nothing usable, DNS enrichment is simply unavailable
     * and `rdns_s`/`rdns_ok_b` stay absent — which is the honest outcome, and better than
     * falling back to a blocking builtin that could stall ingestion.
     *
     * An explicit config override wins over the file, which is useful in containers that have
     * no resolv.conf. A %zone suffix on a link-local IPv6 resolver is stripped. At most two
     * resolvers are tried, so a dead primary costs one timeout rather than five.
     *
     * @return string[]
     */
    public function resolvers(): array
    {
        if ($this->resolvers !== null) {
            return $this->resolvers;
        }
        $out = [];

        foreach ((array) ($this->cfg['dns_servers'] ?? []) as $server) {
            if (filter_var((string) $server, FILTER_VALIDATE_IP) !== false) {
                $out[] = (string) $server;
            }
        }

        if ($out === [] && is_readable('/etc/resolv.conf')) {
            $text = @file_get_contents('/etc/resolv.conf');
            if (is_string($text)
                && preg_match_all('/^\s*nameserver\s+(\S+)/mi', $text, $m)) {
                foreach ($m[1] as $server) {
                    $server = explode('%', $server)[0];
                    if (filter_var($server, FILTER_VALIDATE_IP) !== false) {
                        $out[] = $server;
                    }
                }
            }
        }

        return $this->resolvers = array_slice(array_unique($out), 0, 2);
    }

    /**
     * Build a DNS query packet for one question.
     *
     * Header: random id, flags 0x0100 (standard query, recursion desired), QDCOUNT 1. The
     * question is asked with QCLASS 1, IN.
     */
    public static function buildQuery(string $qname, int $qtype): ?string
    {
        $qname = rtrim($qname, '.');
        if ($qname === '' || strlen($qname) > 253) {
            return null;
        }

        $encoded = '';
        foreach (explode('.', $qname) as $label) {
            $len = strlen($label);
            if ($len === 0 || $len > 63) {
                return null;
            }
            $encoded .= chr($len) . $label;
        }
        $encoded .= "\0";

        $id = random_int(0, 65535);
        $header = pack('n6', $id, 0x0100, 1, 0, 0, 0);

        return $header . $encoded . pack('nn', $qtype, 1);
    }

    /**
     * Extract the answer values from a DNS response.
     *
     * Rejects a response whose transaction id does not match the query's, which is the
     * minimum defence against an off-path spoofed reply.
     *
     * A set TC bit means the answer was truncated, and we do not retry over TCP. A non-zero
     * RCODE means an error, and there is nothing to read. Otherwise the question section is
     * skipped — its name, then QTYPE and QCLASS — and the answers are read, with a PTR name
     * possibly arriving compressed.
     *
     * @return string[]
     */
    public static function parseAnswers(string $response, string $query, int $qtype): array
    {
        if (substr($response, 0, 2) !== substr($query, 0, 2)) {
            return [];
        }

        $header = unpack('nid/nflags/nqd/nan/nns/nar', substr($response, 0, 12));
        if ($header === false || $header['an'] < 1) {
            return [];
        }
        if (($header['flags'] & 0x0200) !== 0) {
            return [];
        }
        if (($header['flags'] & 0x000F) !== 0) {
            return [];
        }

        $offset = 12;
        $len    = strlen($response);

        for ($i = 0; $i < $header['qd']; $i++) {
            if (!self::skipName($response, $offset)) {
                return [];
            }
            $offset += 4;
        }

        $out = [];
        for ($i = 0; $i < $header['an'] && $offset + 10 <= $len; $i++) {
            if (!self::skipName($response, $offset)) {
                break;
            }
            $rr = unpack('ntype/nclass/Nttl/nrdlength', substr($response, $offset, 10));
            if ($rr === false) {
                break;
            }
            $offset += 10;
            $rdlength = (int) $rr['rdlength'];
            if ($offset + $rdlength > $len) {
                break;
            }
            $rdata = substr($response, $offset, $rdlength);

            if ((int) $rr['type'] === $qtype) {
                if ($qtype === 12) {
                    $namePos = $offset;
                    $name = self::readName($response, $namePos, 0);
                    if ($name !== null && $name !== '') {
                        $out[] = $name;
                    }
                } elseif ($qtype === 1 && $rdlength === 4) {
                    $addr = @inet_ntop($rdata);
                    if ($addr !== false) {
                        $out[] = $addr;
                    }
                } elseif ($qtype === 28 && $rdlength === 16) {
                    $addr = @inet_ntop($rdata);
                    if ($addr !== false) {
                        $out[] = $addr;
                    }
                }
            }
            $offset += $rdlength;
        }

        return $out;
    }

    /**
     * Was this a well-formed response that simply had no answer (NXDOMAIN / NODATA)?
     *
     * Used to stop querying the next resolver: a definitive "no such record" is a result,
     * not a failure, and asking a second server would only add latency. That means NOERROR
     * with zero answers, or NXDOMAIN.
     */
    public static function responseIsAuthoritativeEmpty(string $response, string $query): bool
    {
        if (substr($response, 0, 2) !== substr($query, 0, 2)) {
            return false;
        }
        $header = unpack('nid/nflags/nqd/nan/nns/nar', substr($response, 0, 12));
        if ($header === false) {
            return false;
        }
        $rcode = $header['flags'] & 0x000F;
        return $rcode === 0 || $rcode === 3;
    }

    /**
     * Advance $offset past a (possibly compressed) domain name.
     *
     * Returns false when the name is malformed, which is how a hostile response gets
     * rejected instead of sending the parser into a loop. A compression pointer is two bytes
     * in total and the name ends there.
     */
    private static function skipName(string $buf, int &$offset): bool
    {
        $len = strlen($buf);
        $guard = 0;
        while ($offset < $len) {
            if (++$guard > 128) {
                return false;
            }
            $l = ord($buf[$offset]);
            if ($l === 0) {
                $offset++;
                return true;
            }
            if (($l & 0xC0) === 0xC0) {
                $offset += 2;
                return true;
            }
            $offset += 1 + $l;
        }
        return false;
    }

    /**
     * Read a (possibly compressed) domain name, following pointers.
     *
     * $depth guards against a response whose compression pointers form a cycle — a classic
     * DNS parser denial-of-service that must not be able to hang the ingest daemon.
     */
    private static function readName(string $buf, int &$offset, int $depth): ?string
    {
        if ($depth > 16) {
            return null;
        }
        $len   = strlen($buf);
        $parts = [];
        $guard = 0;

        while ($offset < $len) {
            if (++$guard > 128) {
                return null;
            }
            $l = ord($buf[$offset]);
            if ($l === 0) {
                $offset++;
                break;
            }
            if (($l & 0xC0) === 0xC0) {
                if ($offset + 1 >= $len) {
                    return null;
                }
                $pointer = (($l & 0x3F) << 8) | ord($buf[$offset + 1]);
                $offset += 2;
                $sub = self::readName($buf, $pointer, $depth + 1);
                if ($sub === null) {
                    return null;
                }
                $parts[] = $sub;
                break;
            }
            if ($offset + 1 + $l > $len) {
                return null;
            }
            $parts[] = substr($buf, $offset + 1, $l);
            $offset += 1 + $l;
        }

        return implode('.', $parts);
    }

    /**
     * Trim, length-cap and strip control characters from remote text.
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
