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
 *    in the announcement.
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

    /** @var array<string,array> In-process memo keyed by netblock / address. */
    private array $memoAsn = [];
    private array $memoRdns = [];

    /** @var string[]|null Resolvers from /etc/resolv.conf, parsed once. */
    private ?array $resolvers = null;

    /**
     * @param array<string,mixed> $enrichCfg Config::get('enrich')
     * @param State|null          $state     Cache backing store.
     */
    public function __construct(array $enrichCfg, ?State $state = null)
    {
        $this->cfg   = $enrichCfg;
        $this->state = $state;
    }

    /**
     * Look up ASN, AS org, network type and RIR netname for an address.
     *
     * Cached per NETBLOCK rather than per address (SPEC §5.3 "cached per netblock"): the key
     * is the /24 for IPv4 and the /48 for IPv6. A /24 that straddles two autonomous systems
     * is rare enough that the cost — one mislabelled ASN on a handful of hits — is far below
     * the cost of doing a whois round trip for every distinct address on a scanned server.
     *
     * @return array<string,mixed> `asn_i`, `as_org_s`, `as_type_s`, `netname_s`. Empty on
     *                             failure; individual keys absent when unknown.
     */
    public function lookup(string $ip): array
    {
        if (empty($this->cfg['asn_enabled'])) {
            return [];
        }
        if (!Geo::isPublicIp($ip)) {
            return [];
        }

        $key = Security::ipNetwork($ip, 24, 48);

        if (isset($this->memoAsn[$key])) {
            return $this->memoAsn[$key];
        }
        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('asn', $key, $hit);
            if ($hit) {
                return $this->memoAsn[$key] = ($cached ?? []);
            }
        }

        $fields = $this->lookupUncached($ip);

        if ($this->state !== null) {
            $this->state->cachePut(
                'asn',
                $key,
                $fields === [] ? null : $fields,
                ((int) ($this->cfg['asn_ttl_days'] ?? 30)) * 86400
            );
        }
        return $this->memoAsn[$key] = $fields;
    }

    /**
     * The uncached half of lookup(): Cymru, then optionally the RIR, then classify.
     *
     * The RIR lookup is a second network round trip. It is what finds leased ranges, but it is
     * also the slowest part, which is why it is separately switchable. Its org name is
     * preferred only when Cymru gave us nothing.
     *
     * @return array<string,mixed>
     */
    private function lookupUncached(string $ip): array
    {
        $cymru = $this->cymru($ip);
        if ($cymru === null) {
            return [];
        }

        $out = [];
        if ($cymru['asn'] > 0) {
            $out['asn_i'] = $cymru['asn'];
        }
        if ($cymru['as_name'] !== '') {
            $out['as_org_s'] = self::clean($cymru['as_name'], 255);
        }

        $netname = '';
        $orgName = '';
        if (!empty($this->cfg['whois_enabled'])) {
            $rir = $this->rirWhois($ip, $cymru['registry']);
            if ($rir !== null) {
                $netname = $rir['netname'];
                $orgName = $rir['org'];
                if ($netname !== '') {
                    $out['netname_s'] = self::clean($netname, 255);
                }
                if (!isset($out['as_org_s']) && $orgName !== '') {
                    $out['as_org_s'] = self::clean($orgName, 255);
                }
            }
        }

        $out['as_type_s'] = self::classifyOrg(
            ($cymru['as_name'] . ' ' . $orgName),
            $netname
        );

        return $out;
    }

    /**
     * Query Team Cymru's bulk whois for one address.
     *
     * Bulk mode ("begin" / "verbose" / addresses / "end") is used even for a single address
     * because it is the mode that returns the BGP prefix and the registry, both of which we
     * need, and because it is the mode Cymru asks automated clients to use.
     *
     * Response shape:
     *   AS      | IP            | BGP Prefix    | CC | Registry | Allocated  | AS Name
     *   15169   | 8.8.8.8       | 8.8.8.0/24    | US | arin     | 1992-12-01 | GOOGLE, US
     *
     * The header row is told apart from the data by its first column: the header starts with
     * the literal "AS", a data row with a number. The AS name column carries a trailing
     * country code ("GOOGLE, US") which is noise and is dropped.
     *
     * @return array{asn:int,prefix:string,cc:string,registry:string,as_name:string}|null
     */
    private function cymru(string $ip): ?array
    {
        $body = $this->whoisQuery(
            self::CYMRU_HOST,
            self::CYMRU_PORT,
            "begin\nverbose\n" . $ip . "\nend\n"
        );
        if ($body === null) {
            return null;
        }

        foreach (preg_split('/\r\n|\n/', $body) ?: [] as $line) {
            if (!str_contains($line, '|')) {
                continue;
            }
            $cols = array_map('trim', explode('|', $line));
            if (count($cols) < 7 || !ctype_digit($cols[0])) {
                continue;
            }
            return [
                'asn'      => (int) $cols[0],
                'prefix'   => $cols[2],
                'cc'       => $cols[3],
                'registry' => strtolower($cols[4]),
                'as_name'  => (string) preg_replace('/,\s*[A-Z]{2}$/', '', $cols[6]),
            ];
        }
        return null;
    }

    /**
     * Query the appropriate RIR whois server for the netname and org of an address.
     *
     * ARIN needs the 'n +' flag to return the network record with its NetName; the other RIRs
     * answer a bare address directly. The reply is then read with each RIR's own spelling in
     * mind: `netname` for RIPE, APNIC, AFRINIC and ARIN alike, matched case-insensitively;
     * `orgname` for ARIN, `org-name` for RIPE and `owner` for LACNIC; and the free-text
     * `descr` field that RIPE and APNIC share, as the usual fallback.
     *
     * @param string $registry Cymru's registry column ('arin', 'ripencc', ...).
     * @return array{netname:string,org:string}|null
     */
    private function rirWhois(string $ip, string $registry): ?array
    {
        $server = self::RIR_SERVERS[$registry] ?? null;
        if ($server === null) {
            return null;
        }

        $query = $server === 'whois.arin.net' ? ('n + ' . $ip . "\r\n") : ($ip . "\r\n");

        $body = $this->whoisQuery($server, 43, $query);
        if ($body === null) {
            return null;
        }

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
     */
    private function whoisQuery(string $host, int $port, string $query): ?string
    {
        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));

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
            if (strlen($body) > 262144 || microtime(true) > $deadline) {
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
     * original address. Only then is `rdns_ok_b` true.
     *
     * This is the single check that separates a real Googlebot from the thousands of
     * scrapers that put "Googlebot" in their User-Agent, and it is the reason
     * `rdns_claim_failed` carries the heaviest non-definitive weight in SPEC §7. It works
     * because the reverse zone for a crawler's address range is controlled by the crawler's
     * operator and by nobody else.
     *
     * A PTR that does not resolve back is not a lie by itself — plenty of legitimate hosts
     * have stale reverse zones. It is only evidence when combined with a UA that CLAIMS to be
     * a named crawler.
     *
     * @return array<string,mixed> `rdns_s` and `rdns_ok_b`, or empty when nothing resolved.
     */
    public function rdns(string $ip): array
    {
        if (empty($this->cfg['rdns_enabled'])) {
            return [];
        }
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return [];
        }

        if (isset($this->memoRdns[$ip])) {
            return $this->memoRdns[$ip];
        }
        if ($this->state !== null) {
            $hit = false;
            $cached = $this->state->cacheGet('rdns', $ip, $hit);
            if ($hit) {
                return $this->memoRdns[$ip] = ($cached ?? []);
            }
        }

        $fields = [];
        $name = $this->ptr($ip);
        if ($name !== null) {
            $fields['rdns_s'] = self::clean($name, 255);
            $fields['rdns_ok_b'] = $this->forwardConfirms($name, $ip);
        }

        if ($this->state !== null) {
            $this->state->cachePut(
                'rdns',
                $ip,
                $fields === [] ? null : $fields,
                ((int) ($this->cfg['rdns_ttl_days'] ?? 7)) * 86400
            );
        }
        return $this->memoRdns[$ip] = $fields;
    }

    /**
     * Resolve the PTR record for an address, or null.
     *
     * The name that comes back is checked against the restricted grammar a hostname has;
     * anything else came from a hostile PTR zone and must not be allowed into a Solr document
     * or the panel.
     */
    private function ptr(string $ip): ?string
    {
        $qname = self::reverseName($ip);
        if ($qname === null) {
            return null;
        }
        $answers = $this->dnsQuery($qname, 12);
        if ($answers === []) {
            return null;
        }
        $name = rtrim((string) $answers[0], '.');
        if (!preg_match('/^[A-Za-z0-9]([A-Za-z0-9\-._]{0,252}[A-Za-z0-9])?$/', $name)) {
            return null;
        }
        return strtolower($name);
    }

    /**
     * Does resolving $name forward produce $ip?
     *
     * Asks for the record family the address actually belongs to: A (type 1) for IPv4, AAAA
     * (type 28) for IPv6.
     */
    private function forwardConfirms(string $name, string $ip): bool
    {
        $isV6 = str_contains($ip, ':');
        $answers = $this->dnsQuery($name, $isV6 ? 28 : 1);
        if ($answers === []) {
            return false;
        }
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
    private static function reverseName(string $ip): ?string
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
     * Resolve one name/type over UDP against the system resolvers, with a real timeout.
     *
     * PHP's `gethostbyaddr()` and `dns_get_record()` are used nowhere in this class on
     * purpose: neither accepts a timeout, so a single unresponsive authoritative server
     * would stall the ingest daemon for the resolver library's whole retry schedule. About
     * eighty lines of packet building and parsing buys a hard deadline, which SPEC §5.3
     * requires.
     *
     * Scope is deliberately narrow — one question, UDP only, no EDNS, no DNSSEC, truncated
     * answers abandoned. A truncated PTR or A answer is vanishingly rare and the correct
     * behaviour when it happens is "field absent", which is what returning [] produces.
     *
     * The read buffer is 4096 bytes, which covers any answer we would accept; more than that
     * means the response was truncated and it is dropped. A valid but empty answer, NXDOMAIN
     * or NODATA, is a real result, so the next resolver is not asked.
     *
     * @param int $qtype 1 = A, 12 = PTR, 28 = AAAA
     * @return string[] Answer values (names for PTR, addresses for A/AAAA).
     */
    private function dnsQuery(string $qname, int $qtype): array
    {
        $timeout = max(1, (int) ($this->cfg['lookup_timeout'] ?? 3));

        foreach ($this->resolvers() as $server) {
            $packet = self::buildQuery($qname, $qtype);
            if ($packet === null) {
                return [];
            }

            $errno  = 0;
            $errstr = '';
            $target = str_contains($server, ':') ? '[' . $server . ']' : $server;
            $sock = @stream_socket_client(
                'udp://' . $target . ':53',
                $errno,
                $errstr,
                (float) $timeout,
                STREAM_CLIENT_CONNECT
            );
            if ($sock === false) {
                continue;
            }
            stream_set_timeout($sock, $timeout);

            if (@fwrite($sock, $packet) === false) {
                fclose($sock);
                continue;
            }
            $response = @fread($sock, 4096);
            $meta = stream_get_meta_data($sock);
            fclose($sock);

            if (!empty($meta['timed_out']) || !is_string($response) || strlen($response) < 12) {
                continue;
            }

            $answers = self::parseAnswers($response, $packet, $qtype);
            if ($answers !== []) {
                return $answers;
            }
            if (self::responseIsAuthoritativeEmpty($response, $packet)) {
                return [];
            }
        }
        return [];
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
    private function resolvers(): array
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
    private static function buildQuery(string $qname, int $qtype): ?string
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
    private static function parseAnswers(string $response, string $query, int $qtype): array
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
    private static function responseIsAuthoritativeEmpty(string $response, string $query): bool
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
