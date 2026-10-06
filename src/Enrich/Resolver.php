<?php

declare(strict_types=1);

/**
 * Loghound — non-blocking enrichment for the ingest daemon.
 *
 * Every lookup (Cymru bulk whois, RIR whois, reverse DNS, platform geolocation) runs on
 * non-blocking sockets and curl_multi, advanced by pump(). Nothing here ever waits for an
 * answer: the daemon submits addresses, keeps reading, and picks up the addresses whose
 * lookups have finished — answered, failed or timed out — on each pump.
 */

namespace Loghound\Enrich;

final class Resolver
{
    /** Addresses per Cymru bulk connection, and bulk connections open at once. */
    private const CYMRU_BULK = 500;
    private const CYMRU_CONNS = 2;

    /** RIR whois connections open at once, per server and in total. */
    private const RIR_PER_HOST = 4;
    private const RIR_CONNS = 32;

    /** DNS questions in flight at once. */
    private const DNS_IN_FLIGHT = 256;

    /** Geolocation requests in flight at once, each carrying up to GEO_BATCH addresses. */
    private const GEO_REQS = 4;
    private const GEO_BATCH = 50;

    /** Consecutive failures that take a whois server out, and for how long. */
    private const HOST_FAILS = 3;
    private const HOST_COOLDOWN = 600;

    /** RIR lookups allowed to queue; past this a netblock is recorded without its netname. */
    private const RIR_QUEUE_MAX = 2000;

    /** A whois answer is a few kilobytes; more than this means something is wrong. */
    private const WHOIS_MAX_BYTES = 262144;

    private Asn $asn;
    private ?Geo $geo;
    private int $timeout;

    /** @var array<string,array{asn:?string,geo:bool,rdns:bool}> What each pending address still waits for. */
    private array $pending = [];

    /** @var string[] Addresses whose lookups have all finished since the last pump. */
    private array $done = [];

    /** @var array<string,string> netblock key => address to ask Cymru about. */
    private array $asnQueue = [];
    /** @var array<string,array<string,bool>> netblock key => addresses waiting on it. */
    private array $asnWaiters = [];

    /** @var array<int,array<string,mixed>> Open whois connections (Cymru and RIR). */
    private array $whois = [];
    /** @var array<string,array{job:array,row:array}> RIR lookups not yet started. */
    private array $rirQueue = [];
    /** @var array<string,int> Open RIR connections per server. */
    private array $rirHost = [];

    /** @var array<string,string> Whois server name => address, resolved once per process. */
    private array $hostAddr = [];

    /** @var array<string,int> Consecutive failures per whois server. */
    private array $hostFails = [];

    /** @var array<string,float> Whois servers skipped until this time. */
    private array $hostDownUntil = [];

    /** @var array<string,array{0:string,1:string,2:string,3:int}> DNS questions not yet sent: id => [ip, phase, qname, qtype]. */
    private array $dnsQueue = [];
    /** @var array<int,array<string,mixed>> DNS questions in flight. */
    private array $dnsFlight = [];

    /** @var array<string,bool> Addresses ready for geolocation. */
    private array $geoQueue = [];
    /** @var \CurlMultiHandle|null */
    private $multi = null;
    /** @var array<int,array<string,mixed>> Geolocation requests in flight. */
    private array $geoReqs = [];

    public function __construct(Asn $asn, ?Geo $geo)
    {
        $this->asn = $asn;
        $this->geo = $geo;
        $this->timeout = max(1, (int) $asn->setting('lookup_timeout', 3));
    }

    /** Start every lookup an address still needs. Answers already in memo or cache cost nothing. */
    public function submit(string $ip): void
    {
        if (isset($this->pending[$ip])) {
            return;
        }

        $key = $this->asn->asnKey($ip);
        $needAsn = $key !== null && !$this->asn->hasAsn($key);
        $needGeo = $this->geo !== null && $this->geo->wants($ip);
        $needRdns = $this->asn->wantsRdns($ip);

        if (!$needAsn && !$needGeo && !$needRdns) {
            return;
        }

        $this->pending[$ip] = ['asn' => $needAsn ? $key : null, 'geo' => $needGeo, 'rdns' => $needRdns];

        if ($needAsn) {
            if (!isset($this->asnWaiters[$key])) {
                $this->asnQueue[$key] = $ip;
            }
            $this->asnWaiters[$key][$ip] = true;
        } elseif ($needGeo) {
            $this->geoQueue[$ip] = true;
        }

        if ($needRdns) {
            $this->dnsQueue['p' . $ip] = [$ip, 'ptr', (string) Asn::reverseName($ip), 12];
        }
    }

    /** Is any lookup for this address still running? */
    public function isPending(string $ip): bool
    {
        return isset($this->pending[$ip]);
    }

    /** Is anything queued or in flight? */
    public function busy(): bool
    {
        return $this->pending !== [];
    }

    /**
     * Advance every lookup for up to $wait seconds and return the addresses that finished.
     *
     * With $wait = 0 this makes one non-blocking pass. A lookup past its timeout is abandoned:
     * its field stays absent and nothing is cached for it.
     *
     * @return string[]
     */
    public function pump(float $wait = 0.0): array
    {
        $deadline = microtime(true) + max(0.0, $wait);

        do {
            $this->start();

            $read = [];
            $write = [];
            foreach ($this->whois as $id => $c) {
                if ($c['sent'] < strlen($c['query'])) {
                    $write[$id] = $c['fp'];
                } else {
                    $read[$id] = $c['fp'];
                }
            }
            foreach ($this->dnsFlight as $id => $f) {
                $read[$id] = $f['sock'];
            }

            if ($this->geoReqs !== []) {
                $running = 0;
                curl_multi_exec($this->multi, $running);
                $this->harvestGeo();
            }

            $left = max(0.0, $deadline - microtime(true));
            $slice = $this->geoReqs !== [] ? min($left, 0.02) : min($left, 0.1);

            if ($read !== [] || $write !== []) {
                $e = null;
                $n = @stream_select($read, $write, $e, 0, (int) ($slice * 1000000));
                if ($n > 0) {
                    foreach ($write as $fp) {
                        $this->whoisWritable((int) $fp);
                    }
                    foreach ($read as $fp) {
                        $id = (int) $fp;
                        if (isset($this->dnsFlight[$id])) {
                            $this->dnsReadable($id);
                        } elseif (isset($this->whois[$id])) {
                            $this->whoisReadable($id);
                        }
                    }
                }
            } elseif ($this->geoReqs !== [] && $slice > 0) {
                curl_multi_select($this->multi, $slice);
            }

            $this->expire();
        } while (microtime(true) < $deadline && $this->pending !== [] && $this->inFlight());

        $done = $this->done;
        $this->done = [];
        return $done;
    }

    /** Are any sockets or requests actually open (as opposed to queued)? */
    private function inFlight(): bool
    {
        return $this->whois !== [] || $this->dnsFlight !== [] || $this->geoReqs !== []
            || $this->asnQueue !== [] || $this->rirQueue !== [] || $this->dnsQueue !== []
            || $this->geoQueue !== [];
    }

    /** Open whatever the concurrency limits allow. */
    private function start(): void
    {
        $cymru = 0;
        foreach ($this->whois as $c) {
            if ($c['kind'] === 'cymru') {
                $cymru++;
            }
        }
        while ($this->asnQueue !== [] && $cymru < self::CYMRU_CONNS) {
            $keys = array_slice($this->asnQueue, 0, self::CYMRU_BULK, true);
            foreach ($keys as $key => $_) {
                unset($this->asnQueue[$key]);
            }
            $query = "begin\nverbose\n" . implode("\n", $keys) . "\nend\n";
            $timeout = $this->timeout * (1 + intdiv(count($keys), 100));
            if (!$this->openWhois('cymru', 'whois.cymru.com', 43, $query, $timeout, ['keys' => $keys])) {
                foreach ($keys as $key => $_) {
                    $this->asnFinished((string) $key, [], false);
                }
            }
            $cymru++;
        }

        $rirOpen = count($this->whois) - $cymru;
        foreach ($this->rirQueue as $key => $r) {
            if ($rirOpen >= self::RIR_CONNS) {
                break;
            }
            [$host, $port, $query] = $r['job'];
            if (($this->hostDownUntil[$host] ?? 0) > microtime(true)) {
                unset($this->rirQueue[$key]);
                $this->asnFinished((string) $key, Asn::payload($r['row'], null), false);
                continue;
            }
            if (($this->rirHost[$host] ?? 0) >= self::RIR_PER_HOST) {
                continue;
            }
            unset($this->rirQueue[$key]);
            if ($this->openWhois('rir', $host, $port, $query, $this->timeout, ['key' => $key, 'row' => $r['row']])) {
                $this->rirHost[$host] = ($this->rirHost[$host] ?? 0) + 1;
                $rirOpen++;
            } else {
                $this->hostHealth($host, false);
                $this->asnFinished((string) $key, Asn::payload($r['row'], null), false);
            }
        }

        $resolvers = $this->asn->resolvers();
        while ($this->dnsQueue !== [] && count($this->dnsFlight) < self::DNS_IN_FLIGHT) {
            $qid = (string) array_key_first($this->dnsQueue);
            [$ip, $phase, $qname, $qtype] = $this->dnsQueue[$qid];
            unset($this->dnsQueue[$qid]);
            if (!$this->sendDns($resolvers, $ip, $phase, $qname, $qtype)) {
                $this->dnsFailed($ip, $phase, $qname);
            }
        }

        if ($this->geo !== null) {
            while ($this->geoQueue !== [] && count($this->geoReqs) < self::GEO_REQS) {
                $ips = array_keys(array_slice($this->geoQueue, 0, self::GEO_BATCH, true));
                foreach ($ips as $ip) {
                    unset($this->geoQueue[$ip]);
                }
                $ips = array_map('strval', $ips);
                $req = $this->geo->request($ips);
                if ($req === null) {
                    $this->geo->ingest($ips, null);
                    $this->geoFinished($ips);
                } elseif (!$this->geo->usesDefaultTransport()) {
                    $this->geo->ingest($ips, \Loghound\Solr::curlTransport($req));
                    $this->geoFinished($ips);
                } else {
                    $this->openGeo($ips, $req);
                }
            }
        }
    }

    /** Open a non-blocking whois connection. */
    private function openWhois(string $kind, string $host, int $port, string $query, int $timeout, array $ctx): bool
    {
        if (!isset($this->hostAddr[$host])) {
            $addr = gethostbyname($host);
            $this->hostAddr[$host] = filter_var($addr, FILTER_VALIDATE_IP) !== false ? $addr : $host;
        }
        $errno = 0;
        $errstr = '';
        $fp = @stream_socket_client(
            'tcp://' . $this->hostAddr[$host] . ':' . $port,
            $errno,
            $errstr,
            (float) $timeout,
            STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
        );
        if ($fp === false) {
            return false;
        }
        stream_set_blocking($fp, false);
        $this->whois[(int) $fp] = $ctx + [
            'kind' => $kind, 'fp' => $fp, 'host' => $host, 'query' => $query, 'sent' => 0,
            'body' => '', 'deadline' => microtime(true) + $timeout,
        ];
        return true;
    }

    private function whoisWritable(int $id): void
    {
        if (!isset($this->whois[$id])) {
            return;
        }
        $c = &$this->whois[$id];
        $n = @fwrite($c['fp'], substr($c['query'], $c['sent']));
        if ($n === false) {
            $this->whoisClosed($id, false);
            return;
        }
        $c['sent'] += $n;
    }

    private function whoisReadable(int $id): void
    {
        $c = &$this->whois[$id];
        $chunk = @fread($c['fp'], 65536);
        if ($chunk === false || ($chunk === '' && feof($c['fp']))) {
            $this->whoisClosed($id, true);
            return;
        }
        $c['body'] .= $chunk;
        if (strlen($c['body']) > self::WHOIS_MAX_BYTES * ($c['kind'] === 'cymru' ? 64 : 1)) {
            $this->whoisClosed($id, true);
        }
    }

    /** A whois connection ended: $complete false means it timed out or failed before EOF. */
    private function whoisClosed(int $id, bool $complete): void
    {
        $c = $this->whois[$id];
        unset($this->whois[$id]);
        fclose($c['fp']);
        $body = $c['body'] !== '' ? $c['body'] : null;

        if ($c['kind'] === 'cymru') {
            if ($body === null || !$complete) {
                foreach ($c['keys'] as $key => $_) {
                    $this->asnFinished((string) $key, [], false);
                }
                return;
            }
            $rows = Asn::parseCymru($body);
            $whoisOn = !empty($this->asn->setting('whois_enabled'));
            foreach ($c['keys'] as $key => $ip) {
                $bin = @inet_pton($ip);
                $row = $rows[$bin === false ? $ip : (string) inet_ntop($bin)] ?? null;
                if ($row === null) {
                    $this->asnFinished((string) $key, [], true);
                    continue;
                }
                $job = $whoisOn ? Asn::rirJob($ip, $row['registry']) : null;
                if ($job !== null && count($this->rirQueue) >= self::RIR_QUEUE_MAX) {
                    $this->asnFinished((string) $key, Asn::payload($row, null), false);
                } elseif ($job === null) {
                    $this->asnFinished((string) $key, Asn::payload($row, null), true);
                } else {
                    $this->rirQueue[(string) $key] = ['job' => $job, 'row' => $row];
                }
            }
            return;
        }

        $this->rirHost[$c['host']]--;
        $ok = $body !== null && $complete;
        $this->hostHealth($c['host'], $ok);
        $this->asnFinished(
            (string) $c['key'],
            Asn::payload($c['row'], $ok ? Asn::parseRir($body) : null),
            $ok
        );
    }

    /** Track a whois server's consecutive failures and take it out for a while when it keeps failing. */
    private function hostHealth(string $host, bool $ok): void
    {
        if ($ok) {
            $this->hostFails[$host] = 0;
            return;
        }
        $this->hostFails[$host] = ($this->hostFails[$host] ?? 0) + 1;
        if ($this->hostFails[$host] >= self::HOST_FAILS) {
            $this->hostDownUntil[$host] = microtime(true) + self::HOST_COOLDOWN;
            $this->hostFails[$host] = 0;
        }
    }

    /** A netblock is answered (or given up on): release the addresses waiting on it. */
    private function asnFinished(string $key, array $fields, bool $cache): void
    {
        $this->asn->storeAsn($key, $fields, $cache);
        foreach ($this->asnWaiters[$key] ?? [] as $ip => $_) {
            $ip = (string) $ip;
            if (!isset($this->pending[$ip])) {
                continue;
            }
            $this->pending[$ip]['asn'] = null;
            if ($this->pending[$ip]['geo']) {
                $this->geoQueue[$ip] = true;
            }
            $this->settle($ip);
        }
        unset($this->asnWaiters[$key]);
    }

    /** Send one DNS question to the first resolver that accepts the socket. */
    private function sendDns(array $resolvers, string $ip, string $phase, string $qname, int $qtype): bool
    {
        $packet = Asn::buildQuery($qname, $qtype);
        if ($packet === null) {
            return false;
        }
        foreach ($resolvers as $server) {
            $target = str_contains($server, ':') ? '[' . $server . ']' : $server;
            $errno = 0;
            $errstr = '';
            $sock = @stream_socket_client('udp://' . $target . ':53', $errno, $errstr, 1.0);
            if ($sock === false) {
                continue;
            }
            stream_set_blocking($sock, false);
            if (@fwrite($sock, $packet) === false) {
                fclose($sock);
                continue;
            }
            $this->dnsFlight[(int) $sock] = [
                'sock' => $sock, 'ip' => $ip, 'phase' => $phase, 'qname' => $qname, 'qtype' => $qtype,
                'packet' => $packet, 'deadline' => microtime(true) + $this->timeout,
            ];
            return true;
        }
        return false;
    }

    private function dnsReadable(int $id): void
    {
        $f = $this->dnsFlight[$id];
        unset($this->dnsFlight[$id]);
        $response = @fread($f['sock'], 4096);
        fclose($f['sock']);

        if (!is_string($response) || strlen($response) < 12) {
            $this->dnsFailed($f['ip'], $f['phase'], $f['qname']);
            return;
        }
        $answers = Asn::parseAnswers($response, $f['packet'], $f['qtype']);
        if ($answers === [] && !Asn::responseIsAuthoritativeEmpty($response, $f['packet'])) {
            $this->dnsFailed($f['ip'], $f['phase'], $f['qname']);
            return;
        }

        if ($f['phase'] === 'ptr') {
            $name = $answers === [] ? null : Asn::validName((string) $answers[0]);
            if ($name === null) {
                $this->rdnsFinished($f['ip'], [], true);
                return;
            }
            $this->dnsQueue['f' . $f['ip']] = [$f['ip'], 'fwd', $name, str_contains($f['ip'], ':') ? 28 : 1];
            return;
        }

        $this->rdnsFinished($f['ip'], [
            'rdns_s'    => self::clean($f['qname']),
            'rdns_ok_b' => Asn::addressIn($f['ip'], $answers),
        ], true);
    }

    /**
     * A DNS question got no usable answer. A dead PTR leaves the field absent; a dead forward
     * check keeps the name and leaves `rdns_ok_b` absent (unknown, not failed). Neither is cached.
     */
    private function dnsFailed(string $ip, string $phase, string $qname): void
    {
        $this->rdnsFinished($ip, $phase === 'fwd' ? ['rdns_s' => self::clean($qname)] : [], false);
    }

    private function rdnsFinished(string $ip, array $fields, bool $cache): void
    {
        $this->asn->storeRdns($ip, $fields, $cache);
        if (isset($this->pending[$ip])) {
            $this->pending[$ip]['rdns'] = false;
            $this->settle($ip);
        }
    }

    private static function clean(string $name): string
    {
        return mb_substr($name, 0, 255);
    }

    /** Start one geolocation request on the shared curl_multi handle. */
    private function openGeo(array $ips, array $req): void
    {
        if ($this->multi === null) {
            $this->multi = curl_multi_init();
        }
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $req['url'],
            CURLOPT_CUSTOMREQUEST  => $req['method'],
            CURLOPT_HTTPHEADER     => array_merge((array) $req['headers'], ['Expect:']),
            CURLOPT_POSTFIELDS     => $req['body'],
            CURLOPT_TIMEOUT        => $req['timeout'],
            CURLOPT_CONNECTTIMEOUT => $req['connect_timeout'],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_ENCODING       => '',
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            CURLOPT_RETURNTRANSFER => true,
        ]);
        curl_multi_add_handle($this->multi, $ch);
        $this->geoReqs[spl_object_id($ch)] = ['ch' => $ch, 'ips' => $ips];
    }

    private function harvestGeo(): void
    {
        while (($info = curl_multi_info_read($this->multi)) !== false) {
            $ch = $info['handle'];
            $id = spl_object_id($ch);
            if (!isset($this->geoReqs[$id])) {
                continue;
            }
            $ips = $this->geoReqs[$id]['ips'];
            unset($this->geoReqs[$id]);

            $ok = $info['result'] === CURLE_OK;
            $res = [
                'status' => $ok ? (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE) : 0,
                'body'   => $ok ? (string) curl_multi_getcontent($ch) : '',
            ];
            curl_multi_remove_handle($this->multi, $ch);

            $this->geo->ingest($ips, $res);
            $this->geoFinished($ips);
        }
    }

    private function geoFinished(array $ips): void
    {
        foreach ($ips as $ip) {
            $ip = (string) $ip;
            if (isset($this->pending[$ip])) {
                $this->pending[$ip]['geo'] = false;
                $this->settle($ip);
            }
        }
    }

    /** Give up on whatever has run past its deadline. */
    private function expire(): void
    {
        $now = microtime(true);
        foreach ($this->dnsFlight as $id => $f) {
            if ($now >= $f['deadline']) {
                unset($this->dnsFlight[$id]);
                fclose($f['sock']);
                $this->dnsFailed($f['ip'], $f['phase'], $f['qname']);
            }
        }
        foreach ($this->whois as $id => $c) {
            if ($now >= $c['deadline']) {
                $this->whoisClosed($id, false);
            }
        }
    }

    /** Move an address to done once nothing is left for it. */
    private function settle(string $ip): void
    {
        $p = $this->pending[$ip];
        if ($p['asn'] === null && !$p['geo'] && !$p['rdns']) {
            unset($this->pending[$ip]);
            $this->done[] = $ip;
        }
    }
}
