<?php
/**
 * Loghound — the panel's answer cache.
 *
 * WHAT IS BEING PROTECTED. \Loghound\Cache stores the panel's Solr answers in memcached for a
 * duration the operator sets, defaulting to two hours. Two things make that safe rather than
 * merely fast, and both are load-bearing enough to be tested rather than reviewed:
 *
 *  1. THE KEY COVERS EVERYTHING THAT CHANGES THE ANSWER. A key that ignored one filter would
 *     serve one operator's filtered numbers under another heading, which is worse than being
 *     slow. The tests below add, remove and reorder filters, operators, cores, ranges and sort
 *     keys and require every one of those to be a different entry.
 *  2. NOTHING READ BACK IS TRUSTED. An entry is bytes from a network service other processes can
 *     write to. It is JSON, it is validated field by field, and a PHP-serialised payload is a
 *     miss rather than an instantiation.
 *
 * NO NETWORK NEEDED. Most tests run against an in-memory stand-in client, the same arrangement
 * \Loghound\Solr uses for its transport. The tests that need the real extension skip themselves
 * when there is no memcached on 127.0.0.1, so the suite's promise holds on a box with neither.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Cache;
use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Solr;

/**
 * An in-memory stand-in for a memcached client, with the \Memcache arities.
 *
 * Keeps no expiry clock: nothing here tests that memcached expires things, which is memcached's
 * job, and a fake that implemented its own TTL would be testing the fake. What it does model
 * exactly is the part the cache's correctness rests on — that `add` refuses an existing key and
 * `increment` refuses a missing one — because the generation counter and the savings counters
 * are built on those two refusals.
 */
final class LhFakeMemcache
{
    /** @var array<string,mixed> */
    public array $store = [];

    /** @var array<int,string> Every key read, in order, so a test can see what was asked for. */
    public array $reads = [];

    public int $writes = 0;

    /** @return mixed */
    public function get(string $key)
    {
        $this->reads[] = $key;
        return $this->store[$key] ?? false;
    }

    /** @param mixed $value */
    public function set(string $key, $value, int $flags = 0, int $ttl = 0): bool
    {
        $this->store[$key] = $value;
        $this->writes++;
        return true;
    }

    /** @param mixed $value */
    public function add(string $key, $value, int $flags = 0, int $ttl = 0): bool
    {
        if (array_key_exists($key, $this->store)) {
            return false;
        }
        $this->store[$key] = $value;
        return true;
    }

    /** @return int|false */
    public function increment(string $key, int $by = 1)
    {
        if (!array_key_exists($key, $this->store) || !is_numeric($this->store[$key])) {
            return false;
        }
        $this->store[$key] = (int) $this->store[$key] + $by;
        return (int) $this->store[$key];
    }

    public function delete(string $key): bool
    {
        unset($this->store[$key]);
        return true;
    }

    /** How many entries look like cached answers rather than counters. */
    public function entryCount(): int
    {
        $n = 0;
        foreach (array_keys($this->store) as $key) {
            if (preg_match('/\.\d+\.[0-9a-f]{40}$/D', $key) === 1) {
                $n++;
            }
        }
        return $n;
    }
}

/** A cache over a fresh stand-in client, plus the client so a test can inspect it. */
function lh_cache(int $ttl = 7200): array
{
    $fake = new LhFakeMemcache();
    return [Cache::withClient($fake, $ttl), $fake];
}

/** A config with the cache on, pointed at a server nothing is listening on. */
function lh_cache_config(bool $enabled = true, int $ttl = 7200): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');
    $cfg->set('cache.enabled', $enabled);
    $cfg->set('cache.ttl_seconds', $ttl);
    return $cfg;
}

/**
 * A Gateway whose Solr client records its requests and whose cache is a stand-in.
 *
 * @param array<int,array<string,mixed>> $captured
 */
function lh_cache_gateway(array &$captured, Cache $cache, string $method = 'GET'): Gateway
{
    $_SERVER['REQUEST_METHOD'] = $method;

    $transport = function (array $request) use (&$captured): array {
        $captured[] = $request;
        return [
            'status' => 200,
            'body'   => (string) json_encode([
                'responseHeader' => ['status' => 0],
                'response'       => ['numFound' => 3, 'docs' => []],
                'facets'         => ['count' => 3],
            ]),
            'error'  => '',
            'bytes'  => 4096,
        ];
    };

    $cfg = lh_cache_config();
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false, $cache);
}

/** A real memcached client on the conventional port, or null when there is none. */
function lh_real_memcached(): ?object
{
    if (!class_exists('\\Memcached')) {
        return null;
    }

    $port = (int) (getenv('LOGHOUND_TEST_MEMCACHED_PORT') ?: 11211);
    $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
    if (!is_resource($sock)) {
        return null;
    }
    fclose($sock);

    $mc = new \Memcached();
    $mc->setOption(\Memcached::OPT_BINARY_PROTOCOL, true);
    $mc->setOption(\Memcached::OPT_CONNECT_TIMEOUT, 200);
    $mc->addServer('127.0.0.1', $port);
    return $mc;
}

$tests = [];

// ============================================================================================
// The key covers everything that changes the answer.
// ============================================================================================

$tests['cache: the same request in a different array order is one entry'] =
    function (): void {
        [$cache] = lh_cache();

        $a = $cache->key('overview.totals', 'sessions', [
            'query' => ['q' => '*:*', 'fq' => ['a', 'b'], 'rows' => 0],
            'facet' => ['x' => ['type' => 'terms', 'field' => 'f']],
        ]);
        $b = $cache->key('overview.totals', 'sessions', [
            'facet' => ['x' => ['field' => 'f', 'type' => 'terms']],
            'query' => ['rows' => 0, 'fq' => ['a', 'b'], 'q' => '*:*'],
        ]);

        lh_same($a, $b, 'key order must not fragment the cache — these are the same question');
    };

$tests['cache: a changed filter value is a different entry'] =
    function (): void {
        [$cache] = lh_cache();

        $base = ['query' => ['q' => '*:*', 'fq' => ['{!tag=f_verdict_s}verdict_s:"likely_human"']]];
        $other = ['query' => ['q' => '*:*', 'fq' => ['{!tag=f_verdict_s}verdict_s:"likely_bot"']]];

        lh_true(
            $cache->key('t', 'sessions', $base) !== $cache->key('t', 'sessions', $other),
            'a different filter VALUE must be a different entry'
        );
    };

$tests['cache: a changed filter operator is a different entry'] =
    function (): void {
        [$cache] = lh_cache();

        $anyOf = ['query' => ['q' => '*:*', 'fq' => ['netname_s:("a" OR "b")']]];
        $allOf = ['query' => ['q' => '*:*', 'fq' => ['netname_s:("a" AND "b")']]];

        lh_true(
            $cache->key('t', 'sessions', $anyOf) !== $cache->key('t', 'sessions', $allOf),
            'AND and OR over the same values are different populations and must not share an entry'
        );
    };

$tests['cache: an added filter is a different entry'] =
    function (): void {
        [$cache] = lh_cache();

        $one = ['query' => ['q' => '*:*', 'fq' => ['ts_start:[NOW-1HOUR/MINUTE TO *]']]];
        $two = ['query' => ['q' => '*:*', 'fq' => ['ts_start:[NOW-1HOUR/MINUTE TO *]', 'host_s:"a.example"']]];

        lh_true(
            $cache->key('t', 'sessions', $one) !== $cache->key('t', 'sessions', $two),
            'an unfiltered view must never be served to a filtered one — this is the dangerous collision'
        );
    };

$tests['cache: the range, the host, the population and the sort each change the entry'] =
    function (): void {
        [$cache] = lh_cache();

        $keys = [];
        foreach ([
            'range'      => ['q' => '*:*', 'fq' => ['ts_start:[NOW-1HOUR/MINUTE TO *]']],
            'range2'     => ['q' => '*:*', 'fq' => ['ts_start:[NOW-30DAY/DAY TO *]']],
            'host'       => ['q' => '*:*', 'fq' => ['host_s:"a.example"']],
            'host2'      => ['q' => '*:*', 'fq' => ['host_s:"b.example"']],
            'population' => ['q' => '*:*', 'fq' => ['verdict_s:"likely_human"']],
            'sort'       => ['q' => '*:*', 'sort' => 'ts_start desc'],
            'sort2'      => ['q' => '*:*', 'sort' => 'ts_start asc'],
        ] as $label => $query) {
            $keys[$label] = $cache->key('t', 'sessions', ['query' => $query]);
        }

        lh_same(count($keys), count(array_unique($keys)), 'every one of these must be its own entry');
    };

$tests['cache: the core and the tag change the entry'] =
    function (): void {
        [$cache] = lh_cache();

        $parts = ['query' => ['q' => '*:*']];
        lh_true(
            $cache->key('t', 'sessions', $parts) !== $cache->key('t', 'hits', $parts),
            'the same query against a different core is a different answer'
        );
        lh_true(
            $cache->key('a', 'sessions', $parts) !== $cache->key('b', 'sessions', $parts),
            'two views asking structurally similar questions must not share an entry'
        );
    };

$tests['cache: free text is part of the key'] =
    function (): void {
        [$cache] = lh_cache();

        lh_true(
            $cache->key('s', 'sessions', ['text' => 'googlebot']) !== $cache->key('s', 'sessions', ['text' => 'bingbot']),
            'a search term must be part of the key'
        );
        lh_true(
            $cache->key('s', 'sessions', ['text' => '']) !== $cache->key('s', 'sessions', ['text' => 'x']),
            'an empty search and a search must not share an entry'
        );
    };

$tests['cache: two installations on one memcached cannot address each other'] =
    function (): void {
        $one = Cache::fromConfig(lh_cache_config());

        $other = lh_cache_config();
        $other->set('solr.sessions_core', 'somebody_elses_sessions');
        $two = Cache::fromConfig($other);

        $parts = ['query' => ['q' => '*:*']];
        lh_true(
            $one->key('t', 'sessions', $parts) !== $two->key('t', 'sessions', $parts),
            'two installations must not share a keyspace'
        );
    };

$tests['cache: no secret ever appears in a key'] =
    function (): void {
        $cfg = lh_cache_config();
        $cfg->set('beacon.secret', 'BEACONSECRETVALUE');
        $cfg->set('auth.password_hash', '$2y$10$PASSWORDHASHVALUE');

        $key = Cache::fromConfig($cfg)->key('t', 'sessions', ['query' => ['q' => '*:*']]);

        lh_true(!str_contains($key, 'BEACONSECRET'), 'the beacon secret must not reach a cache key');
        lh_true(!str_contains($key, 'PASSWORDHASH'), 'the password hash must not reach a cache key');
        lh_true(strlen($key) < 120, 'a key must stay well inside memcached\'s 250-byte limit');
    };

// ============================================================================================
// The envelope, and what is refused.
// ============================================================================================

$tests['cache: a stored answer comes back with the time it was computed'] =
    function (): void {
        [$cache] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        lh_true($cache->put($key, ['count' => 7], null, 2048), 'the store must succeed');

        $hit = $cache->get($key);
        lh_true(is_array($hit), 'the entry must come back');
        lh_same(['count' => 7], $hit['value'], 'the value must survive the round trip');
        lh_true(abs(time() - (int) $hit['at']) <= 2, 'the entry must carry when it was computed');
    };

$tests['cache: a PHP-serialised payload is a miss, never an instantiation'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        $fake->store[$key] = 'O:8:"stdClass":1:{s:1:"a";i:1;}';

        lh_same(null, $cache->get($key), 'a serialised object must be refused outright');
    };

$tests['cache: a damaged or foreign entry is a miss'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);

        foreach ([
            'not JSON at all'          => 'garbage{',
            'JSON but not an envelope' => '{"hello":"world"}',
            'the wrong schema'         => '{"s":99,"at":100,"v":{"count":1}}',
            'no timestamp'             => '{"s":1,"v":{"count":1}}',
            'a timestamp in the future' => '{"s":1,"at":' . (time() + 86400) . ',"v":{"count":1}}',
            'an empty string'          => '',
        ] as $what => $payload) {
            $fake->store[$key] = $payload;
            lh_same(null, $cache->get($key), 'must be a miss: ' . $what);
        }
    };

$tests['cache: a value that will not encode as JSON is not stored'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        $before = $fake->entryCount();

        $cache->put($key, ['h' => fopen('php://memory', 'rb')]);

        lh_same(null, $cache->get($key), 'an entry that cannot be read back safely must not be kept');
        lh_same($before, $fake->entryCount(), 'nothing must have been written');
    };

// ============================================================================================
// Duration.
// ============================================================================================

$tests['cache: the duration defaults to two hours and is clamped at both ends'] =
    function (): void {
        lh_same(7200, Cache::TTL_DEFAULT, 'the default duration is two hours');
        lh_same(7200, Cache::clampTtl(null), 'an absent duration falls back to the default');
        lh_same(7200, Cache::clampTtl('nonsense'), 'a non-numeric duration falls back to the default');
        lh_same(Cache::TTL_MIN, Cache::clampTtl(1), 'one second must be raised to the floor');
        lh_same(Cache::TTL_MAX, Cache::clampTtl(9999999), 'a week must be lowered to the ceiling');
        lh_same(900, Cache::clampTtl(900), 'a sane value must be kept exactly');
        lh_same(60, Cache::TTL_MIN, 'the floor is one minute');
        lh_same(86400, Cache::TTL_MAX, 'the ceiling is twenty-four hours');
    };

$tests['cache: the configured duration is what an entry is stored with'] =
    function (): void {
        $cfg = lh_cache_config(true, 600);
        lh_same(600, Cache::fromConfig($cfg)->ttl(), 'the operator\'s duration must be the one in force');

        $cfg->set('cache.ttl_seconds', 5);
        lh_same(Cache::TTL_MIN, Cache::fromConfig($cfg)->ttl(), 'a duration below the floor must be raised');
    };

// ============================================================================================
// Clearing.
// ============================================================================================

$tests['cache: after clearing, every question the panel asks is a miss again'] =
    function (): void {
        [$cache] = lh_cache();

        $parts = ['query' => ['q' => '*:*', 'fq' => ['ts_start:[NOW-1HOUR/MINUTE TO *]']]];
        foreach (['a', 'b', 'c'] as $tag) {
            $cache->put($cache->key($tag, 'sessions', $parts), ['count' => 1], null, 1024);
        }
        foreach (['a', 'b', 'c'] as $tag) {
            lh_true(
                is_array($cache->get($cache->key($tag, 'sessions', $parts))),
                'entry ' . $tag . ' must be served before the clear'
            );
        }

        $outcome = $cache->clear();
        lh_true($outcome['cleared'], 'the clear must report success');
        lh_same(3, $outcome['entries'], 'the clear must say how many entries it discarded');

        /* THE KEY IS REBUILT, which is the whole mechanism. Clearing increments a generation the
           key is built from, so the panel — which always derives a key from the request it is
           answering — can no longer name anything from before the clear. The orphans are left to
           expire on their own duration; that is the documented trade-off for never running
           flush_all on a memcached somebody else may be sharing. */
        foreach (['a', 'b', 'c'] as $tag) {
            lh_same(
                null,
                $cache->get($cache->key($tag, 'sessions', $parts)),
                'the same question must miss after the clear: ' . $tag
            );
        }
    };

$tests['cache: clearing changes the keys, so the old generation cannot be addressed'] =
    function (): void {
        [$cache] = lh_cache();

        $parts = ['query' => ['q' => '*:*']];
        $before = $cache->key('t', 'sessions', $parts);
        $cache->clear();
        $after = $cache->key('t', 'sessions', $parts);

        lh_true($before !== $after, 'the same question must hash to a new key after a clear');
    };

$tests['cache: clearing touches nothing outside this installation'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $fake->store['someone_elses_app:sessions'] = 'not ours';
        $cache->put($cache->key('t', 'sessions', ['query' => ['q' => '*:*']]), ['count' => 1]);
        $cache->clear();

        lh_same(
            'not ours',
            $fake->store['someone_elses_app:sessions'] ?? null,
            'a co-tenant\'s entry must survive our Clear — flush_all would have destroyed it'
        );
    };

$tests['cache: a disabled cache clears nothing and says why'] =
    function (): void {
        $cache = Cache::disabled('memcached is not installed');

        $outcome = $cache->clear();
        lh_false($outcome['cleared'], 'there is nothing to clear');
        lh_same(0, $outcome['entries'], 'and nothing was cleared');
        lh_contains($outcome['reason'], 'memcached', 'the reason must reach the operator');
    };

// ============================================================================================
// Provenance and the bandwidth saving.
// ============================================================================================

$tests['cache: an uncached read reports itself as not cached'] =
    function (): void {
        [$cache] = lh_cache();

        $stamp = $cache->stamp();
        lh_false($stamp['cached'], 'nothing has been served from cache');
        lh_same(0, $stamp['age'], 'so there is no age to report');
        lh_same(0, $stamp['hits'], 'and no hits');
    };

$tests['cache: a served entry reports when it was computed and how old it is'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        $fake->store[$key] = (string) json_encode(['s' => 1, 'at' => time() - 600, 'b' => 8192, 'v' => ['count' => 1]]);

        $cache->get($key);
        $stamp = $cache->stamp();

        lh_true($stamp['cached'], 'a hit must be declared');
        lh_near(600, $stamp['age'], 5, 'the age must be the entry\'s real age');
        lh_true(str_starts_with($stamp['computed_at'], gmdate('Y')), 'the computation time must be an ISO timestamp');
        lh_near(7200 - 600, $stamp['expires'], 5, 'the time left must follow from the duration and the age');
    };

$tests['cache: a card built from two entries is only as fresh as the older one'] =
    function (): void {
        [$cache, $fake] = lh_cache();

        $fresh = $cache->key('a', 'sessions', ['query' => ['q' => '*:*']]);
        $stale = $cache->key('b', 'sessions', ['query' => ['q' => '*:*']]);
        $fake->store[$fresh] = (string) json_encode(['s' => 1, 'at' => time() - 10, 'b' => 1, 'v' => ['count' => 1]]);
        $fake->store[$stale] = (string) json_encode(['s' => 1, 'at' => time() - 3000, 'b' => 1, 'v' => ['count' => 2]]);

        $cache->get($fresh);
        $cache->get($stale);

        lh_near(3000, $cache->stamp()['age'], 5, 'the OLDER part must set the age — rounding this flatters the cache');
    };

$tests['cache: the bandwidth saving is the measured size of what was not fetched'] =
    function (): void {
        [$cache] = lh_cache();

        foreach ([['a', 10000], ['b', 25000]] as [$tag, $bytes]) {
            $key = $cache->key($tag, 'sessions', ['query' => ['q' => '*:*']]);
            $cache->put($key, ['count' => 1], null, $bytes);
            $cache->get($key);
        }

        $saved = $cache->savings();
        lh_true($saved['available'], 'the figure must be available');
        lh_same(2, $saved['requests'], 'two reads were served from cache');
        lh_same(35000, $saved['bytes'], 'the saving is the sum of what those responses measured');
        lh_false($saved['partial'], 'every entry knew its size, so the figure is complete');
    };

$tests['cache: a saving that cannot be fully measured says so'] =
    function (): void {
        [$cache] = lh_cache();

        $known = $cache->key('a', 'sessions', ['query' => ['q' => '*:*']]);
        $unknown = $cache->key('b', 'sessions', ['query' => ['q' => '*:*']]);
        $cache->put($known, ['count' => 1], null, 4096);
        $cache->put($unknown, ['count' => 2], null, 0);

        $cache->get($known);
        $cache->get($unknown);

        $saved = $cache->savings();
        lh_true($saved['partial'], 'an entry with no recorded size must mark the figure as incomplete');
        lh_same(4096, $saved['bytes'], 'only what was actually measured may be counted');
    };

$tests['cache: clearing resets the saving, because the period it covers restarts'] =
    function (): void {
        [$cache] = lh_cache();

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        $cache->put($key, ['count' => 1], null, 5000);
        $cache->get($key);
        lh_same(5000, $cache->savings()['bytes'], 'the saving must be recorded');

        $cache->clear();
        $saved = $cache->savings();
        lh_same(0, $saved['bytes'], 'a cleared cache has saved nothing yet');
        lh_same(0, $saved['requests'], 'and served nothing yet');
        lh_true(abs(time() - $saved['since']) <= 2, 'the period must restart at the clear');
    };

$tests['cache: a disabled cache never claims a saving'] =
    function (): void {
        $saved = Cache::disabled()->savings();
        lh_false($saved['available'], 'there is no figure to give');
        lh_same(0, $saved['bytes'], 'and it must not be presented as zero saved from a working cache');
    };

// ============================================================================================
// Absent, unreachable and misconfigured.
// ============================================================================================

$tests['cache: a disabled cache stores nothing and hits nothing'] =
    function (): void {
        $cache = Cache::disabled('turned off');

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        lh_false($cache->put($key, ['count' => 1]), 'a disabled cache must refuse to store');
        lh_same(null, $cache->get($key), 'and must never answer');
        lh_false($cache->isEnabled(), 'and must say it is not working');
    };

$tests['cache: turned off in config means off, whatever memcached is doing'] =
    function (): void {
        $cache = Cache::fromConfig(lh_cache_config(false));

        lh_false($cache->isEnabled(), 'the toggle must be obeyed');
        lh_false($cache->status()['configured'], 'and reported as the operator set it');
    };

$tests['cache: an unusable server address disables the cache with a reason'] =
    function (): void {
        $cfg = lh_cache_config();
        $cfg->set('cache.server', '');

        $status = Cache::fromConfig($cfg)->status();
        lh_true($status['configured'], 'the operator did ask for a cache');
        lh_false($status['working'], 'but it cannot work');
        lh_true($status['reason'] !== '', 'and the check must say why');
    };

$tests['cache: the system check separates "off" from "on but broken"'] =
    function (): void {
        $off = Cache::fromConfig(lh_cache_config(false))->status();
        lh_false($off['configured'], 'off is off');

        $cfg = lh_cache_config();
        $cfg->set('cache.server', '/no/such/socket/anywhere.sock');
        $broken = Cache::fromConfig($cfg)->status();

        lh_true($broken['configured'], 'this one is on');
        lh_false($broken['working'], 'and not working');
        lh_true($broken['reason'] !== '', 'so it needs a sentence the operator can act on');
        lh_same(Cache::TTL_MIN, $broken['ttl_min'], 'the bounds must travel with the check');
        lh_same(Cache::TTL_MAX, $broken['ttl_max'], 'both of them');
    };

// ============================================================================================
// The gateway: which reads are cached, and which are never.
// ============================================================================================

$tests['cache: a repeated identical facet costs one Solr request, not two'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache);

        $query = ['q' => '*:*', 'fq' => ['ts_start:[NOW-1HOUR/MINUTE TO *]']];
        $facet = ['total' => 'unique(ip_s)'];

        $first = $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);
        $second = $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);

        lh_same(1, count($captured), 'the second identical read must be served from cache');
        lh_same($first, $second, 'and must return the same answer');
        lh_true($gw->cacheStamp()['cached'], 'the payload must declare itself cached');
    };

$tests['cache: a changed filter is fetched again rather than answered from the wrong entry'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache);

        $facet = ['total' => 'unique(ip_s)'];
        $gw->facet('overview.totals', 'lh_test_sessions', ['q' => '*:*', 'fq' => ['a:"1"']], $facet);
        $gw->facet('overview.totals', 'lh_test_sessions', ['q' => '*:*', 'fq' => ['a:"2"']], $facet);

        lh_same(2, count($captured), 'a different filter must reach Solr');
    };

$tests['cache: a POST never reads or writes the cache'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache, 'POST');

        try {
            $query = ['q' => '*:*'];
            $gw->facet('job.count', 'lh_test_sessions', $query, ['n' => 'count']);
            $gw->facet('job.count', 'lh_test_sessions', $query, ['n' => 'count']);

            lh_same(
                2,
                count($captured),
                'a job step must always compute — a count watched after a delete has to be the count now'
            );
            lh_false($gw->cacheStamp()['cached'], 'and must never be reported as cached');
        } finally {
            $_SERVER['REQUEST_METHOD'] = 'GET';
        }
    };

$tests['cache: demo mode never caches'] =
    function (): void {
        [$cache] = lh_cache();
        $cfg = lh_cache_config();
        $gw = new Gateway($cfg, null, true, $cache);

        $gw->facet('overview.totals', 'lh_test_sessions', ['q' => '*:*'], ['n' => 'count']);
        lh_false($gw->cacheStamp()['cached'], 'fabricated data must not acquire a second home');
    };

$tests['cache: a failed read is never stored'] =
    function (): void {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        [$cache, $fake] = lh_cache();

        $transport = static function (array $request): array {
            return ['status' => 500, 'body' => '{"error":{"msg":"index is down"}}', 'error' => '', 'bytes' => 64];
        };

        $cfg = lh_cache_config();
        $gw = new Gateway($cfg, new Solr((array) $cfg->get('solr') + ['timeout' => 1], $transport), false, $cache);

        $gw->facet('overview.totals', 'lh_test_sessions', ['q' => '*:*'], ['n' => 'count']);

        lh_same(
            0,
            $fake->entryCount(),
            'an empty answer from a broken index must not become two hours of a dashboard reporting nothing'
        );
    };

$tests['cache: a served answer records the byte cost the client measured'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache);

        $query = ['q' => '*:*'];
        $facet = ['n' => 'count'];
        $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);
        $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);

        $saved = $gw->cacheSavings();
        lh_same(1, $saved['requests'], 'one read was served from cache');
        lh_same(4096, $saved['bytes'], 'and the saving is what the transport reported that response weighed');
    };

$tests['cache: the query log distinguishes a cache hit from a Solr round trip'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache);

        $query = ['q' => '*:*'];
        $facet = ['n' => 'count'];
        $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);
        $gw->facet('overview.totals', 'lh_test_sessions', $query, $facet);

        $log = $gw->queryLog();
        lh_same(2, count($log), 'both reads must appear in the footer');
        lh_false($log[0]['cached'], 'the first was fetched');
        lh_true($log[1]['cached'], 'the second was not');
    };

$tests['cache: selects, searches and value searches are all cached'] =
    function (): void {
        $captured = [];
        [$cache] = lh_cache();
        $gw = lh_cache_gateway($captured, $cache);

        $gw->select('sessions.list', 'lh_test_sessions', ['q' => '*:*', 'rows' => 10]);
        $gw->select('sessions.list', 'lh_test_sessions', ['q' => '*:*', 'rows' => 10]);
        lh_same(1, count($captured), 'a repeated select must be served from cache');

        $gw->search('sessions.text', 'lh_test_sessions', 'googlebot', ['rows' => 10]);
        $gw->search('sessions.text', 'lh_test_sessions', 'googlebot', ['rows' => 10]);
        lh_same(2, count($captured), 'a repeated free-text search must be served from cache');

        $gw->search('sessions.text', 'lh_test_sessions', 'bingbot', ['rows' => 10]);
        lh_same(3, count($captured), 'a different search term must reach Solr');
    };

// ============================================================================================
// The contract the front controller and the configuration must keep.
// ============================================================================================

$tests['cache: the shipped configuration documents both controls and why they matter'] =
    function (): void {
        $example = (string) file_get_contents(__DIR__ . '/../config/loghound.example.php');

        lh_contains($example, "'enabled'     => false", 'the toggle must ship off');
        lh_contains($example, "'ttl_seconds' => 7200", 'the duration must ship at two hours');
        lh_contains($example, "'server'      => '127.0.0.1:11211'", 'the server key must be documented');

        lh_contains($example, 'NO AUTHENTICATION', 'the example must warn that memcached is unauthenticated');
        lh_contains($example, 'Clear cache', 'and must say how to force a refresh before the duration is up');

        $defaults = (string) file_get_contents(__DIR__ . '/../src/Config.php');
        lh_contains($defaults, "'enabled'     => false", 'the real default must match the example');
        lh_contains($defaults, 'Cache::TTL_DEFAULT', 'and must take the duration from the one class that owns it');
    };

$tests['cache: the example configuration is honest about what the bandwidth saving is'] =
    function (): void {
        $example = (string) file_get_contents(__DIR__ . '/../config/loghound.example.php');
        lh_contains($example, 'metered', 'the example must explain that reads are metered');

        $solr = (string) file_get_contents(__DIR__ . '/../src/Solr.php');
        lh_contains(
            $solr,
            'Opensolr meters outgoing traffic',
            'the client must record why it counts response bytes and not request bytes'
        );
        lh_true(
            !str_contains($solr, 'CURLINFO_SIZE_UPLOAD'),
            'request bytes must NOT be counted — they are not billed, and including them '
            . 'would overstate the saving the cache claims'
        );
    };

$tests['cache: every JSON payload carries the provenance stamp'] =
    function (): void {
        $front = (string) file_get_contents(__DIR__ . '/../public/index.php');

        lh_contains($front, "\$payload['cache'] = \$gw->cacheStamp();", 'the stamp must be attached centrally');

        $attach = strpos($front, "\$payload['cache'] = ");
        $emit = strpos($front, 'json_out($payload,');
        lh_true($attach !== false && $emit !== false, 'both the attachment and the emission must exist');
        lh_true($attach < $emit, 'the stamp must be attached BEFORE the payload is emitted');
    };

$tests['cache: the Clear control is a CSRF-checked POST behind authentication'] =
    function (): void {
        $front = (string) file_get_contents(__DIR__ . '/../public/index.php');

        $auth = strpos($front, 'Security::requireAuth(');
        $csrf = strpos($front, 'Security::requireCsrf();');
        $clear = strpos($front, "isset(\$_POST['clear_cache'])");

        lh_true($auth !== false, 'authentication must happen');
        lh_true($csrf !== false, 'CSRF must be enforced');
        lh_true($clear !== false, 'the clear action must exist');
        lh_true($auth < $clear, 'clearing must be behind the signed-in session');
        lh_true($csrf < $clear, 'and behind the CSRF check');
        lh_contains($front, '303', 'the outcome must be a redirect so a refresh cannot clear twice');
    };

$tests['cache: the page is told whether there is anything to clear'] =
    function (): void {
        $front = (string) file_get_contents(__DIR__ . '/../public/index.php');

        lh_contains($front, "'enabled' => \$gw->cache()->isEnabled()", 'the boot payload must say if the cache works');
        lh_contains($front, "'ttl'     => \$gw->cache()->ttl()", 'and how long an entry lives');
        lh_contains($front, "'cleared' =>", 'and what the press that just happened achieved');

        lh_true(
            !str_contains($front, "\$gw->cache()->status()"),
            'the server address and failure reason must stay out of the boot payload'
        );
    };

$tests['cache: nothing anywhere calls flush_all'] =
    function (): void {
        foreach (['src/Cache.php', 'src/Panel/Gateway.php', 'public/index.php'] as $rel) {
            $src = (string) file_get_contents(__DIR__ . '/../' . $rel);
            /* Matched as a CALL, not as a word. Cache.php names flush_all in prose to record why
               it is not used, and a check that could not tell the explanation from the act would
               have to be deleted the first time someone documented the decision. */
            lh_true(
                !str_contains($src, '->flush('),
                $rel . ' must never flush memcached — it would destroy a co-tenant application\'s cache'
            );
            lh_true(!str_contains($src, 'flush_all('), $rel . ' must never issue flush_all');
        }
    };

// ============================================================================================
// The real extension, when there is one here.
// ============================================================================================

$tests['cache: a real memcached stores, serves and clears'] =
    function (): void {
        $mc = lh_real_memcached();
        if ($mc === null) {
            lh_skip('no memcached on 127.0.0.1 (set LOGHOUND_TEST_MEMCACHED_PORT to point elsewhere)');
        }

        $cache = Cache::withClient($mc, 600, 'realtest_' . bin2hex(random_bytes(4)));

        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*', 'fq' => ['a:"1"']]]);
        lh_true($cache->put($key, ['count' => 11], null, 3333), 'the real client must store');

        $hit = $cache->get($key);
        lh_true(is_array($hit), 'and serve it back');
        lh_same(['count' => 11], $hit['value'], 'with the value intact');

        $saved = $cache->savings();
        lh_same(1, $saved['requests'], 'the counter must work on the real client');
        lh_same(3333, $saved['bytes'], 'and so must the byte counter');

        $outcome = $cache->clear();
        lh_true($outcome['cleared'], 'the clear must succeed');
        lh_same(1, $outcome['entries'], 'and count what it discarded');
        lh_same(
            null,
            $cache->get($cache->key('t', 'sessions', ['query' => ['q' => '*:*', 'fq' => ['a:"1"']]])),
            'the same question must miss after the clear'
        );
    };

$tests['cache: a real memcached is never asked to deserialise a PHP value'] =
    function (): void {
        $mc = lh_real_memcached();
        if ($mc === null) {
            lh_skip('no memcached on 127.0.0.1');
        }

        $cache = Cache::withClient($mc, 600, 'realtest_' . bin2hex(random_bytes(4)));
        $key = $cache->key('t', 'sessions', ['query' => ['q' => '*:*']]);
        $cache->put($key, ['count' => 1, 'nested' => ['a' => [1, 2, 3]]], null, 100);

        $raw = $mc->get($key);
        lh_true(is_string($raw), 'what lands in memcached must be a string, not a serialised PHP graph');
        lh_true(is_array(json_decode($raw, true)), 'and it must be JSON');

        $cache->clear();
    };

// ============================================================================================
// Standalone runner — used before tests/run.php exists.
// ============================================================================================

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    require __DIR__ . '/helpers.php';
    require __DIR__ . '/../src/autoload.php';
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
