<?php
/**
 * Loghound — memcached cache for the panel's Solr reads.
 *
 * WHAT THIS IS FOR. The panel runs where the operator is and the index runs where the data
 * is, and those are routinely different countries: a Solr that answers a facet in 1 to 5 ms
 * is 237 ms away, and a view drawing six cards pays that six times. Caching the ANSWER, close
 * to the panel, is the only thing that removes a latency the panel cannot make smaller.
 *
 * HOW LONG AN ENTRY LIVES IS THE OPERATOR'S DECISION, not this class's. One duration applies
 * to everything, it defaults to two hours, and it is a control in Settings rather than a
 * constant here — because only the person reading the panel knows whether they are watching a
 * live incident or checking in twice a day. What the code owes them in exchange is that they
 * can always see how old a number is (`stamp()`, printed beside every card) and can always
 * throw the whole cache away without waiting (`clear()`, the Clear cache button). A long cache
 * is comfortable exactly to the degree that those two things work.
 *
 * OPTIONAL, ALWAYS. memcached is a dependency Loghound asks for and does not require. No
 * extension, no server, an unreachable server, a server that starts refusing mid-request —
 * every one of those degrades to exactly the behaviour of an install with no cache at all,
 * and never to an error on a page. Every failure path here returns a miss.
 *
 * ---------------------------------------------------------------------------------------
 * WHY A GENERATION COUNTER AND NOT flush_all
 * ---------------------------------------------------------------------------------------
 * memcached has no notion of "my keys". `flush_all` empties the whole daemon, which on any
 * box where something else also uses memcached destroys that application's cache too — a
 * Clear button in one panel is not allowed to be an outage in someone else's. So the
 * installation's key prefix carries a GENERATION number, every cache key is built under it,
 * and clearing increments it.
 *
 * BE PRECISE ABOUT WHAT THAT ACHIEVES. It is one atomic operation, it races with nothing, and
 * it touches no other tenant. Because the panel always derives a key from the request it is
 * answering, no question asked after a Clear can name an entry written before it, so every card
 * recomputes — which is what the operator pressed the button for. It does not erase the old
 * bytes: memcached cannot be enumerated, so the orphans are left to be reclaimed by the expiry
 * they were written with, at most the configured duration away. Deleting them instead would
 * mean maintaining an index of every key written, which is an extra write on every store and a
 * second thing to get wrong, to reclaim memory that is already on a timer.
 *
 * ---------------------------------------------------------------------------------------
 * SECURITY
 * ---------------------------------------------------------------------------------------
 * The values here are the operator's traffic data — paths, addresses, user agents, verdicts.
 * Three consequences, all of them enforced below rather than documented and hoped for.
 *
 * KEYS ARE UNGUESSABLE, not merely distinct. The per-installation prefix is an HMAC over the
 * install's own secret material (the beacon secret, the password hash, the config path), so
 * two Loghounds sharing one memcached cannot address each other's entries even though they
 * share a keyspace, and a co-tenant application cannot construct one of our keys to read it.
 * Only the digest ever reaches a key; the secret material never leaves this function.
 *
 * NOTHING IS DESERIALISED. Values are stored as JSON and read back with json_decode(), never
 * with PHP's serializer. A cache entry is bytes from a network service that other processes
 * can write to, so treating it as a PHP object graph — which is what \Memcached does by
 * default — would make anything able to write to memcached able to instantiate objects in
 * this process. The stored envelope is validated field by field, and anything unexpected is
 * a miss.
 *
 * ONLY SUCCESSES ARE STORED, and only aggregates the caller has already decided to show. A
 * failed Solr read is never cached: caching an empty result would turn one bad minute into a
 * TTL's worth of a dashboard that reports nothing is happening.
 *
 * A NOTE FOR THE OPERATOR, which is in config/loghound.example.php as well: memcached has no
 * authentication and no transport security. It belongs on 127.0.0.1 or a unix socket. The
 * unguessable prefix stops a co-tenant reading these entries by construction; it does not
 * make a memcached exposed to a network safe, and nothing can.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Cache
{
    /**
     * Envelope version.
     *
     * Stored with every entry and checked on read. A release that changes the shape of what
     * the panel caches bumps this, and every entry written by the previous release is a miss
     * from that moment — which is the only safe reading of a payload whose meaning changed.
     */
    private const SCHEMA = 1;

    /**
     * How long an entry lives when the operator has not said, in seconds.
     *
     * Two hours. It is the answer for someone who opens the panel once or twice a day and
     * wants it instant, and it is safe to be that long only because the age of every number is
     * on screen beside it and the Clear cache button is on every page.
     */
    public const TTL_DEFAULT = 7200;

    /**
     * Shortest duration the operator may set, in seconds.
     *
     * One minute. Below that the cache stops being a cache — a panel draws a page in less time
     * than that, so a shorter setting would mostly be storing answers nothing lives to read,
     * and the honest way to want fresh numbers is to turn the cache off.
     */
    public const TTL_MIN = 60;

    /**
     * Longest duration the operator may set, in seconds.
     *
     * Twenty-four hours. A cap exists because memcached treats a large enough expiry as an
     * absolute unix timestamp and because "cached since yesterday" is the outer edge of what a
     * traffic dashboard can claim while still being one; a day is also the point past which the
     * stamp on the card would be reporting a date rather than a time.
     */
    public const TTL_MAX = 86400;

    /** Milliseconds to spend reaching memcached before giving up and behaving as uncached. */
    private const CONNECT_TIMEOUT_MS = 150;

    /** Milliseconds to spend on one get or set. A cache slower than Solr is not a cache. */
    private const IO_TIMEOUT_MS = 250;

    /** @var \Memcached|\Memcache|object|null Live client, or null when there is no usable cache. */
    private $mc = null;

    /** Per-installation key prefix, already including the generation. */
    private string $prefix = '';

    /** Unguessable per-installation digest. The generation is appended separately. */
    private string $namespace = '';

    /** Current generation, read once per process and cached here. */
    private ?int $generation = null;

    private bool $enabled;

    /** 'memcached', 'memcache' or '' when neither extension is present. */
    private string $driver = '';

    private string $server;

    /** Why the cache is not working, in a sentence for the Settings system check. */
    private string $reason = '';

    /** How long a stored answer lives, in seconds. Already clamped. */
    private int $ttl;

    /** Set once a memcached operation has failed, so the rest of the request stops trying. */
    private bool $dead = false;

    /** Hits and misses in this request, for the provenance stamp. */
    private int $hits = 0;

    private int $misses = 0;

    /** Unix time the oldest entry served in this request was computed, or null. */
    private ?int $oldest = null;

    /** Response bytes this request did not have to fetch, from the entries it served. */
    private int $savedBytes = 0;

    /** Hits in this request whose entry did not record a size, so the saving is understated. */
    private int $savedUnknown = 0;

    /**
     * @param int $ttl Seconds an entry lives. Clamped by the caller.
     */
    private function __construct(bool $enabled, string $server, string $namespace, int $ttl)
    {
        $this->enabled = $enabled;
        $this->server = $server;
        $this->namespace = $namespace;
        $this->ttl = $ttl;
    }

    /**
     * Build the cache from configuration.
     *
     * The namespace is derived here and only here. It mixes the install's secret material
     * into an HMAC so the resulting prefix is unguessable, and it mixes in the Solr base URL
     * and both core names so that repointing an install at a different index is a different
     * keyspace rather than a set of entries that describe an index nobody is looking at.
     *
     * An install with no secret material at all — auth mode `none`, no beacon — still gets a
     * distinct namespace from its config path, which is the best that can be done and is
     * noted as such in the example config.
     */
    public static function fromConfig(Config $cfg): self
    {
        $enabled = $cfg->get('cache.enabled') === true;
        $server = trim((string) $cfg->get('cache.server', '127.0.0.1:11211'));

        $material = implode("\0", [
            (string) $cfg->path(),
            (string) $cfg->get('solr.base_url', ''),
            (string) $cfg->get('solr.hits_core', ''),
            (string) $cfg->get('solr.sessions_core', ''),
            (string) $cfg->get('beacon.secret', ''),
            (string) $cfg->get('auth.password_hash', ''),
        ]);
        $namespace = substr(hash_hmac('sha256', $material, 'loghound.panel.cache'), 0, 20);

        $ttl = Security::clampInt($cfg->get('cache.ttl_seconds'), self::TTL_MIN, self::TTL_MAX, self::TTL_DEFAULT);

        return new self($enabled, $server, $namespace, $ttl);
    }

    /**
     * Clamp a duration the operator typed, for the Settings form to save and echo back.
     *
     * Exposed so the form and the cache cannot disagree about what is allowed: the field that
     * accepts the number and the object that uses it reach the same verdict from the same
     * function, rather than one validating and the other silently substituting.
     *
     * @param mixed $seconds
     */
    public static function clampTtl($seconds): int
    {
        return Security::clampInt($seconds, self::TTL_MIN, self::TTL_MAX, self::TTL_DEFAULT);
    }

    /**
     * A cache that never stores and never hits.
     *
     * Used by demo mode and by tests that must see the uncached path. It is a real object
     * rather than a null, so no caller needs a branch for "there is no cache".
     */
    public static function disabled(string $reason = 'disabled'): self
    {
        $c = new self(false, '', str_repeat('0', 20), self::TTL_DEFAULT);
        $c->reason = $reason;
        return $c;
    }

    /**
     * Build a cache over a client supplied by the caller.
     *
     * The same arrangement \Loghound\Solr has for its transport, and for the same reason: the
     * envelope handling, the schema check, the generation arithmetic and the hit accounting are
     * where the bugs would be, and none of that should need a running daemon to exercise. A
     * test hands over an in-memory stand-in and the suite keeps its promise of needing no
     * network.
     *
     * The object must answer `get(string)`, `set(string,string,int,int)`, `delete(string)`,
     * `add(string,mixed,int,int)` and `increment(string,int)` — the \Memcache arities, which is
     * what anything that is not a \Memcached instance is called with below.
     */
    public static function withClient(object $client, int $ttl = self::TTL_DEFAULT, string $namespace = 'testns'): self
    {
        $c = new self(true, 'injected', substr(hash('sha256', $namespace), 0, 20), self::clampTtl($ttl));
        $c->mc = $client;
        $c->driver = 'injected';
        return $c;
    }

    /** Is the cache configured on and actually usable? */
    public function isEnabled(): bool
    {
        return $this->enabled && !$this->dead && $this->client() !== null;
    }

    /**
     * What the Settings system check should say about the cache.
     *
     * Reports the CONFIGURED intent and the OBSERVED reality separately, because "on but
     * unreachable" and "off" look identical from a page that only prints a verdict, and they
     * need different actions from the operator.
     *
     * @return array{configured:bool,working:bool,driver:string,server:string,reason:string,ttl:int,ttl_min:int,ttl_max:int}
     */
    public function status(): array
    {
        $working = $this->isEnabled();
        return [
            'configured' => $this->enabled,
            'working'    => $working,
            'driver'     => $this->driver,
            'server'     => $this->server,
            'reason'     => $working ? '' : ($this->reason !== '' ? $this->reason : 'not connected'),
            'ttl'        => $this->ttl,
            'ttl_min'    => self::TTL_MIN,
            'ttl_max'    => self::TTL_MAX,
        ];
    }

    /** How long a stored answer lives, in seconds. One duration for everything. */
    public function ttl(): int
    {
        return $this->ttl;
    }

    /**
     * Build a cache key from everything that changes the answer.
     *
     * THE CALLER PASSES THE WHOLE REQUEST, not a summary of it. A key built from a chosen list
     * of inputs is a key that goes wrong the moment an input is added somewhere else, and the
     * failure is silent and serves one filter's numbers under another's heading. So the
     * canonical form here is the entire Solr request — q, every fq with its tags, sort, rows,
     * start, fl, the facet block, the bound free text — normalised by sorting keys so that two
     * requests differing only in array order share an entry, and hashed.
     *
     * The tag and the core are separate arguments because they are what makes two structurally
     * identical requests different questions, and the range token is separate because it
     * selects the TTL rather than appearing in the hash on its own account.
     *
     * @param array<string,mixed> $parts
     */
    public function key(string $tag, string $core, array $parts): string
    {
        $canonical = self::canonical(['tag' => $tag, 'core' => $core] + $parts);
        $digest = hash('sha256', (string) json_encode($canonical, JSON_INVALID_UTF8_SUBSTITUTE));

        return 'lh.' . $this->namespace . '.' . $this->gen() . '.' . substr($digest, 0, 40);
    }

    /**
     * Read an entry.
     *
     * Returns null for a miss and for every kind of damage: no cache, a dead cache, a
     * non-string value, unparseable JSON, the wrong envelope version, a missing timestamp, a
     * timestamp in the future. There is no partial reading of an entry, and a malformed one is
     * never repaired — it is ignored and overwritten by the next store.
     *
     * @return array{at:int,value:mixed}|null
     */
    public function get(string $key): ?array
    {
        $mc = $this->client();
        if ($mc === null) {
            return null;
        }

        $raw = $this->io(static fn () => $mc->get($key));
        if (!is_string($raw) || $raw === '') {
            $this->misses++;
            return null;
        }

        $env = json_decode($raw, true);
        if (!is_array($env)
            || ($env['s'] ?? null) !== self::SCHEMA
            || !isset($env['at'], $env['v'])
            || !is_int($env['at'])
            || $env['at'] <= 0
            || $env['at'] > time() + 60
        ) {
            $this->misses++;
            return null;
        }

        $this->hits++;
        if ($this->oldest === null || $env['at'] < $this->oldest) {
            $this->oldest = $env['at'];
        }

        $bytes = isset($env['b']) && is_int($env['b']) && $env['b'] > 0 ? $env['b'] : 0;
        if ($bytes > 0) {
            $this->savedBytes += $bytes;
            $this->addSaving($bytes);
        } else {
            $this->savedUnknown++;
        }

        return ['at' => $env['at'], 'value' => $env['v']];
    }

    /**
     * Store an entry.
     *
     * Only ever called with a value the caller has already decided is a good answer. The
     * duration is re-clamped here as well as where it was configured, because a caller passing
     * one is one more place a zero could come from and a zero means "never expires" to
     * memcached.
     *
     * A value that will not encode as JSON is not stored. That is the correct outcome rather
     * than a fallback to the PHP serializer: an answer this class cannot read back safely is
     * an answer it has no business keeping.
     *
     * @param mixed    $value
     * @param int|null $ttl   Seconds, or null for the operator's configured duration.
     * @param int      $bytes Response bytes this answer cost to fetch, 0 when not known. Stored
     *                        with the entry so a later hit can report what it did not spend.
     */
    public function put(string $key, $value, ?int $ttl = null, int $bytes = 0): bool
    {
        $mc = $this->client();
        if ($mc === null) {
            return false;
        }

        /* NO JSON_PARTIAL_OUTPUT_ON_ERROR, deliberately. With it set, a value json_encode()
           cannot represent — a resource, a recursive structure, INF — is silently written as
           null and the entry is stored anyway, so the cache would serve an answer that differs
           from the one Solr gave for up to the whole duration, with nothing to indicate it.
           Refusing to store is the only safe reading. JSON_INVALID_UTF8_SUBSTITUTE stays,
           because log-derived text genuinely does contain invalid byte sequences and replacing
           those is what every other output path in the panel already does. */
        $payload = json_encode(
            ['s' => self::SCHEMA, 'at' => time(), 'b' => max(0, $bytes), 'v' => $value],
            JSON_INVALID_UTF8_SUBSTITUTE
        );
        if (!is_string($payload)) {
            return false;
        }

        $seconds = Security::clampInt($ttl ?? $this->ttl, self::TTL_MIN, self::TTL_MAX, $this->ttl);

        $ok = (bool) $this->io(static function () use ($mc, $key, $payload, $seconds) {
            return $mc instanceof \Memcached
                ? $mc->set($key, $payload, $seconds)
                : $mc->set($key, $payload, 0, $seconds);
        });

        if ($ok) {
            $this->bumpCount();
        }

        return $ok;
    }

    /**
     * Discard every entry this installation has cached, and say how many that was.
     *
     * Increments the generation, so that no key the panel builds afterwards can name anything
     * written before — every card recomputes on the next load. Nothing belonging to another
     * tenant of the same memcached is touched, and the orphaned entries are reclaimed by the
     * expiry they were written with. See the note at the top of this file for why that is the
     * right trade rather than an index of keys to delete.
     *
     * The count is the number of entries STORED under the generation being retired, kept by
     * `bumpCount()` as they were written. It is a truthful count of what was put there, and it
     * is an upper bound on what was still live, since memcached may already have expired or
     * evicted some of them — which is why the wording the panel shows says "cached answers
     * discarded" rather than claiming a number of live keys.
     *
     * @return array{cleared:bool,entries:int,reason:string}
     */
    public function clear(): array
    {
        $mc = $this->client();
        if ($mc === null) {
            return ['cleared' => false, 'entries' => 0, 'reason' => $this->status()['reason']];
        }

        $gen = $this->gen();
        $countKey = $this->countKey($gen);
        $entries = (int) $this->io(static fn () => (int) $mc->get($countKey));

        $genKey = $this->genKey();
        $next = $gen + 1;
        $bumped = $this->io(static function () use ($mc, $genKey, $next) {
            return $mc instanceof \Memcached
                ? $mc->set($genKey, (string) $next, 0)
                : $mc->set($genKey, (string) $next, 0, 0);
        });

        if ($bumped === false || $bumped === null) {
            return ['cleared' => false, 'entries' => 0, 'reason' => 'the cache server did not accept the change'];
        }

        foreach ([$countKey, $this->savedRequestsKey($gen), $this->savedBytesKey($gen), $this->sinceKey($gen)] as $old) {
            $this->io(static fn () => $mc->delete($old));
        }

        $this->generation = $next;
        $this->markSince($next);
        $this->resetStamp();

        return ['cleared' => true, 'entries' => max(0, $entries), 'reason' => ''];
    }

    /**
     * Provenance for everything served in this request.
     *
     * A CACHED NUMBER THAT DOES NOT SAY SO IS A WRONG NUMBER. This is what the panel prints
     * next to the cards, so it reports the OLDEST computation behind the payload rather than
     * an average or the newest: a card built from two entries is only as fresh as its stalest
     * part, and rounding that in the flattering direction is the defect being avoided.
     *
     * `cached` is false whenever nothing came from the cache, which is what an uncached
     * install, a cache miss and a disabled cache all look like — correctly, because in all
     * three cases the numbers were computed during this request.
     *
     * `expires` is how many seconds are left before the oldest part of this payload would be
     * recomputed on its own. It is there so the card can say "computed 14 minutes ago" without
     * the reader having to know what the duration is set to, and so a long duration is
     * legible rather than merely configured.
     *
     * @return array{enabled:bool,cached:bool,hits:int,misses:int,computed_at:string,age:int,ttl:int,expires:int}
     */
    public function stamp(): array
    {
        $cached = $this->hits > 0 && $this->oldest !== null;
        $age = $cached ? max(0, time() - (int) $this->oldest) : 0;

        return [
            'enabled'     => $this->isEnabled(),
            'cached'      => $cached,
            'hits'        => $this->hits,
            'misses'      => $this->misses,
            'computed_at' => $cached ? gmdate('c', (int) $this->oldest) : gmdate('c'),
            'age'         => $age,
            'ttl'         => $this->ttl,
            'expires'     => $cached ? max(0, $this->ttl - $age) : $this->ttl,
        ];
    }

    /** Forget this request's hit/miss tally, so a caller can measure one section of work. */
    public function resetStamp(): void
    {
        $this->hits = 0;
        $this->misses = 0;
        $this->oldest = null;
        $this->savedBytes = 0;
        $this->savedUnknown = 0;
    }

    /**
     * Bandwidth this cache has not spent since it was last cleared.
     *
     * WHY THIS IS WORTH REPORTING AT ALL. Opensolr meters outgoing traffic — the responses Solr
     * sends back — so a plan's bandwidth is consumed by reads, not by writes. The tailer pushing
     * log lines into the index uploads them and gets a short acknowledgement, which is why
     * ingestion is close to free on that quota however busy the site is, and why the metered
     * figure on a Loghound install is almost entirely the panel's own reads. The cache is
     * therefore not a marginal saving on a mixed bill; it is the only lever on that bill.
     *
     * WHY IT IS HONEST. Every number here is a sum of sizes curl measured on the wire and stored
     * with the entry that was served. Nothing is modelled, averaged or extrapolated. What it
     * omits is named rather than hidden: TLS framing is not counted, and `partial` is true when
     * any hit came from an entry written before sizes were recorded, or by a transport that does
     * not report them — in which case the figure understates the saving and must be presented as
     * a floor, not a total. A caller that cannot say "approximately" should not print it.
     *
     * The counters live in memcached under the current generation, so Clear resets them along
     * with the entries they describe, and `since` is when that generation began.
     *
     * @return array{available:bool,requests:int,bytes:int,since:int,partial:bool,
     *               request_requests:int,request_bytes:int}
     */
    public function savings(): array
    {
        $mc = $this->client();
        if ($mc === null) {
            return [
                'available'        => false,
                'requests'         => 0,
                'bytes'            => 0,
                'since'            => 0,
                'partial'          => $this->savedUnknown > 0,
                'request_requests' => $this->hits,
                'request_bytes'    => $this->savedBytes,
            ];
        }

        $gen = $this->gen();
        $reqKey = $this->savedRequestsKey($gen);
        $byteKey = $this->savedBytesKey($gen);
        $sinceKey = $this->sinceKey($gen);

        return [
            'available'        => true,
            'requests'         => max(0, (int) $this->io(static fn () => (int) $mc->get($reqKey))),
            'bytes'            => max(0, (int) $this->io(static fn () => (int) $mc->get($byteKey))),
            'since'            => max(0, (int) $this->io(static fn () => (int) $mc->get($sinceKey))),
            'partial'          => $this->savedUnknown > 0,
            'request_requests' => $this->hits,
            'request_bytes'    => $this->savedBytes,
        ];
    }

    /**
     * Connect on first use, once, and never again after a failure.
     *
     * LAZY BECAUSE MOST REQUESTS DO NOT NEED IT. A page render makes no Solr call at all, so
     * connecting during construction would add a socket to every request that had nothing to
     * ask. Persistent because the connection is the thing worth keeping: \Memcached's
     * persistent id makes the socket outlive the request inside an FPM worker, which is the
     * same saving the Solr client gets from holding its curl handle.
     *
     * Timeouts are deliberately far below the panel's query timeout. An unreachable cache must
     * cost a fraction of a second once and then be out of the way, never turn a working panel
     * into a slow one — which is why `$dead` latches and is never retried in the same request.
     *
     * @return \Memcached|\Memcache|null
     */
    private function client()
    {
        if (!$this->enabled || $this->dead) {
            return null;
        }
        if ($this->mc !== null) {
            return $this->mc;
        }

        [$host, $port] = self::splitServer($this->server);
        if ($host === '') {
            $this->reason = 'cache.server is not a host:port or a socket path';
            $this->dead = true;
            return null;
        }

        try {
            if (class_exists('\\Memcached')) {
                /* THE PERSISTENT ID MUST NAME THE SERVER, not just the installation. A persistent
                   \Memcached is looked up by this string and comes back with its previous server
                   list and open connections still attached, so an id that omitted the address
                   would hand back a client still pointed at the old server after the operator
                   changed it in Settings — and the server-list guard below would then decline to
                   add the new one. It would keep answering, from the wrong place, until the
                   worker recycled. */
                $mc = new \Memcached('loghound.' . $this->namespace . '.' . substr(hash('sha256', $this->server), 0, 12));
                $mc->setOption(\Memcached::OPT_BINARY_PROTOCOL, true);
                $mc->setOption(\Memcached::OPT_CONNECT_TIMEOUT, self::CONNECT_TIMEOUT_MS);
                $mc->setOption(\Memcached::OPT_POLL_TIMEOUT, self::IO_TIMEOUT_MS);
                $mc->setOption(\Memcached::OPT_SEND_TIMEOUT, self::IO_TIMEOUT_MS * 1000);
                $mc->setOption(\Memcached::OPT_RECV_TIMEOUT, self::IO_TIMEOUT_MS * 1000);
                $mc->setOption(\Memcached::OPT_RETRY_TIMEOUT, 1);
                $mc->setOption(\Memcached::OPT_SERVER_FAILURE_LIMIT, 1);
                if ($mc->getServerList() === []) {
                    $mc->addServer($host, $port);
                }

                /* ADDING A SERVER IS NOT REACHING IT. \Memcached::addServer() only records an
                   address; nothing connects until the first operation, so without this probe
                   isEnabled() would answer true for a socket path that does not exist and the
                   Settings check would report a working cache to an operator who has none. One
                   round trip on a loopback socket, once per process, buys a truthful answer. */
                if (!self::answered(@$mc->getVersion())) {
                    $this->reason = 'could not reach the cache server at ' . $this->server;
                    $this->dead = true;
                    return null;
                }

                $this->driver = 'memcached';
                $this->mc = $mc;
                return $mc;
            }

            if (class_exists('\\Memcache')) {
                $mc = new \Memcache();
                if (!@$mc->connect($host, $port, self::CONNECT_TIMEOUT_MS / 1000)) {
                    $this->reason = 'could not connect to ' . $this->server;
                    $this->dead = true;
                    return null;
                }
                $this->driver = 'memcache';
                $this->mc = $mc;
                return $mc;
            }
        } catch (\Throwable $e) {
            $this->reason = 'the memcached client could not be created';
            $this->dead = true;
            return null;
        }

        $this->reason = 'neither the memcached nor the memcache PHP extension is installed';
        $this->dead = true;
        return null;
    }

    /**
     * Did a getVersion() call show at least one server that actually answered?
     *
     * Three shapes have to be told apart, because libmemcached reports an unreachable server in
     * more than one way depending on its version: `false` outright, an empty array, and — the
     * one that would otherwise pass — an array whose value is the sentinel `255.255.255`, which
     * means "asked, never answered". Only a real version string counts as reached.
     *
     * @param mixed $version
     */
    private static function answered($version): bool
    {
        if (!is_array($version)) {
            return false;
        }
        foreach ($version as $reported) {
            if (is_string($reported) && $reported !== '' && $reported !== '255.255.255') {
                return true;
            }
        }
        return false;
    }

    /**
     * Run one cache operation, treating any failure as a miss for the rest of the request.
     *
     * \Memcached signals failure by return value, \Memcache by warnings, and both can throw
     * under a mismatched libmemcached. All three are the same event here — the cache is not
     * answering — and all three must produce a panel that works rather than a stack trace, so
     * the whole call is wrapped and `$dead` latches on the way out.
     *
     * @param callable():mixed $op
     * @return mixed
     */
    private function io(callable $op)
    {
        try {
            $out = @$op();
        } catch (\Throwable $e) {
            $this->dead = true;
            $this->reason = 'a cache operation failed';
            return null;
        }

        if ($out === false && $this->mc instanceof \Memcached) {
            $code = $this->mc->getResultCode();
            if ($code !== \Memcached::RES_NOTFOUND && $code !== \Memcached::RES_NOTSTORED) {
                $this->dead = true;
                $this->reason = 'the cache server stopped answering';
            }
        }

        return $out;
    }

    /** The key holding this installation's generation number. */
    private function genKey(): string
    {
        return 'lh.' . $this->namespace . '.gen';
    }

    /** The key counting entries written under one generation. */
    private function countKey(int $gen): string
    {
        return 'lh.' . $this->namespace . '.n' . $gen;
    }

    /** The key counting reads served from cache under one generation. */
    private function savedRequestsKey(int $gen): string
    {
        return 'lh.' . $this->namespace . '.sr' . $gen;
    }

    /** The key counting response bytes not fetched under one generation. */
    private function savedBytesKey(int $gen): string
    {
        return 'lh.' . $this->namespace . '.sb' . $gen;
    }

    /** The key holding when one generation began, so a saving can be given a period. */
    private function sinceKey(int $gen): string
    {
        return 'lh.' . $this->namespace . '.since' . $gen;
    }

    /**
     * Record that a hit avoided fetching some bytes.
     *
     * Two counters rather than one because "forty reads" and "nine megabytes" answer different
     * questions and neither can be derived from the other. Both are incremented rather than
     * recomputed, since a memcached keyspace cannot be enumerated, and both failures are
     * ignored: a saving that cannot be counted must never be allowed to break the read that was
     * being served when the counting failed.
     */
    private function addSaving(int $bytes): void
    {
        $mc = $this->client();
        if ($mc === null) {
            return;
        }

        $gen = $this->gen();
        foreach ([$this->savedRequestsKey($gen) => 1, $this->savedBytesKey($gen) => $bytes] as $key => $by) {
            $out = $this->io(static fn () => $mc->increment($key, $by));
            if ($out === false || $out === null) {
                $this->io(static function () use ($mc, $key, $by) {
                    return $mc instanceof \Memcached
                        ? $mc->add($key, $by, 0)
                        : $mc->add($key, $by, 0, 0);
                });
            }
        }
    }

    /**
     * The current generation, read once per process.
     *
     * A missing counter is generation 1 and is written back so that the first Clear has
     * something to increment. A value that is not a positive integer — a foreign key collision,
     * a corrupted entry — is treated as generation 1 rather than trusted, which at worst
     * re-uses a keyspace whose entries are about to expire anyway.
     */
    private function gen(): int
    {
        if ($this->generation !== null) {
            return $this->generation;
        }

        $mc = $this->client();
        if ($mc === null) {
            $this->generation = 1;
            return 1;
        }

        $key = $this->genKey();
        $raw = $this->io(static fn () => $mc->get($key));
        $gen = is_string($raw) || is_int($raw) ? (int) $raw : 0;

        if ($gen < 1) {
            $gen = 1;
            $this->io(static function () use ($mc, $key, $gen) {
                return $mc instanceof \Memcached
                    ? $mc->set($key, (string) $gen, 0)
                    : $mc->set($key, (string) $gen, 0, 0);
            });
        }

        $this->generation = $gen;
        $this->markSince($gen);
        return $gen;
    }

    /**
     * Note when a generation began, once, without overwriting an earlier answer.
     *
     * `add` rather than `set`, which is the whole of the correctness here: the first process to
     * reach a new generation stamps it and every later one is refused, so the period a saving is
     * measured over starts when the cache was cleared rather than resetting on every request
     * that happens to look at it.
     */
    private function markSince(int $gen): void
    {
        $mc = $this->mc;
        if ($mc === null) {
            return;
        }

        $key = $this->sinceKey($gen);
        $now = time();
        $this->io(static function () use ($mc, $key, $now) {
            return $mc instanceof \Memcached
                ? $mc->add($key, $now, 0)
                : $mc->add($key, $now, 0, 0);
        });
    }

    /**
     * Count one stored entry, so Clear can say how many it discarded.
     *
     * Incremented rather than recomputed because there is no way to enumerate a memcached
     * keyspace. The counter shares the generation's lifetime and is deleted with it, and its
     * own failure is ignored: a Clear that reports "some" instead of "forty-one" is a smaller
     * problem than a store that fails because a counter did.
     */
    private function bumpCount(): void
    {
        $mc = $this->client();
        if ($mc === null) {
            return;
        }

        $key = $this->countKey($this->gen());
        $out = $this->io(static fn () => $mc->increment($key, 1));
        if ($out === false || $out === null) {
            $this->io(static function () use ($mc, $key) {
                return $mc instanceof \Memcached
                    ? $mc->add($key, 1, 0)
                    : $mc->add($key, 1, 0, 0);
            });
        }
    }

    /**
     * Split `cache.server` into a host and a port.
     *
     * Three forms are accepted: `host:port`, a bare host on the default port, and an absolute
     * path, which is a unix socket and is signalled to both extensions by a port of zero.
     * IPv6 in brackets is handled because `[::1]:11211` is what an operator writes and
     * splitting it on the last colon is what makes it fail.
     *
     * Anything else yields an empty host, which disables the cache with a reason rather than
     * handing an unvalidated string to a connect call.
     *
     * @return array{0:string,1:int}
     */
    private static function splitServer(string $server): array
    {
        $server = trim($server);
        if ($server === '') {
            return ['', 0];
        }

        if ($server[0] === '/') {
            return [$server, 0];
        }

        if ($server[0] === '[') {
            $close = strpos($server, ']');
            if ($close === false) {
                return ['', 0];
            }
            $host = substr($server, 1, $close - 1);
            $rest = substr($server, $close + 1);
            $port = ($rest !== '' && $rest[0] === ':') ? (int) substr($rest, 1) : 11211;
            return [$host, $port > 0 && $port <= 65535 ? $port : 11211];
        }

        $at = strrpos($server, ':');
        if ($at === false) {
            return [$server, 11211];
        }

        $host = substr($server, 0, $at);
        $port = (int) substr($server, $at + 1);
        return [$host, $port > 0 && $port <= 65535 ? $port : 11211];
    }

    /**
     * Put a request into a form where two equal requests are byte-equal.
     *
     * Arrays are key-sorted at every depth, so the same filters added in a different order are
     * one cache entry rather than two. Lists are NOT sorted: the order of an `fq` list does not
     * change the answer, but the order of a `sort` or an `fl` can, and a canonicaliser that
     * cannot tell those apart must not reorder either. Objects and resources cannot appear in a
     * Solr request and are rendered as their type, which makes them a distinct key rather than
     * a fatal error.
     *
     * @param array<array-key,mixed> $in
     * @return array<array-key,mixed>
     */
    private static function canonical(array $in): array
    {
        $out = [];
        foreach ($in as $k => $v) {
            if (is_array($v)) {
                $out[$k] = self::canonical($v);
            } elseif (is_scalar($v) || $v === null) {
                $out[$k] = $v;
            } else {
                $out[$k] = '<' . get_debug_type($v) . '>';
            }
        }
        if (!array_is_list($out)) {
            ksort($out);
        }
        return $out;
    }
}
