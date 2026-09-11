<?php
/**
 * Loghound — the two settings an operator meets on this page that cost money if they are wrong.
 *
 * **Cached queries.** Opensolr meters outgoing traffic, so on a Loghound installation the
 * bandwidth bill is almost entirely this panel's own reads: ingestion uploads lines and gets an
 * acknowledgement back, and that is close to free whatever the site's volume. The cache is
 * therefore not a performance tweak with a billing side effect, it is the only lever on that
 * bill — which is why it has a card of its own rather than a line in the system check, and why
 * these tests are about whether the card tells the truth about it.
 *
 * Two properties are pinned harder than the rest:
 *
 *  1. **Configured and working are two facts, never one verdict.** "Off" and "on but
 *     unreachable" look identical to a card that prints a single word and they need opposite
 *     actions. Collapsing them is how somebody spends an afternoon wondering why the
 *     installation they switched the cache on for is still slow.
 *  2. **The saving is printed only when it can be stated honestly.** `partial` means at least
 *     one hit came from an entry that never recorded its size, so the figure is a floor; a floor
 *     printed as a total is a wrong number, and the card leaves it out entirely instead.
 *
 * **Ingest this log.** The panel's own virtual host is a log source like any other on the
 * machine that serves it, so browsing Loghound creates sessions in the data Loghound displays.
 * The toggle is an opt-OUT — absent means enabled, so no configuration written before it existed
 * changes behaviour — and an unticked source STAYS in the list. A decision an operator made has
 * to remain visible to them; a row that vanished would leave them hunting for a file the scan
 * keeps finding and the panel keeps not mentioning.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Cache;
use Loghound\Config;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Panel\Layout;
use Loghound\Panel\Settings;
use Loghound\Solr;

/**
 * A memcached stand-in, so the cache can be exercised with no daemon and no network.
 *
 * Its own class rather than a shared one because test files are loaded in an order nobody
 * controls, and a suite that depends on which file declared a helper first is a suite that
 * breaks when a file is renamed.
 */
final class LhSettingsFakeMc
{
    /** @var array<string,mixed> */
    public array $store = [];

    /** @return mixed */
    public function get(string $key)
    {
        return $this->store[$key] ?? false;
    }

    /** @param mixed $value */
    public function set(string $key, $value, int $flags = 0, int $ttl = 0): bool
    {
        $this->store[$key] = $value;
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
}

/** A configuration that reaches no network and writes no file unless a test asks it to. */
function lh_sc_config(array $over = []): Config
{
    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_sc_hits');
    $cfg->set('solr.sessions_core', 'lh_sc_sessions');
    foreach ($over as $key => $value) {
        $cfg->set($key, $value);
    }
    return $cfg;
}

/** A gateway over a canned transport and whichever cache the test wants reported. */
function lh_sc_gateway(Config $cfg, ?Cache $cache = null): Gateway
{
    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode([
            'responseHeader' => ['status' => 0],
            'response'       => ['numFound' => 0, 'docs' => []],
        ]),
        'error'  => '',
    ];
    return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false, $cache);
}

/** The Settings page as it renders, so an assertion is about what an operator sees. */
function lh_sc_html(Config $cfg, ?Cache $cache = null): string
{
    $view = new Settings($cfg, lh_sc_gateway($cfg, $cache));
    ob_start();
    try {
        $view->body();
    } finally {
        $html = (string) ob_get_clean();
    }
    return $html;
}

/** One card out of that page, by the id it was opened with. */
function lh_sc_card(string $html, string $id): string
{
    $at = strpos($html, '<section class="card" id="' . $id . '-card"');
    if ($at === false) {
        lh_fail('the settings page has no ' . $id . ' card');
    }
    $next = strpos($html, '<section class="card"', $at + 10);
    return $next === false ? substr($html, $at) : substr($html, $at, $next - $at);
}

/** A cache over the stand-in, with the hits a test needs already accounted for. */
function lh_sc_cache(bool $sized, bool $unsized): Cache
{
    $cache = Cache::withClient(new LhSettingsFakeMc(), 7200, 'lh_sc_' . bin2hex(random_bytes(4)));

    if ($sized) {
        $key = $cache->key('sized', 'core', ['q' => '*:*']);
        $cache->put($key, ['rows' => 1], null, 40960);
        $cache->get($key);
    }
    if ($unsized) {
        $key = $cache->key('unsized', 'core', ['q' => 'other']);
        $cache->put($key, ['rows' => 1], null, 0);
        $cache->get($key);
    }

    return $cache;
}

return [

    /* ----------------------------------------------------------------- the section itself */

    'the cached-queries section is registered in SECTIONS, where its number comes from' =>
        function (): void {
            $cfg = lh_sc_config();
            $view = new Settings($cfg, lh_sc_gateway($cfg));

            $ids = array_column($view->sections(), 0);
            lh_true(in_array('set-cache', $ids, true), 'the section list has to carry the card');

            // Numbering is positional, so a card rendered without a row here would print no
            // number at all and the jump bar would not reach it.
            $solr = array_search('set-solr', $ids, true);
            $cache = array_search('set-cache', $ids, true);
            lh_same($solr + 1, $cache, 'caching reads from Solr, so it is the card after the connection');

            $html = lh_sc_html($cfg);
            lh_contains(lh_sc_card($html, 'set-cache'), 'Cached queries', 'the card renders');
            lh_contains(
                lh_sc_card($html, 'set-cache'),
                '<span class="card-num">' . Layout::cardNum($view->sections(), 'set-cache') . '</span>',
                'the number on the card is the one the list gives it'
            );
        },

    /* ------------------------------------------------------- configured versus working */

    'a cache that is off says so as a choice, not as a fault' =>
        function (): void {
            $card = lh_sc_card(lh_sc_html(lh_sc_config(['cache.enabled' => false])), 'set-cache');

            lh_contains($card, 'chip-good">Off<', 'off is the shipped default and is supported');
            lh_contains($card, 'shipped default', 'and the card says so rather than implying a problem');
            lh_false(
                str_contains($card, 'chip-warn'),
                'an installation that chose not to cache must not be told something needs attention'
            );
        },

    'a cache that is on and answering reports the driver, the server and the duration' =>
        function (): void {
            $cfg = lh_sc_config(['cache.enabled' => true, 'cache.ttl_seconds' => 600]);
            $card = lh_sc_card(lh_sc_html($cfg, lh_sc_cache(false, false)), 'set-cache');

            lh_contains($card, 'chip-good">On<', 'on and working is a pass');
            lh_contains($card, 'Answers are being kept and re-served', 'in words, not in a state name');
        },

    'a cache that is on and NOT answering is its own state, and never reads as off' =>
        function (): void {
            $cfg = lh_sc_config(['cache.enabled' => true, 'cache.server' => '127.0.0.1:1']);
            // Built from the configuration rather than injected, because "asked for and not
            // reachable" is a state only a real Cache::fromConfig() can be in.
            $card = lh_sc_card(lh_sc_html($cfg, Cache::fromConfig($cfg)), 'set-cache');

            lh_contains($card, 'On, and not answering', 'the two facts are reported separately');
            lh_contains($card, 'chip-warn', 'because this one IS a fault and the card must open on it');
            lh_contains($card, 'memcached is running', 'and it says what to go and look at');
            lh_false(
                str_contains($card, 'chip-good">Off<'),
                'reporting an unreachable cache as "off" is the defect this split exists to prevent'
            );
        },

    /* --------------------------------------------------------------------- the duration */

    'the duration field advertises the cache\'s own bounds and its own default' =>
        function (): void {
            $card = lh_sc_card(lh_sc_html(lh_sc_config()), 'set-cache');

            lh_contains($card, 'min="' . Cache::TTL_MIN . '"', 'the floor is the cache\'s, not a literal');
            lh_contains($card, 'max="' . Cache::TTL_MAX . '"', 'and so is the ceiling');
            lh_contains($card, 'value="' . Cache::TTL_DEFAULT . '"', 'an unset duration shows the default');

            // The shipped defaults the card's wording depends on. If any of these three move,
            // the sentence beside the field is wrong and this is what says so.
            lh_same(7200, Cache::TTL_DEFAULT, 'the default duration');
            lh_same(60, Cache::TTL_MIN, 'the shortest duration');
            lh_same(86400, Cache::TTL_MAX, 'the longest duration');
            lh_same(false, Config::load('/nonexistent-loghound-config')->get('cache.enabled'), 'ships off');
        },

    'a duration outside the bounds is brought back inside them by the cache\'s own function' =>
        function (): void {
            lh_same(Cache::TTL_MAX, Cache::clampTtl(999999), 'above the ceiling');
            lh_same(Cache::TTL_MIN, Cache::clampTtl(1), 'below the floor');
            lh_same(Cache::TTL_DEFAULT, Cache::clampTtl('not a number'), 'and nonsense is the default');

            // The point is that the form does not have its own opinion: it posts the number and
            // the SAME call the cache makes decides what it becomes.
            $code = (string) preg_replace(
                '#/\*.*?\*/#s',
                '',
                (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php')
            );
            lh_contains($code, 'Cache::clampTtl($_POST[\'cache_ttl_seconds\']', 'the handler clamps through Cache');
        },

    /* ----------------------------------------------------------------------- the saving */

    'a measured saving is printed, and printed as an approximation' =>
        function (): void {
            $cfg = lh_sc_config(['cache.enabled' => true]);
            $card = lh_sc_card(lh_sc_html($cfg, lh_sc_cache(true, false)), 'set-cache');

            lh_contains($card, 'approximately', 'TLS framing is not counted, so it is never a total');
            lh_contains($card, 'not fetched', 'and it says what the number is a saving of');
        },

    'a saving that is only a floor is left out rather than hedged' =>
        function (): void {
            $cfg = lh_sc_config(['cache.enabled' => true]);
            $card = lh_sc_card(lh_sc_html($cfg, lh_sc_cache(true, true)), 'set-cache');

            lh_false(
                str_contains($card, 'without going to Solr'),
                'one hit from an entry with no recorded size understates the whole figure, and an '
                . 'understated figure presented as a saving is a wrong number'
            );
        },

    'a cache that has answered nothing yet claims nothing' =>
        function (): void {
            $cfg = lh_sc_config(['cache.enabled' => true]);
            $card = lh_sc_card(lh_sc_html($cfg, lh_sc_cache(false, false)), 'set-cache');

            lh_false(str_contains($card, 'without going to Solr'), 'there is no saving to report yet');
        },

    /* -------------------------------------------------------------------- the Clear copy */

    'the Clear cache sentence names exactly the views that honour SCOPE_CACHE' =>
        function (): void {
            $cfg = lh_sc_config();
            $gw = lh_sc_gateway($cfg);
            $card = lh_sc_card(lh_sc_html($cfg), 'set-cache');

            // Derived from the views themselves rather than from a second list, so a view that
            // changes its mind about caching fails this instead of quietly making the prose
            // wrong. The names are the ones in the navigation, which is what the reader has on
            // screen while they read the sentence.
            $named = [];
            foreach (glob(dirname(__DIR__) . '/src/Panel/*.php') as $file) {
                $class = 'Loghound\\Panel\\' . basename($file, '.php');
                if (!class_exists($class) || !is_subclass_of($class, Controller::class)) {
                    continue;
                }
                $reflect = new ReflectionClass($class);
                if ($reflect->isAbstract()) {
                    continue;
                }
                /** @var Controller $view */
                $view = new $class($cfg, $gw);
                $named[$view->slug()] = $view->honours(Controller::SCOPE_CACHE);
            }

            $labels = [];
            foreach (Layout::nav() as $item) {
                $labels[$item['slug']] = $item['label'];
            }

            // The sentence has two halves and a view belongs in exactly one of them, so
            // "is the name in the sentence" is not the question — "is it on the right side of
            // the word that separates them" is.
            // Decoded first: a nav label may contain an ampersand ("Storage & bandwidth"), and
            // comparing a label against its own escaped form is a test of the escaper.
            $text = html_entity_decode($card, ENT_QUOTES, 'UTF-8');
            $split = strpos($text, 'deliberately not on');
            lh_true($split !== false, 'the sentence has to say which pages do NOT carry the control');
            $carries = substr($text, 0, $split);
            $does_not = substr($text, $split);

            foreach ($named as $slug => $cached) {
                $label = $labels[$slug] ?? null;
                if ($label === null) {
                    continue;
                }
                $spoken = $slug === 'sessions' ? 'Session explorer' : $label;
                lh_same(
                    $cached,
                    str_contains($carries, $spoken),
                    $spoken . ': named among the pages that carry Clear cache exactly when it reads cached data'
                );
                lh_same(
                    !$cached,
                    str_contains($does_not, $spoken),
                    $spoken . ': named among the pages that do not carry it exactly when it reads none'
                );
            }
        },

    'the bandwidth paragraph says why reads are what the plan is billed for' =>
        function (): void {
            $card = lh_sc_card(lh_sc_html(lh_sc_config()), 'set-cache');

            foreach ([
                'Opensolr meters outgoing traffic',
                'not writes',
                'ingestion costs almost nothing',
                'a facet response over a large index is not small',
            ] as $phrase) {
                lh_contains($card, $phrase, 'the operator is told what the cache is actually saving');
            }
        },

    /* --------------------------------------------------- Ingest this log, on the sources */

    'every configured source carries an ingest switch, ticked unless it was turned off' =>
        function (): void {
            $cfg = lh_sc_config([
                'base_url' => 'https://logs.example.com',
                'sources'  => [
                    ['path' => '/var/log/a-access.log', 'format' => 'combined',
                     'host' => 'a.example.com', 'confirmed' => true],
                    ['path' => '/var/log/b-access.log', 'format' => 'combined',
                     'host' => 'b.example.com', 'confirmed' => true, 'enabled' => false],
                ],
            ]);
            $card = lh_sc_card(lh_sc_html($cfg), 'set-sources');

            lh_same(2, substr_count($card, 'name="source_enabled"'), 'one switch per configured source');
            lh_same(2, substr_count($card, 'Ingest this log'), 'and each one is labelled');
            lh_same(1, substr_count($card, 'name="source_enabled" checked'), 'absent means enabled; false means not');
            lh_same(1, substr_count($card, 'chip-off">Not ingested<'), 'and the one that is off says so');
            lh_contains($card, 'source-off', 'the row that is off is rendered as a row that is off');
        },

    'a source that is not ingested stays listed, because it is a decision and not a deletion' =>
        function (): void {
            $cfg = lh_sc_config([
                'sources' => [
                    ['path' => '/var/log/quiet-access.log', 'format' => 'combined',
                     'host' => 'quiet.example.com', 'confirmed' => true, 'enabled' => false],
                ],
            ]);
            $card = lh_sc_card(lh_sc_html($cfg), 'set-sources');

            lh_contains($card, '/var/log/quiet-access.log', 'the file is still on the card');
            lh_contains($card, 'action" value="remove_source', 'and removing it is still a separate action');
            lh_same(
                1,
                count((array) $cfg->get('sources')),
                'rendering the card must not take the source out of the configuration'
            );
        },

    'absent means enabled, so nothing written before this existed changes behaviour' =>
        function (): void {
            lh_true(Config::sourceEnabled(['path' => '/x']), 'no key at all');
            lh_true(Config::sourceEnabled(['path' => '/x', 'enabled' => true]), 'true');
            lh_false(Config::sourceEnabled(['path' => '/x', 'enabled' => false]), 'false');
            lh_false(Config::sourceEnabled(['path' => '/x', 'enabled' => 'no']), 'a hand-edited no');
            lh_false(Config::sourceEnabled(['path' => '/x', 'enabled' => '0']), 'a form post of 0');

            // Unreadable is NOT taken as off: validate() refuses it, so a typo is an error the
            // operator sees rather than a source that silently stopped being read.
            lh_true(Config::sourceEnabled(['path' => '/x', 'enabled' => 'maybe']), 'unreadable is not off');
        },

    'the panel\'s own site is named as such, and only where that is true' =>
        function (): void {
            $shared = [
                'base_url' => 'https://logs.example.com',
                'sources'  => [
                    ['path' => '/var/log/own-access.log', 'format' => 'combined',
                     'host' => 'logs.example.com', 'confirmed' => true],
                    ['path' => '/var/log/other-access.log', 'format' => 'combined',
                     'host' => 'shop.example.com', 'confirmed' => true],
                ],
            ];
            $card = lh_sc_card(lh_sc_html(lh_sc_config($shared)), 'set-sources');

            lh_same(
                1,
                substr_count($card, 'This is Loghound&rsquo;s own site'),
                'the note belongs to the panel\'s own vhost and to no other row'
            );
            lh_contains($card, 'keep your own visits out of the data', 'and it says what turning it off buys');

            // NOT a claim about the beacon. Loghound's own script and collector are excluded
            // automatically, on host AND path, so a measured site's own /collect.php is
            // untouched — saying this toggle is needed to stop double-counting would be false.
            lh_false(str_contains($card, 'double'), 'the note must not imply the beacon is counted twice');

            $away = $shared;
            $away['base_url'] = 'https://panel.elsewhere.example';
            lh_false(
                str_contains(lh_sc_card(lh_sc_html(lh_sc_config($away)), 'set-sources'), 'own site'),
                'an installation whose panel is on a host it does not ingest gets no such note'
            );
        },
];
