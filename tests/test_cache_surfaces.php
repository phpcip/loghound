<?php
/**
 * Loghound — the query cache is visible wherever it changes what a reader sees.
 *
 * The cache itself is tested elsewhere. What these tests are about is the three places an
 * operator meets it, and the one rule they share: **a state the product is in must be
 * legible from where the operator is standing, and must never be reported as a different
 * state that happens to look similar.**
 *
 *  1. The system check separates "off" from "on but unreachable". Those look identical from
 *     a row that prints only a verdict and they need opposite actions — one is a choice, the
 *     other is a fault — and collapsing them is how somebody spends an afternoon wondering
 *     why an installation they switched the cache on for is still slow.
 *  2. The Clear cache control appears only where a Solr read is actually cached, so pressing
 *     it can never discard nothing while saying it had. That rule is pinned in
 *     tests/test_page_toolbar.php; what is pinned here is that it is never offered at all
 *     when the cache is off or not answering.
 *  3. The indexes-not-chosen banner, which is the same principle one step along: an account
 *     saved without indexes made every view answer "a service this panel depends on is not
 *     answering", which is true of the symptom and silent about the cause.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Cache;
use Loghound\Config;
use Loghound\Setup\Pairs;
use Loghound\Setup\Requirements;

/** The cache row out of a full requirements run, or null if it is not there. */
function lh_cs_row(Config $cfg): ?array
{
    foreach ((new Requirements(dirname(__DIR__), $cfg))->all() as $row) {
        if (($row['id'] ?? '') === 'cache') {
            return $row;
        }
    }

    return null;
}

/** A config carrying just enough to construct the pieces under test. */
function lh_cs_cfg(array $over = []): Config
{
    $dir = lh_tmpdir('lh_cachesurf');
    mkdir($dir . '/config', 0o755, true);

    $cfg = Config::load($dir . '/config/loghound.php');
    foreach ($over as $k => $v) {
        $cfg->set($k, $v);
    }

    return $cfg;
}

return [

    /* ------------------------------------------------------------- the system check */

    'the system check reports the cache at all' => function (): void {
        $row = lh_cs_row(lh_cs_cfg());
        lh_true($row !== null, 'Requirements::all() must carry a cache row');
        lh_same('Query cache', $row['label'], 'the row is named for what it is');
    },

    'a cache that is off is a pass, because off is the default and is supported' => function (): void {
        $row = lh_cs_row(lh_cs_cfg(['cache.enabled' => false]));

        lh_same('pass', $row['state'], 'the panel is entirely correct with no cache');
        lh_contains($row['detail'], 'Off', 'and it says so');
        lh_same([], $row['fix'], 'there is nothing to fix about a supported default');
    },

    'a cache asked for and not answering is a warn, never a fail' => function (): void {
        $row = lh_cs_row(lh_cs_cfg([
            'cache.enabled' => true,
            'cache.server'  => '127.0.0.1:1',
        ]));

        lh_same(
            'warn',
            $row['state'],
            'an unreachable cache must never block an installation: every answer is simply fetched '
                . 'from Solr instead, so nothing is broken'
        );
        lh_true($row['fix'] !== [], 'a fault comes with the command that fixes it');
    },

    'off and unreachable are different rows, not one verdict' => function (): void {
        $off = lh_cs_row(lh_cs_cfg(['cache.enabled' => false]));
        $bad = lh_cs_row(lh_cs_cfg(['cache.enabled' => true, 'cache.server' => '127.0.0.1:1']));

        lh_true(
            $off['state'] !== $bad['state'] || $off['detail'] !== $bad['detail'],
            'Cache::status() reports configured and working separately precisely so these two can be '
                . 'told apart. A row that renders them the same throws that away and sends half the '
                . 'operators who read it to the wrong place.'
        );
    },

    /* ----------------------------------------------------- the bounds the form must use */

    'the form and the cache agree about what a duration may be' => function (): void {
        lh_same(Cache::TTL_MIN, Cache::clampTtl(1), 'below the floor clamps up');
        lh_same(Cache::TTL_MAX, Cache::clampTtl(999999999), 'above the ceiling clamps down');
        lh_same(Cache::TTL_DEFAULT, Cache::clampTtl('not a number'), 'nonsense falls back to the default');
        lh_same(3600, Cache::clampTtl(3600), 'a value in range is kept');

        lh_true(Cache::TTL_MIN < Cache::TTL_MAX, 'the bounds are the right way round');
    },

    /* ----------------------------------------------------- the control, when there is none */

    'the Clear cache control is withheld entirely when there is nothing to clear' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');

        lh_contains(
            $src,
            "empty(\$cache['enabled'])",
            'a cache that is off or not answering must not advertise a button that would do nothing'
        );

        $pos = strpos($src, 'name="clear_cache"');
        $gate = strpos($src, "empty(\$cache['enabled'])");
        lh_true(
            $gate !== false && $pos !== false && $gate < $pos,
            'the gate must come before the control it guards'
        );
    },

    /* ------------------------------------------------ indexes chosen, or honestly not yet */

    'the panel says indexes have not been chosen rather than blaming a service' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');

        lh_contains(
            $src,
            'Pairs::isPending($cfg)',
            'Layout::banners() must report the interim state. Without it the only thing the panel said '
                . 'was "A service this panel depends on is not answering", on every view, which names '
                . 'the symptom and hides the cause.'
        );
        lh_contains($src, 'Pairs::pendingHeadline()', 'the headline comes from the one place that owns it');
        lh_contains($src, 'Pairs::pendingDetail($cfg)', 'and so does the detail');
        lh_contains($src, '#set-solr', 'the banner must lead to the list that resolves it');
    },

    'the pending banner is free of a control-plane call' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Pairs.php');

        $start = strpos($src, 'function isPending');
        lh_true($start !== false, 'isPending exists');

        $body = substr($src, $start, 700);
        foreach (['listIndexes', 'account(', 'curl', 'file_get_contents'] as $forbidden) {
            lh_false(
                str_contains($body, $forbidden),
                'isPending() is read on every page of the panel and must answer from the recorded '
                    . 'verdict alone; it must never reach the network. Found: ' . $forbidden
            );
        }
    },

    'the generated pending key is documented in the shipped example' => function (): void {
        $example = (string) file_get_contents(dirname(__DIR__) . '/config/loghound.example.php');

        lh_contains(
            $example,
            'pair_pending',
            'a key Loghound writes into an operator\'s configuration has to be explained there, or the '
                . 'first time they read the file they find a value nothing accounts for'
        );
    },
];
