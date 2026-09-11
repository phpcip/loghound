<?php
/**
 * Loghound — the page toolbar shows only controls the view honours.
 *
 * THE DEFECT. The range picker, the host selector and the "Filter by" bar were rendered on
 * every view: Layout emitted the six range links unconditionally, and app.js injected the other
 * two whatever the page underneath them did. On Settings that was four controls of which not
 * one had any effect — the only Solr query on that page is deliberately pinned to thirty days,
 * and no card on it reads a facet or a host — so pressing 7D changed nothing and said nothing.
 * Storage & bandwidth had the same picker and the same silence.
 *
 * THE RULE THESE TESTS ENFORCE. A view declares what scopes it, in Controller::toolbar(), and
 * the toolbar is rendered from that declaration and nothing else. Clear cache joined the three
 * later under the same rule, for the same reason: it is offered only where a Solr read is
 * actually cached, so it cannot sit on a page where pressing it would discard nothing. The declaration is a CLAIM
 * about the view's own queries, so these tests check the claim against the source rather than
 * taking it: a view that says it honours the range must bound its queries by the selected
 * range, and one that says it honours the host or the facets must put the facet filters into
 * its `fq`.
 *
 * And the reverse, which is the half that made this reach the owner: a view that does NOT
 * declare a control must not be reachable by it either — nothing may quietly keep working
 * through a control the page does not show.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Panel\Controller;

/**
 * Every concrete view class in the panel, discovered rather than listed.
 *
 * By glob, so a view added later is covered without anybody remembering to register it here —
 * which is the whole point: the defect was a control inherited by a page that never considered
 * it, and a hand-kept list would have the same blind spot.
 *
 * @return array<string,string> short name => fully qualified class
 */
function lh_tb_views(): array
{
    $out = [];
    foreach (glob(dirname(__DIR__) . '/src/Panel/*.php') ?: [] as $file) {
        $short = basename($file, '.php');
        $class = 'Loghound\\Panel\\' . $short;
        if (!class_exists($class)) {
            continue;
        }
        $ref = new \ReflectionClass($class);
        if ($ref->isAbstract() || !$ref->isSubclassOf(Controller::class)) {
            continue;
        }
        $out[$short] = $class;
    }
    ksort($out);

    return $out;
}

/** The source of one view class. */
function lh_tb_source(string $short): string
{
    return (string) file_get_contents(dirname(__DIR__) . '/src/Panel/' . $short . '.php');
}

/** The toolbar a view declares, without constructing it. */
function lh_tb_declared(string $class): array
{
    $ref = new \ReflectionClass($class);

    return (array) $ref->newInstanceWithoutConstructor()->toolbar();
}

return [

    /* ------------------------------------------------------- every view has an opinion */

    'every view declares its own toolbar rather than inheriting one' => function (): void {
        $views = lh_tb_views();
        lh_true(count($views) >= 12, 'the glob found the views, got ' . count($views));

        foreach ($views as $short => $class) {
            $declaring = (new \ReflectionClass($class))->getMethod('toolbar')->getDeclaringClass()->getShortName();
            lh_same(
                $short,
                $declaring,
                $short . ' does not declare toolbar() and would inherit Controller\'s default. Every view '
                    . 'must say which of the range picker, the host selector and the filter bar its own '
                    . 'queries honour — that is what stops a new view showing a control it ignores.'
            );
        }
    },

    'a declared control is one of the four that exist' => function (): void {
        $known = [Controller::SCOPE_RANGE, Controller::SCOPE_HOST, Controller::SCOPE_FACETS, Controller::SCOPE_CACHE];

        foreach (lh_tb_views() as $short => $class) {
            foreach (lh_tb_declared($class) as $control) {
                lh_true(
                    in_array($control, $known, true),
                    $short . ' declares the unknown toolbar control ' . lh_show($control)
                );
            }
        }
    },

    /* ------------------------------------- the declaration is checked against the code */

    'a view that claims the range actually bounds its queries by it' => function (): void {
        foreach (lh_tb_views() as $short => $class) {
            if (!in_array(Controller::SCOPE_RANGE, lh_tb_declared($class), true)) {
                continue;
            }
            $src = lh_tb_source($short);
            lh_true(
                str_contains($src, '$this->range')
                    || str_contains($src, 'sessionFqs()')
                    || str_contains($src, 'settledSessionFqs()')
                    || str_contains($src, 'hitFqs()')
                    || str_contains($src, 'logFqs()'),
                $short . ' declares that the time range scopes it, but its source never reads $this->range '
                    . 'and never calls a filter builder that injects it. Either the claim is wrong and the '
                    . 'picker should not be offered, or the queries are missing the bound.'
            );
        }
    },

    'a view that claims the host or the facets actually passes the filters in' => function (): void {
        foreach (lh_tb_views() as $short => $class) {
            $declared = lh_tb_declared($class);
            if (!in_array(Controller::SCOPE_HOST, $declared, true)
                && !in_array(Controller::SCOPE_FACETS, $declared, true)
            ) {
                continue;
            }
            $src = lh_tb_source($short);
            lh_true(
                str_contains($src, 'sessionFqs()')
                    || str_contains($src, 'settledSessionFqs()')
                    || str_contains($src, 'hitFqs()')
                    || str_contains($src, 'facets->fqs(')
                    || str_contains($src, 'fqsWithoutHost()'),
                $short . ' declares that the host selector or the filter bar scopes it, but nothing in its '
                    . 'source puts the facet filters into an fq. A chip that changes no number is exactly '
                    . 'the lie this declaration exists to prevent.'
            );
        }
    },

    /* --------------------------------- the two views the owner reported, pinned by name */

    'Settings offers no toolbar control at all' => function (): void {
        $declared = lh_tb_declared('Loghound\\Panel\\Settings');
        lh_same(
            [],
            $declared,
            'Settings is scoped by nothing: its one Solr query is pinned to thirty days on purpose, and no '
                . 'card on it reads a facet or a host. It must therefore offer no range picker, no host '
                . 'selector and no filter bar.'
        );

        $src = lh_tb_source('Settings');
        lh_false(
            str_contains($src, '$this->range') || str_contains($src, 'sessionFqs()') || str_contains($src, 'hitFqs()'),
            'Settings has grown a range-scoped or filter-scoped query. If that is deliberate, it must now '
                . 'declare the control so the reader gets one.'
        );
    },

    'Storage and bandwidth is scoped by nothing the reader can filter with' => function (): void {
        $declared = lh_tb_declared('Loghound\\Panel\\Usage');

        foreach ([Controller::SCOPE_RANGE, Controller::SCOPE_HOST, Controller::SCOPE_FACETS] as $control) {
            lh_false(
                in_array($control, $declared, true),
                'Usage answers how far back the data goes and what the plan allows. Neither is a question '
                    . 'about a time window, a host or a filter, so it offers none of the three.'
            );
        }

        /* It DOES read Solr, so the cache control belongs to it. That is a different kind of
           entry from the other three: they say what narrows the numbers, this says the numbers
           can be recomputed. Both are "does pressing this do anything on this page", which is
           the one question the declaration answers. */
        lh_true(
            in_array(Controller::SCOPE_CACHE, $declared, true),
            'Usage reads Solr, so clearing the cache changes what it shows'
        );
    },

    'the cache control is offered only where a Solr read is actually cached' => function (): void {
        foreach (['Overview', 'Bots', 'Fingerprints', 'Networks', 'Sessions', 'Performance', 'Hosts', 'Callers', 'Usage'] as $short) {
            lh_true(
                in_array(Controller::SCOPE_CACHE, lh_tb_declared('Loghound\\Panel\\' . $short), true),
                $short . ' reads Solr, so Clear cache refreshes it and belongs on it'
            );
        }

        foreach (['Indexes', 'Queries', 'Settings'] as $short) {
            lh_false(
                in_array(Controller::SCOPE_CACHE, lh_tb_declared('Loghound\\Panel\\' . $short), true),
                $short . ' must not offer Clear cache. Index analytics and Query analysis read the Opensolr '
                    . 'request log, which is not cached, and Settings makes no cached read at all — so the '
                    . 'button would discard nothing while saying it had.'
            );
        }
    },

    'the Clear cache control is a CSRF-protected POST, never a link' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');

        lh_contains($src, 'name="clear_cache"', 'the control exists');
        lh_contains($src, "honours(Controller::SCOPE_CACHE)", 'and is gated on the declaration');
        lh_contains($src, "empty(\$cache['enabled'])", 'and on the cache actually working');
        lh_contains($src, 'Security::csrfToken()', 'clearing state needs a token');
        lh_contains($src, "<form method=\"post\"", 'clearing state is a POST');

        lh_false(
            (bool) preg_match('~<a[^>]+clear_cache~', $src),
            'a GET route would let any page on the internet empty the operator\'s cache with an <img> tag'
        );
    },

    'the Opensolr-plane views keep the range and drop the two that cannot reach them' => function (): void {
        foreach (['Indexes', 'Queries', 'Callers'] as $short) {
            $declared = lh_tb_declared('Loghound\\Panel\\' . $short);

            lh_true(
                in_array(Controller::SCOPE_RANGE, $declared, true),
                $short . ' reads the Opensolr request log through a date filter built from the selected '
                    . 'range, so the picker belongs on it'
            );
            lh_false(
                in_array(Controller::SCOPE_HOST, $declared, true),
                $short . ' must not offer the host selector: f[host_s][] is read by the Loghound sessions '
                    . 'plane and has no effect on the Opensolr request log'
            );
            lh_false(
                in_array(Controller::SCOPE_FACETS, $declared, true),
                $short . ' must not offer the f[...] filter bar: it filters a plane this view does not read. '
                    . 'It has its own lf[...] chips instead.'
            );
        }
    },

    /* ------------------------------------------------------------- the rendering side */

    'Layout renders the range picker only when the view honours it' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');

        lh_contains(
            $src,
            'honours(Controller::SCOPE_RANGE)',
            'Layout::header() must ask the view before emitting the range picker'
        );
    },

    'the declaration reaches the browser, because two controls are injected there' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/public/index.php');
        lh_contains(
            $src,
            "'toolbar' => \$view->toolbar()",
            'the boot payload must carry the declaration; the host selector and the filter bar are '
                . 'injected by JavaScript and cannot see the PHP decision otherwise'
        );

        $app = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/app.js');
        lh_contains($app, "honours('facets')", 'app.js gates the filter bar on the declaration');

        $hosts = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/hosts.js');
        lh_contains($hosts, 'scopedByHost()', 'the host selector is gated on the declaration');
        lh_contains(
            $hosts,
            'noteHosts(',
            'the host LIST must still be fetched on every view even where the selector is not drawn, '
                . 'because url.js needs it to know whether this installation serves one site or several'
        );
    },

    'the bandwidth readout is not inside the row of controls' => function (): void {
        $usage = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/usage.js');
        lh_contains($usage, "byId('lh-readout')", 'the strip mounts in its own slot');
        lh_false(
            str_contains($usage, "querySelector('.head-tools')"),
            'the bandwidth strip is a readout, not a control, and must not be injected into .head-tools '
                . 'beside the range links'
        );

        $layout = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');
        lh_contains($layout, 'id="lh-readout"', 'Layout provides the readout slot');
    },

    /* ------------------------------------------------------------- state is not lost */

    'the range and the filters survive a navigation between views' => function (): void {
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Layout.php');

        lh_contains(
            $src,
            "self::urlWith(['v' => \$item['slug']])",
            'the sidebar must build its links through urlWith(). Bare ?v=<slug> links threw away the time '
                . 'range and every filter on every navigation — which matters more now that a view without '
                . 'a picker has nowhere to show the choice while the reader is on it.'
        );

        lh_contains(
            $src,
            "isset(Query::ranges()[\$range])",
            'urlWith() must carry the selected range, validated against the table'
        );
    },
];
