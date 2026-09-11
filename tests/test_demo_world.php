<?php
/**
 * Loghound — tests for the synthetic world the panel runs on in demo mode.
 *
 * Demo mode exists so that `git clone` plus a webserver gives a working dashboard before
 * Solr is provisioned — for screenshots, for offline demos, and so a front-end change can be
 * verified with no backend. That only holds if the fabricated documents satisfy the same
 * contract the real schema states, and two clauses of it had drifted:
 *
 *  - Every panel query against the sessions core carries `doc_type_s:session`, because that
 *    core also holds the daily rollups. The demo documents declared no type at all, so they
 *    matched none of those filters and the whole dashboard rendered empty.
 *  - `host_s` was never emitted, so the Virtual hosts view — whose entire job is to compare
 *    the sites on a machine — showed its "no virtual host recorded" state, which is the
 *    answer for an operator on plain `combined`, not for a demo.
 *
 * The distribution is asserted, not just the presence of the field: a comparison view needs
 * something to compare, and three hosts with the same bot share teaches nothing.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Panel\Fixtures;
use Loghound\Panel\Query;

/**
 * The host comparison exactly as Panel\Hosts::compare() asks for it.
 *
 * Built here rather than by calling the view so that the fixture world is what is under
 * test: the view is a thin wrapper over this request and has its own tests.
 *
 * @return array<string,array<string,mixed>> host => bucket
 */
function lh_demo_host_rows(): array
{
    $nested = ['bytes' => 'sum(bytes_l)', 'hits' => 'sum(hits_i)', 'pages' => 'sum(pages_i)'];
    foreach (Query::populations() as $key => $filter) {
        $nested[$key] = ['type' => 'query', 'q' => $filter];
    }

    $f = Fixtures::facet('hosts.compare', [
        'q'  => '*:*',
        'fq' => [Query::SESSION_DOCS],
    ], [
        'hosts' => [
            'type'     => 'terms',
            'field'    => Query::HOST_FIELD,
            'limit'    => 50,
            'mincount' => 1,
            'sort'     => 'count desc',
            'facet'    => $nested,
        ],
    ]);

    $rows = [];
    foreach ((array) ($f['hosts']['buckets'] ?? []) as $bucket) {
        $rows[(string) $bucket['val']] = $bucket;
    }
    return $rows;
}

/** The evasive-bot share of one comparison row, as a percentage. */
function lh_demo_evasive_share(array $bucket): float
{
    $sessions = (int) $bucket['count'];
    return $sessions > 0 ? ((int) $bucket['evasive']['count'] / $sessions) * 100 : 0.0;
}

return [

    'a demo session document declares its type, or every panel query drops it'
        => static function (): void {
            $all = Fixtures::facet('sessions.probe', ['q' => '*:*', 'fq' => []], []);
            $typed = Fixtures::facet('sessions.probe', ['q' => '*:*', 'fq' => [Query::SESSION_DOCS]], []);

            lh_true((int) $all['count'] > 0, 'the demo world has sessions');
            lh_same(
                (int) $all['count'],
                (int) $typed['count'],
                'every sessions-core query the panel issues carries doc_type_s:session, so a demo '
                . 'document without one empties the entire dashboard'
            );
        },

    'the demo serves more than one virtual host' => static function (): void {
        $rows = lh_demo_host_rows();

        lh_true(
            count($rows) >= 3,
            'the Virtual hosts view is a comparison and needs something to compare; got '
            . count($rows) . ' host(s)'
        );
    },

    'one demo host is clearly busier than the others' => static function (): void {
        $rows = lh_demo_host_rows();
        $counts = array_map(static fn (array $b): int => (int) $b['count'], $rows);
        arsort($counts);
        $ordered = array_values($counts);

        lh_true(
            $ordered[0] > $ordered[1] * 1.5,
            'the busy site must be obviously the busy site: ' . json_encode($counts)
        );
        lh_true($ordered[count($ordered) - 1] > 0, 'and no host is an empty row');
    },

    'bot pressure differs enough between demo hosts to be worth looking at'
        => static function (): void {
            $rows = lh_demo_host_rows();
            $shares = [];
            foreach ($rows as $host => $bucket) {
                $shares[$host] = round(lh_demo_evasive_share($bucket), 1);
            }
            arsort($shares);
            $ordered = array_values($shares);

            lh_true(
                $ordered[0] >= $ordered[count($ordered) - 1] + 25,
                'the evasive-bot share is the column an operator scans, so the demo has to show a '
                . 'real difference across it: ' . json_encode($shares)
            );
            lh_true($ordered[0] < 100.0, 'and no host is fabricated as pure bot traffic');
        },

    'the five populations still add up to each host row total' => static function (): void {
        foreach (lh_demo_host_rows() as $host => $bucket) {
            $sum = 0;
            foreach (array_keys(Query::populations()) as $key) {
                $sum += (int) $bucket[$key]['count'];
            }
            lh_same(
                (int) $bucket['count'],
                $sum,
                'the populations are mutually exclusive and exhaustive, so the row for ' . $host
                . ' must sum to its own total'
            );
        }
    },

    'the host selector finds the same hosts the comparison does' => static function (): void {
        $f = Fixtures::facet('hosts.list', [
            'q'  => '*:*',
            'fq' => [],
        ], Query::hostFacet(50));

        $listed = [];
        foreach ((array) ($f['hosts']['buckets'] ?? []) as $bucket) {
            $listed[] = (string) $bucket['val'];
        }
        sort($listed);

        $compared = array_keys(lh_demo_host_rows());
        sort($compared);

        lh_same($compared, $listed, 'the selector and the table must describe the same machine');
    },

    'every demo hit names the host its session arrived on' => static function (): void {
        $hosts = [];
        foreach (lh_demo_host_rows() as $host => $bucket) {
            $hosts[$host] = true;
        }

        $page = Fixtures::select('perf.hits', ['q' => '*:*', 'rows' => 500]);
        lh_true($page['numFound'] > 0, 'the demo world has hits');

        foreach ($page['docs'] as $i => $hit) {
            lh_has_key($hit, Query::HOST_FIELD, 'hit ' . $i);
            lh_true(
                isset($hosts[(string) $hit[Query::HOST_FIELD]]),
                'the virtual-host selector scopes the hits core too, so a hit naming a host the '
                . 'sessions do not would empty the Performance view: ' . (string) $hit[Query::HOST_FIELD]
            );
        }
    },

    'the demo world is still byte-identical on every build' => static function (): void {
        $first = lh_demo_host_rows();
        $second = lh_demo_host_rows();

        lh_same(
            array_map(static fn (array $b): int => (int) $b['count'], $first),
            array_map(static fn (array $b): int => (int) $b['count'], $second),
            'screenshots are reproducible only while the seeded world is'
        );
    },

    'the detection fixture names a host the traffic actually uses' => static function (): void {
        $report = Fixtures::detection();
        $vhost = (string) ($report['sources'][0]['vhost'] ?? '');

        lh_true($vhost !== '', 'the demo detection report names a virtual host');
        lh_has_key(
            lh_demo_host_rows(),
            $vhost,
            'the log source on the Settings page and the traffic on the dashboard have to be the '
            . 'same story, or the demo teaches two different machines'
        );
    },
];
