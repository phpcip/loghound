<?php
/**
 * Loghound — Who is querying your index.
 *
 * THIS IS THE PAGE THAT JUSTIFIES THE WHOLE SECTION. Everything else here could, in
 * principle, be built by anyone with an Opensolr account. This cannot, because it needs
 * both planes at once.
 *
 * Loghound already classifies every address it sees in a web log: bot or human, which
 * network, which fingerprint cluster. Opensolr already records every address that queried
 * a search index. Cross-reference the two and two questions get answers that neither side
 * can produce alone:
 *
 *  1. **How much of the search backend's work is being done for traffic already classified
 *     as a bot?** It is cheap to compute and it turns an abstract bot problem into a
 *     concrete cost: this share of your index's capacity is being spent on clients you had
 *     already decided were not people.
 *
 *  2. **Which Solr traffic has no matching web traffic at all?** An address that queries
 *     the index but never appears in the web log did not come through the site. That is a
 *     leaked API key, a scraper that found the endpoint, or an integration somebody forgot
 *     about — a genuine security finding, and one that is only visible with both planes in
 *     front of you.
 *
 * HOW IT IS DONE, AND HOW IT IS NOT. The addresses come out of a FACET on the Opensolr
 * side — one call, no documents — and are looked up in Loghound's own sessions index with
 * ONE faceted query. There is no per-address call to anything. The Solr-side facet is
 * bounded, so the answer covers the busiest addresses rather than all of them, and every
 * number on the page says so.
 *
 * WHEN THE WEB SIDE IS NOT THERE. Loghound may hold Opensolr credentials without running
 * on the machine that serves the website — a perfectly reasonable way to install it. In
 * that case the correlation cannot be computed, and the card says what it would have told
 * them, in terms of the numbers already on the screen. It never pretends the data is
 * missing for a technical reason it is not, and it never renders a broken table.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;
use Loghound\Solr;

final class Callers extends OpensolrView
{
    /**
     * The filter that keeps a rollup document out of a session count.
     *
     * The sessions core holds two document types discriminated by `doc_type_s` — one per
     * closed session, and one per day written by the scorer — and the schema is explicit
     * that every dashboard query must say which it wants. A rollup carries `ts_start`, so
     * without this filter it falls inside the time range and is counted as a session,
     * inflating every denominator on this page by one per day. Both queries below carry it.
     */
    private const SESSION_DOCS = 'doc_type_s:session';

    public function slug(): string
    {
        return 'callers';
    }

    public function title(): string
    {
        return 'Who is querying';
    }

    public function subtitle(): string
    {
        return 'The addresses hitting your search indexes, lined up against your web traffic.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        $shared = $this->sharedApi($action);
        if ($shared !== null) {
            return $shared;
        }

        return match ($action) {
            'who'   => $this->who(),
            'cross' => $this->cross(),
            default => ['error' => 'Unknown action'],
        };
    }

    /**
     * The busiest addresses and handlers, from one faceted call.
     *
     * @return array<string,mixed>
     */
    private function who(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'facet_fields' => ['ip', 'path'],
            'facet_limit'  => self::IP_FACET_LIMIT,
        ]);

        $addresses = (array) ($res['facet_fields']['ip'] ?? []);

        return $this->logEnvelope($res, [
            'addresses' => $addresses,
            'handlers'  => (array) ($res['facet_fields']['path'] ?? []),
            'covered'   => array_sum(array_map('intval', $addresses)),
            'limit'     => self::IP_FACET_LIMIT,
        ]);
    }

    /**
     * The correlation.
     *
     * Two calls total, whatever the number of addresses: one facet on the platform, one
     * facet on the local sessions index. Issuing a lookup per address would be the obvious
     * implementation and the wrong one — sixty round trips to answer a question one
     * faceted query answers.
     *
     * @return array<string,mixed>
     */
    private function cross(): array
    {
        $res = $this->fetch([
            'fq'           => $this->logFqs(),
            'rows'         => 0,
            'facet_fields' => ['ip'],
            'facet_limit'  => self::IP_FACET_LIMIT,
        ]);
        if ($res['state'] !== 'ok') {
            return $this->logEnvelope($res, self::emptyCross());
        }

        $ips = array_map('intval', (array) ($res['facet_fields']['ip'] ?? []));
        arsort($ips);

        $web = $this->webSide(array_keys($ips));

        $rows = [];
        $byClass = ['bot' => 0, 'human' => 0, 'unknown' => 0, 'unseen' => 0];

        foreach ($ips as $ip => $requests) {
            $seen = $web['by_ip'][(string) $ip] ?? null;
            $class = self::classify($seen, $web['state'] === 'ok');
            $byClass[$class] += $requests;

            $rows[] = [
                'ip'       => (string) $ip,
                'requests' => $requests,
                'sessions' => $seen === null ? null : (int) $seen['sessions'],
                'botlike'  => $seen === null ? null : (int) $seen['botlike'],
                'human'    => $seen === null ? null : (int) $seen['human'],
                'declared' => $seen === null ? null : (int) $seen['declared'],
                'webhits'  => $seen === null ? null : $seen['hits'],
                'class'    => $class,
            ];
        }

        $covered = array_sum($ips);

        return $this->logEnvelope($res, [
            'web_state'   => $web['state'],
            'web_note'    => $web['message'],
            'web_sessions' => $web['sessions'],
            'addresses'   => count($ips),
            'limit'       => self::IP_FACET_LIMIT,
            'covered'     => $covered,
            'by_class'    => $byClass,
            'rows'        => $rows,
        ]);
    }

    /**
     * Look the addresses up in Loghound's own sessions index.
     *
     * `state` distinguishes the three outcomes that need different words on screen: the
     * lookup worked, the index answered but holds no web traffic for this range (Loghound
     * is not watching the web server that fronts this search index), or the index could not
     * be reached at all (a local problem, not a missing feature).
     *
     * @param array<int,string> $ips
     * @return array{state:string,message:string,sessions:int,by_ip:array<string,array<string,mixed>>}
     */
    private function webSide(array $ips): array
    {
        if ($ips === []) {
            return ['state' => 'no_addresses', 'message' => '', 'sessions' => 0, 'by_ip' => []];
        }

        $this->gw->resetError();
        $overall = $this->gw->facet('opensolr.web.range', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => [self::SESSION_DOCS, Query::rangeFq('ts_start', $this->range)],
        ], ['addresses' => 'unique(ip_s)']);

        $error = $this->gw->error();
        if ($error !== null) {
            return [
                'state'    => 'unavailable',
                'message'  => $error,
                'sessions' => 0,
                'by_ip'    => [],
            ];
        }

        $sessions = (int) ($overall['count'] ?? 0);
        if ($sessions === 0) {
            return [
                'state'    => 'no_web_data',
                'message'  => 'Loghound has no web sessions in this time range to compare against.',
                'sessions' => 0,
                'by_ip'    => [],
            ];
        }

        $this->gw->resetError();
        $facets = $this->gw->facet('opensolr.web.by_ip', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => [
                self::SESSION_DOCS,
                Query::rangeFq('ts_start', $this->range),
                Solr::termsFilter('ip_s', $ips),
            ],
        ], [
            'by_ip' => [
                'type'  => 'terms',
                'field' => 'ip_s',
                'limit' => count($ips),
                'sort'  => 'count desc',
                'facet' => [
                    'botlike'  => ['type' => 'query', 'q' => Query::POP_BOTLIKE],
                    'human'    => ['type' => 'query', 'q' => Query::POP_HUMAN],
                    'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED_ANY],
                    'hits'     => 'sum(hits_i)',
                ],
            ],
        ]);

        $error = $this->gw->error();
        if ($error !== null) {
            return ['state' => 'unavailable', 'message' => $error, 'sessions' => $sessions, 'by_ip' => []];
        }

        $byIp = [];
        foreach (self::buckets($facets, 'by_ip') as $bucket) {
            $byIp[(string) ($bucket['val'] ?? '')] = [
                'sessions' => (int) ($bucket['count'] ?? 0),
                'botlike'  => self::qcount($bucket, 'botlike'),
                'human'    => self::qcount($bucket, 'human'),
                'declared' => self::qcount($bucket, 'declared'),
                'hits'     => self::num($bucket, 'hits'),
            ];
        }

        return ['state' => 'ok', 'message' => '', 'sessions' => $sessions, 'by_ip' => $byIp];
    }

    /**
     * Decide what an address is, from its web sessions.
     *
     * A majority rule rather than a weighted attribution, because the caption has to be
     * able to state the rule in one sentence. An address whose sessions Loghound scored
     * mostly as automation counts as a bot; one with human sessions and no bot sessions
     * counts as human; one that was scored but reached no verdict counts as unknown.
     *
     * "Unseen" is only claimed when the web side actually answered. If the sessions index
     * is unreachable, every address is "unknown" — an absent lookup is not evidence of
     * absence, and reporting it as a security finding would be a fabrication.
     *
     * @param array<string,mixed>|null $seen
     */
    private static function classify(?array $seen, bool $webAvailable): string
    {
        if (!$webAvailable) {
            return 'unknown';
        }
        if ($seen === null || (int) $seen['sessions'] === 0) {
            return 'unseen';
        }
        $bot = (int) $seen['botlike'];
        $human = (int) $seen['human'];
        if ($bot > 0 && $bot >= $human) {
            return 'bot';
        }
        if ($human > 0) {
            return 'human';
        }
        return 'unknown';
    }

    /**
     * The shape a correlation response has when there is nothing to correlate.
     *
     * @return array<string,mixed>
     */
    private static function emptyCross(): array
    {
        return [
            'web_state'    => 'no_addresses',
            'web_note'     => '',
            'web_sessions' => 0,
            'addresses'    => 0,
            'limit'        => self::IP_FACET_LIMIT,
            'covered'      => 0,
            'by_class'     => ['bot' => 0, 'human' => 0, 'unknown' => 0, 'unseen' => 0],
            'rows'         => [],
        ];
    }

    public function body(): void
    {
        if (!$this->configured()) {
            self::noCredentials();
            return;
        }

        $this->whoCard();
        $this->crossCard();
        $this->explainCard();
    }

    /** Top addresses and handlers on the search side. */
    private function whoCard(): void
    {
        self::cardOpen('cl-who', '01', 'Busiest addresses', '', self::indexPicker('cl-core'));
        self::skeleton('cl-who', 'rows', 0, 'Faceting client addresses');

        echo '<div class="split-card">';
        echo '<div class="split-half"><h2>Addresses</h2>'
            . '<p class="split-note">The clients that sent the most queries to this index.</p>'
            . '<div class="table-wrap"><table id="cl-ips-table"><thead><tr>'
            . '<th scope="col">Address</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '<div class="split-half"><h2>Handlers</h2>'
            . '<p class="split-note">Which endpoint they were calling.</p>'
            . '<div class="table-wrap"><table id="cl-handlers-table"><thead><tr>'
            . '<th scope="col">Handler</th><th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="bar-col">Share</th></tr></thead><tbody></tbody></table></div></div>';
        echo '</div>';

        self::cardClose('cl-who');
    }

    /** The correlation itself. */
    private function crossCard(): void
    {
        self::cardOpen('cl-cross', '02', 'Cross-referenced with your web traffic', '');
        self::skeleton('cl-cross', 'stats', 0, 'Matching search clients against web sessions');

        echo '<div class="stats">';
        foreach ([
            ['bot',     'Serving bots',      'Requests from addresses whose web sessions Loghound scored as automation'],
            ['human',   'Serving people',    'Requests from addresses whose web sessions look human'],
            ['unseen',  'No web traffic',    'Requests from addresses that never appear in your web logs at all'],
            ['unknown', 'Undecided',         'Scored, but the evidence reached no verdict either way'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';

        echo '<div id="cl-cross-state"></div>';

        echo '<div class="table-wrap"><table id="cl-cross-table"><thead><tr>'
            . '<th scope="col">Address</th>'
            . '<th scope="col" class="num">Search requests</th>'
            . '<th scope="col">Web traffic</th>'
            . '<th scope="col" class="num">Web sessions</th>'
            . '<th scope="col" class="num">Scored bot</th>'
            . '<th scope="col" class="num">Scored human</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('cl-cross');
    }

    /** What the two questions are, and why they need both halves. */
    private function explainCard(): void
    {
        self::cardOpen('cl-explain', '03', 'Why this needs both halves');
        echo '<div class="explain">';
        echo '<p>Your search index knows which addresses queried it. It has no idea which of them were '
            . 'people. Your web logs know which addresses were people. They have no idea what those '
            . 'people asked your search index. Neither half can answer a question about the other, which '
            . 'is why this page exists inside Loghound rather than next to it.</p>';
        echo '<p><strong>Serving bots.</strong> Every query costs CPU on a search node you pay for. Once '
            . 'the addresses are classified, that cost splits into work done for visitors and work done '
            . 'for scrapers, and the second number is usually larger than people expect. It is measured '
            . 'here rather than estimated: these are the same verdicts, from the same scoring rules, that '
            . 'the rest of Loghound reports.</p>';
        echo '<p><strong>No web traffic at all.</strong> This is the finding worth chasing. A client that '
            . 'queries your index but never requests a page did not arrive through your website. The '
            . 'benign explanations are a server-side integration, a monitoring check or a background job '
            . 'you set up and forgot. The rest are not benign: a leaked API key, an index left open to '
            . 'the internet, or somebody who found the endpoint and is now reading your catalogue '
            . 'directly. Either way you want to know which it is.</p>';
        echo '<p class="faint">An address is classified by the majority of its web sessions in the same '
            . 'time range. The comparison covers the busiest addresses on the search side, not all of '
            . 'them, and the card above states how much of the traffic that accounts for.</p>';
        echo '</div>';
        self::cardEnd();
    }
}
