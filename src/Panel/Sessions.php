<?php
/**
 * Loghound — Session explorer.
 *
 * The one view that returns documents rather than aggregates, and therefore the one that
 * needs the most care:
 *
 *  - The search box is free text from a browser. It is bound as the Solr parameter `uq`
 *    and referenced as `{!edismax ... v=$uq}` — never concatenated into `q`. Any
 *    `{!localparam}` block is stripped first so the parser cannot be switched.
 *  - Facet filters arrive as `f[field][]=value`. The field must be in
 *    Query::filterFields(); the value is quoted and escaped by Query::term/quote.
 *  - `rows` and `start` are clamped on every request (Security::clampInt, and
 *    Security::MAX_ROWS/MAX_START as the ceiling).
 *  - `sort` is a key into a map of literal sort strings, not a field plus a direction.
 *  - `fl` is an explicit allowlist (Query::sessionFl / hitFl), never `*`.
 *
 * Every value that comes back is attacker-controlled — paths, User-Agents and referers
 * are whatever the client on the wire chose to send — so the browser renders all of it
 * with textContent, and any referer shown as a link goes through Security::safeUrl on
 * the way out of PHP.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Sessions extends Controller
{
    /** Page size ceiling for the session list. */
    private const MAX_ROWS = 100;

    /** Hard cap on hits returned for one session's timeline. */
    private const MAX_TIMELINE = 300;

    public function slug(): string
    {
        return 'sessions';
    }

    public function title(): string
    {
        return 'Session explorer';
    }

    public function subtitle(): string
    {
        return 'Search every session, then open one and watch it happen request by request.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'list'   => $this->list(),
            'facets' => $this->facets(),
            'detail' => $this->detail(),
            default  => ['error' => 'Unknown action'],
        };
    }

    /**
     * A page of matching sessions.
     *
     * Its own request, separate from the facet sidebar, so the table appears as soon as
     * the documents are back instead of waiting on eight terms facets. Free text goes to
     * the Gateway as text and is bound as the `uq` parameter by Solr::queryText(); it is
     * never concatenated into a query.
     *
     * @return array<string,mixed>
     */
    private function list(): array
    {
        $text = self::text('q', 200);
        $sortKey = self::param('sort', array_keys(Query::sorts()), 'recent');
        $rows = self::rows(self::MAX_ROWS, 25);
        $start = self::start();

        $res = $this->gw->search('sessions.list', $this->gw->sessionsCore(), $text, [
            'fq'    => $this->sessionFqs(),
            'sort'  => Query::sorts()[$sortKey],
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::sessionFl(),
        ]);

        return $this->envelope([
            'q'        => $text,
            'sort'     => $sortKey,
            'rows'     => $rows,
            'start'    => $start,
            'numFound' => $res['numFound'],
            'docs'     => array_map([$this, 'shapeSession'], $res['docs']),
            'active'   => $this->filters,
        ]);
    }

    /**
     * Facet counts for the sidebar, over the same query as the result table.
     *
     * Identity-shaped fields are filterable but never faceted: `ip_s` and `session_id_s`
     * have effectively unbounded cardinality, so a terms facet on them is slow and tells
     * the operator nothing.
     *
     * @return array<string,mixed>
     */
    private function facets(): array
    {
        $text = self::text('q', 200);
        $skip = ['ip_s', 'session_id_s', 'fp_hash_s', 'as_org_s', 'netname_s'];

        $definitions = [];
        foreach (Query::filterFields() as $field => $label) {
            if (in_array($field, $skip, true)) {
                continue;
            }
            $definitions[$field] = ['type' => 'terms', 'field' => $field, 'limit' => 12, 'sort' => 'count desc'];
        }
        $definitions['beacon'] = ['type' => 'query', 'q' => Query::POP_BEACON];

        $f = $this->gw->searchFacet(
            'sessions.facets',
            $this->gw->sessionsCore(),
            $text,
            ['fq' => $this->sessionFqs()],
            $definitions
        );

        $facets = [];
        foreach (Query::filterFields() as $field => $label) {
            if (!isset($definitions[$field])) {
                continue;
            }
            $buckets = [];
            foreach (self::buckets($f, $field) as $bucket) {
                $buckets[] = [
                    'value' => (string) ($bucket['val'] ?? ''),
                    'count' => (int) ($bucket['count'] ?? 0),
                ];
            }
            if ($buckets !== []) {
                $facets[] = ['field' => $field, 'label' => $label, 'buckets' => $buckets];
            }
        }

        return $this->envelope([
            'facets'       => $facets,
            'active'       => $this->filters,
            'matched'      => (int) ($f['count'] ?? 0),
            'beacon_count' => self::qcount($f, 'beacon'),
        ]);
    }

    /**
     * One session, with its hit timeline and the beacon overlay.
     *
     * @return array<string,mixed>
     */
    private function detail(): array
    {
        $id = self::text('id', 128);
        if (!preg_match('/^[A-Za-z0-9_-]{8,128}$/', $id)) {
            return $this->envelope(['error' => 'Not a session id.']);
        }

        $sess = $this->gw->select('sessions.one', $this->gw->sessionsCore(), [
            'q'    => '*:*',
            'fq'   => [Query::term('id', $id)],
            'rows' => 1,
            'fl'   => Query::sessionFl(),
        ]);

        if ($sess['docs'] === []) {
            return $this->envelope(['error' => 'That session is not in the index (it may have aged past retention).']);
        }
        $doc = $this->shapeSession($sess['docs'][0]);

        $limit = Security::clampInt($_GET['limit'] ?? null, 10, self::MAX_TIMELINE, 200);
        $hits = $this->gw->select('sessions.hits', $this->gw->hitsCore(), [
            'q'    => '*:*',
            'fq'   => [Query::term('session_id_s', $id)],
            'sort' => 'ts asc',
            'rows' => $limit,
            'fl'   => Query::hitFl(),
        ]);

        $timeline = [];
        foreach ($hits['docs'] as $h) {
            $timeline[] = [
                'id'      => (string) ($h['id'] ?? ''),
                'ts'      => (string) ($h['ts'] ?? ''),
                'seq'     => isset($h['session_seq_i']) ? (int) $h['session_seq_i'] : null,
                'method'  => (string) ($h['method_s'] ?? ''),
                'path'    => (string) ($h['path_s'] ?? ''),
                'query'   => isset($h['query_s']) ? (string) $h['query_s'] : null,
                'status'  => isset($h['status_i']) ? (int) $h['status_i'] : null,
                'bytes'   => isset($h['bytes_l']) ? (int) $h['bytes_l'] : null,
                'dur_us'  => isset($h['dur_us_l']) ? (int) $h['dur_us_l'] : null,
                'kind'    => (string) ($h['kind_s'] ?? ''),
                'asset'   => isset($h['asset_kind_s']) ? (string) $h['asset_kind_s'] : null,
                'proto'   => (string) ($h['proto_s'] ?? ''),
                'referer' => isset($h['referer_s']) ? (string) $h['referer_s'] : null,
                'referer_href' => isset($h['referer_s']) ? Security::safeUrl((string) $h['referer_s']) : null,
                'flags'   => array_values(array_map('strval', (array) ($h['hit_flags_ss'] ?? []))),
            ];
        }

        return $this->envelope([
            'session'   => $doc,
            'timeline'  => $timeline,
            'truncated' => count($timeline) >= $limit,
            'reasons'   => Bots::reasonCatalogue(),
        ]);
    }

    /**
     * Normalise a session document for the browser.
     *
     * Two jobs. First, absent stays absent: a field that Solr did not return becomes null
     * and renders as an em-dash, never as 0 — SPEC §1 forbids the zero-fill, and this is
     * where it would otherwise creep in. Second, the referer gets a pre-validated href so
     * the client never has to decide whether a URL is safe to link.
     *
     * @param array<string,mixed> $d
     * @return array<string,mixed>
     */
    private function shapeSession(array $d): array
    {
        $int = static fn (string $k) => isset($d[$k]) && is_numeric($d[$k]) ? (int) $d[$k] : null;
        $flt = static fn (string $k) => isset($d[$k]) && is_numeric($d[$k]) ? (float) $d[$k] : null;
        $str = static fn (string $k) => isset($d[$k]) && is_scalar($d[$k]) ? (string) $d[$k] : null;
        $bool = static fn (string $k) => array_key_exists($k, $d) ? (bool) $d[$k] : null;
        $list = static fn (string $k) => array_values(array_map('strval', (array) ($d[$k] ?? [])));

        $out = [
            'id'        => (string) ($d['id'] ?? ''),
            'ts_start'  => $str('ts_start'),
            'ts_end'    => $str('ts_end'),
            'hits'      => $int('hits_i'),
            'pages'     => $int('pages_i'),
            'assets'    => $int('assets_i'),
            'uniq_paths' => $int('uniq_paths_i'),
            'bytes'     => $int('bytes_l'),
            'entry'     => $str('entry_path_s'),
            'exit'      => $str('exit_path_s'),
            'status'    => [
                '2xx' => $int('status_2xx_i'),
                '3xx' => $int('status_3xx_i'),
                '4xx' => $int('status_4xx_i'),
                '5xx' => $int('status_5xx_i'),
            ],
            'got_304'   => $bool('got_304_b'),

            'beacon'    => $bool('beacon_b'),
            'log_span_ms' => $int('log_span_ms_l'),
            'wall_ms'   => $int('wall_ms_l'),
            'visible_ms' => $int('visible_ms_l'),
            'engaged_ms' => $int('engaged_ms_l'),
            'interactions' => $int('interactions_i'),
            'max_scroll' => $int('max_scroll_pct_i'),
            'pageviews' => $int('pageviews_i'),
            'asset_ratio' => $flt('asset_ratio_f'),
            'gap_p50_ms' => $int('gap_p50_ms_l'),
            'gap_stddev_ms' => $int('gap_stddev_ms_l'),

            'ip'        => $str('ip_s'),
            'ip_net'    => $str('ip_net_s'),
            'asn'       => $int('asn_i'),
            'as_org'    => $str('as_org_s'),
            'as_type'   => $str('as_type_s'),
            'netname'   => $str('netname_s'),
            'rdns'      => $str('rdns_s'),
            'rdns_ok'   => $bool('rdns_ok_b'),
            'country'   => $str('country_s'),
            'region'    => $str('region_s'),
            'city'      => $str('city_s'),
            'tz'        => $str('tz_s'),

            'ua'        => $str('ua_s'),
            'browser'   => $str('browser_s'),
            'browser_ver' => $int('browser_ver_i'),
            'os'        => $str('os_s'),
            'device'    => $str('device_s'),
            'ua_bot'    => $bool('ua_bot_b'),
            'ua_bot_name' => $str('ua_bot_name_s'),
            'ua_bot_cat' => $str('ua_bot_cat_s'),
            'ai_crawler' => $bool('ai_crawler_b'),

            'referer'   => $str('referer_s'),
            'referer_host' => $str('referer_host_s'),
            'referer_type' => $str('referer_type_s'),

            'fp'        => $str('fp_hash_s'),
            'fp_ips_24h' => $int('fp_ips_24h_i'),

            'js'        => $bool('js_b'),
            'headless'  => $bool('headless_b'),
            'automation' => $list('automation_ss'),
            'ua_claim_ok' => $bool('ua_claim_ok_b'),
            'tz_match'  => $bool('tz_match_b'),
            'webgl'     => $str('webgl_s'),

            'score'     => $flt('bot_score_f'),
            'verdict'   => $str('bot_verdict_s'),
            'reasons'   => $list('bot_reasons_ss'),
            'class'     => $str('bot_class_s'),
            'rule_version' => $int('rule_version_i'),
        ];

        $out['referer_href'] = $out['referer'] !== null ? Security::safeUrl($out['referer']) : null;
        return $out;
    }

    public function body(): void
    {
        $this->searchCard();

        echo '<div class="explorer">';
        $this->facetsCard();
        $this->resultsCard();
        echo '</div>';

        echo '<section class="card detail" id="se-detail" hidden>';
        echo '<div class="card-head"><h2><span class="card-num">03</span><span>Session detail</span></h2>'
            . '<button type="button" id="se-detail-close" class="ghost small">Close</button></div>';
        echo '<div id="se-detail-body"></div>';
        echo '</section>';
    }

    /**
     * The search form.
     *
     * A GET form, so every search is a bookmarkable URL and the view works with
     * JavaScript disabled.
     */
    private function searchCard(): void
    {
        self::cardOpen(
            'se-search',
            '01',
            'Search',
            'Free text is matched with edismax across path, User-Agent, AS organisation, netname, reverse DNS, '
            . 'city and country. It is sent to Solr as a bound parameter, never as query syntax.'
        );

        echo '<form class="searchbar" method="get" action="" id="se-form">';
        echo '<input type="hidden" name="v" value="sessions">';
        echo '<input type="hidden" name="range" value="' . Security::esc($this->range['key']) . '">';
        echo '<label class="sr-only" for="se-q">Search sessions</label>';
        echo '<input type="search" id="se-q" name="q" '
            . 'placeholder="Search paths, User-Agents, organisations, netnames, cities" '
            . 'value="' . Security::esc(self::text('q', 200)) . '" autocomplete="off" spellcheck="false">';
        echo '<label class="sr-only" for="se-sort">Sort by</label>';
        echo '<select id="se-sort" name="sort">';
        $active = self::param('sort', array_keys(Query::sorts()), 'recent');
        foreach ([
            'recent'  => 'Most recent',
            'oldest'  => 'Oldest first',
            'score'   => 'Highest bot score',
            'hits'    => 'Most requests',
            'engaged' => 'Most engaged time',
            'span'    => 'Longest log span',
        ] as $value => $label) {
            echo '<option value="' . Security::esc($value) . '"' . ($value === $active ? ' selected' : '') . '>'
                . Security::esc($label) . '</option>';
        }
        echo '</select>';
        echo '<button type="submit" class="primary">Search</button>';
        echo '</form>';

        self::cardEnd();
    }

    /** The facet sidebar, loaded separately from the results. */
    private function facetsCard(): void
    {
        echo '<aside class="facets" aria-label="Filters">';
        self::cardOpen('se-facets', '02', 'Filters');
        self::skeleton('se-facets', 'rows', 0, 'Counting facet values');
        echo '<div id="se-active"></div>';
        echo '<div id="se-facet-list"></div>';
        self::cardClose('se-facets');
        echo '</aside>';
    }

    /** The result table. */
    private function resultsCard(): void
    {
        echo '<div class="results">';
        self::cardOpen('se-results', '', 'Sessions', '', '<span class="job-meta" id="se-count"></span>');
        self::skeleton('se-results', 'rows', 0, 'Searching sessions');

        echo '<div class="table-wrap"><table id="se-table"><thead><tr>'
            . '<th scope="col">Started</th>'
            . '<th scope="col">Verdict</th>'
            . '<th scope="col">Address</th>'
            . '<th scope="col">Network</th>'
            . '<th scope="col">Client</th>'
            . '<th scope="col" class="num">Reqs</th>'
            . '<th scope="col" class="num">Log span</th>'
            . '<th scope="col" class="num">Engaged</th>'
            . '<th scope="col">Entry</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="pager" id="se-pager"></div>';

        self::cardClose('se-results');
        echo '</div>';
    }
}
