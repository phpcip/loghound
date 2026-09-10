<?php
/**
 * Loghound — Solr query construction helpers for the panel.
 *
 * Every Solr request the dashboard makes is assembled here or in a Panel controller,
 * server-side, from constants and allowlists. There is deliberately NO endpoint that
 * forwards a caller-supplied Solr fragment: the browser sends a view name, a time range
 * token and allowlisted facet selections, and this class turns those into query syntax.
 *
 * The two rules that matter:
 *  1. Free text NEVER reaches `q`/`fq` by concatenation. It is bound as a Solr parameter
 *     (`uq`) and referenced with `v=$uq`, which makes it a literal to the query parser.
 *  2. Field names NEVER reach a query unless they came out of one of the allowlists in
 *     this file (validated again through Security::isSafeFieldName as a belt-and-braces).
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Query
{
    /**
     * Population filters — mutually exclusive and, together, exhaustive over any session
     * document that has been scored. They exist as named constants because the difference
     * between "a bot" and "a crawler that told us it was a crawler" is the whole point of
     * the product, and it must not be re-derived slightly differently in each view.
     */

    /** Sessions we believe a person drove. */
    public const POP_HUMAN = 'bot_verdict_s:(human OR likely_human)';

    /** Scored, but the evidence did not reach a verdict in either direction. */
    public const POP_UNKNOWN = 'bot_verdict_s:unknown';

    /** Anything the scorer called a bot, honest or not. Used for ratios, never for blame. */
    public const POP_BOTLIKE = 'bot_verdict_s:(bot OR likely_bot)';

    /**
     * AI training/inference crawlers that identify themselves (GPTBot, ClaudeBot, ...).
     * Split out of "declared" because operators care about this group specifically.
     */
    public const POP_AI = 'bot_verdict_s:(bot OR likely_bot) AND ai_crawler_b:true';

    /**
     * Crawlers and monitors that declare themselves and pass verification. NOT a threat —
     * SPEC §7 is explicit that conflating these with evasive automation is what makes
     * existing tools useless, so they get their own series and their own table everywhere.
     */
    public const POP_DECLARED = 'bot_verdict_s:(bot OR likely_bot) AND -ai_crawler_b:true'
        . ' AND bot_class_s:(declared_crawler OR monitor)';

    /**
     * The interesting group: scored as automation, did not declare itself. Headless
     * browsers, scripted clients, spoofed UAs, rotating-proxy fleets.
     */
    public const POP_EVASIVE = 'bot_verdict_s:(bot OR likely_bot) AND -ai_crawler_b:true'
        . ' AND -bot_class_s:(declared_crawler OR monitor)';

    /**
     * Declared crawlers AND AI crawlers together — "everything that told us what it was".
     *
     * Expressed as a single-field OR group rather than `POP_DECLARED OR POP_AI` because
     * mixing AND and OR across fields in one Lucene string is ambiguous without explicit
     * parentheses, and an ambiguous filter is a silently wrong number.
     */
    public const POP_DECLARED_ANY = 'bot_verdict_s:(bot OR likely_bot)'
        . ' AND bot_class_s:(declared_crawler OR monitor OR ai_crawler)';

    /** Sessions where a beacon actually arrived — the only population with real timings. */
    public const POP_BEACON = 'beacon_b:true';

    /**
     * The five overview series, in stacking order (most human at the bottom).
     *
     * @return array<string,string> series key => filter query
     */
    public static function populations(): array
    {
        return [
            'human'    => self::POP_HUMAN,
            'unknown'  => self::POP_UNKNOWN,
            'declared' => self::POP_DECLARED,
            'ai'       => self::POP_AI,
            'evasive'  => self::POP_EVASIVE,
        ];
    }

    /**
     * Human-readable labels for the population keys, used in legends and in the
     * "population covered" caption every chart carries.
     *
     * @return array<string,string>
     */
    public static function populationLabels(): array
    {
        return [
            'human'    => 'Humans',
            'unknown'  => 'Unknown',
            'declared' => 'Declared crawlers',
            'ai'       => 'AI crawlers',
            'evasive'  => 'Evasive bots',
            'all'      => 'All sessions',
            'beacon'   => 'Sessions with beacon data',
        ];
    }

    /**
     * Time ranges the UI is allowed to ask for.
     *
     * Solr date math is used rather than formatted timestamps so the range is evaluated
     * by Solr against its own clock; there is no timezone skew between PHP and Solr to
     * get wrong. `secs` drives the bucket-size choice and the sparkline geometry.
     *
     * @return array<string,array{label:string,start:string,secs:int,gap:string,fmt:string}>
     */
    public static function ranges(): array
    {
        return [
            '1h'  => ['label' => 'Last hour',    'start' => 'NOW-1HOUR/MINUTE',  'secs' => 3600,    'gap' => '+2MINUTE', 'fmt' => 'time'],
            '6h'  => ['label' => 'Last 6 hours', 'start' => 'NOW-6HOUR/MINUTE',  'secs' => 21600,   'gap' => '+15MINUTE','fmt' => 'time'],
            '24h' => ['label' => 'Last 24 hours','start' => 'NOW-24HOUR/HOUR',   'secs' => 86400,   'gap' => '+1HOUR',   'fmt' => 'hour'],
            '7d'  => ['label' => 'Last 7 days',  'start' => 'NOW-7DAY/HOUR',     'secs' => 604800,  'gap' => '+3HOUR',   'fmt' => 'hour'],
            '30d' => ['label' => 'Last 30 days', 'start' => 'NOW-30DAY/DAY',     'secs' => 2592000, 'gap' => '+1DAY',    'fmt' => 'day'],
            '90d' => ['label' => 'Last 90 days', 'start' => 'NOW-90DAY/DAY',     'secs' => 7776000, 'gap' => '+1DAY',    'fmt' => 'day'],
        ];
    }

    /**
     * Resolve a caller-supplied range token to a range definition, defaulting to 24h.
     *
     * Anything not in the table is silently replaced with the default rather than
     * rejected, because a bad `range` in a bookmarked URL should show a dashboard, not
     * an error page — and there is nothing to leak either way.
     */
    public static function range(?string $token): array
    {
        $ranges = self::ranges();
        $key = is_string($token) && isset($ranges[$token]) ? $token : '24h';
        $def = $ranges[$key];
        $def['key'] = $key;
        return $def;
    }

    /**
     * Build the `fq` clause that bounds a query to the selected range.
     *
     * @param string $field `ts_start` on the sessions core, `ts` on hits.
     */
    public static function rangeFq(string $field, array $range): string
    {
        // Field comes from our own callers, never from input, but validate anyway: this
        // is the one place a typo would become a syntax injection rather than an error.
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        return $field . ':[' . $range['start'] . ' TO NOW]';
    }

    /**
     * Escape a literal value for use inside a quoted Solr term.
     *
     * Backslash and double-quote are the only characters that can terminate a quoted
     * phrase, so escaping those two and then wrapping in quotes makes any byte sequence
     * — including a User-Agent full of Lucene operators — a literal.
     */
    public static function quote(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    /**
     * Build a `field:"value"` filter with both halves validated/escaped.
     */
    public static function term(string $field, string $value): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe field name: ' . $field);
        }
        return $field . ':' . self::quote($value);
    }

    /**
     * Fields the session explorer is allowed to filter on, with their display labels.
     *
     * This doubles as the facet list rendered in the sidebar: if a field is not here it
     * cannot be faceted and it cannot be filtered, so a crafted query string cannot
     * reach an arbitrary field.
     *
     * @return array<string,string>
     */
    public static function filterFields(): array
    {
        return [
            'bot_verdict_s' => 'Verdict',
            'bot_class_s'   => 'Bot class',
            'as_type_s'     => 'Network type',
            'country_s'     => 'Country',
            'browser_s'     => 'Browser',
            'os_s'          => 'OS',
            'device_s'      => 'Device',
            'ua_bot_cat_s'  => 'Declared bot category',
            'referer_type_s' => 'Referrer type',
            'bot_reasons_ss' => 'Signal fired',
            'as_org_s'      => 'AS organisation',
            'netname_s'     => 'Netname',
            'fp_hash_s'     => 'Fingerprint',
            'ip_s'          => 'IP',
            'session_id_s'  => 'Session',
        ];
    }

    /**
     * Sort options for the session explorer, mapped to literal Solr sort strings.
     *
     * A map rather than a "field + direction" pair on purpose: the value that reaches
     * Solr is one of these constants and can never be assembled from input.
     *
     * @return array<string,string>
     */
    public static function sorts(): array
    {
        return [
            'recent'  => 'ts_start desc',
            'oldest'  => 'ts_start asc',
            'score'   => 'bot_score_f desc',
            'hits'    => 'hits_i desc',
            'engaged' => 'engaged_ms_l desc',
            'span'    => 'log_span_ms_l desc',
        ];
    }

    /**
     * The field list returned for a session row in the explorer.
     *
     * Explicit rather than `fl=*`: the panel should never accidentally start shipping a
     * field that was added to the schema for scoring purposes, and an explicit list is
     * also what keeps the response small.
     */
    public static function sessionFl(): string
    {
        return implode(',', [
            'id', 'ts_start', 'ts_end', 'hits_i', 'pages_i', 'assets_i', 'uniq_paths_i',
            'bytes_l', 'entry_path_s', 'exit_path_s',
            'status_2xx_i', 'status_3xx_i', 'status_4xx_i', 'status_5xx_i', 'got_304_b',
            'log_span_ms_l', 'wall_ms_l', 'visible_ms_l', 'engaged_ms_l', 'beacon_b',
            'interactions_i', 'max_scroll_pct_i', 'pageviews_i', 'asset_ratio_f',
            'gap_p50_ms_l', 'gap_stddev_ms_l',
            'ip_s', 'ip_net_s', 'asn_i', 'as_org_s', 'as_type_s', 'netname_s',
            'rdns_s', 'rdns_ok_b', 'country_s', 'region_s', 'city_s', 'tz_s',
            'ua_s', 'browser_s', 'browser_ver_i', 'os_s', 'device_s',
            'ua_bot_b', 'ua_bot_name_s', 'ua_bot_cat_s', 'ai_crawler_b',
            'referer_s', 'referer_host_s', 'referer_type_s',
            'fp_hash_s', 'fp_ips_24h_i',
            'js_b', 'headless_b', 'automation_ss', 'ua_claim_ok_b', 'tz_match_b', 'webgl_s',
            'bot_score_f', 'bot_verdict_s', 'bot_reasons_ss', 'bot_class_s', 'rule_version_i',
        ]);
    }

    /** The field list for a single hit in the session drill-down timeline. */
    public static function hitFl(): string
    {
        return implode(',', [
            'id', 'ts', 'method_s', 'path_s', 'query_s', 'status_i', 'bytes_l', 'dur_us_l',
            'kind_s', 'asset_kind_s', 'proto_s', 'referer_s', 'session_seq_i', 'hit_flags_ss',
        ]);
    }

    /**
     * The edismax query-fields string for free-text search.
     *
     * Weights follow SPEC §4.1: path first (that is what an operator usually remembers),
     * then the identity strings. The `_txt` suffixes are the analysed copies fed by the
     * catchall copyFields.
     *
     * NOTE: SPEC §4.1 defines the catchall on the `hits` core only. The session explorer
     * searches `sessions`, so the sessions configset needs the same `text_all` field and
     * the same copyFields, or free text there will only ever match on whatever analysed
     * copies exist. Flagged in docs/PANEL.md.
     */
    public const QF_FIELDS = 'path_txt^3 ua_txt^2 as_org_txt^2 netname_txt^2 rdns_txt city_txt country_txt';

    /**
     * Build the `q` parameter and its bound parameters for a free-text search.
     *
     * FALLBACK ONLY. \Loghound\Solr::queryText() is the supported path and Gateway uses
     * it; this exists so the panel still works against a client that does not provide it.
     *
     * Two things are load-bearing:
     *  - The text is BOUND as `uq` and referenced with `v=$uq`. It is never concatenated
     *    into `q`, so nothing typed into the search box can be query syntax.
     *  - There is no `defType`. Solr honours a leading `{!parser}` switch only when the
     *    top-level parser is the default lucene one; adding `defType=edismax` makes
     *    edismax read the braces as literal search text and silently return nothing.
     *    Solr::DENIED_PARAMS refuses `defType` outright for exactly this reason.
     *
     * @return array<string,string> Parameters to merge into the request.
     */
    public static function textSearch(string $text): array
    {
        $text = trim($text);
        // Strip any local-param block so a user cannot switch parsers by typing
        // "{!func}..." into the search box; the rest of the string is bound, not spliced.
        while (preg_match('/^\{![^}]*\}/', $text)) {
            $text = trim((string) preg_replace('/^\{![^}]*\}/', '', $text));
        }
        if ($text === '') {
            return ['q' => '*:*'];
        }
        return [
            // This exact literal is the only non-trivial `q` Solr::assertSafeQuery()
            // accepts. Do not "improve" it by inlining qf or mm.
            'q'  => '{!edismax v=$uq}',
            'uq' => $text,
            'qf' => self::QF_FIELDS,
            'mm' => '100%',
        ];
    }

    /**
     * Number of sparkline buckets to request for a fingerprint cluster's activity.
     *
     * Kept small deliberately: this is a nested range facet inside a terms facet, so the
     * cost is buckets × clusters. 24 is enough to see a duty cycle.
     */
    public const SPARK_BUCKETS = 24;

    /**
     * Compute a `gap` string that divides the selected range into SPARK_BUCKETS pieces.
     *
     * Returned as Solr date math in seconds, which is exact for every range we offer.
     */
    public static function sparkGap(array $range): string
    {
        $seconds = max(60, intdiv($range['secs'], self::SPARK_BUCKETS));
        return '+' . $seconds . 'SECOND';
    }
}
