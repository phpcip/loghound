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

use Loghound\Score\Attacks;
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
     * Sessions that made more than one request — the only ones a LOG SPAN can describe.
     *
     * A span is the last request minus the first, so a session with exactly one request has a
     * span of zero BY CONSTRUCTION and no measurement has taken place. Measured on a real index:
     * of 4,132 sessions, 3,205 were a single request. Averaging those in gives a median of zero,
     * which is arithmetically correct and completely useless — and it is what the Overview's
     * timing card was reporting as "how long they actually stayed".
     *
     * So any span statistic is taken over THIS population and the single-request count is
     * printed beside it rather than folded into it. The same discipline the beacon clocks
     * already keep: a session with no beacon is excluded from them and named, not counted as a
     * zero.
     */
    public const POP_MULTI_REQUEST = 'hits_i:[2 TO *]';

    /**
     * Sessions whose span came out at zero DESPITE having more than one request.
     *
     * Not a measurement of zero — a resolution floor. The span is derived from the timestamps in
     * the access log, and the stock Apache `%t` and nginx `$time_local` record whole seconds, so
     * two requests inside the same second are indistinguishable and the difference is 0. On the
     * same index as above, 376 of the 926 multi-request sessions were in this state.
     *
     * It is offered as its own number so the card can say "shorter than this log's clock can
     * measure" instead of printing `0 ms` as though it had measured it. A format that logs a
     * fraction — HAProxy, `%{msec}t`, `%{usec}t`, nginx's `$msec`, any ISO-8601 with a decimal —
     * makes this number collapse toward nothing, which is also how an operator discovers that
     * widening their LogFormat would buy them something.
     */
    public const POP_SPAN_FLOORED = 'log_span_ms_l:0';

    /**
     * Requests (or sessions) that matched at least one named attack pattern.
     *
     * A method rather than a constant because the vocabulary lives in Score\Attacks and a
     * constant cannot call it; it belongs HERE rather than in the view for the same reason the
     * five POP_* constants do — a population that is re-derived slightly differently in each
     * card is a set of numbers that quietly disagree.
     *
     * IT NAMES THE CODES EXPLICITLY rather than asking for "any value of hit_flags_ss", and that
     * is deliberate: `hit_flags_ss` is a general per-hit signal field, so a future flag that is
     * not an attack would otherwise join this population and inflate every count on the Attacks
     * view. Built entirely from a closed table of constants and quoted anyway; nothing a caller
     * can send reaches it.
     */
    public static function attackFq(): string
    {
        $quoted = array_map([self::class, 'quote'], Attacks::codes());
        return 'hit_flags_ss:(' . implode(' OR ', $quoted) . ')';
    }

    /**
     * The sessions core holds two kinds of document: one per session, and the daily rollups
     * that `privacy.rollup_forever` keeps after the sessions themselves have been deleted.
     * Every count, facet and delete against that core has to say which it means, or the
     * rollups are counted as sessions and every total is quietly too high.
     *
     * Used by the views that were written against it and by the size-based retention trim,
     * which must never delete a rollup: they are aggregate counts with nothing in them that
     * identifies a visitor, they cost almost nothing to keep, and they are the difference
     * between a 90-day tool and one that can show you last year.
     */
    public const SESSION_DOCS = 'doc_type_s:session';

    /**
     * Sessions that have ENDED — the settled population.
     *
     * A NEGATION, never `provisional_b:false`, and the distinction is the whole correctness of
     * the clause: bin/loghound-score writes `provisional_b` only as true and omits it entirely on
     * a settled document, so every session indexed before the field existed has no value for it.
     * `provisional_b:false` would match none of them and would empty every card that used it.
     *
     * Use this on any number that is only meaningful over a completed session: a duration
     * average, an engagement percentile, a coverage ratio whose denominator assumes the session
     * had its chance to produce the thing being counted.
     */
    public const SETTLED_SESSIONS = '-provisional_b:true';

    /**
     * Sessions that were seen on a transport plane — i.e. everything except beacon-only.
     *
     * A NEGATION, for exactly the reason SETTLED_SESSIONS is one, and the mistake it prevents is
     * the same mistake wearing a different field name. `planes_s` has no schema default, so every
     * session indexed before the field existed carries no value for it at all. `planes_s:log_only`
     * would match none of them and would silently drop a site's whole history from any figure
     * built on it — a number that looks like a measurement and is an artefact of when a field was
     * added. This spelling keeps that history, because absence is not `beacon_only`.
     *
     * The panel offers the same thing through the facet control rather than this constant: the
     * "None of" operator over `beacon_only` produces `-planes_s:("beacon_only")`, which is this
     * clause. The constant is here for code that needs the population without going through a
     * request.
     */
    public const HAS_LOG_PLANE = '-planes_s:beacon_only';

    /**
     * Sessions that are still open — partial counts, provisional verdicts (SPEC §4.2).
     *
     * Offered so a view can single them out deliberately, which is the point of the field: the
     * session explorer can badge a live session, and "is anything happening right now" becomes a
     * one-facet question. It is never the right filter for an aggregate.
     */
    public const PROVISIONAL_SESSIONS = 'provisional_b:true';

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

            /* TWO MORE THAT ARE NOT VERDICTS, and they are here because the headline tiles on
               the Networks page name them. `all` is the whole scope with nothing added, which is
               what "Sessions: 3" is a count of; without it a tile that names every visit had no
               way to show one. `datacentre` is the pair of network types that tile counts —
               hosting and VPN — and it has to be one clause, because a dimension filter can
               carry a single value and this population is two. */
            'all'        => '*:*',
            'datacentre' => 'as_type_s:(hosting OR vpn)',
        ];
    }

    /**
     * Which of the five populations a given VERDICT rolls up into.
     *
     * ------------------------------------------------------------------------------------
     * ONE DEFINITION, READ BY BOTH PAGES
     * ------------------------------------------------------------------------------------
     * The panel speaks two vocabularies about the same sessions and always will, because they
     * answer different questions. The Overview groups by POPULATION — Humans, Unknown, Declared
     * crawlers, AI crawlers, Evasive bots — which is "what KIND of thing was this". The session
     * explorer's Verdict dimension lists the five stored verdicts — human, likely_human,
     * unknown, likely_bot, bot — which is "how confident are we". Both are legitimate and
     * neither can replace the other: the populations fold two verdicts into Humans and split two
     * across three bot classes.
     *
     * What is NOT legitimate is the reader having no way to tell that they are the same
     * sessions. Overview said Humans 7; the facet beside it said Human 4 and Likely human 1; and
     * nothing on either screen said those were the same number seen two ways. So this map
     * exists, it is the ONLY statement of the relationship, and Panel\Vocabulary reads it when
     * it explains a verdict — which means the facet row for `likely_human` now says which
     * headline counter it is inside, and the two can only drift if this table is edited.
     *
     * `bot` and `likely_bot` map to null DELIBERATELY rather than to a fourth name. Their
     * population is not decided by the verdict at all — it is decided by `bot_class_s` and
     * `ai_crawler_b`, which is why POP_DECLARED, POP_AI and POP_EVASIVE all carry a class
     * clause. Answering with a single name here would be a guess dressed as a fact, and callers
     * are expected to handle the null by naming all three.
     *
     * @return array<string,string|null> verdict => population key, or null when the class decides
     */
    public static function populationOfVerdict(): array
    {
        return [
            'human'        => 'human',
            'likely_human' => 'human',
            'unknown'      => 'unknown',
            'likely_bot'   => null,
            'bot'          => null,
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
            'all'        => 'All sessions',
            'beacon'     => 'Sessions with beacon data',
            'datacentre' => 'Visits from hosting or VPN networks',
        ];
    }

    /**
     * Time ranges the UI is allowed to ask for.
     *
     * Solr date math is used rather than formatted timestamps so the range is evaluated
     * by Solr against its own clock; there is no timezone skew between PHP and Solr to
     * get wrong. `secs` drives the bucket-size choice and the sparkline geometry.
     *
     * `short` is what the duration control prints. It is declared rather than derived from the
     * key, because "All time" is not a duration and upper-casing its key would produce "ALL".
     *
     * ALL TIME IS UNBOUNDED, AND ONLY THE FILTER KNOWS IT. `unbounded` makes rangeFq() emit no
     * date clause at all, so every total, table and facet under it covers the whole index — which
     * is what the operator asked for. `start` and `gap` stay valid Solr date math because a
     * RANGE FACET cannot have an open start: a time series needs a finite axis, so the chart on
     * such a page covers the last year in weekly buckets while the figures beside it cover
     * everything. Both are honest; they are answering different questions.
     *
     * @return array<string,array{label:string,short:string,start:string,secs:int,gap:string,fmt:string,unbounded?:bool}>
     */
    public static function ranges(): array
    {
        return [
            '1h'  => ['label' => 'Last hour',    'short' => '1H',  'start' => 'NOW-1HOUR/MINUTE',  'secs' => 3600,    'gap' => '+2MINUTE', 'fmt' => 'time'],
            '3h'  => ['label' => 'Last 3 hours', 'short' => '3H',  'start' => 'NOW-3HOUR/MINUTE',  'secs' => 10800,   'gap' => '+5MINUTE', 'fmt' => 'time'],
            '6h'  => ['label' => 'Last 6 hours', 'short' => '6H',  'start' => 'NOW-6HOUR/MINUTE',  'secs' => 21600,   'gap' => '+15MINUTE','fmt' => 'time'],
            '24h' => ['label' => 'Last 24 hours','short' => '24H', 'start' => 'NOW-24HOUR/HOUR',   'secs' => 86400,   'gap' => '+1HOUR',   'fmt' => 'hour'],
            '7d'  => ['label' => 'Last 7 days',  'short' => '7D',  'start' => 'NOW-7DAY/HOUR',     'secs' => 604800,  'gap' => '+3HOUR',   'fmt' => 'hour'],
            '30d' => ['label' => 'Last 30 days', 'short' => '30D', 'start' => 'NOW-30DAY/DAY',     'secs' => 2592000, 'gap' => '+1DAY',    'fmt' => 'day'],
            '90d' => ['label' => 'Last 90 days', 'short' => '90D', 'start' => 'NOW-90DAY/DAY',     'secs' => 7776000, 'gap' => '+1DAY',    'fmt' => 'day'],
            'all' => ['label' => 'All time',     'short' => 'All time', 'start' => 'NOW-1YEAR/DAY', 'secs' => 31536000, 'gap' => '+7DAY',  'fmt' => 'day', 'unbounded' => true],
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
     * AN UNBOUNDED RANGE PRODUCES `*:*`, not a wide window. "All time" means no date filter at
     * all, and the shape of this method's contract — every caller splices the result into an
     * `fq` array literal — makes a match-everything clause the honest spelling of "no clause":
     * it costs nothing, it cannot be forgotten at a call site, and `field:[* TO *]` would have
     * been wrong in a way that is hard to see, because it drops every document that has no
     * value for the field.
     *
     * @param string $field `ts_start` on the sessions core, `ts` on hits.
     */
    public static function rangeFq(string $field, array $range): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        if (!empty($range['unbounded'])) {
            return '*:*';
        }
        return $field . ':[' . $range['start'] . ' TO ' . self::rangeEnd($range) . ']';
    }

    /**
     * The upper bound of a range, rounded to the same unit its lower bound is rounded to.
     *
     * ------------------------------------------------------------------------------------
     * THE DEFECT THIS FIXES: TWO PAGES THAT CANNOT AGREE BY CONSTRUCTION
     * ------------------------------------------------------------------------------------
     * The upper bound used to be a bare `NOW`, which Solr re-evaluates on every request, to the
     * millisecond. The lower bound is rounded — `NOW-1HOUR/MINUTE` — so the window's start moved
     * once a minute while its end moved continuously. Two cards on one screen therefore covered
     * two different windows, and two PAGES opened a minute apart covered windows that differed
     * by a whole minute of traffic at both ends.
     *
     * That is how the Overview and the session explorer came to report different numbers for
     * what the operator was told was the same range: Overview counted 7 humans and 14 unknown,
     * the Sessions verdict facet counted 5 and 19. Neither was wrong. They were answers to two
     * questions that differed by however long the reader took to click.
     *
     * Rounding the end to the SAME unit as the start makes the window a fixed interval for the
     * whole of that unit, so every query issued in the same minute — or hour, or day — is
     * literally the same question, and two pages can only disagree if the data changed inside
     * the window they both name. It also makes the clause a cache key Solr can actually reuse:
     * a bare `NOW` produces a distinct filter string per request and never hits the filter
     * cache, which is why a dashboard of a dozen cards was a dozen full scans.
     *
     * IT ROUNDS UP, NOT DOWN. `NOW/MINUTE` would truncate, and truncating discards the newest
     * traffic — up to a minute on the short ranges and up to a DAY on the 30- and 90-day ones,
     * where the most recent day is usually what somebody is looking at. `/MINUTE+1MINUTE` is the
     * end of the current unit rather than the start of it, so nothing that has been indexed is
     * outside the window. The bound is in the near future and matches no document that does not
     * exist yet, which costs nothing.
     *
     * The unit is derived from the lower bound's own rounding rather than declared a second
     * time, so a range added to the table cannot acquire a mismatched pair.
     *
     * @param array<string,mixed> $range A range definition from ranges().
     */
    public static function rangeEnd(array $range): string
    {
        $start = (string) ($range['start'] ?? '');
        $slash = strrpos($start, '/');
        if ($slash === false) {
            return 'NOW';
        }
        $unit = substr($start, $slash + 1);
        if (preg_match('/^[A-Z]+$/D', $unit) !== 1) {
            return 'NOW';
        }

        return 'NOW/' . $unit . '+1' . $unit;
    }

    /**
     * The lower bound a DATE-RANGE filter on the Opensolr request-log plane should carry.
     *
     * That plane cannot take a `*:*` clause the way rangeFq() emits one — its filters are built
     * by \Loghound\OpensolrLog, which composes `date:[from TO to]` and validates each bound — so
     * "no date filter" is expressed there as an open lower bound instead. `*` is inside the bound
     * pattern OpensolrLog::assertBound() accepts, so this stays inside the plane's own contract
     * rather than routing around it.
     */
    public static function filterStart(array $range): string
    {
        return empty($range['unbounded']) ? (string) $range['start'] : '*';
    }

    /**
     * The time window immediately before the selected one, of the same length.
     *
     * WHAT "TRENDING" NEEDS THAT "TOP" DOES NOT. A top-N list ranks by how much traffic something
     * had; a trending list ranks by how much MORE it had than usual, which is meaningless without
     * saying what "usual" is. The baseline chosen here is the equivalent window immediately before
     * the selected one — the previous seven days for a seven-day view, the previous hour for an
     * hourly one — because it is the only baseline a reader can reconstruct from what the page
     * already tells them, and because it holds the day of the week and the time of day roughly
     * constant, which a fixed baseline like "the last 30 days" does not.
     *
     * IT IS NOT LIKE FOR LIKE AT THE EDGE, and the cards say so. The selected window runs up to
     * NOW and its start is rounded down (`NOW-24HOUR/HOUR`), so it is up to one bucket longer than
     * the baseline AND its final bucket is still filling. A page can therefore appear to be down
     * purely because the current period has not finished. Every card built on this states it.
     *
     * Built entirely from the range table's own date-math strings and its integer length, so no
     * part of it can originate in a request.
     *
     * @param string $field `ts_start` on the sessions core, `ts` on hits.
     * @param array<string,mixed> $range A resolved range from self::range().
     */
    public static function previousRangeFq(string $field, array $range): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        $secs = max(60, (int) $range['secs']);

        return $field . ':[' . $range['start'] . '-' . $secs . 'SECOND TO ' . $range['start'] . '}';
    }

    /**
     * Both windows at once: the selected range and the baseline before it.
     *
     * Used as the `fq` of a trending query, whose two halves are then separated by query
     * sub-facets. One request rather than two, and the two halves cannot end up scoped by
     * different filters because there is only one scope.
     *
     * @param array<string,mixed> $range
     */
    public static function spanningRangeFq(string $field, array $range): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        $secs = max(60, (int) $range['secs']);

        return $field . ':[' . $range['start'] . '-' . $secs . 'SECOND TO NOW]';
    }

    /**
     * A filter matching everything older than N days on a date field.
     *
     * Built entirely from a validated field name and a clamped integer, so no part of it
     * can originate in a request. Used by the retention preview.
     *
     * @throws \InvalidArgumentException when the field name is not on the safe pattern.
     */
    public static function rangeUntil(string $field, int $days): string
    {
        if (!Security::isSafeFieldName($field)) {
            throw new \InvalidArgumentException('Unsafe range field');
        }
        return $field . ':[* TO NOW-' . Security::clampInt($days, 1, 3650, 90) . 'DAY]';
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
            'host_s'        => 'Virtual host',
            'bot_verdict_s' => 'Verdict',
            'bot_class_s'   => 'Bot class',
            'as_type_s'     => 'Network type',
            'country_s'     => 'Country',
            'browser_s'     => 'Browser',
            'os_s'          => 'OS',
            'device_s'      => 'Device',
            'ua_bot_cat_s'  => 'Declared bot category',
            'referer_type_s' => 'Referrer type',

            /* THE SITE THAT SENT THEM, which was on both cores and on neither allowlist. The
               referrer TYPE answers "was this organic or paid"; the HOST answers "which of the
               forty sites linking to us is actually sending people", which is the question the
               analytics section is for and which could not be asked at all. Present on both
               schemas, so it needs no exclusion on either plane. */
            'referer_host_s' => 'Referring site',
            'bot_reasons_ss' => 'Signal fired',

            /* WHAT THEY TYPED INTO YOUR OWN SEARCH BOX. The field was indexed on both cores and
               already named in multiValuedFilterFields(), but it was never listed here — so it
               could be stored and never asked about: no dimension, no label, and no group in
               any breakdown. A visit that searched for something is the most legible thing a
               visit can do, and it was the one thing the dialogs could not say. */
            'search_terms_ss' => 'Search terms',
            'as_org_s'      => 'AS organisation',
            'netname_s'     => 'Netname',
            'fp_hash_s'     => 'Fingerprint',
            'ip_s'          => 'IP',
            'session_id_s'  => 'Session',
            'sec_ch_ua_s'      => 'Client hints (Sec-CH-UA)',
            'sec_ch_platform_s' => 'Client platform',
            'tls_proto_s'      => 'TLS version',
            'ua_bot_name_s'    => 'Declared crawler',
            'city_s'           => 'City',
            'region_s'         => 'Region',
            'asn_i'            => 'ASN',
            'paths_ss'         => 'Path',

            /* WHERE A VISIT STARTED AND WHERE IT ENDED, which are different questions from "which
               paths did it touch" and were not askable at all. `paths_ss` is the union over a
               visit, so filtering by it answers "visits that saw /pricing at some point"; the
               analytics section needs "visits that ARRIVED on /pricing", which is what a landing
               page is. Both are SESSION-ONLY: a hit has a `path_s` and no notion of being the
               first or last of anything, so both are excluded from the hits plane below. */
            'entry_path_s'     => 'Landing page',
            'exit_path_s'      => 'Exit page',
            'signed_in_b'      => 'Signed in',

            /* THE NAME THE MEASURED SITE ATTACHED, and a real dimension rather than a field that
               merely rides along on the document. It was in sessionFl() — returned with every
               session, visible in a drill-down — but absent from this list, so it could not be
               faceted, filtered or opened. "Who was here" is the first question anybody asks of
               a signed-in visit, and it had no answer. Sessions-only by construction: a request
               carries no identity, the session it belongs to does. */
            'ident_s'          => 'Signed-in visitor',
            'planes_s'         => 'Planes',
            'search_terms_ss'  => 'Search term',

            /* THE STATUS DIMENSIONS, AND WHY THERE ARE TWO OF THEM. `status_class_s` is what an
               operator asks — was it answered, redirected, refused, or did it break — and it is
               four buckets a reader can take in. `status_i` is what an investigator asks, and 403
               apart from 401 is a real question that a class cannot answer. Offering only the
               class would make the panel coarser than the data; offering only the code would put
               a sixty-row facet in a sidebar.

               BOTH ARE HITS-ONLY (see hitsOnlyFields), because a status belongs to a REQUEST. A
               session that recorded one 2xx and one 4xx tells you nothing about which of its
               requests was which, and a session-plane filter on a field the sessions core does
               not define would match nothing while looking like it worked. */
            'status_class_s'   => 'Status class',
            'status_i'         => 'Status code',

            /* Present on BOTH cores at different grains: on a hit it is what that request
               matched, on a session it is the union across its requests. Same vocabulary, so one
               name (Score\Attacks). */
            'hit_flags_ss'     => 'Attack pattern',
        ];
    }

    /**
     * Dimensions the HITS core defines and the sessions core does not.
     *
     * The mirror image of the `$sessionOnly` list in hitFilterFields(), and it exists for the
     * same reason: an `fq` naming a field a core does not define matches NOTHING, so a status
     * filter carried onto a sessions-core view would empty every card under a chip that says it
     * is merely narrowing. Zero results that look like an answer is the one failure mode the
     * whole facet layer is built to prevent.
     *
     * @return array<int,string>
     */
    public static function hitsOnlyFields(): array
    {
        return ['status_i', 'status_class_s'];
    }

    /**
     * The subset of filterFields() the SESSIONS core can answer.
     *
     * Derived by subtraction, exactly as hitFilterFields() is, so a dimension added to the
     * master list is available on both planes by default and has to be excluded on purpose.
     *
     * @return array<string,string>
     */
    public static function sessionFilterFields(): array
    {
        return array_diff_key(self::filterFields(), array_flip(self::hitsOnlyFields()));
    }

    /**
     * The filterable fields that hold a LIST per document rather than one value.
     *
     * This is the list that decides where the "All of" operator appears, and it is a schema
     * fact rather than a preference: on a single-valued field `a AND b` is empty by
     * construction, so offering the control there would give an operator a button whose only
     * possible answer is zero results. Measured against a real Solr node to be sure of the
     * claim rather than reasoning about it — on a single-valued string field the AND form
     * returned 0 where OR returned 485; on a multi-valued one it returned 74 where OR returned
     * 163.
     *
     * Both entries are `multiValued="true"` in solr/sessions/conf/schema.xml:
     *   `paths_ss`        every distinct path the session touched
     *   `bot_reasons_ss`  every scoring rule that fired on it
     *
     * A field added to the schema as multi-valued and left out of here loses the operator
     * rather than breaking, which is the safe direction; the reverse would produce an empty
     * view. tests/test_facets.php reads the schema and fails if the two disagree.
     *
     * @return array<int,string>
     */
    public static function multiValuedFilterFields(): array
    {
        return ['paths_ss', 'bot_reasons_ss', 'search_terms_ss', 'hit_flags_ss'];
    }

    /**
     * The type of each filterable field, for fields where a quoted literal is the wrong shape.
     *
     * Everything absent from this map is a string and is quoted into a Solr literal, which is
     * what makes an AS organisation full of Lucene operators match as text. The two exceptions
     * are declared because a value that cannot BE that type has to be refused at the request
     * boundary rather than sent:
     *
     *   `asn_i`       a point int. `asn_i:("nonsense")` is a Solr 400, and a 400 reaches the
     *                 operator as an error banner across a page whose cards are all fine.
     *   `signed_in_b` a boolean, whose only two values are the words Solr writes.
     *
     * @return array<string,string> field => 'string'|'int'|'bool'
     */
    public static function filterFieldKinds(): array
    {
        return [
            'asn_i'       => 'int',
            'status_i'    => 'int',
            'signed_in_b' => 'bool',
        ];
    }

    /**
     * The cross-tabulations worth asking, per view, as `[outer, inner, question]`.
     *
     * A pivot is added where a cross-tab is the ACTUAL question an operator has on that view,
     * and nowhere else. A nested facet costs buckets × buckets, and a pivot that repeats what
     * the view's ordinary facets already answer is a second round trip bought for nothing —
     * so there is no pivot on the session explorer, where the dimension dialog already breaks
     * a value down along every other dimension, and none on the Opensolr analytics views,
     * where the platform's classic faceting cannot nest at all.
     *
     * Each one is clickable through to the filtered view like every other facet value, because
     * a cell that names a population and cannot be opened is a dead end.
     *
     * THREE ENTRIES, AND THE OMISSIONS ARE THE POINT. Every other view was considered and left
     * out for a stated reason:
     *
     *   Virtual hosts  ALREADY a cross-tab. Panel\Hosts nests the five population queries inside
     *                  its host facet, so host × verdict is on screen. A pivot would be a second
     *                  round trip for a number already there.
     *   Fingerprints   ALREADY answered, and better. The cluster table carries `unique(asn_i)` and
     *                  `unique(country_s)` PER FINGERPRINT, which is the actual spread question;
     *                  a pivot would answer it for the whole population instead.
     *   Performance    The cross-tab an operator wants is status code by virtual host. It is now
     *                  POSSIBLE — `status_class_s` is a hits-plane dimension and its cells are
     *                  openable — and it is still not here, because Performance's own status
     *                  heatmap already crosses status against TIME, which is the question that
     *                  view is for. Attacks takes the status pivot, where it is the whole point.
     *   Sessions       The dimension dialog already breaks any value down along every other
     *                  dimension, on demand, for the value the operator actually clicked.
     *   Index
     *   analytics      The platform's endpoint offers classic faceting only and cannot nest at all
     *                  (\Loghound\OpensolrLog, "what reaches the platform").
     *
     * @return array<string,array{0:string,1:string,2:string}>
     */
    /**
     * The population a VIEW is about, as sessions-core `fq` clauses.
     *
     * THE FILTER RAIL COUNTS WHAT THE PAGE COUNTS. The rail is one shared request for every
     * view, so it was answering "how many sessions in total came from Romania" while sitting
     * beside a page whose every other number is about attacks — 55 next to a table showing
     * none. A count that does not describe the page it is printed on is worse than no count:
     * the reader picks the value and lands on an empty table.
     *
     * Keyed by view slug, like pivots(), and DELIBERATELY SHORT. A view earns an entry here
     * only when it has one fixed population; the views that offer a humans/bots switch have a
     * CONTROL, not a scope, and giving them a fixed one here would silently override the
     * reader's own choice. Everything absent from this table keeps the whole-traffic counts,
     * which is the honest answer for Overview, Sessions, Networks and the rest.
     *
     * @return array<int,string>
     */
    public static function viewScope(string $view): array
    {
        switch ($view) {
            case 'attacks':
                return [self::attackFq()];
            case 'searches':
                return ['search_terms_ss:*'];
            default:
                return [];
        }
    }

    public static function pivots(): array
    {
        return [
            'overview' => ['country_s', 'bot_verdict_s',
                'Which countries send humans and which send automation.'],
            'bots' => ['bot_class_s', 'as_type_s',
                'Where each kind of bot comes from.'],
            'networks' => ['as_type_s', 'bot_verdict_s',
                'Whether a network type is carrying people or automation.'],

            /* THE ONE CROSS-TAB THIS PRODUCT EXISTS TO PRINT. Every other tool in this category
               lists the scary-looking requests and stops. What an operator needs is that list
               crossed with WHAT THE SERVER ANSWERED, because a traversal attempt answered 404 is
               the background radiation of the internet and the same attempt answered 200 is an
               incident. Both cells are openable, so "show me the ones that got a 200" is one
               click from the grid. */
            'attacks' => ['hit_flags_ss', 'status_class_s',
                'What the server answered each kind of probe with.'],
        ];
    }

    /**
     * The subset of filterFields() the HITS core can answer.
     *
     * The two schemas are deliberately different: a verdict, a bot class and the list of
     * signals that fired are conclusions the scorer reaches about a whole session, and they
     * exist only on the sessions core. An `fq` naming a field a core does not define matches
     * nothing at all, so a hits-core view given the full list would answer every filtered
     * question with zero rather than with the answer it could have given.
     *
     * Derived by subtraction rather than by listing what is shared, so a filter added to
     * filterFields() is available on both cores by default and has to be excluded on
     * purpose. Adding a session-only field without excluding it here is caught by the test
     * that checks every name in this list against solr/hits/conf/schema.xml.
     *
     * @return array<string,string>
     */
    public static function hitFilterFields(): array
    {
        $sessionOnly = [
            'bot_verdict_s',
            'bot_class_s',
            'bot_reasons_ss',
            'paths_ss',
            'entry_path_s',
            'exit_path_s',
            'signed_in_b',
            'ident_s',
            'planes_s',
        ];

        return array_diff_key(self::filterFields(), array_flip($sessionOnly));
    }

    /**
     * Sidebar fields that are spelled differently on the sessions core.
     *
     * A hit points at the session it belongs to through `session_id_s`; a session document
     * IS that session, so the same value is its `id`. The sessions core therefore does not
     * define `session_id_s` at all, and a Session chip taken straight from the sidebar
     * matched nothing on every sessions-core view — a filter that answers zero rather than
     * refusing, which reads as "this session has no traffic" instead of "this filter is
     * broken".
     *
     * @return array<string,string>
     */
    public static function sessionFilterAliases(): array
    {
        return ['session_id_s' => 'id'];
    }

    /**
     * The field that names the virtual host a request arrived on.
     *
     * `host_s` is on every hit (SPEC §4.1, from `%v`) and on every session document, where
     * the sessionizer copies it from the first hit. It was missing from filterFields()
     * above, which meant the dashboard blended every vhost on the machine into one view: on
     * a box serving six sites, "which of my sites takes the most bot traffic" — the question
     * a multi-site install actually has — could not be asked at all.
     *
     * It is a first-class filter now, so it flows through Controller::filterFqs() and scopes
     * EVERY query on EVERY view, rather than being a control on one card.
     */
    public const HOST_FIELD = 'host_s';

    /**
     * The facet that lists the hosts present in a range, for the selector.
     *
     * The limit is generous but bounded: a machine with more virtual hosts than this has a
     * different problem, and an unbounded terms facet on a string field is a way to ask Solr
     * for every distinct value it has ever seen.
     *
     * @return array<string,mixed>
     */
    public static function hostFacet(int $limit = 200): array
    {
        return [
            'hosts' => [
                'type'     => 'terms',
                'field'    => self::HOST_FIELD,
                'limit'    => Security::clampInt($limit, 1, 500, 200),
                'mincount' => 1,
                'sort'     => 'count desc',
            ],
        ];
    }

    /**
     * The `fq` that scopes a query to one virtual host, or null for "every host".
     *
     * An empty selection deliberately produces NO filter rather than a filter matching
     * nothing: "all hosts" is the default view of a multi-site install, and a selector that
     * silently emptied the dashboard when nothing was picked would be read as "no traffic".
     */
    public static function hostFq(string $host): ?string
    {
        $host = trim($host);
        return $host === '' ? null : self::term(self::HOST_FIELD, $host);
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
     *
     * `provisional_b` is on the list because a row whose counts are still moving has to be able
     * to say so. Absent on a settled session, so the front end reads it as a flag, not a boolean
     * with two meanings.
     */
    public static function sessionFl(): string
    {
        return implode(',', [
            'id', 'ts_start', 'ts_end', 'host_s', 'hits_i', 'pages_i', 'assets_i', 'uniq_paths_i',
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
            'provisional_b',
            'ident_s', 'signed_in_b',
            'planes_s', 'search_terms_ss',
            'js_b', 'headless_b', 'automation_ss', 'ua_claim_ok_b', 'tz_match_b', 'webgl_s',
            'bot_score_f', 'bot_verdict_s', 'bot_reasons_ss', 'bot_class_s', 'rule_version_i',
            'hit_flags_ss', 'hit_rules_i',
        ]);
    }

    /** The field list for a single hit in the session drill-down timeline. */
    public static function hitFl(): string
    {
        return implode(',', [
            'id', 'ts', 'host_s', 'method_s', 'path_s', 'query_s', 'status_i', 'bytes_l', 'dur_us_l',
            'kind_s', 'asset_kind_s', 'proto_s', 'referer_s', 'session_seq_i',
            'hit_flags_ss', 'hit_rules_i', 'status_class_s',
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
        while (preg_match('/^\{![^}]*\}/', $text)) {
            $text = trim((string) preg_replace('/^\{![^}]*\}/', '', $text));
        }
        if ($text === '') {
            return ['q' => '*:*'];
        }
        return [
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
