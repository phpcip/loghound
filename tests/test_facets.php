<?php
/**
 * Loghound — the facet layer: tagging, exclusion, the three operators, the URL contract.
 *
 * WHAT THESE TESTS ARE PROTECTING. The defect this component was built to fix is invisible in a
 * unit test unless it is stated as one: a filter applied without a tag sits inside its own
 * facet, so the dimension the operator just used collapses to a single value and a second one
 * can never be chosen. Several tests below assert the tag and the matching `excludeTags` rather
 * than merely that a filter was produced, because "a filter was produced" is exactly what the
 * broken version also did.
 *
 * The Solr behaviour itself was verified against a live node while this was written — a tagged
 * filter with its own facet excluded returned both values where the untagged one returned one,
 * a pure-negative filter returned the complement, and an AND within a single-valued field
 * returned nothing where the same shape on a multi-valued field returned the intersection.
 * SPEC §12 forbids a network call from the suite, so what is asserted HERE is that the strings
 * we send are the strings that were verified, and that our own sanitisers accept them.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Panel\Facets;
use Loghound\Panel\Query;
use Loghound\Panel\Vocabulary;
use Loghound\Score\Rules;

/** A selection on the sessions plane, built from a request array. */
function lh_f(array $f): Facets
{
    return Facets::sessions(['f' => $f]);
}

/** The facet definition for one dimension out of a termsFacets() call. */
function lh_def(Facets $facets, string $field, int $limit = 12): array
{
    $defs = $facets->termsFacets([$field], $limit);
    return $defs[$field] ?? [];
}

/** A minimal Solr facet response for one terms dimension. */
function lh_buckets(string $field, array $pairs, ?int $numBuckets = null): array
{
    $buckets = [];
    foreach ($pairs as $value => $count) {
        $buckets[] = ['val' => $value, 'count' => $count];
    }
    $node = ['buckets' => $buckets];
    if ($numBuckets !== null) {
        $node['numBuckets'] = $numBuckets;
    }
    return ['count' => array_sum($pairs), $field => $node];
}

if (!function_exists('lh_fx_values')) {
    /**
     * Drive Sessions::values() against a recording transport, and hand back both halves.
     *
     * The REAL Solr client, so every request is judged by the sanitisers production applies and a
     * pass here means the strings we send are strings Solr was given. The facet response is
     * supplied by the caller, which is the only way to exercise a TRUNCATED dimension: the demo
     * world is 1,400 sessions over a 20-path pool, so nothing in it can exceed a 2,000-value
     * listing and the truncated branch is unreachable there by construction.
     *
     * @param array<string,mixed> $get
     * @param array<string,mixed> $facets The `facets` block Solr answers with.
     * @return array{0:array<string,mixed>,1:array<int,array<string,mixed>>}
     */
    function lh_fx_values(array $get, array $facets, int $numFound = 0): array
    {
        $saved = $_GET;
        $_GET = $get;
        $captured = [];
        try {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-config');
            $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
            $cfg->set('solr.sessions_core', 'lh_fx_sessions');
            $cfg->set('solr.hits_core', 'lh_fx_hits');

            $transport = function (array $request) use (&$captured, $facets, $numFound): array {
                $captured[] = $request;
                return [
                    'status' => 200,
                    'body'   => (string) json_encode([
                        'responseHeader' => ['status' => 0],
                        'response'     => ['numFound' => $numFound, 'docs' => []],
                        'facets'       => $facets,
                        'facet_counts' => ['facet_fields' => $facets['_classic'] ?? []],
                    ]),
                    'error'  => '',
                ];
            };
            $gw = new \Loghound\Panel\Gateway($cfg, new \Loghound\Solr((array) $cfg->get('solr'), $transport), false);
            $result = (new \Loghound\Panel\Sessions($cfg, $gw))->api('values');
        } finally {
            $_GET = $saved;
        }
        return [$result, $captured];
    }

    /** Every parameter of every captured request, decoded. */
    function lh_fx_params(array $captured): array
    {
        $out = [];
        foreach ($captured as $request) {
            foreach (explode('&', (string) ($request['body'] ?? '')) as $pair) {
                if ($pair === '') {
                    continue;
                }
                [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
                $out[rawurldecode($k)][] = rawurldecode(str_replace('+', ' ', $v));
            }
        }
        return $out;
    }
}

return [

    /* -----------------------------------------------------------------------
     * The bug: a dimension must keep listing every value it has
     * -------------------------------------------------------------------- */

    'a filtered dimension carries a tag, so its own facet can ignore it' =>
        function (): void {
            $facets = lh_f(['host_s' => ['opensolr.com']]);

            lh_same(
                ['{!tag=f_host_s}host_s:("opensolr.com")'],
                $facets->fqs(),
                'the clause must be tagged; an untagged one is inside its own facet'
            );
            lh_same(
                ['excludeTags' => ['f_host_s']],
                lh_def($facets, 'host_s')['domain'] ?? null,
                'the host facet must exclude the host filter and nothing else'
            );
        },

    'a dimension with no filter on it is not given an exclusion' =>
        function (): void {
            $facets = lh_f(['host_s' => ['opensolr.com']]);

            lh_no_key(
                lh_def($facets, 'country_s'),
                'domain',
                'excluding a tag that is not in force would be noise, and would read as a bug'
            );
        },

    'each dimension excludes only its own tag, so every other one still narrows' =>
        function (): void {
            $facets = lh_f([
                'host_s'        => ['opensolr.com'],
                'bot_verdict_s' => ['human'],
            ]);
            $defs = $facets->termsFacets(['host_s', 'bot_verdict_s', 'country_s'], 12);

            lh_same(['f_host_s'], $defs['host_s']['domain']['excludeTags'], 'host excludes host');
            lh_same(['f_bot_verdict_s'], $defs['bot_verdict_s']['domain']['excludeTags'], 'verdict excludes verdict');
            lh_no_key($defs['country_s'], 'domain', 'country is filtered by both and excludes neither');
        },

    'the whole sidebar is one Solr request, however many dimensions it has' =>
        function (): void {
            $fields = array_keys(Query::filterFields());
            $defs = lh_f(['country_s' => ['DE']])->termsFacets($fields, 12);

            lh_eq(count($fields), count($defs), 'one definition per dimension, in one json.facet');
            foreach ($defs as $name => $def) {
                lh_same('terms', $def['type'], $name . ' must be a terms facet');
            }
        },

    /* -----------------------------------------------------------------------
     * The three operators
     * -------------------------------------------------------------------- */

    'any of is the default, and is what an operator-less URL means' =>
        function (): void {
            $facets = lh_f(['country_s' => ['DE', 'FR']]);

            lh_same(Facets::OP_ANY, $facets->op('country_s'), 'an absent op is "any of"');
            lh_same(
                ['{!tag=f_country_s}country_s:("DE" OR "FR")'],
                $facets->fqs(),
                'values within one dimension are OR-ed'
            );
        },

    'none of excludes the selected values, for one value and for a set' =>
        function (): void {
            $one = lh_f(['as_type_s' => ['hosting', 'op' => 'none']]);
            lh_same(
                ['{!tag=f_as_type_s}-as_type_s:("hosting")'],
                $one->fqs(),
                '"everything except hosting" must be a pure negative on the dimension'
            );

            $many = lh_f(['bot_class_s' => ['declared_crawler', 'monitor', 'op' => 'none']]);
            lh_same(
                ['{!tag=f_bot_class_s}-bot_class_s:("declared_crawler" OR "monitor")'],
                $many->fqs(),
                'a set is excluded as one negated OR group, not as two clauses'
            );
        },

    'all of is offered on a multi-valued dimension and honoured' =>
        function (): void {
            $facets = lh_f(['paths_ss' => ['/a', '/b', 'op' => 'all']]);

            lh_same(Facets::ARITY_MULTI, $facets->arity('paths_ss'), 'paths_ss holds a list per session');
            lh_same(
                ['{!tag=f_paths_ss}paths_ss:("/a" AND "/b")'],
                $facets->fqs(),
                'sessions that touched BOTH paths'
            );
        },

    'all of is neither offered nor honoured on a single-valued dimension' =>
        function (): void {
            $facets = lh_f(['country_s' => ['DE', 'FR', 'op' => 'all']]);

            lh_same(
                Facets::OP_ANY,
                $facets->op('country_s'),
                'a AND b over one value per document is empty by construction, so it falls back'
            );
            lh_same(
                ['{!tag=f_country_s}country_s:("DE" OR "FR")'],
                $facets->fqs(),
                'and the filter must widen rather than empty the view'
            );

            $ops = array_column($facets->operators('country_s'), 'op');
            lh_false(in_array(Facets::OP_ALL, $ops, true), 'the control must not offer it at all');
            lh_true(in_array(Facets::OP_NONE, $ops, true), 'exclusion is always meaningful');
        },

    'the operator control is offered on every dimension, and states which is in force' =>
        function (): void {
            $facets = lh_f(['bot_reasons_ss' => ['no_assets', 'op' => 'none']]);
            $ops = $facets->operators('bot_reasons_ss');

            lh_eq(3, count($ops), 'a multi-valued dimension offers all three');
            foreach ($ops as $entry) {
                lh_true($entry['label'] !== '', 'every operator needs words on the control');
                lh_true($entry['hint'] !== '', 'and a sentence saying what it does to THIS dimension');
                lh_same($entry['op'] === Facets::OP_NONE, $entry['on'], 'exactly the one in force is marked');
            }
        },

    'the multi-valued list matches the schema, so the control appears where AND can match' =>
        function (): void {
            $schema = (string) file_get_contents(dirname(__DIR__) . '/solr/sessions/conf/managed-schema.xml');

            foreach (Query::multiValuedFilterFields() as $field) {
                lh_true(
                    (bool) preg_match('/name="' . preg_quote($field, '/') . '"[^>]*multiValued="true"/', $schema),
                    $field . ' must really be multiValued in the sessions schema'
                );
            }
            foreach (array_keys(Query::filterFields()) as $field) {
                if (in_array($field, Query::multiValuedFilterFields(), true) || $field === 'session_id_s') {
                    continue;
                }
                lh_false(
                    (bool) preg_match('/name="' . preg_quote($field, '/') . '"[^>]*multiValued="true"/', $schema),
                    $field . ' is offered as single-valued and must not be a list in the schema'
                );
            }
        },

    /* -----------------------------------------------------------------------
     * Injection, types and hostile input
     * -------------------------------------------------------------------- */

    'every clause the layer builds survives the Solr client\'s own filter check' =>
        function (): void {
            $hostile = 'x" OR 1=1 ) AND *:* -a:b "';

            foreach ([Facets::OP_ANY, Facets::OP_ALL, Facets::OP_NONE] as $op) {
                $facets = lh_f([
                    'as_org_s'       => [$hostile, 'op' => $op],
                    'paths_ss'       => ['/a', $hostile, 'op' => $op],
                    'bot_reasons_ss' => ['no_assets', 'op' => $op],
                ]);
                foreach ($facets->fqs() as $fq) {
                    \Loghound\Solr::assertSafeFilter($fq);
                    lh_false(str_contains($fq, "\n"), 'no newline may reach a filter');
                }
            }
        },

    'a field name is never taken from the request' =>
        function (): void {
            $facets = lh_f([
                'host_s'                  => ['ok'],
                'bot_verdict_s:*'         => ['x'],
                'not_a_field_s'           => ['x'],
                '{!frange}'               => ['x'],
                'raw_s'                   => ['x'],
            ]);

            lh_same(['host_s'], $facets->selected(), 'only a field on the allowlist becomes a filter');
        },

    'a value that cannot be the field\'s type is dropped rather than sent' =>
        function (): void {
            lh_same(
                ['15169'],
                lh_f(['asn_i' => ['15169', 'nonsense', '-1x', '']])->values('asn_i'),
                'asn_i is a point int: a quoted non-number is a Solr 400, which becomes an error banner'
            );
            lh_same(
                ['{!tag=f_asn_i}asn_i:(15169)'],
                lh_f(['asn_i' => ['15169']])->fqs(),
                'and a numeric field is not quoted'
            );
            lh_same(
                ['true'],
                lh_f(['signed_in_b' => ['true', 'yes', '1']])->values('signed_in_b'),
                'a boolean takes the two words Solr writes and nothing else'
            );
        },

    'a control character in a value drops the value, it is not stripped out' =>
        function (): void {
            $facets = lh_f(['as_org_s' => ["Tele\x00fonica", 'Orange']]);

            lh_same(
                ['Orange'],
                $facets->values('as_org_s'),
                'stripping would join the halves into a third value nobody asked for'
            );
        },

    'the operator is an allowlist of three, and a crafted one falls back' =>
        function (): void {
            foreach (['", op', 'ALL', 'and', '', 'none;drop'] as $bad) {
                lh_same(
                    Facets::OP_ANY,
                    lh_f(['country_s' => ['DE', 'op' => $bad]])->op('country_s'),
                    'an unrecognised operator must behave as the default'
                );
            }
        },

    'values and their count are both capped' =>
        function (): void {
            $many = array_map(static fn (int $i): string => 'v' . $i, range(1, 60));
            lh_eq(20, count(lh_f(['country_s' => $many])->values('country_s')), 'twenty values per dimension');

            $long = str_repeat('a', 900);
            $kept = lh_f(['as_org_s' => [$long]])->values('as_org_s');
            lh_eq(256, mb_strlen($kept[0]), 'a value is capped at 256 characters');
        },

    'a non-numeric key inside a dimension is not a value' =>
        function (): void {
            $facets = lh_f(['country_s' => [0 => 'DE', 'op' => 'none', 'sneaky' => 'FR']]);

            lh_same(['DE'], $facets->values('country_s'), 'only numeric keys hold values');
            lh_same(Facets::OP_NONE, $facets->op('country_s'), 'and op is read as the operator');
        },

    'the generated tag is a legal Solr tag whatever the field is called' =>
        function (): void {
            foreach (array_keys(Query::filterFields()) as $field) {
                $tag = lh_f([])->tag($field);
                lh_true(
                    (bool) preg_match('/^[A-Za-z0-9_]{1,64}$/', $tag),
                    $field . ' must yield a tag Solr::assertSafeFilter accepts: ' . $tag
                );
            }
        },

    /* -----------------------------------------------------------------------
     * The URL contract
     * -------------------------------------------------------------------- */

    'the URL keeps the values where they were and carries the operator beside them' =>
        function (): void {
            $facets = Facets::sessions([
                'v' => 'networks', 'range' => '7d',
                'f' => ['country_s' => ['DE']],
            ]);
            $url = $facets->urlOperator('country_s', Facets::OP_NONE);

            lh_contains($url, 'f%5Bcountry_s%5D%5B%5D=DE', 'f[country_s][] is unchanged');
            lh_contains($url, 'f%5Bcountry_s%5D%5Bop%5D=none', 'the operator rides in the same array');
            lh_contains($url, 'range=7d', 'the range survives a filter change');
            lh_contains($url, 'v=networks', 'and so does the view');
        },

    'an operator of "any of" is left out of the URL, so an old link is byte-identical' =>
        function (): void {
            $facets = Facets::sessions(['v' => 'overview', 'f' => ['country_s' => ['DE']]]);

            lh_false(
                str_contains($facets->urlFor($facets->selection()), 'op'),
                'the default must not appear, or every shared URL changes shape for nothing'
            );
        },

    'a filter link never carries the API parameters of the request that built it' =>
        function (): void {
            $facets = Facets::sessions([
                'v' => 'sessions', 'api' => 'dimensions', 'field' => 'country_s',
                'value' => 'DE', 'id' => 'abc', 'start' => '200', 'limit' => '300',
                'f' => ['country_s' => ['DE']],
            ]);
            $url = $facets->urlAdd('country_s', 'FR');

            foreach (['api=', 'field=', 'value=', 'id=', 'limit='] as $leak) {
                lh_false(str_contains($url, $leak), 'a page link carrying ' . $leak . ' would answer with JSON');
            }
            lh_false(str_contains($url, 'start='), 'paging resets: page 4 of the old result set is not a place to land');
        },

    'the view can be overridden, because the dimension list is fetched from one view everywhere' =>
        function (): void {
            $facets = Facets::sessions(['v' => 'sessions', 'f' => ['country_s' => ['DE']]]);

            lh_contains(
                $facets->urlAdd('country_s', 'FR', 'networks'),
                'v=networks',
                'a facet pressed on Networks must not navigate to the session explorer'
            );
        },

    'toggling is one gesture: the same link selects and deselects' =>
        function (): void {
            $facets = Facets::sessions(['f' => ['country_s' => ['DE']]]);

            lh_contains($facets->urlToggle('country_s', 'FR'), 'FR', 'an unselected value is added');
            lh_false(
                str_contains($facets->urlToggle('country_s', 'DE'), 'country_s'),
                'the last selected value removes the whole dimension'
            );
        },

    'an operator cannot be set on a dimension that has no values, or to one it does not offer' =>
        function (): void {
            $empty = Facets::sessions([]);
            lh_same('?', $empty->urlOperator('country_s', Facets::OP_NONE), 'nothing to operate on');

            $single = Facets::sessions(['f' => ['country_s' => ['DE']]]);
            lh_false(
                str_contains($single->urlOperator('country_s', Facets::OP_ALL), 'op'),
                'a crafted link must not put a control into a state the UI cannot leave'
            );
        },

    /* -----------------------------------------------------------------------
     * Honest counts
     * -------------------------------------------------------------------- */

    'a dimension whose facet is excluded says its counts are not the page total' =>
        function (): void {
            $facets = lh_f(['host_s' => ['a.example']]);
            $group = $facets->group(
                lh_buckets('host_s', ['a.example' => 15, 'b.example' => 40]),
                'host_s',
                12
            );

            lh_same('excluded', $group['basis'], 'the counts came from a domain with this filter lifted');
            lh_contains($group['basis_note'], 'lifted', 'and the group must say so');
            lh_eq(2, count($group['buckets']), 'every host is still listed, which is the whole fix');
        },

    'a multi-valued dimension says its buckets overlap and cannot be summed' =>
        function (): void {
            $group = lh_f([])->group(
                lh_buckets('bot_reasons_ss', ['no_assets' => 30, 'no_interaction' => 20]),
                'bot_reasons_ss',
                12
            );

            lh_true($group['overlaps'], 'one session can hold several reasons');
            lh_contains($group['basis_note'], 'do not sum', 'a reader adding them up must be warned off');
        },

    'a selected value is still offered when it has fallen out of the top N' =>
        function (): void {
            $facets = lh_f(['country_s' => ['VA']]);
            $group = $facets->group(lh_buckets('country_s', ['DE' => 900, 'FR' => 800]), 'country_s', 2);

            $values = array_column($group['buckets'], 'value');
            lh_true(in_array('VA', $values, true), 'otherwise the filter is on with no way to turn it off');

            foreach ($group['buckets'] as $bucket) {
                if ($bucket['value'] === 'VA') {
                    lh_same(null, $bucket['count'], 'and it must claim no number it does not have');
                }
            }
        },

    'a value being excluded is a third state, never rendered as selected' =>
        function (): void {
            $facets = lh_f(['as_type_s' => ['hosting', 'op' => 'none']]);
            $group = $facets->group(lh_buckets('as_type_s', ['hosting' => 50, 'isp' => 500]), 'as_type_s', 12);

            $states = array_column($group['buckets'], 'state', 'value');
            lh_same('excluded', $states['hosting'], 'a tick beside a value just thrown away would be a lie');
            lh_same('off', $states['isp'], 'and an untouched value is untouched');
        },

    'the distinct-value count is carried when Solr was asked for it' =>
        function (): void {
            $group = lh_f([])->group(lh_buckets('as_org_s', ['A' => 5], 897), 'as_org_s', 12);

            lh_eq(897, $group['distinct'], 'the value browser has to be able to say "the top N of M"');
            lh_true(lh_def(lh_f([]), 'as_org_s') !== [], 'and the definition must be buildable');
            lh_true(
                (bool) (lh_f([])->termsFacets(['as_org_s'], 200, true)['as_org_s']['numBuckets'] ?? false),
                'numBuckets is requested only when the number is going on screen'
            );
        },

    'the Solr client accepts a facet definition this layer builds, exclusions and all' =>
        function (): void {
            $facets = lh_f(['host_s' => ['a.example'], 'paths_ss' => ['/a', '/b', 'op' => 'all']]);
            $defs = array_merge(
                $facets->termsFacets(array_keys(Query::filterFields()), 12, true),
                $facets->pivot('pivot', 'country_s', 'bot_verdict_s')
            );

            $solr = new \Loghound\Solr([
                'base_url' => 'http://127.0.0.1:8983/solr',
                'transport' => static fn (): array => ['status' => 200, 'body' => '{}', 'error' => ''],
            ]);
            $ref = new \ReflectionMethod($solr, 'sanitiseFacet');
            $clean = $ref->invoke($solr, $defs);

            lh_same(
                ['f_host_s'],
                $clean['host_s']['domain']['excludeTags'],
                'the exclusion must survive the sanitiser, or the whole fix is dropped in silence'
            );
            lh_true(isset($clean['pivot']['facet']['by']), 'and a pivot must keep its inner level');
        },

    /* -----------------------------------------------------------------------
     * Pivots
     * -------------------------------------------------------------------- */

    'a pivot is a nested facet, asked of Solr rather than assembled in PHP' =>
        function (): void {
            $def = lh_f([])->pivot('pivot', 'country_s', 'bot_verdict_s', 6, 4)['pivot'];

            lh_same('country_s', $def['field'], 'the outer dimension');
            lh_same('bot_verdict_s', $def['facet']['by']['field'], 'the inner one, nested');
            lh_eq(6, $def['limit'], 'both levels are bounded, because the cost is the product');
            lh_eq(4, $def['facet']['by']['limit']);
            lh_no_key($def, 'domain', 'a pivot is a report, so its numbers must be the filtered ones on the page');
        },

    'a pivot refuses a dimension crossed with itself, and a bad bucket name' =>
        function (): void {
            $facets = lh_f([]);

            lh_same([], $facets->pivot('pivot', 'country_s', 'country_s'), 'a value crossed with itself answers nothing');
            lh_same([], $facets->pivot('a b', 'country_s', 'os_s'), 'a bucket name is ours, and is checked');
            lh_same([], $facets->pivot('pivot', 'country_s; drop', 'os_s'), 'a field name is checked again here');
        },

    'a pivot row reports how much of itself its cells cover' =>
        function (): void {
            $response = ['pivot' => ['buckets' => [
                ['val' => 'DE', 'count' => 100, 'by' => ['buckets' => [
                    ['val' => 'human', 'count' => 60],
                    ['val' => 'bot', 'count' => 25],
                ]]],
            ]]];
            $rows = Facets::pivotRows($response, 'pivot', 'country_s', 'bot_verdict_s');

            lh_eq(100, $rows[0]['count'], 'the row total');
            lh_eq(85, $rows[0]['covered'], 'the inner facet is limited, so the cells do NOT add up to it');
            lh_same('Human', $rows[0]['cells'][0]['label'], 'and a cell reads in words, not in slugs');
        },

    'every pivot pairing names two real, filterable dimensions' =>
        function (): void {
            $fields = Query::filterFields();

            foreach (Query::pivots() as $view => $pivot) {
                lh_true(isset($fields[$pivot[0]]), $view . ': the outer dimension must be filterable to be clickable');
                lh_true(isset($fields[$pivot[1]]), $view . ': so must the inner one');
                lh_true($pivot[0] !== $pivot[1], $view . ': a dimension crossed with itself answers nothing');
                lh_true(strlen($pivot[2]) > 40, $view . ': a cross-tab with no stated question is a grid of numbers');
            }
        },

    /* -----------------------------------------------------------------------
     * Words instead of slugs
     * -------------------------------------------------------------------- */

    'every reason code the scorer can emit has a label and an explanation' =>
        function (): void {
            foreach (Rules::reasonCodes() as $code) {
                lh_has_key(Rules::REASONS, $code, 'a rule with no label surfaces as a slug in the interface');
                $entry = Rules::REASONS[$code];
                lh_true($entry['label'] !== $code, $code . ' needs words, not its own slug');
                lh_true(strlen($entry['why']) > 30, $code . ' needs a sentence saying what it tests');
                lh_true(
                    in_array($entry['severity'], ['high', 'med', 'low', 'info'], true),
                    $code . ' needs a severity'
                );
            }
        },

    'the two codes that are not rules are labelled as absences, not as findings' =>
        function (): void {
            foreach ([Rules::PROVISIONAL_REASON, Rules::CLEAN_REASON] as $code) {
                lh_same('info', Rules::REASONS[$code]['severity'], $code . ' is not an accusation');
            }
            lh_contains(
                Rules::REASONS[Rules::CLEAN_REASON]['why'],
                'absence of evidence',
                'a clean session has not been shown to be human, only not to be caught'
            );
            lh_contains(
                Rules::REASONS[Rules::PROVISIONAL_REASON]['why'],
                'not ended',
                'a provisional session had nothing detected about it'
            );
        },

    'an unknown reason code renders as itself, never as a plausible guess' =>
        function (): void {
            $unknown = Rules::reason('some_rule_added_later');

            lh_same('some_rule_added_later', $unknown['label'], 'the slug is the honest label');
            lh_contains($unknown['why'], 'some_rule_added_later', 'and the sentence says this version does not know it');
            lh_same('some_rule_added_later', Vocabulary::label('bot_reasons_ss', 'some_rule_added_later'));
        },

    'the signal dimension reads in words and keeps the slug as the filter value' =>
        function (): void {
            $facets = lh_f(['bot_reasons_ss' => ['fp_cluster_proxy_fleet']]);
            $group = $facets->group(
                lh_buckets('bot_reasons_ss', ['fp_cluster_proxy_fleet' => 9, 'ua_declared_bot' => 4]),
                'bot_reasons_ss',
                12
            );

            $rows = [];
            foreach ($group['buckets'] as $bucket) {
                $rows[$bucket['value']] = $bucket;
            }
            lh_same('Proxy fleet fingerprint', $rows['fp_cluster_proxy_fleet']['label'], 'the primary text is words');
            lh_same('fp_cluster_proxy_fleet', $rows['fp_cluster_proxy_fleet']['value'], 'the slug stays reachable');
            lh_true($rows['fp_cluster_proxy_fleet']['why'] !== '', 'and carries its explanation for a tooltip');
            lh_same(
                ['{!tag=f_bot_reasons_ss}bot_reasons_ss:("fp_cluster_proxy_fleet")'],
                $facets->fqs(),
                'filtering still happens on the slug — only the presentation changed'
            );
            lh_true($group['vocabulary'], 'and the group tells the renderer a vocabulary applies');
        },

    'every dimension whose values are internal identifiers has a vocabulary' =>
        function (): void {
            foreach (['bot_verdict_s', 'bot_class_s', 'as_type_s', 'referer_type_s', 'ua_bot_cat_s', 'signed_in_b'] as $field) {
                lh_true(Vocabulary::has($field), $field . ' holds slugs and must be spoken in words');
                lh_true(Vocabulary::knownValues($field) !== [], $field . ' has a closed value set');

                foreach (Vocabulary::knownValues($field) as $value) {
                    $spoken = Vocabulary::value($field, $value);
                    lh_true($spoken['label'] !== $value, $field . '/' . $value . ' must not read as its own slug');
                }
            }
        },

    'a dimension holding real-world text is left alone' =>
        function (): void {
            foreach (['host_s', 'as_org_s', 'netname_s', 'city_s', 'browser_s', 'paths_ss', 'ip_s'] as $field) {
                lh_false(Vocabulary::has($field), $field . ' already holds words a person uses');
                lh_same('whatever', Vocabulary::label($field, 'whatever'), 'so the value is its own label');
            }
        },

    'the three verdicts an operator misreads are explained rather than just labelled' =>
        function (): void {
            lh_same('Likely human', Vocabulary::label('bot_verdict_s', 'likely_human'));
            lh_contains(
                Vocabulary::value('bot_verdict_s', 'unknown')['why'],
                'did not reach a verdict',
                'unknown is a finding, not a failure to measure'
            );
            lh_contains(
                Vocabulary::value('bot_class_s', 'declared_crawler')['why'],
                'Honest traffic',
                'SPEC 7: conflating a declared crawler with evasive automation is the defect to avoid'
            );
        },

    'the panel\'s reason catalogue and the rules agree, word for word' =>
        function (): void {
            if (!method_exists(\Loghound\Panel\Bots::class, 'reasonCatalogue')) {
                lh_skip('the panel catalogue has already been folded into Rules');
            }
            foreach (\Loghound\Panel\Bots::reasonCatalogue() as $code => $entry) {
                lh_has_key(Rules::REASONS, $code, $code . ' must be in the one source of truth');
                lh_same($entry['label'], Rules::REASONS[$code]['label'], $code . ': one label, not two');
                lh_same($entry['why'], Rules::REASONS[$code]['why'], $code . ': one explanation, not two');
            }
        },

    'a closed vocabulary can offer a value with no traffic, and marks it as counted' =>
        function (): void {
            $facets = lh_f([]);
            $group = $facets->withKnownValues(
                $facets->group(lh_buckets('bot_verdict_s', ['human' => 40]), 'bot_verdict_s', 12)
            );

            $rows = [];
            foreach ($group['buckets'] as $bucket) {
                $rows[$bucket['value']] = $bucket['count'];
            }
            lh_eq(40, $rows['human']);
            lh_same(0, $rows['bot'], 'zero is a measurement: it was counted over the range and there were none');
            lh_true($group['complete'], 'and the group says the list is the whole vocabulary');
        },

    'an open vocabulary is never padded' =>
        function (): void {
            $facets = lh_f([]);
            $group = $facets->withKnownValues(
                $facets->group(lh_buckets('country_s', ['DE' => 40]), 'country_s', 12)
            );

            lh_eq(1, count($group['buckets']), 'a country list is whatever the traffic held');
            lh_no_key($group, 'complete');
        },

    /* -----------------------------------------------------------------------
     * The two planes
     * -------------------------------------------------------------------- */

    'the hits plane carries no session-only field, and does not borrow the session aliases' =>
        function (): void {
            $hits = Facets::hits(['f' => [
                'bot_verdict_s' => ['human'],
                'session_id_s'  => ['abc'],
                'country_s'     => ['DE'],
            ]]);

            lh_false(in_array('bot_verdict_s', $hits->selected(), true), 'a verdict exists only on sessions');
            lh_same(
                ['{!tag=f_session_id_s}session_id_s:("abc")', '{!tag=f_country_s}country_s:("DE")'],
                $hits->fqs(),
                'on the hits core session_id_s is a real field: rewriting it to id would match nothing'
            );
        },

    'the sessions plane rewrites the session id to the document id' =>
        function (): void {
            lh_same(
                ['{!tag=f_session_id_s}id:("abc")'],
                lh_f(['session_id_s' => ['abc']])->fqs(),
                'a session document IS its session, so the sessions core has no session_id_s'
            );
        },

    'the Opensolr log plane has its own namespace and cannot use tags' =>
        function (): void {
            $labels = \Loghound\Panel\OpensolrView::logFilterFields();
            $log = Facets::log(['lf' => ['path' => ['/select', 'op' => 'none']], 'f' => ['host_s' => ['x']]], $labels);

            lh_same('lf', $log->namespaceKey(), 'the two planes share no field name, so they share no namespace');
            lh_same([], $log->values('host_s'), 'a sessions field is not a request-log field');
            lh_same(
                ['-path:("/select")'],
                $log->fqs(),
                'the platform refuses any {! in a filter, so the clause carries no tag'
            );

            \Loghound\OpensolrLog::assertSafeFq($log->fqs()[0]);
        },

    'on the log plane a facet ignores its own filter by being asked again without it' =>
        function (): void {
            $labels = \Loghound\Panel\OpensolrView::logFilterFields();
            $log = Facets::log(['lf' => ['path' => ['/select'], 'http_status' => ['500']]], $labels);

            lh_no_key(
                $log->termsFacets(['path'], 15)['path'],
                'domain',
                'excludeTags cannot survive the platform endpoint, so it must not be sent'
            );
            lh_same(
                ['http_status:("500")'],
                $log->fqs(null, 'path'),
                'lifting one dimension is how its own facet is computed: one extra request per filtered dimension'
            );
        },

    /* -----------------------------------------------------------------------
     * Backwards compatibility
     * -------------------------------------------------------------------- */

    'a URL shared before the operator existed behaves exactly as it did' =>
        function (): void {
            $facets = lh_f(['country_s' => ['DE', 'FR'], 'browser_s' => ['Chrome']]);

            lh_same(
                [
                    '{!tag=f_country_s}country_s:("DE" OR "FR")',
                    '{!tag=f_browser_s}browser_s:("Chrome")',
                ],
                $facets->fqs(),
                'values OR within a dimension, dimensions AND as separate fq entries'
            );
            lh_same(
                ['country_s' => ['DE', 'FR'], 'browser_s' => ['Chrome']],
                $facets->flat(),
                'and the flat shape every payload has always carried is unchanged'
            );
        },

    'the operator is reported alongside the selection and never folded into it' =>
        function (): void {
            $payload = lh_f(['as_type_s' => ['hosting', 'op' => 'none']])->payload();

            lh_same(['as_type_s' => ['hosting']], $payload['active'], 'active stays field => values');
            lh_same('none', $payload['dimensions'][0]['op'], 'the operator is its own field');
            lh_same('None of', $payload['dimensions'][0]['op_label'], 'with the words the control shows');
            lh_same('Hosting / datacentre', $payload['dimensions'][0]['chosen'][0]['label'], 'and a chip reads in words');
        },

    'duplicated values collapse, so a double-click cannot widen a filter twice' =>
        function (): void {
            lh_same(['DE'], lh_f(['country_s' => ['DE', 'DE', 'DE']])->values('country_s'));
        },

    /* -----------------------------------------------------------------------
     * The boundary with the icon system, and with the views
     * -------------------------------------------------------------------- */

    'the words and the marks are separate authorities, and neither enumerates the other\'s list' =>
        function (): void {
            $icons = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/icons.js');

            foreach (['bot_verdict_s', 'bot_class_s', 'as_type_s', 'ua_bot_cat_s'] as $field) {
                if (!str_contains($icons, $field . ': {')) {
                    continue;
                }
                lh_true(
                    (bool) preg_match('/' . preg_quote($field, '/') . ':\s*\{.*?\n\s*_:/s', $icons),
                    $field . ': icons.js must carry a generic fallback, so no value in the PHP '
                        . 'vocabulary can ever come out mark-less'
                );
            }
            lh_false(
                str_contains($icons, 'Likely human'),
                'the WORDS belong to Panel\\Vocabulary; icons.js draws the mark and nothing else'
            );
            lh_false(
                str_contains($icons, 'Proxy fleet fingerprint'),
                'and the signal wording belongs to Score\\Rules, which is where the rules are'
            );
        },

    'no module keeps a second copy of the filter allowlist or the vocabulary' =>
        function (): void {
            $identity = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/identity.js');

            lh_contains($identity, 'boot.dimensions', 'the filterable set is served, not retyped');
            lh_contains($identity, 'boot.vocabulary', 'and so are the words');
            foreach (['paths_ss', 'asn_i', 'city_s', 'region_s', 'ua_bot_name_s'] as $field) {
                lh_false(
                    (bool) preg_match('/^\s*' . preg_quote($field, '/') . ':\s*\x27/m', $identity),
                    $field . ' drifted out of the hand-kept copy once already'
                );
            }
        },

    'the value browser reuses the one dialog shell rather than building a second modal' =>
        function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facetfilter.js');

            lh_contains($js, "from './dialog.js'", 'one dialog, with one set of focus rules');
            lh_contains($js, 'isCurrent(generation)', 'a slow fetch for a dismissed dialog must render nothing');
            lh_contains($js, 'dialogFail(', 'and a failed one must say so where it was asked');
            lh_false(
                (bool) preg_match('/class:\s*\x27lh-dialog/', $js),
                'the shell is built by dialog.js; a second one here would be a second set of focus bugs'
            );
        },

    'the value browser is a real letter index over real links' =>
        function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facetfilter.js');

            lh_contains($js, "ABCDEFGHIJKLMNOPQRSTUVWXYZ#", 'every letter, plus a bucket for the rest');
            lh_contains($js, "class: 'fb-letter is-off'", 'a letter with no values is visibly inactive');
            lh_contains($js, 'scrollIntoView', 'pressing a letter jumps to its group');
            lh_contains($js, "el('h4', { class: 'fb-letter-head'", 'values are grouped under letter headings');
            lh_contains($js, 'stagedUrl(group, value)', 'every row is a real href, so a middle-click works');
            lh_contains($js, 'staged.delete(value)', 'and a plain click stages instead of closing the dialog');
        },

    'the listing says it is capped, and the search says it is not' =>
        function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facetfilter.js');

            lh_contains($js, 'most common of', 'a listing that is not the whole list must say so');
            lh_contains(
                $js,
                'it searches every value',
                'and must not let the cap be read as a limit on the search, which it no longer is'
            );
            lh_contains(
                $js,
                'Every value of this dimension was searched',
                'a search result must say what population it covered'
            );
            lh_contains(
                $js,
                'showing.searched',
                'the two populations are different and the note must branch on which one is drawn'
            );
        },

    'a value search is debounced, guarded against a stale answer, and reachable on Enter' =>
        function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facetfilter.js');

            lh_contains($js, 'SEARCH_DEBOUNCE_MS = 250', 'a burst of keystrokes must be one request');
            lh_contains($js, "event.key === 'Enter'", 'somebody faster than the debounce must not have to wait');
            lh_contains($js, 'result.token !== searchToken', 'an answer overtaken by a newer one must be dropped');
            lh_contains($js, 'isCurrent(generation)', 'and so must one for a dialog that has been closed');
            lh_contains($js, 'isComplete(listing)', 'a dimension already wholly in the page must filter locally');
        },

    'a search that is too short or empty never reaches Solr' =>
        function (): void {
            lh_same('', Facets::searchTerm(null), 'no box, no search');
            lh_same('', Facets::searchTerm(''), 'an empty box is not a search');
            lh_same('', Facets::searchTerm('   '), 'nor is a box holding spaces');
            lh_same('', Facets::searchTerm('a'), 'one character scans most of a term dictionary to say nothing');
            lh_same('ab', Facets::searchTerm('  ab  '), 'two is where a search starts narrowing something');
            lh_eq(
                Facets::MAX_SEARCH,
                mb_strlen(Facets::searchTerm(str_repeat('x', 500))),
                'and the substring is capped, because matching one walks the term dictionary'
            );
            lh_same(
                'abcd',
                Facets::searchTerm("ab\x00cd"),
                'a control character would split the parameter, so it is taken out before the blunt check throws'
            );
        },

    'the facet substring is checked at the client boundary, and hostile text is not an error' =>
        function (): void {
            foreach (['', '   ', str_repeat('x', 65), "a\nwt=xml", "a\x00b"] as $bad) {
                lh_throws(
                    static fn () => \Loghound\Solr::assertSafeContains($bad),
                    'a substring that could split the parameter or scan forever must be refused'
                );
            }

            foreach (['{!frange l=0}', '_query_:"*:*"', '") OR (""="', '/path/with spaces', 'Ünïcøde'] as $ok) {
                lh_same(
                    trim($ok),
                    \Loghound\Solr::assertSafeContains($ok),
                    'Solr compares a substring literally and never parses it, so a path or a User-Agent '
                        . 'containing query syntax must be searchable: ' . $ok
                );
            }
        },

    'the substring search is a classic facet, because the JSON facet API silently ignores one' =>
        function (): void {
            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Solr.php');

            lh_contains($php, 'facet.contains', 'the parameter that actually filters terms');
            lh_contains($php, 'facet.contains.ignoreCase', 'and it must be case-insensitive');
            lh_contains(
                $php,
                'silently dropped',
                'the reason this is not a json.facet has to be written down, or it will be "fixed" back'
            );
            lh_false(
                (bool) preg_match('/\$clean\[\x27contains\x27\]/', $php),
                'allowlisting contains inside sanitiseFacet would ship a search box that ignores what is typed'
            );
        },

    'a value search excludes the dimension\'s own filter, like the listing does' =>
        function (): void {
            $facets = lh_f(['as_org_s' => ['Amazon']]);

            lh_same(
                ['f_as_org_s'],
                $facets->ownTags('as_org_s'),
                'searching inside a filtered dimension would only ever return what is already selected'
            );
            lh_same([], $facets->ownTags('country_s'), 'an unfiltered dimension has nothing to exclude');
        },

    'a facet.field carrying a tag exclusion passes validation, and nothing else does' =>
        function (): void {
            $solr = new \Loghound\Solr([
                'base_url'  => 'http://127.0.0.1:8983/solr',
                'transport' => static fn (): array => ['status' => 200, 'body' => '{}', 'error' => ''],
            ]);
            $ref = new \ReflectionMethod($solr, 'sanitiseQueryParams');

            $clean = $ref->invoke($solr, ['q' => '*:*', 'facet.field' => '{!ex=f_host_s}host_s']);
            lh_same(
                '{!ex=f_host_s}host_s',
                $clean['facet.field'],
                'the classic spelling of "ignore my own filter" must survive, or multi-select breaks'
            );

            foreach (['{!frange l=0}host_s', '{!join from=a to=b}host_s', '{!ex=f_a}{!frange}host_s'] as $bad) {
                lh_throws(
                    static fn () => $ref->invoke($solr, ['q' => '*:*', 'facet.field' => $bad]),
                    'only the exclusion block is skipped; every other local param must still be refused: ' . $bad
                );
            }
        },

    'no view builds its own facet markup or its own fq' =>
        function (): void {
            foreach (glob(dirname(__DIR__) . '/src/Panel/*.php') as $file) {
                $name = basename($file);
                if (in_array($name, ['Facets.php', 'Controller.php', 'Query.php'], true)) {
                    continue;
                }
                $php = (string) file_get_contents($file);

                lh_false(
                    (bool) preg_match('/\$_GET\[\x27lf?\x27\]/', $php),
                    $name . ' must not read the filter parameters itself'
                );
                lh_false(
                    (bool) preg_match('/\$field\s*\.\s*\x27:\(\x27\s*\.\s*implode/', $php),
                    $name . ' must not build a filter clause by hand; there were three of these'
                );
                lh_false(
                    str_contains($php, 'Query::quote(') && str_contains($php, "implode(' OR '"),
                    $name . ' must not OR a value list by hand — that is what loses the operator'
                );
            }
        },

    'every view that declares a pivot renders a card for it, and no other view does' =>
        function (): void {
            $pivots = Query::pivots();

            foreach ([
                'overview' => 'Overview', 'bots' => 'Bots', 'networks' => 'Networks',
                'fingerprints' => 'Fingerprints', 'hosts' => 'Hosts', 'performance' => 'Performance',
                'sessions' => 'Sessions',
            ] as $slug => $class) {
                $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/' . $class . '.php');
                lh_same(
                    isset($pivots[$slug]),
                    str_contains($php, 'pivotCard('),
                    $class . ': a pivot is declared in exactly one table and rendered from it'
                );
            }
        },

    'a pivot costs no request of its own' =>
        function (): void {
            foreach (['Overview', 'Bots', 'Networks'] as $class) {
                $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/' . $class . '.php');
                lh_contains(
                    $php,
                    '$this->pivotDef(',
                    $class . ': the pivot must be folded into a facet request the view already makes'
                );
                lh_eq(
                    1,
                    substr_count($php, '$this->pivotRows('),
                    $class . ': and read back from that same response, once'
                );
            }
        },

    /* -----------------------------------------------------------------------
     * The value browser's search, on the branch the demo world cannot reach
     * -------------------------------------------------------------------- */

    'a search that matches renders the matches, labelled, over the whole dimension' =>
        function (): void {
            [$result, $captured] = lh_fx_values(
                ['field' => 'bot_reasons_ss', 'vq' => 'no_'],
                ['_classic' => ['bot_reasons_ss' => ['no_assets', 30, 'no_js_on_html', 12]]]
            );
            $group = $result['group'];

            lh_same('no_', $result['search'], 'the term is echoed back so the box and the answer agree');
            lh_true($group['searched'], 'the answer must declare that every value was searched');
            lh_false($group['truncated'], 'two matches is not a truncated result');
            lh_eq(2, count($group['buckets']), 'both matches');
            lh_same('No sub-resources', $group['buckets'][0]['label'], 'a search result is spoken in words too');
            lh_same('no_assets', $group['buckets'][0]['value'], 'and still carries the slug it filters on');

            $params = lh_fx_params($captured);
            lh_same(['no_'], $params['facet.contains'], 'the substring must reach Solr as its own parameter');
            lh_same(['true'], $params['facet.contains.ignoreCase'], 'hashes and paths are searched case-blind');
            lh_same(['bot_reasons_ss'], $params['facet.field'], 'no filter is on this dimension, so no exclusion');
            lh_no_key($params, 'json.facet', 'the JSON facet API has no substring filter; this must not use it');
        },

    'a search that matches NOTHING is an answer, not an absent one' =>
        function (): void {
            [$result] = lh_fx_values(
                ['field' => 'as_org_s', 'vq' => 'zzzz'],
                ['_classic' => ['as_org_s' => []]]
            );

            lh_true($result['group'] !== null, 'a null group would fall back to a listing and hide the search');
            lh_same([], $result['group']['buckets'], 'and it must be honestly empty');
            lh_true($result['group']['searched'], 'the reader is owed "this was searched and found nothing"');
            lh_same('zzzz', $result['group']['search']);
            lh_same('as_org_s', $result['group']['field'], 'a shaped group, so the dialog renders it like any other');
            lh_true(isset($result['group']['operators']), 'including the controls, which still apply');
        },

    'a search on a FILTERED dimension lifts that dimension\'s own filter' =>
        function (): void {
            [, $captured] = lh_fx_values(
                ['field' => 'as_org_s', 'vq' => 'ama', 'f' => ['as_org_s' => ['Amazon.com Inc.']]],
                ['_classic' => ['as_org_s' => ['Amazon.com Inc.', 18]]]
            );
            $params = lh_fx_params($captured);

            lh_same(
                ['{!ex=f_as_org_s}as_org_s'],
                $params['facet.field'],
                'searching inside its own filter would only ever return what is already selected'
            );
            lh_true(
                in_array('{!tag=f_as_org_s}as_org_s:("Amazon.com Inc.")', $params['fq'], true),
                'the filter itself still applies to the page; only the facet ignores it'
            );
        },

    'a result at the cap says it was cut, so "not found" is never inferred from it' =>
        function (): void {
            $many = [];
            for ($i = 0; $i < 200; $i++) {
                $many[] = 'value-' . $i;
                $many[] = 1;
            }
            [$result] = lh_fx_values(
                ['field' => 'as_org_s', 'vq' => 'value'],
                ['_classic' => ['as_org_s' => $many]]
            );

            lh_eq(200, count($result['group']['buckets']), 'the cap');
            lh_true($result['group']['truncated'], 'and it must say it hit the cap');
        },

    'a listing states its own cap and the distinct count behind it' =>
        function (): void {
            [$result, $captured] = lh_fx_values(
                ['field' => 'as_org_s'],
                ['count' => 900, 'as_org_s' => ['numBuckets' => 4821, 'buckets' => [
                    ['val' => 'Amazon.com Inc.', 'count' => 300],
                ]]]
            );

            lh_eq(4821, $result['group']['distinct'], 'the dialog must be able to say "the N most common of M"');
            lh_no_key($result['group'], 'search', 'a listing is not a search and must not claim to be');

            $params = lh_fx_params($captured);
            lh_no_key($params, 'facet.contains', 'a listing must not carry a substring');
            lh_true(isset($params['json.facet']), 'a listing IS a JSON facet; only the search is classic');
        },

    'one message covers a search that found nothing, whoever ran it' =>
        function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facetfilter.js');

            lh_contains($js, 'function populationNote(', 'one function owns the sentence');
            $code = (string) preg_replace('#/\*.*?\*/#s', '', $js);
            lh_false(
                str_contains($code, 'Nothing to show here'),
                'a second, generic empty state reads as an empty panel rather than a completed search'
            );
            lh_false(
                str_contains($code, 'No value here matches'),
                'and a second wording for the same situation is how the two got out of step'
            );
            lh_eq(
                1,
                substr_count($code, 'No value contains'),
                'exactly one wording reaches the screen for "this search found nothing"'
            );
            lh_contains($js, 'function searchSentence(', 'one builder for the sentence, used by both surfaces');
            lh_contains(
                $js,
                'searched: complete',
                'a local search over a listing that holds the whole dimension DID search every value, '
                    . 'so the note must branch on the population and not on which code ran'
            );
            lh_contains(
                $js,
                'Only the values listed here were searched',
                'and over a capped listing it must say the opposite'
            );
            lh_contains(
                $js,
                'searchSentence(0, typed, complete, false)',
                'the sidebar must use the same builder, not a paraphrase of it'
            );
        },

    /* -----------------------------------------------------------------------
     * The two dimensions the beacon plane added
     * -------------------------------------------------------------------- */

    'the new dimensions are registered on the cores that actually define them' =>
        function (): void {
            lh_has_key(Query::filterFields(), 'planes_s', 'the transport-plane dimension');
            lh_has_key(Query::filterFields(), 'search_terms_ss', 'the search-term dimension');

            lh_false(
                isset(Query::hitFilterFields()['planes_s']),
                'planes_s says which planes have seen a SESSION; a hit is one line on one of them'
            );
            lh_true(
                isset(Query::hitFilterFields()['search_terms_ss']),
                'search_terms_ss is on BOTH schemas, so excluding it would answer zero on every hits view'
            );

            foreach (['planes_s', 'search_terms_ss'] as $field) {
                lh_contains(Query::sessionFl(), $field, $field . ' is stored, so a session row must carry it');
                lh_no_key(Query::filterFieldKinds(), $field, $field . ' is a string and needs no type entry');
            }

            $hits = (string) file_get_contents(dirname(__DIR__) . '/solr/hits/conf/managed-schema.xml');
            lh_contains($hits, 'name="search_terms_ss"', 'and the hits schema really does define it');
        },

    'a search term is multi-valued, so "All of" is offered on it' =>
        function (): void {
            $facets = lh_f(['search_terms_ss' => ['red shoes', 'blue hat', 'op' => 'all']]);

            lh_same(Facets::ARITY_MULTI, $facets->arity('search_terms_ss'));
            lh_same(
                ['{!tag=f_search_terms_ss}search_terms_ss:("red shoes" AND "blue hat")'],
                $facets->fqs(),
                'sessions that searched for BOTH, which is the question this dimension exists for'
            );
            lh_true(in_array('all', array_column($facets->operators('search_terms_ss'), 'op'), true));
        },

    'the transport plane is asked for by EXCLUSION, never by naming a value' =>
        function (): void {
            lh_same(
                '-planes_s:beacon_only',
                Query::HAS_LOG_PLANE,
                'planes_s has no schema default, so naming log_only would silently drop every '
                    . 'session indexed before the field existed'
            );
            lh_same(
                ['{!tag=f_planes_s}-planes_s:("beacon_only")'],
                lh_f(['planes_s' => ['beacon_only', 'op' => 'none']])->fqs(),
                'and the "None of" operator is how the interface spells the same clause'
            );
        },

    'a plane is spoken in words, and the history that predates the field is its own row' =>
        function (): void {
            lh_true(Vocabulary::has('planes_s'), 'log_only / log_beacon / beacon_only are identifiers');
            lh_same('Server log only', Vocabulary::label('planes_s', 'log_only'));
            lh_same('Beacon only', Vocabulary::label('planes_s', 'beacon_only'));

            $facets = lh_f([]);
            $group = $facets->withAbsentValue(
                $facets->group(lh_buckets('planes_s', ['log_only' => 40, 'log_beacon' => 25, 'beacon_only' => 5]), 'planes_s', 12),
                200
            );

            lh_has_key($group, 'absent', 'the sessions with no value for the field must be accounted for');
            lh_eq(130, $group['absent']['count'], 'and counted, not folded into log_only');
            lh_same('none', $group['absent']['op'], 'selecting them is an exclusion over every known value');
        },

    'a dimension of typed text survives tens of thousands of distinct values' =>
        function (): void {
            $buckets = [];
            for ($i = 0; $i < 2000; $i++) {
                $buckets[] = ['val' => 'term ' . $i, 'count' => 1];
            }
            [$result] = lh_fx_values(
                ['field' => 'search_terms_ss'],
                ['count' => 90000, 'search_terms_ss' => ['numBuckets' => 40000, 'buckets' => $buckets]]
            );
            $group = $result['group'];

            lh_eq(2000, count($group['buckets']), 'the listing is bounded whatever the cardinality');
            lh_eq(40000, $group['distinct'], 'and states how much it is not showing');
            lh_true($group['truncated'], 'so the dialog cannot present it as a complete list');
            lh_true(
                $group['overlaps'],
                'one session holds several search terms, so these counts do not sum to the total'
            );
        },

    'a value carrying query syntax is counted and shown, but never a dead link' =>
        function (): void {
            $facets = lh_f([]);
            $group = $facets->group(
                ['count' => 100, 'search_terms_ss' => ['buckets' => [
                    ['val' => 'red shoes', 'count' => 40],
                    ['val' => '{!frange l=0}', 'count' => 3],
                    ['val' => '_query_:x', 'count' => 1],
                ]]],
                'search_terms_ss',
                12
            );
            $states = array_column($group['buckets'], 'state', 'value');

            lh_same('off', $states['red shoes'], 'an ordinary term is selectable');
            lh_same(
                'unfilterable',
                $states['{!frange l=0}'],
                'a term somebody really searched for, which assertSafeFilter refuses to carry'
            );
            lh_same('unfilterable', $states['_query_:x']);
            lh_eq(3, count($group['buckets']), 'and none of them is dropped: the count is real');

            foreach ($group['buckets'] as $bucket) {
                if ($bucket['state'] === 'unfilterable') {
                    lh_contains($bucket['why'], 'counted but not selected', 'the row must say why it is inert');
                }
            }

            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/facets.js');
            lh_contains(
                $js,
                "state === 'unfilterable'",
                'and the renderer must draw it static, because a link that does nothing is worse'
            );
        },

    /* -----------------------------------------------------------------------
     * A rule input nothing ever wrote
     * -------------------------------------------------------------------- */

    'beacon_orphan_b is gone from the schema, the signals and the shipped docs' =>
        function (): void {
            $schema = (string) file_get_contents(dirname(__DIR__) . '/solr/sessions/conf/managed-schema.xml');
            lh_false(str_contains($schema, 'beacon_orphan_b'), 'nothing ever wrote it, so it is not a field');

            $signals = (string) file_get_contents(dirname(__DIR__) . '/src/Score/Signals.php');
            lh_false(
                str_contains($signals, 'beacon_orphan'),
                'a rule input that can never be true makes the ladder look more thorough than it is'
            );

            $rules = (string) file_get_contents(dirname(__DIR__) . '/src/Score/Rules.php');
            lh_false(str_contains($rules, 'beacon_orphan'), 'and no rule may reach for it');

            lh_contains($schema, 'name="planes_s"', 'the honest field for the same observation stays');
        },

    'the fact beacon_orphan_b claimed is still recorded, without the accusation' =>
        function (): void {
            lh_same(
                'Beacon only',
                Vocabulary::label('planes_s', 'beacon_only'),
                'a beacon with no matching log line is an observation about transport planes'
            );
            lh_false(
                str_contains(mb_strtolower(Vocabulary::value('planes_s', 'beacon_only')['why']), 'suspicious'),
                'a tailer that is behind produces these in bulk and none of them is evidence of anything'
            );
        },

    /* -----------------------------------------------------------------------
     * Starting a session
     * -------------------------------------------------------------------- */

    'a session is started in one place, correctly, and refuses rather than warns' =>
        function (): void {
            lh_false(
                \Loghound\Security::startSession(),
                'under the runner, output has been written, so no session can be started — and it '
                    . 'must say so by returning false rather than by emitting a warning'
            );

            foreach (['Panel/Settings.php', 'Panel/Jobs.php', 'Security.php'] as $file) {
                $php = (string) file_get_contents(dirname(__DIR__) . '/src/' . $file);
                lh_false(
                    str_contains($php, '@session_start('),
                    $file . ': silencing the warning is not the same as not earning it'
                );
            }

            $settings = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');
            lh_false(
                str_contains($settings, 'session_start()'),
                'two hand-rolled copies here skipped the empty cache limiter, which is the defect '
                    . 'Security::startSession() exists to prevent'
            );
            lh_contains($settings, 'Security::startSession()', 'there is one way to start a session');

            $jobs = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Jobs.php');
            lh_false(
                (bool) preg_match('/^\s*session_start\(\);/m', $jobs),
                'the job owner must not start a session its own way either'
            );
            lh_contains($jobs, 'Security::startSession()', 'it delegates the how');
            lh_contains(
                $jobs,
                "PHP_SAPI !== 'cli'",
                'while KEEPING its own policy: a scorer run from cron has no browser, and the '
                    . 'shared wrapper would start a session for it'
            );

            $security = (string) file_get_contents(dirname(__DIR__) . '/src/Security.php');
            lh_contains($security, 'headers_sent(', 'the guard');
            lh_contains($security, 'session_cache_limiter', 'and the reason the wrapper exists at all');
            lh_contains(
                $security,
                "PHP_SAPI !== 'cli'",
                'a web request that reaches here after output is a caller bug and must be logged, '
                    . 'not silently swallowed'
            );

            /* THE RULE APPLIES TO THE FILE THAT OWNS IT TOO. sessionSignOut() called
               session_start() bare, without the empty cache limiter, two functions from a
               sibling that got it right — which is exactly how somebody copies the wrong one.
               Exactly one call may exist in this file: the one inside the wrapper. */
            lh_eq(
                1,
                preg_match_all('/^\s*(?:@|return )?session_start\(\);/m', $security),
                'src/Security.php may contain exactly one session_start(), inside startSession()'
            );
            lh_contains(
                $security,
                'private static function sessionPresented(',
                'and the precondition sessionResume() and sessionSignOut() share is named once, '
                    . 'not written out in both'
            );
            lh_eq(
                1,
                substr_count($security, "isset(\$_COOKIE[session_name()])"),
                'there was one copy of that test per caller, four hundred lines apart'
            );
        },

    /* -----------------------------------------------------------------------
     * No underscored identifier ever reaches a reader
     * -------------------------------------------------------------------- */

    'no rendered view puts a vocabulary slug or a field name in front of a person' =>
        function (): void {
            $slugs = [];
            foreach (Vocabulary::all() as $field => $values) {
                foreach (array_keys($values) as $value) {
                    if (str_contains($value, '_')) {
                        $slugs[$value] = $field;
                    }
                }
            }
            lh_true(count($slugs) > 20, 'the sweep is only worth anything if it knows the vocabularies');

            $cfg = \Loghound\Config::load('/nonexistent-loghound-config');
            $cfg->set('ui.demo', true);
            $gw = \Loghound\Panel\Gateway::fromConfig($cfg);

            $saved = $_GET;
            $problems = [];
            try {
                foreach ([
                    'Overview', 'Bots', 'Fingerprints', 'Networks', 'Sessions',
                    'Performance', 'Hosts', 'Indexes', 'Queries', 'Callers', 'Usage',
                ] as $name) {
                    $_GET = ['range' => '24h'];
                    $class = '\\Loghound\\Panel\\' . $name;
                    $view = new $class($cfg, $gw);

                    ob_start();
                    $view->body();
                    $html = (string) ob_get_clean();

                    /* Only TEXT NODES are read by a person. Attributes carry the slug on purpose —
                       it is the filter value — and a comment is for whoever edits the file. */
                    $text = (string) preg_replace('/<!--.*?-->/s', '', $html);
                    $text = (string) preg_replace('/<[^>]*>/', ' ', $text);

                    foreach ($slugs as $slug => $field) {
                        if (str_contains($text, $slug)) {
                            $problems[] = $name . ' renders the slug "' . $slug . '"';
                        }
                    }
                    foreach (array_keys(Query::filterFields()) as $field) {
                        if (preg_match('/(^|\s)' . preg_quote($field, '/') . '(\s|[.,]|$)/', $text)) {
                            $problems[] = $name . ' renders the field name "' . $field . '"';
                        }
                    }
                }
            } finally {
                $_GET = $saved;
            }

            lh_same(
                [],
                array_values(array_unique($problems)),
                'a person reads words: "Proxy fleet fingerprint", not fp_cluster_proxy_fleet, and '
                    . '"Signal fired", not bot_reasons_ss. The slug stays the filter value in the '
                    . 'URL and the value in Solr, and the mapping belongs in the documentation.'
            );
        },

    'no API payload puts a slug in a field a view renders as text' =>
        function (): void {
            $slugs = [];
            foreach (Vocabulary::all() as $values) {
                foreach (array_keys($values) as $value) {
                    if (str_contains($value, '_')) {
                        $slugs[] = $value;
                    }
                }
            }

            $cfg = \Loghound\Config::load('/nonexistent-loghound-config');
            $cfg->set('ui.demo', true);
            $gw = \Loghound\Panel\Gateway::fromConfig($cfg);

            /* The keys a renderer prints as prose. `value` is deliberately NOT among them: that is
               the slug, and it belongs in the href. */
            $spoken = ['label', 'why', 'basis_note', 'question', 'op_label', 'text', 'note'];

            $saved = $_GET;
            $problems = [];
            try {
                foreach ([
                    'Overview' => ['totals', 'timing', 'series', 'toppages'],
                    'Bots'     => ['split', 'reasons', 'verdicts', 'classes', 'crawlers'],
                    'Networks' => ['totals', 'asns', 'types', 'netnames', 'geo'],
                    'Sessions' => ['list', 'facets', 'dimensions'],
                ] as $name => $actions) {
                    foreach ($actions as $action) {
                        $_GET = ['range' => '24h'];
                        $class = '\\Loghound\\Panel\\' . $name;
                        $payload = (new $class($cfg, $gw))->api($action);

                        array_walk_recursive(
                            $payload,
                            function ($value, $key) use ($slugs, $spoken, $name, $action, &$problems): void {
                                if (!is_string($value) || !in_array($key, $spoken, true)) {
                                    return;
                                }
                                foreach ($slugs as $slug) {
                                    if (str_contains($value, $slug)) {
                                        $problems[] = $name . '/' . $action . ': "' . $key . '" carries ' . $slug;
                                    }
                                }
                            }
                        );
                    }
                }
            } finally {
                $_GET = $saved;
            }

            lh_same([], array_values(array_unique($problems)), 'a label is words, all the way to the wire');
        },

    'the client cannot put a slug on screen for a dimension that has words for it' =>
        function (): void {
            $identity = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/identity.js');

            lh_contains($identity, 'export function valueText(', 'one helper for "what a person reads"');
            lh_contains(
                $identity,
                'const mono = spoken ? false : options.mono;',
                'a value with words is never set in the identifier face, whatever the call site asked for'
            );
            lh_contains(
                $identity,
                '? spoken.label',
                'and the label overrides a caller that passed the slug as the visible text'
            );
            lh_false(
                str_contains($identity, 'valueSlug'),
                'the helper that existed to show the slug beside the label is gone'
            );

            foreach (['views/bots.js', 'detail.js', 'facetfilter.js'] as $file) {
                $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/' . $file);
                lh_false(
                    str_contains($js, "fb-slug"),
                    $file . ' must not render the slug beside the label'
                );
            }

            $bots = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/bots.js');
            lh_false(
                str_contains($bots, 'title: row.code'),
                'not even as a tooltip: there is no technical-reader exception inside the panel'
            );
            lh_contains(
                $bots,
                "valueText('bot_verdict_s', row.verdict)",
                'a chart legend is read by a person too'
            );
        },

    'a rule added without a label still fails the suite' =>
        function (): void {
            lh_same(
                array_values(array_diff(Rules::reasonCodes(), array_keys(Rules::REASONS))),
                [],
                'Score\\Rules::REASONS is the single source the documentation is generated from, '
                    . 'so a code with no entry must stop the build rather than reach a reader as a slug'
            );
        },
];
