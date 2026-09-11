<?php
/**
 * Loghound — tests for the visitor-level detail work: the drill-down endpoints, the
 * dimension/filter presentation, and the identity a measured site attaches to a session.
 *
 * WHAT IS PINNED HERE AND WHY EACH ONE IS PINNED
 *
 *  - Solr injection on a NEW input surface. `dimension` takes a field name and a value from
 *    the browser, which is exactly the shape that goes wrong: the field must come from an
 *    allowlist and the value must be bound as an escaped literal, never spliced. An AS
 *    organisation name is whatever a regional registry holds and a path is whatever a client
 *    asked for, so both are tested with Lucene operators in them.
 *  - The numeric-field path. A point field cannot take a quoted term, so it is the one case
 *    that is built without quoting — which means it is the one case where a non-numeric value
 *    must be REFUSED rather than coerced. "Unparseable" becoming "matches everything" is how
 *    that mistake shows up.
 *  - Scope. Every drill-down carries the document-type clause, the range and the active
 *    filters. Without the first, the daily rollup documents are counted as sessions and every
 *    number in the dialog is inflated.
 *  - Cost. A terms facet over `ip_s` has a bucket per visitor, so the browse list must not
 *    contain it however convenient that would be.
 *  - Absent is not false, for the third time in this codebase. `signed_in_b` is written only
 *    when the site actually said something, so a site that never sends it must not be counted
 *    as anonymous — and the three-state presentation must show the remainder as its own bucket
 *    rather than letting a reader assume it.
 *  - The identity gate. `beacon.store_identity` is off by default, and off has to mean the
 *    string is discarded before anything is written, not hidden afterwards.
 *  - CSP compatibility of the new front end. No inline script, no `on*` attribute and no
 *    `javascript:` in anything rendered or shipped, because the panel's script-src is 'self'
 *    with no 'unsafe-inline' and a dialog that needed one would be unopenable.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Beacon;
use Loghound\Config;
use Loghound\Panel\Gateway;
use Loghound\Panel\Sessions;
use Loghound\Solr;

if (!function_exists('lh_vd_config')) {
    /** A configuration pointed at a Solr that does not exist, with demo mode off. */
    function lh_vd_config(): Config
    {
        $cfg = Config::load('/nonexistent-loghound-config');
        $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
        $cfg->set('solr.hits_core', 'lh_vd_hits');
        $cfg->set('solr.sessions_core', 'lh_vd_sessions');
        return $cfg;
    }

    /**
     * A Gateway over the REAL Solr client with a recording transport.
     *
     * Nothing leaves the machine, and using the real client means every request is judged by
     * the sanitisers production applies — so a failure here is a genuine injection risk rather
     * than a mock disagreeing with a mock.
     *
     * @param array<int,array<string,mixed>> $captured
     * @param array<int,array<string,mixed>> $docs
     */
    function lh_vd_gateway(array &$captured, array $docs = []): Gateway
    {
        $transport = function (array $request) use (&$captured, $docs): array {
            $captured[] = $request;
            return [
                'status' => 200,
                'body'   => (string) json_encode([
                    'responseHeader' => ['status' => 0],
                    'response' => ['numFound' => count($docs), 'docs' => $docs],
                    'facets'   => ['count' => count($docs)],
                ]),
                'error'  => '',
            ];
        };
        $cfg = lh_vd_config();
        return new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
    }

    /**
     * Run one Sessions action with a given $_GET.
     *
     * @param array<string,mixed>            $get
     * @param array<int,array<string,mixed>> $docs
     * @return array{0:array<string,mixed>,1:array<int,array<string,mixed>>}
     */
    function lh_vd_run(string $action, array $get, array $docs = []): array
    {
        $saved = $_GET;
        $_GET = $get;
        $captured = [];
        try {
            $result = (new Sessions(lh_vd_config(), lh_vd_gateway($captured, $docs)))->api($action);
        } finally {
            $_GET = $saved;
        }
        return [$result, $captured];
    }

    /**
     * Every value of a repeated parameter across every captured request.
     *
     * Solr::encodeParams() writes an array parameter as `fq=a&fq=b`, which parse_str() cannot
     * represent, so the body is split by hand.
     *
     * @param array<int,array<string,mixed>> $captured
     * @return array<int,string>
     */
    function lh_vd_repeated(array $captured, string $key): array
    {
        $out = [];
        foreach ($captured as $request) {
            foreach (explode('&', (string) ($request['body'] ?? '')) as $pair) {
                if ($pair === '') {
                    continue;
                }
                [$k, $v] = array_pad(explode('=', $pair, 2), 2, '');
                if (rawurldecode($k) === $key) {
                    $out[] = rawurldecode($v);
                }
            }
        }
        return $out;
    }

    /** The concatenated bodies of every captured request. */
    function lh_vd_bodies(array $captured): string
    {
        $out = '';
        foreach ($captured as $request) {
            $out .= rawurldecode(str_replace('+', ' ', (string) ($request['body'] ?? ''))) . "\n";
        }
        return $out;
    }

    /** Read one shipped file. */
    function lh_vd_file(string $relative): string
    {
        $path = dirname(__DIR__) . '/' . $relative;
        if (!is_file($path)) {
            lh_fail('missing file: ' . $relative);
        }
        return (string) file_get_contents($path);
    }

    /** A Beacon with the given beacon-section overrides. */
    function lh_vd_beacon(array $overrides = []): Beacon
    {
        $cfg = Config::load('/nonexistent-loghound-config');
        $cfg->set('beacon.secret', str_repeat('k', 64));
        foreach ($overrides as $key => $value) {
            $cfg->set('beacon.' . $key, $value);
        }
        return new Beacon($cfg);
    }
}

return [

    /* -----------------------------------------------------------------------
     * The dimension drill-down: field allowlist and value binding
     * -------------------------------------------------------------------- */

    'dimension: a field the allowlist does not carry is refused without querying Solr' =>
        function (): void {
            foreach (['ua_s', 'password', '*', 'id', 'bot_score_f', 'session_id_s'] as $field) {
                [$result, $captured] = lh_vd_run('dimension', ['field' => $field, 'value' => 'x']);
                lh_has_key($result, 'error', 'refusal for ' . $field);
                lh_same([], $captured, 'no Solr request may be issued for field ' . $field);
            }
        },

    'dimension: an allowlisted field is accepted and queried' =>
        function (): void {
            [$result, $captured] = lh_vd_run('dimension', ['field' => 'country_s', 'value' => 'DE']);
            lh_same(null, $result['error'], 'a valid dimension must produce no error');
            lh_true(count($captured) > 0, 'a valid dimension must reach Solr');
            lh_same('country_s', $result['field'], 'the field is echoed back');
            lh_same('DE', $result['value'], 'the value is echoed back');
        },

    'dimension: a hostile value is bound as an escaped literal, never as query syntax' =>
        function (): void {
            $hostile = 'Evil" OR ip_s:* OR netname_s:"';
            [, $captured] = lh_vd_run('dimension', ['field' => 'as_org_s', 'value' => $hostile]);

            $fqs = lh_vd_repeated($captured, 'fq');
            $found = null;
            foreach ($fqs as $fq) {
                if (str_starts_with($fq, 'as_org_s:')) {
                    $found = $fq;
                }
            }
            lh_true($found !== null, 'the dimension clause must be present');
            lh_same(
                'as_org_s:"Evil\\" OR ip_s:* OR netname_s:\\""',
                $found,
                'both quotes must be backslash-escaped inside one quoted term'
            );
            lh_false(
                (bool) preg_match('/as_org_s:[^"]*\bOR\b/', $found),
                'no bare OR may escape the quoted term'
            );
        },

    'dimension: a path value with Lucene operators in it stays a literal' =>
        function (): void {
            [, $captured] = lh_vd_run('dimension', ['field' => 'paths_ss', 'value' => '/a\\b^2~ (c OR d)']);
            $fqs = lh_vd_repeated($captured, 'fq');
            $found = '';
            foreach ($fqs as $fq) {
                if (str_starts_with($fq, 'paths_ss:')) {
                    $found = $fq;
                }
            }
            lh_same('paths_ss:"/a\\\\b^2~ (c OR d)"', $found, 'the backslash must be doubled and the rest quoted');
        },

    'dimension: a numeric field takes an unquoted integer and refuses anything else' =>
        function (): void {
            [$ok, $captured] = lh_vd_run('dimension', ['field' => 'asn_i', 'value' => '14061']);
            lh_same(null, $ok['error'], 'a numeric ASN must produce no error');
            lh_true(
                in_array('asn_i:14061', lh_vd_repeated($captured, 'fq'), true),
                'a point field must be filtered without quotes'
            );

            foreach (['14061 OR *', '*', '-1', '1e5', 'AS14061', '14061;drop'] as $bad) {
                [$result, $requests] = lh_vd_run('dimension', ['field' => 'asn_i', 'value' => $bad]);
                lh_has_key($result, 'error', 'a non-integer ASN (' . $bad . ') must be refused');
                lh_same([], $requests, 'a refused numeric value must not reach Solr: ' . $bad);
            }
        },

    'dimension: an empty value is refused rather than matching everything' =>
        function (): void {
            [$result, $captured] = lh_vd_run('dimension', ['field' => 'country_s', 'value' => '']);
            lh_has_key($result, 'error', 'an empty value');
            lh_same([], $captured, 'an empty value must not reach Solr');
        },

    'dimension: the session filter alias is applied, so a session id filter is not silently empty' =>
        function (): void {
            [, $captured] = lh_vd_run('dimension', [
                'field' => 'fp_hash_s',
                'value' => 'abc123',
                'f'     => ['session_id_s' => ['s-1']],
            ]);
            $bodies = lh_vd_bodies($captured);
            lh_contains($bodies, 'id:("s-1")', 'session_id_s must be rewritten to id on the sessions core');
            lh_false(
                str_contains($bodies, 'session_id_s:'),
                'the sessions core does not define session_id_s, so that name must never reach it'
            );
        },

    /* -----------------------------------------------------------------------
     * Scope: the numbers in a dialog must describe what is on screen
     * -------------------------------------------------------------------- */

    'dimension: the scope carries the document type, the range and the active filters' =>
        function (): void {
            [$result, $captured] = lh_vd_run('dimension', [
                'field' => 'browser_s',
                'value' => 'Chrome',
                'range' => '7d',
                'f'     => ['country_s' => ['DE'], 'as_type_s' => ['hosting']],
            ]);

            $fqs = lh_vd_repeated($captured, 'fq');
            lh_true(in_array('doc_type_s:session', $fqs, true), 'the rollup documents must be excluded');
            lh_true(
                in_array('ts_start:[NOW-7DAY/HOUR TO NOW]', $fqs, true),
                'the selected range must bound the drill-down'
            );
            lh_true(
                in_array('{!tag=f_country_s}country_s:("DE")', $fqs, true),
                'the active country filter must still apply, and must be tagged so its own facet can ignore it'
            );
            lh_true(
                in_array('{!tag=f_as_type_s}as_type_s:("hosting")', $fqs, true),
                'every active filter must still apply, each under its own tag'
            );
            lh_same(['DE'], $result['active']['country_s'], 'the dialog must be told which filters produced it');
        },

    'dimension: a dimension is never broken down by itself' =>
        function (): void {
            [, $captured] = lh_vd_run('dimension', ['field' => 'country_s', 'value' => 'DE']);
            $bodies = lh_vd_bodies($captured);
            lh_false(
                str_contains($bodies, '"by_country_s"'),
                'breaking a country down by country is a single bucket that answers nothing'
            );
            lh_contains($bodies, '"by_as_org_s"', 'the other dimensions must still be counted');
        },

    'dimension: rows on the visitor sample are bounded and the projection is explicit' =>
        function (): void {
            [, $captured] = lh_vd_run('dimension', ['field' => 'country_s', 'value' => 'DE', 'rows' => '9999']);
            $rows = lh_vd_repeated($captured, 'rows');
            foreach ($rows as $value) {
                lh_true((int) $value <= 100, 'no drill-down may ask Solr for more than a sample: got ' . $value);
            }
            foreach (lh_vd_repeated($captured, 'fl') as $fl) {
                lh_false(str_contains($fl, '*'), 'fl must be an explicit list, never a wildcard');
                lh_contains($fl, 'ident_s', 'the projection must carry the operator-supplied identity');
                lh_contains($fl, 'signed_in_b', 'the projection must carry the signed-in state');
            }
        },

    'dimension: a path also asks the hits core what was actually returned' =>
        function (): void {
            [, $captured] = lh_vd_run('dimension', ['field' => 'paths_ss', 'value' => '/pricing']);
            $bodies = lh_vd_bodies($captured);
            lh_contains($bodies, 'path_s:"/pricing"', 'the hits core must be asked about the path itself');
            lh_contains($bodies, '"status"', 'the status mix is the first thing a path row owes the reader');

            $hits = false;
            foreach ($captured as $request) {
                if (str_contains((string) ($request['url'] ?? ''), 'lh_vd_hits')) {
                    $hits = true;
                }
            }
            lh_true($hits, 'the path profile must come from the hits core, not the sessions core');
        },

    /* -----------------------------------------------------------------------
     * The browse list
     * -------------------------------------------------------------------- */

    'dimensions: the browse list never facets over addresses or session ids' =>
        function (): void {
            [, $captured] = lh_vd_run('dimensions', []);
            $bodies = lh_vd_bodies($captured);

            lh_false(
                str_contains($bodies, '"field":"ip_s"'),
                'a terms facet over ip_s has a bucket per visitor and must not be in a browse list'
            );
            lh_false(
                str_contains($bodies, '"field":"session_id_s"'),
                'session_id_s is not a dimension and is not defined on the sessions core'
            );
            lh_contains($bodies, '"field":"as_org_s"', 'AS organisation must be browsable');
            lh_contains($bodies, '"field":"netname_s"', 'netname must be browsable');
            lh_contains($bodies, '"field":"browser_s"', 'browser must be browsable');
            lh_contains($bodies, '"field":"os_s"', 'OS must be browsable');
            lh_contains($bodies, '"field":"device_s"', 'device must be browsable');
            lh_contains($bodies, '"field":"ua_bot_cat_s"', 'declared bot category must be browsable');
        },

    'dimensions: the browse list is scoped by the range and the filters already in force' =>
        function (): void {
            [$result, $captured] = lh_vd_run('dimensions', [
                'range' => '30d',
                'f'     => ['browser_s' => ['Chrome']],
            ]);
            $fqs = lh_vd_repeated($captured, 'fq');
            lh_true(in_array('doc_type_s:session', $fqs, true), 'rollups must be excluded from a browse count');
            lh_true(in_array('ts_start:[NOW-30DAY/DAY TO NOW]', $fqs, true), 'the range must bound the counts');
            lh_true(
                in_array('{!tag=f_browser_s}browser_s:("Chrome")', $fqs, true),
                'an already-active filter must narrow the counts, tagged so the browser facet still lists every browser'
            );
            lh_same(['Chrome'], $result['active']['browser_s'], 'the active set must travel to the client');
        },

    /* -----------------------------------------------------------------------
     * Signed-in: three states, and the third is not a rounding error
     * -------------------------------------------------------------------- */

    'dimensions: the signed-in state is a real filterable dimension, not a read-only split' =>
        function (): void {
            [, $captured] = lh_vd_run('dimensions', []);
            $bodies = lh_vd_bodies($captured);
            lh_contains(
                $bodies,
                '"field":"signed_in_b"',
                'it is a terms facet on the field now, not two hand-written query facets'
            );
        },

    'dimensions: an unreported signed-in state is its own row, never folded into anonymous' =>
        function (): void {
            $saved = $_GET;
            $_GET = [];
            $captured = [];
            try {
                $transport = function (array $request) use (&$captured): array {
                    $captured[] = $request;
                    return [
                        'status' => 200,
                        'body'   => (string) json_encode([
                            'responseHeader' => ['status' => 0],
                            'response' => ['numFound' => 0, 'docs' => []],
                            'facets'   => [
                                'count'       => 100,
                                'signed_in_b' => ['buckets' => [
                                    ['val' => true, 'count' => 10],
                                    ['val' => false, 'count' => 15],
                                ]],
                            ],
                        ]),
                        'error'  => '',
                    ];
                };
                $cfg = lh_vd_config();
                $gw = new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);
                $result = (new Sessions($cfg, $gw))->api('dimensions');
            } finally {
                $_GET = $saved;
            }

            $group = null;
            foreach ($result['dimensions'] as $candidate) {
                if ($candidate['field'] === 'signed_in_b') {
                    $group = $candidate;
                }
            }
            lh_true($group !== null, 'the signed-in split must be offered as a dimension');
            lh_true($group['filterable'], 'it is in the filter allowlist now, so it must be pressable');

            $buckets = [];
            foreach ($group['buckets'] as $bucket) {
                $buckets[$bucket['value']] = $bucket;
            }
            lh_same(10, $buckets['true']['count'], 'the signed-in count must be reported as given');
            lh_same(15, $buckets['false']['count'], 'the anonymous count must be reported as given');
            lh_same('Signed in', $buckets['true']['label'], 'a boolean facet must not print the word "true"');
            lh_same('Anonymous', $buckets['false']['label']);

            lh_has_key($group, 'absent', 'the sessions in neither bucket must be accounted for');
            lh_same(
                75,
                $group['absent']['count'],
                'the remaining 75 were never classified and must be their own row, not anonymous'
            );
            lh_same(
                'none',
                $group['absent']['op'],
                'and it is a real filter now: neither true nor false is the "None of" operator over both'
            );
            lh_same(['true', 'false'], $group['absent']['values']);
        },

    'dimensions: a remainder is only offered when the arithmetic is sound' =>
        function (): void {
            [$result] = lh_vd_run('dimensions', []);
            foreach ($result['dimensions'] as $group) {
                if ($group['field'] !== 'signed_in_b') {
                    continue;
                }
                lh_no_key(
                    $group,
                    'absent',
                    'with no buckets for the two known values the remainder would be the whole population'
                );
            }
        },

    /* -----------------------------------------------------------------------
     * The beacon: identity and signed-in state
     * -------------------------------------------------------------------- */

    'beacon: the identity string is discarded entirely unless it is switched on' =>
        function (): void {
            $off = lh_vd_beacon();
            lh_false($off->storesIdentity(), 'store_identity must default to false');
            lh_same('', $off->normalise(['xi' => 'ada@example.com'])['ident'], 'an identity must not survive the gate');

            $on = lh_vd_beacon(['store_identity' => true]);
            lh_same(
                'ada@example.com',
                $on->normalise(['xi' => 'ada@example.com'])['ident'],
                'with the gate open the identity must survive intact'
            );
        },

    'beacon: a hostile identity string is bounded and stripped of control characters' =>
        function (): void {
            $b = lh_vd_beacon(['store_identity' => true]);

            $long = $b->normalise(['xi' => str_repeat('a', 5000)])['ident'];
            lh_true(strlen($long) <= Beacon::MAX_IDENT, 'the identity must be length-capped');

            $dirty = $b->normalise(['xi' => "ada\r\n\x00<script>@example.com"])['ident'];
            lh_false(str_contains($dirty, "\n"), 'a newline must not survive into a stored field');
            lh_false(str_contains($dirty, "\x00"), 'a NUL must not survive');
            lh_contains($dirty, '<script>', 'markup is kept as DATA and escaped at the sink, not silently rewritten');

            foreach ([['x'], 42, null, true] as $junk) {
                lh_same('', $b->normalise(['xi' => $junk])['ident'], 'a non-string identity must become empty');
            }
        },

    'beacon: the signed-in state is three-state and an absent one is never false' =>
        function (): void {
            $b = lh_vd_beacon();

            lh_same(true, $b->normalise(['xs' => 1])['signed_in'], 'integer 1 means signed in');
            lh_same(true, $b->normalise(['xs' => '1'])['signed_in'], 'the string "1" means signed in');
            lh_same(true, $b->normalise(['xs' => true])['signed_in'], 'boolean true means signed in');
            lh_same(false, $b->normalise(['xs' => 0])['signed_in'], 'integer 0 means anonymous');
            lh_same(false, $b->normalise(['xs' => '0'])['signed_in'], 'the string "0" means anonymous');

            lh_same(null, $b->normalise([])['signed_in'], 'an absent state must be null, never false');
            foreach (['maybe', '', 2, -1, ['1'], 1.5] as $junk) {
                lh_same(
                    null,
                    $b->normalise(['xs' => $junk])['signed_in'],
                    'an unparseable state is unknown, never anonymous: ' . lh_show($junk)
                );
            }
        },

    'beacon: switching the signed-in flag off drops it without touching the identity' =>
        function (): void {
            $b = lh_vd_beacon(['store_identity' => true, 'store_signed_in' => false]);
            $p = $b->normalise(['xi' => 'ada@example.com', 'xs' => 1]);
            lh_same(null, $p['signed_in'], 'the flag must be dropped when its own switch is off');
            lh_same('ada@example.com', $p['ident'], 'the two switches must be independent');

            $b2 = lh_vd_beacon(['store_identity' => false, 'store_signed_in' => true]);
            $p2 = $b2->normalise(['xi' => 'ada@example.com', 'xs' => 0]);
            lh_same('', $p2['ident'], 'the identity must be dropped when its own switch is off');
            lh_same(false, $p2['signed_in'], 'the flag must survive independently');
        },

    'beacon: a session nobody classified carries NO signed-in field on the document' =>
        function (): void {
            $b = lh_vd_beacon();
            $doc = $b->mergeIntoSession([], [
                ['id' => 1, 'pv' => 'p1', 'wall_ms' => 1000, 'signals' => []],
            ]);
            lh_no_key(
                $doc,
                'signed_in_b',
                'a site that said nothing must leave the field absent — absent is not anonymous'
            );
            lh_no_key($doc, 'ident_s', 'no identity means no field, not an empty one');
        },

    'beacon: an explicit anonymous session is recorded as false, not as absent' =>
        function (): void {
            $doc = lh_vd_beacon()->mergeIntoSession([], [
                ['id' => 1, 'pv' => 'p1', 'wall_ms' => 1000, 'signals' => [], 'signed_in' => false],
            ]);
            lh_has_key($doc, 'signed_in_b', 'an explicit answer must be stored');
            lh_same(false, $doc['signed_in_b'], 'explicitly anonymous is a fact worth keeping');
        },

    'beacon: signing in partway through a visit makes it a signed-in session' =>
        function (): void {
            $doc = lh_vd_beacon(['store_identity' => true])->mergeIntoSession([], [
                ['id' => 1, 'pv' => 'p1', 'wall_ms' => 1000, 'signals' => [], 'signed_in' => false],
                ['id' => 2, 'pv' => 'p2', 'wall_ms' => 2000, 'signals' => [], 'signed_in' => true,
                 'ident' => 'ada@example.com'],
            ]);
            lh_same(true, $doc['signed_in_b'], 'signed-in must win over anonymous within one session');
            lh_same('ada@example.com', $doc['ident_s'], 'the last non-empty identity must win');
        },

    'beacon: the identity is capped again on the way into the session document' =>
        function (): void {
            $doc = lh_vd_beacon(['store_identity' => true])->mergeIntoSession([], [
                ['id' => 1, 'pv' => 'p1', 'signals' => [], 'ident' => str_repeat('z', 4000)],
            ]);
            lh_true(
                mb_strlen($doc['ident_s']) <= Beacon::MAX_IDENT,
                'the staging table is on disk and could have been edited, so the cap is applied again here'
            );
        },

    'beacon: a session with no beacon rows gains neither field' =>
        function (): void {
            $doc = lh_vd_beacon(['store_identity' => true])->mergeIntoSession([], []);
            lh_no_key($doc, 'ident_s', 'no beacon means no identity');
            lh_no_key($doc, 'signed_in_b', 'no beacon means no signed-in state');
            lh_same(false, $doc['beacon_b'], 'the absence of a beacon is itself recorded');
        },

    /* -----------------------------------------------------------------------
     * The beacon script and the collector agree on the wire format
     * -------------------------------------------------------------------- */

    'beacon: b.js sends the two identity keys the server reads, and guesses neither' =>
        function (): void {
            $js = lh_vd_file('public/b.js');

            lh_contains($js, "out.xi = xIdent", 'the identity must be sent under the key the server normalises');
            lh_contains($js, "out.xs = xSigned", 'the signed-in state must be sent under the key the server reads');
            lh_contains($js, "attr('data-ident')", 'the script tag is the documented primary channel');
            lh_contains($js, "attr('data-signed-in')", 'the signed-in attribute must be read');
            lh_contains($js, 'w.loghound.identify', 'a late sign-in needs a hook no attribute can express');

            lh_false(
                (bool) preg_match('/document\.cookie|querySelector\([^)]*(email|password)/i', $js),
                'the beacon must never go looking for an identity the site did not declare'
            );
            lh_false(
                (bool) preg_match('/localStorage\s*(\[|\.\s*(get|set|remove)Item)/', $js),
                'the beacon stores nothing on the client (the header may mention it; nothing may USE it)'
            );
        },

    'beacon: an omitted signed-in state is omitted from the payload, not sent as 0' =>
        function (): void {
            $js = lh_vd_file('public/b.js');
            lh_contains(
                $js,
                'if (xSigned !== undefined) { out.xs = xSigned; }',
                'sending 0 for "not reported" would make every unadopted site look anonymous'
            );
        },

    'collect.php stages both fields and takes neither from anywhere but the payload' =>
        function (): void {
            $php = lh_vd_file('public/collect.php');
            lh_contains($php, "'ident'       => \$payload['ident']", 'the identity must be staged from the payload');
            lh_contains($php, "'signed_in'   => \$payload['signed_in']", 'the signed-in state must be staged');
            lh_false(
                str_contains($php, '$_COOKIE'),
                'the collector must never read a cookie to work out who somebody is'
            );
        },

    /* -----------------------------------------------------------------------
     * CSP and escaping on the new front end
     * -------------------------------------------------------------------- */

    'the new front-end modules contain no inline handler, no eval and no javascript: URL' =>
        function (): void {
            foreach ([
                'public/assets/js/dialog.js',
                'public/assets/js/identity.js',
                'public/assets/js/facets.js',
                'public/assets/js/detail.js',
            ] as $file) {
                $js = lh_vd_file($file);
                lh_false((bool) preg_match('/\bonclick\s*=/i', $js), $file . ' must not set an inline handler');
                lh_false(
                    (bool) preg_match('/[\'"`]javascript:/i', $js),
                    $file . ' must not build a javascript: URL'
                );
                lh_false((bool) preg_match('/\beval\s*\(/', $js), $file . ' must not eval');
                lh_false(str_contains($js, 'new Function'), $file . ' must not compile a function from a string');
                lh_false(
                    (bool) preg_match('/\.innerHTML\s*=/', $js),
                    $file . ' must build DOM with textContent, never innerHTML'
                );
                lh_false(
                    (bool) preg_match('/\.(outerHTML|insertAdjacentHTML)\b/', $js),
                    $file . ' must not reach a markup-parsing sink either'
                );
            }
        },

    'the dialog closes on the button, the overlay and Escape, and returns focus' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/dialog.js');
            lh_contains($js, "close.addEventListener('click', closeDialog)", 'the close button must close it');
            lh_contains($js, "scrim.addEventListener('click', closeDialog)", 'the overlay must close it');
            lh_contains($js, "event.key !== 'Escape'", 'Escape must close it');
            lh_contains($js, "event.key !== 'Tab'", 'Tab must be trapped while it is open');
            lh_contains($js, 'opener.focus()', 'focus must go back to whatever opened it');
            lh_contains($js, "'aria-modal': 'true'", 'a modal must announce itself as one');

            // Escape is bound to the DOCUMENT, not to the panel. A panel-scoped Escape only
            // works while focus is already inside the panel, which makes it useless in the one
            // situation it exists for — and the Tab trap used to leak focus out of the dialog,
            // so that situation was reachable. Measured in a real browser: with focus on
            // <body>, Escape now closes the dialog and returns focus to the opener.
            lh_contains(
                $js,
                "document.addEventListener('keydown', onDocumentKey)",
                'Escape must work from anywhere on the page, not only from inside the panel'
            );
        },

    'the focus trap keeps Tab inside the dialog even when its body holds no control' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/dialog.js');

            // THE MEASURED DEFECT. The focusable selector ended in a bare `[tabindex]`, which
            // matched the dialog body — created with tabindex="-1" so it can take focus on open
            // but never be tabbed to. A non-tabbable node therefore sat at the END of the list,
            // so the wrap-around branch never fired and Tab walked straight out of the modal
            // into the page behind it. Every freshly opened dialog was in that state, because
            // its body is the word "Loading…" until the fetch lands.
            lh_contains(
                $js,
                '[tabindex]:not([tabindex="-1"])',
                'a node that cannot be tabbed to must not be counted as the last tab stop'
            );
            lh_contains(
                $js,
                'input:not([disabled])',
                'a disabled field is not a tab stop either',
            );
            lh_contains(
                $js,
                "byId('lh-dialog-body').focus();",
                'a body with nothing tabbable in it still keeps Tab inside the dialog'
            );

            // aria-modal is a promise; inert is the mechanism. Without it the page behind the
            // scrim stayed tabbable and fully announced to a screen reader.
            lh_contains($js, "node.setAttribute('inert', '')", 'the page behind a modal must be inert');
            lh_contains($js, "node.removeAttribute('inert')", 'and must get its controls back on close');
        },

    'a dialog that fails offers a way to try again' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/dialog.js');

            // Every failed CARD in the panel offers a retry. A failed dialog offered nothing but
            // Close, so the only way to try again was to shut it, find the row again and press
            // it again — and a dialog opened from a facet list has no row to go back to.
            lh_contains($js, 'export function dialogFail(body, err, retry)', 'a failure can carry its own retry');
            lh_contains($js, "typeof retry === 'function'", 'and only draws the control when there is one');

            foreach ([
                'public/assets/js/detail.js'       => ['openSession(id)', 'openDimension(field, value)'],
                'public/assets/js/facetfilter.js'  => ['openValueBrowser(field, label, ns)'],
            ] as $file => $expected) {
                $src = lh_vd_file($file);
                foreach ($expected as $needle) {
                    lh_contains($src, 'dialogFail', $file . ' renders its failure into the dialog');
                    lh_contains($src, $needle, $file . ' passes ' . $needle . ' as the retry');
                }
            }
        },

    'a link inside a clickable row navigates instead of opening the dialog' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/dialog.js');
            lh_contains(
                $js,
                "target.closest('a[href], input, select, textarea')",
                'the filter link must win over the row it sits in'
            );

            // A button wins too — the expander, a copy control — EXCEPT the one whose whole
            // job is to open this dialog. Without that exception the explicit row opener was
            // swallowed by the guard protecting the links beside it, and since every identity
            // cell now carries two lines of links, a row with no opener reads as dead.
            lh_contains($js, "const button = target.closest('button');", 'a button still wins by default');
            lh_contains(
                $js,
                "!button.hasAttribute('data-lh-open')",
                'the row opener is the one button that must not be swallowed'
            );
            lh_contains(
                lh_vd_file('public/assets/js/identity.js'),
                'export function openButton(',
                'every drillable row needs one surface that is unambiguously "open this"'
            );
        },

    'a failed open is never a row that silently does nothing' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/dialog.js');
            lh_contains($js, "openDialog('That could not be opened'", 'an opener that threw before opening still reports');
            lh_contains($js, 'console.error(', 'the rejection must reach somewhere an operator can copy from');
        },

    'the demo world mints a session id that does not move between requests' =>
        function (): void {
            // The id was sha1 of the address, the start instant and a seeded draw. The draw is
            // reproducible and the instant is not, so every request minted a different id for
            // the same synthetic visit and the session dialog could never find one.
            $php = lh_vd_file('src/Panel/Fixtures.php');
            lh_false(
                str_contains($php, "sha1('lh' . \$ip . \$start"),
                'a demo id derived from the clock cannot be looked up on the next request'
            );

            $first = \Loghound\Panel\Fixtures::select('sessions.list', ['q' => '*:*', 'rows' => 1, 'fl' => 'id']);
            $id = (string) ($first['docs'][0]['id'] ?? '');
            lh_true($id !== '', 'the demo world must produce a session');

            $again = \Loghound\Panel\Fixtures::select('sessions.one', [
                'q' => '*:*',
                'fq' => ['id:"' . $id . '"'],
                'rows' => 1,
            ]);
            lh_same(1, count($again['docs']), 'the id the list handed out must still resolve');
        },

    'a value is only rendered as a filter link when the server would honour the field' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/identity.js');
            lh_contains($js, 'if (!isFilterable(field)', 'a link that cannot filter is a lie about what it does');
            lh_contains(
                $js,
                'boot.dimensions',
                'the filterable set comes from the server, not from a table retyped in the client'
            );
            foreach (array_keys(\Loghound\Panel\Query::filterFields()) as $field) {
                lh_false(
                    (bool) preg_match('/^\s*' . preg_quote($field, '/') . ':\s*\x27/m', $js),
                    $field . ': a second copy of the allowlist is what drifted last time'
                );
            }
        },

    'flags are drawn from codepoints, never fetched, and fall back to the plain code' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/identity.js');
            lh_contains($js, 'String.fromCodePoint', 'a flag must be composed locally');
            lh_contains($js, '0x1F1E6', 'the regional-indicator block is the whole mechanism');
            lh_contains($js, 'flagsSupported()', 'a platform that cannot compose them must get the plain code');
            lh_false(
                (bool) preg_match('/fetch\(|<img|\.src\s*=|url\(/', $js),
                'a flag must cost no request and no third-party asset — the panel has to work air-gapped'
            );
        },

    /* -----------------------------------------------------------------------
     * The rendered views
     * -------------------------------------------------------------------- */

    'every table in the views that were widened declares its columns and can scroll' =>
        function (): void {
            $saved = $_GET;
            $_GET = [];
            try {
                foreach ([
                    \Loghound\Panel\Sessions::class,
                    \Loghound\Panel\Bots::class,
                    \Loghound\Panel\Fingerprints::class,
                    \Loghound\Panel\Networks::class,
                    \Loghound\Panel\Hosts::class,
                ] as $class) {
                    $captured = [];
                    $view = new $class(lh_vd_config(), lh_vd_gateway($captured));
                    ob_start();
                    $view->body();
                    $html = (string) ob_get_clean();

                    foreach (['<table id=' => 'a table'] as $needle => $what) {
                        if (!str_contains($html, $needle)) {
                            continue;
                        }
                        $tables = substr_count($html, '<table id=');
                        lh_same(
                            $tables,
                            preg_match_all('/<table id=[^>]*class="(?:[^"]*\s)?table-fixed(?:\s[^"]*)?"/', $html),
                            $class . ': every ' . $what . ' must be fixed-layout so no column is pushed off screen'
                        );
                        lh_same(
                            $tables,
                            substr_count($html, '<colgroup>'),
                            $class . ': fixed layout only helps when the widths are declared'
                        );
                        lh_same(
                            $tables,
                            substr_count($html, '<div class="table-wrap">'),
                            $class . ': each table needs its own horizontal scroll container as the backstop'
                        );
                    }

                    lh_false(
                        (bool) preg_match('/\son[a-z]+\s*=/i', $html),
                        $class . ' must not emit an inline event handler; the CSP forbids one'
                    );
                    lh_false(
                        (bool) preg_match('/<script(?![^>]*type="application\/json")/i', $html),
                        $class . ' must not emit an inline script'
                    );
                }
            } finally {
                $_GET = $saved;
            }
        },

    'the session explorer no longer carries a permanently empty detail card' =>
        function (): void {
            $saved = $_GET;
            $_GET = [];
            try {
                $captured = [];
                $view = new Sessions(lh_vd_config(), lh_vd_gateway($captured));
                ob_start();
                $view->body();
                $html = (string) ob_get_clean();
            } finally {
                $_GET = $saved;
            }
            lh_false(
                str_contains($html, 'id="se-detail"'),
                'the detail is a shared dialog now, so the page must not grow an empty section for it'
            );
            lh_contains($html, 'Recent visitors', 'the table is the recent-visitors list and should say so');
            lh_contains($html, '>Where<', 'the flag and city column must exist');
        },

    'the search box value is escaped into the rendered form' =>
        function (): void {
            $saved = $_GET;
            $_GET = ['q' => '"><img src=x onerror=alert(1)>'];
            try {
                $captured = [];
                $view = new Sessions(lh_vd_config(), lh_vd_gateway($captured));
                ob_start();
                $view->body();
                $html = (string) ob_get_clean();
            } finally {
                $_GET = $saved;
            }
            lh_false(
                str_contains($html, '"><img src=x onerror=alert(1)>'),
                'the hostile term must never appear verbatim; if it does it has broken out of the attribute'
            );
            lh_false(str_contains($html, '<img'), 'a hostile search term must not become an element');
            lh_contains(
                $html,
                '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;',
                'it must be escaped in full, not stripped'
            );
        },

    /* -----------------------------------------------------------------------
     * Style rules this project holds itself to
     * -------------------------------------------------------------------- */

    'the appended stylesheet block uses tokens and hex, never a colour name' =>
        function (): void {
            $css = lh_vd_file('public/assets/css/panel.css');
            $at = strpos($css, 'VISITOR DETAIL — flags, the value-as-filter control');
            lh_true($at !== false, 'the appended block must be findable so another agent can leave it alone');
            $block = substr($css, $at);

            foreach (['white', 'black', 'red', 'blue', 'green', 'grey', 'gray', 'orange'] as $name) {
                lh_false(
                    (bool) preg_match('/:\s*' . $name . '\b/i', $block),
                    'a colour name (' . $name . ') is never acceptable; use a token or a hex code'
                );
            }
            lh_false(
                (bool) preg_match('/font-size:\s*(\d|1[0-3])px/', $block),
                'nothing on a public surface goes below 14px'
            );
            lh_contains($block, 'var(--accent)', 'the one accent comes from the theme tokens');
            lh_contains($block, '@media (max-width: 900px)', 'the dialog must work at phone width');
        },

    'nothing in the new code claims an AI wrote it' =>
        function (): void {
            foreach ([
                'public/assets/js/dialog.js',
                'public/assets/js/identity.js',
                'public/assets/js/facets.js',
                'public/assets/js/detail.js',
                'src/Panel/Sessions.php',
                'docs/BEACON.md',
            ] as $file) {
                $body = lh_vd_file($file);
                lh_false(
                    (bool) preg_match('/\b(Claude|Anthropic|Copilot|ChatGPT|GPT-4|generated by an? AI)\b/i', $body),
                    $file . ' must carry no AI attribution'
                );
            }
        },

    'docs/BEACON.md documents both fields, the switches and the storage consequence' =>
        function (): void {
            $md = lh_vd_file('docs/BEACON.md');
            lh_contains($md, 'data-ident', 'the identity attribute must be documented');
            lh_contains($md, 'data-signed-in', 'the signed-in attribute must be documented');
            lh_contains($md, 'beacon.store_identity', 'the switch must be named');
            lh_contains($md, 'beacon.store_signed_in', 'the second switch must be named');
            lh_contains($md, 'Three states, not two', 'the absent state must be explained, not glossed over');
            lh_contains($md, 'window.loghound.identify', 'the late-sign-in hook must be documented');
            lh_contains($md, 'personal data', 'the storage consequence must be stated plainly');
            lh_contains($md, '**no second', 'the design constraint must be stated');
        },

    'the installer beacon step mentions both attributes and what the identity costs' =>
        function (): void {
            $note = \Loghound\Setup\Steps::beaconIdentityNote();
            lh_contains($note, 'data-signed-in', 'the installer must mention the signed-in attribute');
            lh_contains($note, 'data-ident', 'the installer must mention the identity attribute');
            lh_contains($note, 'beacon.store_identity', 'it must name the switch that governs storage');
            lh_contains($note, 'personal data', 'it must say what storing an identity means');

            $view = lh_vd_file('src/Setup/View.php');
            lh_contains($view, 'beaconIdentityNote()', 'and the finish screen must actually render it');
        },

    'the shipped example configuration explains both new settings' =>
        function (): void {
            $example = lh_vd_file('config/loghound.example.php');
            lh_contains($example, "'store_identity' => false", 'the identity switch must ship off');
            lh_contains($example, "'store_signed_in' => true", 'the boolean switch may ship on');
            lh_contains($example, 'WHAT IT STORES', 'a setting about personal data must say what it stores');

            $defaults = lh_vd_file('src/Config.php');
            lh_contains($defaults, "'store_identity'   => false", 'the real default must match the example');
            lh_contains($defaults, "'store_signed_in'  => true", 'the real default must match the example');
        },
    /* -----------------------------------------------------------------------
     * The facet control, and sorting
     * -------------------------------------------------------------------- */

    'the facet renderer is shared, so no view can grow an unrecognisable one of its own' =>
        function (): void {
            $sidebar = lh_vd_file('public/assets/js/views/sessions.js');
            lh_contains($sidebar, "import { activeFilters, renderFacetPanel } from '../facets.js'", 'one renderer');
            lh_false(
                str_contains($sidebar, "class: 'facet-group'"),
                'the session explorer must not keep its own bespoke facet markup'
            );
        },

    'a facet value is the whole row, looks pressable, and toggles itself off' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/facets.js');
            lh_contains($js, "class: 'facet-opt'", 'the row itself is the control');
            lh_contains(
                $js,
                'toggleUrl(group.field, bucket.value',
                'one gesture selects and deselects, and it keeps the operator in force'
            );
            lh_contains($js, "state === 'on' ? ' is-on' : ''", 'the selected state must be on the row');
            lh_contains(
                $js,
                "state === 'excluded' ? ' is-excluded' : ''",
                'and so must the third state, because a tick beside an excluded value is a lie'
            );
            lh_contains($js, "'aria-label'", 'a screen reader gets neither the bar nor the tick');
            lh_contains($js, "class: 'facet-fill'", 'the distribution must be readable without reading a number');
            lh_contains($js, "class: 'facet-n'", 'the count needs its own aligned column');
        },

    'the panel does not assert fixed boolean semantics in prose' =>
        function (): void {
            // The paragraph that explained OR-within / AND-across is gone: it was a third of
            // the expanded panel's width, and the behaviour it asserted is becoming per
            // dimension and explicit in the controls, which would have made it wrong as well
            // as noisy. Whatever states it now, it is not a sentence in a constant.
            $php = lh_vd_file('src/Panel/Sessions.php');
            lh_false(str_contains($php, 'MULTI_SELECT_NOTE'), 'the constant and its uses are retired');
            lh_false(str_contains($php, 'Picking several values'), 'and so is the sentence');

            [$result] = lh_vd_run('facets', []);
            lh_no_key($result, 'multi', 'the payload must stop carrying it too');
        },

    'a long value list has a way in: show all, and a box that filters the values' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/facetfilter.js');
            lh_contains($js, "class: 'facet-more'", 'the top N needs a way to the rest');
            lh_contains($js, "api('sessions', 'values'", 'show all must fetch the full list');
            lh_contains($js, "class: 'facet-q'", 'a long list needs its own search box');
            lh_contains($js, 'indexOf(needle)', 'the box filters over every value, not only the rows on screen');
            lh_contains(lh_vd_file('public/assets/js/facets.js'), 'showAllButton(', 'and the list uses the shared control');
        },

    'values: one dimension, bounded, and only a dimension the allowlist carries' =>
        function (): void {
            [$bad, $none] = lh_vd_run('values', ['field' => 'ua_s']);
            lh_has_key($bad, 'error', 'an unknown dimension');
            lh_same([], $none, 'a refused dimension must not reach Solr');

            [$ok, $captured] = lh_vd_run('values', ['field' => 'as_org_s']);
            lh_same(null, $ok['error'], 'a valid dimension must produce no error');
            lh_same('as_org_s', $ok['field'], 'the field must be echoed back');

            $bodies = lh_vd_bodies($captured);
            lh_contains($bodies, '"field":"as_org_s"', 'the requested dimension must be faceted');
            lh_false(
                str_contains($bodies, '"field":"country_s"'),
                'a single-dimension request must not facet every other dimension as well'
            );
            lh_false(str_contains($bodies, '"limit":-1'), 'an unbounded terms facet enumerates the whole field');
        },

    'a selected value is always visible even when it falls outside the top N' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/facets.js');
            lh_contains($js, 'const picked =', 'the selected values must be identified separately');
            lh_contains($js, 'head.indexOf(bucket) < 0', 'a selected value outside the head must be appended');
        },

    'every table can be sorted by every named column, in both directions' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/sorttable.js');
            lh_contains($js, "th.classList.add('sortable')", 'headers must gain the affordance');
            lh_contains($js, "setAttribute('aria-sort'", 'the current sort must be announced');
            lh_contains($js, "'sorted-desc' : 'sorted-asc'", 'the direction must be visible');
            lh_contains($js, "table.dataset.sortDir === 'asc' ? 'desc' : 'asc'", 'a second press must reverse it');
            // KEYBOARD OPERATION COMES FROM A REAL BUTTON NOW, not from a keydown listener on
            // the <th>. The header used to carry tabindex="0" and a handler with no role at
            // all, so a screen reader announced "column header, Requests" and said nothing
            // about it being pressable — a control that reads as text. Putting role="button" on
            // the <th> would have been worse: it stops being a columnheader and its
            // presentational children take the header's own text out of the accessibility tree.
            //
            // The keydown listener had to GO at the same time, not merely be joined by a
            // button: a button fires a click for Enter and for Space itself, so keeping both
            // sorted twice per press and flipped the direction straight back. Measured in a
            // real browser: one Enter sorts ascending, the second descending.
            lh_contains($js, "button.className = 'sort-btn'", 'the sort control must be a real button');
            lh_contains($js, "th.removeAttribute('tabindex')", 'the header itself must stop being the control');
            lh_false(
                str_contains($js, "document.addEventListener('keydown', onActivate)"),
                'a native button already turns Enter and Space into a click; a second listener sorts twice'
            );
            lh_false(
                str_contains($js, "th.setAttribute('role'"),
                'a <th> with role=button is no longer a column header and hides its own text from AT'
            );
            lh_contains($js, "classList.contains('w-expand')", 'a control column has nothing to sort by');
            lh_false((bool) preg_match('/\bonclick\s*=/i', $js), 'the CSP forbids an inline handler');
        },

    'sorting sends absent values to the bottom whichever way the column is sorted' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/sorttable.js');
            lh_contains($js, "if (a === '') {\n        return 1;", 'an unknown must never lead a descending sort');
            lh_contains($js, "text === '—'", 'an em dash is an absence, not a string to sort');
        },

    'sorting keeps an expanded sub-row attached to the row it belongs to' =>
        function (): void {
            $js = lh_vd_file('public/assets/js/sorttable.js');
            lh_contains($js, 'ATTACHED', 'a members row must travel with its cluster');
            lh_contains($js, 'groups[groups.length - 1].extra.push(row)', 'or the addresses land under the wrong one');
        },

    'a duration or a timestamp carries its own sort key rather than being parsed back' =>
        function (): void {
            $core = lh_vd_file('public/assets/js/core.js');
            lh_contains($core, "'data-sort': cell.sort", 'the cell builder must accept a sort key');

            $sessions = lh_vd_file('public/assets/js/views/sessions.js');
            lh_contains($sessions, "'data-sort': doc.ts_start", 'a rendered timestamp sorts wrongly as a string');
            lh_contains($sessions, "String(doc.hits)", 'a rendered count sorts wrongly as a string');
            lh_contains($sessions, "String(doc.score)", 'a verdict cell sorts by its score, not by the word');

            // Log span and engaged time are no longer columns in this table — seven columns fit
            // where ten did not — so the pin moved to the dialog that still shows both.
            $detail = lh_vd_file('public/assets/js/detail.js');
            lh_contains($detail, 'log_span', 'the dialog is where a session\'s two clocks are read now');

            $networks = lh_vd_file('public/assets/js/views/networks.js');
            lh_contains($networks, 'sort: row.sessions', 'a formatted count sorts wrongly as a string');
        },

    'prose is set in the body face and only identifiers are monospace' =>
        function (): void {
            // `.chip` IS the body face now, so the `chip-word` opt-in that used to correct it is
            // gone from the stylesheet and from every call site. The rule it encoded is stronger
            // for being the default: a chip carries a word, and a chip that really holds an
            // identifier asks for `.mono` like every other identifier in the panel.
            foreach ([
                'public/assets/js/views/sessions.js',
                'public/assets/js/views/fingerprints.js',
                'public/assets/js/detail.js',
                'public/assets/js/views/bots.js',
            ] as $file) {
                lh_false(
                    str_contains(lh_vd_file($file), 'chip-word'),
                    $file . ': the chip is the body face by default; the opt-in is retired'
                );
            }

            $css = lh_vd_file('public/assets/css/panel.css');
            lh_false(str_contains($css, '.chip-word {'), 'the retired variant must not come back');
            lh_contains($css, 'font: 600 14px/1.4 var(--font-ui)', 'a chip is set in the body face');
            lh_contains($css, '.explorer .facets { border-right', 'the sidebar needs a boundary, not just a heading');

            $networks = lh_vd_file('public/assets/js/views/networks.js');
            lh_false(
                str_contains($networks, "dimValue('as_org_s', row.org, { mono: true })"),
                'an organisation name is prose and must not be set as code'
            );
        },

    'an absent value is an em dash of its own, never a separator with nothing beside it' =>
        function (): void {
            $sessions = lh_vd_file('public/assets/js/views/sessions.js');
            lh_contains($sessions, 'if (lower.length) {', 'the separator is only emitted between two real values');
            lh_false(
                str_contains($sessions, "join(' · ') || '—'"),
                'joining possibly-empty parts and falling back leaves a stray separator in the middle'
            );
        },

    'no view closes a card content wrapper that was never opened' =>
        function (): void {
            foreach ([
                'src/Panel/Sessions.php',
                'src/Panel/Bots.php',
                'src/Panel/Fingerprints.php',
                'src/Panel/Networks.php',
                'src/Panel/Hosts.php',
            ] as $file) {
                $php = lh_vd_file($file);
                $closes = preg_match_all('/self::cardClose\(/', $php);
                $skeletons = preg_match_all('/self::skeleton\(/', $php);
                lh_true(
                    $closes <= $skeletons,
                    $file . ': cardClose() closes the content div that only skeleton() opens, so a card without '
                    . 'one must call cardEnd() instead — otherwise it emits a stray </div> and closes the page '
                    . 'container early'
                );
            }
        },
];
