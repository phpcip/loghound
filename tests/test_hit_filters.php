<?php
/**
 * Loghound — tests for filter scoping across the two cores.
 *
 * The sidebar filters every view, but the panel queries two indexes with deliberately
 * different schemas. Hits carry what the log line said; sessions additionally carry what
 * the scorer concluded. An `fq` naming a field a core does not define matches nothing, so
 * the wrong list on the wrong core turns a filtered view into an empty one — and the right
 * list applied to neither turns a scoped view into an unscoped one showing every site on
 * the machine under a chip that names one.
 *
 * Both failures were live: `hitFqs()` returned the time range alone, so the virtual-host
 * selector silently did nothing to Performance.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Panel\Performance;
use Loghound\Panel\Query;
use Loghound\Solr;

/**
 * A Controller subclass that exposes the protected `fq` builders for inspection.
 */
final class LhFilterProbe extends Controller
{
    public function slug(): string
    {
        return 'probe';
    }

    public function title(): string
    {
        return 'Probe';
    }

    public function subtitle(): string
    {
        return 'Test double';
    }

    public function body(): void
    {
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return [];
    }

    /**
     * @return array<int,string>
     */
    public function probeHitFqs(): array
    {
        return $this->hitFqs();
    }

    /**
     * @return array<int,string>
     */
    public function probeSessionFqs(): array
    {
        return $this->sessionFqs();
    }

    /**
     * @return array<int,string>
     */
    public function probeIgnored(): array
    {
        return $this->ignoredHitFilters();
    }

    /**
     * @param array<int,string> $allowed
     */
    public static function probeParam(string $key, array $allowed, string $default): string
    {
        return self::param($key, $allowed, $default);
    }
}

/**
 * Build a probe controller with the given `$_GET` in place.
 *
 * @param array<string,mixed> $get
 */
function lh_filter_probe(array $get): LhFilterProbe
{
    $_GET = $get;

    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');

    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode(['responseHeader' => ['status' => 0]]),
        'error'  => '',
    ];

    return new LhFilterProbe($cfg, new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false));
}

/**
 * The field names a schema file actually defines.
 *
 * @return array<int,string>
 */
function lh_filter_schema_fields(string $relative): array
{
    $xml = (string) file_get_contents(__DIR__ . '/../' . $relative);
    preg_match_all('/<(?:field|dynamicField)\b[^>]*\bname="([^"]+)"/', $xml, $m);
    return $m[1];
}

return [

    'an empty allowlist admits nothing instead of everything' => static function (): void {
        $got = LhFilterProbe::probeParam('kind', [], 'fallback');
        if ($got !== 'fallback') {
            throw new \RuntimeException(
                'param() returned the raw request value ' . var_export($got, true)
                . ' for an empty allowlist, so a caller building the list dynamically loses the guard '
                . 'at exactly the moment the list comes back empty.'
            );
        }
        $_GET = [];
    },

    'an allowlisted value still passes and a foreign one still falls back'
        => static function (): void {
            $_GET = ['kind' => 'html'];
            if (LhFilterProbe::probeParam('kind', ['html', 'asset'], 'html') !== 'html') {
                throw new \RuntimeException('A value on the allowlist was rejected.');
            }
            $_GET = ['kind' => 'evil'];
            if (LhFilterProbe::probeParam('kind', ['html', 'asset'], 'html') !== 'html') {
                throw new \RuntimeException('A value off the allowlist was accepted.');
            }
            $_GET = [];
        },

    'every hits filter field is defined by the hits schema' => static function (): void {
        $defined = lh_filter_schema_fields('solr/hits/conf/schema.xml');

        foreach (array_keys(Query::hitFilterFields()) as $field) {
            if (!in_array($field, $defined, true)) {
                throw new \RuntimeException(
                    'hitFilterFields() offers ' . $field . ', which the hits schema does not define. '
                    . 'Every query carrying it will match nothing.'
                );
            }
        }
    },

    'every sidebar filter field reaches a field the sessions schema defines'
        => static function (): void {
            $defined = lh_filter_schema_fields('solr/sessions/conf/schema.xml');
            $aliases = Query::sessionFilterAliases();

            /* THE SESSIONS SUBSET. The master allowlist now carries hits-only dimensions, so the
               question this test asks has to be asked of the list the sessions plane actually
               offers — Facets::sessions() reads that one, and so does the sidebar. */
            foreach (array_keys(Query::sessionFilterFields()) as $field) {
                $onCore = $aliases[$field] ?? $field;
                if (!in_array($onCore, $defined, true)) {
                    throw new \RuntimeException(
                        'filterFields() offers ' . $field . ', which reaches the sessions core as '
                        . $onCore . ' — a field that schema does not define, so the filter answers '
                        . 'zero instead of refusing.'
                    );
                }
            }
        },

    'a hits-only dimension is defined by the hits core and absent from the sessions core'
        => static function (): void {
            $hits = lh_filter_schema_fields('solr/hits/conf/schema.xml');
            $sessions = lh_filter_schema_fields('solr/sessions/conf/schema.xml');
            $offered = Query::filterFields();

            lh_true(Query::hitsOnlyFields() !== [], 'the hits-only list is not empty');

            foreach (Query::hitsOnlyFields() as $field) {
                lh_true(isset($offered[$field]), $field . ' is a dimension at all');
                lh_true(in_array($field, $hits, true), $field . ' is defined by the hits schema');
                lh_false(
                    in_array($field, $sessions, true),
                    $field . ' is listed as hits-only, so the sessions schema must NOT define it — '
                    . 'if it does, the subtraction is hiding a dimension that would have worked'
                );
                lh_false(
                    isset(Query::sessionFilterFields()[$field]),
                    $field . ' must not reach the sessions plane'
                );
            }
        },

    'an alias only ever renames a field into one that exists' => static function (): void {
        $defined = lh_filter_schema_fields('solr/sessions/conf/schema.xml');
        $offered = Query::filterFields();

        foreach (Query::sessionFilterAliases() as $from => $to) {
            if (!isset($offered[$from])) {
                throw new \RuntimeException('An alias renames ' . $from . ', which is not a sidebar filter.');
            }
            if (!in_array($to, $defined, true)) {
                throw new \RuntimeException('An alias points at ' . $to . ', which the sessions schema lacks.');
            }
            if (!\Loghound\Security::isSafeFieldName($to)) {
                throw new \RuntimeException('An alias produces an unsafe field name: ' . $to);
            }
        }
    },

    'the Session chip is spelled for the core it is sent to' => static function (): void {
        $probe = lh_filter_probe(['f' => ['session_id_s' => ['s-abc123']]]);

        $sessions = implode(' | ', $probe->probeSessionFqs());
        if (!str_contains($sessions, 'id:("s-abc123")')) {
            throw new \RuntimeException(
                'The Session filter reached the sessions core under a name it does not define, so it '
                . 'matched nothing and read as an empty session. Got: ' . $sessions
            );
        }

        $hits = implode(' | ', $probe->probeHitFqs());
        if (!str_contains($hits, 'session_id_s:("s-abc123")')) {
            throw new \RuntimeException(
                'The Session filter lost its hits-core spelling. Got: ' . $hits
            );
        }
        $_GET = [];
    },

    'the fields excluded from the hits list are the session-only conclusions'
        => static function (): void {
            $missing = array_diff_key(Query::filterFields(), Query::hitFilterFields());

            $expected = [
                'bot_verdict_s',
                'bot_class_s',
                'bot_reasons_ss',
                'paths_ss',
                'signed_in_b',
                'planes_s',
            ];

            if (array_keys($missing) !== $expected) {
                throw new \RuntimeException(
                    'The hits/sessions filter split changed to: ' . implode(', ', array_keys($missing))
                    . '. If a field was added to filterFields() it must be present on BOTH schemas or '
                    . 'excluded here on purpose. The three verdict fields are the scorer\'s conclusions '
                    . 'about a whole session; paths_ss is the set of paths a session touched, and a hit '
                    . 'has one path, not a set; signed_in_b is what the site told the beacon, which '
                    . 'arrives once per session and never per log line; planes_s records which '
                    . 'transport planes have seen a SESSION, and a hit is one line on one of them. '
                    . 'search_terms_ss is deliberately NOT here: it is on both schemas.'
                );
            }
        },

    'the virtual-host filter reaches a hits-core query' => static function (): void {
        $probe = lh_filter_probe(['f' => ['host_s' => ['shop.example.com']]]);
        $fqs = $probe->probeHitFqs();

        $found = false;
        foreach ($fqs as $fq) {
            if (str_contains($fq, Query::HOST_FIELD) && str_contains($fq, 'shop.example.com')) {
                $found = true;
            }
        }
        if (!$found) {
            throw new \RuntimeException(
                'Picking one virtual host left the hits-core query unscoped, so Performance would report '
                . 'the latency of every site on the machine under a chip naming one. Got: '
                . implode(' | ', $fqs)
            );
        }
        $_GET = [];
    },

    'a session-only filter never reaches a hits-core query' => static function (): void {
        $probe = lh_filter_probe(['f' => ['bot_verdict_s' => ['bot'], 'country_s' => ['RO']]]);
        $fqs = $probe->probeHitFqs();

        foreach ($fqs as $fq) {
            if (str_contains($fq, 'bot_verdict_s')) {
                throw new \RuntimeException(
                    'A verdict filter reached the hits core, which does not define the field, so the '
                    . 'whole view would answer zero. Got: ' . $fq
                );
            }
        }

        $kept = false;
        foreach ($fqs as $fq) {
            if (str_contains($fq, 'country_s')) {
                $kept = true;
            }
        }
        if (!$kept) {
            throw new \RuntimeException('Dropping the session-only filter also dropped a usable one.');
        }
        $_GET = [];
    },

    'the sessions core still receives every filter' => static function (): void {
        $probe = lh_filter_probe(['f' => ['bot_verdict_s' => ['bot'], 'host_s' => ['a.example.com']]]);
        $joined = implode(' | ', $probe->probeSessionFqs());

        foreach (['bot_verdict_s', 'host_s', 'doc_type_s:session'] as $expected) {
            if (!str_contains($joined, $expected)) {
                throw new \RuntimeException('The sessions query lost ' . $expected . ': ' . $joined);
            }
        }
        $_GET = [];
    },

    'a dropped filter is named, not silently ignored' => static function (): void {
        $probe = lh_filter_probe(['f' => ['bot_verdict_s' => ['bot'], 'country_s' => ['RO']]]);
        $ignored = $probe->probeIgnored();

        if ($ignored !== ['Verdict']) {
            throw new \RuntimeException(
                'Expected the Verdict filter to be reported as unhonoured, got: '
                . var_export($ignored, true)
            );
        }
        $_GET = [];
    },

    'nothing is reported when every active filter applies' => static function (): void {
        $probe = lh_filter_probe(['f' => ['country_s' => ['RO']]]);
        if ($probe->probeIgnored() !== []) {
            throw new \RuntimeException('A filter the hits core can answer was reported as ignored.');
        }
        $_GET = [];
    },

    'every Performance response carries the list, so no action can forget it'
        => static function (): void {
            $method = new \ReflectionMethod(Performance::class, 'envelope');
            if ($method->getDeclaringClass()->getName() !== Performance::class) {
                throw new \RuntimeException(
                    'Performance no longer overrides envelope(), so the four action methods each have to '
                    . 'remember to report ignored filters, and one of them will not.'
                );
            }

            $js = (string) file_get_contents(__DIR__ . '/../public/assets/js/views/performance.js');
            if (!str_contains($js, 'filters_ignored')) {
                throw new \RuntimeException('The view sends the list and the front end never reads it.');
            }
        },
];
