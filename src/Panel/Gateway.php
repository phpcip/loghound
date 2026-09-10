<?php
/**
 * Loghound — the panel's only door to Solr.
 *
 * Every Panel controller talks to this class and never to \Loghound\Solr directly. Two
 * reasons:
 *
 *  1. **Demo mode.** The panel must render on a box where Solr has never been reachable —
 *     a fresh clone, a screenshot session, an offline demo. Routing all reads through one
 *     object means demo data can be substituted at a single point, and it means the demo
 *     responses go through exactly the same PHP shaping code as real ones, so a bug in
 *     the shaping shows up in the demo instead of hiding there.
 *
 *  2. **Failure is a UI state, not an exception.** A Solr that is down should produce a
 *     dashboard with an honest banner, not a stack trace. Every method here returns a
 *     usable empty structure and records the error for the banner.
 *
 * Each call carries a `$tag`: a short stable name for the query's *shape*. The tag is
 * what demo mode dispatches on, and it is what appears in the debug footer. It is chosen
 * by the calling controller and never comes from the request.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\Security;

final class Gateway
{
    private Config $cfg;

    /**
     * The real Solr client (\Loghound\Solr), or null when the class is not present yet
     * or the configuration is incomplete. Typed as object so this file has no compile-time
     * dependency on a class another agent owns.
     */
    private ?object $solr;

    private bool $demo;

    /** @var string|null Last transport/Solr error, surfaced in the panel banner. */
    private ?string $error = null;

    /** @var array<int,array{tag:string,core:string,ms:float}> Query log for the debug footer. */
    private array $log = [];

    /**
     * @param bool $demo When true, no network call is ever made and Fixtures answers.
     */
    public function __construct(Config $cfg, ?object $solr, bool $demo)
    {
        $this->cfg  = $cfg;
        $this->solr = $solr;
        $this->demo = $demo;
    }

    /**
     * Build a gateway from config, deciding demo mode and instantiating Solr if possible.
     *
     * Demo mode is explicit and never inferred from "Solr happens to be down": a silently
     * fabricated dashboard is worse than an empty one. It turns on only when the operator
     * asks, via `LOGHOUND_DEMO=1` in the environment or `ui.demo => true` in the config.
     */
    public static function fromConfig(Config $cfg): self
    {
        $demo = getenv('LOGHOUND_DEMO') === '1' || $cfg->get('ui.demo') === true;

        $solr = null;
        if (!$demo && class_exists('\\Loghound\\Solr')) {
            try {
                $solrCfg = (array) $cfg->get('solr', []);
                $solrCfg['timeout'] = self::queryTimeout($cfg);
                $solr = new \Loghound\Solr($solrCfg);
            } catch (\Throwable $e) {
                $solr = null;
            }
        }

        return new self($cfg, $solr, $demo);
    }

    /**
     * How long a single panel query may take, in seconds.
     *
     * Chosen to sit comfortably under the reference install's PHP-FPM
     * `max_execution_time = 60`, so a slow Solr produces a readable error inside the
     * panel rather than a killed process and a gateway error page. Operator-tunable via
     * `ui.query_timeout`, but clamped: no value here may make a request outlive the
     * process that issued it.
     */
    public static function queryTimeout(Config $cfg): int
    {
        return Security::clampInt($cfg->get('ui.query_timeout'), 3, 45, 20);
    }

    /** Is the panel showing fabricated data? Drives the permanent demo banner. */
    public function isDemo(): bool
    {
        return $this->demo;
    }

    /** The last Solr error, if any. Rendered in the panel's connection banner. */
    public function error(): ?string
    {
        return $this->error;
    }

    /** @return array<int,array{tag:string,core:string,ms:float}> */
    public function queryLog(): array
    {
        return $this->log;
    }

    /** Name of the sessions core, from config. */
    public function sessionsCore(): string
    {
        return (string) $this->cfg->get('solr.sessions_core', 'loghound_sessions');
    }

    /** Name of the hits core, from config. */
    public function hitsCore(): string
    {
        return (string) $this->cfg->get('solr.hits_core', 'loghound_hits');
    }

    /**
     * Is the backend reachable at all?
     *
     * Used once per page render to decide between "no data yet, here is how to start"
     * and "your Solr is unreachable", which are very different problems for the operator.
     */
    public function ping(): bool
    {
        if ($this->demo) {
            return true;
        }
        if ($this->solr === null) {
            $this->error = 'Solr client is not available (src/Solr.php missing or configuration incomplete).';
            return false;
        }
        try {
            $ref = new \ReflectionMethod($this->solr, 'ping');
            $ok = $ref->getNumberOfParameters() > 0
                ? (bool) $this->solr->ping($this->sessionsCore())
                : (bool) $this->solr->ping();
            if (!$ok) {
                $this->error = 'Solr did not respond to a ping on core "' . $this->sessionsCore() . '".';
            }
            return $ok;
        } catch (\Throwable $e) {
            $this->error = 'Solr ping failed: ' . $e->getMessage();
            return false;
        }
    }

    /**
     * Run a free-text search and return documents.
     *
     * Free text is the one input that cannot be an allowlist, so it never passes through
     * this class as query syntax. \Loghound\Solr::queryText() exists precisely for it:
     * it binds the text as the `uq` parameter and references it from a `{!edismax v=$uq}`
     * switch that the client itself wrote. Solr::assertSafeQuery() accepts exactly that
     * one form of `q` and nothing else, so there is no way to smuggle a parser change
     * through — a hand-built variant would simply be refused.
     *
     * @param array<string,mixed> $params fq/sort/rows/start/fl. Must not contain q or uq.
     * @return array{docs:array<int,array<string,mixed>>,numFound:int}
     */
    public function search(string $tag, string $core, string $text, array $params): array
    {
        if ($this->demo) {
            return $this->select($tag, $core, $params + ['q' => $text === '' ? '*:*' : 'text', 'uq' => $text]);
        }
        if ($this->solr === null) {
            $this->error ??= 'Solr client is not available.';
            return ['docs' => [], 'numFound' => 0];
        }

        $started = microtime(true);
        try {
            $resp = method_exists($this->solr, 'queryText')
                ? $this->solr->queryText($core, $text, $params)
                : $this->solr->query($core, array_merge($params, Query::textSearch($text)));
            $this->note($tag, $core, $started);
            return [
                'docs'     => (array) ($resp['response']['docs'] ?? []),
                'numFound' => (int) ($resp['response']['numFound'] ?? 0),
            ];
        } catch (\Throwable $e) {
            $this->error = self::explain($tag, $e);
            return ['docs' => [], 'numFound' => 0];
        }
    }

    /**
     * Run a free-text search that returns only facets.
     *
     * The facet sidebar in the session explorer must describe the result set the operator
     * is looking at, which means the same bound text has to reach the facet request too.
     *
     * @param array<string,mixed> $params
     * @param array<string,mixed> $facet
     * @return array<string,mixed>
     */
    public function searchFacet(string $tag, string $core, string $text, array $params, array $facet): array
    {
        if ($this->demo || $text === '') {
            $q = $this->demo
                ? $params + ['q' => $text === '' ? '*:*' : 'text', 'uq' => $text]
                : $params + ['q' => '*:*'];
            return $this->facet($tag, $core, $q, $facet);
        }
        if ($this->solr === null) {
            $this->error ??= 'Solr client is not available.';
            return ['count' => 0];
        }

        $started = microtime(true);
        try {
            $resp = $this->solr->jsonFacet($core, array_merge($params, [
                'q'  => '{!edismax v=$uq}',
                'uq' => $text,
                'qf' => Query::QF_FIELDS,
                'mm' => '100%',
            ]), $facet);
            $this->note($tag, $core, $started);
            return $this->normaliseFacets($resp);
        } catch (\Throwable $e) {
            $this->error = self::explain($tag, $e);
            return ['count' => 0];
        }
    }

    /**
     * Run a JSON Facet request and return the `facets` block.
     *
     * This is the workhorse: nearly every number in the dashboard is a facet, not a
     * document. `rows=0` is forced so an aggregate query can never accidentally ship
     * documents to the browser.
     *
     * @param string               $tag   Stable shape name (also the demo-fixture key).
     * @param array<string,mixed>  $query Solr request parameters (q, fq, ...).
     * @param array<string,mixed>  $facet The json.facet structure.
     * @return array<string,mixed> The facets block, always with a numeric 'count'.
     */
    public function facet(string $tag, string $core, array $query, array $facet): array
    {
        $query['rows'] = 0;
        $started = microtime(true);

        if ($this->demo) {
            $facets = Fixtures::facet($tag, $query, $facet);
            $this->note($tag, $core, $started);
            return $this->normaliseFacets($facets);
        }

        if ($this->solr === null) {
            $this->error ??= 'Solr client is not available.';
            return ['count' => 0];
        }

        try {
            $resp = $this->solr->jsonFacet($core, $query, $facet);
            $this->note($tag, $core, $started);
            return $this->normaliseFacets($resp);
        } catch (\Throwable $e) {
            $this->error = self::explain($tag, $e);
            return ['count' => 0];
        }
    }

    /**
     * Run a document query and return `['docs' => [...], 'numFound' => int]`.
     *
     * Only three places use it: the session explorer list, the session drill-down, and
     * the hit timeline. Everything else is a facet, per SPEC §10.
     *
     * @param array<string,mixed> $params
     * @return array{docs:array<int,array<string,mixed>>,numFound:int}
     */
    public function select(string $tag, string $core, array $params): array
    {
        $started = microtime(true);

        if ($this->demo) {
            $out = Fixtures::select($tag, $params);
            $this->note($tag, $core, $started);
            return $out;
        }

        if ($this->solr === null) {
            $this->error ??= 'Solr client is not available.';
            return ['docs' => [], 'numFound' => 0];
        }

        try {
            $resp = $this->solr->query($core, $params);
            $this->note($tag, $core, $started);
            return [
                'docs'     => (array) ($resp['response']['docs'] ?? []),
                'numFound' => (int) ($resp['response']['numFound'] ?? 0),
            ];
        } catch (\Throwable $e) {
            $this->error = self::explain($tag, $e);
            return ['docs' => [], 'numFound' => 0];
        }
    }

    /**
     * Accept either the whole Solr response or a bare facets block.
     *
     * The contract for Solr::jsonFacet() says it returns an array; it does not say
     * whether that array is the full response envelope or the facets node. Both are
     * handled so the panel keeps working whichever way it lands, rather than silently
     * rendering zeroes.
     *
     * @param mixed $resp
     * @return array<string,mixed>
     */
    private function normaliseFacets($resp): array
    {
        if (!is_array($resp)) {
            return ['count' => 0];
        }
        if (isset($resp['facets']) && is_array($resp['facets'])) {
            $facets = $resp['facets'];
            if (!isset($facets['count']) && isset($resp['response']['numFound'])) {
                $facets['count'] = (int) $resp['response']['numFound'];
            }
            return $facets;
        }
        if (isset($resp['count'])) {
            return $resp;
        }
        return ['count' => 0] + $resp;
    }

    /**
     * Turn a transport exception into a sentence an operator can act on.
     *
     * A timeout and a refused connection are different problems with different fixes,
     * and "Solr query failed" tells them apart for nobody. The query tag is included so
     * a slow view can be identified without turning on debug logging.
     */
    private static function explain(string $tag, \Throwable $e): string
    {
        $msg = $e->getMessage();
        $lower = strtolower($msg);

        if (str_contains($lower, 'timed out') || str_contains($lower, 'timeout')) {
            return 'Solr did not answer within the panel query timeout while running "' . $tag . '". '
                . 'Either the query is too heavy for this index (try a shorter time range) '
                . 'or the node is overloaded.';
        }
        if (str_contains($lower, 'could not resolve') || str_contains($lower, 'couldn\'t resolve')) {
            return 'The Solr hostname could not be resolved while running "' . $tag . '". Check solr.base_url and DNS.';
        }
        if (str_contains($lower, 'connection refused') || str_contains($lower, 'failed to connect')) {
            return 'The connection to Solr was refused while running "' . $tag . '". '
                . 'Check that the node is up and that the port is reachable from this host.';
        }
        if (str_contains($lower, '401') || str_contains($lower, '403') || str_contains($lower, 'unauthor')) {
            return 'Solr rejected the credentials while running "' . $tag . '". Check solr.http_user and solr.http_pass.';
        }
        if (str_contains($lower, '404')) {
            return 'Solr returned 404 while running "' . $tag . '" — the core name is probably wrong, '
                . 'or the index has not been created yet.';
        }
        return 'Solr query "' . $tag . '" failed: ' . $msg;
    }

    /**
     * Forget the last error.
     *
     * The error is sticky so a page render can surface it in the banner. A job step needs
     * to know whether ITS call failed, not whether anything has ever failed, so it clears
     * first and checks after.
     */
    public function resetError(): void
    {
        $this->error = null;
    }

    /** Record a query in the debug log shown in the panel footer. */
    private function note(string $tag, string $core, float $started): void
    {
        $this->log[] = [
            'tag'  => $tag,
            'core' => $core,
            'ms'   => round((microtime(true) - $started) * 1000, 1),
        ];
    }
}
