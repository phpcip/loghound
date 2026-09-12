<?php
/**
 * Loghound — tests for sessions that have not ended yet (SPEC §4.2 `provisional_b`).
 *
 * The defect these cover, measured on a live install: 1,912 documents in the hits core, 0 in
 * the sessions core, ingestion working perfectly, every view reporting zero — because a session
 * is only scored once it has been silent for `ingest.session_idle_sec`, 1800 seconds by default.
 * For half an hour after installation the product looks broken.
 *
 * Publishing a document for an open session fixes that and introduces four ways to be wrong,
 * so there is a layer of tests for each:
 *
 *  1. IDENTITY. The provisional document and the final one are ONE document at ONE id, so a
 *     close overwrites rather than duplicating. A session counted twice is worse than a session
 *     counted late.
 *  2. VERDICT. Five of the seventeen rules fire on the ABSENCE of something the session may
 *     still do, and all five would accuse a live human. They must not be evaluated, and the
 *     verdict must not be allowed to claim `human` — "nothing incriminating yet" on one request
 *     is not an acquittal, and a verdict that exonerates and then flips is worse than one that
 *     waits.
 *  3. COST. A session is republished only when it has logged a new hit. Ten thousand idle open
 *     sessions must cost nothing.
 *  4. ROLLUPS. The daily aggregates outlive the sessions behind them, so a partial session must
 *     never reach one.
 *
 * The scorer's own document builder is a function inside an executable script that runs its
 * pipeline on include, so the assertions about it read the source. That is narrow on purpose:
 * everything that CAN be exercised behaviourally is, and the source assertions are reserved for
 * invariants that live in the wiring rather than in a class.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Panel\Controller;
use Loghound\Panel\Gateway;
use Loghound\Panel\Query;
use Loghound\Score\Rules;
use Loghound\Score\Signals;
use Loghound\Sessionizer;
use Loghound\Solr;
use Loghound\State;

/**
 * A Controller subclass exposing the two protected `fq` builders.
 */
final class LhProvisionalProbe extends Controller
{
    public function slug(): string
    {
        return 'provisional-probe';
    }

    public function title(): string
    {
        return 'Probe';
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
    public function probeSessionFqs(): array
    {
        return $this->sessionFqs();
    }

    /**
     * @return array<int,string>
     */
    public function probeSettledFqs(): array
    {
        return $this->settledSessionFqs();
    }
}

/**
 * A probe controller wired to a Solr that is never reached.
 */
function lh_prov_probe(): LhProvisionalProbe
{
    $_GET = [];

    $cfg = Config::load('/nonexistent-loghound-config');
    $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
    $cfg->set('solr.hits_core', 'lh_test_hits');
    $cfg->set('solr.sessions_core', 'lh_test_sessions');

    $transport = static fn (array $request): array => [
        'status' => 200,
        'body'   => (string) json_encode(['responseHeader' => ['status' => 0]]),
        'error'  => '',
    ];

    return new LhProvisionalProbe(
        $cfg,
        new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false)
    );
}

/**
 * A session aggregate in the shape Sessionizer::finalise() produces.
 *
 * Deliberately a CLEAN human-looking session: one page, a couple of sub-resources, nothing
 * incriminating. That is the shape the floor exists for.
 *
 * @param array<string,mixed> $overrides
 * @param array<string,mixed> $first
 * @return array<string,mixed>
 */
function lh_prov_session(array $overrides = [], array $first = []): array
{
    return array_merge([
        'session_id'    => 'sess-provisional',
        'client_key'    => '203.0.113.0/24|abc',
        'ts_start'      => 1789034228,
        'ts_end'        => 1789034300,
        'hits'          => 4,
        'pages'         => 1,
        'assets'        => 3,
        'favicons'      => 0,
        'sub_resources' => 3,
        'uniq_paths'    => 4,
        'bytes'         => 40000,
        'st2'           => 4,
        'st3'           => 0,
        'st4'           => 0,
        'st5'           => 0,
        'got_304'       => false,
        'html_200'      => true,
        'log_span_ms'   => 72000,
        'asset_ratio'   => 0.75,
        'repeat_assets' => 0,
        'gaps'          => [1200, 300, 450],
        'gap_p50_ms'    => 450,
        'gap_stddev_ms' => 400,
        'first'         => array_merge([
            'ip_s'      => '203.0.113.7',
            'ua_s'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36',
            'browser_s' => 'Chrome',
            'browser_ver_i' => 131,
            'os_s'      => 'Windows',
            'device_s'  => 'desktop',
            'as_type_s' => 'isp',
            'fp_hash_s' => 'fp-clean',
        ], $first),
    ], $overrides);
}

/**
 * Score a session aggregate, optionally as a still-open one.
 *
 * @param array<string,mixed> $session
 * @param array<string,mixed> $beacon
 * @param array<string,mixed> $ctx
 * @return array<string,mixed>
 */
function lh_prov_score(array $session, bool $provisional, array $beacon = [], array $ctx = [], ?int $fpIps = 1): array
{
    $rules   = new Rules();
    $signals = Signals::fromSession($session, $beacon, $fpIps);

    return $rules->score($signals, array_merge($ctx, ['provisional' => $provisional]));
}

/** The scorer script's source, for the wiring assertions. */
function lh_prov_scorer_source(): string
{
    return (string) file_get_contents(__DIR__ . '/../bin/loghound-score');
}

/**
 * A file's contents with PHP comments removed.
 *
 * The docblocks in this codebase explain at length why `provisional_b:false` is wrong, so a
 * grep for the string matches the explanation as readily as the mistake. Tokenising is the only
 * way to ask the question about CODE. A file PHP cannot tokenise is returned as-is, so a
 * non-PHP file (a JS asset, a schema) is still searched.
 */
function lh_prov_strip_comments(string $path): string
{
    $body = (string) file_get_contents($path);
    if (!str_ends_with($path, '.php') && strpos($body, '<?php') === false) {
        return $body;
    }

    $out = '';
    foreach (token_get_all($body) as $token) {
        if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $out .= is_array($token) ? $token[1] : $token;
    }
    return $out;
}

/**
 * Run a closure with a fresh State on a temporary database.
 */
function lh_prov_with_state(callable $fn): void
{
    $dir = lh_tmpdir('lh_provisional');
    $state = new State($dir . '/state.db');
    try {
        $fn($state, $dir . '/state.db');
    } finally {
        $state->close();
        lh_rmtree($dir);
    }
}

return [

    'an open session and the closed one it becomes share a single document id'
        => static function (): void {
            lh_prov_with_state(static function (State $state): void {
                $cfg = ['ingest' => ['session_idle_sec' => 1800], 'privacy' => ['ip_mode' => 'full']];
                $sessionizer = new Sessionizer($state, $cfg);

                $tsMs = 1789034228000;
                $sessionizer->assign([
                    'ts'       => '2026-09-10T09:57:08Z',
                    '_ts_ms'   => $tsMs,
                    'ip_s'     => '203.0.113.7',
                    'ip_net_s' => '203.0.113.0/24',
                    'ua_s'     => 'curl/8.4.0',
                    'path_s'   => '/',
                    'status_i' => 200,
                    'kind_s'   => 'html',
                ]);

                $open = $sessionizer->listOpen();
                lh_same(1, count($open), 'one open session is listed');
                $openId = (string) $open[0]['session_id'];

                $closed = $sessionizer->closeIdle($tsMs + 3600 * 1000);
                lh_same(1, count($closed), 'the same session closes');
                $closedId = (string) $closed[0]['session_id'];

                lh_same(
                    $openId,
                    $closedId,
                    'the provisional document and the final one must land on the same Solr id, or the '
                    . 'close adds a second document and the session is counted twice'
                );
            });
        },

    'listing open sessions does not close them' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            $state->openSession('ck-a', 1789034228000, 'example.com', ['hits' => 1]);

            lh_same(1, count($sessionizer->listOpen()), 'the open session is listed');
            lh_same(1, $state->openSessionCount(), 'and it is still open afterwards');
        });
    },

    'a closed session is never listed as open again' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            $id = $state->openSession('ck-a', 1789034228000, null, ['hits' => 1]);

            $state->closeSession($id);

            lh_same(
                0,
                count($sessionizer->listOpen()),
                'closeIdle() stamps closed_at before returning a session, so listOpen() must not '
                . 'pick the same session up in the same run and publish a provisional document over '
                . 'the final one'
            );
        });
    },

    'the scorer writes the session id as the document id and adds no provisional suffix'
        => static function (): void {
            $src = lh_prov_scorer_source();

            lh_contains(
                $src,
                "'id'         => (string) \$session['session_id'],",
                'the document id is the session id and nothing else'
            );
            if (preg_match('/[\'"]id[\'"]\s*=>[^;]*provisional/i', $src)) {
                lh_fail(
                    'the document id is being decorated for provisional sessions, which would make the '
                    . 'close ADD a document instead of replacing one'
                );
            }
        },

    'provisional_b is only ever written as true' => static function (): void {
        $src = lh_prov_scorer_source();

        lh_contains($src, "\$doc['provisional_b'] = true;", 'the marker is set on an open session');

        if (preg_match('/provisional_b[\'"]?\]?\s*=\s*false/i', $src)) {
            lh_fail(
                'provisional_b is being written as false somewhere. It must be ABSENT on a settled '
                . 'document, because that is what makes -provisional_b:true also match every session '
                . 'indexed before the field existed'
            );
        }
    },

    'every deferred rule fires on a finished session and is silent on an open one'
        => static function (): void {
            $rules = new Rules();

            $cases = [
                'no_js_on_html' => [
                    'session' => [],
                    'beacon'  => [],
                    'ctx'     => ['beacon_deployed' => true],
                ],
                'no_assets' => [
                    'session' => ['assets' => 0, 'favicons' => 0, 'sub_resources' => 0],
                    'beacon'  => [],
                    'ctx'     => [],
                ],
                'no_304_on_repeat' => [
                    'session' => ['repeat_assets' => 3, 'got_304' => false],
                    'beacon'  => [],
                    'ctx'     => ['site_sends_304' => true],
                ],
                'no_interaction' => [
                    'session' => [],
                    'beacon'  => ['beacon_b' => true, 'interactions_i' => 0],
                    'ctx'     => [],
                ],
                'single_page_10s' => [
                    'session' => ['pages' => 1, 'log_span_ms' => 2000],
                    'beacon'  => [],
                    'ctx'     => [],
                ],
            ];

            lh_same(
                Rules::DEFERRED_CODES,
                array_keys($cases),
                'every deferred code has a case here, in the same order as the constant'
            );

            foreach ($cases as $code => $case) {
                $signals = Signals::fromSession(lh_prov_session($case['session']), $case['beacon'], 1);

                lh_true(
                    $rules->fired($code, $signals, $case['ctx']) !== null,
                    $code . ' fires once the session has ended (otherwise this test proves nothing)'
                );
                lh_same(
                    null,
                    $rules->fired($code, $signals, $case['ctx'] + ['provisional' => true]),
                    $code . ' must be silent while the session is still open: it reads the ABSENCE of '
                    . 'something the visitor may still do, and it would accuse a live human'
                );
            }
        },

    'a presence-based rule still fires on an open session' => static function (): void {
        $rules   = new Rules();
        $signals = Signals::fromSession(
            lh_prov_session([], ['ua_bot_b' => true, 'ua_bot_name_s' => 'Googlebot', 'ua_bot_cat_s' => 'search']),
            [],
            1
        );

        lh_true(
            $rules->fired('ua_declared_bot', $signals, ['provisional' => true]) !== null,
            'a declared crawler is a fact about the first request, so it must be reported in the first '
            . 'minute rather than in half an hour — that is the whole point of publishing open sessions'
        );
    },

    'a clean open session is never called human' => static function (): void {
        $final = lh_prov_score(lh_prov_session(['pages' => 2, 'log_span_ms' => 90000]), false);
        lh_same('human', $final['verdict'], 'the same session, finished, is a human');

        $live = lh_prov_score(lh_prov_session(['pages' => 2, 'log_span_ms' => 90000]), true);
        lh_same(
            Rules::PROVISIONAL_FLOOR,
            $live['verdict'],
            'an open session that has tripped nothing has not been fully tested, so calling it human '
            . 'is a claim the evidence does not support — and one that would FLIP as the session continued'
        );
        lh_true(
            in_array(Rules::PROVISIONAL_REASON, $live['reasons'], true),
            'and the floored verdict explains itself, exactly as SPEC §1 requires of every verdict'
        );
    },

    'no score below the floor can produce a human or likely_human verdict while open'
        => static function (): void {
            $rules = new Rules();

            foreach ([0.0, 5.0, 15.0, 20.0, 35.0, 39.0] as $score) {
                $verdict = $rules->verdictFor($score);
                lh_true(
                    in_array($verdict, ['human', 'likely_human'], true),
                    'score ' . $score . ' is a human-side verdict when final, got ' . $verdict
                );
            }

            $live = lh_prov_score(lh_prov_session([], ['as_type_s' => 'hosting']), true);
            lh_true(
                !in_array($live['verdict'], ['human', 'likely_human'], true),
                'a provisional verdict is never on the human side of the scale, whatever it scored'
            );
        },

    'the floor raises a verdict and never lowers one' => static function (): void {
        $session = lh_prov_session([], ['ua_bot_b' => true, 'ua_bot_name_s' => 'GPTBot', 'ai_crawler_b' => true]);

        $final = lh_prov_score($session, false);
        $live  = lh_prov_score($session, true);

        lh_same('bot', $final['verdict'], 'a self-declared crawler is a bot when finished');
        lh_same(
            'bot',
            $live['verdict'],
            'and still a bot while open — the floor suppresses an overclaim of humanity, it does not '
            . 'soften a finding that rests on evidence already in the log'
        );
        lh_same('ai_crawler', $live['class'], 'and the class is assigned from the published verdict');
    },

    'an automation marker is called a bot on the first request' => static function (): void {
        $live = lh_prov_score(
            lh_prov_session(),
            true,
            ['beacon_b' => true, 'automation_ss' => ['webdriver'], 'interactions_i' => 0]
        );

        lh_same(
            'bot',
            $live['verdict'],
            'navigator.webdriver has no innocent explanation and will not become innocent later, so an '
            . 'open session carrying it is called immediately'
        );
        lh_same('headless', $live['class'], 'class');
        lh_true(
            in_array('automation_marker', $live['reasons'], true),
            'and the reason is the marker, not the provisional floor'
        );
        lh_true(
            !in_array('no_interaction', $live['reasons'], true),
            'while no_interaction, which reads "has not scrolled YET", stays out of it'
        );
    },

    'a floored verdict does not also claim that nothing fired' => static function (): void {
        $live = lh_prov_score(lh_prov_session(['pages' => 2, 'log_span_ms' => 90000]), true);

        lh_true(
            !in_array('no_bot_signals', $live['reasons'], true),
            'no_bot_signals means "this session was tested and tripped nothing". Five rules were not '
            . 'evaluated, so the facet that counts clean sessions must not count this one'
        );
        lh_same(
            [Rules::PROVISIONAL_REASON],
            $live['reasons'],
            'the one reason is the honest one'
        );
    },

    'every reason on a provisional verdict has an explanation attached' => static function (): void {
        foreach ([true, false] as $provisional) {
            $live = lh_prov_score(lh_prov_session(['pages' => 2, 'log_span_ms' => 90000]), $provisional);
            foreach ($live['reasons'] as $code) {
                lh_has_key($live['detail'], $code, 'detail for ' . $code);
                lh_true(
                    ($live['detail'][$code]['why'] ?? '') !== '',
                    'the reason ' . $code . ' carries a sentence a person can read'
                );
            }
        }
    },

    'the provisional gate does not change the verdict on a finished session' => static function (): void {
        $shapes = [
            lh_prov_session(),
            lh_prov_session(['assets' => 0, 'favicons' => 0, 'sub_resources' => 0]),
            lh_prov_session(['repeat_assets' => 4]),
            lh_prov_session(['pages' => 1, 'log_span_ms' => 1000]),
            lh_prov_session([], ['as_type_s' => 'hosting']),
        ];

        foreach ($shapes as $i => $session) {
            $withFlag    = lh_prov_score($session, false, [], ['site_sends_304' => true, 'beacon_deployed' => true]);
            $withoutFlag = (new Rules())->score(
                Signals::fromSession($session, [], 1),
                ['site_sends_304' => true, 'beacon_deployed' => true]
            );

            lh_same(
                $withoutFlag['score'],
                $withFlag['score'],
                'shape ' . $i . ': passing provisional=false must be identical to not passing it at all, '
                . 'which is why rule_version_i was deliberately NOT bumped'
            );
            lh_same($withoutFlag['verdict'], $withFlag['verdict'], 'shape ' . $i . ': verdict');
            lh_same($withoutFlag['reasons'], $withFlag['reasons'], 'shape ' . $i . ': reasons');
        }
    },

    'the deferred list is exactly the rules that read an absence' => static function (): void {
        foreach (Rules::DEFERRED_CODES as $code) {
            lh_true(
                in_array($code, Rules::codes(), true),
                $code . ' is a real rule code, not a typo that silently defers nothing'
            );
        }
        lh_same(
            5,
            count(Rules::DEFERRED_CODES),
            'five of the seventeen rules are absence-based; changing that number means the reasoning in '
            . 'the constant docblock has to change with it'
        );
        lh_same(
            count(Rules::DEFERRED_CODES),
            count(array_unique(Rules::DEFERRED_CODES)),
            'no duplicates'
        );
    },

    'a session is republished only after it has logged a new hit' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            $id = $state->openSession('ck-a', 1789034228000, null, ['hits' => 1]);

            $first = $sessionizer->listOpen();
            lh_same(1, count($first), 'a session that has never been published is dirty');

            $sessionizer->markProvisional($first);
            lh_same(
                0,
                count($sessionizer->listOpen()),
                'and clean afterwards — rewriting an unchanged session on every run is what turns ten '
                . 'thousand open sessions into ten thousand pointless Solr writes a minute'
            );

            $state->updateSession($id, 1789034300000, 1, ['hits' => 2]);
            lh_same(
                1,
                count($sessionizer->listOpen()),
                'a new hit makes it dirty again, so the panel follows the session as it grows'
            );
        });
    },

    'a hit that lands mid-run leaves the session dirty' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            $id = $state->openSession('ck-a', 1789034228000, null, ['hits' => 1]);

            $published = $sessionizer->listOpen();

            $state->updateSession($id, 1789034999000, 1, ['hits' => 2]);

            $sessionizer->markProvisional($published);

            lh_same(
                1,
                count($sessionizer->listOpen()),
                'the mark records the instant that was PUBLISHED, not the row as it stands now, so a hit '
                . 'that arrived while the run was in flight is not silently lost from the panel'
            );
        });
    },

    'the open batch is bounded' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            for ($i = 0; $i < 12; $i++) {
                $state->openSession('ck-' . $i, 1789034228000 + $i * 1000, null, ['hits' => 1]);
            }

            lh_same(5, count($sessionizer->listOpen(5)), 'the limit is honoured');
            lh_same(
                12,
                count($sessionizer->listOpen(5000)),
                'and a limit above the population simply returns the population'
            );
        });
    },

    'the freshest open sessions are published first' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $sessionizer = new Sessionizer($state, ['ingest' => ['session_idle_sec' => 1800]]);
            $state->openSession('ck-stale', 1789030000000, null, ['hits' => 1]);
            $fresh = $state->openSession('ck-fresh', 1789034228000, null, ['hits' => 1]);

            $batch = $sessionizer->listOpen(1);
            lh_same(1, count($batch), 'one row');
            lh_same(
                $fresh,
                (string) $batch[0]['session_id'],
                'when the batch limit bites it must drop the sessions nobody is watching, not an '
                . 'arbitrary slice'
            );
        });
    },

    'the scorer names its own bound' => static function (): void {
        $src = lh_prov_scorer_source();

        lh_contains($src, 'const PROVISIONAL_BATCH = 500;', 'the bound is a named constant');
        lh_contains($src, 'listOpen(PROVISIONAL_BATCH)', 'and the open batch actually uses it');
    },

    'publishing is recorded only after the documents are in Solr' => static function (): void {
        $src = lh_prov_scorer_source();

        $index = strpos($src, '$solr->addDocs($sessionCore, $chunk, true);');
        $mark  = strpos($src, '$sessionizer->markProvisional($publishedOpen);');

        lh_true($index !== false, 'the indexing call is where this test expects it');
        lh_true($mark !== false, 'so is the mark');
        lh_true(
            $mark > $index,
            'a session marked published before the index succeeded would stay stale in the panel until '
            . 'its next hit, on the one run that most needed retrying'
        );
    },

    'a provisional merge does not consume the staged beacon rows' => static function (): void {
        $src = lh_prov_scorer_source();

        lh_contains(
            $src,
            'if (!$provisional) {',
            'the beacon ids are collected under a guard'
        );

        $window = (string) strstr($src, '$rows = $state->beaconsFor(');
        $window = substr($window, 0, 600);

        lh_contains($window, 'if (!$provisional)', 'and the guard is in the merge block');
        lh_true(
            strpos($window, '$mergedIds[] = (int) $row[\'id\'];') > strpos($window, 'if (!$provisional)'),
            'staged rows may be marked merged only for a session that CLOSED — there is no second copy '
            . 'of the execution plane anywhere, and a provisional document is about to be overwritten'
        );
    },

    'the daily rollup counts settled sessions only' => static function (): void {
        $src = lh_prov_scorer_source();

        lh_contains(
            $src,
            "const SETTLED_SESSIONS = '-provisional_b:true';",
            'the scorer has the settled filter, spelled as a negation'
        );

        $rollup = (string) strstr($src, 'function computeRollup(');
        lh_contains(
            $rollup,
            'SETTLED_SESSIONS',
            'and computeRollup() uses it. Without it an open session\'s partial hit count and floored '
            . 'verdict are folded into a historical total on every rebuild, and the rollup is the one '
            . 'set of numbers meant to outlive the sessions behind it'
        );
    },

    'a run that published nothing but provisional documents rebuilds no rollup'
        => static function (): void {
            $src = lh_prov_scorer_source();

            lh_contains(
                $src,
                '$days[gmdate(\'Y-m-d\', (int) $session[\'ts_start\'])] = true;',
                'days are collected per session'
            );
            lh_contains(
                $src,
                '} else {' . "\n" . '        $days[',
                'and only for a session that closed, so a provisional-only run does no rollup work at all'
            );
            lh_contains(
                $src,
                "if (\$closed !== [] && (int) gmdate('H', \$now) < 2) {",
                'the previous-day rebuild is gated on the same thing, rather than firing every minute '
                . 'between midnight and 02:00 UTC for sessions that have not closed'
            );
        },

    'the settled filter is a negation, never a false' => static function (): void {
        lh_same(
            '-provisional_b:true',
            Query::SETTLED_SESSIONS,
            'provisional_b is written only as true, so provisional_b:false would match no session at '
            . 'all — including every session a site already had before the field existed'
        );
        lh_same('provisional_b:true', Query::PROVISIONAL_SESSIONS, 'and the inverse is the plain term');
    },

    'nothing anywhere asks for provisional_b:false' => static function (): void {
        $roots = ['src', 'bin', 'public', 'install', 'tools'];
        $bad   = [];

        foreach ($roots as $root) {
            $dir = __DIR__ . '/../' . $root;
            if (!is_dir($dir)) {
                continue;
            }
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $body = lh_prov_strip_comments((string) $file);
                if (preg_match('/provisional_b\s*:\s*false/i', $body)) {
                    $bad[] = (string) $file;
                }
            }
        }

        lh_same(
            [],
            $bad,
            'a query for provisional_b:false silently excludes a site\'s whole history; the settled '
            . 'population is always -provisional_b:true'
        );
    },

    'sessionFqs includes open sessions and settledSessionFqs excludes them' => static function (): void {
        $probe = lh_prov_probe();

        $live = $probe->probeSessionFqs();
        lh_true(
            !in_array(Query::SETTLED_SESSIONS, $live, true),
            'the default list counts live traffic. Excluding it here would leave a fresh install showing '
            . 'nothing for the whole idle timeout, which is the defect provisional documents exist to fix'
        );
        lh_true(in_array(Query::SESSION_DOCS, $live, true), 'and it still excludes the rollup documents');

        $settled = $probe->probeSettledFqs();
        lh_true(
            in_array(Query::SETTLED_SESSIONS, $settled, true),
            'a card that MEASURES a session rather than counting one asks for this list'
        );
        lh_true(in_array(Query::SESSION_DOCS, $settled, true), 'which is otherwise the same list');

        lh_same(
            count($live) + 1,
            count($settled),
            'the settled list is the live list plus exactly one clause'
        );

        $_GET = [];
    },

    'a session row can say that its counts are still moving' => static function (): void {
        lh_contains(
            Query::sessionFl(),
            'provisional_b',
            'the explorer returns the marker, so a row whose hit count is partial can be labelled as '
            . 'such instead of reading as a finished session that did very little'
        );
    },

    'the sessions schema defines the marker as a filterable boolean' => static function (): void {
        $xml = (string) file_get_contents(__DIR__ . '/../solr/sessions/conf/schema.xml');

        if (!preg_match('/<field\s+name="provisional_b"[^>]*>/', $xml, $m)) {
            lh_fail('the sessions schema does not define provisional_b');
        }
        $field = $m[0];

        lh_contains($field, 'type="boolean"', 'type');
        lh_contains($field, 'indexed="true"', 'indexed, because every panel query filters on it');
        lh_contains($field, 'docValues="true"', 'docValues, because it is faceted');
    },

    'SPEC records the field contract' => static function (): void {
        $spec = (string) file_get_contents(__DIR__ . '/../SPEC.md');

        lh_contains($spec, '`provisional_b`', 'SPEC §4.2 names the field');
        lh_contains($spec, '-provisional_b:true', 'and the only correct way to ask for settled sessions');
        lh_contains($spec, 'PROVISIONAL_BATCH', 'and the cost bound');
    },

    'the open-session table carries the publication marker' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $columns = [];
            $res = $state->db()->query('PRAGMA table_info(sessions_open)');
            while (($row = $res->fetchArray(SQLITE3_ASSOC)) !== false) {
                $columns[] = (string) $row['name'];
            }

            lh_true(in_array('scored_ts', $columns, true), 'scored_ts exists on a fresh database');
        });
    },

    'migrating a database that already has the column is not an error' => static function (): void {
        $dir  = lh_tmpdir('lh_provisional_twice');
        $path = $dir . '/state.db';

        try {
            $first = new State($path);
            $first->close();

            $second = new State($path);
            $second->close();

            $third = new State($path);
            $marks = [];
            $id = $third->openSession('ck-a', 1789034228000, null, ['hits' => 1]);
            $marks[$id] = 1789034228000;
            $third->markSessionsScored($marks);
            lh_same(
                0,
                count($third->listDirtyOpenSessions()),
                'and the column still works after two more migrations over the same file'
            );
            $third->close();
        } finally {
            lh_rmtree($dir);
        }
    },

    'marking an unknown session id changes nothing and throws nothing' => static function (): void {
        lh_prov_with_state(static function (State $state): void {
            $state->openSession('ck-a', 1789034228000, null, ['hits' => 1]);
            $state->markSessionsScored(['no-such-session' => 1789034228000]);

            lh_same(
                1,
                count($state->listDirtyOpenSessions()),
                'a mark for a session that is gone must not quietly clean a different one'
            );
        });
    },
];
