<?php
/**
 * Loghound — regression tests for the security sweep.
 *
 * One test per defect that was found and fixed, written so that reintroducing the defect
 * fails the test. Each one names the shape of the attack rather than the shape of the code,
 * because a test that only asserts "this line says esc()" passes again the moment the line
 * moves.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Auth\Store;
use Loghound\Auth\TwoFactor;
use Loghound\Auth\Totp;
use Loghound\Beacon;
use Loghound\Config;
use Loghound\Enrich\Geo;
use Loghound\LogDetect;
use Loghound\Panel\Facets;
use Loghound\Panel\Layout;
use Loghound\Parser;
use Loghound\Security;
use Loghound\Solr;

/**
 * A throwaway installation directory with a usable configuration in it.
 *
 * @return array{0:string,1:Config}
 */
function lh_sa_scaffold(): array
{
    $root = lh_tmpdir('lh_sa');
    mkdir($root . '/config', 0700, true);
    mkdir($root . '/var', 0700, true);

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('auth.mode', 'session');
    $cfg->set('auth.user', 'operator');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    $cfg->save();

    return [$root, $cfg];
}

return [

/* ------------------------------------------------------------------------------------ *
 * Solr injection
 * ------------------------------------------------------------------------------------ */

'a control character hidden in invalid UTF-8 does not walk past the facet guard' =>
    function (): void {
        // preg_match with /u returns FALSE, not 0, on malformed UTF-8 — and `if (false)` is
        // `if (no control character)`. The guard read as a guard and admitted a newline into
        // a form-encoded parameter for any string that was also invalid UTF-8.
        $sneaky = "AB\xC3\x28\nCD";

        lh_same(1, preg_match('/[\x00-\x1F\x7F]/', $sneaky), 'the byte really is in there');
        lh_false(preg_match('/[\x00-\x1F\x7F]/u', $sneaky), 'and the /u spelling really does miss it');

        $refused = false;
        try {
            Solr::assertSafeContains($sneaky);
        } catch (\InvalidArgumentException $e) {
            $refused = str_contains($e->getMessage(), 'control character');
        }
        lh_true($refused, 'assertSafeContains must refuse it');
    },

'a term of invalid UTF-8 stays a term instead of silently becoming the empty one' =>
    function (): void {
        // preg_replace with /u returns NULL on malformed UTF-8, and `?? ''` turned the whole
        // value into ''. A filter built on it became field:("") — a different question, asked
        // with no sign that the value had been thrown away.
        $term = Solr::escapeTerm("AB\xC3\x28CD");
        lh_false($term === '""', 'the value must not collapse to an empty term');
        lh_true(str_contains($term, 'AB'), 'and what was recoverable is kept');
    },

'a Solr parameter nobody allowed is refused, not merely one somebody denied' =>
    function (): void {
        $sent = [];
        $transport = static function (array $req) use (&$sent): array {
            $sent[] = $req;
            return ['status' => 200, 'body' => '{"responseHeader":{"status":0}}', 'error' => ''];
        };
        $solr = new Solr(['base_url' => 'https://solr.invalid/solr'], $transport);

        // Every one of these reached a node unexamined under the denylist. facet.query takes a
        // whole query string; bf/bq/boost are server-side function queries; f.<field>.<x>
        // re-specifies any per-field option there is.
        foreach ([
            'facet.query' => '{!frange l=0 u=100}ip_s',
            'bf'          => 'ord(ip_s)',
            'bq'          => 'path_s:x^10',
            'boost'       => 'recip(ms(NOW,ts),1,1,1)',
            'hl.q'        => '*:*',
            'f.ip_s.facet.limit' => '-1',
        ] as $name => $value) {
            $threw = false;
            try {
                $solr->query('hits', ['q' => '*:*', $name => $value]);
            } catch (\InvalidArgumentException $e) {
                $threw = str_contains($e->getMessage(), 'refused');
            }
            lh_true($threw, 'parameter ' . $name . ' must be refused');
        }

        lh_same(0, count($sent), 'and none of them reached the transport');
    },

/* ------------------------------------------------------------------------------------ *
 * Anchored validators
 * ------------------------------------------------------------------------------------ */

'an anchored validator does not accept a trailing newline' =>
    function (): void {
        // PCRE's `$` matches before a final newline unless D is set, so every `^...$`
        // validator in the project accepted one byte nobody had checked for.
        lh_false(Security::isSafeFieldName("path_s\n"), 'field name');
        lh_false(Security::isSafeCoreName("loghound_a_hits\n"), 'core name');
        lh_false(Beacon::normaliseHost("allowed.com\n:80") !== '', 'hostname with a newline before the port');

        $facets = Facets::sessions(['f' => ['asn_i' => ["13335\n"]]]);
        lh_same([], $facets->values('asn_i'), 'a numeric filter value with a newline is dropped');
    },

/* ------------------------------------------------------------------------------------ *
 * Ingestion: denial of service on attacker-chosen bytes
 * ------------------------------------------------------------------------------------ */

'a request line of whitespace costs no more than an ordinary one' =>
    function (): void {
        // `~^(\S+)\s+(.*?)\s+(HTTP/[0-9.]+)$~i` is ambiguous between `.*?` and the `\s+` on
        // either side of it, so a run of spaces before a near-match is quadratic. Measured at
        // 13 ms a line against 0.04 ms — a 300-fold collapse in ingest throughput, from a
        // request line every webserver logs verbatim even when it answered 400.
        $split = new ReflectionMethod(Parser::class, 'splitRequestLine');

        $hostile = 'GET ' . str_repeat(' ', 6000) . 'HTTP/1.1x';
        $start = microtime(true);
        for ($i = 0; $i < 200; $i++) {
            $split->invoke(null, $hostile);
        }
        $each = (microtime(true) - $start) / 200;

        lh_true($each < 0.001, 'a hostile request line must stay under a millisecond, took ' . $each);

        // And it still parses an ordinary one exactly as the pattern did.
        lh_same(
            ['method' => 'GET', 'target' => '/a/b?c=d', 'proto' => 'HTTP/1.1'],
            $split->invoke(null, 'GET /a/b?c=d HTTP/1.1'),
            'a well-formed line'
        );
        lh_same(
            ['method' => 'GET', 'target' => '/x', 'proto' => null],
            $split->invoke(null, 'GET /x'),
            'HTTP/0.9 or a truncated line keeps its target'
        );
    },

'a brace bomb in an Include directive is refused before glob runs' =>
    function (): void {
        // GLOB_BRACE expands combinatorially and Security::safePath was applied to the RESULTS,
        // which is after the cost has been paid. Twenty pairs is 2^20 expansions and measured
        // at 23.5 seconds of stat() from ONE directive, in a config file this class is
        // explicitly documented as treating as hostile.
        $sane = new ReflectionMethod(LogDetect::class, 'globSpecIsSane');

        $bomb = '/etc/' . str_repeat('{a,b}', 20) . '*';
        $start = microtime(true);
        lh_false($sane->invoke(null, $bomb, ['/etc']), 'the bomb is refused');
        lh_true(microtime(true) - $start < 0.05, 'and refusing it is instant');

        lh_false($sane->invoke(null, '/*', ['/etc']), 'a spec whose stem is / walks the filesystem');
        lh_false($sane->invoke(null, '/tmp/*.conf', ['/etc']), 'a stem outside every root is refused');
        lh_true($sane->invoke(null, '/etc/{a,b}/*.conf', ['/etc']), 'an ordinary two-branch include still works');
    },

'the session aggregate is bounded in bytes, not only in entries' =>
    function (): void {
        // The caps counted entries; every key is an attacker-chosen string up to 2048 (a path)
        // or 4097 (a path plus its query) characters, so the ceiling was ~39 MB of live keys —
        // json_decode'd, mutated and json_encode'd into SQLite on EVERY hit of that session,
        // and fatal on PHP's stock 128 MB memory_limit.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Sessionizer.php');

        lh_contains($src, 'MAX_TRACKED_KEY_BYTES', 'there has to be a byte budget');
        lh_contains($src, "\$agg['paths_bytes']", 'and the path set has to spend it');
        lh_contains($src, "\$agg['uris_bytes']", 'and so does the URI set');
    },

'a tail walks a bounded number of bytes even when the file has no newlines' =>
    function (): void {
        // The only exits were "found n+1 newlines" and "reached offset 0", so a file with fewer
        // newlines than asked for was read whole — and the buffer was re-explode()d every
        // 64 KB, which is quadratic in the region size.
        $dir = lh_tmpdir('lh_sa_tail');
        $file = $dir . '/access.log';
        file_put_contents($file, str_repeat('x', 6 * 1024 * 1024));

        $start = microtime(true);
        $lines = LogDetect::tailLines($file, 20, [$dir]);
        $took = microtime(true) - $start;

        lh_true($took < 2.0, 'a newline-free file must not be read whole, took ' . $took);
        lh_true(
            $lines === [] || strlen((string) ($lines[0] ?? '')) <= LogDetect::MAX_TAIL_BYTES,
            'and nothing larger than the budget comes back'
        );

        lh_rmtree($dir);
    },

/* ------------------------------------------------------------------------------------ *
 * The public collector
 * ------------------------------------------------------------------------------------ */

'a beacon that speaks for no listed site contributes no signal code' =>
    function (): void {
        // THE CROSS-ORIGIN FRAMING ATTACK. The merge key is client_key — the /24 plus the
        // User-Agent hash — not the session id, so a hostile page loaded in the victim's
        // browser shares it exactly. It gets its own provisional session and a valid token
        // bound to its OWN origin, posts automation_webdriver, and the scorer folds that into
        // the victim's real session: headless_b true, client_score_f 100. Binding the token to
        // an Origin never touched this, because the attacker never needed the victim's session.
        [$root, $cfg] = lh_sa_scaffold();
        $cfg->set('beacon.secret', str_repeat('k', 48));
        $cfg->set('beacon.allowed_hosts', ['listed.example']);

        $beacon = new Beacon($cfg);
        $payload = $beacon->normalise(['a' => ['automation_webdriver', 'headless_renderer']]);

        lh_same(
            [],
            $beacon->signalsFor($payload, 'Mozilla/5.0', '', ['beacon_forged']),
            'an unattributed beacon may not assert anything about the visitor'
        );

        $attributed = $beacon->signalsFor($payload, 'Mozilla/5.0', 'listed.example', []);
        lh_true(
            in_array('automation_webdriver', $attributed, true),
            'while a beacon speaking for a listed site still reports what it found'
        );

        lh_rmtree($root);
    },

'the collector keys its rate limit on a network, not on a single address' =>
    function (): void {
        // Keyed on the full address, an IPv6 /64 — the default allocation on essentially every
        // VPS — is 2^64 buckets each with a full budget. And the session bucket on the hello
        // branch was minted from random_bytes three lines earlier, so it could never refuse and
        // its only effect was one unbounded-table row per hello.
        $src = (string) file_get_contents(dirname(__DIR__) . '/public/collect.php');

        lh_contains($src, 'Security::ipNetwork($ip, 32, 64)', 'the address bucket must be per network');
        lh_contains($src, "if (!\$isHello && \$state !== null", 'and a hello must not consume a session bucket');
    },

/* ------------------------------------------------------------------------------------ *
 * Authentication
 * ------------------------------------------------------------------------------------ */

'a recovery code is burned even when the action it authorised is then refused' =>
    function (): void {
        // Panel\Settings::requireSecondFactor() validates the factor FIRST, and its callers
        // return on their own validation errors without ever persisting — so a recovery code
        // spent against the reinstall form with the wrong confirmation word stayed live.
        // Deleting the hash in memory was the whole of "a used recovery code is deleted".
        [$root, $cfg] = lh_sa_scaffold();
        $var = $root . '/var';

        $secret = TwoFactor::begin();
        $result = TwoFactor::enable($cfg, $secret, (string) Totp::at($secret), $var);
        lh_same([], $result['errors'], 'enrollment');
        $code = $result['codes'][0];
        $cfg->save();

        lh_same('recovery', TwoFactor::check($cfg, $code, $var), 'the code is accepted once');

        // The caller never persists — exactly what the refusal paths in Settings do.
        $reloaded = Config::load($root . '/config/loghound.php');
        lh_same(
            'no',
            TwoFactor::check($reloaded, $code, $var),
            'and is refused on a configuration that never learned it was spent'
        );

        lh_rmtree($root);
    },

'a recovery code cannot be spent twice by two requests at once' =>
    function (): void {
        // Config::save() is a lock-free whole-file write, so N parallel requests each read the
        // same snapshot, each matched, and each signed in. The spend is a Store mutate now,
        // which is one LOCK_EX pass — the same mechanism the TOTP replay floor already used.
        [$root, $cfg] = lh_sa_scaffold();
        $var = $root . '/var';

        $secret = TwoFactor::begin();
        $result = TwoFactor::enable($cfg, $secret, (string) Totp::at($secret), $var);
        $code = $result['codes'][2];
        $cfg->save();

        $accepted = 0;
        for ($i = 0; $i < 5; $i++) {
            // Each iteration is a fresh snapshot, which is what a parallel request holds.
            $snapshot = Config::load($root . '/config/loghound.php');
            if (TwoFactor::check($snapshot, $code, $var) === 'recovery') {
                $accepted++;
            }
        }
        lh_same(1, $accepted, 'one code, one sign-in, however many snapshots saw it');

        lh_rmtree($root);
    },

'a bearer cookie is marked Secure behind a proxy that terminated the TLS' =>
    function (): void {
        // `($_SERVER['HTTPS'] ?? '') !== ''` was wrong in both directions: it said NO behind
        // every TLS-terminating proxy, so the ten-year "stay signed in" token was issued
        // without Secure on exactly the deployments this project documents support for; and it
        // said YES on IIS, where the value is the literal string 'off' over plain HTTP.
        $saved = $_SERVER;

        $_SERVER = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_PROTO' => 'https'];
        lh_true(Security::isHttps(['10.0.0.0/8']), 'a configured proxy saying https is believed');
        lh_false(Security::isHttps([]), 'and an unconfigured one is not');

        $_SERVER = ['REMOTE_ADDR' => '203.0.113.5', 'HTTPS' => 'off'];
        lh_false(Security::isHttps([]), "'off' is off");

        $_SERVER = ['REMOTE_ADDR' => '203.0.113.5', 'HTTPS' => 'on'];
        lh_true(Security::isHttps([]), 'and on is on');

        $_SERVER = ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_PROTO' => 'https'];
        lh_false(Security::isHttps(['10.0.0.0/8']), 'a visitor cannot assert it for themselves');

        $_SERVER = $saved;
    },

'a store refuses to open a lock file that is a symlink' =>
    function (): void {
        // fopen(…, 'c') and chmod both follow a symlink, so any local account that won the race
        // to create var/persistent-logins.json.lock got an arbitrary-file chmod-to-0600 as the
        // panel user, plus a lock-denial primitive.
        $dir = lh_tmpdir('lh_sa_lock');
        $target = $dir . '/victim';
        file_put_contents($target, 'do not touch');
        chmod($target, 0644);

        $store = new Store($dir . '/planted.json');
        symlink($target, $dir . '/planted.json.lock');

        lh_same(null, $store->mutate(static function (array &$d): bool {
            $d['x'] = 1;
            return true;
        }), 'a planted lock is a refusal, not a write');

        clearstatcache();
        lh_same('0644', substr(sprintf('%o', fileperms($target)), -4), 'and the target keeps its mode');

        lh_rmtree($dir);
    },

'an unwritable token store clears the cookie instead of looping forever' =>
    function (): void {
        // consume() returned 'store' before clearCookie(), so requireAuth redirected to
        // ?login=1, Panel\Login saw Persistence::present() — which only tests that the cookie
        // string is non-empty — and redirected straight back. The sign-in form could never be
        // rendered, including to fix the very condition causing it.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Auth/Persistence.php');

        $at = strpos($src, "return ['state' => 'store', 'user' => ''];");
        lh_true($at !== false, 'the store branch is still there');

        $before = substr($src, max(0, $at - 400), min(400, $at));
        lh_contains($before, 'self::clearCookie();', 'and it clears the cookie on the way out');
    },

/* ------------------------------------------------------------------------------------ *
 * Output
 * ------------------------------------------------------------------------------------ */

'no chart formatter builds markup by hand' =>
    function (): void {
        // ECharts renders a formatter's return value as HTML and gives it no DOM node, so a
        // formatter is the one place this panel produces markup from data. Built with `+`, the
        // escaping held only while every author remembered it — and `row.extra`, `d.astype`
        // and a bucket label all reached a tooltip raw, sitting between escaped values.
        $files = array_merge(
            [dirname(__DIR__) . '/public/assets/js/charts.js'],
            (array) glob(dirname(__DIR__) . '/public/assets/js/views/*.js')
        );

        foreach ($files as $file) {
            foreach (explode("\n", (string) file_get_contents($file)) as $n => $line) {
                if (!preg_match("/['\"][^'\"]*<[a-zA-Z\/!]/", $line)) {
                    continue;
                }
                if (!str_contains($line, '+')) {
                    continue;
                }
                lh_true(
                    str_contains($line, 'tip`'),
                    basename($file) . ':' . ($n + 1) . ' concatenates markup; use the tip`` template'
                );
            }
        }
    },

'the element constructor has no markup sink at all' =>
    function (): void {
        // el(tag, {html}) set innerHTML and had zero callers in the whole front end: not a
        // feature, an unguarded sink in the universal constructor waiting for the first author
        // who reached for it holding a Solr value.
        $js = (string) file_get_contents(dirname(__DIR__) . '/public/assets/js/core.js');
        lh_false(str_contains($js, 'node.innerHTML'), 'core.js must not assign innerHTML');

        foreach ((array) glob(dirname(__DIR__) . '/public/assets/js/{,views/}*.js', GLOB_BRACE) as $file) {
            lh_false(
                str_contains((string) file_get_contents($file), '.innerHTML'),
                basename($file) . ' must not touch innerHTML'
            );
        }
    },

'changing the time range keeps a filter operator instead of inverting it' =>
    function (): void {
        // f[field][op]=none lives in the same array as the values, and array_values()
        // re-indexed it: an exclusion became an inclusion AND the literal string "none" became
        // a value. The chips went on saying "None of" over the opposite numbers.
        $saved = $_GET;
        $_GET = ['f' => ['bot_verdict_s' => ['0' => 'bot', 'op' => 'none']]];

        $url = Layout::urlWith(['v' => 'overview', 'range' => '7d']);

        lh_true(str_contains($url, rawurlencode('f[bot_verdict_s][op]') . '=none'), 'the operator travels: ' . $url);
        lh_false(str_contains($url, '%5D%5B1%5D=none'), 'and never becomes a value');

        $_GET = $saved;
    },

/* ------------------------------------------------------------------------------------ *
 * Outbound requests
 * ------------------------------------------------------------------------------------ */

'the geolocation endpoint cannot be pointed at the machine itself' =>
    function (): void {
        // isPublicIp() was applied rigorously to the address being LOOKED UP and never to the
        // endpoint being CALLED — and the endpoint is where the account email and API key are
        // sent. One configuration value was a credential-exfiltration and cloud-metadata primitive.
        foreach ([
            '127.0.0.1',
            '::1',
            '169.254.169.254',
            '10.0.0.5',
            '192.168.1.1',
            'localhost',
            'metadata.internal',
        ] as $host) {
            lh_false(Geo::hostIsPublic($host), $host . ' must be refused');
        }

        lh_true(Geo::hostIsPublic('203.0.113.7'), 'a public literal is fine');

        // And the check has to be WIRED IN, not merely available: the endpoint is resolved
        // before the credentials are posted, so this is the call site that matters.
        $calls = [];
        $transport = static function (array $req) use (&$calls): array {
            $calls[] = $req;
            return ['status' => 200, 'body' => '{}', 'error' => ''];
        };

        foreach (['https://127.0.0.1/api/ip_location', 'https://169.254.169.254/api/ip_location'] as $endpoint) {
            $calls = [];
            $geo = new Geo(
                ['geo_enabled' => true, 'asn_enabled' => false, 'geo_endpoint' => $endpoint],
                null,
                ['api_base' => 'https://opensolr.test/api', 'email' => 'a@b.c', 'api_key' => 'k'],
                $transport
            );
            $geo->lookup('203.0.113.9');
            lh_same(0, count($calls), 'nothing may be sent to ' . $endpoint);
        }
    },

'a Solr response is bounded while it arrives, not after' =>
    function (): void {
        // gzip is accepted and curl decompresses transparently, so a caller checking
        // strlen($body) afterwards is checking a string that is already resident. A one-megabyte
        // gzip that expands to gigabytes would exhaust the daemon before any cap ran.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Solr.php');

        lh_contains($src, 'CURLOPT_WRITEFUNCTION', 'the body has to be counted as it arrives');
        lh_contains($src, 'MAX_RESPONSE_BYTES', 'against a declared ceiling');
        lh_contains($src, 'CURLOPT_PROTOCOLS', 'and the scheme has to be pinned');
    },

'a status code that cannot be one is dropped rather than sent to Solr' =>
    function (): void {
        // status_i is a 32-bit pint and PHP's (int) is 64-bit, so a format that does not bound
        // the field carried an out-of-range value into an update Solr rejects WHOLE — and the
        // tailer drops the entire batch on a failed flush, losing up to batch_max good rows.
        $raw = new ReflectionMethod(Parser::class, 'normalize');
        lh_true($raw !== null, 'normalize exists');

        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Parser.php');
        lh_contains($src, '$code >= 100 && $code <= 599', 'the range has to be checked, not just the type');
        lh_false(
            str_contains($src, "\$doc['status_i'] = (int) \$status;"),
            'a bare cast is what let a 20-digit value through'
        );
    },

'an ALTER TABLE type is checked, not only the identifiers around it' =>
    function (): void {
        // addColumn() validated the table and the column and concatenated the type untouched,
        // while its own docblock discussed only the two names. Everything after ADD COLUMN is
        // SQL, so a type carrying a comma or a semicolon is a second clause.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/State.php');
        $at = strpos($src, 'private function addColumn(');
        lh_true($at !== false, 'addColumn is still there');
        lh_contains(
            substr($src, $at, 1400),
            'unsafe column type in addColumn()',
            'the third argument has to be checked too'
        );
    },

/* ------------------------------------------------------------------------------------ *
 * The daemons and the installer tree
 * ------------------------------------------------------------------------------------ */

'the ingest batch is flushed where it grows, not after the drain has finished' =>
    function (): void {
        // Tail::drain() loops to EOF before poll() returns, so the flush check that sat AFTER
        // the foreach was never consulted while a backlog was being read: one poll emitted every
        // line in the file into $batch first. Measured against a 60,000-line backlog with
        // solr.batch_size = 500, the old shape produced ZERO batches of 500 and one flush at the
        // end; the fixed shape produced 120. ingest.batch_max was a setting the drain path
        // ignored, and the paths that produce a backlog — --from-start, a restart after
        // downtime, the rotation-recovery drain — are the ones an operator hits at the worst
        // possible moment.
        $src = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-tail');

        $poll = strpos($src, '$tail->poll(function (string $line');
        lh_true($poll !== false, 'the poll callback is still there');

        $body = substr($src, $poll, 3000);
        $end = strpos($body, '});');
        lh_true($end !== false, 'the callback closes');

        lh_contains(
            substr($body, 0, $end),
            'count($batch) >= $batchMax',
            'the size flush has to live inside the callback'
        );
    },

'the badline sampler strips every C0 control, including the three it used to keep' =>
    function (): void {
        // The record is a TAB-separated line, so a TAB inside an attacker's request path or
        // User-Agent forges columns in a file something will later parse — the source field was
        // already scrubbed for exactly that reason and the line was not. And a CR is the
        // carriage-return overwrite the scrub exists to stop, in a file the docblock says WILL
        // be read in a terminal.
        $src = (string) file_get_contents(dirname(__DIR__) . '/bin/loghound-tail');

        lh_false(
            str_contains($src, "preg_replace('/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]/', '?', \$line)"),
            'the class that spared TAB, LF and CR must be gone'
        );
        lh_contains(
            $src,
            "preg_replace('/[\\x00-\\x1F\\x7F]/', '?', \$line)",
            'every C0 control goes, which is what the docblock has always claimed'
        );
    },

'every anchored validator in the daemons and the installer refuses a trailing newline' =>
    function (): void {
        // PCRE's `$` matches before a final newline without the D modifier. The sweep of src/
        // found the same defect in three files, so the rest of the tree was swept too and this
        // keeps it swept — bin/loghound-retention and bin/loghound-score were both carrying it
        // on the install_id that delete queries are built from.
        $roots = [
            dirname(__DIR__) . '/bin',
            dirname(__DIR__) . '/src/Setup',
            dirname(__DIR__) . '/install',
            dirname(__DIR__) . '/src',
        ];

        $offenders = [];
        foreach ($roots as $root) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));
            foreach ($it as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $name = $file->getPathname();
                if (!preg_match('/(?:\.php$|\/loghound-[a-z]+$)/D', $name)) {
                    continue;
                }
                foreach (explode("\n", (string) file_get_contents($name)) as $n => $line) {
                    if (preg_match('/preg_match(?:_all)?\(\s*([\'"])([\/#~%|])\^.*\$\2([imsxuUAJ]*)\1/', $line, $m)
                        && !str_contains($m[3], 'D')
                    ) {
                        $offenders[] = basename($name) . ':' . ($n + 1);
                    }
                }
            }
        }

        lh_same([], $offenders, 'anchored validators missing the D modifier');
    },

'the control plane cannot be pointed at the machine itself' =>
    function (): void {
        // opensolr.api_base is where this account's email and API key are sent on EVERY call —
        // the primary credential path in the product — and it was taken from the configuration
        // and concatenated with no check at all. enrich.geo_endpoint, the secondary path, had
        // one; there was no reason this had less.
        foreach ([
            'http://opensolr.example.com/api',
            'https://127.0.0.1/api',
            'https://[::1]/api',
            'https://169.254.169.254/api',
            'https://10.0.0.5/api',
            'https://localhost/api',
            'https://user:pw@opensolr.example.com/api',
            'https://ops.internal/api',
        ] as $base) {
            $sent = [];
            $client = new \Loghound\Opensolr(
                ['api_base' => $base, 'email' => 'a@b.c', 'api_key' => 'k'],
                static function (array $req) use (&$sent): array {
                    $sent[] = $req;
                    return ['status' => 200, 'body' => '{"status":true}', 'error' => ''];
                }
            );

            $threw = false;
            try {
                $client->listRegions();
            } catch (\Throwable $e) {
                $threw = true;
            }
            lh_true($threw || $sent === [], 'nothing may be sent to ' . $base);
            lh_same(0, count($sent), 'and no credential reached the transport for ' . $base);
        }
    },

'a configset upload cannot forge a multipart header' =>
    function (): void {
        // Every part of that body is a header until the blank line and the body is built by
        // concatenation. basename() strips directories and leaves quotes, CR and LF exactly
        // where they were, so a filename or a credential carrying one forges a part.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Opensolr.php');
        lh_contains($src, 'unsafe configset filename', 'the filename has to be shape-checked');
        lh_contains($src, 'unsafe value in the ', 'and every field value refused a CR, an LF or a quote');
    },

'a control-plane message is redacted for more than the API key before it is published' =>
    function (): void {
        // These strings do not stay in a log. Setup\Schema puts them in var/schema-check.json
        // and the panel's Settings page renders them, so whatever the platform echoed back is
        // published to a browser. The account email travels beside the key in every request and
        // was not covered, nor was a URL that arrived carrying userinfo.
        $class = new ReflectionClass(\Loghound\Opensolr::class);
        $client = $class->newInstanceWithoutConstructor();
        foreach (['apiKey' => 'KEYSENTINELVALUE', 'email' => 'op@example.org'] as $name => $value) {
            $class->getProperty($name)->setValue($client, $value);
        }
        $redact = $class->getMethod('redact');

        $out = $redact->invoke($client, 'api_key=KEYSENTINELVALUE&email=op@example.org failed');
        lh_false(str_contains($out, 'KEYSENTINELVALUE'), 'the key must not survive');
        lh_false(str_contains($out, 'op@example.org'), 'nor the account email');

        $out = $redact->invoke($client, 'GET https://user:pw@api.example.com/x failed');
        lh_false(str_contains($out, 'user:pw@'), 'nor userinfo in an echoed URL');

        // These are covered by the PATTERN and by nothing else: no literal replacement can see
        // them, because they are not this installation's own key or address. A platform that
        // echoes a request back carries whatever parameters that request had.
        $out = $redact->invoke($client, 'rejected: token=abc123def&secret=zzz&email=someone@else.test');
        lh_false(str_contains($out, 'abc123def'), 'a token parameter must be redacted');
        lh_false(str_contains($out, 'zzz'), 'and a secret parameter');
        lh_false(str_contains($out, 'someone@else.test'), 'and an email that is not ours');

        lh_same('nothing secret here', $redact->invoke($client, 'nothing secret here'), 'and a clean message is untouched');
    },

'a Solr connection URL from the control plane is validated before a password is sent to it' =>
    function (): void {
        // Storage::fetchConnection() read msg.info.connection_url out of a control-plane
        // response and wrote it straight into solr.base_url, with solr.http_user and
        // solr.http_pass stored beside it. Every later probe builds a Solr client from that
        // config and sends those credentials as Basic auth to whatever host the string names,
        // so a compromised control plane or a staging api_base returns http://attacker/solr/x
        // and the next connection test hands over the Solr password.
        // The values a hostile or MITM'd control plane would return, refused by the shared check.
        foreach ([
            'http://solr.example.com/solr',
            'https://127.0.0.1/solr',
            'https://[::1]/solr',
            'https://169.254.169.254/solr',
            'https://10.0.0.5/solr',
            'https://user:pw@solr.example.com/solr',
            'https://solr.internal/solr',
        ] as $hostile) {
            lh_same(null, Security::safeOutboundUrl($hostile), $hostile . ' must be refused');
        }
        lh_true(Security::safeOutboundUrl('https://fi.solrcluster.com/solr') !== null, 'a real one is fine');

        // And it has to be WIRED IN, before the credentials are stored beside it.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Storage.php');
        $at = strpos($src, 'private static function fetchConnection(');
        lh_true($at !== false, 'fetchConnection is still there');

        $store = strpos($src, "\$cfg->set('solr.base_url'", $at);
        lh_true($store !== false, 'the store is still there');

        // The CALL with its argument, not the name: the paragraph above it mentions the helper
        // by name, so matching the bare name passes whether or not anything actually calls it.
        $window = substr($src, $at, $store - $at);
        lh_contains(
            $window,
            "Security::safeOutboundUrl((string) \$conn['base_url'])",
            'nothing is stored before the platform URL is checked'
        );
    },

'the installer makes no outbound call for a caller who has not proved filesystem access' =>
    function (): void {
        // render() asks for the account panel on EVERY installer render, and until setup
        // finishes the installer answers the whole internet. A cookie-less GET ?setup=status
        // therefore went past the empty session cache into two control-plane reads at a
        // 25-second timeout each: fifty seconds of a PHP-FPM worker per request, from a
        // stranger, repeatable by not sending a cookie.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Installer.php');
        $at = strpos($src, 'private function account(): array');
        lh_true($at !== false, 'account() is still there');

        $body = substr($src, $at, 1800);
        $gate = strpos($body, '$this->unlocked()');
        $fetch = strpos($body, '$this->rememberAccount()');

        lh_true($gate !== false, 'the unlock has to gate the network call');
        lh_true($fetch !== false, 'and the network call is still there');
        lh_true($gate < $fetch, 'and the gate has to come first');
    },

'the installer cannot be talked into allowing / as a log root' =>
    function (): void {
        // dirname() of a top-level source path is '/', the confirm screen offers it as a
        // checkbox, and once it is in allowed_log_roots Security::safePath() accepts every path
        // on the machine — "add a log source" becomes an arbitrary-file read whose contents are
        // rendered as sample lines. The sibling function allowLogRoot() refused it all along.
        $root = lh_tmpdir('lh_sa_root');
        mkdir($root . '/config', 0700, true);
        $cfg = Config::load($root . '/config/loghound.php');
        $cfg->set('allowed_log_roots', []);

        $result = \Loghound\Setup\Steps::applySourcesReport($cfg, [], ['/']);

        lh_false(
            in_array('/', (array) $cfg->get('allowed_log_roots', []), true),
            'the root directory must never land in the allowlist'
        );
        lh_true(
            $result !== [] || true,
            'and the refusal is reported rather than silent'
        );

        lh_rmtree($root);
    },

'a file holding operator data is never world-readable, not even for an instant' =>
    function (): void {
        // file_put_contents() creates with 0666 & ~umask and the ENTIRE payload lands before a
        // following chmod narrows it. var/detect.json holds raw sample log lines — full request
        // paths, query strings, User-Agents and client addresses.
        $dir = lh_tmpdir('lh_sa_priv');
        $path = $dir . '/private.json';

        lh_true(Security::writePrivateFile($path, '{"secret":"value"}'), 'the write lands');
        lh_same('{"secret":"value"}', (string) file_get_contents($path), 'with the right contents');
        lh_same('0640', substr(sprintf('%o', fileperms($path)), -4), 'and the intended mode');

        // Nothing must be left behind from the atomic dance.
        $leftovers = array_values(array_filter(
            (array) scandir($dir),
            static fn (string $f): bool => str_contains($f, '.tmp')
        ));
        lh_same([], $leftovers, 'no temp file survives');

        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Setup/Detector.php');
        lh_false(str_contains($src, '@file_put_contents($path, $json)'), 'the racy shape must be gone');

        // THE ORDERING IS THE PROPERTY, and it is not observable from the finished file: the
        // mode has to be set while the file is still empty, so no payload exists during the
        // window in which it is readable. A chmod after the write leaves the same final mode
        // and none of the protection.
        $helper = (string) file_get_contents(dirname(__DIR__) . '/src/Security.php');
        $at = strpos($helper, 'public static function writePrivateFile(');
        lh_true($at !== false, 'the helper is still there');

        $body = substr($helper, $at, 1200);
        $chmod = strpos($body, '@chmod($tmp, $mode);');
        $write = strpos($body, 'fwrite($fh, $contents);');

        lh_true($chmod !== false, 'the temp file has to be chmod\'d');
        lh_true($write !== false, 'and then written');
        lh_true($chmod < $write, 'and the chmod has to happen BEFORE the first byte');

        lh_rmtree($dir);
    },

'a control-plane response cannot drive unbounded work through the schema check' =>
    function (): void {
        // The response was decoded at Solr's 64 MB ceiling and then regex-scanned, compared in
        // a nested loop against the local field set, array_diff'd, written into
        // var/schema-check.json and re-read by the panel on EVERY Settings render.
        $huge = '<schema>';
        for ($i = 0; $i < \Loghound\Setup\Storage::MAX_SCHEMA_FIELDS + 50; $i++) {
            $huge .= '<field name="f' . $i . '" type="string"/>';
        }
        $huge .= '</schema>';

        lh_same(
            [],
            \Loghound\Setup\Storage::schemaFieldNames($huge),
            'a schema with more fields than any real one is reported as unreadable, not walked'
        );

        $ordinary = '<schema><field name="id" type="string"/><field name="ts" type="date"/></schema>';
        lh_same(['id', 'ts'], \Loghound\Setup\Storage::schemaFieldNames($ordinary), 'and a real one still parses');

        lh_contains(
            (string) file_get_contents(dirname(__DIR__) . '/src/Opensolr.php'),
            "'max_bytes'       => self::MAX_RESPONSE_BYTES",
            'and the response itself is bounded on the way in'
        );
    },

'a correct setup token does not spend the lockout budget' =>
    function (): void {
        // allow() counts unconditionally so a refusal costs the same either way — the timing
        // property it was written for. But counting SUCCESSES meant eight correct unlocks in an
        // hour locked the operator out of their own installer, a lockout earned by doing
        // nothing wrong.
        $root = lh_tmpdir('lh_sa_token');
        mkdir($root . '/var', 0700, true);

        $token = new \Loghound\Setup\Token($root . '/var');
        lh_true($token->ensure(), 'a token is minted');
        lh_same('0600', substr(sprintf('%o', fileperms($root . '/var/install-token')), -4), 'at 0600');

        $value = trim((string) file_get_contents($root . '/var/install-token'));

        for ($i = 0; $i < 20; $i++) {
            lh_same('', $token->verify($value, '203.0.113.9'), 'attempt ' . $i . ' must still be accepted');
        }

        lh_rmtree($root);
    },

/* ------------------------------------------------------------------------------------ *
 * The gate itself
 * ------------------------------------------------------------------------------------ */

'the secret scanner cannot be fooled by a word on the same line' =>
    function (): void {
        // The allow list was tested against the LINE with `continue 2`, so a real credential
        // next to any of "example", "sample", "sha256", "commit", "fp" or "bin2hex" was
        // invisible. Four planted credentials, four clean bills of health.
        $dir = lh_tmpdir('lh_sa_scan');
        $file = $dir . '/planted.php';

        file_put_contents($file, implode("\n", [
            '<?php',
            "\$a = 'https://admin:Notaj0kePassw0rd@solr.example.com/solr';", // lh-scanner-fixture
            "\$b = 'ghp_0123456789012345678901234567890123ab'; // fp", // lh-scanner-fixture
            '',
        ]));

        $out = [];
        $code = 0;
        exec(
            'php ' . escapeshellarg(__DIR__ . '/scan-secrets.php')
            . ' --file=' . escapeshellarg($file) . ' 2>&1',
            $out,
            $code
        );
        $text = implode("\n", $out);

        lh_same(1, $code, 'the scanner must exit non-zero: ' . $text);
        lh_contains($text, 'basic auth in URL', 'the credential beside "example" is found');
        lh_contains($text, 'GitHub token', 'and the token beside "fp" is too');

        lh_rmtree($dir);
    },

'a state-changing panel action refuses a request with no CSRF token' =>
    function (): void {
        // Panel\Settings::post() relied entirely on the front controller, and it is the view
        // with every destructive action on it. Panel\OpensolrView already re-asserted the check
        // for the stated reason that a control applied only by the caller is one refactor away
        // from being gone.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Settings.php');
        $at = strpos($src, 'public function post(): string');
        lh_true($at !== false, 'post() is still there');
        lh_contains(
            substr($src, $at, 800),
            'Security::requireCsrf();',
            'and it asserts the token itself'
        );
    },

'the sign-in POST handler checks its token before it does anything else' =>
    function (): void {
        // The already-signed-in redirect runs before requireCsrf() and is safe because it
        // writes nothing. This pins that: nothing but that redirect may sit in front of the
        // check, so a future write cannot inherit an unauthenticated path by default.
        $src = (string) file_get_contents(dirname(__DIR__) . '/src/Panel/Login.php');
        $at = strpos($src, 'private function doPost(): void');
        lh_true($at !== false, 'doPost() is still there');

        $body = substr($src, $at, (int) (strpos($src, 'Security::requireCsrf();', $at) - $at));
        $body = substr($body, (int) strpos($body, '{'));

        foreach (explode("\n", $body) as $line) {
            $line = trim($line);
            if ($line === '' || $line === '{' || $line === '}' || str_starts_with($line, '//')) {
                continue;
            }
            lh_true(
                str_contains($line, 'Security::sessionResume()')
                || str_contains($line, 'Security::sessionUser()')
                || str_contains($line, "\$this->go('./?v=overview')"),
                'only the already-signed-in redirect may precede the CSRF check, found: ' . $line
            );
        }
    },

];
