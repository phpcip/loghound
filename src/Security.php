<?php
/**
 * Loghound — Security primitives.
 *
 * Every escaping, authentication and input-validation helper in the project lives here.
 * There must be exactly ONE implementation of each of these in the codebase: if you find
 * yourself writing htmlspecialchars() or hash_equals() anywhere else, use these instead.
 *
 * Threat model: this application parses attacker-controlled data by definition. Log lines
 * contain request paths, User-Agent and Referer strings chosen by whoever hit the origin
 * server, and the beacon collector is a public unauthenticated write path. Nothing that
 * arrives from either source may be treated as safe at any sink.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use Loghound\Auth\Persistence;
use Loghound\Auth\TwoFactor;

final class Security
{
    /** Hard ceiling on Solr `rows` regardless of what a caller asks for. */
    public const MAX_ROWS = 500;

    /** Hard ceiling on Solr `start` (deep paging is a DoS vector and a useless UX). */
    public const MAX_START = 100000;

    /**
     * The failed-sign-in ledger, inside var/ next to the setup token's own ledger.
     *
     * A file rather than SQLite, for the same reason Setup\Token uses one: the login path
     * has to keep working on an installation whose ext-sqlite3 is missing or whose state
     * database is being rebuilt, and an authentication control that depends on a component
     * the panel is meant to REPORT on is a control that disappears exactly when it matters.
     */
    public const LOGIN_LEDGER = 'login-attempts.json';

    /**
     * Was this request's session created from a persistent-login token?
     *
     * Request-scoped, because it is a fact about THIS request and not about the session: the
     * session it produced is an ordinary one from the next request onwards. requireCsrf() reads
     * it so that a state-changing request whose session had to be re-established is answered
     * with an explanation instead of a bare token mismatch. See requireCsrf().
     */
    private static bool $resumedFromToken = false;

    /** Session key holding the signed-in operator's username. */
    private const S_USER = 'lh_user';

    /** Session key holding the instant the session was signed in (absolute timeout anchor). */
    private const S_LOGIN_AT = 'lh_login_at';

    /** Session key holding the instant of the last authenticated request (idle anchor). */
    private const S_SEEN_AT = 'lh_seen_at';

    /**
     * Session key marking a session that took the "stay signed in" option.
     *
     * Its only effect is that the idle and absolute timeouts are not applied. Every other
     * session is governed by them exactly as before — the option is the whole of the
     * difference, and an operator who did not take it is not affected by its existence.
     */
    private const S_PERSIST = 'lh_persist';

    /** Session key holding the username that passed the password but not yet the second factor. */
    private const S_2FA_USER = 'lh_2fa_user';

    /** Session key holding when that happened, so a half-finished sign-in cannot sit open. */
    private const S_2FA_AT = 'lh_2fa_at';

    /** Session key remembering whether the sign-in that is pending asked to be remembered. */
    private const S_2FA_REMEMBER = 'lh_2fa_remember';

    /**
     * How long a sign-in may sit waiting for its second factor.
     *
     * Five minutes is long enough to find a phone and short enough that a session holding
     * "this username's password was correct" does not linger. The pending session grants no
     * access to anything while it waits: it has no lh_user, so authenticate() reports it as
     * not signed in like any other anonymous request.
     */
    public const PENDING_TTL = 300;

    /**
     * Escape for HTML text/attribute context.
     *
     * Used for every log-derived value that reaches the page: paths, User-Agents,
     * referers, AS org names. ENT_QUOTES covers both quote styles so the same call is
     * safe inside a double- or single-quoted attribute.
     */
    public static function esc(?string $s): string
    {
        return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Escape for embedding a PHP value inside a <script> block.
     *
     * JSON_HEX_TAG is the important flag: it turns "<" and ">" into < / > so a
     * User-Agent containing "</script>" cannot break out of the script element. The other
     * HEX flags close off attribute-context and HTML-comment edge cases.
     */
    public static function escJs($value): string
    {
        return json_encode(
            $value,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
        );
    }

    /**
     * Does this URL carry credentials in its authority — `scheme://user:pass@host/…`?
     *
     * Two independent tests, because one of them is the belt and the other the braces.
     * parse_url() is what an HTTP client will itself see, so its verdict is authoritative
     * for what would actually be sent. The raw-authority test then catches anything
     * parse_url decides not to split out: everything between `://` and the first `/`, `?`
     * or `#` is the authority by definition, and an `@` in there is userinfo whatever else
     * it may look like.
     *
     * Used by safeUrl() to refuse rendering such a URL, and by the setup steps to refuse
     * STORING one, where a specific message can be given instead of a bare refusal.
     */
    public static function urlHasUserinfo(string $url): bool
    {
        $parts = parse_url($url);
        if (is_array($parts) && (isset($parts['user']) || isset($parts['pass']))) {
            return true;
        }
        if (!preg_match('~^[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]*)~', $url, $m)) {
            return false;
        }
        return str_contains($m[1], '@');
    }

    /**
     * Validate a URL for use in an href/src attribute.
     *
     * Referer values come straight from the wire and routinely contain javascript:,
     * data: and vbscript: payloads. Anything that is not plainly http(s) returns '#'
     * rather than being rendered as a live link. Control characters and whitespace are
     * refused along with them, because either can split a header or break out of an
     * attribute.
     *
     * A URL carrying userinfo is refused as well, and that matters in both directions.
     * Rendering `https://user:pass@host/` as a live link publishes somebody's credentials
     * to whoever reads the panel and hands them to the target host the moment it is
     * clicked, and an embedded-credential link is the oldest shape of a spoofed hostname
     * there is. On the way IN it is the same refusal that stops `solr.base_url` from being
     * a password stored in config/loghound.php and repeated into every request URL — the
     * setup steps call urlHasUserinfo() first so they can say WHY rather than only "no".
     */
    public static function safeUrl(?string $url): string
    {
        $url = trim((string) $url);
        if ($url === '') {
            return '#';
        }
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return '#';
        }
        if (preg_match('/[\x00-\x20\x7F"\'<>]/', $url)) {
            return '#';
        }
        if (self::urlHasUserinfo($url)) {
            return '#';
        }
        return $url;
    }

    /**
     * Constant-time string comparison.
     *
     * Wraps hash_equals so token checks cannot be short-circuited by timing. Never
     * compare a secret with == or ===.
     */
    public static function equals(string $known, string $given): bool
    {
        return hash_equals($known, $given);
    }

    /**
     * Compute the beacon/session HMAC.
     *
     * The beacon collector is public, so a client could otherwise claim any session id and
     * any dwell time it liked. Every beacon payload must carry a token minted here.
     */
    public static function hmac(string $secret, string $payload): string
    {
        return hash_hmac('sha256', $payload, $secret);
    }

    /**
     * Mint a beacon token bound to a session id and an issue time.
     *
     * The issued-at is carried in the clear (and signed) so the collector can reject
     * impossible dwell-time claims without keeping server-side state per beacon.
     */
    public static function mintToken(string $secret, string $sessionId, int $issuedAt): string
    {
        return $issuedAt . '.' . self::hmac($secret, $sessionId . '|' . $issuedAt);
    }

    /**
     * Verify a beacon token and return its issued-at timestamp, or null when invalid.
     *
     * A token issued in the future is as broken as an expired one and is refused the same
     * way, with 60 seconds of slack so that ordinary clock skew between the browser's
     * request and this host is not treated as an attack.
     *
     * @param int $maxAge Seconds after which a token is refused (default 12h).
     */
    public static function verifyToken(
        string $secret,
        string $sessionId,
        string $token,
        int $maxAge = 43200
    ): ?int {
        $parts = explode('.', $token, 2);
        if (count($parts) !== 2) {
            return null;
        }
        [$issuedAt, $mac] = $parts;
        if (!ctype_digit($issuedAt)) {
            return null;
        }
        $issuedAt = (int) $issuedAt;
        $expected = self::hmac($secret, $sessionId . '|' . $issuedAt);
        if (!self::equals($expected, $mac)) {
            return null;
        }
        $age = time() - $issuedAt;
        if ($age < -60 || $age > $maxAge) {
            return null;
        }
        return $issuedAt;
    }

    /**
     * Issue (and lazily create) the per-session CSRF token for the panel.
     */
    public static function csrfToken(): string
    {
        self::startSession();
        if (empty($_SESSION['lh_csrf'])) {
            $_SESSION['lh_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['lh_csrf'];
    }

    /**
     * Throw the current CSRF token away and mint a new one.
     *
     * Called at sign-in. The token that was valid for the anonymous pre-login session is
     * not a privilege in itself, but it was known to whoever could observe that session,
     * and an authenticated session should share nothing with the unauthenticated one it
     * grew out of.
     */
    public static function rotateCsrf(): string
    {
        self::startSession();
        $_SESSION['lh_csrf'] = bin2hex(random_bytes(32));
        return $_SESSION['lh_csrf'];
    }

    /**
     * Start a session without letting PHP rewrite our cache headers.
     *
     * THIS IS NOT A TIDINESS WRAPPER. session_start() emits its own Cache-Control according
     * to session.cache_limiter, and it REPLACES whatever the application already sent. The
     * front controller and the sign-in page both send `Cache-Control: no-store, private`
     * before any session exists, and on a default php.ini the limiter happens to overwrite it
     * with `no-store, no-cache, must-revalidate` — which is still no-store, so the mistake is
     * invisible. On an installation whose pool sets `session.cache_limiter = private`, the
     * same call replaces it with `private, max-age=10800`, and the SIGN-IN PAGE becomes
     * cacheable: the browser is then free to re-present a form whose CSRF token was rotated
     * hours ago, which is a guaranteed "CSRF token mismatch" on a sign-in that should have
     * worked. Measured, not theorised.
     *
     * Passing an empty limiter tells PHP to send nothing, so the header the application chose
     * is the header that is sent, on every php.ini.
     *
     * PUBLIC, because it was private and two other places grew their own copy of it —
     * Panel\Settings::stashSolrNote() and takeSolrNote() both called session_start() directly,
     * without the empty limiter, which is the defect described above reproduced twice. There is
     * one way to start a session in this application and this is it.
     *
     * WHY THE headers_sent() GUARD IS NOT A PAPER-OVER. A session cannot be started once output
     * has begun, because the session cookie is a header; PHP warns and refuses. Calling it anyway
     * produced 127 warnings per test run, which is noise that trains everybody to ignore warnings.
     * But the guard must not turn a real defect into a silence, so the two cases are separated:
     *
     *   CLI — the test runner prints each result as it goes, so by the time a test asks for a
     *         session, output has been written. There are no headers and no cookie to send; the
     *         refusal is an artefact of the harness and nothing is wrong. Return quietly.
     *   WEB — output before a session start is a BUG IN THE CALLER, and a serious one: without a
     *         cookie the session does not persist, so the operator cannot sign in and every CSRF
     *         check fails, with nothing on screen to explain it. It is logged with the file and
     *         line that sent the output first, which is the only fact that makes it fixable.
     *
     * It does not die: killing the render would turn a header-ordering mistake into a blank 500
     * and hide the very diagnosis being logged. It returns false, the caller's writes to $_SESSION
     * go to a superglobal that is never persisted, and the authentication fails closed.
     *
     * @return bool Whether a session is active when this returns.
     */
    public static function startSession(): bool
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return true;
        }

        $file = '';
        $line = 0;
        if (headers_sent($file, $line)) {
            if (PHP_SAPI !== 'cli') {
                error_log(
                    'Loghound: a session was needed after output had already been sent from '
                    . $file . ':' . $line . '. The session cookie cannot be set, so sign-in and '
                    . 'CSRF will fail. Nothing may be echoed before Security::startSession().'
                );
            }
            return false;
        }

        @session_cache_limiter('');
        session_start();

        return session_status() === PHP_SESSION_ACTIVE;
    }

    /**
     * Enforce a CSRF token on a state-changing request.
     *
     * Fails closed: any request that is not a GET/HEAD must present a matching token or
     * the process is terminated with 403 before the handler runs.
     *
     * ONE CASE IS REPORTED DIFFERENTLY, AND NOT ACCEPTED. When this request's session was just
     * re-established from a persistent-login token, the session that issued the submitted token
     * no longer exists — PHP's garbage collector deleted it — so there is nothing to compare
     * against and no way for any token to be valid. That is not the operator doing anything
     * wrong, and answering it with "CSRF token mismatch" is the same misleading page this whole
     * area was fixed to stop producing: they are signed in, the panel works, and the message
     * describes an attack. So it is answered with 409 and the actual remedy. The request is
     * still refused, no token is accepted, and the guard is not relaxed by a single byte.
     */
    public static function requireCsrf(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'GET' || $method === 'HEAD') {
            return;
        }

        $given = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        if (is_string($given) && self::equals(self::csrfToken(), $given)) {
            return;
        }

        if (self::$resumedFromToken) {
            http_response_code(409);
            $api = $_GET['api'] ?? null;
            if (is_string($api) && $api !== '') {
                header('Content-Type: application/json; charset=utf-8');
                exit((string) json_encode([
                    'error' => 'Your session was re-established, so this page is out of date. '
                        . 'Reload it and try again.',
                ]));
            }
            header('Content-Type: text/plain; charset=utf-8');
            exit(
                "You are signed in, but this page was loaded under a session the server has since\n" .
                "cleaned up, so the form it carried is out of date. Reload the page and do it again.\n"
            );
        }

        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        exit("CSRF token mismatch\n");
    }

    /**
     * Resolve a filesystem path and confirm it sits inside one of the allowed roots.
     *
     * Log locations are operator-configurable, which makes them an arbitrary-file-read
     * primitive if taken at face value. realpath() collapses .. and symlinks, then the
     * prefix check is done against the resolved root so a symlink out of the tree cannot
     * escape. Returns null when the path is missing or outside every allowed root.
     *
     * The prefix comparison appends a separator to the root before matching, so that
     * "/var/log-evil" cannot pass itself off as living under "/var/log".
     *
     * @param string[] $allowedRoots
     */
    public static function safePath(string $path, array $allowedRoots): ?string
    {
        $real = realpath($path);
        if ($real === false) {
            return null;
        }
        foreach ($allowedRoots as $root) {
            $realRoot = realpath($root);
            if ($realRoot === false) {
                continue;
            }
            if ($real === $realRoot || str_starts_with($real, rtrim($realRoot, '/') . '/')) {
                return $real;
            }
        }
        return null;
    }

    /**
     * Clamp an integer into a range, tolerating garbage input.
     *
     * Used on every caller-supplied rows/start/limit before it reaches Solr.
     */
    public static function clampInt($value, int $min, int $max, int $default): int
    {
        if (!is_numeric($value)) {
            return $default;
        }
        $n = (int) $value;
        return max($min, min($max, $n));
    }

    /**
     * Validate a Solr field name against the allowlist pattern.
     *
     * Field names arriving from the UI (sort keys, facet fields) are concatenated into
     * Solr parameters, so they must never contain anything but the safe character class.
     */
    public static function isSafeFieldName(string $field): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_]{1,64}$/D', $field);
    }

    /**
     * Validate a Solr core / Opensolr index name.
     */
    public static function isSafeCoreName(string $core): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_]{1,64}$/D', $core);
    }

    /**
     * A USABILITY check on an operator-supplied log pattern. NOT a safety proof.
     *
     * What it actually establishes, and all it establishes:
     *   - the pattern is a delimited regex with a modifier block we recognise;
     *   - it is not absurdly long;
     *   - it COMPILES, which is the mistake an operator makes most often;
     *   - it is fast enough on ONE ordinary log-shaped line of about 900 bytes.
     *
     * IT DOES NOT PROVE THE PATTERN IS SAFE, and it must never be described as if it did.
     * The probe runs the candidate against a single fixed subject of plausible log-shaped
     * text. Every real log pattern is anchored — `/^(?<remote_addr>\S+) .../` — and an
     * anchored pattern fails against that subject in a handful of steps whatever its
     * internal shape, so the timing tells you nothing about the pathological case. `/^(a+)+$/`
     * is accepted here, and so is any pattern built the same way: the subject that makes it
     * blow up is not this one, it is whichever line an attacker chooses to send to the
     * origin server.
     *
     * CATASTROPHIC BACKTRACKING IS CONTAINED AT MATCH TIME, NOT HERE. LogFormat::parse()
     * sets its own pcre.backtrack_limit around every single match and treats exhaustion as
     * an ordinary parse failure, so the worst a hostile line can cost is one bounded match
     * attempt. That is the guard. This function is the thing that stops an operator from
     * saving a typo and finding out at 3am.
     *
     * The /e modifier is long gone from PHP, but a modifier block we do not explicitly
     * expect is refused anyway rather than passed to PCRE to see what happens.
     *
     * @return string|null Null when acceptable, otherwise a human-readable reason.
     */
    public static function validateUserRegex(string $pattern, float $budgetSeconds = 0.10): ?string
    {
        if (strlen($pattern) > 4096) {
            return 'Pattern is too long (max 4096 bytes).';
        }
        if (!preg_match('/^([\/#~%|])(.*)\1([imsxuUAD]*)$/sD', $pattern)) {
            return 'Pattern must be a delimited regex, e.g. /^(?<ip>\S+) .../';
        }

        $oldLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '100000');

        $subject = str_repeat('a b "c" 123 ', 40) . str_repeat('x', 400);

        $start = microtime(true);
        $result = @preg_match($pattern, $subject);
        $elapsed = microtime(true) - $start;

        ini_set('pcre.backtrack_limit', (string) $oldLimit);

        if ($result === false) {
            $err = preg_last_error();
            if ($err === PREG_BACKTRACK_LIMIT_ERROR) {
                return 'Pattern backtracks excessively and would stall ingestion.';
            }
            return 'Pattern failed to compile: ' . preg_last_error_msg();
        }
        if ($elapsed > $budgetSeconds) {
            return sprintf(
                'Pattern is too slow (%.0f ms on a 900-byte line); it would not keep up with ingestion.',
                $elapsed * 1000
            );
        }
        return null;
    }

    /**
     * The two authentication modes that exist, and what each one is.
     *
     * A single list so the installer, Settings and Config::validate() cannot drift apart
     * and start disagreeing about which values are real. 'none' is deliberately NOT here:
     * it is the pre-setup state, not something an operator chooses.
     *
     * @return array<string,array{label:string,text:string,cost:string}>
     */
    public static function authModes(): array
    {
        return [
            'basic' => [
                'label' => 'The browser\'s own password prompt',
                'text'  => 'Your browser asks for the username and password before it shows anything. '
                    . 'Every tool that speaks HTTP can sign in the same way, so curl and scripts work '
                    . 'with nothing more than --user.',
                'cost'  => 'The prompt is the browser\'s and cannot be styled, and there is no way to '
                    . 'sign out short of closing the browser.',
            ],
            'session' => [
                'label' => 'A sign-in page',
                'text'  => 'Loghound shows its own sign-in form, keeps you signed in for as long as you '
                    . 'are using it, and gives you a Sign out button that ends the session on the server.',
                'cost'  => 'It only works in a browser: curl and scripts cannot sign in to it, so a '
                    . 'monitoring check against the panel has to be moved to Basic or dropped.',
            ],
        ];
    }

    /**
     * The timeouts and lockout thresholds in force, clamped to sane bounds.
     *
     * Read from config on every request rather than cached, so changing them in Settings
     * takes effect on the next request instead of the next restart. Every value goes
     * through clampInt, so a hand-edited config cannot switch the lockout off by writing
     * a zero or a string into it.
     *
     * @param array<string,mixed> $auth The 'auth' section of the config.
     * @return array{idle:int,absolute:int,attempts:int,window:int}
     */
    public static function authLimits(array $auth): array
    {
        return [
            'idle'     => self::clampInt($auth['idle_timeout'] ?? null, 60, 86400, 1800),
            'absolute' => self::clampInt($auth['absolute_timeout'] ?? null, 300, 2592000, 43200),
            'attempts' => self::clampInt($auth['lockout_attempts'] ?? null, 1, 1000, 8),
            'window'   => self::clampInt($auth['lockout_window'] ?? null, 60, 86400, 900),
        ];
    }

    /**
     * Verify a username and password against the configured account.
     *
     * The username is compared in constant time as well as the password, so a valid
     * account name cannot be enumerated by timing, and password_verify is always reached
     * with a real hash when one is configured so that a wrong username and a wrong
     * password cost the same. Returns false when no password has been set at all, which
     * is the state of a half-finished install: no credential means no way in, never a
     * way in for everybody.
     *
     * @param array<string,mixed> $auth The 'auth' section of the config.
     */
    public static function verifyPassword(array $auth, string $user, string $password): bool
    {
        $hash = (string) ($auth['password_hash'] ?? '');
        if ($hash === '') {
            return false;
        }
        $userOk = self::equals((string) ($auth['user'] ?? ''), $user);
        $passOk = password_verify($password, $hash);
        return $userOk && $passOk;
    }

    /**
     * Is the client actually presenting a session, rather than merely arriving?
     *
     * THE PRECONDITION sessionResume() AND sessionSignOut() SHARE, and the reason neither of
     * them can simply call startSession(). The panel is on the public internet and is crawled
     * and probed constantly; starting a session for every anonymous request would write a
     * session file per probe. A session is touched only when the client presents one — a
     * cookie, or an id set explicitly by a caller such as the test harness. Anything else is
     * "not signed in", which is the same answer with none of the disk churn.
     *
     * It is a named test rather than a condition written twice, because it was written twice
     * and the two copies sat four hundred lines apart.
     */
    private static function sessionPresented(): bool
    {
        return session_id() !== '' || isset($_COOKIE[session_name()]);
    }

    /**
     * Resume an existing session without creating one.
     *
     * The precondition is sessionPresented(); everything after it — the active-session check,
     * the headers_sent guard and the empty cache limiter — is startSession()'s, and is
     * delegated rather than repeated. This used to repeat the limiter line, which is how
     * sessionSignOut() below came to be missing it: one of the two copies was simply forgotten.
     */
    public static function sessionResume(): bool
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return true;
        }
        if (!self::sessionPresented()) {
            return false;
        }
        return self::startSession();
    }

    /**
     * Sign an operator in, after their password has already been verified.
     *
     * session_regenerate_id(true) runs BEFORE the identity is written and deletes the old
     * session file. That is the whole defence against session fixation: an attacker who
     * planted a known session id on the browser — through a link, a subdomain cookie or an
     * XSS on a neighbouring host — holds an id that stops existing at the exact moment it
     * would have become valuable.
     *
     * Only a username and two timestamps are stored. The password is not kept, the hash is
     * not kept, and nothing derived from either is kept: the session file is readable by
     * whoever can read the filesystem, and it must not be worth reading.
     *
     * $persistent records that this session took the "stay signed in" option, which is the
     * only thing that exempts it from the two timeouts. It is set by the sign-in form when the
     * operator ticks the box, and by the persistent-token path when a token recreates a
     * session that PHP's garbage collector deleted — that session has to be exempt too, or the
     * token would be resurrecting sessions only to have them expire again.
     */
    public static function sessionSignIn(string $user, bool $persistent = false): void
    {
        self::startSession();
        session_regenerate_id(true);

        self::clearPending();

        /* An enrollment or an uncollected set of recovery codes that has outlived its TTL goes
           here too. sweepEphemeral() used to run only on the already-signed-in branch of
           authenticateSession(), so a session re-established from a persistent-login token
           carried whatever the previous one had been holding into the new one unswept. */
        TwoFactor::sweepEphemeral();

        $now = time();
        $_SESSION[self::S_USER]     = $user;
        $_SESSION[self::S_LOGIN_AT] = $now;
        $_SESSION[self::S_SEEN_AT]  = $now;
        $_SESSION[self::S_PERSIST]  = $persistent;

        self::rotateCsrf();
    }

    /**
     * Record that a password was correct but the second factor is still outstanding.
     *
     * THE SESSION THIS LEAVES BEHIND IS NOT AUTHENTICATED. It carries no lh_user, so
     * authenticate() reports it as anonymous and every panel view refuses it exactly as it
     * refuses a stranger. All it holds is "this username's password was right, recently, and
     * whether they asked to be remembered" — enough to know what to do when a valid code
     * arrives, and not enough to be worth stealing.
     *
     * The id is regenerated here as well as at sign-in, and the session emptied first. An
     * attacker who planted an id gets it invalidated at the first step rather than the second,
     * and nothing from the anonymous session — a CSRF token somebody else chose included —
     * carries into the half-authenticated one.
     */
    public static function sessionPending(string $user, bool $remember): void
    {
        self::startSession();

        $_SESSION = [];
        session_regenerate_id(true);

        $_SESSION[self::S_2FA_USER]     = $user;
        $_SESSION[self::S_2FA_AT]       = time();
        $_SESSION[self::S_2FA_REMEMBER] = $remember;

        self::rotateCsrf();
    }

    /**
     * The username waiting on a second factor, or '' when none is (still) waiting.
     *
     * A pending stage older than PENDING_TTL is treated as absent. The check is here rather
     * than in the caller so that no caller can forget it.
     */
    public static function pendingUser(): string
    {
        $user = is_string($_SESSION[self::S_2FA_USER] ?? null) ? $_SESSION[self::S_2FA_USER] : '';
        $at   = (int) ($_SESSION[self::S_2FA_AT] ?? 0);

        if ($user === '' || $at <= 0 || (time() - $at) > self::PENDING_TTL) {
            return '';
        }
        return $user;
    }

    /** Did the pending sign-in ask to be remembered? */
    public static function pendingRemember(): bool
    {
        return ($_SESSION[self::S_2FA_REMEMBER] ?? false) === true;
    }

    /** Forget any half-finished sign-in. */
    public static function clearPending(): void
    {
        unset($_SESSION[self::S_2FA_USER], $_SESSION[self::S_2FA_AT], $_SESSION[self::S_2FA_REMEMBER]);
    }

    /** Did this session take the "stay signed in" option? */
    public static function sessionIsPersistent(): bool
    {
        return ($_SESSION[self::S_PERSIST] ?? false) === true;
    }

    /**
     * End a session on the server, not just in the browser.
     *
     * Clearing the cookie alone would leave a session file that is still valid to anyone
     * who kept the id, so the order is: empty the array, expire the cookie, then
     * session_destroy() to delete the server-side record. After this the old id is
     * worthless even when replayed.
     *
     * WHAT IS THIS CALLER'S AND WHAT IS SHARED. The precondition is sessionPresented(), the
     * same one sessionResume() uses: nothing to sign out of unless the client presented
     * something. The starting is startSession()'s — this used to call session_start() bare,
     * without the empty cache limiter, which is the exact defect that wrapper exists to
     * prevent, two functions from a sibling that got it right. A sign-out response carrying
     * `private, max-age=10800` instead of the application's `no-store` is a sign-out page a
     * browser may re-present from cache.
     *
     * SIGN-OUT DIVERGES IN ONE PLACE, DELIBERATELY. When no session can be started — output
     * has already gone out, so the cookie header cannot be set — the old code called
     * session_start() anyway, wrote to a $_SESSION that would never be persisted, and then
     * called session_destroy() with no active session, which warns and destroys nothing. The
     * cookie expiry is the half that still works and still matters, because it is what stops
     * the browser presenting the id again, so it is attempted regardless; the server-side
     * destroy is skipped, because there is nothing to destroy and pretending otherwise is how
     * a sign-out comes to report success it did not achieve. The session file is then left to
     * PHP's garbage collector, which is the same fate as a browser that simply never returns.
     */
    public static function sessionSignOut(): void
    {
        $active = session_status() === PHP_SESSION_ACTIVE;

        if (!$active) {
            if (!self::sessionPresented()) {
                return;
            }
            $active = self::startSession();
        }

        if ($active) {
            $_SESSION = [];
        }

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires'  => time() - 42000,
                'path'     => $params['path'] ?? '/',
                'domain'   => $params['domain'] ?? '',
                'secure'   => (bool) ($params['secure'] ?? false),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
        }

        if ($active) {
            session_destroy();
        }
    }

    /** The signed-in operator's username, or an empty string when nobody is signed in. */
    public static function sessionUser(): string
    {
        return is_string($_SESSION[self::S_USER] ?? null) ? $_SESSION[self::S_USER] : '';
    }

    /**
     * Decide whether this request may proceed, and say why when it may not.
     *
     * Split out of requireAuth() so the decision can be tested without a process that
     * exits: requireAuth() is nothing but this plus the HTTP response for each outcome.
     *
     * States, all of which except 'ok' mean the request is refused:
     *   ok        — authenticated, carry on.
     *   setup     — auth.mode is 'none'; setup never finished.
     *   basic     — Basic mode, credentials missing or wrong: challenge.
     *   login     — session mode, nobody signed in: show the sign-in page.
     *   idle      — session mode, no activity for auth.idle_timeout.
     *   absolute  — session mode, signed in longer than auth.absolute_timeout.
     *   locked    — too many failed attempts from this address.
     *   store     — the attempt ledger could not be read or written.
     *   unknown   — a mode with no implementation behind it.
     *
     * FAIL CLOSED IN BOTH DIRECTIONS. A mode we do not implement is refused rather than
     * waved through, and an attempt counter that cannot be consulted is refused too: a
     * check that cannot be performed is a failed check, never a passed one.
     *
     * @param array<string,mixed> $auth           The 'auth' section of the config.
     * @param string|null         $varDir         Where the attempt ledger lives; null = the app's own var/.
     * @param string[]            $trustedProxies CIDRs whose X-Forwarded-For may be believed.
     * @return array{state:string,user:string,retry:int}
     */
    public static function authenticate(array $auth, ?string $varDir = null, array $trustedProxies = []): array
    {
        $mode = (string) ($auth['mode'] ?? 'none');

        if ($mode === 'none') {
            return ['state' => 'setup', 'user' => '', 'retry' => 0];
        }
        if ($mode !== 'basic' && $mode !== 'session') {
            return ['state' => 'unknown', 'user' => '', 'retry' => 0];
        }

        if ($mode === 'session') {
            return self::authenticateSession($auth, $varDir, $trustedProxies);
        }

        $ip = self::clientIp($trustedProxies);
        $gate = self::loginGate($ip, $auth, $varDir);
        if (!$gate['available']) {
            return ['state' => 'store', 'user' => '', 'retry' => 0];
        }
        if (!$gate['allowed']) {
            return ['state' => 'locked', 'user' => '', 'retry' => $gate['retry']];
        }

        $user = is_string($_SERVER['PHP_AUTH_USER'] ?? null) ? $_SERVER['PHP_AUTH_USER'] : '';
        $pass = is_string($_SERVER['PHP_AUTH_PW'] ?? null) ? $_SERVER['PHP_AUTH_PW'] : '';

        if (!self::verifyPassword($auth, $user, $pass)) {
            self::loginFailure($ip, $auth, $varDir);
            usleep(random_int(150000, 400000));
            return ['state' => 'basic', 'user' => '', 'retry' => 0];
        }

        if ($gate['count'] > 0) {
            self::loginSuccess($ip, $auth, $varDir);
        }
        return ['state' => 'ok', 'user' => $user, 'retry' => 0];
    }

    /**
     * The session-mode half of authenticate().
     *
     * Both timeouts are enforced here rather than left to the session garbage collector,
     * which is best-effort by design and runs on somebody else's request. An expired
     * session is destroyed on the spot: the operator is sent back to the sign-in page, so
     * the timeout is a door that reopens rather than a dead end.
     *
     * The idle anchor is only moved forward for a request that was already authenticated,
     * so a stream of anonymous requests cannot keep somebody else's session alive.
     *
     * NEITHER TIMEOUT APPLIES TO A SESSION THAT TOOK THE "STAY SIGNED IN" OPTION. That is what
     * the option is. Every other session is governed by them unchanged, which is the point:
     * the feature adds a choice, it does not relax the default.
     *
     * When no session is signed in, a persistent-login cookie gets its chance before the
     * operator is sent to the form. That path is where a session deleted by PHP's garbage
     * collector comes back, and it is rate limited like any other sign-in.
     *
     * @param array<string,mixed> $auth
     * @param string[]            $trustedProxies
     * @return array{state:string,user:string,retry:int}
     */
    private static function authenticateSession(
        array $auth,
        ?string $varDir = null,
        array $trustedProxies = []
    ): array {
        $user = self::sessionResume() ? self::sessionUser() : '';

        if ($user === '') {
            return self::resumeRemembered($auth, $varDir, $trustedProxies);
        }

        TwoFactor::sweepEphemeral();

        if (self::sessionIsPersistent()) {
            $_SESSION[self::S_SEEN_AT] = time();
            return ['state' => 'ok', 'user' => $user, 'retry' => 0];
        }

        $limits = self::authLimits($auth);
        $now = time();
        $loginAt = (int) ($_SESSION[self::S_LOGIN_AT] ?? 0);
        $seenAt  = (int) ($_SESSION[self::S_SEEN_AT] ?? 0);

        if ($loginAt <= 0 || $now - $loginAt > $limits['absolute']) {
            self::sessionSignOut();
            return ['state' => 'absolute', 'user' => '', 'retry' => 0];
        }
        if ($seenAt <= 0 || $now - $seenAt > $limits['idle']) {
            self::sessionSignOut();
            return ['state' => 'idle', 'user' => '', 'retry' => 0];
        }

        $_SESSION[self::S_SEEN_AT] = $now;
        return ['state' => 'ok', 'user' => $user, 'retry' => 0];
    }

    /**
     * Try the "stay signed in" cookie, and sign the operator in when it checks out.
     *
     * THE RATE LIMITER AND THE LOCKOUT APPLY HERE TOO, and that is not decoration. Without it
     * this path would be a second front door with no counter on it: an attacker holding a
     * cookie of unknown freshness, or fishing for a selector, would get unlimited attempts at
     * a credential while the password form next to it allowed eight. The gate is consulted
     * before the token is looked at, a failed verifier is recorded as a failed sign-in, and an
     * unreadable ledger refuses the attempt — the same three rules the password path follows.
     *
     * THEFT IS REPORTED AS AN ORDINARY REFUSAL. The operator is sent to the sign-in form, where
     * Panel\Login shows them what happened. Saying anything here would mean saying it to
     * whoever presented the cookie, which on the theory that it was stolen is the thief.
     *
     * THE TOKEN IS CHECKED AGAINST THE ACCOUNT THAT ACTUALLY EXISTS. A token naming a username
     * the config no longer has is destroyed rather than honoured, so renaming the account —
     * or any future change that makes an old identity meaningless — cannot be undone by a
     * cookie from before it.
     *
     * @param array<string,mixed> $auth
     * @param string[]            $trustedProxies
     * @return array{state:string,user:string,retry:int}
     */
    private static function resumeRemembered(array $auth, ?string $varDir, array $trustedProxies): array
    {
        if (!Persistence::present()) {
            return ['state' => 'login', 'user' => '', 'retry' => 0];
        }

        $ip = self::clientIp($trustedProxies);
        $gate = self::loginGate($ip, $auth, $varDir);

        if (!$gate['available']) {
            return ['state' => 'store', 'user' => '', 'retry' => 0];
        }
        if (!$gate['allowed']) {
            return ['state' => 'locked', 'user' => '', 'retry' => $gate['retry']];
        }

        $result = Persistence::consume($varDir, Persistence::lifetime($auth));

        if ($result['state'] === 'theft') {
            self::loginFailure($ip, $auth, $varDir);
            return ['state' => 'login', 'user' => '', 'retry' => 0];
        }
        if ($result['state'] !== 'ok' || $result['user'] === '') {
            return ['state' => 'login', 'user' => '', 'retry' => 0];
        }
        if (!self::equals((string) ($auth['user'] ?? ''), $result['user'])) {
            Persistence::revokeAll($varDir);
            return ['state' => 'login', 'user' => '', 'retry' => 0];
        }

        self::sessionSignIn($result['user'], true);
        self::$resumedFromToken = true;

        if ($gate['count'] > 0) {
            self::loginSuccess($ip, $auth, $varDir);
        }

        return ['state' => 'ok', 'user' => $result['user'], 'retry' => 0];
    }

    /**
     * Authenticate a panel request, or answer it with the refusal and stop.
     *
     * Supports HTTP Basic (simple, works behind any proxy, easy to script against) and the
     * session/form mode (a real sign-in page and a real sign-out). Fails closed: when no
     * auth is configured at all the panel refuses to serve rather than exposing traffic
     * data to the internet, because an analytics dashboard left open is a data breach and
     * defaults decide outcomes.
     *
     * The front controller sends an installation that has no credentials to the browser
     * installer before this is ever reached, so the 'setup' branch is a backstop for any
     * other caller rather than something an operator is expected to see.
     *
     * A refused session-mode request is REDIRECTED to the sign-in page, not answered with
     * a bare 403. The 403 was a dead end: an operator who configured session mode had no
     * route back into their own panel. The one exception is a `?api=` request, which is a
     * fetch() from an already-loaded page — that gets 401 JSON, because redirecting an
     * XHR to an HTML login form produces a confusing parse error instead of a clear
     * "sign in again".
     *
     * @param array<string,mixed> $auth           The 'auth' section of the config.
     * @param string|null         $varDir         Where the attempt ledger lives; null = the app's own var/.
     * @param string[]            $trustedProxies CIDRs whose X-Forwarded-For may be believed.
     */
    public static function requireAuth(array $auth, ?string $varDir = null, array $trustedProxies = []): void
    {
        $result = self::authenticate($auth, $varDir, $trustedProxies);
        $state = $result['state'];

        if ($state === 'ok') {
            return;
        }

        if ($state === 'setup') {
            http_response_code(503);
            header('Content-Type: text/plain; charset=utf-8');
            exit(
                "Loghound has not finished being set up, so it has no way to sign you in.\n" .
                "Open this site in a browser to finish setup, or run this on the server:\n" .
                '  ' . dirname(__DIR__) . "/bin/loghound-setup\n"
            );
        }

        if ($state === 'locked') {
            $minutes = max(1, (int) ceil($result['retry'] / 60));
            http_response_code(429);
            header('Retry-After: ' . max(1, $result['retry']));
            header('Content-Type: text/plain; charset=utf-8');
            /* THE ABSOLUTE PATH IS LOGGED, NOT PRINTED. This response is reachable with no
               credentials at all — eight wrong passwords — and it used to hand an anonymous
               prober the deployment root, the directory layout and whether the install is a
               symlinked deploy. That is reconnaissance that turns a later file-handling bug
               into an exploit. The operator, who can read the error log, still gets the path. */
            error_log('Loghound: sign-in lockout in force; clear it by deleting ' . self::ledgerPath($varDir));
            exit(
                "Too many failed sign-in attempts from your address.\n" .
                'Try again in ' . $minutes . " minute(s).\n" .
                'To clear it now, delete var/' . self::LOGIN_LEDGER . " inside your Loghound\n" .
                "installation; the server error log names its full path.\n"
            );
        }

        if ($state === 'store') {
            http_response_code(503);
            header('Content-Type: text/plain; charset=utf-8');
            error_log(
                'Loghound: cannot write the sign-in attempt ledger in '
                . dirname(self::ledgerPath($varDir)) . '; refusing every sign-in until it is writable.'
            );
            exit(
                "Loghound cannot record failed sign-in attempts, because it cannot write to its\n" .
                "var/ directory. It refuses to sign anyone in rather than skip the check. Give that\n" .
                "directory to the user this panel runs as; the server error log names it.\n"
            );
        }

        if ($state === 'basic') {
            header('WWW-Authenticate: Basic realm="Loghound"');
            http_response_code(401);
            header('Content-Type: text/plain; charset=utf-8');
            exit("Authentication required\n");
        }

        if ($state === 'login' || $state === 'idle' || $state === 'absolute') {
            $api = $_GET['api'] ?? null;
            if (is_string($api) && $api !== '') {
                http_response_code(401);
                header('Content-Type: application/json; charset=utf-8');
                exit((string) json_encode(['error' => 'Your session has ended. Reload the page to sign in again.']));
            }
            $why = $state === 'login' ? '' : '&why=' . rawurlencode($state);
            header('Location: ?login=1' . $why, true, 302);
            exit;
        }

        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        exit("Unknown auth mode\n");
    }

    /**
     * Where the failed-attempt ledger lives.
     *
     * Null means the application's own var/, worked out from this file's location. The
     * parameter exists so a caller can point it somewhere else — the front controller
     * passes the install prefix explicitly, and the tests give each case its own
     * directory — never so that the limiter can be turned off: there is no value of
     * $varDir that means "do not count".
     */
    public static function ledgerPath(?string $varDir = null): string
    {
        $dir = ($varDir !== null && $varDir !== '') ? rtrim($varDir, '/') : dirname(__DIR__) . '/var';
        return $dir . '/' . self::LOGIN_LEDGER;
    }

    /**
     * May this address try to sign in?
     *
     * PER ADDRESS, AND ONLY PER ADDRESS. There is deliberately no global cap here, and
     * that is the difference between this limiter and the setup token's. A global counter
     * on a login form is a denial-of-service primitive handed to anyone who can reach it:
     * a few thousand wrong passwords from a botnet would trip it, and the legitimate
     * operator — whose password is correct and whose address has zero failures — would be
     * locked out of their own panel for as long as the attacker cared to keep going. Per
     * address, an attacker can only ever lock out the address they are attacking from.
     * Setup\Token makes the opposite trade on purpose: it guards a one-time,
     * takeover-shaped window where refusing everybody is the safer failure.
     *
     * Each address gets its OWN window rather than sharing one global window, so an
     * attacker's traffic can neither reset nor extend the operator's counter.
     *
     * `available` false means the ledger could not be opened or locked. Callers must treat
     * that as a refusal — a check that cannot be performed is a failed check.
     *
     * @param array<string,mixed> $auth
     * @return array{allowed:bool,available:bool,retry:int,count:int}
     */
    public static function loginGate(string $ip, array $auth, ?string $varDir = null): array
    {
        $limits = self::authLimits($auth);
        $entry = self::attempts($varDir, self::ipKey($ip), $limits['window'], 'read');

        if ($entry === null) {
            return ['allowed' => false, 'available' => false, 'retry' => 0, 'count' => 0];
        }

        $count = $entry['n'];
        if ($count < $limits['attempts']) {
            return ['allowed' => true, 'available' => true, 'retry' => 0, 'count' => $count];
        }

        $retry = max(1, $entry['w'] + $limits['window'] - time());
        return ['allowed' => false, 'available' => true, 'retry' => $retry, 'count' => $count];
    }

    /**
     * Record one failed sign-in attempt for an address.
     *
     * @param array<string,mixed> $auth
     */
    public static function loginFailure(string $ip, array $auth, ?string $varDir = null): void
    {
        $limits = self::authLimits($auth);
        self::attempts($varDir, self::ipKey($ip), $limits['window'], 'add');
    }

    /**
     * Forget an address's failures after it proves it knows the password.
     *
     * Without this, an operator who mistypes their password four times and then gets it
     * right would still be four attempts from a lockout for the rest of the window.
     *
     * Callers skip it when the address has no failures recorded, which is the normal case:
     * Basic mode re-authenticates on every single request, and rewriting the ledger under a
     * lock on each of them would put a file write in front of every page for nothing.
     *
     * @param array<string,mixed> $auth
     */
    public static function loginSuccess(string $ip, array $auth, ?string $varDir = null): void
    {
        $limits = self::authLimits($auth);
        self::attempts($varDir, self::ipKey($ip), $limits['window'], 'clear');
    }

    /**
     * The ledger key for an address.
     *
     * Hashed, because var/ is readable by the service user and a plain list of the
     * addresses that failed to sign in is a small piece of intelligence about who is
     * being watched and from where. An empty REMOTE_ADDR (a CLI caller, a broken SAPI)
     * gets one shared bucket rather than an exemption.
     */
    private static function ipKey(string $ip): string
    {
        return $ip === '' ? 'unknown' : hash('sha256', $ip);
    }

    /**
     * Read or update one address's entry in the fixed-window ledger.
     *
     * The same shape as Setup\Token's limiter — a JSON file under an exclusive flock, a
     * fixed window, small human-scaled numbers — with one difference: the window is per
     * address rather than global, so one client cannot move another client's window.
     *
     * Entries whose window has expired are dropped on every write, which keeps the file
     * proportional to the number of addresses currently failing rather than to the number
     * that ever have. The hard cap is a backstop for a flood from many addresses at once;
     * evicting entries can only ever forgive attempts, never invent them.
     *
     * Returns null when the ledger cannot be opened or locked, which every caller must
     * treat as a refusal.
     *
     * @param string $op 'read', 'add' or 'clear'
     * @return array{n:int,w:int}|null
     */
    private static function attempts(?string $varDir, string $key, int $window, string $op): ?array
    {
        $file = self::ledgerPath($varDir);
        $dir  = dirname($file);

        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            return null;
        }

        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return null;
        }
        @chmod($file, 0600);

        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            return null;
        }

        $now = time();
        $raw = (string) stream_get_contents($fh);
        $data = json_decode($raw, true);
        $ips = (is_array($data) && isset($data['ips']) && is_array($data['ips'])) ? $data['ips'] : [];

        $entry = is_array($ips[$key] ?? null) ? $ips[$key] : ['n' => 0, 'w' => $now];
        $entry = ['n' => (int) ($entry['n'] ?? 0), 'w' => (int) ($entry['w'] ?? 0)];

        if ($entry['w'] + $window < $now) {
            $entry = ['n' => 0, 'w' => $now];
        }

        if ($op === 'add') {
            $entry['n']++;
            $ips[$key] = $entry;
        } elseif ($op === 'clear') {
            unset($ips[$key]);
            $entry = ['n' => 0, 'w' => $now];
        }

        if ($op !== 'read') {
            foreach ($ips as $k => $v) {
                if (!is_array($v) || (int) ($v['w'] ?? 0) + $window < $now) {
                    unset($ips[$k]);
                }
            }
            if (count($ips) > 500) {
                $ips = array_slice($ips, -200, null, true);
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) json_encode(['ips' => $ips]));
            fflush($fh);
        }

        flock($fh, LOCK_UN);
        fclose($fh);

        return $entry;
    }

    /**
     * Emit the panel's security response headers.
     *
     * The CSP is deliberately strict and the panel is written to live within it: no inline
     * event handlers, no eval, no third-party origins. ECharts is served from our own
     * assets directory precisely so this policy can stay closed.
     *
     * THE ONE INLINE SCRIPT IS THE IMPORT MAP, and it is admitted by hash rather than by
     * loosening anything. Assets::importMap() is what versions the panel's ES module graph —
     * see that file for why an unversioned `import './core.js'` is a release that half-lands —
     * and an import map has no interoperable external form, so it must be inline. A
     * `'sha256-…'` source expression permits exactly that one generated string: 'unsafe-inline'
     * is never introduced, and a tampered or mistyped map is refused rather than run.
     *
     * The hash is emitted on every response, including the ones that carry no import map. It
     * costs a header token and it removes the failure this whole mechanism exists to prevent —
     * a shell that emits a map, forgets to ask for the hash, and silently goes back to serving
     * a year-old module graph with no error anywhere to say so.
     *
     * $root IS THE SAME TREE THE SHELL WILL EMIT THE MAP FROM, and it has to be, because a hash
     * taken over a DIFFERENT tree's map matches nothing: the browser refuses the map outright,
     * resolves every bare specifier as before, and the graph goes stale — silently, with the
     * policy header looking entirely correct. The installer serves its own responses and
     * carries its own root, so it passes it; the panel's root and this class's are the same
     * directory, so it does not have to.
     */
    public static function sendSecurityHeaders(?string $root = null): void
    {
        header('Content-Security-Policy: '
            . "default-src 'self'; script-src 'self' " . Assets::importMapCspHash($root) . '; '
            . "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            . "connect-src 'self'; font-src 'self'; object-src 'none'; "
            . "base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: same-origin');
        header('X-Frame-Options: DENY');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), interest-cohort=()');
    }

    /**
     * Write a file that is never readable by anyone but its owner's group, at any instant.
     *
     * THE ORDERING IS THE WHOLE POINT. `file_put_contents()` creates with `0666 & ~umask` —
     * 0644 on a default umask, 0666 on an FPM pool that sets none — and the ENTIRE payload is
     * on disk before a following chmod() narrows it. Both call sites that used that shape write
     * operator data: `var/detect.json` holds up to five raw sample log lines per source, which
     * is full request paths, query strings, User-Agents and client addresses, and
     * `var/schema-check.json` holds control-plane messages. On a shared host the race is won by
     * spinning on open().
     *
     * So: a fresh temp name opened with `x` (O_CREAT|O_EXCL, which no symlink can satisfy),
     * chmod BEFORE the first byte, then an atomic rename over the target. Config::save() and
     * Setup\Token::ensure() already write this way; these two did not.
     *
     * @return bool Whether the file is now on disk with the intended contents.
     */
    public static function writePrivateFile(string $path, string $contents, int $mode = 0640): bool
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            return false;
        }

        $tmp = $dir . '/.' . basename($path) . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $fh = @fopen($tmp, 'xb');
        if ($fh === false) {
            return false;
        }
        @chmod($tmp, $mode);

        $written = fwrite($fh, $contents);
        fflush($fh);
        fclose($fh);

        if ($written === false || $written !== strlen($contents) || !@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        @chmod($path, $mode);
        return true;
    }

    /**
     * Does this hostname resolve to somewhere on the public internet, and only there?
     *
     * THE CHECK THAT DECIDES WHERE A CREDENTIAL IS SENT. Two configuration values name an
     * outbound host that receives the Opensolr account email and API key on every call —
     * `opensolr.api_base` and `enrich.geo_endpoint` — and neither was checked at all.
     * `https://127.0.0.1/…`, `https://[::1]/…`, `https://169.254.169.254/…` or any internal
     * name was accepted, which is a credential-exfiltration and cloud-metadata primitive out
     * of one config line.
     *
     * THREE REFUSALS, CHEAPEST FIRST, AND ONE HONEST LIMIT.
     *
     *   1. A literal address must be public. This is the attack shape that matters and it
     *      needs no resolver: loopback, link-local, and every reserved range are refused.
     *   2. A name that cannot BE public is refused on its spelling: `localhost`, any
     *      single-label name, and the reserved local suffixes.
     *   3. When a resolver answers, EVERY address it returns must be public — not merely the
     *      first, because a name with one public and one loopback record would otherwise
     *      connect to whichever the resolver handed curl. The verdict is memoised, so this
     *      costs one lookup per host for the life of the process.
     *
     * THE LIMIT, STATED RATHER THAN GLOSSED: when no resolver answers — an air-gapped box, the
     * test suite, a name that does not exist — step 3 cannot run and the name is allowed through
     * on the strength of steps 1 and 2. Refusing instead would make an offline installation fail
     * closed on a value that is read from a file only the operator writes.
     *
     * Redirects cannot reintroduce any of this: Solr::curlTransport sets CURLOPT_FOLLOWLOCATION
     * to false and pins CURLOPT_PROTOCOLS, so there is no per-hop revalidation to do.
     */
    public static function hostIsPublic(string $host): bool
    {
        static $memo = [];

        $host = strtolower(trim($host, " \t[]"));
        if ($host === '' || strlen($host) > 253) {
            return false;
        }
        if (isset($memo[$host])) {
            return $memo[$host];
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $memo[$host] = (filter_var(
                $host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) !== false);
        }

        if (!preg_match('/^[a-z0-9]([a-z0-9\-._]{0,251}[a-z0-9])?$/D', $host)) {
            return $memo[$host] = false;
        }
        if (!str_contains($host, '.')) {
            return $memo[$host] = false;
        }
        foreach (['.localhost', '.local', '.internal', '.intranet', '.home.arpa'] as $suffix) {
            if (str_ends_with($host, $suffix)) {
                return $memo[$host] = false;
            }
        }

        foreach ([DNS_A, DNS_AAAA] as $type) {
            $records = @dns_get_record($host, $type);
            foreach (is_array($records) ? $records : [] as $record) {
                $value = (string) ($record['ip'] ?? ($record['ipv6'] ?? ''));
                if ($value !== '' && filter_var(
                    $value,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                ) === false) {
                    return $memo[$host] = false;
                }
            }
        }

        return $memo[$host] = true;
    }

    /**
     * Is this an https URL pointing at a public host, with no credentials of its own?
     *
     * The shape every outbound base URL in this project has to have. Returns the trimmed URL
     * or null, so a caller can fail closed in one line.
     */
    public static function safeOutboundUrl(string $url): ?string
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > 2048) {
            return null;
        }
        if (preg_match('/[\x00-\x20\x7F"\'<>]/', $url)) {
            return null;
        }

        $parts = parse_url($url);
        if (!is_array($parts)) {
            return null;
        }
        if (strtolower((string) ($parts['scheme'] ?? '')) !== 'https') {
            return null;
        }
        $host = (string) ($parts['host'] ?? '');
        if ($host === '' || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }
        return self::hostIsPublic($host) ? $url : null;
    }

    /**
     * Did this request really arrive over TLS?
     *
     * TWO WAYS THE OLD EXPRESSION — `($_SERVER['HTTPS'] ?? '') !== ''` — WAS WRONG, and both
     * of them decide whether a bearer credential is marked `Secure`.
     *
     *   It said NO on a request that was HTTPS. This project supports reverse-proxied
     *   deployments and honours `X-Forwarded-For` from `trusted_proxies`, but nothing read
     *   `X-Forwarded-Proto`. With TLS terminating at a load balancer or Cloudflare and the
     *   origin listening on plain HTTP, `$_SERVER['HTTPS']` is unset — so the ten-year
     *   "stay signed in" token, which grants a full panel session with no timeout, was issued
     *   WITHOUT `Secure` and would travel in cleartext on any `http://` request to the same
     *   host that an attacker could induce.
     *
     *   It said YES on a request that was not. Under IIS and some SAPIs `$_SERVER['HTTPS']`
     *   is the literal string `'off'` over plain HTTP, and `'off' !== ''`. The cookie then
     *   carries `Secure` on a plain-HTTP install, the browser never sends it back, and the
     *   feature silently does not work.
     *
     * The forwarded header is believed ONLY when the immediate peer is a proxy the operator
     * configured, on exactly the reasoning clientIp() uses: otherwise any visitor could assert
     * `X-Forwarded-Proto: https` and change how a cookie is marked.
     *
     * @param string[] $trustedProxies CIDRs whose forwarded headers may be believed.
     */
    public static function isHttps(array $trustedProxies = []): bool
    {
        $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
        if ($https !== '' && $https !== 'off' && $https !== '0') {
            return true;
        }
        if ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443) {
            return true;
        }

        $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        if ($remote === '' || !self::ipInAny($remote, $trustedProxies)) {
            return false;
        }

        $proto = strtolower(trim((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
        if ($proto !== '') {
            $first = trim((string) (explode(',', $proto)[0] ?? ''));
            return $first === 'https';
        }

        $ssl = strtolower((string) ($_SERVER['HTTP_X_FORWARDED_SSL'] ?? ''));
        return $ssl === 'on';
    }

    /**
     * Read the true client IP for the current request.
     *
     * X-Forwarded-For is attacker-controlled unless the immediate peer is a proxy we
     * placed there ourselves, so it is honoured only when REMOTE_ADDR is in the operator's
     * configured trusted-proxy list, and even then only the right-most untrusted hop is
     * taken. Getting this wrong lets any visitor forge their own source address.
     *
     * @param string[] $trustedProxies CIDR strings.
     */
    public static function clientIp(array $trustedProxies = []): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($remote === '' || !self::ipInAny($remote, $trustedProxies)) {
            return $remote;
        }
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff === '') {
            return $remote;
        }
        $hops = array_map('trim', explode(',', $xff));
        for ($i = count($hops) - 1; $i >= 0; $i--) {
            $hop = $hops[$i];
            if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
                return $remote;
            }
            if (!self::ipInAny($hop, $trustedProxies)) {
                return $hop;
            }
        }
        return $remote;
    }

    /**
     * Test whether an IP falls inside any of the supplied CIDR ranges.
     *
     * @param string[] $cidrs
     */
    public static function ipInAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::ipInCidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Test whether an IP falls inside a single CIDR range (v4 and v6).
     */
    public static function ipInCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipBin = @inet_pton($ip);
        $subBin = @inet_pton($subnet);
        if ($ipBin === false || $subBin === false || strlen($ipBin) !== strlen($subBin)) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($bytes > 0 && strncmp($ipBin, $subBin, $bytes) !== 0) {
            return false;
        }
        if ($rem === 0) {
            return true;
        }
        $mask = chr((0xFF << (8 - $rem)) & 0xFF);
        return (($ipBin[$bytes] & $mask) === ($subBin[$bytes] & $mask));
    }

    /**
     * Apply the configured privacy transform to an IP before it is stored.
     *
     * 'full'     keeps the address as-is (self-hosted default; the operator already has
     *            the raw address in their own logs).
     * 'truncate' zeroes the host portion — /24 for v4, /48 for v6 — which keeps network
     *            level analysis working while dropping the identifier.
     * 'hash'     replaces it with a keyed hash rotated daily, so cross-day correlation of
     *            an individual becomes impossible while same-day sessionisation still works.
     */
    public static function applyIpPrivacy(string $ip, string $mode, string $salt): string
    {
        if ($mode === 'full') {
            return $ip;
        }
        if ($mode === 'hash') {
            return substr(hash_hmac('sha256', $ip, $salt . gmdate('Y-m-d')), 0, 24);
        }
        if ($mode === 'truncate') {
            return self::ipNetwork($ip, 24, 48);
        }
        return $ip;
    }

    /**
     * Reduce an IP to its network prefix.
     *
     * Also used outside privacy mode to build `ip_net_s`, the clustering key that groups a
     * rotating-proxy fleet's exits when they share a netblock.
     */
    public static function ipNetwork(string $ip, int $v4bits = 24, int $v6bits = 48): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return $ip;
        }
        $isV6 = strlen($bin) === 16;
        $bits = $isV6 ? $v6bits : $v4bits;

        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;
        $out   = substr($bin, 0, $bytes);

        if ($rem > 0) {
            $mask = chr((0xFF << (8 - $rem)) & 0xFF);
            $out .= ($bin[$bytes] & $mask);
            $bytes++;
        }
        $out = str_pad($out, $isV6 ? 16 : 4, "\0");

        $addr = @inet_ntop($out);
        return ($addr === false ? $ip : $addr) . '/' . $bits;
    }
}
