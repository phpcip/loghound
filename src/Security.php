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

    /** Session key holding the signed-in operator's username. */
    private const S_USER = 'lh_user';

    /** Session key holding the instant the session was signed in (absolute timeout anchor). */
    private const S_LOGIN_AT = 'lh_login_at';

    /** Session key holding the instant of the last authenticated request (idle anchor). */
    private const S_SEEN_AT = 'lh_seen_at';

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
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
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
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $_SESSION['lh_csrf'] = bin2hex(random_bytes(32));
        return $_SESSION['lh_csrf'];
    }

    /**
     * Enforce a CSRF token on a state-changing request.
     *
     * Fails closed: any request that is not a GET/HEAD must present a matching token or
     * the process is terminated with 403 before the handler runs.
     */
    public static function requireCsrf(): void
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'GET' || $method === 'HEAD') {
            return;
        }
        $given = $_POST['csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
        if (!is_string($given) || !self::equals(self::csrfToken(), $given)) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            exit("CSRF token mismatch\n");
        }
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
        return (bool) preg_match('/^[A-Za-z0-9_]{1,64}$/', $field);
    }

    /**
     * Validate a Solr core / Opensolr index name.
     */
    public static function isSafeCoreName(string $core): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_]{1,64}$/', $core);
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
        if (!preg_match('/^([\/#~%|])(.*)\1([imsxuUAD]*)$/s', $pattern)) {
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
     * Resume an existing session without creating one.
     *
     * The panel is on the public internet and is crawled and probed constantly. Starting
     * a session for every anonymous request would write a session file per probe, so a
     * session is only started when the client actually presents one — a cookie, or an id
     * set explicitly by a caller such as the test harness. Anything else is simply "not
     * signed in", which is the same answer with none of the disk churn.
     */
    public static function sessionResume(): bool
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return true;
        }
        if (session_id() === '' && !isset($_COOKIE[session_name()])) {
            return false;
        }
        return session_start();
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
     */
    public static function sessionSignIn(string $user): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        session_regenerate_id(true);

        $now = time();
        $_SESSION[self::S_USER]     = $user;
        $_SESSION[self::S_LOGIN_AT] = $now;
        $_SESSION[self::S_SEEN_AT]  = $now;

        self::rotateCsrf();
    }

    /**
     * End a session on the server, not just in the browser.
     *
     * Clearing the cookie alone would leave a session file that is still valid to anyone
     * who kept the id, so the order is: empty the array, expire the cookie, then
     * session_destroy() to delete the server-side record. After this the old id is
     * worthless even when replayed.
     */
    public static function sessionSignOut(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            if (session_id() === '' && !isset($_COOKIE[session_name()])) {
                return;
            }
            session_start();
        }

        $_SESSION = [];

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

        session_destroy();
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
            return self::authenticateSession($auth);
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
     * @param array<string,mixed> $auth
     * @return array{state:string,user:string,retry:int}
     */
    private static function authenticateSession(array $auth): array
    {
        if (!self::sessionResume()) {
            return ['state' => 'login', 'user' => '', 'retry' => 0];
        }

        $user = self::sessionUser();
        if ($user === '') {
            return ['state' => 'login', 'user' => '', 'retry' => 0];
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
                "Open this site in a browser to finish setup, or run bin/loghound-setup on the server.\n"
            );
        }

        if ($state === 'locked') {
            $minutes = max(1, (int) ceil($result['retry'] / 60));
            http_response_code(429);
            header('Retry-After: ' . max(1, $result['retry']));
            header('Content-Type: text/plain; charset=utf-8');
            exit(
                "Too many failed sign-in attempts from your address.\n" .
                'Try again in ' . $minutes . " minute(s).\n" .
                'To clear it now, delete ' . self::ledgerPath($varDir) . " on the server.\n"
            );
        }

        if ($state === 'store') {
            http_response_code(503);
            header('Content-Type: text/plain; charset=utf-8');
            exit(
                "Loghound cannot record failed sign-in attempts, because it cannot write to\n" .
                dirname(self::ledgerPath($varDir)) . ". It refuses to sign anyone in rather than\n" .
                "skip the check. Give that directory to the user this panel runs as.\n"
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
     */
    public static function sendSecurityHeaders(): void
    {
        header("Content-Security-Policy: default-src 'self'; script-src 'self'; "
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
