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
     * Validate a URL for use in an href/src attribute.
     *
     * Referer values come straight from the wire and routinely contain javascript:,
     * data: and vbscript: payloads. Anything that is not plainly http(s) returns '#'
     * rather than being rendered as a live link. Control characters and whitespace are
     * refused along with them, because either can split a header or break out of an
     * attribute.
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
     * Test a user-supplied regex for safety and usability before it is ever stored.
     *
     * A custom log pattern is untrusted code. Two failure modes matter: a pattern that
     * does not compile (caught by the @preg_match probe) and a pattern that backtracks
     * catastrophically, which would wedge the ingest daemon permanently. The probe runs
     * the pattern against a subject engineered to expose nested quantifier blowup, under a
     * low backtrack limit, and measures elapsed time; anything slow or failing is refused
     * at save time, which is the only moment a human is present to fix it.
     *
     * The shape of the pattern is checked before any of that. The /e modifier is long
     * gone from PHP, but a modifier block we do not explicitly expect is refused anyway
     * rather than passed to PCRE to see what happens.
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
     * Authenticate a panel request.
     *
     * Supports HTTP Basic (simple, works behind any proxy, easy to script against) and a
     * form/session mode. Fails closed: when no auth is configured at all the panel refuses
     * to serve rather than exposing traffic data to the internet, because an analytics
     * dashboard left open is a data breach and defaults decide outcomes.
     *
     * The front controller sends an installation that has no credentials to the browser
     * installer before this is ever reached, so the 'none' branch below is a backstop for
     * any other caller rather than something an operator is expected to see.
     *
     * The username is compared in constant time as well as the password, so that valid
     * account names cannot be enumerated by timing. A failed attempt then sleeps for a
     * randomised fraction of a second, which blunts online guessing without needing a
     * lockout system that an attacker could trip deliberately to deny the operator access.
     *
     * @param array $cfg The 'auth' section of the config.
     */
    public static function requireAuth(array $cfg): void
    {
        $mode = $cfg['mode'] ?? 'none';

        if ($mode === 'none') {
            http_response_code(503);
            header('Content-Type: text/plain; charset=utf-8');
            exit(
                "Loghound has not finished being set up, so it has no way to sign you in.\n" .
                "Open this site in a browser to finish setup, or run bin/loghound-setup on the server.\n"
            );
        }

        if ($mode === 'basic') {
            $user = $_SERVER['PHP_AUTH_USER'] ?? '';
            $pass = $_SERVER['PHP_AUTH_PW'] ?? '';
            $okUser = (string) ($cfg['user'] ?? '');
            $hash   = (string) ($cfg['password_hash'] ?? '');

            $userOk = self::equals($okUser, $user);
            $passOk = $hash !== '' && password_verify($pass, $hash);

            if (!$userOk || !$passOk) {
                usleep(random_int(150000, 400000));
                header('WWW-Authenticate: Basic realm="Loghound"');
                http_response_code(401);
                exit("Authentication required\n");
            }
            return;
        }

        if ($mode === 'session') {
            if (session_status() !== PHP_SESSION_ACTIVE) {
                session_start();
            }
            if (empty($_SESSION['lh_user'])) {
                http_response_code(403);
                exit("Not signed in\n");
            }
            return;
        }

        http_response_code(500);
        exit("Unknown auth mode\n");
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
