<?php
/**
 * Loghound — the failure artefact.
 *
 * WHAT THIS IS FOR. When something breaks, the operator should be able to select one block,
 * paste it into a forum post or an issue, and have somebody else diagnose it without a
 * conversation. So a failure in this product is a deliberate artefact rather than an escaped
 * stack trace: it names what was being attempted in the product's own words, which step died,
 * the complete underlying error including whatever the platform or the system returned, and
 * enough context to reproduce — release, PHP, operating system, web server, which front end,
 * which index or file.
 *
 * ---------------------------------------------------------------------------------------
 * IT IS DESIGNED TO BE PASTED IN PUBLIC, SO REDACTION IS THE HARD REQUIREMENT
 * ---------------------------------------------------------------------------------------
 * Gathering everything into one place creates a new sink, and a sink is where secrets leak.
 * The Opensolr API key, the beacon signing key, the address salt, the panel password hash,
 * the index HTTP auth password and any session token must never appear in a block, whichever
 * layer produced the message.
 *
 * Two passes, because either alone is insufficient:
 *
 *   1. SHAPE. `api_key=…`, `secret=…`, `https://user:pass@host` and the rest of the
 *      credential-shaped parameter names, the same set Panel\Jobs::redact() and
 *      Opensolr::redact() already use. This catches a secret that belongs to somebody else —
 *      a key the operator pasted into the wrong field, a URL echoed back by a proxy.
 *   2. VALUE. Every secret THIS installation actually holds, replaced by name. This catches
 *      the same key when it arrives without a label: quoted bare in a platform message,
 *      embedded in a path, or spelled in a way no pattern anticipated.
 *
 * REDACTION HAPPENS HERE, AT THE SINK, AND NEVER WHERE A VALUE IS READ. That distinction is
 * load bearing on this platform: Opensolr sets a new index's HTTP auth password TO THE ACCOUNT
 * API KEY, so an earlier attempt that scrubbed API-key-shaped strings out of control-plane
 * RESPONSES replaced the credential Loghound needs with a marker, and every authenticated
 * query afterwards failed 401. tests/test_secret_boundaries.php pins that: a response carries
 * its values through intact, and containment belongs to each place a value is SHOWN. This
 * class is such a place. Nothing consumes a block as a credential, so redacting here cannot
 * break authentication, and not redacting here publishes the account key.
 *
 * VALUE REDACTION HAS A LENGTH FLOOR. A configured "secret" of two characters would otherwise
 * shred every message that happened to contain those two characters, which turns a diagnostic
 * into noise. Anything shorter than MIN_SECRET is left to the shape pass.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

use Loghound\Auth\Persistence;

final class Diagnostics
{
    /** Longest any single field may be before it is cut. A report is for reading. */
    public const MAX_FIELD = 1200;

    /** Longest a row label may be. Short, because every other label is padded to match it. */
    public const MAX_LABEL = 60;

    /**
     * Shortest configured secret that is worth replacing by value.
     *
     * Every real secret in this product is far longer: an Opensolr API key, a 64-character
     * beacon key, a 32-character salt, a bcrypt hash. The floor exists so a misconfigured or
     * placeholder value cannot turn redaction into a find-and-replace over ordinary prose.
     */
    private const MIN_SECRET = 8;

    /**
     * The configuration keys that hold a secret, each with the marker it becomes.
     *
     * EXHAUSTIVE BY CONSTRUCTION, not by memory: this is the same list config/loghound.php is
     * described by in install/install.sh's shred step, and the same list Setup\Reset keeps or
     * clears. `solr.http_pass` is on it even though it equals the API key on a managed install
     * — it does not on a custom Solr, and a list that relies on the two being equal is a list
     * that leaks the day somebody changes it.
     *
     * `opensolr.email` is not a secret and is here anyway. It is the account's identity and it
     * travels beside the key in every control-plane request, so a message echoed back by the
     * platform can carry it; a block designed to be pasted in public has no business naming
     * whose account this is.
     *
     * @var array<string,string>
     */
    private const SECRET_KEYS = [
        'opensolr.api_key'   => '[opensolr api key redacted]',
        'opensolr.email'     => '[account email redacted]',
        'beacon.secret'      => '[beacon signing key redacted]',
        'privacy.ip_salt'    => '[address salt redacted]',
        'auth.password_hash' => '[password hash redacted]',
        'solr.http_pass'     => '[index password redacted]',
        /* THE SECOND FACTOR IS A SECRET AND WAS NOT ON THIS LIST. Anyone who reads the Base32
           seed can mint the operator's codes forever, which makes it worth more than the
           password hash directly above it. It reached a published block whenever a message
           quoted it without an `api_key=`-shaped label — "code rejected for SEED" — because
           the shape pass has nothing to match on and the value pass did not know it. */
        'auth.totp.secret'   => '[two-factor seed redacted]',
    ];

    /**
     * Configuration keys holding a LIST of secrets rather than one.
     *
     * Separate because secretValues() type-checks for a string, so an array-valued key put on
     * SECRET_KEYS would be skipped in silence — present on the list, doing nothing, and
     * reading as covered. The recovery codes are stored as hashes, which is not a reason to
     * publish them: a hash of a ten-character code is a target, not a protection.
     *
     * @var array<string,string>
     */
    private const SECRET_LIST_KEYS = [
        'auth.totp.recovery' => '[recovery code redacted]',
    ];

    /**
     * The release this tree is.
     *
     * `LOGHOUND` is defined by src/autoload.php and is already the one version string in the
     * product, so it is read rather than duplicated and a bump has one place to happen. A
     * method rather than a class constant because a constant expression naming an undefined
     * constant is a fatal at class-load time, and this class has to be loadable on the one
     * path where things are already broken.
     */
    public static function release(): string
    {
        return defined('LOGHOUND') ? (string) constant('LOGHOUND') : 'unknown';
    }

    /**
     * Build a report.
     *
     * `$facts` is ordered context the caller knows and this class cannot: which index, which
     * file, which account. Its keys are labels and its values are redacted like everything
     * else, because the caller may well be passing a URL it got from the platform.
     *
     * A Throwable contributes its class and the file and line it was raised at, which is the
     * part of a stack trace worth publishing; the frames themselves are not included, because
     * they carry argument values and this artefact is public by design.
     *
     * @param string             $doing What was being attempted, in the product's own words.
     * @param string             $step  The step that died.
     * @param \Throwable|string  $error The complete underlying error.
     * @param array<string,string> $facts
     * @return array<string,mixed>
     */
    public static function capture(
        string $doing,
        string $step,
        $error,
        array $facts = [],
        ?Config $cfg = null,
        ?string $root = null
    ): array {
        $message = $error instanceof \Throwable ? $error->getMessage() : (string) $error;

        $where = '';
        $class = '';
        if ($error instanceof \Throwable) {
            $class = get_class($error);
            $where = self::relative((string) $error->getFile(), $root) . ':' . $error->getLine();
        }

        /* A LABEL IS PUBLISHED EXACTLY AS LOUDLY AS A VALUE. Both halves of a fact come from
           the caller, and a caller building a label out of what failed — a URL, a parameter
           name, a filename it was handed — put whatever that was into the block untouched,
           because only the value side was ever redacted. */
        $clean = [];
        foreach ($facts as $label => $value) {
            if (!is_string($label) || $label === '') {
                continue;
            }
            $clean[self::label($label, $cfg)] = self::field((string) $value, $cfg);
        }

        return [
            'at'          => time(),
            'doing'       => self::field($doing, $cfg),
            'step'        => self::field($step, $cfg),
            'error'       => self::field($message, $cfg),
            'error_class' => self::field($class, $cfg),
            'raised_at'   => self::field($where, $cfg),
            'facts'       => $clean,
            'environment' => self::cleanPairs(self::environment($cfg), $cfg),
        ];
    }

    /**
     * Redact and cap both halves of a label/value map.
     *
     * @param array<string,string> $pairs
     * @return array<string,string>
     */
    public static function cleanPairs(array $pairs, ?Config $cfg = null): array
    {
        $out = [];
        foreach ($pairs as $label => $value) {
            $label = self::label((string) $label, $cfg);
            if ($label === '') {
                continue;
            }
            $out[$label] = self::field(is_scalar($value) ? (string) $value : '', $cfg);
        }

        return $out;
    }

    /**
     * Redact, flatten and hard-cap a row label.
     *
     * Capped far shorter than a value because block() pads every label to the width of the
     * longest one: an uncapped label does not merely appear in the report, it reformats the
     * whole of it, and one long enough turns a readable artefact into a single unwrappable
     * line nobody can paste anywhere.
     */
    private static function label(string $label, ?Config $cfg): string
    {
        $label = self::oneLine(self::redact($label, $cfg));

        return strlen($label) > self::MAX_LABEL
            ? substr($label, 0, self::MAX_LABEL) . '…'
            : $label;
    }

    /**
     * The environment half of the context, gathered once per report.
     *
     * Every value here is read from the running process rather than from configuration, so a
     * report describes the machine the failure happened on and not what somebody wrote down.
     * `ui.timezone` is deliberately absent: the timestamps in a block are UTC and say so.
     *
     * @return array<string,string>
     */
    public static function environment(?Config $cfg = null): array
    {
        $server = $_SERVER['SERVER_SOFTWARE'] ?? '';
        $server = is_string($server) && $server !== '' ? $server : 'not reported';

        $env = [
            'Loghound'         => self::release(),
            'PHP'              => PHP_VERSION . ' (' . PHP_SAPI . ')',
            'Operating system' => php_uname('s') . ' ' . php_uname('r'),
            'Web server'       => PHP_SAPI === 'cli' ? 'none (command line)' : $server,
            'Front end'        => PHP_SAPI === 'cli' ? 'terminal' : 'browser panel',
        ];

        if ($cfg !== null) {
            $mode = (string) $cfg->get('solr.mode', '');
            $env['Solr mode'] = $mode === '' ? 'unset' : $mode;
        }

        return $env;
    }

    /**
     * Render a report as the one block an operator copies.
     *
     * Plain text, aligned on a colon, no colour and no box drawing: it has to survive being
     * pasted into a forum, an issue tracker and a terminal, and it has to be readable in a
     * narrow window. Timestamps are mm/dd/yyyy hh:mm:ss UTC, the format this product uses
     * everywhere a date is shown.
     *
     * @param array<string,mixed> $report
     */
    public static function block(array $report): string
    {
        $rows = [
            'What it was doing' => (string) ($report['doing'] ?? ''),
            'Where it failed'   => (string) ($report['step'] ?? ''),
            'Error'             => (string) ($report['error'] ?? ''),
        ];

        if ((string) ($report['error_class'] ?? '') !== '') {
            $rows['Error type'] = (string) $report['error_class'];
        }
        if ((string) ($report['raised_at'] ?? '') !== '') {
            $rows['Raised at'] = (string) $report['raised_at'];
        }

        $rows['When'] = gmdate('m/d/Y H:i:s', (int) ($report['at'] ?? time())) . ' UTC';

        /* THE LEDGER IS A FILE, SO A REPORT REACHING HERE IS UNTRUSTED INPUT. Labels are
           flattened and capped again on the way out rather than only on the way in, because
           this is the last point before the block is shown and a label is what sets the width
           of every row in it. */
        foreach ((array) ($report['facts'] ?? []) as $label => $value) {
            $rows[self::label((string) $label, null)] = is_scalar($value) ? (string) $value : '';
        }
        foreach ((array) ($report['environment'] ?? []) as $label => $value) {
            $rows[self::label((string) $label, null)] = is_scalar($value) ? (string) $value : '';
        }
        unset($rows['']);

        $width = 0;
        foreach (array_keys($rows) as $label) {
            $width = max($width, strlen((string) $label));
        }

        $out = ['Loghound problem report'];
        foreach ($rows as $label => $value) {
            $out[] = str_pad((string) $label, $width) . ' : ' . self::oneLine((string) $value);
        }

        return implode("\n", $out);
    }

    /**
     * Redact a string for publication.
     *
     * Public because every other sink that shows an error benefits from the same two passes,
     * and because the tests plant each secret in a failure path and assert this is what stops
     * it. Safe to call on text that has already been through it.
     */
    public static function redact(string $text, ?Config $cfg = null): string
    {
        $patterns = [
            '/(api[_-]?key|apikey|key|token|secret|password|passwd|pwd|salt|email)=([^&\s"\']*)/i'
                => '$1=[redacted]',
            '#(https?://)[^/@\s:]+:[^/@\s]+@#i' => '$1[redacted]@',
        ];
        foreach ($patterns as $pattern => $replacement) {
            $text = preg_replace($pattern, $replacement, $text) ?? $text;
        }

        foreach (self::secretValues($cfg) as $value => $marker) {
            $text = str_replace((string) $value, $marker, $text);
        }

        return $text;
    }

    /**
     * Every secret value this installation holds, mapped to the marker it becomes.
     *
     * The session id and the CSRF token are included alongside the configured secrets: both
     * are bearer credentials for the signed-in panel, both can reach an error message through
     * a URL or a cookie header a transport quoted back, and neither is in the configuration.
     *
     * @return array<string,string>
     */
    private static function secretValues(?Config $cfg): array
    {
        $out = [];

        if ($cfg !== null) {
            foreach (self::SECRET_KEYS as $key => $marker) {
                $value = $cfg->get($key, '');
                if (is_string($value) && strlen($value) >= self::MIN_SECRET) {
                    $out[$value] = $marker;
                }
            }

            foreach (self::SECRET_LIST_KEYS as $key => $marker) {
                foreach ((array) $cfg->get($key, []) as $value) {
                    if (is_string($value) && strlen($value) >= self::MIN_SECRET) {
                        $out[$value] = $marker;
                    }
                }
            }
        }

        if (PHP_SAPI !== 'cli' && session_status() === PHP_SESSION_ACTIVE) {
            $sid = session_id();
            if (is_string($sid) && strlen($sid) >= self::MIN_SECRET) {
                $out[$sid] = '[session id redacted]';
            }
            $csrf = $_SESSION['lh_csrf'] ?? null;
            if (is_string($csrf) && strlen($csrf) >= self::MIN_SECRET) {
                $out[$csrf] = '[session token redacted]';
            }
            $owner = $_SESSION['lh_job_owner'] ?? null;
            if (is_string($owner) && strlen($owner) >= self::MIN_SECRET) {
                $out[$owner] = '[session token redacted]';
            }
        }

        /* THE STAY-SIGNED-IN TOKEN IS A BEARER CREDENTIAL AND LIVES IN NO CONFIGURATION FILE.
           It is worth a signed-in panel for as long as it lasts, it arrives on every request
           as `lh_remember=selector:verifier`, and a transport or a proxy that quotes a request
           header back puts it straight into a message. Both halves are registered, because a
           message may carry the verifier on its own. */
        $remember = $_COOKIE[Persistence::COOKIE] ?? null;
        if (is_string($remember) && $remember !== '') {
            if (strlen($remember) >= self::MIN_SECRET) {
                $out[$remember] = '[stay signed in token redacted]';
            }
            foreach (explode(':', $remember) as $half) {
                if (strlen($half) >= self::MIN_SECRET) {
                    $out[$half] = '[stay signed in token redacted]';
                }
            }
        }

        /* THE CREDENTIAL'S OWN WIRE FORM. A secret does not only travel as itself: HTTP Basic
           sends `base64(user:pass)`, and that is how Loghound authenticates to Solr — where
           `solr.http_pass` IS the account API key on a managed installation. A proxy or a Solr
           error page that reflects the request's `Authorization` header therefore puts the
           account key into a message in a spelling no pattern matches and the literal pass
           does not see, and this block is designed to be pasted in public. Registering the
           encoded forms costs one pass over a handful of short strings.

           Built from the values already collected above, so a secret added to either list is
           covered in both spellings without a second place to remember. */
        foreach (array_keys($out) as $secret) {
            $encoded = base64_encode((string) $secret);
            if (strlen($encoded) >= self::MIN_SECRET) {
                $out[$encoded] = $out[$secret];
            }
        }

        if ($cfg !== null) {
            $user = (string) $cfg->get('solr.http_user', '');
            $pass = (string) $cfg->get('solr.http_pass', '');
            if ($user !== '' && strlen($pass) >= self::MIN_SECRET) {
                $out[base64_encode($user . ':' . $pass)] = '[index password redacted]';
            }
        }

        /* LONGEST FIRST. str_replace() runs in array order, so a short value that is a
           substring of a longer one would otherwise cut the longer one in half and leave the
           remainder of it in the block. */
        uksort($out, static fn ($a, $b): int => strlen((string) $b) <=> strlen((string) $a));

        return $out;
    }

    /**
     * Redact, flatten and cap one field.
     *
     * The cap is applied AFTER redaction, never before: cutting first can leave the tail of a
     * secret in the block with the pattern that would have matched it beyond the cut.
     */
    private static function field(string $value, ?Config $cfg): string
    {
        $value = self::redact($value, $cfg);
        if (strlen($value) > self::MAX_FIELD) {
            $value = substr($value, 0, self::MAX_FIELD) . '…';
        }

        return $value;
    }

    /** Flatten newlines so one row of the block is one line. */
    private static function oneLine(string $value): string
    {
        $flat = str_replace(["\r", "\n"], ' ', $value);

        return trim(preg_replace('/\s+/', ' ', $flat) ?? $flat);
    }

    /**
     * A source path relative to the install root.
     *
     * An absolute path is the operator's directory layout, which is nobody else's business and
     * is noise in a report that is going to be read by somebody on a different machine. The
     * repository-relative path is the part that identifies the code.
     */
    private static function relative(string $path, ?string $root): string
    {
        $base = rtrim($root ?? dirname(__DIR__), '/');
        if ($base !== '' && str_starts_with($path, $base . '/')) {
            return substr($path, strlen($base) + 1);
        }

        return basename($path);
    }
}
