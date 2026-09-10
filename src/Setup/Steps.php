<?php
/**
 * Loghound — the parts of setup that are not storage and not detection.
 *
 * Secrets, log-source confirmation, privacy, the panel account, and the "what do I do
 * next" text. Both installers call these, so both produce the same configuration from the
 * same answers — which is the property the installer test suite pins.
 *
 * Everything here is a pure-ish function over a Config: validate, mutate, hand back a list
 * of human-readable problems. Nothing renders, nothing echoes, nothing exits.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Security;

final class Steps
{
    /**
     * Minimum panel password length.
     *
     * Ten, the same number `bin/loghound-setup` enforces. The panel is reachable from the
     * internet and shows every visitor, path and IP address on the site; a short password
     * on that is a data breach with extra steps.
     */
    public const MIN_PASSWORD = 10;

    /**
     * Generate the secrets that must exist before the daemons will start.
     *
     * Only ever FILLS IN a missing value. An existing beacon secret is kept, because
     * rotating it invalidates every token already issued to a live visitor's browser and
     * turns their honest timing reports into "forged" — which the scorer, correctly,
     * treats as evidence of a bot.
     *
     * @return string[] Names of the secrets that were generated, for the progress line.
     */
    public static function ensureSecrets(Config $cfg): array
    {
        $made = [];

        if (strlen((string) $cfg->get('beacon.secret', '')) < 32) {
            $cfg->set('beacon.secret', bin2hex(random_bytes(32)));
            $made[] = 'beacon signing key';
        }

        if (strlen((string) $cfg->get('privacy.ip_salt', '')) < 16) {
            $cfg->set('privacy.ip_salt', bin2hex(random_bytes(16)));
            $made[] = 'address hashing salt';
        }

        return $made;
    }

    /**
     * Confirm a set of detected sources into the configuration.
     *
     * SPEC §8: nothing is ever ingested with a silently guessed format, so a source only
     * gets here after a human has looked at five parsed lines and said yes.
     *
     * `allowed_log_roots` is widened only for directories the operator explicitly ticked,
     * and only to the exact directory needed — never to '/'. That list is a security
     * control: it is what stops the log-path setting from being an arbitrary-file-read.
     *
     * @param array<int,array<string,mixed>> $chosen  Source entries from the detection report.
     * @param string[]                       $widen   Directories the operator agreed to allow.
     * @return string[] Problems; empty means every chosen source was stored.
     */
    public static function applySources(Config $cfg, array $chosen, array $widen = []): array
    {
        $errors = [];
        $roots  = (array) $cfg->get('allowed_log_roots', []);

        foreach ($widen as $dir) {
            $real = realpath((string) $dir);
            if ($real === false || !is_dir($real)) {
                $errors[] = 'Cannot allow ' . $dir . ': there is no such directory.';
                continue;
            }
            if (!in_array($real, $roots, true)) {
                $roots[] = $real;
            }
        }
        $cfg->set('allowed_log_roots', array_values(array_unique($roots)));

        $sources = [];
        foreach ($chosen as $src) {
            $path = (string) ($src['path'] ?? '');
            if ($path === '') {
                continue;
            }
            if (Security::safePath(dirname($path), $roots) === null) {
                $errors[] = $path . ' is outside the directories Loghound may read.';
                continue;
            }

            $format = (string) ($src['format_name'] ?? '');
            if ($format === '' || $format === 'unknown' || $format === 'unrecognised') {
                $errors[] = 'No usable format was worked out for ' . $path . '.';
                continue;
            }
            $stored = $format;
            if (!array_key_exists($format, \Loghound\LogDetect::library())
                && (string) ($src['format_string'] ?? '') !== '') {
                $stored = (string) $src['format_string'];
            }

            $entry = ['path' => $path, 'format' => $stored, 'confirmed' => true];
            $host = (string) ($src['vhost'] ?? '');
            if ($host !== '') {
                $entry['host'] = $host;
            }
            $sources[] = $entry;
        }

        if ($sources !== []) {
            $cfg->set('sources', $sources);
        }
        return $errors;
    }

    /**
     * The three IP storage modes, each explained in one plain sentence.
     *
     * This is the screen where an operator decides what they are keeping about their
     * visitors. It has to be legible, not a formality — so the trade-off of each mode is
     * stated, including what it costs the bot detection, rather than only its benefit.
     *
     * @return array<string,array{label:string,text:string,cost:string}>
     */
    public static function ipModes(): array
    {
        return [
            'full' => [
                'label' => 'Keep the full address',
                'text'  => 'The visitor\'s IP address is stored as it is. You already have it in '
                    . 'your own access log, so this stores nothing you were not keeping already.',
                'cost'  => 'Strongest detection. Choose another mode if you would rather not hold '
                    . 'addresses in a second place.',
            ],
            'truncate' => [
                'label' => 'Drop the last part of the address',
                'text'  => 'Only the network is kept — the first three parts of an IPv4 address, '
                    . 'the first three groups of an IPv6 one. Individual visitors stop being '
                    . 'identifiable while network-level analysis still works.',
                'cost'  => 'Slightly weaker: a proxy fleet whose exits share one network now looks '
                    . 'like a single address, so the fingerprint-cluster count under-reports.',
            ],
            'hash' => [
                'label' => 'Store an unreadable hash',
                'text'  => 'The address is replaced by a keyed hash that changes every day. '
                    . 'Sessions still work within a day; joining a person\'s visits across days '
                    . 'becomes impossible, including for you.',
                'cost'  => 'Weakest for forensics: you can no longer look up who an address '
                    . 'belonged to, or check it against a threat list.',
            ],
        ];
    }

    /**
     * Store the privacy answers.
     *
     * @return string[] Problems; empty means stored.
     */
    public static function applyPrivacy(Config $cfg, string $ipMode, $retentionDays): array
    {
        if (!array_key_exists($ipMode, self::ipModes())) {
            return ['Choose one of the three ways to store visitor addresses.'];
        }

        $cfg->set('privacy.ip_mode', $ipMode);
        $cfg->set('privacy.retention_days', Security::clampInt($retentionDays, 0, 3650, 90));

        self::ensureSecrets($cfg);

        return [];
    }

    /**
     * Store the username and password used to sign in to Loghound.
     *
     * The password is hashed immediately with password_hash(PASSWORD_DEFAULT) and the
     * plaintext is not kept anywhere — not in the config, not in a session, not in a log.
     *
     * @return string[] Problems; empty means stored.
     */
    public static function applyAdmin(Config $cfg, string $user, string $password, string $confirm): array
    {
        $errors = [];

        $user = trim($user);
        if ($user === '') {
            $errors[] = 'Choose a username.';
        } elseif (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', $user)) {
            $errors[] = 'The username may contain letters, digits, and . _ - @ only.';
        }

        if (strlen($password) < self::MIN_PASSWORD) {
            $errors[] = 'Use a password of at least ' . self::MIN_PASSWORD . ' characters. This page '
                . 'shows every visitor, page and address on your site.';
        }
        if ($confirm !== '' && $password !== $confirm) {
            $errors[] = 'The two passwords are not the same.';
        }

        if ($errors !== []) {
            return $errors;
        }

        $cfg->set('auth.user', $user);
        $cfg->set('auth.password_hash', password_hash($password, PASSWORD_DEFAULT));
        $cfg->set('auth.mode', 'basic');

        return [];
    }

    /**
     * Store the public URL of this installation, used to build the beacon snippet.
     *
     * @return string[] Problems; empty means stored (an empty URL is allowed and skipped).
     */
    public static function applyBaseUrl(Config $cfg, string $url): array
    {
        $url = rtrim(trim($url), '/');
        if ($url === '') {
            return [];
        }
        if (Security::safeUrl($url) === '#') {
            return ['The address of this panel must be a plain http:// or https:// URL.'];
        }
        $cfg->set('base_url', $url);
        return [];
    }

    /**
     * Which steps are finished, judged from the configuration itself.
     *
     * There is no separate "wizard state" anywhere: the partly-written config file IS the
     * state. That is what makes every step resumable across a reload, a new browser, or a
     * switch from the browser installer to the shell wizard and back.
     *
     * @return array<string,bool> step key => complete
     */
    public static function progress(Config $cfg): array
    {
        $solrReady = (string) $cfg->get('solr.hits_core', '') !== ''
            && (string) $cfg->get('solr.sessions_core', '') !== ''
            && (string) $cfg->get('solr.base_url', '') !== '';

        return [
            Installer::STEP_SOURCES => (array) $cfg->get('sources', []) !== [],
            Installer::STEP_STORAGE => $solrReady,
            Installer::STEP_PRIVACY => strlen((string) $cfg->get('beacon.secret', '')) >= 32,
            Installer::STEP_ADMIN   => (string) $cfg->get('auth.password_hash', '') !== '',
        ];
    }

    /**
     * The first step that is not finished — where a returning operator is put back.
     */
    public static function firstIncomplete(Config $cfg): string
    {
        foreach (self::progress($cfg) as $step => $done) {
            if (!$done) {
                return $step;
            }
        }
        return Installer::STEP_ADMIN;
    }

    /**
     * What to do once the configuration is written.
     *
     * Shared so the shell wizard and the browser installer print the same instructions;
     * if these ever drift, one of the two is lying to somebody.
     *
     * @return array<int,array{title:string,lines:string[]}>
     */
    public static function nextSteps(Config $cfg, string $root): array
    {
        $base = rtrim((string) $cfg->get('base_url', ''), '/');
        if ($base === '') {
            $base = 'https://loghound.example.com';
        }

        return [
            [
                'title' => 'Start reading the logs',
                'lines' => [
                    'sudo systemctl enable --now loghound-tail.service',
                    'sudo systemctl enable --now loghound-score.timer loghound-retention.timer',
                ],
            ],
            [
                'title' => 'Check it is keeping up',
                'lines' => [
                    $root . '/bin/loghound-tail --status --human',
                ],
            ],
            [
                'title' => 'Add the beacon to your site',
                'lines' => [
                    '<script src="' . $base . '/b.js?v=1" defer></script>',
                ],
            ],
        ];
    }

    /**
     * Why the beacon is worth the one line of HTML, in the words the panel uses elsewhere.
     */
    public static function beaconRationale(): string
    {
        return 'Without it Loghound still works, but the execution plane is blind: headless '
            . 'automation is inferred rather than proven, and time-on-site falls back to the '
            . 'weak log-derived number every other log analyser reports.';
    }
}
