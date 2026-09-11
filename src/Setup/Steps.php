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
     * THE ADDRESS SALT IS MINTED HERE FOR EVERY INSTALLATION, whichever front end ran and
     * whatever `privacy.ip_mode` ends up as. It is only read by hash mode, but minting it
     * unconditionally is what makes switching to hash mode later a setting change rather
     * than a setting change that silently needs a secret nobody generated. Settings mints
     * one too if it ever finds the mode moving to hash without a salt behind it.
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
     * The flat problem list is what every existing caller wants; a caller that has to tell
     * a partial success from a total one — the browser installer does, because one refused
     * source must not block the six that were fine — calls applySourcesReport() instead and
     * gets the same work described per source.
     *
     * @param array<int,array<string,mixed>> $chosen  Source entries from the detection report.
     * @param string[]                       $widen   Directories the operator agreed to allow.
     * @return string[] Problems; empty means every chosen source was stored.
     */
    public static function applySources(Config $cfg, array $chosen, array $widen = []): array
    {
        $report = self::applySourcesReport($cfg, $chosen, $widen);

        $problems = $report['widening'];
        foreach ($report['refused'] as $one) {
            $problems[] = $one['message'];
        }
        return $problems;
    }

    /**
     * Confirm a set of detected sources, saying per source what was stored and what was not.
     *
     * SAME RULES AS applySources(), WHICH IS A THIN WRAPPER AROUND THIS — there is one
     * implementation of "may this file be ingested, and with which format", not two.
     *
     * The reason this shape exists is that "did it work" is not a yes/no question here. An
     * operator confirming seven discovered files, one of which sits outside
     * `allowed_log_roots` and was not explicitly widened, used to be told the whole step had
     * failed and left with no way forward in the middle of an installation. The six good
     * ones are stored, the refusals are named individually, and the caller can report both.
     * A refused source is never quietly dropped and never counted as stored.
     *
     * `stored` lists the paths that are now in `sources`. `refused` names every path that is
     * not, with the sentence explaining why. `widening` holds problems with the directories
     * the operator asked to allow, which are not attributable to any one source.
     *
     * @param array<int,array<string,mixed>> $chosen  Source entries from the detection report.
     * @param string[]                       $widen   Directories the operator agreed to allow.
     * @return array{stored:string[],refused:array<int,array{path:string,message:string}>,widening:string[]}
     */
    public static function applySourcesReport(Config $cfg, array $chosen, array $widen = []): array
    {
        $widening = [];
        $refused  = [];
        $roots    = (array) $cfg->get('allowed_log_roots', []);

        foreach ($widen as $dir) {
            $real = realpath((string) $dir);
            if ($real === false || !is_dir($real)) {
                $widening[] = 'Cannot allow ' . $dir . ': there is no such directory.';
                continue;
            }
            if (!in_array($real, $roots, true)) {
                $roots[] = $real;
            }
        }
        $cfg->set('allowed_log_roots', array_values(array_unique($roots)));

        $sources = [];
        $stored  = [];
        foreach ($chosen as $src) {
            $path = (string) ($src['path'] ?? '');
            if ($path === '') {
                continue;
            }
            if (Security::safePath(dirname($path), $roots) === null) {
                $refused[] = [
                    'path'    => $path,
                    'message' => $path . ' is outside the directories Loghound may read.',
                ];
                continue;
            }

            $format = (string) ($src['format_name'] ?? '');
            if ($format === '' || $format === 'unknown' || $format === 'unrecognised') {
                $refused[] = [
                    'path'    => $path,
                    'message' => 'No usable format was worked out for ' . $path . '.',
                ];
                continue;
            }
            $storedFormat = $format;
            if (!array_key_exists($format, \Loghound\LogDetect::library())
                && (string) ($src['format_string'] ?? '') !== '') {
                $storedFormat = (string) $src['format_string'];
            }

            $entry = ['path' => $path, 'format' => $storedFormat, 'confirmed' => true];
            $host = (string) ($src['vhost'] ?? '');
            if ($host !== '') {
                $entry['host'] = $host;
            }
            $sources[] = $entry;
            $stored[]  = $path;
        }

        if ($sources !== []) {
            $cfg->set('sources', $sources);
        }

        return ['stored' => $stored, 'refused' => $refused, 'widening' => $widening];
    }

    /**
     * The three ways a visitor's address may be stored.
     *
     * The list itself, and nothing else. Setup does not ask which one to use — the default
     * in Config::defaults() stands and the panel's Settings page is where it is changed —
     * so the prose describing each mode lives on that screen, next to the control that
     * changes it. This is the one list both that screen and applyPrivacy() validate against.
     *
     * @return string[]
     */
    public static function ipModes(): array
    {
        return ['full', 'truncate', 'hash'];
    }

    /**
     * Store the privacy settings.
     *
     * Neither installer asks for these any more. What still calls this is the shell wizard,
     * when LOGHOUND_IP_MODE or LOGHOUND_RETENTION_DAYS is supplied by an unattended install,
     * and the tests that pin what those variables do.
     *
     * @return string[] Problems; empty means stored.
     */
    public static function applyPrivacy(Config $cfg, string $ipMode, $retentionDays): array
    {
        if (!in_array($ipMode, self::ipModes(), true)) {
            return ['Choose one of the three ways to store visitor addresses.'];
        }

        $cfg->set('privacy.ip_mode', $ipMode);
        $cfg->set('privacy.retention_days', Security::clampInt($retentionDays, 0, 3650, 90));

        self::ensureSecrets($cfg);

        return [];
    }

    /**
     * The two ways to sign in, each with its real trade-off.
     *
     * A thin pass-through to Security::authModes() so that the installer, the panel and
     * Config::validate() all read the same list from the same place. Kept here as well
     * because every other choice the wizard offers is described by a Steps:: method, and a
     * screen that reaches into a different class for one of its four questions is how the
     * wording drifts.
     *
     * @return array<string,array{label:string,text:string,cost:string}>
     */
    public static function authModes(): array
    {
        return Security::authModes();
    }

    /**
     * Switch between Basic and the sign-in page without touching the credentials.
     *
     * Exists so that changing your mind later is a supported operation rather than an
     * edit to config/loghound.php: Settings calls this, the installer calls applyAdmin(),
     * and both end up at the same two values. Refuses to move to a mode that would leave
     * the panel unreachable — a mode that signs people in with a password needs one to
     * have been set first.
     *
     * @return string[] Problems; empty means stored.
     */
    public static function applyAuthMode(Config $cfg, string $mode): array
    {
        if (!array_key_exists($mode, self::authModes())) {
            return ['Choose one of the two ways to sign in.'];
        }
        if ((string) $cfg->get('auth.password_hash', '') === ''
            || (string) $cfg->get('auth.user', '') === '') {
            return ['Set a username and password before choosing how to sign in.'];
        }

        $cfg->set('auth.mode', $mode);
        return [];
    }

    /**
     * Store the username and password used to sign in to Loghound.
     *
     * The password is hashed immediately with password_hash(PASSWORD_DEFAULT) and the
     * plaintext is not kept anywhere — not in the config, not in a session, not in a log.
     *
     * The mode defaults to 'basic' because that is what every installation made before the
     * sign-in page existed uses, and because it is the answer that cannot strand anyone:
     * it needs no cookies, no JavaScript and no session storage. An unrecognised mode is
     * refused rather than quietly corrected, so a form field that stops matching this list
     * fails loudly instead of silently changing how the panel authenticates.
     *
     * @param string $mode 'basic' or 'session'; see Security::authModes().
     * @return string[] Problems; empty means stored.
     */
    public static function applyAdmin(
        Config $cfg,
        string $user,
        string $password,
        string $confirm,
        string $mode = 'basic'
    ): array {
        $errors = [];

        if (!array_key_exists($mode, self::authModes())) {
            $errors[] = 'Choose one of the two ways to sign in.';
        }

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
        $cfg->set('auth.mode', $mode);

        return [];
    }

    /**
     * Store the public URL of this installation, used to build the beacon snippet.
     *
     * The userinfo case is separated out because this value is pasted into the beacon
     * snippet the operator hands to their own site, so credentials typed in here would end
     * up in the HTML of every page they measure. A bare "that is not a valid URL" would
     * leave them retyping the same thing.
     *
     * @return string[] Problems; empty means stored (an empty URL is allowed and skipped).
     */
    public static function applyBaseUrl(Config $cfg, string $url): array
    {
        $url = rtrim(trim($url), '/');
        if ($url === '') {
            return [];
        }
        if (Security::urlHasUserinfo($url)) {
            return ['The address of this panel must not contain a username or password. '
                . 'Enter it as https://host/path only.'];
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
     * Where `bin/loghound-tail` leaves the status document it writes about itself.
     *
     * The daemon rewrites this at most once a second for as long as it is alive, whether or
     * not any log line arrived, so its modification is a record of the tailer running rather
     * than of the site being busy. `--status` reads this exact file and nothing else, and so
     * does ingestStatus(): one artefact, one answer, whoever is asking.
     */
    public const TAIL_STATUS_FILE = 'var/tail-status.json';

    /**
     * How old the tailer's own status document may be before it stops counting as evidence.
     *
     * Ten seconds, the same number `bin/loghound-tail --status` uses to decide it is looking
     * at a dead daemon's leftovers. Both places have to agree, because an operator who runs
     * the command after reading this panel must not be told two different things.
     */
    public const TAIL_STALE_AFTER = 10;

    /**
     * What to do once the configuration is written.
     *
     * Shared so the shell wizard, the browser installer and the panel print the same
     * instructions; if these ever drift, one of the three is lying to somebody.
     *
     * The unit line is ONE command. `systemctl enable --now` takes a list, so the service
     * and both timers are enabled and started together, and the title says what `enable`
     * buys — the units come back on their own after a reboot. Nothing here CHECKS that, and
     * nothing in this product can: there is no process execution anywhere in `src/`, `bin/`
     * or `public/`, which is a published property of Loghound and worth more than a badge.
     *
     * `lines` is a list of single, directly pasteable lines — one line in, one line out, so
     * a copy button hands the operator something a shell will accept unedited.
     *
     * A group whose command cannot honestly be built carries an empty `lines` and a
     * populated `problem` naming what to fix. That is the beacon's case when `base_url` is
     * unset or unusable: a snippet pointing at a guessed host is pasted into a template,
     * collects nothing, and reads as the product being broken.
     *
     * @return array<int,array{key:string,title:string,lines:string[],problem:string}>
     */
    public static function nextSteps(Config $cfg, string $root, bool $mayUseRequestHost = false): array
    {
        [$snippet, $problem] = self::beaconSnippet($cfg, $mayUseRequestHost);

        return [
            [
                'key'     => 'ingest',
                'title'   => 'Start reading the logs, now and after every reboot',
                'lines'   => self::ingestCommands($root),
                'problem' => '',
            ],
            [
                'key'     => 'status',
                'title'   => 'Check it is keeping up',
                'lines'   => [
                    rtrim($root, '/') . '/bin/loghound-tail --status --human',
                ],
                'problem' => '',
            ],
            [
                'key'     => 'beacon',
                'title'   => 'Add the beacon to your site',
                'lines'   => $snippet === '' ? [] : [$snippet],
                'problem' => $problem,
            ],
        ];
    }

    /** Where a systemd unit lives, and the one this installation is named after. */
    private const SYSTEMD_DIR = '/etc/systemd/system';

    private const TAIL_UNIT = 'loghound-tail.service';

    /**
     * The commands that actually start ingestion on THIS machine.
     *
     * `systemctl enable --now loghound-tail.service` is the whole answer only when the unit
     * files are on the machine, and they are not always: install.sh puts them there, but a
     * tree deployed any other way — copied into place, checked out, provisioned by a control
     * panel — has the code and no units. Handing that operator a command whose only possible
     * outcome is `Unit file loghound-tail.service does not exist` is the same failure as
     * handing them a beacon snippet pointing at a host nobody owns: they copy it, they trust
     * it, and what comes back tells them nothing about what to do instead.
     *
     * So the units are looked for first, and the install step is prepended only when it is
     * needed — or when we cannot see, which is its own answer rather than a guess. The units
     * ship inside the tree, so installing them is a copy and one substitution: they carry the
     * default prefix throughout, which is exactly what install.sh rewrites.
     *
     * It stays ONE line, chained on `&&`, because the copy button next to it promises a
     * pasteable command and a two-line block is two pastes and a chance to run the second
     * without the first. `&&` also means a failed copy never reaches the enable.
     *
     * @return array<int,string>
     */
    private static function ingestCommands(string $root): array
    {
        $enable = 'sudo systemctl enable --now loghound-tail.service '
            . 'loghound-score.timer loghound-retention.timer';

        if (self::unitsInstalled() === true) {
            return [$enable];
        }

        $root = rtrim($root, '/');

        return [
            'sudo install -m 0644 ' . $root . '/install/loghound-*.service '
                . $root . '/install/loghound-*.timer ' . self::SYSTEMD_DIR . '/'
                . ' && sudo sed -i "s#/opt/loghound#' . $root . '#g" '
                . self::SYSTEMD_DIR . '/loghound-*.service ' . self::SYSTEMD_DIR . '/loghound-*.timer'
                . ' && sudo systemctl daemon-reload'
                . ' && ' . $enable,
        ];
    }

    /**
     * Are the systemd units on this machine?
     *
     * Returns null when the question cannot be answered rather than guessing at it. The
     * panel runs under an open_basedir that does not include the systemd directory on a
     * stock install, and there `is_readable()` returns false for a unit that is present —
     * so a bare false would report "not installed" to every correctly installed operator
     * and tell them to reinstall files they already have.
     */
    private static function unitsInstalled(): ?bool
    {
        $basedir = (string) ini_get('open_basedir');
        if ($basedir !== '') {
            $visible = false;
            foreach (explode(PATH_SEPARATOR, $basedir) as $allowed) {
                $allowed = rtrim(trim($allowed), '/');
                if ($allowed !== '' && str_starts_with(self::SYSTEMD_DIR . '/', $allowed . '/')) {
                    $visible = true;
                    break;
                }
            }
            if (!$visible) {
                return null;
            }
        }

        return @is_readable(self::SYSTEMD_DIR . '/' . self::TAIL_UNIT);
    }

    /**
     * The panel's address as this screen should present it.
     *
     * The saved value wins. Falling back to the request is offered only where the operator
     * is looking at that same address in an editable field — during setup — so that the
     * field and everything derived from it cannot disagree. Elsewhere the fallback is off
     * and an unset address stays visible as unset.
     */
    public static function effectiveBaseUrl(Config $cfg, bool $mayUseRequestHost = false): string
    {
        $saved = rtrim(trim((string) $cfg->get('base_url', '')), '/');
        if ($saved !== '') {
            return $saved;
        }

        return $mayUseRequestHost ? self::requestBaseUrl() : '';
    }

    /**
     * The address this request arrived on, or an empty string.
     *
     * The Host header is chosen by whoever sent the request, so it is shape-checked before
     * it is echoed into a page: a hostname or an IPv4 literal with an optional port, and
     * nothing else. A header carrying a path, a scheme, a credential or markup yields
     * nothing rather than a URL built around it.
     */
    public static function requestBaseUrl(): string
    {
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
        if ($host === '' || strlen($host) > 255) {
            return '';
        }
        if (!preg_match('/^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$/', $host)) {
            return '';
        }

        $scheme = (($_SERVER['HTTPS'] ?? '') !== '') ? 'https' : 'http';

        return $scheme . '://' . $host;
    }

    /**
     * The one-line beacon tag, or the reason there is not one to give.
     *
     * The snippet is worthless unless the URL in it is the URL visitors' browsers can
     * actually reach. That is `base_url` once setup has saved one. There is no example
     * domain and never a made-up host: a snippet somebody copies, trusts and pastes into
     * their site has to work, and one that points at a plausible-looking host nobody owns
     * fails silently and reads as the product being broken.
     *
     * DURING SETUP there is no saved value yet, and refusing outright would be pedantry: the
     * address field on that same screen is already filled in from the request, the operator
     * can see it and correct it, and it is the value the form is about to save. So the
     * installer passes $mayUseRequestHost and the snippet shows the same address the field
     * shows — one value in two places, never two. After setup the flag is off, because by
     * then an empty base_url is a real misconfiguration and inventing a host would hide it.
     *
     * "Unusable" is judged by the same two checks applyBaseUrl() refuses a value with, so a
     * config file edited by hand is held to the standard the form enforces.
     *
     * @return array{0:string,1:string} [snippet, problem] — exactly one is ever non-empty.
     */
    public static function beaconSnippet(Config $cfg, bool $mayUseRequestHost = false): array
    {
        $base = self::effectiveBaseUrl($cfg, $mayUseRequestHost);

        if ($base === '') {
            return ['', 'The public address of this panel is not set, so there is no snippet to copy. '
                . 'Set base_url in config/loghound.php to the URL your visitors would reach this '
                . 'installation at, then come back.'];
        }
        if (Security::urlHasUserinfo($base)) {
            return ['', 'The configured address of this panel contains a username or password, which would '
                . 'be published in the HTML of every page you measure. Set base_url to https://host/path '
                . 'only.'];
        }
        if (Security::safeUrl($base) === '#') {
            return ['', 'The configured address of this panel is not a plain http:// or https:// URL, so no '
                . 'snippet can be built from it. Correct base_url in config/loghound.php.'];
        }

        return ['<script src="' . $base . '/b.js?v=1" defer></script>', ''];
    }

    /**
     * Is anything actually reading the logs, judged from the tailer's own record?
     *
     * THIS IS EVIDENCE, NOT INFERENCE. It does not ask systemd, it does not run a process
     * and it does not open a socket — Loghound contains no exec, shell_exec, proc_open or
     * SSH by design, and a liveness badge is not worth giving that up. What it does is read
     * the document the daemon writes about itself every second and look at how old it is,
     * which answers "is ingestion working" better than a unit file's state would anyway: an
     * active unit whose tailer is wedged still reports active.
     *
     * The four states are deliberately distinct. 'absent' means the daemon has never run
     * here, which is the case this whole section exists for. 'stale' means it ran and has
     * stopped, which is a different sentence and a different worry. 'unreadable' means the
     * file is there but is not a status document — a permissions problem or a half-migrated
     * install — and is never quietly folded into either of the others.
     *
     * Boot persistence is NOT reported. Nothing here can see it.
     *
     * @param string $root Installation root; the status file is found under it.
     * @return array{state:string,file:string,age_sec:?int,generated_at:?string,lag_bytes:?int,lines:?int,indexed:?int,sources:?int}
     */
    public static function ingestStatus(string $root): array
    {
        $file = rtrim($root, '/') . '/' . self::TAIL_STATUS_FILE;
        $blank = [
            'state'        => 'absent',
            'file'         => $file,
            'age_sec'      => null,
            'generated_at' => null,
            'lag_bytes'    => null,
            'lines'        => null,
            'indexed'      => null,
            'sources'      => null,
        ];

        if (!is_file($file) || !is_readable($file)) {
            return $blank;
        }

        $raw = @file_get_contents($file);
        $doc = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($doc) || !is_string($doc['generated_at'] ?? null)) {
            return ['state' => 'unreadable'] + $blank;
        }

        $written = strtotime($doc['generated_at']);
        if ($written === false) {
            return ['state' => 'unreadable'] + $blank;
        }

        $age = max(0, time() - $written);
        $totals = is_array($doc['totals'] ?? null) ? $doc['totals'] : [];

        return [
            'state'        => $age > self::TAIL_STALE_AFTER ? 'stale' : 'live',
            'file'         => $file,
            'age_sec'      => $age,
            'generated_at' => $doc['generated_at'],
            'lag_bytes'    => is_int($doc['lag_bytes'] ?? null) ? $doc['lag_bytes'] : null,
            'lines'        => is_int($totals['lines'] ?? null) ? $totals['lines'] : null,
            'indexed'      => is_int($totals['docs_indexed'] ?? null) ? $totals['docs_indexed'] : null,
            'sources'      => is_array($doc['sources'] ?? null) ? count($doc['sources']) : null,
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
