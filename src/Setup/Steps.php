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

use Loghound\Auth\Persistence;
use Loghound\Beacon\Doc;
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
            /* THE / GUARD ITS SIBLING HAS HAD ALL ALONG. allowLogRoot() refuses it in so many
               words and this path did not, which made the difference reachable: a discovered
               source at a top-level path — an Apache `CustomLog /access.log`, or a fallback glob
               resolving to `/*` — yields dirname() === '/', the confirm screen offers it as a
               checkbox, and ticking it puts `/` in allowed_log_roots. From that moment
               Security::safePath() accepts every path on the machine and "add a log source"
               becomes an arbitrary-file read whose contents are rendered as sample lines. */
            if ($real === '/') {
                $widening[] = 'Refusing to allow / — that would let any file on this server be '
                    . 'read as a log.';
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
     * Add one directory to the list of places Loghound may read log files from.
     *
     * `allowed_log_roots` is a security control: it is what stops the log-path setting from
     * being an arbitrary-file-read primitive, which is why no web form widens it and why
     * applySourcesReport() only widens it for directories an operator explicitly ticked.
     *
     * This exists for the one remaining case that had no working answer at all: a log file
     * typed in by hand that sits outside the list. The browser installer refuses it, correctly,
     * and told the operator to use the shell wizard — which called the same refusal and printed
     * the same sentence, so the instruction was a loop with no exit. Granting it needs an
     * explicit yes from somebody at a terminal on the machine, which is a different and
     * stronger proof than a form post, and this is the one place that records it.
     *
     * Widens to the exact directory and nothing above it. A path that does not resolve is
     * refused rather than stored hopefully, because a root that does not exist is a root that
     * will match something else the day it does.
     *
     * @return string|null A problem to show, or null when the directory is now allowed.
     */
    public static function allowLogRoot(Config $cfg, string $dir): ?string
    {
        $real = realpath($dir);
        if ($real === false || !is_dir($real)) {
            return 'Cannot allow ' . $dir . ': there is no such directory.';
        }
        if ($real === '/') {
            return 'Refusing to allow / — that would let any file on this server be read as a log.';
        }

        $roots = (array) $cfg->get('allowed_log_roots', []);
        if (!in_array($real, $roots, true)) {
            $roots[] = $real;
            $cfg->set('allowed_log_roots', array_values(array_unique($roots)));
        }

        return null;
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
     * Changing the mode revokes every persistent-login token. Those are session-mode
     * credentials; carrying them across a switch to Basic and back would mean a cookie issued
     * under one set of rules still opening the door under another.
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
        Persistence::revokeAll($cfg->varDir());

        return [];
    }

    /**
     * Store the username and password used to sign in to Loghound.
     *
     * The password is hashed immediately with password_hash(PASSWORD_DEFAULT) and the
     * plaintext is not kept anywhere — not in the config, not in a session, not in a log.
     *
     * SETTING A NEW PASSWORD REVOKES EVERY OTHER PROOF OF IDENTITY. Every persistent-login
     * token is destroyed, and two-factor is switched off. Both follow from what this operation
     * means: a new password is a statement that the old credentials no longer stand, and a
     * "stay signed in" cookie that survived one would make the change cosmetic. Turning
     * two-factor off is also the documented way back in for an operator who has lost both the
     * phone and the recovery codes — it is only reachable from the installer and from
     * bin/loghound-setup, so performing it already requires shell access to the box, which is
     * proof enough of who they are. Settings deliberately has no password form.
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
        } elseif (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/D', $user)) {
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

        $cfg->set('auth.totp', ['enabled' => false, 'secret' => '', 'recovery' => []]);
        Persistence::revokeAll($cfg->varDir());

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
     * The nickname the duration-carrying Apache format is published under, on every surface.
     *
     * NEVER `combined`. Debian and Ubuntu already define that nickname in `apache2.conf`, and
     * redefining it inside a `<VirtualHost>` does not reliably win: the configuration is
     * accepted, `configtest` is happy, the reload succeeds, and the lines keep coming out in
     * the old shape with nothing in any error log to say why. A format with its own name has
     * none of that ambiguity, and `combined_d` says what it is — `combined` plus the duration.
     */
    public const DURATION_NICKNAME = 'combined_d';

    /**
     * How far back the parse-health window on a source reaches, in seconds.
     *
     * Five minutes. A format change takes a source from parsing everything to parsing nothing
     * inside a couple of minutes — the incident this was built from went from 19 parse errors
     * to 90 in three — so the window has to be long enough to hold the whole transition on a
     * quiet site, and short enough that it has emptied again a few minutes after the fix.
     */
    public const DRIFT_WINDOW_SEC = 300;

    /**
     * How many lines a source must have offered in that window before the rate means anything.
     *
     * Below twenty, two scanner probes and one real request is a 67% failure rate. The floor
     * is what separates "this file changed shape" from "somebody pointed a vulnerability
     * scanner at the site", which is the distinction the whole check exists to make.
     */
    public const DRIFT_MIN_ATTEMPTS = 20;

    /**
     * The share of a window's lines that must fail before the format is called changed.
     *
     * Ninety per cent. A changed format fails essentially every line, because every line now
     * carries a field the stored format has no column for; junk arrives as a trickle against a
     * background of traffic that parses. The ten per cent of headroom covers the tail of
     * old-shape lines still being read out of a rotated file while the new ones arrive.
     */
    public const DRIFT_FAIL_RATE = 0.9;

    /* THE THREE DRIFT_ CONSTANTS ABOVE ARE A DESIGN, NOT A LIVE CHECK, AND THAT IS DELIBERATE.
       Nothing reads them yet. The premise they were written against — "the tailer knows its
       parse-error rate per source" — is not true of this code: `parse_errors` is a single
       process-wide counter incremented in `bin/loghound-tail`, and the per-source entries in
       the status document are Tail::status(), which carries a path, an offset, a lag and a
       format name and no failure count at all. There is nothing per-source to divide by.

       Shipping the check anyway would mean deciding "this source changed shape" from a number
       that every other source, and every vulnerability scanner spraying junk at any one of
       them, contributes to. DRIFT_MIN_ATTEMPTS and DRIFT_FAIL_RATE are per-source thresholds
       precisely so that a scanner cannot trip them; applied to a global counter they lose the
       one property they exist for, and a banner that names the wrong source — or names a
       source on a day nothing changed — teaches the operator to dismiss the banner that is
       right. Wrong beats silent only until the first false alarm.

       So this pass fixes the cause instead of detecting it: every surface that tells an
       operator to change their log format now also tells them to rescan the source, and
       docs/INSTALL.md documents the failure in full under "Three ways this silently does
       nothing". The detector needs a windowed per-source attempts/failures ledger in
       Loghound\State plus the tailer writing to it, which is a change to `bin/loghound-tail`
       and a state-schema migration — its own pass, with these constants already agreed. */

    /**
     * The nickname the full recommended Apache format is published under.
     *
     * Distinct from any distro-defined name for the same reason DURATION_NICKNAME is, and
     * pinned here so that the panel, the installer, the detector library and docs/INSTALL.md
     * cannot drift into publishing two different format strings under one nickname. An
     * operator who pasted both would get whichever Apache read last, silently.
     */
    public const RECOMMENDED_NICKNAME = 'loghound';

    /**
     * Changing a log format is two thirds of the job; this is the third nobody expects.
     *
     * Loghound compiles and STORES the format per source. The moment a line gains a field the
     * stored format has no column for, every new line becomes a parse error — the lines are
     * still being written and still being read, the counter climbs, and the panel shows
     * nothing. The incident this sentence was written from went from 19 parse errors to 90 in
     * three minutes with no other symptom.
     *
     * Carried as one string so the Performance card, the Hosts card and the documentation say
     * it identically. It is prose, never a copyable line: nothing here is pasteable into a
     * shell, and tests/test_setup_instructions.php holds the panel to that.
     */
    /**
     * What to do after changing the web server's log format, with the commands it names.
     *
     * A METHOD, NOT A CONSTANT, and that is the whole point of it. It was a const, so it could
     * not interpolate an installation root and named its two commands as `bin/loghound-setup`
     * and `bin/loghound-tail --status --human` — followable from exactly one directory, by a
     * reader who is in a browser and will paste them into a shell somewhere else. Every other
     * command this product prints is absolute; this was the exception, on two views.
     *
     * Still prose and never a pasteable line: it goes inside a <p>, and the panel puts a Copy
     * button on <pre>. tests/test_doc_claims.php holds it to that.
     */
    public static function rescanAdvice(string $root): string
    {
        $bin = rtrim($root, '/') . '/bin/';

        return 'Then tell Loghound the shape changed: rescan the source under Settings, or re-run '
            . $bin . 'loghound-setup. It stores the format per source, so until you do, every '
            . 'newly written line is a parse error and nothing new reaches the panel. Check '
            . $bin . 'loghound-tail --status --human afterwards — parse errors should be back to '
            . 'zero within a minute.';
    }

    /**
     * The full recommended Apache LogFormat, exactly as docs/INSTALL.md publishes it.
     *
     * ONE definition, because the string is long enough that a second copy would be edited on
     * its own and nobody would notice.
     *
     * ONE PHYSICAL LINE, WITH NO CONTINUATION BACKSLASHES. It used to be published as five
     * lines joined by Apache's `\` continuation, which is valid and which nobody pastes
     * correctly: the backslash has to be the last character before the newline, so a copy out
     * of a browser, a chat window or a PDF — anything that reflows or trims trailing
     * whitespace — silently produces a broken directive or, worse, four stray lines Apache
     * reads as separate junk. A single line survives every one of those journeys. It is long,
     * and length is the cheaper problem.
     *
     * The `\"` sequences are NOT optional and are not this codebase's escaping: Apache's own
     * parser requires a quote inside a quoted format string to be backslash-escaped, so a line
     * with them stripped is rejected at configtest.
     */
    public static function recommendedLogFormat(): string
    {
        return 'LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O %D \"%{Referer}i\" \"%{User-Agent}i\" '
            . '\"%{Accept}i\" \"%{Accept-Language}i\" \"%{Accept-Encoding}i\" '
            . '\"%{Sec-CH-UA}i\" \"%{Sec-CH-UA-Platform}i\" \"%{Sec-CH-UA-Mobile}i\" '
            . '\"%{Sec-Fetch-Site}i\" \"%{Sec-Fetch-Mode}i\" \"%{Sec-Fetch-Dest}i\" \"%{Sec-Fetch-User}i\" '
            . '\"%{X-Forwarded-For}i\" \"%H\" \"%{SSL_PROTOCOL}x\" \"%{SSL_CIPHER}x\"" '
            . self::RECOMMENDED_NICKNAME;
    }

    /**
     * `combined` plus the request duration, for an operator who only wants the Performance view.
     *
     * NOT published as `combined`. Debian and Ubuntu define that nickname in apache2.conf and
     * redefining it inside a <VirtualHost> does not reliably win — configtest passes, the reload
     * succeeds, the lines keep coming out in the old shape, and no error log says why. See
     * DURATION_NICKNAME, which is where the name itself is decided.
     */
    public static function durationLogFormat(): string
    {
        return 'LogFormat "%h %l %u %t \"%r\" %>s %O %D \"%{Referer}i\" \"%{User-Agent}i\"" '
            . self::DURATION_NICKNAME;
    }

    /**
     * The `CustomLog` line that puts a nickname to work, which is the half people forget.
     *
     * Defining a format does nothing on its own. A format defined and never referenced is the
     * quietest version of this whole failure: the config is valid, the reload is clean, and the
     * log file is byte-for-byte what it was.
     */
    public static function customLogLine(string $nickname): string
    {
        return 'CustomLog ${APACHE_LOG_DIR}/example_com_access.log ' . $nickname;
    }

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
     * THE BEACON IS THREE GROUPS RATHER THAN ONE, and the two extra ones are the material an
     * operator used to have to go and find. The moment somebody is pasting the tag into their
     * template is the moment attaching an identity costs nothing, and it is the moment a
     * Content-Security-Policy will quietly stop the whole thing from working. Both are a single
     * paste, built from this installation's own address, so neither has to be adapted first.
     *
     * @return array<int,array{key:string,title:string,lines:string[],problem:string}>
     */
    public static function nextSteps(Config $cfg, string $root, bool $mayUseRequestHost = false): array
    {
        [$snippet, $problem] = self::beaconSnippet($cfg, $mayUseRequestHost);
        $ingestProblem = self::ingestProblem($cfg);
        $base = $problem === '' ? self::effectiveBaseUrl($cfg, $mayUseRequestHost) : '';
        $origin = $base === '' ? '' : Doc::cspOrigin($base);

        return [
            [
                'key'     => 'ingest',
                'title'   => 'Start reading the logs, now and after every reboot',
                'lines'   => $ingestProblem === '' ? self::ingestCommands($root) : [],
                'problem' => $ingestProblem,
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
            [
                'key'     => 'beacon-identity',
                'title'   => 'Optional: tell Loghound who the visitor is',
                'lines'   => $base === '' ? [] : [self::beaconIdentitySnippet($cfg, $base)],
                'problem' => $problem,
            ],
            [
                'key'     => 'beacon-csp',
                'title'   => 'If the measured site sends a Content-Security-Policy',
                'lines'   => $origin === '' ? [] : [Doc::cspDirectives($origin)],
                'problem' => $problem,
            ],
        ];
    }

    /**
     * The beacon tag with an identity on it, written the way somebody would actually paste it.
     *
     * The address comes out of the template's own user object rather than being a literal,
     * because a literal is the one form nobody can use unedited — and because the two values
     * have to change per request or a page cache will serve the first visitor's identity to
     * everyone else. The escaping is in the snippet for the same reason: an address with a
     * quote in it would otherwise break the tag.
     *
     * `data-params` rides along when this installation has configured parameters to collect, so
     * the identity snippet and the plain one never disagree about what the page sends.
     */
    private static function beaconIdentitySnippet(Config $cfg, string $base): string
    {
        return Doc::snippet($base, array_merge(Doc::configuredAttrs($cfg), [
            'data-ident'     => '<?= htmlspecialchars($user->email, ENT_QUOTES) ?>',
            'data-signed-in' => '<?= $user->isSignedIn() ? \'1\' : \'0\' ?>',
        ]));
    }

    /**
     * Running Loghound: what is on, how to watch it, how to stop it, how to remove it.
     *
     * Separate from nextSteps() because these are not setup steps — they are the answers an
     * operator needs on day two and at 3am, and a product that only documents how to turn
     * itself on is a product people are afraid to run. Every line names this installation's
     * own paths, so none of it has to be adapted before it is pasted.
     *
     * One line per group, for the same reason nextSteps() is: each sits under a copy button
     * that promises a single paste.
     *
     * @return array<int,array{key:string,title:string,lines:array<int,string>,problem:string}>
     */
    public static function operations(string $root): array
    {
        $root  = rtrim($root, '/');
        $units = 'loghound-tail.service loghound-score.timer loghound-retention.timer';

        return [
            [
                'key'     => 'units',
                'title'   => 'What is running, and whether it comes back after a reboot',
                'lines'   => ['systemctl --no-pager status ' . $units],
                'problem' => '',
            ],
            [
                'key'     => 'journal',
                'title'   => 'Watch what the reader is doing, live',
                'lines'   => ['sudo journalctl -u loghound-tail.service -f'],
                'problem' => '',
            ],
            /* THE FILE ONLY EXISTS IF install.sh WROTE THE POOL. `var/php-error.log` is named
               by `php_admin_value[error_log]` in the FPM pool install.sh generates, so a tree
               deployed any other way — copied into place, checked out, provisioned by a
               control panel — has the code and no such file, and this copy button handed that
               operator `tail: cannot open … No such file or directory`. ingestCommands() two
               methods below already reasons about exactly that deployment and conditionalises
               itself on unitsInstalled(); this did not. When the file is not there the command
               that FINDS the log is given instead, which works on every deployment. */
            [
                'key'     => 'ownlog',
                'title'   => 'Its own errors, if a page misbehaves',
                'lines'   => is_file($root . '/var/php-error.log')
                    ? ['sudo tail -n 100 ' . $root . '/var/php-error.log']
                    : [
                        '# This installation has no ' . $root . '/var/php-error.log, so PHP is',
                        '# logging elsewhere. This says where:',
                        'php -i | grep -E \'^(error_log|log_errors)\'',
                    ],
                'problem' => '',
            ],
            [
                'key'     => 'stop',
                'title'   => 'Stop it, and keep it stopped across reboots',
                'lines'   => ['sudo systemctl disable --now ' . $units],
                'problem' => '',
            ],
            [
                'key'     => 'uninstall',
                'title'   => 'Remove Loghound from this machine',
                'lines'   => ['sudo ' . $root . '/install/uninstall.sh'],
                'problem' => '',
            ],
        ];
    }

    /**
     * The reason starting the daemon would fail right now, or an empty string.
     *
     * The ingest command is shown on the last screen of the installer, where setup has not
     * been finished — and until it is, `beacon.secret` and the address salt do not exist,
     * because ensureSecrets() runs at finish. The daemon validates its configuration before
     * it does anything and exits 78/CONFIG on an incomplete one, straight into a restart
     * loop, with a message telling the operator to run install.sh, which is not the answer.
     *
     * So the command is withheld until it would work, and the screen says what to do instead.
     * A command printed next to a copy button is a promise that pasting it achieves
     * something; printing one that cannot yet succeed spends the operator's trust to save
     * ourselves a conditional.
     *
     * The daemon's own check is reused rather than a second list of preconditions here —
     * two lists disagree eventually, and the one that matters is the daemon's.
     */
    private static function ingestProblem(Config $cfg): string
    {
        if ($cfg->validate() === []) {
            return '';
        }

        /* ONE SENTENCE FOR TWO SCREENS. This array is rendered by the installer AND by the
           panel's Settings page, and the wording was written for the installer alone: it said
           "the button above", which is not on Settings, and "it is in Settings afterwards" to
           a reader who is already in Settings. Neither screen can be named here, so neither
           is. */
        return 'The configuration is not complete yet, so there is nothing to start: the ingest '
            . 'daemon reads it, checks it before it runs, and stops on an incomplete one. Finish '
            . 'the outstanding setup steps — each one says what it still needs — and this command '
            . 'appears here, ready to paste, as soon as it would work.';
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

        return $mayUseRequestHost
            ? self::requestBaseUrl((array) $cfg->get('trusted_proxies', []))
            : '';
    }

    /**
     * The address this request arrived on, or an empty string.
     *
     * The Host header is chosen by whoever sent the request, so it is shape-checked before
     * it is echoed into a page: a hostname or an IPv4 literal with an optional port, and
     * nothing else. A header carrying a path, a scheme, a credential or markup yields
     * nothing rather than a URL built around it.
     *
     * @param string[] $trustedProxies CIDRs whose X-Forwarded-Proto may be believed.
     */
    public static function requestBaseUrl(array $trustedProxies = []): string
    {
        $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
        if ($host === '' || strlen($host) > 255) {
            return '';
        }
        if (!preg_match('/^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$/D', $host)) {
            return '';
        }

        /* Through Security::isHttps(), which is the one place this question is answered. The
           inline expression it replaces said "http" behind every TLS-terminating proxy — so the
           beacon snippet the installer prints pointed at http:// on an https-only site and was
           silently blocked as mixed content — and said "https" on IIS, where the value is the
           literal string 'off' over plain HTTP. */
        $scheme = Security::isHttps($trustedProxies) ? 'https' : 'http';

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
     * EVERY REFUSAL NAMES THE FIX THAT IS IN FRONT OF THE READER, which is not the same fix on
     * both screens. `$mayUseRequestHost` is passed by exactly one caller — the installer's
     * sign-in screen, which is the only screen allowed to guess an address from the request —
     * and that screen renders the **Public URL** field about fifty lines above this message.
     * Telling that operator to go and hand-edit `base_url` in a file, while the input for it is
     * on the screen they are looking at, is an instruction that is worse than no instruction:
     * they will do it, and the form will overwrite it when they press the button. After setup
     * the flag is off, there is no such field on the page, and the file is the honest answer.
     *
     * THE TAG ITSELF IS BUILT BY Beacon\Doc AND NOWHERE ELSE. This method used to write out
     * `b.js?v=1`, hardcoded, while the panel built the same tag from the beacon file's own
     * modification time — so the snippet handed out at the end of setup pinned every visitor of
     * that site to the first version of the script for good, because `b.js` is served
     * `immutable` for a week and a fixed URL is never re-fetched.
     *
     * @return array{0:string,1:string} [snippet, problem] — exactly one is ever non-empty.
     */
    public static function beaconSnippet(Config $cfg, bool $mayUseRequestHost = false): array
    {
        $base = self::effectiveBaseUrl($cfg, $mayUseRequestHost);

        $setIt = $mayUseRequestHost
            ? 'Fill in the "Public URL" field on this screen — it is just above this card — and '
                . 'press the button; the snippet is then on the Settings page.'
            : 'Set base_url in config/loghound.php to the URL your visitors would reach this '
                . 'installation at, then come back.';

        $correctIt = $mayUseRequestHost
            ? 'Correct the "Public URL" field on this screen, just above this card, and press the '
                . 'button.'
            : 'Correct base_url in config/loghound.php.';

        if ($base === '') {
            return ['', 'The public address of this panel is not set, so there is no snippet to copy. '
                . $setIt];
        }
        if (Security::urlHasUserinfo($base)) {
            return ['', 'The configured address of this panel contains a username or password, which would '
                . 'be published in the HTML of every page you measure. It must be https://host/path only. '
                . $correctIt];
        }
        if (Security::safeUrl($base) === '#') {
            return ['', 'The configured address of this panel is not a plain http:// or https:// URL, so no '
                . 'snippet can be built from it. ' . $correctIt];
        }

        return [Doc::snippet($base, Doc::configuredAttrs($cfg)), ''];
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
        if (!is_array($doc)) {
            return ['state' => 'unreadable'] + $blank;
        }

        if (($doc['state'] ?? '') === 'refused') {
            $errors = [];
            foreach ((array) ($doc['errors'] ?? []) as $error) {
                if (is_string($error) && $error !== '') {
                    $errors[] = $error;
                }
            }

            return [
                'state'  => 'refused',
                'at'     => is_int($doc['at'] ?? null) ? $doc['at'] : null,
                'errors' => $errors,
            ] + $blank;
        }

        if (!is_string($doc['generated_at'] ?? null)) {
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
     * Why the beacon is worth the one line of HTML, in the words every surface uses.
     *
     * One paragraph, from Beacon\Doc, so the installer's last screen, the panel's finish card
     * and the shell wizard say the same thing. Plain sentences with no markup, because all
     * three render it as escaped prose.
     */
    public static function beaconRationale(): string
    {
        return Doc::rationale();
    }

    /**
     * Every option the beacon reads, in the one paragraph the installer screen has room for.
     *
     * KEPT UNDER THIS NAME BECAUSE THE INSTALLER'S LAST SCREEN CALLS IT, and because the
     * identity attributes are still what it leads with — they are the ones that cost nothing to
     * add while somebody is already pasting the tag, and the ones with a storage consequence
     * they have not consented to unless they were told. It now carries the rest of the option
     * list too: that screen has two prose slots and this is the one that answers "what else can
     * this tag do", which used to be answerable only by opening a JavaScript file.
     *
     * The text itself is Beacon\Doc::optionsNote(), so the panel's beacon card and this screen
     * cannot drift.
     */
    public static function beaconIdentityNote(): string
    {
        return Doc::optionsNote();
    }
}
