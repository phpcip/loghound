<?php
/**
 * Loghound — Settings and setup.
 *
 * The most important thing on this page is the **log format review**. SPEC §8 is blunt
 * about it: never silently ingest with a guessed format. So the detected mapping is shown
 * as a table of token → Loghound field, five real lines from the operator's own log are
 * rendered as the records they would become, a confidence percentage is printed, and
 * nothing is ingested from that source until someone presses "Looks right".
 *
 * THE SOURCE LIST IS EDITABLE FOR THE LIFE OF THE INSTALLATION, not only during setup. A
 * host added three months after the install used to mean hand-editing a PHP file that
 * deliberately lives outside the document root at mode 0640, so the three actions that make
 * a full loop are all here: `rescan` re-runs discovery, `confirm_source` starts ingesting a
 * file, `remove_source` stops. The rescan is a stepped job rather than a plain POST because
 * it walks the webserver configuration and samples up to twenty files, which is exactly the
 * kind of work that outlives PHP-FPM's execution limit; see rescanPlan().
 *
 * The page also owns the settings that change what gets stored about people — IP privacy
 * mode and retention — which are given their own section and plain-language consequences
 * rather than being buried in a list of toggles. Neither installer asks for them, so this
 * is the only place either one is chosen as well as the only place either is changed.
 *
 * Secrets (Opensolr API key, beacon HMAC secret, IP salt, Solr password) are NEVER echoed
 * back, not even masked in a value attribute. They are reported as present or absent.
 * SPEC §9: never print the API key back to the screen or into a log.
 *
 * State changes are ordinary form POSTs with a CSRF token, handled server-side and
 * followed by a redirect (POST/Redirect/GET), so the page works with JavaScript disabled
 * and a refresh never re-submits.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\LogDetect;
use Loghound\Security;
use Loghound\Setup\Detector;
use Loghound\Setup\Requirements;
use Loghound\Setup\Steps;

final class Settings extends Controller implements JobHost, Sections
{
    /**
     * Where `bin/loghound-setup` is expected to leave its detection report.
     *
     * This file is the contract between the setup tooling and this panel. Shape:
     * {generated_at:int, sources:[{path, server, vhost, format_name, format_string,
     * source, confidence:float, lines_tested:int, lines_parsed:int, confirmed:bool,
     * mapping:[{token, field, example}], missing:[{field, token, why}],
     * samples:[{raw, parsed:{field:value}}]}]}
     */
    private const DETECT_FILE = __DIR__ . '/../../var/detect.json';


    /**
     * The job kind that re-runs log discovery, registered by this view rather than built in.
     *
     * Not a plain POST action. Discovery walks the Apache and nginx configuration trees,
     * following every Include, and then tails and grades up to twenty candidate files. On a
     * box with twenty vhosts that is comfortably capable of outliving the reference install's
     * `max_execution_time = 60`, and an action that can be killed halfway is an action that
     * leaves the operator with a dead tab and no idea whether it ran.
     */
    private const KIND_RESCAN = 'source_rescan';

    public function slug(): string
    {
        return 'settings';
    }

    public function title(): string
    {
        return 'Settings';
    }

    public function subtitle(): string
    {
        return 'Log sources, storage, privacy, scoring and the beacon snippet.';
    }

    /**
     * Read-only JSON actions.
     *
     * `beacon` was a blocking Solr query inside body() and is now fetched by the page
     * after it has rendered, because a settings page must not wait on Solr to appear.
     * `job_latest` lets a reloaded page reattach to an operation that is still running.
     *
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'beacon'     => $this->envelope(['beacon' => $this->beaconStatus()]),
            'job_latest' => $this->latestJob(),
            default      => ['error' => 'Unknown action'],
        };
    }

    /**
     * Every job kind this view will start: the built-ins plus the ones it plans itself.
     *
     * The rescan is withheld in demo mode. Demo mode fabricates a traffic world and serves a
     * fabricated detection report, so a button on it that walked the real machine's webserver
     * configuration and overwrote the real `var/detect.json` would be doing something the
     * banner at the top of the page says is not happening. Withholding the kind here refuses
     * it at start, at poll and at cancel in one place rather than three.
     *
     * @return array<int,string>
     */
    private function jobKinds(): array
    {
        return array_merge(Jobs::KINDS, array_keys($this->jobPlans()));
    }

    /**
     * Planners for the job kinds this view supplies, keyed by kind.
     *
     * @return array<string,callable(array<string,mixed>):array<int,array{label:string,run:callable}>>
     */
    private function jobPlans(): array
    {
        if ($this->gw->isDemo()) {
            return [];
        }
        return [self::KIND_RESCAN => static fn (array $ctx): array => self::rescanPlan()];
    }

    /** The job store for this view, with this view's own planners registered. */
    private function jobs(): Jobs
    {
        return new Jobs($this->cfg, $this->gw, $this->jobPlans());
    }

    /**
     * Re-run log discovery and republish the detection report, in two bounded steps.
     *
     * SPLIT WHERE THE TIME ACTUALLY GOES. Step one reads the webserver configuration, which
     * is the unbounded half — it follows Include directives through whatever tree the
     * operator has — and stores only the small metadata map it produced. Step two samples and
     * grades each candidate, which is two hundred lines read from the end of each file, and
     * writes the report. Neither step is anywhere near the execution limit on its own, which
     * is the entire point of running this as a job.
     *
     * Nothing here ingests anything and nothing here changes the configuration: a rescan
     * republishes what is on the machine, and a source only starts being read when a human
     * presses "Looks right" (SPEC §8). Confirmations already in the config survive, because
     * Detector::report() carries them forward.
     *
     * Sample log lines are attacker-chosen bytes, so they go into the report file and never
     * into the job context, which travels back to the browser on every poll.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    private static function rescanPlan(): array
    {
        return [
            [
                'label' => 'Looking for access logs',
                'run'   => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $candidates = Detector::candidates($cfg, null);
                    $found = count($candidates);

                    return [
                        'note'    => $found . ' candidate file' . ($found === 1 ? '' : 's'),
                        'detail'  => $found === 0
                            ? 'Nothing matched your webserver configuration or the usual locations. '
                                . 'A path can still be added by hand with bin/loghound-setup.'
                            : 'Read from your webserver configuration where it could be, and from the '
                                . 'usual locations where it could not.',
                        'context' => ['candidates' => $candidates],
                    ];
                },
            ],
            [
                'label' => 'Reading each file and saving the report',
                'run'   => static function (array $ctx, Config $cfg, Gateway $gw): array {
                    $candidates = is_array($ctx['candidates'] ?? null)
                        ? $ctx['candidates']
                        : Detector::candidates($cfg, null);

                    $sources = [];
                    foreach ($candidates as $path => $meta) {
                        $sources[] = Detector::examine($cfg, (string) $path, (array) $meta);
                    }

                    $written = Detector::writeReport($cfg, Detector::report($sources, $cfg));
                    if ($written === null) {
                        return [
                            'ok'     => false,
                            'note'   => 'not saved',
                            'detail' => 'The detection report could not be written. Check that var/ exists '
                                . 'and is writable by the user this panel runs as.',
                        ];
                    }

                    $examined = count($sources);
                    return [
                        'note'    => $examined . ' file' . ($examined === 1 ? '' : 's') . ' examined',
                        'detail'  => 'The review below has been rebuilt. Nothing is ingested from a new '
                            . 'file until you confirm it.',
                        'context' => ['candidates' => [], 'examined' => $examined],
                    ];
                },
            ],
        ];
    }

    /**
     * The newest job of a requested kind belonging to this operator.
     *
     * The kind is checked against this view's own list before the store is touched, and the
     * store scopes every lookup to the caller's own session, so this cannot be used to read
     * somebody else's operation.
     *
     * @return array<string,mixed>
     */
    private function latestJob(): array
    {
        $kind = self::param('kind', $this->jobKinds(), '');
        if ($kind === '') {
            return ['error' => 'Unknown operation.'];
        }
        try {
            $job = $this->jobs()->latest($kind);
        } catch (\Throwable $e) {
            return ['error' => 'The job store is unavailable.'];
        }
        return $this->envelope(['job' => $job]);
    }

    /**
     * Act on a job only if it is one of THIS view's kinds.
     *
     * The store scopes every lookup to the signed-in operator, so an id can only ever name a
     * job they own — but ownership is not enough. Several views accept POSTs and each
     * registers a different set of planners, so advancing a job of another view's kind would
     * rebuild it against a plan that does not contain its steps: the store would find no step
     * at the job's index and mark an operation that had barely begun as finished. Checking
     * the kind first turns that into a refusal.
     *
     * A job of the wrong kind is reported exactly as one that does not exist, so an id cannot
     * be probed for which view owns it.
     *
     * @param callable(Jobs,string):array<string,mixed> $fn
     * @return array<string,mixed>
     */
    private function onOwnJob(Jobs $jobs, string $id, callable $fn): array
    {
        if ($id === '') {
            return ['error' => 'That operation is no longer available. Start it again.'];
        }
        $job = $jobs->get($id);
        if (!isset($job['kind']) || !in_array($job['kind'], $this->jobKinds(), true)) {
            return ['error' => 'That operation is no longer available. Start it again.'];
        }
        return $fn($jobs, $id);
    }

    /**
     * Handle one of the asynchronous job endpoints, answering with JSON.
     *
     * Reached through post(), so the front controller has already enforced both
     * authentication and the CSRF token: a job endpoint mutates state and is treated
     * exactly like any other state-changing request. Failure to open the store is
     * reported as a failure, never silently ignored.
     *
     * Declared `never` rather than `void`: both paths out of this method end in
     * sendJson(), which exits. Saying so in the signature is what lets post() write
     * `return $this->jobJson(...)` for each job case and stay exhaustive, instead of
     * relying on a fall-through that happens to be harmless only because this method
     * never comes back.
     *
     * @param callable(Jobs):array<string,mixed> $fn
     */
    private function jobJson(callable $fn): never
    {
        try {
            $jobs = $this->jobs();
        } catch (\Throwable $e) {
            error_log('[loghound-panel] job store: ' . Jobs::redact($e->getMessage()));
            self::sendJson(['error' => 'The job store could not be opened. Check that var/ is writable.'], 500);
        }
        $result = $fn($jobs);
        self::sendJson($result, isset($result['error']) ? 400 : 200);
    }

    /**
     * Handle a settings POST.
     *
     * CSRF has already been enforced by the front controller before this is reached.
     * Every value is validated here rather than trusted, and the config is only written
     * once validation passes, so a bad form submission cannot leave a config that stops
     * the daemons from starting.
     *
     * EVERY arm of the switch returns. The three job cases used to fall through, and were
     * correct only because jobJson() exits before the next case can run — so moving a case,
     * or giving jobJson() a way to come back, would have silently started running one
     * action's handler after another's.
     *
     * There is no `rescan` arm. A rescan is started through `job_start` with this view's own
     * kind, because it is a stepped job — see rescanPlan() for why it cannot be synchronous.
     * `remove_source` is destructive and is reachable only from here, which is only reachable
     * on POST: the front controller routes GET to api() and body(), neither of which writes.
     *
     * @return string The redirect query string to send the browser to.
     */
    public function post(): string
    {
        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';

        switch ($action) {
            case 'confirm_source':
                return $this->confirmSource();

            case 'remove_source':
                return $this->removeSource();

            case 'privacy':
                return $this->savePrivacy();

            case 'scoring':
                return $this->saveScoring();

            case 'ui':
                return $this->saveUi();

            case 'auth_mode':
                return $this->saveAuthMode();

            case 'job_start':
                return $this->jobJson(function (Jobs $jobs): array {
                    $kind = self::postParam('kind', $this->jobKinds());
                    return $kind === ''
                        ? ['error' => 'Unknown operation.']
                        : $jobs->start($kind);
                });

            case 'job_poll':
                return $this->jobJson(
                    fn (Jobs $jobs): array => $this->onOwnJob(
                        $jobs,
                        self::postJobId(),
                        static fn (Jobs $j, string $id): array => $j->advance($id)
                    )
                );

            case 'job_cancel':
                return $this->jobJson(
                    fn (Jobs $jobs): array => $this->onOwnJob(
                        $jobs,
                        self::postJobId(),
                        static fn (Jobs $j, string $id): array => $j->cancel($id)
                    )
                );

            default:
                return '?v=settings&err=unknown_action';
        }
    }

    /**
     * Read a POST field constrained to an allowlist.
     *
     * Returns the empty string when the value is absent or not on the list, so a caller
     * that forgets to check gets a value the job store will refuse rather than one it
     * will act on.
     *
     * @param array<int,string> $allowed
     */
    private static function postParam(string $key, array $allowed): string
    {
        $value = $_POST[$key] ?? null;
        return is_string($value) && in_array($value, $allowed, true) ? $value : '';
    }

    /**
     * Read a job id from a POST body, shape-checked before it reaches the store.
     */
    private static function postJobId(): string
    {
        $value = $_POST['id'] ?? null;
        return is_string($value) && Jobs::isJobId($value) ? $value : '';
    }

    /**
     * Persist the configuration and make the change visible to the very next request.
     *
     * config/loghound.php is a PHP file, so once it has been executed it lives in the
     * opcode cache. With the default opcache.revalidate_freq of 2 seconds, a settings
     * save followed immediately by another request can hand that request the OLD array
     * — which silently discards the change the operator just made. Invalidating the
     * entry closes that window. The guard matters because opcache is not always loaded.
     *
     * @return string|null Null on success, otherwise the flash error code.
     */
    private function persist(): ?string
    {
        try {
            $this->cfg->save();
        } catch (\Throwable $e) {
            return 'save_failed';
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate(__DIR__ . '/../../config/loghound.php', true);
        }
        return null;
    }

    /**
     * Mark a detected log source as reviewed and accepted.
     *
     * The flag is written into var/detect.json (the tailer reads it there) AND the source
     * is added to `sources` in the config, which is what actually enables ingestion. The
     * path is re-validated against `allowed_log_roots` on the way in: a detection file is
     * a file on disk, and a file on disk is not automatically trustworthy.
     *
     * THE STORED SHAPE IS THE ONE Setup\Steps::applySources() PRODUCES, and it has to be:
     * the installer and this page are documented as interchangeable, so a source confirmed
     * in either must ingest identically. `format_name` is stored only when it names a format
     * in the built-in library; anything else — the operator's own LogFormat/log_format
     * string copied out of their webserver config, or a custom regex from the SPEC §8 step 4
     * escape hatch — is stored as `format_string`, which is the actual definition. This page
     * used to store `format_name` unconditionally, so a custom-regex source confirmed here
     * ended up with the literal word "custom" as its format and the tailer, which resolves a
     * stored format by library name and otherwise by compiling it, could make nothing of it.
     *
     * A source with no usable format is refused rather than stored with a guess, for the
     * same reason applySources() refuses it: SPEC §8 forbids ingesting on a guessed format,
     * and 'combined' was a guess with a friendly name.
     */
    private function confirmSource(): string
    {
        $path = is_string($_POST['path'] ?? null) ? $_POST['path'] : '';
        $report = $this->detection();
        $found = null;
        foreach (($report['sources'] ?? []) as $src) {
            if (($src['path'] ?? null) === $path) {
                $found = $src;
                break;
            }
        }
        if ($found === null) {
            return '?v=settings&err=no_such_source';
        }

        $roots = (array) $this->cfg->get('allowed_log_roots', []);
        if (Security::safePath(dirname($path), $roots) === null) {
            return '?v=settings&err=path_not_allowed';
        }

        $stored = self::storedFormat($found);
        if ($stored === '') {
            return '?v=settings&err=no_usable_format';
        }

        $sources = (array) $this->cfg->get('sources', []);
        $already = false;
        foreach ($sources as $i => $s) {
            if (($s['path'] ?? null) === $path) {
                $sources[$i]['format'] = $stored;
                $sources[$i]['confirmed'] = true;
                $already = true;
            }
        }
        if (!$already) {
            $sources[] = [
                'path'      => $path,
                'format'    => $stored,
                'host'      => (string) ($found['vhost'] ?? ''),
                'confirmed' => true,
            ];
        }
        $this->cfg->set('sources', array_values($sources));

        $err = $this->persist();
        if ($err !== null) {
            return '?v=settings&err=' . $err;
        }

        $this->markConfirmed($path);
        return '?v=settings&ok=source_confirmed';
    }

    /**
     * Stop ingesting one configured log source.
     *
     * THE FORM NAMES THE SOURCE BY AN OPAQUE ID, NEVER BY A PATH OR A LIST POSITION, and the
     * server resolves that id against its own stored list. A path would have to be trusted or
     * re-derived, and a list index is worse still: the list is rebuilt on every render from a
     * file on disk, so a stale tab could delete a row nobody was looking at. The id is derived
     * from the stored path, so an id that matches nothing in the config matches nothing at
     * all — there is no request that can remove an entry the config does not already hold.
     *
     * Both halves of the loop are undone: the entry leaves `sources`, which is what actually
     * enables ingestion, and the detection report's `confirmed` flag is cleared so the source
     * reappears in the review below awaiting a decision rather than silently vanishing.
     * Nothing is deleted from Solr — documents already indexed from that file stay, because
     * "stop reading this file" and "forget what this file said" are different requests and
     * only one of them was made.
     *
     * Reachable on POST only: the front controller routes GET to api() and body().
     */
    private function removeSource(): string
    {
        $id = is_string($_POST['source'] ?? null) ? $_POST['source'] : '';
        if (!preg_match('/^[0-9a-f]{16}$/', $id)) {
            return '?v=settings&err=no_such_source';
        }

        $kept = [];
        $removed = null;
        foreach ((array) $this->cfg->get('sources', []) as $source) {
            $path = is_array($source) ? (string) ($source['path'] ?? '') : '';
            if ($path !== '' && hash_equals(self::sourceId($path), $id)) {
                $removed = $path;
                continue;
            }
            $kept[] = $source;
        }

        if ($removed === null) {
            return '?v=settings&err=no_such_source';
        }

        $this->cfg->set('sources', array_values($kept));

        $err = $this->persist();
        if ($err !== null) {
            return '?v=settings&err=' . $err;
        }

        $this->markConfirmed($removed, false);
        return '?v=settings&ok=source_removed';
    }

    /**
     * The opaque identifier a stored source is addressed by in a form.
     *
     * A truncated keyless digest of the path: stable across renders, so a form posted from a
     * page that has since been rebuilt still names the same source, and meaningless on its
     * own, so nothing about the filesystem travels through the browser. It is an addressing
     * scheme and not a secret — the authorisation is that the id must resolve against a path
     * ALREADY in this operator's configuration, which is checked at the point of use.
     */
    private static function sourceId(string $path): string
    {
        return substr(hash('sha256', $path), 0, 16);
    }

    /**
     * The value a confirmed source stores in `sources[].format`.
     *
     * One implementation of the rule Setup\Steps::applySources() applies, so the browser
     * installer, the shell wizard and this page cannot drift apart: a library name is stored
     * as the name, and anything else is stored as the definition it was detected from. An
     * empty return means the detector never worked out a usable format and the source must
     * be refused, not stored with a default.
     *
     * @param array<string,mixed> $source One entry of the detection report.
     */
    private static function storedFormat(array $source): string
    {
        $name = (string) ($source['format_name'] ?? '');
        if ($name === '' || $name === 'unknown' || $name === 'unrecognised') {
            return '';
        }
        $definition = (string) ($source['format_string'] ?? '');
        if (!array_key_exists($name, LogDetect::library()) && $definition !== '') {
            return $definition;
        }
        return $name;
    }

    /**
     * Persist the reviewed flag back into the detection report.
     *
     * Best-effort: the config write is what matters, and a read-only var/ should not turn a
     * successful confirmation — or a successful removal — into an error. Clearing the flag is
     * the same operation in reverse, so it is the same code: a removed source has to go back
     * to "awaiting review" rather than disappear, or the only way to change your mind again
     * would be another full rescan.
     */
    private function markConfirmed(string $path, bool $confirmed = true): void
    {
        if (!is_file(self::DETECT_FILE) || !is_writable(self::DETECT_FILE)) {
            return;
        }
        $raw = file_get_contents(self::DETECT_FILE);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)) {
            return;
        }
        foreach (($data['sources'] ?? []) as $i => $src) {
            if (($src['path'] ?? null) === $path) {
                $data['sources'][$i]['confirmed'] = $confirmed;
            }
        }
        @file_put_contents(self::DETECT_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Save the privacy section, refusing anything outside the documented values.
     *
     * THIS IS THE ONLY PLACE EITHER SETTING IS CHOSEN. Neither installer asks for them, so a
     * configuration reaching here may never have had an answer beyond Config::defaults().
     *
     * Hash mode is the one mode that needs `privacy.ip_salt`, and it is minted here if it is
     * missing — setup mints one for every installation, but a configuration written by hand,
     * or one whose salt was shredded, must not be able to select a mode whose secret does not
     * exist. Steps::ipModes() is the list both this and the wizard validate against.
     */
    private function savePrivacy(): string
    {
        $mode = is_string($_POST['ip_mode'] ?? null) ? $_POST['ip_mode'] : '';
        if (!in_array($mode, Steps::ipModes(), true)) {
            return '?v=settings&err=bad_ip_mode';
        }
        $days = Security::clampInt($_POST['retention_days'] ?? null, 0, 3650, 90);

        if ($mode === 'hash' && strlen((string) $this->cfg->get('privacy.ip_salt', '')) < 16) {
            $this->cfg->set('privacy.ip_salt', bin2hex(random_bytes(24)));
        }

        $this->cfg->set('privacy.ip_mode', $mode);
        $this->cfg->set('privacy.retention_days', $days);
        $this->cfg->set('privacy.rollup_forever', isset($_POST['rollup_forever']));

        $err = $this->persist();
        return $err !== null ? '?v=settings&err=' . $err : '?v=settings&ok=privacy_saved';
    }

    /**
     * Save scoring weights and thresholds.
     *
     * `rule_version_i` is bumped on every change so that historical documents scored
     * under the old weights remain traceable (SPEC §7). Weights are keyed by rule code
     * and only codes the panel knows about are accepted, so the config cannot accumulate
     * junk keys from a crafted form post.
     */
    private function saveScoring(): string
    {
        $known = array_keys(Bots::reasonCatalogue());
        $weights = [];
        $posted = $_POST['weight'] ?? [];
        if (is_array($posted)) {
            foreach ($posted as $code => $value) {
                if (!is_string($code) || !in_array($code, $known, true)) {
                    continue;
                }
                $weights[$code] = Security::clampInt($value, 0, 100, 0);
            }
        }

        $t = [];
        foreach (['bot' => 80, 'likely_bot' => 60, 'unknown' => 40, 'likely_human' => 20] as $k => $default) {
            $t[$k] = Security::clampInt($_POST['threshold'][$k] ?? null, 0, 100, $default);
        }
        if (!($t['bot'] > $t['likely_bot'] && $t['likely_bot'] > $t['unknown'] && $t['unknown'] > $t['likely_human'])) {
            return '?v=settings&err=bad_thresholds';
        }

        $this->cfg->set('scoring.weights', $weights);
        $this->cfg->set('scoring.thresholds', $t);
        $this->cfg->set('scoring.rule_version', ((int) $this->cfg->get('scoring.rule_version', 1)) + 1);

        $err = $this->persist();
        return $err !== null ? '?v=settings&err=' . $err : '?v=settings&ok=scoring_saved';
    }

    /**
     * Switch between Basic authentication and the sign-in page.
     *
     * The choice used to exist only during installation, so changing your mind afterwards
     * meant hand-editing config/loghound.php — on a file the panel deliberately keeps
     * outside the document root and at mode 0640.
     *
     * The decision itself is Setup\Steps::applyAuthMode(), which is also what the installer
     * calls: it refuses a mode that is not in Security::authModes(), and it refuses to move
     * to either mode before a username and a password hash exist, so this form cannot leave
     * the panel with no way in. Nothing here re-implements that check.
     */
    private function saveAuthMode(): string
    {
        $mode = is_string($_POST['auth_mode'] ?? null) ? $_POST['auth_mode'] : '';

        if (Steps::applyAuthMode($this->cfg, $mode) !== []) {
            return '?v=settings&err=bad_auth_mode';
        }

        $err = $this->persist();
        return $err !== null ? '?v=settings&err=' . $err : '?v=settings&ok=auth_saved';
    }

    /**
     * How you sign in to this panel, changeable after installation.
     *
     * The two choices and their wording come from Security::authModes(), the same list the
     * installer renders and the same list Steps::applyAuthMode() validates against, so the
     * form can never offer a mode the config would refuse or describe one differently from
     * the way the wizard described it.
     *
     * The username and password are NOT editable here. They are set by the installer or by
     * bin/loghound-setup, and a form that could change the panel's own credentials while
     * authenticated by them is a much larger blast radius than this section is worth.
     */
    private function authSection(): void
    {
        $mode = (string) $this->cfg->get('auth.mode', 'none');
        $haveAccount = (string) $this->cfg->get('auth.password_hash', '') !== ''
            && (string) $this->cfg->get('auth.user', '') !== '';

        self::cardOpen(
            'set-auth',
            self::sectionNum('set-auth'),
            'Sign-in',
            'Applies to the next request. Changing this does not change your username or password.'
        );

        if (!$haveAccount) {
            echo '<div class="banner banner-warn">No username and password are stored, so there is nothing to '
                . 'sign in with yet. Set them with <code>bin/loghound-setup</code> first.</div>';
            self::cardEnd();
            return;
        }

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="auth_mode">';

        echo '<fieldset><legend>How you sign in</legend>';
        foreach (Security::authModes() as $val => $meta) {
            echo '<label class="radio"><input type="radio" name="auth_mode" value="' . Security::esc($val) . '"'
                . ($mode === $val ? ' checked' : '') . '>';
            echo '<span><strong>' . Security::esc($meta['label']) . '</strong><br><span class="muted">'
                . Security::esc($meta['text']) . ' ' . Security::esc($meta['cost'])
                . '</span></span></label>';
        }
        echo '</fieldset>';

        echo '<button type="submit" class="primary">Save sign-in method</button>';
        echo '</form>';
        echo '<p class="muted">The sign-in page keeps session files in the directory named by '
            . '<code>session.save_path</code> in your PHP-FPM pool. If you have never used it, create that '
            . 'directory and give it to the user this panel runs as before switching.</p>';
        self::cardEnd();
    }

    /** Save display preferences: timezone used for rendering timestamps. */
    private function saveUi(): string
    {
        $tz = is_string($_POST['timezone'] ?? null) ? $_POST['timezone'] : 'UTC';
        if (!in_array($tz, \DateTimeZone::listIdentifiers(), true)) {
            return '?v=settings&err=bad_timezone';
        }
        $this->cfg->set('ui.timezone', $tz);
        $err = $this->persist();
        return $err !== null ? '?v=settings&err=' . $err : '?v=settings&ok=ui_saved';
    }

    /**
     * Load the detection report, or the demo one.
     *
     * @return array<string,mixed>
     */
    private function detection(): array
    {
        if ($this->gw->isDemo()) {
            return Fixtures::detection();
        }
        if (is_file(self::DETECT_FILE) && is_readable(self::DETECT_FILE)) {
            $raw = file_get_contents(self::DETECT_FILE);
            $data = is_string($raw) ? json_decode($raw, true) : null;
            if (is_array($data)) {
                return $data;
            }
        }
        return ['sources' => []];
    }

    /** Flash messages, keyed so nothing from the query string is ever echoed raw. */
    private static function flash(): void
    {
        $ok = [
            'source_confirmed' => 'Log source confirmed. The tailer will pick it up on its next poll.',
            'source_removed'   => 'Log source removed. The tailer stops reading it on its next poll; '
                . 'documents already indexed from it are untouched.',
            'sources_rescanned' => 'The scan finished and the review below has been rebuilt. Nothing is '
                . 'ingested from a newly found file until you confirm it.',
            'privacy_saved'    => 'Privacy settings saved.',
            'scoring_saved'    => 'Scoring weights saved. The rule version was bumped so older verdicts stay traceable.',
            'ui_saved'         => 'Display settings saved.',
            'auth_saved'       => 'Sign-in method saved. It applies to the next request, so you may be asked '
                . 'to sign in again.',
            'solr_up'          => 'Solr answered. The connection is working.',
        ];
        $err = [
            'solr_down'       => 'Solr did not answer. Check the base URL, credentials and firewall.',
            'no_such_source'  => 'That log source is not in the detection report or the configuration any '
                . 'more. Run a scan to rebuild the list.',
            'path_not_allowed' => 'That path is outside allowed_log_roots and was refused.',
            'no_usable_format' => 'No usable log format was worked out for that file, so it was not '
                . 'stored. Set one by hand with bin/loghound-setup rather than ingesting on a guess.',
            'save_failed'     => 'The configuration file could not be written. Check ownership and mode 0640 on config/loghound.php.',
            'bad_ip_mode'     => 'Unknown IP privacy mode.',
            'bad_thresholds'  => 'Thresholds must descend: bot > likely_bot > unknown > likely_human.',
            'bad_timezone'    => 'Unknown timezone.',
            'bad_auth_mode'   => 'That sign-in method was refused. Choose one of the two offered, and note that '
                . 'neither can be selected before a username and password have been set.',
            'unknown_action'  => 'Unknown action.',
        ];

        $k = is_string($_GET['ok'] ?? null) ? $_GET['ok'] : '';
        if (isset($ok[$k])) {
            echo '<div class="banner banner-good" role="status">' . Security::esc($ok[$k]) . '</div>';
        }
        $k = is_string($_GET['err'] ?? null) ? $_GET['err'] : '';
        if (isset($err[$k])) {
            echo '<div class="banner banner-bad" role="alert">' . Security::esc($err[$k]) . '</div>';
        }
    }

    /** Emit the hidden CSRF field every form on this page carries. */
    private static function csrfField(): void
    {
        echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';
    }

    /**
     * The sections on this page, in the order they render.
     *
     * One list drives three things that used to be maintained separately and drifted: the
     * order sections are rendered in, the number printed on each card, and the jump bar.
     * Before it, two cards both claimed 02 and two both claimed 03.
     *
     * The second element is the JUMP-BAR label, not the card's heading, and it is short
     * because the bar is one row that never wraps — eleven headings at full length do not fit
     * on a line at any realistic width. The heading stays in each section's own cardOpen().
     *
     * @var array<int,array{0:string,1:string,2:string}> id, nav label, renderer
     */
    private const SECTIONS = [
        ['set-finish', 'Finish setup', 'finishSection'],
        ['set-ops', 'Running it', 'operationsSection'],
        ['set-check', 'System check', 'systemCheckSection'],
        ['set-sources', 'Log sources', 'sourcesSection'],
        ['set-solr', 'Solr', 'solrSection'],
        ['set-beacon', 'Beacon', 'beaconSection'],
        ['set-privacy', 'Privacy', 'privacySection'],
        ['set-retention', 'Retention', 'retentionSection'],
        ['set-scoring', 'Scoring', 'scoringSection'],
        ['set-auth', 'Sign-in', 'authSection'],
        ['set-display', 'Display', 'displaySection'],
    ];

    /**
     * The card list, for the jump bar Layout pins above the page and for the numbering.
     *
     * The bar itself used to be emitted here, inside `.view`, and did not work: `.view` is a
     * flex column, and a `position: sticky` child of a flex container is sticky within its own
     * flex item box — a box exactly as tall as the bar — so it had no travel and scrolled away
     * once the reader passed the sixth card. Layout renders it as a sibling of `.view`, where
     * its containing block is the whole page.
     *
     * @return array<int,array<int,string>>
     */
    public function sections(): array
    {
        return self::SECTIONS;
    }

    /** The number a card carries, from its position in SECTIONS rather than a literal. */
    private static function sectionNum(string $id): string
    {
        return Layout::cardNum(self::SECTIONS, $id);
    }

    public function body(): void
    {
        self::flash();

        foreach (self::SECTIONS as [$id, $label, $method]) {
            $this->{$method}();
        }
    }

    /**
     * The installer's "After you finish" screen, kept for the life of the installation.
     *
     * THE DEFECT THIS FIXES. Those instructions used to exist once, on the last screen of
     * the installer, under a line saying to copy them now because the screen was about to
     * disappear. An operator who clicked through — or whose tab was closed under them —
     * lost the two things that make Loghound collect anything, and nothing in the panel
     * afterwards said ingestion had never been started or that the beacon was never added.
     *
     * It is the FIRST card on this page, above the log sources, because an operator who
     * has never seen the installer's last screen has to find it without being told where
     * to look, and because Layout's banner points here from every other view when
     * ingestion is not running.
     *
     * The content is Steps::nextSteps(), the same array the installer renders — there is
     * one copy of these commands in the product, not two.
     *
     * Two health facts are reported, and neither is guessed:
     *  - Ingestion, from the status document `bin/loghound-tail` writes about itself once a
     *    second and `--status` reads. Rendered server-side; it is a local file read.
     *  - The beacon, from beaconStatus(), which asks the sessions core whether any beacon
     *    data has ever arrived. Fetched after render by settings.js, because a settings
     *    page must not block on Solr.
     *
     * What is NOT reported is whether the units are enabled at boot. `systemctl enable`
     * does persist across a reboot, and the group title says so, but this panel cannot
     * verify it: there is no exec, shell_exec, proc_open or SSH anywhere in src/, bin/ or
     * public/, that is a published property of Loghound, and it is not being traded for a
     * status badge. The liveness figure above is real evidence; boot persistence is stated
     * as what the command buys, never as something that has been checked.
     */
    private function finishSection(): void
    {
        $ingest = Steps::ingestStatus(self::root());
        $healthy = $ingest['state'] === 'live';

        self::cardOpen(
            'set-finish',
            self::sectionNum('set-finish'),
            'Finish setting up',
            'Setup writes the configuration. It does not start the ingest daemon and it cannot add the beacon '
            . 'to your site; both are done here, once, by hand.'
        );

        echo '<div class="finish-state ' . ($healthy ? 'finish-ok' : 'finish-bad') . '" id="finish-ingest"'
            . ' role="status">';
        echo '<span class="finish-dot" aria-hidden="true"></span>';
        echo '<div class="finish-text"><strong>' . Security::esc(self::ingestLabel($ingest)) . '</strong>';
        echo '<span class="muted">' . Security::esc(self::ingestDetail($ingest)) . '</span>';
        echo '</div></div>';

        echo '<div class="finish-state finish-unknown" id="finish-beacon" role="status">';
        echo '<span class="finish-dot" aria-hidden="true"></span>';
        echo '<div class="finish-text"><strong id="finish-beacon-label">Beacon: checking</strong>';
        echo '<span class="muted" id="finish-beacon-detail">Asking the sessions core whether any beacon data has '
            . 'ever arrived. The beacon is optional; without it the execution plane is blind.</span>';
        echo '</div></div>';

        echo '<details class="finish-all" id="finish-all"' . ($healthy ? '' : ' open') . '>';
        echo '<summary>The commands, and the one line of HTML</summary>';

        foreach (Steps::nextSteps($this->cfg, self::root()) as $group) {
            $key = (string) $group['key'];
            echo '<div class="finish-group" id="finish-g-' . Security::esc($key) . '">';
            echo '<h3>' . Security::esc((string) $group['title']) . '</h3>';
            if ($key === 'ingest') {
                echo '<p class="muted">One command. <code>enable --now</code> starts the service and both '
                    . 'timers immediately and brings them back after a reboot; this panel reports whether '
                    . 'they are running, and cannot see whether they are enabled at boot.</p>';
            }
            self::commandBlock('finish-cmd-' . $key, $group);
            echo '</div>';
        }

        echo '</details>';
        echo '<p class="muted">' . Security::esc(Steps::beaconRationale()) . '</p>';
        self::cardEnd();
    }

    /**
     * The installer's system check, kept available after the installer is gone.
     *
     * Every one of these can break AFTER a successful install and nothing else would say so:
     * an open_basedir narrowed by a PHP upgrade, a log directory whose permissions changed
     * under a distribution update, an extension dropped by a package change. The installer
     * knew how to report each of them and exactly which command fixes it, and all of that
     * disappeared the moment setup completed — leaving the operator with a panel that shows
     * nothing and no way to find out why.
     *
     * The same Requirements the installer runs, so the two cannot disagree. Failures are
     * shown expanded with their fix; a clean machine gets one line and the whole list behind
     * a disclosure, because a card that shouts on a healthy install is a card people stop
     * reading.
     */
    private function systemCheckSection(): void
    {
        $req  = new Requirements(self::root(), $this->cfg);
        $rows = $req->all();

        $bad = [];
        foreach ($rows as $row) {
            if ((string) $row['state'] !== 'pass') {
                $bad[] = $row;
            }
        }

        self::cardOpen(
            'set-check',
            self::sectionNum('set-check'),
            'System check',
            'What this installation needs from the machine, re-checked every time you open this page.'
        );

        echo '<p class="muted">Checked as <code>' . Security::esc(Requirements::phpUser())
            . '</code>, the user this page runs as. Any command below is written for that user.</p>';

        if ($bad === []) {
            echo '<div class="finish-state finish-ok" role="status">';
            echo '<span class="finish-dot" aria-hidden="true"></span>';
            echo '<div class="finish-text"><strong>Everything this installation needs is in place.</strong>';
            echo '<span class="muted">' . count($rows) . ' checks, all passing.</span>';
            echo '</div></div>';
        } else {
            foreach ($bad as $row) {
                self::checkRow($row);
            }
        }

        echo '<details class="finish-all"' . ($bad === [] ? '' : ' open') . '>';
        echo '<summary>Every check, including the ones that pass</summary>';
        foreach ($rows as $row) {
            self::checkRow($row);
        }
        echo '</details>';

        self::cardEnd();
    }

    /**
     * One requirement, with the command that fixes it when there is one.
     *
     * @param array<string,mixed> $row From Requirements::all().
     */
    private static function checkRow(array $row): void
    {
        $state = (string) $row['state'];
        $chip  = $state === 'pass' ? 'chip-good' : ($state === 'warn' ? 'chip-warn' : 'chip-bad');
        $word  = $state === 'pass' ? 'OK' : ($state === 'warn' ? 'Note' : 'Fix');

        echo '<div class="check-row">';
        echo '<p><span class="chip ' . $chip . '">' . $word . '</span> <strong>'
            . Security::esc((string) $row['label']) . '</strong></p>';
        echo '<p class="muted">' . Security::esc((string) $row['detail']) . '</p>';

        $fix = array_values(array_filter(
            array_map('strval', (array) $row['fix']),
            static fn (string $line): bool => trim($line) !== ''
        ));
        if ($fix !== []) {
            self::commandBlock(
                'check-fix-' . substr(hash('sha256', (string) $row['label']), 0, 12),
                ['key' => 'fix', 'title' => '', 'lines' => $fix, 'problem' => '']
            );
        }
        echo '</div>';
    }

    /**
     * Running it: what is on, how to watch it, how to stop it, how to remove it.
     *
     * Its own card, always visible, never behind a disclosure. An operator who installs
     * something is entitled to know how to see what it is doing and how to get rid of it
     * without going to look for documentation, and a product that only explains how to turn
     * itself on is one people are reluctant to run at all.
     *
     * Every command names this installation's own paths and units, so none of it has to be
     * adapted before it is pasted.
     */
    private function operationsSection(): void
    {
        self::cardOpen(
            'set-ops',
            self::sectionNum('set-ops'),
            'Running it',
            'Everything Loghound put on this machine, and how to inspect, stop or remove it.'
        );

        echo '<p class="muted">Three units do the work, and nothing else runs. '
            . '<code>loghound-tail.service</code> reads the logs continuously; '
            . '<code>loghound-score.timer</code> scores finished sessions about once a minute; '
            . '<code>loghound-retention.timer</code> trims old data once a day. The panel you are '
            . 'reading is served by your web server and stores nothing itself.</p>';

        foreach (Steps::operations(self::root()) as $group) {
            $key = (string) $group['key'];
            echo '<div class="finish-group" id="ops-g-' . Security::esc($key) . '">';
            echo '<h3>' . Security::esc((string) $group['title']) . '</h3>';
            if ($key === 'uninstall') {
                echo '<p class="muted">Stops and removes the units, the timers, the service user and the '
                    . 'files, and shreds every secret rather than unlinking it. It asks before it deletes '
                    . 'anything, it asks separately before deleting the two Opensolr indexes, and '
                    . '<code>--dry-run</code> prints every action without doing any of them.</p>';
            }
            self::commandBlock('ops-cmd-' . $key, $group);
            echo '</div>';
        }

        self::cardEnd();
    }

    /**
     * The installation root, as the setup steps expect to be handed it.
     *
     * Steps::nextSteps() builds the `bin/loghound-tail --status` line from it and
     * Steps::ingestStatus() finds the tailer's status document under it, so the panel and
     * the installer describe the same checkout. Resolved rather than concatenated, so the
     * command the operator copies has no `/../..` in the middle of it.
     */
    private static function root(): string
    {
        $root = dirname(__DIR__, 2);
        $real = realpath($root);
        return $real === false ? $root : $real;
    }

    /**
     * The headline sentence for whatever the tailer last said about itself.
     *
     * @param array<string,mixed> $ingest From Steps::ingestStatus().
     */
    private static function ingestLabel(array $ingest): string
    {
        return match ((string) $ingest['state']) {
            'live'  => 'Ingestion: running',
            'stale' => 'Ingestion: stopped',
            'refused' => 'Ingestion: refused to start',
            'unreadable' => 'Ingestion: cannot tell',
            default => 'Ingestion: never started',
        };
    }

    /**
     * The supporting line: what was measured, and what to do when it is bad.
     *
     * Numbers only where there are numbers. SPEC §1 forbids inventing one, so an absent
     * lag or line count is simply not mentioned rather than printed as zero.
     *
     * @param array<string,mixed> $ingest From Steps::ingestStatus().
     */
    private static function ingestDetail(array $ingest): string
    {
        if ((string) $ingest['state'] === 'unreadable') {
            return $ingest['file'] . ' exists but is not a status document. Check that the user '
                . 'bin/loghound-tail runs as can write it.';
        }
        if ((string) $ingest['state'] === 'refused') {
            $why = implode(' · ', array_slice((array) ($ingest['errors'] ?? []), 0, 3));

            return 'The daemon started, refused the configuration and stopped'
                . ($why === '' ? '' : ': ' . $why)
                . '. Fix that, then start it again — systemd does not retry this by itself, '
                . 'deliberately, because it is not a condition that resolves on its own.';
        }
        if ((string) $ingest['state'] === 'absent') {
            return 'Nothing has ever written ' . $ingest['file'] . ', so no log line has been read on this '
                . 'machine. Run the first command below.';
        }

        $age = (int) $ingest['age_sec'];
        $parts = ['Last read ' . $age . ' second' . ($age === 1 ? '' : 's') . ' ago'];
        if ($ingest['sources'] !== null) {
            $parts[] = (int) $ingest['sources'] . ' log file' . ((int) $ingest['sources'] === 1 ? '' : 's');
        }
        if ($ingest['lines'] !== null) {
            $parts[] = number_format((int) $ingest['lines']) . ' lines read';
        }
        if ($ingest['lag_bytes'] !== null) {
            $parts[] = number_format((int) $ingest['lag_bytes']) . ' bytes behind';
        }

        $line = implode(' · ', $parts) . '.';

        return (string) $ingest['state'] === 'live'
            ? $line
            : $line . ' The daemon stops updating that record within a second of dying, so this one is '
                . 'leftovers. Start it again with the first command below.';
    }

    /**
     * One pasteable command, with its copy control.
     *
     * Byte-identical in behaviour to the installer's own block (Setup\View::commandBlock):
     * both render a `data-copy` button with no handler attribute — the CSP is
     * `script-src 'self'` — and both are wired by public/assets/js/copy.js, which the
     * panel bundle and the installer bundle each import. A group carrying a `problem`
     * instead of a command renders the sentence and no button, because a copy control over
     * a block with nothing in it hands the operator an empty clipboard.
     *
     * @param array{key:string,title:string,lines:string[],problem:string} $group
     */
    private static function commandBlock(string $id, array $group): void
    {
        if ((string) $group['problem'] !== '') {
            echo '<div class="banner banner-warn">' . Security::esc((string) $group['problem']) . '</div>';
            return;
        }

        echo '<div class="snippet-block">';
        echo '<pre class="snippet mono" id="' . Security::esc($id) . '">';
        echo Security::esc(implode("\n", $group['lines']));
        echo '</pre>';
        echo '<button type="button" class="copy-btn" data-copy="' . Security::esc($id) . '"'
            . ' aria-live="polite">Copy</button>';
        echo '</div>';
    }

    /**
     * The log-format review. The single most important control on this page.
     *
     * Three controls, which together are the whole life cycle of a log source: scan for
     * files, start reading one, stop reading one. Before these existed the list was whatever
     * the installer had left behind, and a vhost added months later meant editing a PHP file
     * by hand outside the document root.
     */
    private function sourcesSection(): void
    {
        $report = $this->detection();
        $sources = (array) ($report['sources'] ?? []);
        $configured = [];
        foreach ((array) $this->cfg->get('sources', []) as $s) {
            if (isset($s['path'])) {
                $configured[(string) $s['path']] = !empty($s['confirmed']);
            }
        }

        self::cardOpen(
            'set-sources',
            self::sectionNum('set-sources'),
            'Log sources',
            'Detected by reading your webserver configuration where possible, and by scoring sample lines against '
            . 'the known-format library where it is not. Nothing is ingested until you confirm the mapping below.'
        );

        $this->rescanControl();

        if ($sources === []) {
            echo '<div class="empty show">';
            echo '<h3>No log sources detected yet</h3>';
            echo '<p>Use <strong>Scan this server again</strong> above, or run the setup command. Either one reads '
                . 'your Apache or nginx configuration, finds the <code>CustomLog</code> / <code>access_log</code> '
                . 'directives, works out the exact format for each one, and writes the result to '
                . '<code>var/detect.json</code>:</p>';
            echo '<pre class="snippet mono">sudo -u loghound php bin/loghound-setup detect</pre>';
            echo '<p>Then reload this page to review what it found.</p>';
            echo '</div>';
            $this->orphanSources($sources);
            self::cardEnd();
            return;
        }

        foreach ($sources as $src) {
            $path = (string) ($src['path'] ?? '');
            $confidence = (float) ($src['confidence'] ?? 0);
            $confirmed = !empty($src['confirmed']) || !empty($configured[$path]);

            echo '<article class="source">';
            echo '<div class="source-head">';
            echo '<h3 class="mono">' . Security::esc($path) . '</h3>';
            echo '<span class="chip ' . ($confirmed ? 'chip-good' : 'chip-warn') . '">'
                . ($confirmed ? 'Confirmed' : 'Awaiting review') . '</span>';
            echo '</div>';

            echo '<dl class="kv">';
            echo '<dt>Server</dt><dd class="mono">' . Security::esc((string) ($src['server'] ?? 'unknown')) . '</dd>';
            if (!empty($src['vhost'])) {
                echo '<dt>Virtual host</dt><dd class="mono">' . Security::esc((string) $src['vhost']) . '</dd>';
            }
            echo '<dt>Format</dt><dd class="mono">' . Security::esc((string) ($src['format_name'] ?? 'custom')) . '</dd>';
            echo '<dt>Confidence</dt><dd><span class="mono">' . Security::esc(number_format($confidence, 1)) . '%</span> '
                . '<span class="meter" role="img" aria-label="'
                . Security::esc(number_format($confidence, 1)) . ' percent of sample lines parsed cleanly">'
                . '<span class="meter-fill" style="width:' . Security::esc((string) max(0, min(100, $confidence))) . '%"></span></span> '
                . '<span class="muted">' . Security::esc((string) ($src['lines_parsed'] ?? 0)) . ' of '
                . Security::esc((string) ($src['lines_tested'] ?? 0)) . ' sample lines parsed cleanly</span></dd>';
            if (!empty($src['source'])) {
                echo '<dt>Detected from</dt><dd>' . Security::esc((string) $src['source']) . '</dd>';
            }
            if (!empty($src['format_string'])) {
                echo '<dt>Format string</dt><dd><code class="mono wrap">'
                    . Security::esc((string) $src['format_string']) . '</code></dd>';
            }
            echo '</dl>';

            $mapping = (array) ($src['mapping'] ?? []);
            if ($mapping !== []) {
                echo '<h4>Field mapping</h4>';
                echo '<div class="table-wrap"><table class="tight"><thead><tr>'
                    . '<th scope="col">Log token</th><th scope="col">Loghound field</th><th scope="col">Example</th>'
                    . '</tr></thead><tbody>';
                foreach ($mapping as $m) {
                    echo '<tr>';
                    echo '<td class="mono">' . Security::esc((string) ($m['token'] ?? '')) . '</td>';
                    echo '<td class="mono">' . Security::esc((string) ($m['field'] ?? '')) . '</td>';
                    echo '<td class="mono clip">' . Security::esc((string) ($m['example'] ?? '')) . '</td>';
                    echo '</tr>';
                }
                echo '</tbody></table></div>';
            }

            $missing = (array) ($src['missing'] ?? []);
            if ($missing !== []) {
                echo '<h4>Not logged — and what that costs you</h4>';
                echo '<ul class="missing">';
                foreach ($missing as $m) {
                    echo '<li><code class="mono">' . Security::esc((string) ($m['token'] ?? '')) . '</code> → '
                        . '<code class="mono">' . Security::esc((string) ($m['field'] ?? '')) . '</code>: '
                        . Security::esc((string) ($m['why'] ?? '')) . '</li>';
                }
                echo '</ul>';
                echo '<p class="muted">The recommended <code>LogFormat</code> in <code>docs/INSTALL.md</code> adds all '
                    . 'of these. Plain <code>combined</code> still works — it just detects less.</p>';
            }

            $samples = array_slice((array) ($src['samples'] ?? []), 0, 5);
            if ($samples !== []) {
                echo '<h4>Five lines from this file, parsed</h4>';
                echo '<p class="muted">Read these. If a value is in the wrong column, the format is wrong, and '
                    . 'confirming it would fill your index with nonsense.</p>';
                foreach ($samples as $s) {
                    echo '<div class="sample">';
                    echo '<pre class="sample-raw mono">' . Security::esc((string) ($s['raw'] ?? '')) . '</pre>';
                    echo '<div class="table-wrap"><table class="tight sample-parsed"><tbody>';
                    foreach ((array) ($s['parsed'] ?? []) as $field => $value) {
                        echo '<tr><th scope="row" class="mono">' . Security::esc((string) $field) . '</th>';
                        echo '<td class="mono clip">' . Security::esc((string) $value) . '</td></tr>';
                    }
                    echo '</tbody></table></div>';
                    echo '</div>';
                }
            }

            if (!$confirmed) {
                echo '<form method="post" action="?v=settings" class="confirm-form">';
                self::csrfField();
                echo '<input type="hidden" name="action" value="confirm_source">';
                echo '<input type="hidden" name="path" value="' . Security::esc($path) . '">';
                echo '<button type="submit" class="primary">Looks right — start ingesting this file</button>';
                echo '</form>';
            } elseif (isset($configured[$path])) {
                self::removeForm($path, 'Stop ingesting this file');
            }
            echo '</article>';
        }

        $this->orphanSources($sources);
        self::cardEnd();
    }

    /**
     * The button that re-runs discovery, and the panel its progress renders into.
     *
     * A stepped job rather than a form, for the reason rescanPlan() gives: this walks the
     * webserver configuration and samples up to twenty files, and a synchronous POST that can
     * exceed the execution limit is a gateway timeout with no way to tell whether it ran.
     * The page reattaches to a running scan after a refresh, so closing the tab is safe.
     *
     * Withheld in demo mode, where the detection report on screen is fabricated and there is
     * nothing honest for a real scan of this machine to do with it.
     */
    private function rescanControl(): void
    {
        if ($this->gw->isDemo()) {
            echo '<p class="muted">Scanning is switched off while the panel is showing demo data.</p>';
            return;
        }

        echo '<div class="job-actions">';
        echo '<button type="button" data-job="' . Security::esc(self::KIND_RESCAN) . '" data-mount="job-rescan">'
            . 'Scan this server again</button>';
        echo '</div>';
        echo '<div id="job-rescan"></div>';
        echo '<p class="muted">Reads your webserver configuration and the usual log locations, then grades a '
            . 'sample of every file it finds. It changes nothing on its own: a newly found file is added to the '
            . 'review below and is ingested only once you confirm it.</p>';
    }

    /**
     * Configured sources that the last scan did not find.
     *
     * A source can be in `sources` and absent from the report — added by
     * `bin/loghound-setup`, or left behind by a file that has since been moved or deleted.
     * Without this it would be ingesting (or failing to) with no representation anywhere in
     * the panel and no way to remove it short of editing the config by hand, which is the
     * whole problem this section exists to fix.
     *
     * @param array<int,array<string,mixed>> $reported The detection report's sources.
     */
    private function orphanSources(array $reported): void
    {
        $known = [];
        foreach ($reported as $src) {
            $known[(string) ($src['path'] ?? '')] = true;
        }

        $orphans = [];
        foreach ((array) $this->cfg->get('sources', []) as $source) {
            $path = is_array($source) ? (string) ($source['path'] ?? '') : '';
            if ($path !== '' && !isset($known[$path])) {
                $orphans[$path] = (string) ($source['format'] ?? '');
            }
        }
        if ($orphans === []) {
            return;
        }

        echo '<h3>Configured, but not found by the last scan</h3>';
        echo '<p class="muted">These are being read by the tailer and were not in the last detection run — they '
            . 'were added by <code>bin/loghound-setup</code>, or the file has moved since.</p>';
        foreach ($orphans as $path => $format) {
            echo '<article class="source">';
            echo '<div class="source-head"><h3 class="mono">' . Security::esc($path) . '</h3>';
            echo '<span class="chip chip-warn">Not in the last scan</span></div>';
            echo '<dl class="kv"><dt>Format</dt><dd><code class="mono wrap">'
                . Security::esc($format) . '</code></dd></dl>';
            self::removeForm($path, 'Stop ingesting this file');
            echo '</article>';
        }
    }

    /**
     * The form that removes one configured source.
     *
     * The source travels as the opaque id sourceId() derives from its path, never as the path
     * itself and never as a position in the list: the server resolves the id against the
     * configuration it already holds, so a crafted or stale submission can only ever name
     * something that is already there — or nothing at all.
     */
    private static function removeForm(string $path, string $label): void
    {
        echo '<form method="post" action="?v=settings" class="confirm-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="remove_source">';
        echo '<input type="hidden" name="source" value="' . Security::esc(self::sourceId($path)) . '">';
        echo '<button type="submit">' . Security::esc($label) . '</button>';
        echo '</form>';
    }

    /**
     * Solr connection, read-only, with the checks offered as asynchronous jobs.
     *
     * Nothing here contacts Solr while the page renders. Both checks are stepped jobs the
     * operator starts, because a ping to an unreachable host and a document count on a
     * large index are exactly the operations that used to hang a request until PHP-FPM
     * killed it. Credentials are reported as present or absent and never printed.
     *
     * There is one storage backend and the panel says so. A configuration left over from
     * before the bring-your-own-Solr option was removed still carries `solr.mode: custom`, and
     * that is reported here as the refusal it is rather than as a second kind of install:
     * Loghound provisions and manages its own two indexes on Opensolr, and it cannot do that on
     * a Solr it does not administer. Config::validate() refuses the same value, which is what
     * stops the daemons; this is the half of the message an operator sees in the browser.
     */
    private function solrSection(): void
    {
        $mode = (string) $this->cfg->get('solr.mode', Config::SOLR_MODE);

        self::cardOpen('set-solr', self::sectionNum('set-solr'), 'Solr connection');

        if ($mode !== Config::SOLR_MODE) {
            echo '<p class="pop">This configuration is not usable.</p>';
            echo '<p>It sets <code>solr.mode</code> to <code class="mono">' . Security::esc($mode)
                . '</code>. Loghound provisions and manages its own two indexes on your Opensolr '
                . 'account — creating them, uploading their configsets and reloading them — and it '
                . 'cannot do that on a Solr it does not administer, so pointing it at one is no '
                . 'longer supported. Set <code>solr.mode</code> to <code class="mono">'
                . Security::esc(Config::SOLR_MODE) . '</code> in <code>config/loghound.php</code> and '
                . 'run <code>bin/loghound-setup</code> to provision the two indexes. The ingest, '
                . 'scoring and retention daemons refuse to start until you do.</p>';
        }

        echo '<dl class="kv">';
        echo '<dt>Account</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('opensolr.email', '—')) . '</dd>';
        echo '<dt>Region</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('opensolr.region', '—')) . '</dd>';
        echo '<dt>API key</dt><dd>' . ($this->cfg->get('opensolr.api_key')
            ? '<span class="chip chip-good">Set</span>'
            : '<span class="chip chip-warn">Missing</span>') . '</dd>';
        echo '<dt>Hits core</dt><dd class="mono">' . Security::esc($this->gw->hitsCore()) . '</dd>';
        echo '<dt>Sessions core</dt><dd class="mono">' . Security::esc($this->gw->sessionsCore()) . '</dd>';
        echo '<dt>Query timeout</dt><dd class="mono">'
            . Security::esc((string) Gateway::queryTimeout($this->cfg)) . 's</dd>';
        echo '</dl>';

        echo '<p class="muted">Connection details are edited in <code>config/loghound.php</code> outside the '
            . 'document root, not here: the file holds the API key and the beacon secret, and a web form is the '
            . 'wrong place to put either.</p>';

        echo '<div class="job-actions">';
        echo '<button type="button" class="primary" data-job="solr_connection" data-mount="job-solr">'
            . 'Run connection check</button>';
        echo '<button type="button" data-job="opensolr_check" data-mount="job-solr">'
            . 'Validate Opensolr credentials</button>';
        echo '</div>';
        echo '<div id="job-solr"></div>';
        echo '<p class="muted">Each check runs as a sequence of steps with its own progress, so it cannot time '
            . 'out however slow the backend is. You can close this page and come back to it.</p>';
        self::cardClose('set-solr');
    }

    /**
     * Retention: what the policy is, and what it would delete.
     *
     * The preview is a job for the same reason as the connection check — counting
     * documents older than a cutoff on a large index is not instant. The panel never
     * deletes; `bin/loghound-retention` does, and the summary says so.
     */
    private function retentionSection(): void
    {
        $days = (int) $this->cfg->get('privacy.retention_days', 0);

        self::cardOpen('set-retention', self::sectionNum('set-retention'), 'Retention preview');
        echo '<p class="pop">' . ($days > 0
            ? Security::esc('Documents older than ' . $days . ' days are eligible for deletion.')
            : 'Retention is disabled, so nothing is ever deleted.') . '</p>';
        echo '<p class="muted">This counts what is past the retention window. It does not delete anything — '
            . 'deletion is done by <code>bin/loghound-retention</code>, which is deliberately the only thing in '
            . 'the product allowed to issue a delete-by-query.</p>';
        echo '<div class="job-actions">';
        echo '<button type="button" data-job="retention_preview" data-mount="job-retention">'
            . 'Preview what would be deleted</button>';
        echo '</div>';
        echo '<div id="job-retention"></div>';
        self::cardClose('set-retention');
    }

    /**
     * Resolve the public base URL of this Loghound install.
     *
     * Prefers the configured `base_url`. Falls back to the request's own scheme and Host
     * purely so the snippets on screen are usable before setup is finished — Host is
     * client-controlled, so the value is escaped like any other untrusted string on
     * output and the operator is told to configure it properly.
     *
     * @return array{0:string,1:bool} [base URL without trailing slash, was it configured]
     */
    private function baseUrl(): array
    {
        $base = rtrim((string) $this->cfg->get('base_url', ''), '/');
        if ($base !== '') {
            return [$base, true];
        }
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'loghound.example.com');
        $scheme = (($_SERVER['HTTPS'] ?? '') !== '') ? 'https' : 'http';
        return [$scheme . '://' . $host, false];
    }

    /**
     * The cache-busting version for `b.js`.
     *
     * The beacon is served with long cache headers (SPEC §3), so the only way a change
     * reaches returning visitors promptly is a version query. Using the file's own mtime
     * means there is nothing to remember to bump — and nothing to build.
     */
    private function beaconVersion(): string
    {
        $path = __DIR__ . '/../../public/b.js';
        return is_file($path) ? (string) filemtime($path) : '1';
    }

    /**
     * Is the beacon actually being received?
     *
     * An operator who has pasted a snippet into a template has no way to know whether it
     * worked, and "no engaged time in the dashboard" is indistinguishable from "no
     * traffic yet". So this asks the sessions core directly: how many sessions carried
     * beacon data recently, and when did the most recent one arrive.
     *
     * The query is deliberately NOT bounded by the page's time-range selector — the
     * question is "does this work at all", not "what happened in the last hour". It is
     * still bounded to `doc_type_s:session`, because the daily rollup documents that share
     * this core also carry `ts_start` and would otherwise be counted in the denominator.
     *
     * @return array{ever:int,hour:int,day:int,last:?string,coverage:?float}
     */
    private function beaconStatus(): array
    {
        $f = $this->gw->facet('settings.beacon', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => [self::FQ_SESSION_DOCS, Query::SETTLED_SESSIONS, 'ts_start:[NOW-30DAY TO NOW]'],
        ], [
            'withBeacon' => ['type' => 'query', 'q' => Query::POP_BEACON, 'facet' => [
                'last' => 'max(ts_start)',
                'hour' => ['type' => 'query', 'q' => 'ts_start:[NOW-1HOUR TO NOW]'],
                'day'  => ['type' => 'query', 'q' => 'ts_start:[NOW-24HOUR TO NOW]'],
            ]],
            'eligible' => ['type' => 'query', 'q' => 'pages_i:[1 TO *]'],
        ]);

        $node = is_array($f['withBeacon'] ?? null) ? $f['withBeacon'] : [];
        $eligible = self::qcount($f, 'eligible');
        $ever = (int) ($node['count'] ?? 0);

        return [
            'ever'     => $ever,
            'hour'     => self::qcount($node, 'hour'),
            'day'      => self::qcount($node, 'day'),
            'last'     => is_string($node['last'] ?? null) ? $node['last'] : null,
            'coverage' => $eligible > 0 ? round(($ever / $eligible) * 100, 1) : null,
        ];
    }

    /**
     * The beacon section: what it is, what you get without it, what you get with it,
     * how to install it on four common stacks, whether it is currently working, and
     * exactly what it collects.
     *
     * This is a teaching section, not a snippet dump. The intended reading time is about
     * thirty seconds for someone who has never heard of the three-plane model.
     */
    private function beaconSection(): void
    {
        [$base, $configured] = $this->baseUrl();
        $ver = $this->beaconVersion();
        $src = $base . '/b.js?v=' . $ver;
        $enabled = (bool) $this->cfg->get('beacon.enabled');

        self::cardOpen('set-beacon', self::sectionNum('set-beacon'), 'Beacon / JavaScript tracking');
        echo '<p class="pop">One line of JavaScript, optional. Loghound works without it. This section explains '
            . 'exactly what changes if you add it.</p>';

        echo '<div class="beacon-status beacon-none" id="beacon-status" role="status">'
            . '<span class="beacon-dot" aria-hidden="true"></span>'
            . '<div class="beacon-status-text">'
            . '<strong id="beacon-status-label">Beacon: checking</strong>'
            . '<span class="muted" id="beacon-status-detail">Asking the sessions core whether any beacon data has '
            . 'arrived. This runs after the page renders, so it never holds the page up.</span>'
            . '</div></div>';

        if (!$enabled) {
            echo '<div class="banner banner-warn"><strong>The collector is switched off.</strong> '
                . '<code>beacon.enabled</code> is false in <code>config/loghound.php</code>, so '
                . '<code>public/collect.php</code> will discard everything the snippet sends.</div>';
        }
        if (!$configured) {
            echo '<div class="banner banner-warn"><code>base_url</code> is not set in the configuration, so the '
                . 'snippets below were built from the address you happen to be using right now. Set it before '
                . 'handing any of this to a colleague.</div>';
        }

        echo '<div class="planes">';

        echo '<div class="plane plane-without">';
        echo '<h3>Without the beacon</h3>';
        echo '<p class="plane-sub">Planes 1 and 2 — the access log, and what correlating log lines reveals. '
            . 'This is a complete, working product on its own.</p>';
        echo '<ul class="plane-list">';
        foreach ([
            'Full traffic analysis: sessions, pages, entry and exit paths, status codes, bytes, latency percentiles.',
            'Header-fingerprint clustering — the cross-IP proxy-fleet detection this tool exists for. It reads request headers, not JavaScript.',
            'ASN, RIR netname and network-type classification, so a datacentre range does not read as a household.',
            'Forward-confirmed reverse DNS, which is what separates the real Googlebot from something wearing its User-Agent.',
            'Behavioural signals: asset ratio, conditional-request behaviour, inter-request timing regularity, session shape.',
            'Log span — first request to last request — for every single session.',
        ] as $item) {
            echo '<li>' . Security::esc($item) . '</li>';
        }
        echo '</ul>';
        echo '<p class="plane-note">Scoring rules that work with no JavaScript at all: '
            . '<code>no_js_on_html</code>, <code>fp_cluster_proxy_fleet</code>, <code>ua_secch_mismatch</code>, '
            . '<code>platform_mismatch</code>, <code>rdns_claim_failed</code>, <code>hosting_asn_browser_ua</code>, '
            . '<code>no_304_on_repeat</code>, <code>periodic_timing</code>, <code>single_page_10s</code>, '
            . '<code>no_assets</code>, <code>ua_declared_bot</code>.</p>';
        echo '</div>';

        echo '<div class="plane plane-with">';
        echo '<h3>With the beacon</h3>';
        echo '<p class="plane-sub">Plane 3 — what actually happened inside the browser. Everything above still '
            . 'applies; this is added on top and cross-checked against it.</p>';
        echo '<ul class="plane-list">';
        foreach ([
            'Real time on site: visible time (tab in front, window focused) and engaged time (within 30 seconds of a genuine interaction) — not "the tab was open for 41 minutes".',
            'The last page of the session, which log-based tools structurally cannot measure: once the visitor stops requesting things, the log goes silent.',
            'Headless-browser detection: driver artefacts, software rasterisers, missing plugin and language tables, the classic permission contradictions.',
            'UA-claim verification: the User-Agent claims a Chrome version, and the engine is tested for features that shipped in it. A spoofed string cannot retrofit V8.',
            'Timezone cross-check between the browser and the IP geolocation.',
            'Forged-timing detection: a client claiming four hours of engagement thirty seconds after its token was issued is recorded as evidence, not discarded.',
        ] as $item) {
            echo '<li>' . Security::esc($item) . '</li>';
        }
        echo '</ul>';
        echo '<p class="plane-note">Scoring rules that become available <strong>only</strong> with the beacon: '
            . '<code>automation_marker</code>, <code>headless_renderer</code>, <code>ua_claim_failed</code>, '
            . '<code>no_interaction</code>, <code>tz_mismatch</code>, <code>beacon_forged</code>.</p>';
        echo '</div>';

        echo '</div>';

        echo '<p class="muted">The short version: <strong>without it you keep the bot detection, and lose the '
            . 'honest time measurement</strong>. Three of the four timing numbers on the Overview page — wall '
            . 'clock, visible and engaged — come from here. The fourth, log span, does not and never will.</p>';

        echo '<h3>Install it</h3>';
        echo '<p class="muted">Every snippet points at <code class="mono">' . Security::esc($src) . '</code>. '
            . 'The <code>?v=</code> query is the beacon file&rsquo;s own modification time: the file is served with '
            . 'long cache headers, and this is what makes an update reach returning visitors.</p>';

        $htmlSnippet = '<script src="' . $src . '" defer></script>';

        $wpSnippet = <<<PHPCODE
        // wp-content/themes/your-theme/functions.php
        add_action('wp_head', static function (): void {
            echo '<script src="{$src}" defer></script>' . "\\n";
        }, 99);
        PHPCODE;

        $schemeless = preg_replace('#^https?:#', '', $src) ?? $src;
        $drupalSnippet = <<<DRUPALCODE
        # your_theme.libraries.yml
        loghound:
          header: true
          js:
            {$schemeless}: { type: external, minified: true, attributes: { defer: true } }

        # your_theme.theme  (or a small custom module)
        function your_theme_page_attachments(array &\$attachments): void {
          \$attachments['#attached']['library'][] = 'your_theme/loghound';
        }
        DRUPALCODE;

        $gtmSnippet = $htmlSnippet;

        $snippets = [
            ['id' => 'sn-html', 'label' => 'Plain HTML', 'code' => $htmlSnippet,
                'note' => 'Put it before <code>&lt;/head&gt;</code>. <code>defer</code> means it never blocks rendering, and it starts measuring at parse time rather than after every image has loaded.'],
            ['id' => 'sn-wp', 'label' => 'WordPress', 'code' => $wpSnippet,
                'note' => 'Goes in your theme&rsquo;s <code>functions.php</code>, or better, a small must-use plugin so it survives a theme change. Priority 99 keeps it late in <code>wp_head</code>.'],
            ['id' => 'sn-drupal', 'label' => 'Drupal', 'code' => $drupalSnippet,
                'note' => 'The library route, which survives cache rebuilds and template changes. <code>header: true</code> puts it in <code>&lt;head&gt;</code>. Run <code>drush cr</code> afterwards. Editing <code>html.html.twig</code> directly works too and is one line, but it is lost the next time the theme is updated.'],
            ['id' => 'sn-gtm', 'label' => 'Google Tag Manager', 'code' => $gtmSnippet,
                'note' => 'New tag → Custom HTML → paste → trigger <em>All Pages</em>. Leave <em>Support document.write</em> unchecked. Note that a tag manager loads asynchronously, so the first fraction of a second of each pageview is not measured.'],
        ];

        echo '<div class="snippets">';
        echo '<div class="tabs" role="tablist" aria-label="Installation method">';
        foreach ($snippets as $i => $s) {
            echo '<button type="button" role="tab" class="tab' . ($i === 0 ? ' on' : '') . '"'
                . ' id="tab-' . Security::esc($s['id']) . '"'
                . ' aria-selected="' . ($i === 0 ? 'true' : 'false') . '"'
                . ' aria-controls="panel-' . Security::esc($s['id']) . '"'
                . ' data-tab="' . Security::esc($s['id']) . '">'
                . Security::esc($s['label']) . '</button>';
        }
        echo '</div>';

        foreach ($snippets as $i => $s) {
            echo '<div class="tabpanel" role="tabpanel" id="panel-' . Security::esc($s['id']) . '"'
                . ' aria-labelledby="tab-' . Security::esc($s['id']) . '"'
                . ' data-tabpanel="' . Security::esc($s['id']) . '"' . ($i === 0 ? '' : ' hidden') . '>';
            echo '<pre class="snippet mono" id="' . Security::esc($s['id']) . '">'
                . Security::esc($s['code']) . '</pre>';
            echo '<div class="snippet-actions">';
            echo '<button type="button" class="ghost" data-copy="' . Security::esc($s['id']) . '">Copy</button>';
            echo '<span class="muted">' . $s['note'] . '</span>';
            echo '</div>';
            echo '</div>';
        }
        echo '</div>';

        echo '<h3>What it collects, exactly</h3>';
        echo '<p class="muted"><strong>No cookies are set by default</strong>, and no identifier is written to the '
            . 'visitor&rsquo;s device. Visitor identity is a hash derived server-side from the network prefix and '
            . 'request headers. A cookie mode exists but is opt-in and off. Someone&rsquo;s legal team will ask for '
            . 'this list, so here it is in full — the authoritative version ships in the repository as '
            . '<code class="mono">docs/PRIVACY.md</code>.</p>';

        echo '<div class="collects">';
        echo '<div><h4>It sends</h4><ul>';
        foreach ([
            'Three durations in milliseconds — wall clock, visible, engaged — measured with performance.now() deltas, plus the pageview count.',
            'Counts only: how many interactions of each type, and the furthest scroll depth as a percentage.',
            'Automation markers present on the page object: navigator.webdriver, driver globals, the WebGL unmasked renderer string.',
            'Environment facts used for cross-checks: the browser timezone, navigator.languages and platform, screen and window dimensions, device pixel ratio, hardware concurrency.',
            'The session identifier the server issued, and the HMAC token that proves the server issued it.',
        ] as $item) {
            echo '<li>' . Security::esc($item) . '</li>';
        }
        echo '</ul></div>';

        echo '<div><h4>It never sends</h4><ul>';
        foreach ([
            'Keystrokes, or the content of anything typed. Key events are counted, never read.',
            'Mouse coordinates or a movement recording. Only whether movement looked mechanical.',
            'Form values, page text, DOM contents, or a screenshot of any kind.',
            'Anything from another origin, and nothing from local or session storage.',
            'Its own idea of your IP address, User-Agent, hostname or referer — the collector reads those from the connection and ignores whatever the client claims (SPEC §6.3).',
        ] as $item) {
            echo '<li>' . Security::esc($item) . '</li>';
        }
        echo '</ul></div>';
        echo '</div>';

        echo '<p class="muted">Payloads are capped at '
            . Security::esc(number_format((int) $this->cfg->get('beacon.max_payload', 8192)))
            . ' bytes, rate-limited to '
            . Security::esc(number_format((int) $this->cfg->get('beacon.rate_per_min', 120)))
            . ' requests per minute per address, and the collector answers <code>204</code> to everything so it '
            . 'never reveals whether a token was valid. It writes to a local SQLite staging table and does not '
            . 'talk to Solr at all, which keeps Solr credentials out of the public request path.</p>';

        self::cardEnd();
    }

    /**
     * IP privacy mode and retention, with the consequence of each spelled out.
     *
     * Setup does not ask about either one, so this card is where both are decided as well as
     * changed, and it says so — an operator who expected the question during installation has
     * to be able to find where it went.
     */
    private function privacySection(): void
    {
        $mode = (string) $this->cfg->get('privacy.ip_mode', 'full');
        $days = (int) $this->cfg->get('privacy.retention_days', 90);

        self::cardOpen('set-privacy', self::sectionNum('set-privacy'), 'Privacy');

        echo '<p class="muted">Setup does not ask about these. A new installation keeps the full '
            . 'address and deletes hits after 90 days; this card is where both are changed.</p>';

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="privacy">';

        echo '<fieldset><legend>How IP addresses are stored</legend>';
        foreach ([
            ['full', 'Full address', 'Stored as received. You already have these in your own access log; this keeps the panel consistent with it. Best detection quality.'],
            ['truncate', 'Truncated (/24 and /48)', 'The host part is zeroed. Network-level analysis and fingerprint clustering still work; the individual address is gone. Per-IP drill-down becomes per-netblock.'],
            ['hash', 'Hashed with a daily-rotating salt', 'Replaced by a keyed hash that changes every day, so the same person cannot be followed across days. Sessionisation still works within a day. Rotating-proxy detection is weakened because distinct-IP counts become distinct-hash counts.'],
        ] as [$val, $label, $desc]) {
            echo '<label class="radio"><input type="radio" name="ip_mode" value="' . Security::esc($val) . '"'
                . ($mode === $val ? ' checked' : '') . '>';
            echo '<span><strong>' . Security::esc($label) . '</strong><br><span class="muted">'
                . Security::esc($desc) . '</span></span></label>';
        }
        echo '</fieldset>';

        echo '<fieldset><legend>Retention</legend>';
        echo '<label for="retention">Delete hits and sessions older than</label> ';
        echo '<input type="number" id="retention" name="retention_days" min="0" max="3650" value="'
            . Security::esc((string) $days) . '" inputmode="numeric"> <span class="muted">days (0 keeps everything)</span>';
        echo '<label class="check"><input type="checkbox" name="rollup_forever"'
            . ($this->cfg->get('privacy.rollup_forever') ? ' checked' : '') . '> '
            . 'Keep the daily rollup documents indefinitely <span class="muted">(they are tiny and hold no addresses)</span></label>';
        echo '<p class="muted">Deletion is performed by <code>bin/loghound-retention</code> on a timer. If that unit '
            . 'is not enabled, this setting does nothing — a retention policy that is only written down is not a '
            . 'retention policy.</p>';
        echo '</fieldset>';

        echo '<button type="submit" class="primary">Save privacy settings</button>';
        echo '</form>';
        self::cardEnd();
    }

    /** Per-rule scoring weights and the verdict thresholds. */
    private function scoringSection(): void
    {
        $catalogue = Bots::reasonCatalogue();
        $weights = (array) $this->cfg->get('scoring.weights', []);
        $thresholds = (array) $this->cfg->get('scoring.thresholds', []);
        $defaults = [
            'automation_marker' => 100, 'headless_renderer' => 90, 'ua_claim_failed' => 85,
            'no_js_on_html' => 70, 'fp_cluster_proxy_fleet' => 80, 'ua_secch_mismatch' => 75,
            'platform_mismatch' => 70, 'rdns_claim_failed' => 95, 'hosting_asn_browser_ua' => 45,
            'tz_mismatch' => 35, 'no_interaction' => 40, 'no_304_on_repeat' => 30,
            'periodic_timing' => 45, 'single_page_10s' => 15, 'no_assets' => 25,
            'beacon_forged' => 90, 'ua_declared_bot' => 100,
        ];

        self::cardOpen(
            'set-scoring',
            self::sectionNum('set-scoring'),
            'Scoring weights',
            'Points added to bot_score_f when a rule fires. Saving bumps rule_version_i, so sessions scored under '
            . 'the old weights stay identifiable. Existing documents are not rescored.'
        );

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="scoring">';

        echo '<div class="table-wrap"><table class="tight"><thead><tr>'
            . '<th scope="col">Rule</th><th scope="col">Fires when</th><th scope="col" class="num">Weight</th>'
            . '</tr></thead><tbody>';
        foreach ($catalogue as $code => $meta) {
            $value = isset($weights[$code]) ? (int) $weights[$code] : ($defaults[$code] ?? 0);
            echo '<tr>';
            echo '<td><code class="mono">' . Security::esc($code) . '</code><br><span class="muted">'
                . Security::esc($meta['label']) . '</span></td>';
            echo '<td class="muted">' . Security::esc($meta['why']) . '</td>';
            echo '<td class="num"><input type="number" min="0" max="100" name="weight['
                . Security::esc($code) . ']" value="' . Security::esc((string) $value) . '" inputmode="numeric"></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';

        echo '<fieldset><legend>Verdict thresholds</legend>';
        echo '<p class="muted">A score at or above each threshold gets that verdict. They must descend.</p>';
        echo '<div class="thresholds">';
        foreach ([
            'bot' => 'bot', 'likely_bot' => 'likely_bot', 'unknown' => 'unknown', 'likely_human' => 'likely_human',
        ] as $key => $label) {
            $v = (int) ($thresholds[$key] ?? ['bot' => 80, 'likely_bot' => 60, 'unknown' => 40, 'likely_human' => 20][$key]);
            echo '<label>' . Security::esc($label) . ' ≥ <input type="number" min="0" max="100" name="threshold['
                . Security::esc($key) . ']" value="' . Security::esc((string) $v) . '" inputmode="numeric"></label>';
        }
        echo '</div></fieldset>';

        echo '<button type="submit" class="primary">Save scoring</button>';
        echo '</form>';
        self::cardEnd();
    }

    /** Display preferences. */
    private function displaySection(): void
    {
        $tz = (string) $this->cfg->get('ui.timezone', 'UTC');

        self::cardOpen('set-display', self::sectionNum('set-display'), 'Display');
        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="ui">';
        echo '<label for="tz">Render timestamps in</label> ';
        echo '<select id="tz" name="timezone">';
        foreach (\DateTimeZone::listIdentifiers() as $zone) {
            echo '<option value="' . Security::esc($zone) . '"' . ($zone === $tz ? ' selected' : '') . '>'
                . Security::esc($zone) . '</option>';
        }
        echo '</select> ';
        echo '<button type="submit" class="primary">Save</button>';
        echo '<p class="muted">Timestamps are always shown as <code>mm/dd/yyyy hh:mm:ss</code>. '
            . 'Solr stores everything in UTC; this setting only changes how it is displayed.</p>';
        echo '</form>';
        self::cardEnd();
    }
}
