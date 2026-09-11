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

use Loghound\Auth\Base32;
use Loghound\Auth\Persistence;
use Loghound\Auth\TwoFactor;
use Loghound\Config;
use Loghound\LogDetect;
use Loghound\Quota;
use Loghound\Security;
use Loghound\Setup\Detector;
use Loghound\Setup\Job;
use Loghound\Setup\Pairs;
use Loghound\Setup\Requirements;
use Loghound\Setup\Reset;
use Loghound\Setup\Schema;
use Loghound\Setup\Steps;
use Loghound\Setup\Storage;
use Loghound\Setup\Token;

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

    /**
     * The job kind that compares this release's schemas against the live ones.
     *
     * A job for the same reason the rescan is one, and a job rather than something the card
     * does while it renders for a second reason: it is two control-plane round trips, and a
     * Settings page that waits on opensolr.com is a Settings page that stops rendering the day
     * opensolr.com is slow. The card shows the saved verdict and this is what refreshes it.
     */
    private const KIND_SCHEMA = 'schema_check';

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
        return [
            self::KIND_RESCAN => static fn (array $ctx): array => self::rescanPlan(),
            self::KIND_SCHEMA => static fn (array $ctx): array => Schema::checkPlan(self::root()),
        ];
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
                                . 'A path can still be added by hand below, or with '
                                . self::setupCommand() . '.'
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
        /* ASKED FOR A SECOND TIME, DELIBERATELY. The front controller enforces it before any
           view is constructed, and Panel\OpensolrView re-asserts it here for the reason its
           own docblock gives: a control that is only applied by the caller is one refactor
           away from being gone. This is the view with every destructive action on it, and it
           was the one that did not repeat the check. */
        Security::requireCsrf();

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

            case 'opensolr_credentials':
                return $this->saveOpensolrCredentials();

            case 'reinstall':
                return $this->reinstall();

            case 'panel_password':
                return $this->savePanelPassword();

            case 'opensolr_pair':
                return $this->switchPair();

            case 'add_source':
                return $this->addSource();

            case 'revoke_remembered':
                return $this->revokeRemembered();

            case 'totp_begin':
                return $this->totpBegin();

            case 'totp_cancel':
                return $this->totpCancel();

            case 'totp_enable':
                return $this->totpEnable();

            case 'totp_disable':
                return $this->totpDisable();

            case 'totp_regenerate':
                return $this->totpRegenerate();

            case 'totp_download':
                $this->totpDownload();
                return '?v=settings#set-2fa';

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
     * THE PATH INVALIDATED IS THE ONE THAT WAS WRITTEN, from the Config object itself. It used
     * to be a literal `__DIR__ . '/../../config/loghound.php'`, which is the same file on an
     * ordinary installation and a DIFFERENT file on any layout where the config does not sit two
     * directories above this one — a symlinked deploy, a shared config, the test scaffold. There
     * the invalidation silently cleared an entry for a file nobody had written and left the stale
     * one in place, which is the exact failure this call exists to prevent.
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
            @opcache_invalidate($this->cfg->path(), true);
        }
        return null;
    }

    /**
     * Change the Opensolr account this installation uses, from the panel.
     *
     * WHY THIS EXISTS, since this card used to refuse it. It said connection details are edited
     * in config/loghound.php and that a web form is the wrong place for an API key. The owner
     * has overruled that: it has to be doable in the interface. The refusal was trying to avoid
     * a real cost, so the cost is paid here instead of being avoided — every property the
     * refusal was protecting is enforced explicitly below.
     *
     * WRITE-ONLY. The stored key is never rendered back: not as a value, not in a data
     * attribute, not in JSON. The card reports that a key is configured, never what it is. An
     * empty key field KEEPS the stored key, exactly as the wizard's prompt does, which is what
     * lets an operator change only the email or only the region without retyping a secret.
     *
     * VALIDATED BEFORE IT IS PERSISTED. A key that does not authenticate must never replace one
     * that does — pasting a typo would otherwise lock the operator out of their own indexes
     * with no way back except a shell. The candidate values are set on the in-memory
     * configuration, proved against the platform, and only then written; nothing reaches disk
     * unless persist() is reached, so a refusal restores the previous values and leaves
     * config/loghound.php byte-identical.
     *
     * A CURRENT SECOND FACTOR IS REQUIRED WHEN ONE IS CONFIGURED, the same as turning two-factor
     * off. That is the deliberate choice, and the reason is that this action is strictly more
     * dangerous than the one that already costs a factor: the Opensolr key is a whole-account
     * credential, and being able to REPLACE it from a stolen session means pointing this
     * installation at an account the attacker controls — every future visitor record then lands
     * in their indexes, quietly, while the panel keeps looking healthy. A session cookie alone
     * must not buy that.
     *
     * NOTHING ACCOUNT-SCOPED IS CACHED, so there is nothing here to invalidate. The plan's index
     * allowance is read from get_account_summary at the moment it is needed rather than stored,
     * precisely because a number remembered against one account is silently wrong the moment the
     * credentials point at another. What DOES survive a change of account is the pair of index
     * names, and those may not belong to the new one — which is checked and reported rather than
     * left to be discovered as an empty dashboard.
     *
     * Nothing here is logged, and nothing reaches a job: the key travels from the form field
     * into Config and stops. The POST entry is unset as soon as it has been read, so a later
     * var_dump of the request, or any handler that runs after this one, cannot reach it.
     */
    private function saveOpensolrCredentials(): string
    {
        $anchor = '#set-solr';

        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            return '?v=settings&err=' . $refused . $anchor;
        }

        $before = [
            'email'  => (string) $this->cfg->get('opensolr.email', ''),
            'key'    => (string) $this->cfg->get('opensolr.api_key', ''),
            'region' => (string) $this->cfg->get('opensolr.region', ''),
            'mode'   => (string) $this->cfg->get('solr.mode', Config::SOLR_MODE),
        ];

        $email  = is_string($_POST['opensolr_email'] ?? null) ? trim($_POST['opensolr_email']) : '';
        $key    = is_string($_POST['opensolr_api_key'] ?? null) ? trim($_POST['opensolr_api_key']) : '';
        $region = is_string($_POST['opensolr_region'] ?? null) ? trim($_POST['opensolr_region']) : '';

        unset($_POST['opensolr_api_key']);

        $problems = Storage::saveCredentials($this->cfg, $email === '' ? $before['email'] : $email, $key);
        if ($problems !== []) {
            $this->restoreOpensolr($before);
            return $this->refuseCredentials(implode(' ', $problems), $anchor);
        }

        try {
            $regions = Storage::listRegions($this->cfg);
        } catch (\Throwable $e) {
            $this->restoreOpensolr($before);
            return $this->refuseCredentials(Storage::explainApi($e->getMessage()), $anchor);
        }

        $chosen = $this->settleRegion($region === '' ? $before['region'] : $region, $regions, $region !== '');
        if ($chosen === null) {
            $this->restoreOpensolr($before);
            return $this->refuseCredentials(
                'Opensolr does not offer the region "' . $region . '" to this account. '
                . 'It offers: ' . implode(', ', $regions) . '.',
                $anchor
            );
        }
        $this->cfg->set('opensolr.region', $chosen);

        $moved = $this->accountMoved($before, $email, $key);
        $orphaned = $moved ? $this->indexesNotOwned() : [];

        if ($orphaned !== [] && ($_POST['accept_reindex'] ?? '') !== '1') {
            $this->restoreOpensolr($before);
            return $this->refuseCredentials(
                'Those credentials work, but that account does not hold '
                . implode(' or ', $orphaned) . ', which is where this installation\'s history is. '
                . 'Changing to it would leave the panel pointing at indexes it cannot read. Tick '
                . '"I will choose new indexes" to change accounts anyway and pick a pair from the '
                . 'new one, or put the previous account back.',
                $anchor
            );
        }

        $err = $this->persist();
        if ($err !== null) {
            $this->restoreOpensolr($before);
            return '?v=settings&err=' . $err . $anchor;
        }

        self::stashSolrNote('good', $this->credentialOutcome($before, $chosen, $moved));

        return '?v=settings&ok=opensolr_saved' . $anchor;
    }

    /**
     * Change the panel username and password, from the panel.
     *
     * THERE WAS NO WAY TO DO THIS AT ALL. The password could be set by either installer and
     * changed by neither, so an operator who wanted to rotate it had to re-run setup or edit a
     * password hash into a file by hand. That is the kind of friction that ends with a password
     * never being rotated.
     *
     * THE CURRENT PASSWORD IS REQUIRED, and that is the point of the whole action rather than a
     * formality. Persistent sign-in means a session can outlive the browser being closed, and a
     * stolen one must not be enough to lock the real operator out of their own panel by changing
     * the password out from under them. Verifying the old password is what makes that cost
     * something the thief does not have.
     *
     * A CURRENT SECOND FACTOR IS ALSO REQUIRED when one is configured. The same reasoning as
     * disabling two-factor: a password change hands over the account, and if a session cookie
     * alone bought it then the factor would be decoration on any browser somebody had already
     * got into. The wrong-attempt ledger and the delay are the sign-in form's, so this endpoint
     * is not a cheaper place to grind than the front door.
     *
     * The rules are Setup\Steps::applyAdmin()'s — the same minimum length, the same username
     * shape, the same confirmation — because the installer and this page are documented as
     * producing the same configuration and a second set of rules is how that stops being true.
     * applyAdmin() also revokes every persistent-login token and switches two-factor off, which
     * is deliberate and is why the two-factor secret is put back below: turning the factor off
     * is the documented way back in for somebody who has lost their phone AND their recovery
     * codes, and it is reachable only from a shell — an operator who still has their factor and
     * is merely changing a password has not asked to lose it.
     *
     * Neither password is rendered, logged, or kept: applyAdmin() hashes immediately, and both
     * POST entries are removed as soon as they have been read.
     */
    private function savePanelPassword(): string
    {
        $anchor = '#set-auth';

        $current = is_string($_POST['current_password'] ?? null) ? $_POST['current_password'] : '';
        $hash    = (string) $this->cfg->get('auth.password_hash', '');

        if ($hash === '' || !password_verify($current, $hash)) {
            unset($_POST['current_password'], $_POST['password'], $_POST['password2']);
            $this->factorFailure();
            return '?v=settings&err=bad_current_password' . $anchor;
        }

        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            unset($_POST['current_password'], $_POST['password'], $_POST['password2']);
            return '?v=settings&err=' . $refused . $anchor;
        }

        $totp = (array) $this->cfg->get('auth.totp', []);
        $mode = (string) $this->cfg->get('auth.mode', 'basic');

        $problems = Steps::applyAdmin(
            $this->cfg,
            is_string($_POST['user'] ?? null) ? $_POST['user'] : '',
            is_string($_POST['password'] ?? null) ? $_POST['password'] : '',
            is_string($_POST['password2'] ?? null) ? $_POST['password2'] : '',
            $mode
        );

        unset($_POST['current_password'], $_POST['password'], $_POST['password2']);

        if ($problems !== []) {
            self::stashAuthNote(implode(' ', $problems));
            return '?v=settings&err=password_refused' . $anchor;
        }

        $this->cfg->set('auth.totp', $totp);

        $err = $this->persist();
        if ($err !== null) {
            return '?v=settings&err=' . $err . $anchor;
        }

        return '?v=settings&ok=password_saved' . $anchor;
    }

    /** Queue the precise reason a password was refused, for the card to render once. */
    private static function stashAuthNote(string $text): void
    {
        Security::startSession();
        $_SESSION['lh_settings_auth_note'] = $text;
    }

    /** Read and clear it. */
    private static function takeAuthNote(): string
    {
        Security::startSession();
        $note = $_SESSION['lh_settings_auth_note'] ?? '';
        unset($_SESSION['lh_settings_auth_note']);
        return is_string($note) ? $note : '';
    }

    /**
     * The form that changes the panel username and password.
     *
     * Three password fields and never a value attribute on any of them. The username is shown
     * because it is not a secret and retyping it to change a password would be pointless
     * friction.
     *
     * Rendered inside the sign-in card by authSection(), as an addition rather than a
     * replacement: how you sign in and what you sign in WITH are two settings that belong
     * together, and splitting them across two cards is how an operator fails to find one.
     */
    private function passwordPart(): void
    {
        self::problemBanner(self::takeAuthNote());

        echo '<h4>Changing your username or password</h4>';
        echo '<p class="muted">The current password is required, because staying signed in means a '
            . 'session can outlive a closed browser — and a stolen one must not be enough to change '
            . 'the password out from under you. Every browser that was staying signed in is signed '
            . 'out when it changes, including this one.</p>';

        echo '<form method="post" action="?v=settings" class="setup-form" autocomplete="off">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="panel_password">';

        echo '<label for="pw_user">Username</label>';
        echo '<input type="text" id="pw_user" name="user" size="24" autocomplete="username" '
            . 'value="' . Security::esc((string) $this->cfg->get('auth.user', '')) . '" required>';

        echo '<label for="pw_current">Current password</label>';
        echo '<input type="password" id="pw_current" name="current_password" size="34" '
            . 'autocomplete="current-password" required>';

        echo '<label for="pw_new">New password</label>';
        echo '<input type="password" id="pw_new" name="password" size="34" '
            . 'autocomplete="new-password" required>';

        echo '<label for="pw_new2">New password again</label>';
        echo '<input type="password" id="pw_new2" name="password2" size="34" '
            . 'autocomplete="new-password" required>';
        echo '<p class="muted">At least ' . (int) Steps::MIN_PASSWORD . ' characters. This page shows '
            . 'every visitor, path and address on your site.</p>';

        if (TwoFactor::isEnabled((array) $this->cfg->get('auth', []))) {
            echo '<label for="pw_code">Code from your authenticator</label>';
            echo '<input type="text" id="pw_code" name="code" inputmode="numeric" '
                . 'autocomplete="one-time-code" size="12" spellcheck="false" required>';
            echo '<p class="muted">Two-factor stays on and keeps the same phone — changing a '
                . 'password is not a reason to lose it.</p>';
        }

        echo '<button type="submit" class="primary">Change it</button>';
        echo '</form>';
    }

    /**
     * Reset this installation and hand the same browser back to the installer.
     *
     * WHAT IT IS. The owner wanted a way to start the installation over from inside the panel.
     * The installer gate stays exactly as it is — Installer::isNeeded() is structural and
     * nothing here changes it — and this button is simply a supported way of making it true
     * again. That the button lives behind a signed-in session is what makes it acceptable where
     * an open "re-run setup" route would not be.
     *
     * THE LOCKOUT THIS HAS TO AVOID, and it is the whole design problem. Clearing the
     * configuration makes the installer reachable, and the installer demands the token from
     * var/install-token — which needs shell access to read. An operator who runs this box
     * entirely through a browser would otherwise destroy their panel and be locked out of the
     * installer in the same click. So the proof is carried forward: pressing this button in an
     * authenticated session IS the proof the token exists to provide, and Token::grant() hands
     * it to this session, one-shot and short-lived. Nothing is relaxed for anybody else — a
     * visitor who did not press it still has to produce the file.
     *
     * IT COSTS A CURRENT SECOND FACTOR when one is configured, for the same reason disabling
     * two-factor does and then some: this destroys a working installation's sign-in and its
     * link to its own data, and a stolen session cookie must not be enough to do that. The
     * ledger and the delay are the sign-in form's, through requireSecondFactor().
     *
     * The confirmation is a typed word rather than a second button, because the consequences
     * list above it is long and the point is that it gets read.
     */
    private function reinstall(): string
    {
        $anchor = '#set-reinstall';

        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            return '?v=settings&err=' . $refused . $anchor;
        }

        $typed = is_string($_POST['confirm'] ?? null) ? strtoupper(trim($_POST['confirm'])) : '';
        if ($typed !== 'REINSTALL') {
            return '?v=settings&err=reinstall_unconfirmed' . $anchor;
        }

        $result = Reset::perform($this->cfg);
        if (!$result['ok']) {
            return '?v=settings&err=save_failed' . $anchor;
        }

        Token::grant();

        return './';
    }

    /**
     * Add a log file the operator typed, from Settings rather than from the installer.
     *
     * THE GAP THIS CLOSES. Rescanning and confirming what the scan found were already here, but
     * a file the scan cannot see — an unusual path, a directory outside `allowed_log_roots` —
     * could only be added during installation. Changing which files are ingested is not an
     * install-time decision, and sending an operator back through setup to add one is the
     * friction this whole round of work exists to remove.
     *
     * `allowed_log_roots` IS STILL NEVER WIDENED FROM A WEB FORM, and that is not softened
     * here. The list is what stops the log-path setting from being an arbitrary-file-read, a
     * form post is not proof of anything, and this endpoint is behind a session rather than
     * behind shell access. Detector::manualSource() refuses a path outside it exactly as it does
     * in the installer, and its refusal names the two routes that genuinely work — the shell
     * wizard, which asks at a terminal, or the file itself.
     *
     * SAFE WHILE THE TAILER IS RUNNING, because of what a source IS. The tailer reads its
     * configuration at startup and on SIGHUP, so a source added here is picked up on the next
     * reload or restart and not mid-file. Its read position lives in var/state.db keyed by path,
     * so a file that was ingested before, removed, and added again resumes from where it stopped
     * rather than replaying — and a genuinely new file is read from its END, so adding one never
     * floods the index with history nobody asked for.
     */
    private function addSource(): string
    {
        $anchor = '#set-sources';

        $path   = is_string($_POST['path'] ?? null) ? $_POST['path'] : '';
        $format = is_string($_POST['format'] ?? null) ? $_POST['format'] : '';
        $regex  = is_string($_POST['regex'] ?? null) ? $_POST['regex'] : '';

        $result = Detector::manualSource($this->cfg, $path, $format, $regex);
        if (!$result['ok']) {
            self::stashSourceNote($result['error']);
            return '?v=settings&err=source_refused' . $anchor;
        }

        $problems = Steps::applySources($this->cfg, [$result['source']]);
        if ($problems !== []) {
            self::stashSourceNote(implode(' ', $problems));
            return '?v=settings&err=source_refused' . $anchor;
        }

        $err = $this->persist();
        if ($err !== null) {
            return '?v=settings&err=' . $err . $anchor;
        }

        return '?v=settings&ok=source_added' . $anchor;
    }

    /** Queue the precise reason a source was refused, for the card to render once. */
    private static function stashSourceNote(string $text): void
    {
        Security::startSession();
        $_SESSION['lh_settings_source_note'] = $text;
    }

    /** Read and clear it. */
    private static function takeSourceNote(): string
    {
        Security::startSession();
        $note = $_SESSION['lh_settings_source_note'] ?? '';
        unset($_SESSION['lh_settings_source_note']);
        return is_string($note) ? $note : '';
    }

    /**
     * The form that adds a log file by hand, with the same format list the installer offers.
     *
     * Rendered inside the log-sources card as an addition. The custom-pattern field is shown
     * and hidden by the same `#regex-row` behaviour the installer uses, so the control behaves
     * identically on both screens; a pattern that does not compile, or one that backtracks badly
     * enough to stall ingestion, is refused at save time here exactly as it is there.
     */
    private function addSourcePart(): void
    {
        self::problemBanner(self::takeSourceNote());

        $roots = (array) $this->cfg->get('allowed_log_roots', []);

        echo '<h4>Add a log file by hand</h4>';
        echo '<p class="muted">For a log the scan cannot see. It has to be inside '
            . Security::esc(implode(', ', array_map('strval', $roots)))
            . ' — that list is a safety control and it is never widened from a web form. To read a '
            . 'file outside it, run <code class="mono">' . Security::esc(self::setupCommand())
            . '</code>, which asks at a terminal, or add the directory to '
            . '<code>allowed_log_roots</code> in the config file.</p>';

        echo '<form method="post" action="?v=settings" class="setup-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="add_source">';

        echo '<label for="src_path">Path to the access log</label>';
        echo '<input type="text" id="src_path" name="path" size="44" autocomplete="off" '
            . 'spellcheck="false" required>';

        echo '<label for="format">Format</label>';
        echo '<select id="format" name="format">';
        foreach (Detector::formatChoices() as $value => $label) {
            echo '<option value="' . Security::esc((string) $value) . '">'
                . Security::esc((string) $label) . '</option>';
        }
        echo '</select>';

        echo '<div id="regex-row" hidden>';
        echo '<label for="regex">Pattern, with named groups</label>';
        echo '<input type="text" id="regex" name="regex" size="44" autocomplete="off" spellcheck="false">';
        echo '<p class="muted">Checked before it is stored: a pattern that does not compile, or one '
            . 'that backtracks badly enough to stall ingestion, is refused here rather than at three '
            . 'in the morning.</p>';
        echo '</div>';

        echo '<button type="submit" class="primary">Add this file</button>';
        echo '</form>';
    }

    /**
     * Move this installation onto a different pair of Opensolr indexes, after installation.
     *
     * THE SAME WORK THE INSTALLER DOES, through the same steps. Storage::reuseSteps() is the
     * one definition of what adopting a pair MEANS — confirm the account still holds it, read
     * the connection details, compare the live schema against this release's, verify both cores
     * answer — and running it here rather than reimplementing it is what stops the panel and the
     * installer from drifting into two different ideas of the same operation.
     *
     * IT RUNS SYNCHRONOUSLY, which is safe only because none of those steps creates anything.
     * The provisioning path is a browser-driven job precisely because creating two indexes and
     * uploading four files takes longer than a gateway will hold a request; adopting a pair is a
     * handful of reads and one optional upload, and a request that times out here has changed
     * nothing that matters — the steps write the configuration as they go and the whole thing is
     * re-runnable from the same screen.
     *
     * NOTHING IN THE OLD PAIR IS TOUCHED. It is not cleared, not deleted, not reshaped; this
     * installation simply stops reading and writing it. That is worth saying on the way out,
     * because "switch" is a word that sounds like a move.
     */
    private function switchPair(): string
    {
        $anchor = '#set-solr';

        /* A SECOND FACTOR, ON EXACTLY THE REASONING saveOpensolrCredentials() GIVES. That method
           demands one because "being able to REPLACE it from a stolen session means pointing this
           installation at an account the attacker controls — every future visitor record then
           lands in their indexes, quietly, while the panel keeps looking healthy". Repointing the
           core pair achieves the same redirection of the write path, and it did not ask. */
        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            return '?v=settings&err=' . $refused . $anchor;
        }

        $installId = is_string($_POST['install_id'] ?? null) ? $_POST['install_id'] : '';
        if (!preg_match('/^[a-f0-9]{4,32}$/D', $installId)) {
            return '?v=settings&err=pair_unknown' . $anchor;
        }

        $was = [
            'hits'     => (string) $this->cfg->get('solr.hits_core', ''),
            'sessions' => (string) $this->cfg->get('solr.sessions_core', ''),
        ];

        try {
            $job = Job::create($this->cfg->varDir() . '/setup', Job::KIND_REUSE, [
                'install_id'     => $installId,
                'upgrade_schema' => ($_POST['upgrade_schema'] ?? '') === '1',
            ]);
        } catch (\Throwable $e) {
            self::stashSolrNote('bad', 'The job store could not be opened: ' . Jobs::redact($e->getMessage()));
            return '?v=settings&err=pair_failed' . $anchor;
        }

        if (!$job->runAll($this->cfg, self::root())) {
            self::stashSolrNote('bad', Jobs::redact($job->error()));
            return '?v=settings&err=pair_failed' . $anchor;
        }

        $now = (string) $this->cfg->get('solr.hits_core', '');
        self::stashSolrNote(
            'good',
            'This installation now reads and writes ' . $now . ' and '
            . (string) $this->cfg->get('solr.sessions_core', '') . '. '
            . ($was['hits'] === '' || $was['hits'] === $now
                ? 'Nothing else changed.'
                : 'Nothing in ' . $was['hits'] . ' or ' . $was['sessions'] . ' was deleted, cleared or '
                    . 'moved — they are still on your account with everything in them, and this '
                    . 'installation has simply stopped using them. The panel now shows what is in the '
                    . 'new pair, which is not the same history.')
        );

        return '?v=settings&ok=pair_switched' . $anchor;
    }

    /**
     * The pairs this account holds, offered as somewhere else to point this installation.
     *
     * One control-plane read per render of this card, which is the same cost the installer's
     * storage step pays and for the same reason: a list of indexes that is a minute stale is a
     * list that offers something already deleted. A failed read is reported and the rest of the
     * card still renders.
     *
     * An unmatched half is shown as what it is rather than hidden, exactly as in the installer —
     * it is billable, and a leftover nobody mentions is a leftover nobody deletes.
     */
    private function pairSwitchPart(): void
    {
        if ((string) $this->cfg->get('opensolr.api_key', '') === '') {
            return;
        }

        $account = Storage::account($this->cfg);

        echo '<h4>Use a different pair of indexes</h4>';

        if (!$account['ok']) {
            echo '<p class="muted">' . Security::esc($account['error']) . '</p>';
            return;
        }

        echo '<p class="muted">' . Security::esc($account['capacity']['sentence']) . '</p>';

        foreach ($account['halves'] as $half) {
            echo '<p class="muted"><span class="mono">' . Security::esc((string) $half['name'])
                . '</span> is on this account without its matching <span class="mono">'
                . Security::esc((string) $half['missing']) . '</span> — what a setup run that stopped '
                . 'half way leaves behind. It cannot be used as a pair and it still counts against '
                . 'your plan.</p>';
        }

        $others = [];
        foreach ($account['pairs'] as $pair) {
            if (!Pairs::isCurrent($this->cfg, $pair)) {
                $others[] = $pair;
            }
        }

        if ($others === []) {
            echo '<p class="muted">This account has no other Loghound pair to move to. A new pair is '
                . 'created by running setup.</p>';
            return;
        }

        echo '<p class="muted">Moving this installation onto another pair does not delete, clear or '
            . 'move anything in the one it is using now — that pair stays on your account with '
            . 'everything in it, and the panel simply starts showing the other one instead.</p>';

        echo '<form method="post" action="?v=settings" class="setup-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="opensolr_pair">';

        $first = true;
        foreach ($others as $pair) {
            echo '<label class="radio">';
            echo '<input type="radio" name="install_id" value="'
                . Security::esc((string) $pair['install_id']) . '"' . ($first ? ' checked' : '') . ' required>';
            echo '<span><span class="mono">' . Security::esc((string) $pair['hits']) . '</span><br>'
                . '<span class="mono">' . Security::esc((string) $pair['sessions']) . '</span></span>';
            echo '</label>';
            $first = false;
        }

        echo '<label class="check"><input type="checkbox" name="upgrade_schema" value="1"> '
            . 'Add the fields this version writes, if that pair was made by an older Loghound</label>';
        echo '<p class="muted">Unticked, the shape is checked first and the move stops if it does not '
            . 'match, changing nothing.</p>';

        echo '<button type="submit" class="primary">Use this pair</button>';
        echo '</form>';
    }

    /**
     * Which of this installation's two indexes the CURRENTLY CONFIGURED account does not hold.
     *
     * A pair belongs to an account, so changing the account and keeping the pair is a
     * combination that can be wrong — and it fails silently: the credentials authenticate, the
     * configuration saves, and the panel then reads nothing because the platform refuses every
     * query for an index this account does not own. Catching it here turns a mystery into a
     * sentence at the moment the operator can still say no.
     *
     * Called with the candidate credentials already on the in-memory configuration, so the
     * client it builds is the NEW account's.
     *
     * A read that fails returns nothing rather than everything: refusing a credential change
     * because the network hiccuped would block the very edit that fixes a broken account, and
     * the outcome line still reports that the check could not be made.
     *
     * @return string[] Index names the account does not hold.
     */
    private function indexesNotOwned(): array
    {
        $wanted = array_values(array_filter([
            (string) $this->cfg->get('solr.hits_core', ''),
            (string) $this->cfg->get('solr.sessions_core', ''),
        ]));

        if ($wanted === []) {
            return [];
        }

        try {
            $held = Storage::client($this->cfg)->listIndexes();
        } catch (\Throwable $e) {
            return [];
        }

        return array_values(array_diff($wanted, $held));
    }

    /**
     * Demand a current second factor when one is configured, and nothing when one is not.
     *
     * Exactly what totpDisable() and totpRegenerate() demand, through the same per-address
     * ledger and paying the same delay on a wrong code. An endpoint that checks a six-digit
     * code without counting it is not a weaker control, it is none — and the attacker it exists
     * to stop is the one already holding a session.
     *
     * @return string A flash error code, or '' when the request may proceed.
     */
    private function requireSecondFactor(): string
    {
        if (!TwoFactor::isEnabled((array) $this->cfg->get('auth', []))) {
            return '';
        }

        $blocked = $this->factorGate();
        if ($blocked !== '') {
            return $blocked;
        }

        $code = is_string($_POST['code'] ?? null) ? $_POST['code'] : '';
        if (TwoFactor::check($this->cfg, $code, $this->cfg->varDir()) === 'no') {
            $this->factorFailure();
            return 'totp_bad_code';
        }

        return '';
    }

    /**
     * Put the Opensolr settings back as they were, in memory only.
     *
     * The refusal path never calls persist(), so the file on disk was never touched; this
     * restores the running request's view of the configuration so that whatever renders next
     * — the redirect target included — describes what is actually stored rather than the
     * candidate that was just rejected.
     *
     * @param array{email:string,key:string,region:string,mode:string} $before
     */
    private function restoreOpensolr(array $before): void
    {
        $this->cfg->set('opensolr.email', $before['email']);
        $this->cfg->set('opensolr.api_key', $before['key']);
        $this->cfg->set('opensolr.region', $before['region']);
        $this->cfg->set('solr.mode', $before['mode']);
    }

    /**
     * Which region the change should end up on, or null when the operator asked for a bad one.
     *
     * A region the operator TYPED is held to the platform's list and refused if it is not on
     * it. A region merely carried over from before is not: an account can legitimately stop
     * offering a region it once did, and refusing the whole credential change because of a
     * stale value would block the very edit that fixes it. In that case the region is cleared
     * and the outcome says so.
     *
     * @param string[] $regions
     */
    private function settleRegion(string $wanted, array $regions, bool $explicit): ?string
    {
        if ($wanted === '') {
            return '';
        }
        if (in_array($wanted, $regions, true)) {
            return $wanted;
        }
        return $explicit ? null : '';
    }

    /**
     * Did this change move the installation to a different Opensolr account?
     *
     * A new email is the obvious case. A new KEY is treated as one too, because an API key is
     * bound to an account: a key that is not the stored one either belongs to somebody else's
     * account or is a reissued key for this one, and only the first of those matters — the
     * second costs nothing but a re-learned allowance.
     *
     * @param array{email:string,key:string,region:string,mode:string} $before
     */
    private function accountMoved(array $before, string $email, string $key): bool
    {
        if ($email !== '' && strcasecmp($email, $before['email']) !== 0) {
            return true;
        }
        return $key !== '' && $key !== $before['key'];
    }

    /**
     * One sentence saying what the change did, and what it costs if it moved accounts.
     *
     * A CHANGE OF ACCOUNT IS NOT A MOVE OF DATA, and saying so is the point. The two indexes
     * this installation writes to belong to whoever created them; pointing the panel at another
     * account does not carry them across, and if the new account does not hold them the panel
     * stops being able to read its own history. That is checked here rather than left to be
     * discovered as an empty dashboard.
     *
     * The region is described for what it actually controls — where indexes created LATER are
     * placed — because implying that changing it relocates an existing index would be a
     * confident lie about somebody's data.
     *
     * @param array{email:string,key:string,region:string,mode:string} $before
     */
    private function credentialOutcome(array $before, string $region, bool $moved): string
    {
        $text = 'Opensolr accepted these credentials and they are stored.';

        if ($region !== $before['region']) {
            $text .= ' The region is now ' . ($region === '' ? 'unset' : $region)
                . ', which decides where any indexes created from here LAND — the two you already '
                . 'have stay exactly where they were made.';
        }

        if (!$moved) {
            return $text;
        }

        $text .= ' This is a different account.';

        $hits     = (string) $this->cfg->get('solr.hits_core', '');
        $sessions = (string) $this->cfg->get('solr.sessions_core', '');
        if ($hits === '' || $sessions === '') {
            return $text;
        }

        try {
            $held = Storage::client($this->cfg)->listIndexes();
        } catch (\Throwable $e) {
            return $text . ' Whether this account holds ' . $hits . ' and ' . $sessions
                . ' could not be checked just now — run the connection check below.';
        }

        if (in_array($hits, $held, true) && in_array($sessions, $held, true)) {
            return $text . ' It holds both of the indexes this installation uses, so nothing else changes.';
        }

        return $text . ' WARNING: this account does not hold ' . $hits . ' and ' . $sessions
            . ', which is where all of your history is. The panel will read nothing until you point '
            . 'it at indexes this account owns — use "Use a different pair of indexes" below, or run '
            . self::setupCommand() . ', either of which will offer you any Loghound pairs it has. '
            . 'Or put the previous account back here.';
    }

    /**
     * Refuse a credential change, keeping the precise reason out of the query string.
     *
     * The reason has to be specific — "Opensolr did not accept this email address and API key"
     * is actionable and "that did not work" is not — and it is text from a remote service, so
     * it can never travel in a URL that gets echoed. The flash map exists precisely to keep
     * anything from the query string out of the page; this puts the sentence in the session
     * instead and the card renders it, escaped, once.
     */
    private function refuseCredentials(string $why, string $anchor): string
    {
        self::stashSolrNote('bad', $why);
        return '?v=settings&err=opensolr_refused' . $anchor;
    }

    /**
     * Queue a one-shot sentence for the Solr card, and read it back exactly once.
     *
     * In the session rather than the query string, for the reason refuseCredentials() gives.
     * Never carries a credential: every caller passes either a fixed sentence or one built by
     * Storage::explainApi(), which scrubs before it returns.
     *
     * @param string $kind 'good', 'warn' or 'bad'; anything else is treated as 'bad'.
     */
    private static function stashSolrNote(string $kind, string $text): void
    {
        Security::startSession();
        $_SESSION['lh_settings_solr_note'] = [
            'kind' => in_array($kind, ['good', 'warn'], true) ? $kind : 'bad',
            'text' => $text,
        ];
    }

    /**
     * @return array{kind:string,text:string}|null
     */
    private static function takeSolrNote(): ?array
    {
        Security::startSession();
        $note = $_SESSION['lh_settings_solr_note'] ?? null;
        unset($_SESSION['lh_settings_solr_note']);

        return is_array($note)
            ? ['kind' => (string) $note['kind'], 'text' => (string) $note['text']]
            : null;
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
        if (!preg_match('/^[0-9a-f]{16}$/D', $id)) {
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
        /* A SECOND FACTOR, BECAUSE THIS DECIDES WHAT IS STORED ABOUT EVERY FUTURE VISITOR.
           Moving ip_mode back to `full` from a stolen session de-anonymises an installation
           that had chosen not to keep addresses, silently, and the operator's only evidence
           would be the data itself. A privacy posture that one stolen cookie can reverse is
           not a posture. */
        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            return '?v=settings&err=' . $refused . '#set-privacy';
        }

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
        /* A SECOND FACTOR, BECAUSE THIS IS A WAY TO TURN THE SECOND FACTOR OFF. The two-factor
           section only operates in session mode (twoFactorSection() refuses outside it), so
           moving the panel to Basic from a stolen session sidesteps the factor without ever
           presenting one — which is precisely what totpDisable() exists to prevent. */
        $refused = $this->requireSecondFactor();
        if ($refused !== '') {
            return '?v=settings&err=' . $refused . '#set-auth';
        }

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
            'Applies to the next request. Your username and password are changed further down this card.'
        );

        if (!$haveAccount) {
            echo '<div class="banner banner-warn">No username and password are stored, so there is nothing to '
                . 'sign in with yet. Set them with <code class="mono">' . Security::esc(self::setupCommand())
                . '</code> first.</div>';
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

        $this->passwordPart();

        echo '<p class="muted">Or change it from a shell, which a headless install still needs. Every '
            . 'prompt is defaulted to the stored value, so Enter through the rest and change only what '
            . 'you came for.</p>';
        self::commandBlock('set-auth-setup', self::setupGroup());

        $this->rememberedPart($mode);

        self::cardEnd();
    }

    /**
     * The "stay signed in" part of the sign-in card: what it costs, and how to take it back.
     *
     * There is nothing to configure here and that is deliberate. The option is taken on the
     * sign-in form, per browser, by the person sitting at it — a switch on this page that turned
     * it on for everybody would be a setting that changes how somebody else's browser behaves.
     * What this page owns is the part the sign-in form cannot: saying how many browsers are
     * currently remembered, and destroying all of them.
     *
     * THE COST IS STATED PLAINLY AND NOT DRESSED UP. An operator who has taken this option has
     * no timeout protecting them, so whoever holds that browser profile is signed in until
     * somebody presses Sign out. Anyone choosing that deserves to be told rather than reassured.
     */
    private function rememberedPart(string $mode): void
    {
        if ($mode !== 'session') {
            return;
        }

        $count = Persistence::count($this->cfg->varDir());

        echo '<h3>Stay signed in</h3>';
        echo '<p class="muted">The sign-in form offers a <strong>Stay signed in on this browser</strong> '
            . 'box. A browser that takes it is signed in with <strong>no idle timeout and no maximum '
            . 'session age</strong> — it survives closing the browser and restarting the machine, and it '
            . 'ends only when somebody presses Sign out. Whoever has that browser profile has this panel. '
            . 'Sessions that do not take it still expire after '
            . Security::esc(self::minutes((int) $this->cfg->get('auth.idle_timeout', 1800)))
            . ' idle and '
            . Security::esc(self::minutes((int) $this->cfg->get('auth.absolute_timeout', 43200)))
            . ' in total, exactly as before.</p>';

        echo '<p>' . ($count === 0
            ? 'No browser is currently remembered.'
            : Security::esc($count === 1
                ? 'One browser is currently remembered.'
                : $count . ' browsers are currently remembered.'))
            . '</p>';

        if ($count > 0) {
            echo '<form method="post" action="?v=settings">';
            self::csrfField();
            echo '<input type="hidden" name="action" value="revoke_remembered">';
            echo '<button type="submit" class="ghost">Sign every remembered browser out</button>';
            echo '</form>';
            echo '<p class="muted">Including this one, if it is one of them. Signing out, changing your '
                . 'password and changing the sign-in method above all do the same thing.</p>';
        }
    }

    /**
     * A duration as a sentence a reader can check against their own expectation.
     *
     * Minutes up to an hour, then hours: "30 minutes", "12 hours". Not a humanising flourish —
     * the numbers in this card are the ones an operator compares with what they configured, and
     * "1800 seconds" is not a figure anybody holds in their head.
     */
    private static function minutes(int $seconds): string
    {
        if ($seconds < 3600) {
            $n = max(1, (int) round($seconds / 60));
            return $n . ($n === 1 ? ' minute' : ' minutes');
        }
        $n = (int) round($seconds / 3600);
        return $n . ($n === 1 ? ' hour' : ' hours');
    }

    /**
     * Two-factor authentication: enrollment, recovery codes, and turning it off.
     *
     * FOUR STATES, and each one is a different card because they are different questions:
     *   off        — an explanation and one button.
     *   enrolling  — the QR code, the secret as text, and a field for a code to confirm it.
     *   codes      — the recovery codes, shown exactly once, with a download.
     *   on         — what is protecting the account, and the two ways to change that.
     *
     * RENDERED ENTIRELY ON THE SERVER, with ordinary forms and POST/Redirect/GET. The panel has a
     * shared dialog shell and this deliberately does not use it: that shell fetches a record over
     * the API and renders it with textContent, so putting enrollment through it would mean
     * sending the shared secret to JavaScript and rebuilding three thousand SVG modules in the
     * DOM. The secret is drawn where it is generated, it never crosses a request boundary it does
     * not have to, and the whole flow works with JavaScript off — which is the right trade for
     * the one screen in the product whose failure mode is an operator locked out of their panel.
     */
    private function twoFactorSection(): void
    {
        $auth = (array) $this->cfg->get('auth', []);
        $on = TwoFactor::isEnabled($auth);
        $pending = $on ? '' : TwoFactor::pendingSecret();
        $codes = TwoFactor::takeCodes();

        self::cardOpen(
            'set-2fa',
            self::sectionNum('set-2fa'),
            'Two-factor authentication',
            $on
                ? 'On. Signing in needs your password and a code from your authenticator app.'
                : 'Off. A stolen password is enough to sign in.'
        );

        if ((string) $this->cfg->get('auth.mode', 'none') !== 'session') {
            echo '<div class="banner banner-warn">Two-factor needs the sign-in page. HTTP Basic has no '
                . 'second step to put a code in — the browser\'s own prompt asks for a username and a '
                . 'password and nothing else. Switch the sign-in method above to the sign-in page first.</div>';
            self::cardEnd();
            return;
        }

        if ($codes !== []) {
            $this->recoveryCodesPart($codes);
        }

        if ($on) {
            $this->twoFactorOnPart($auth);
        } elseif ($pending !== '') {
            $this->enrollPart($pending);
        } else {
            $this->twoFactorOffPart();
        }

        self::cardEnd();
    }

    /** The off state: what it buys, and the one button that starts it. */
    private function twoFactorOffPart(): void
    {
        echo '<p>With two-factor on, signing in takes your password <em>and</em> a six-digit code from an '
            . 'authenticator app on your phone. Somebody who learns your password — from a reused '
            . 'credential, a keylogger, a look over your shoulder — still cannot get in.</p>';
        echo '<p class="muted">Any standard app works: Google Authenticator, Aegis, 1Password, Bitwarden, '
            . 'FreeOTP. Loghound draws the QR code itself, on this machine, so the shared secret is never '
            . 'sent to anybody else.</p>';

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_begin">';
        echo '<button type="submit" class="primary">Set up two-factor authentication</button>';
        echo '</form>';
    }

    /**
     * The enrolling state: scan this, or type it, then prove it worked.
     *
     * The secret is shown as text as well as a QR code, because a QR code is no use on a machine
     * whose camera is the thing being set up, and because an operator entering it into a password
     * manager needs to select it. It is grouped in fours for reading off a screen; Base32 decoding
     * strips the spaces again, so what is displayed and what the app is given are the same secret.
     */
    private function enrollPart(string $secret): void
    {
        $svg = TwoFactor::qr($this->cfg, $secret);

        echo '<ol class="steps-2fa">';
        echo '<li><strong>Scan this with your authenticator app.</strong>';
        if ($svg !== null) {
            echo '<div class="qr-frame">' . $svg . '</div>';
        } else {
            echo '<p class="muted">The QR code could not be drawn for this account name. Type the key '
                . 'below into the app by hand instead — it is exactly equivalent.</p>';
        }
        echo '</li>';

        echo '<li><strong>Or type the key in by hand.</strong>';
        echo '<p class="qr-key mono">' . Security::esc(Base32::group($secret)) . '</p>';
        echo '<p class="muted">Time-based, six digits, 30 seconds — the defaults every app uses. The '
            . 'spaces are only there to be read; leave them out or type them, it makes no difference.</p>';
        echo '</li>';

        echo '<li><strong>Enter the code the app shows now.</strong>';
        echo '<form method="post" action="?v=settings" class="setup-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_enable">';
        echo '<label for="totp-confirm">Six-digit code</label>';
        echo '<input type="text" id="totp-confirm" name="code" size="12" inputmode="numeric" '
            . 'autocomplete="one-time-code" spellcheck="false" required>';
        echo '<button type="submit" class="primary">Turn on two-factor</button>';
        echo '</form>';
        echo '<p class="muted">Nothing is saved until this code is accepted, so closing this page now '
            . 'leaves two-factor off and locks nobody out.</p>';
        echo '</li>';
        echo '</ol>';

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_cancel">';
        echo '<button type="submit" class="ghost small">Cancel this setup</button>';
        echo '</form>';
    }

    /**
     * The recovery codes, shown exactly once.
     *
     * Once, because only their hashes are stored — there is nothing to show again. The download
     * posts them back rather than re-reading them from anywhere, which is why the form carries
     * them in hidden fields: this request is the last one that has them.
     *
     * @param string[] $codes
     */
    private function recoveryCodesPart(array $codes): void
    {
        echo '<div class="banner banner-warn" role="alert">These ten codes are shown <strong>once</strong>. '
            . 'Only their hashes are stored, so this page cannot show them again. Each one works once in '
            . 'place of a code from your app, and they are the only way back in if you lose the phone. '
            . 'Save them somewhere a stranger cannot reach, and not beside your password.</div>';

        echo '<ul class="recovery-codes mono">';
        foreach ($codes as $code) {
            echo '<li>' . Security::esc($code) . '</li>';
        }
        echo '</ul>';

        echo '<form method="post" action="?v=settings">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_download">';
        foreach ($codes as $code) {
            echo '<input type="hidden" name="codes[]" value="' . Security::esc($code) . '">';
        }
        echo '<button type="submit" class="primary">Download them as a text file</button>';
        echo '</form>';
    }

    /**
     * The on state: what is protecting the account, and the two ways to change it.
     *
     * The remaining-codes figure is there because running out silently is how somebody ends up
     * locked out: each recovery code is consumed when it is used, and nothing else in the panel
     * would ever mention it.
     *
     * @param array<string,mixed> $auth
     */
    private function twoFactorOnPart(array $auth): void
    {
        $left = TwoFactor::recoveryRemaining($auth);

        echo '<p>Two-factor is on. Signing in asks for your password, then a six-digit code.</p>';

        echo '<p' . ($left <= 2 ? ' class="warn-text"' : '') . '>'
            . Security::esc($left === 0
                ? 'No recovery codes are left. If you lose the phone, the only way back in is '
                    . self::setupCommand() . ' on the server.'
                : ($left === 1
                    ? 'One recovery code is left.'
                    : $left . ' recovery codes are left.'))
            . '</p>';

        echo '<h3>New recovery codes</h3>';
        echo '<form method="post" action="?v=settings" class="setup-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_regenerate">';
        echo '<label for="totp-regen">Current code, or a recovery code</label>';
        echo '<input type="text" id="totp-regen" name="code" size="24" inputmode="numeric" '
            . 'autocomplete="one-time-code" spellcheck="false" required>';
        echo '<button type="submit" class="ghost">Show a new set of recovery codes</button>';
        echo '</form>';
        echo '<p class="muted">A new set replaces the old one, so every code you have written down stops '
            . 'working the moment you press this. It costs a code for the same reason turning two-factor '
            . 'off does: ten fresh recovery codes are a standing way past the phone, so a stolen session '
            . 'must not be able to mint them.</p>';

        echo '<h3>Turn two-factor off</h3>';
        echo '<form method="post" action="?v=settings" class="setup-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="totp_disable">';
        echo '<label for="totp-off">Current code, or a recovery code</label>';
        echo '<input type="text" id="totp-off" name="code" size="24" inputmode="numeric" '
            . 'autocomplete="one-time-code" spellcheck="false" required>';
        echo '<button type="submit" class="ghost">Turn two-factor off</button>';
        echo '</form>';
        echo '<p class="muted">A code is required, not just being signed in. If a stolen session were '
            . 'enough to remove the second factor, the second factor would be protecting nothing. Turning '
            . 'it off also signs out every browser that chose to stay signed in.</p>';
    }

    /**
     * Destroy every "stay signed in" token.
     *
     * The panel's own answer to a lost laptop. It is the one revocation an operator can perform
     * without shell access and without changing their password, and it takes effect on the next
     * request every one of those browsers makes — including this one, which is why the flash
     * message says so rather than letting it come as a surprise.
     */
    private function revokeRemembered(): string
    {
        Persistence::revokeAll($this->cfg->varDir());

        return '?v=settings&ok=remembered_revoked#set-auth';
    }

    /**
     * May this address try a second factor right now?
     *
     * EVERY ENDPOINT THAT VERIFIES A CODE IS BEHIND THIS ONE, and that is the whole point.
     * Six digits is a million possibilities: a code is only as strong as the number of guesses
     * allowed against it, so an endpoint that checks one without counting is not a weaker
     * control, it is no control. These three live inside the panel and are reachable with a
     * session cookie alone — which is precisely the position an attacker who stole a session is
     * in, and the second factor exists to be the thing they still cannot produce. Turning it off
     * is the most valuable of the three, so it is the last place that may be a free oracle.
     *
     * They share the sign-in form's per-address ledger rather than a counter of their own, so
     * guesses cannot be laundered by alternating between the sign-in page and this one.
     *
     * @return string '' when the attempt may proceed, otherwise a flash error code.
     */
    private function factorGate(): string
    {
        $auth = (array) $this->cfg->get('auth', []);
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));

        $gate = Security::loginGate($ip, $auth, $this->cfg->varDir());

        if (!$gate['available']) {
            return 'totp_store';
        }
        if (!$gate['allowed']) {
            return 'totp_locked';
        }
        return '';
    }

    /**
     * Record a wrong code, and pay the same delay a wrong password pays.
     *
     * The delay matters as much as the count. Without it this endpoint answers faster than the
     * sign-in form does, which makes it the cheaper place to grind — and an attacker will always
     * pick the cheaper one.
     */
    private function factorFailure(): void
    {
        $auth = (array) $this->cfg->get('auth', []);
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));

        Security::loginFailure($ip, $auth, $this->cfg->varDir());
        usleep(random_int(150000, 400000));
    }

    /**
     * Mint a candidate two-factor secret and show the QR code.
     *
     * Nothing is stored in the configuration here: the secret lives in this session until a code
     * proves the operator's app has it. An enrollment already in progress is replaced, because
     * the only reason to press this button twice is that the first QR code did not scan.
     */
    private function totpBegin(): string
    {
        if (TwoFactor::isEnabled((array) $this->cfg->get('auth', []))) {
            return '?v=settings&err=totp_already_on#set-2fa';
        }

        TwoFactor::beginEnrollment();

        return '?v=settings#set-2fa';
    }

    /** Throw away an enrollment in progress. */
    private function totpCancel(): string
    {
        TwoFactor::cancelEnrollment();

        return '?v=settings&ok=totp_cancelled#set-2fa';
    }

    /**
     * Turn two-factor on, given a code that proves the candidate secret arrived.
     *
     * The recovery codes come back in plaintext once and are parked in the session for the
     * render that follows this redirect. Everything else about the write — the secret, the code
     * hashes, the revocation of every persistent-login token — is TwoFactor::enable()'s.
     *
     * A configuration that cannot be written must not leave two-factor half on, so the enable is
     * rolled back in memory and reported as a storage failure rather than a wrong code.
     */
    private function totpEnable(): string
    {
        $blocked = $this->factorGate();
        if ($blocked !== '') {
            return '?v=settings&err=' . $blocked . '#set-2fa';
        }

        $secret = TwoFactor::pendingSecret();
        if ($secret === '') {
            return '?v=settings&err=totp_expired#set-2fa';
        }

        $code = is_string($_POST['code'] ?? null) ? $_POST['code'] : '';
        $result = TwoFactor::enable($this->cfg, $secret, $code, $this->cfg->varDir());

        if ($result['errors'] !== []) {
            $this->factorFailure();
            return '?v=settings&err=totp_bad_code#set-2fa';
        }

        $err = $this->persist();
        if ($err !== null) {
            $this->cfg->set('auth.totp', ['enabled' => false, 'secret' => '', 'recovery' => []]);
            return '?v=settings&err=' . $err . '#set-2fa';
        }

        TwoFactor::cancelEnrollment();
        TwoFactor::stashCodes($result['codes']);

        return '?v=settings&ok=totp_on#set-2fa';
    }

    /**
     * Turn two-factor off, which costs a current code or a recovery code.
     *
     * Never just the session. A session cookie is one secret; if it were enough to strip the
     * second factor, stealing it would be enough to reduce the account to one factor and the
     * factor would be protecting nothing.
     */
    private function totpDisable(): string
    {
        $blocked = $this->factorGate();
        if ($blocked !== '') {
            return '?v=settings&err=' . $blocked . '#set-2fa';
        }

        $code = is_string($_POST['code'] ?? null) ? $_POST['code'] : '';

        if (TwoFactor::disable($this->cfg, $code, $this->cfg->varDir()) !== []) {
            $this->factorFailure();
            return '?v=settings&err=totp_bad_code#set-2fa';
        }

        $err = $this->persist();
        return $err !== null ? '?v=settings&err=' . $err . '#set-2fa' : '?v=settings&ok=totp_off#set-2fa';
    }

    /**
     * Issue a fresh set of recovery codes, invalidating the old set.
     *
     * COSTS A CURRENT FACTOR, like turning two-factor off, and for the same reason. A recovery
     * code is a standing credential that skips the second factor; being able to mint ten new
     * ones on demand is therefore equivalent to being able to remove the factor, only quieter.
     * If a session cookie alone were enough, stealing one would buy an attacker a permanent way
     * past the phone — and the operator's own codes would stop working, which is the only sign
     * they would ever get.
     */
    private function totpRegenerate(): string
    {
        if (!TwoFactor::isEnabled((array) $this->cfg->get('auth', []))) {
            return '?v=settings&err=totp_off_already#set-2fa';
        }

        $blocked = $this->factorGate();
        if ($blocked !== '') {
            return '?v=settings&err=' . $blocked . '#set-2fa';
        }

        $code = is_string($_POST['code'] ?? null) ? $_POST['code'] : '';
        if (TwoFactor::check($this->cfg, $code, $this->cfg->varDir()) === 'no') {
            $this->factorFailure();
            return '?v=settings&err=totp_bad_code#set-2fa';
        }

        $codes = TwoFactor::regenerate($this->cfg);

        $err = $this->persist();
        if ($err !== null) {
            return '?v=settings&err=' . $err . '#set-2fa';
        }

        TwoFactor::stashCodes($codes);

        return '?v=settings&ok=totp_codes#set-2fa';
    }

    /**
     * Hand the recovery codes back as a text file.
     *
     * The codes come from the form, because they are not stored in plaintext anywhere and this
     * is the only request that still has them. That makes the request body decide what the file
     * says, so every value is checked against the exact shape mintRecoveryCodes() produces and
     * the set is capped — nothing arbitrary can be routed through this into a download. The
     * filename is a literal for the same reason.
     *
     * @return never
     */
    private function totpDownload(): void
    {
        $submitted = $_POST['codes'] ?? [];
        $codes = [];

        foreach (is_array($submitted) ? $submitted : [] as $code) {
            if (is_string($code) && TwoFactor::looksLikeRecoveryCode($code)) {
                $codes[] = $code;
            }
            if (count($codes) >= TwoFactor::RECOVERY_CODES) {
                break;
            }
        }

        if ($codes === []) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            exit("There were no recovery codes in that request.\n");
        }

        $body = TwoFactor::recoveryFile((string) $this->cfg->get('site_name', 'Loghound'), $codes);

        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="loghound-recovery-codes.txt"');
        header('Content-Length: ' . strlen($body));
        header('Cache-Control: no-store, private');
        header('X-Content-Type-Options: nosniff');
        echo $body;
        exit;
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
            'remembered_revoked' => 'Every remembered browser was signed out. Each of them, including this '
                . 'one if it was among them, has to sign in again on its next request.',
            'totp_on'          => 'Two-factor is on. Save the recovery codes below now — this is the only '
                . 'time they can be shown.',
            'totp_off'         => 'Two-factor is off. Signing in needs only your password again, and every '
                . 'remembered browser was signed out.',
            'totp_codes'       => 'A new set of recovery codes was issued. The old set no longer works.',
            'totp_cancelled'   => 'Two-factor setup was cancelled. Nothing was stored and nothing changed.',
            'opensolr_saved'   => 'Opensolr account updated. The details are in the Solr card below.',
            'password_saved'   => 'Your sign-in was changed. Every remembered browser was signed out, '
                . 'so you will be asked for the new password on the next request.',
            'pair_switched'    => 'This installation now uses a different pair of indexes. What it was '
                . 'using before is still on your account, untouched.',
            'source_added'     => 'Log file added. The reader picks it up on its next reload, and starts '
                . 'from the end of the file rather than replaying its history.',
        ];
        $err = [
            'solr_down'       => 'Solr did not answer. Check the base URL, credentials and firewall.',
            'no_such_source'  => 'That log source is not in the detection report or the configuration any '
                . 'more. Run a scan to rebuild the list.',
            'path_not_allowed' => 'That path is outside allowed_log_roots and was refused.',
            'no_usable_format' => 'No usable log format was worked out for that file, so it was not '
                . 'stored. Add it by hand on the log sources card, or with the setup wizard, rather '
                . 'than ingesting on a guess.',
            'save_failed'     => 'The configuration file could not be written. Check ownership and mode 0640 on config/loghound.php.',
            'bad_ip_mode'     => 'Unknown IP privacy mode.',
            'bad_thresholds'  => 'Thresholds must descend: '
                . Vocabulary::label('bot_verdict_s', 'bot') . ' above '
                . Vocabulary::label('bot_verdict_s', 'likely_bot') . ' above '
                . Vocabulary::label('bot_verdict_s', 'unknown') . ' above '
                . Vocabulary::label('bot_verdict_s', 'likely_human') . '.',
            'bad_timezone'    => 'Unknown timezone.',
            'bad_auth_mode'   => 'That sign-in method was refused. Choose one of the two offered, and note that '
                . 'neither can be selected before a username and password have been set.',
            'unknown_action'  => 'Unknown action.',
            'totp_bad_code'   => 'That code was not accepted. Check that your phone\'s clock is right, then '
                . 'enter the code the app is showing now. Nothing was changed.',
            'totp_expired'    => 'That two-factor setup timed out, so the key was discarded. Start again to '
                . 'get a fresh QR code.',
            'totp_already_on' => 'Two-factor is already on. Turn it off first if you want to enrol a '
                . 'different phone.',
            'totp_off_already' => 'Two-factor is not on, so there are no recovery codes to reissue.',
            'totp_store'      => 'Loghound cannot record failed code attempts, because it cannot write to '
                . 'its var directory. It refuses to check a code rather than check one without counting '
                . 'it — give that directory to the user this panel runs as.',
            'totp_locked'     => 'Too many wrong codes from your address. Wait for the lockout window to '
                . 'pass and try again — the same limit that protects the sign-in form protects this.',
            'opensolr_refused' => 'The Opensolr account was NOT changed. What was already stored is still '
                . 'stored and still working; the reason is on the Solr card below.',
            'reinstall_unconfirmed' => 'Nothing was reset. Type REINSTALL in the box to confirm — the '
                . 'word is asked for because the list above it is worth reading first.',
            'bad_current_password' => 'That is not the current password, so nothing was changed. It is '
                . 'asked for because a session that outlives a closed browser must not be enough on '
                . 'its own to take the panel over.',
            'password_refused' => 'The new sign-in was refused and nothing was changed. The reason is '
                . 'on the sign-in card below.',
            'pair_unknown'     => 'Choose which pair of indexes to move to.',
            'pair_failed'      => 'The move did not finish, and nothing was changed at Opensolr. The '
                . 'reason is on the Solr card below.',
            'source_refused'   => 'That log file was not added. The reason is on the log sources card below.',
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

    /**
     * A problem inside a card, in the markup the accordion force-opens on.
     *
     * THE ACCORDION MUST NOT BE ABLE TO HIDE A FAILURE. Sections fold shut by default and
     * remember the operator's choice, and responsive.js force-opens any section carrying
     * `.check-row .chip-warn`, `.source-head .chip-warn` or a `.confirm-form`. A refusal
     * rendered only as a banner would therefore be correct, escaped, and inside a collapsed
     * card — which is the worst outcome the fold can produce.
     *
     * So every one-shot refusal on this page goes out through here, carrying the marker as
     * well as the sentence, and only when there IS something wrong: a card that always carried
     * the marker would be a card that never folds.
     */
    private static function problemBanner(string $text): void
    {
        if ($text === '') {
            return;
        }
        echo '<div class="check-row"><span class="chip chip-warn">Needs attention</span></div>';
        echo '<div class="banner banner-bad" role="alert">' . Security::esc($text) . '</div>';
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
        ['set-retention', 'Maintenance', 'retentionSection'],
        ['set-scoring', 'Scoring', 'scoringSection'],
        ['set-auth', 'Sign-in', 'authSection'],
        ['set-2fa', 'Two-factor', 'twoFactorSection'],
        ['set-display', 'Display', 'displaySection'],
        ['set-reinstall', 'Reinstall', 'reinstallSection'],
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
     * What the site itself can tell Loghound about a visitor.
     *
     * Two facts nothing else can supply: whether the visitor was signed in, and who they
     * were. Neither is inferred — no cookie is read, no form scraped, no meta tag hunted —
     * so if the site does not declare them they simply do not exist on the session.
     *
     * The two are deliberately independent, and the reason is the difference in what they
     * cost. The boolean identifies nobody and splits every number on the dashboard into
     * signed-in and anonymous, which is the most useful cut the product can offer and one
     * no log-only tool can compute. The identity string is personal data: it lands on the
     * session document, shows in the panel, lives in the search index and sits in every
     * backup of it until retention deletes the session. So it is off until somebody turns
     * it on, and turning on one does not turn on the other.
     *
     * The prose is Steps::beaconIdentityNote(), the same sentences the installer's beacon
     * step renders, so the two cannot drift.
     *
     * IT SITS UNDER THE SNIPPETS, not above them, and it reads the LIVE configuration. Both of
     * those are corrections of the same defect. It used to be config prose several screens
     * above the install tabs, describing two switches without ever showing the attributes they
     * govern, so an operator could read the whole card and still not know how to pass an email —
     * the attributes existed only in a JavaScript docblock and a markdown file, neither of which
     * anybody installing a snippet opens.
     *
     * And a card that describes the attributes without saying whether THIS installation will
     * store what they carry sets a trap: `beacon.store_identity` is false by default, so a site
     * that pastes the identity snippet has its emails discarded server-side, the panel shows
     * nothing, and there is no error anywhere to explain it. The snippet and the switch are one
     * story or they are a bug report waiting to happen.
     */
    private function beaconIdentityBlock(): void
    {
        $storesIdentity = (bool) $this->cfg->get('beacon.store_identity', false);
        $storesSignedIn = (bool) $this->cfg->get('beacon.store_signed_in', true);

        echo '<h3>Telling Loghound who the visitor is</h3>';
        echo '<p class="muted">' . Security::esc(Steps::beaconIdentityNote()) . '</p>';

        echo '<h4>On this installation, right now</h4>';

        echo '<div class="banner ' . ($storesIdentity ? 'banner-good' : 'banner-warn') . '">';
        if ($storesIdentity) {
            echo '<strong><code class="mono">data-ident</code> is stored.</strong> '
                . '<code class="mono">beacon.store_identity</code> is on, so an identity your site sends is '
                . 'written to the session document, is searchable and facetable in the panel, and stays in '
                . 'the index and in every backup of it until retention deletes the session.';
        } else {
            echo '<strong><code class="mono">data-ident</code> is DISCARDED.</strong> '
                . '<code class="mono">beacon.store_identity</code> is <code>false</code> in '
                . '<code>config/loghound.php</code> — the default — so if you paste the snippets above as they '
                . 'are, the address is dropped by the collector before anything is written and no identity will '
                . 'ever appear in the panel. Nothing will look broken and there will be no error to find. Set it '
                . 'to <code>true</code> first, or leave <code>data-ident</code> out of the snippet.';
        }
        echo '</div>';

        echo '<div class="banner ' . ($storesSignedIn ? 'banner-good' : 'banner-warn') . '">';
        if ($storesSignedIn) {
            echo '<strong><code class="mono">data-signed-in</code> is stored.</strong> '
                . '<code class="mono">beacon.store_signed_in</code> is on, so the signed-in / anonymous split '
                . 'is available on every view as the <em>Signed in</em> dimension.';
        } else {
            echo '<strong><code class="mono">data-signed-in</code> is DISCARDED.</strong> '
                . '<code class="mono">beacon.store_signed_in</code> has been turned off, so the flag is dropped '
                . 'before anything is written and the <em>Signed in</em> dimension will stay empty.';
        }
        echo '</div>';

        echo '<p class="muted">The two switches are independent, and that is the point rather than an '
            . 'oversight. <code class="mono">beacon.store_signed_in</code> is a boolean that identifies nobody, '
            . 'and the split it gives you — signed-in against anonymous — reads differently on engaged time, on '
            . 'paths taken and on the bot verdict, which is the most useful cut this product can offer. '
            . '<code class="mono">beacon.store_identity</code> is personal data. Plenty of sites want the first '
            . 'and not the second.</p>';

        echo '<h4>Three ways to supply it, for three different situations</h4>';
        echo '<p class="muted">They are not alternatives to pick between on taste. Each one is the only one '
            . 'that works in its situation.</p>';

        echo '<dl class="kv">';

        echo '<dt>Attributes on the script tag</dt><dd><strong>When your server already knows who it is at '
            . 'render time.</strong> This is the normal case and the one every tab above shows: the template '
            . 'that renders the page renders the tag, in the same response, so there is no second request, no '
            . 'extra script and no ordering problem.<br>'
            . '<code class="mono">' . Security::esc('<script src="…/b.js" data-ident="ada@example.com" '
                . 'data-signed-in="1" defer></script>') . '</code></dd>';

        echo '<dt><code class="mono">window.LoghoundIdent</code> / '
            . '<code class="mono">window.LoghoundSignedIn</code></dt><dd><strong>When adding an attribute to '
            . 'the tag is awkward but setting a variable above it is not</strong> — a tag manager, a templating '
            . 'system that owns the <code>&lt;script&gt;</code> element, a CMS block you cannot edit. They must '
            . 'be set <em>before</em> b.js executes, which with <code>defer</code> means anywhere in the '
            . 'document.<br>'
            . '<code class="mono">' . Security::esc('<script>window.LoghoundIdent="ada@example.com";'
                . 'window.LoghoundSignedIn=true;</script>') . '</code></dd>';

        echo '<dt><code class="mono">window.loghound.identify(ident, signedIn)</code></dt><dd><strong>When the '
            . 'identity arrives after the page has loaded</strong> — a single-page application that signs '
            . 'somebody in without a navigation, which no attribute can express. Both arguments are optional '
            . 'and independent. <strong>It makes no request of its own:</strong> the values ride the heartbeat '
            . 'that is already scheduled, so attaching an identity costs your site nothing extra.<br>'
            . '<code class="mono">' . Security::esc('window.loghound.identify("ada@example.com", true);')
            . '</code></dd>';

        echo '</dl>';

        echo '<p class="muted"><strong>An identity is capped at ' . Security::esc((string) \Loghound\Beacon::MAX_IDENT)
            . ' bytes</strong> and anything longer is truncated to it. That holds any email address, customer '
            . 'number or account id anybody sensibly uses as one; it is there because the collector is public, '
            . 'so the value is whatever the page chose to send, and an unbounded one would be a way to make '
            . 'every staging row large.</p>';

        echo '<p class="muted"><strong>Loghound never guesses either value.</strong> No cookie is read, no form '
            . 'is scraped, no meta tag is looked for and no <code>window</code> variable is hunted through. If '
            . 'your site does not say, the field does not exist.</p>';

        echo '<p class="muted">A third state matters and is easy to lose: a site that never '
            . 'answers is <strong>not reported</strong>, not anonymous. Loghound keeps those apart '
            . 'and counts them separately — <code class="mono">signed_in_b</code> is written only when a page '
            . 'actually said one or the other, so a site that has not adopted the attribute cannot be read as a '
            . 'site full of anonymous visitors.</p>';
    }

    /**
     * Every option `public/b.js` reads, as one table the interface can render.
     *
     * THE COMPLETE LIST, AND IT LIVES HERE RATHER THAN ONLY IN A DOCBLOCK. The full set of
     * attributes and globals used to exist in exactly two places — the header comment of
     * `public/b.js` and `docs/BEACON.md` — and the application itself printed a bare one-line
     * snippet and nothing else. An operator installing the beacon reads neither of those, so
     * every option beyond `src` was effectively undocumented for the person who needed it.
     *
     * Declared as data rather than written out as markup so that
     * tests/test_standalone.php can hold it against `b.js` itself: the option list is
     * mechanically derivable from the source — every `attr('data-…')`, every `attrInt('data-…')`
     * and every `w.Loghound…` — and a test that fails when the script grows an option this table
     * does not carry is worth more than a careful proof-read that was accurate on the day.
     *
     * Each entry: the option, what it does, its default, its accepted range or format, and the
     * configuration key that decides whether what it sends is actually STORED. A null `switch`
     * means nothing can discard it — the value is used by the script itself, or it is a
     * measurement rather than a declaration.
     *
     * @return array<int,array{name:string,kind:string,what:string,default:string,limits:string,switch:?string}>
     */
    public static function beaconOptions(): array
    {
        return [
            [
                'name'    => 'data-endpoint',
                'kind'    => 'attribute',
                'what'    => 'Collector URL, when it is not a sibling of b.js.',
                'default' => 'the script&rsquo;s own <code class="mono">src</code> with '
                    . '<code class="mono">b.js</code> &rarr; <code class="mono">collect.php</code>',
                'limits'  => 'Any URL. Set it only if you serve the script from a CDN or a different path.',
                'switch'  => null,
            ],
            [
                'name'    => 'data-hb',
                'kind'    => 'attribute',
                'what'    => 'Heartbeat interval, in milliseconds. A beat is sent only when engaged time '
                    . 'actually advanced, so an idle tab produces one, not hundreds.',
                'default' => '15000',
                'limits'  => 'Integer, clamped to 2&nbsp;000&ndash;300&nbsp;000. Anything else is ignored '
                    . 'and the default is used.',
                'switch'  => null,
            ],
            [
                'name'    => 'data-idle',
                'kind'    => 'attribute',
                'what'    => 'How long after a real interaction a visitor still counts as engaged, in '
                    . 'milliseconds. This is the definition of the <em>Engaged</em> clock.',
                'default' => '30000',
                'limits'  => 'Integer, clamped to 1&nbsp;000&ndash;600&nbsp;000.',
                'switch'  => null,
            ],
            [
                'name'    => 'data-ident',
                'kind'    => 'attribute',
                'what'    => 'An identity <strong>your site</strong> attaches to the session &mdash; an email '
                    . 'address, a customer number, whatever you call the person. Never guessed.',
                'default' => 'absent, and absent is not empty',
                'limits'  => 'Free text, truncated to ' . \Loghound\Beacon::MAX_IDENT . ' bytes. Control '
                    . 'characters stripped, invalid UTF-8 repaired.',
                'switch'  => 'beacon.store_identity',
            ],
            [
                'name'    => 'data-signed-in',
                'kind'    => 'attribute',
                'what'    => 'Whether the visitor was signed in. Splits every number in the panel into '
                    . 'signed-in and anonymous.',
                'default' => 'absent &mdash; which means <strong>not reported</strong>, never &ldquo;no&rdquo;',
                'limits'  => '<code class="mono">1</code>/<code class="mono">0</code> or '
                    . '<code class="mono">true</code>/<code class="mono">false</code>. Anything else, '
                    . 'including an empty attribute a template rendered blank, is read as not reported.',
                'switch'  => 'beacon.store_signed_in',
            ],
            [
                'name'    => 'data-params',
                'kind'    => 'attribute',
                'what'    => 'URL query parameter <strong>names</strong> whose values are kept as search terms. '
                    . 'Nothing else in the query string is read.',
                'default' => 'absent &mdash; no parameter is collected',
                'limits'  => 'Comma separated. At most 8 names, each at most 40 characters of '
                    . '<code class="mono">a-z 0-9 _ - . [ ]</code>. Each value is capped at 96 characters '
                    . 'and dropped, not truncated, if longer.',
                'switch'  => 'beacon.query_params',
            ],
            [
                'name'    => 'window.LoghoundIdent',
                'kind'    => 'global',
                'what'    => 'The same value as <code class="mono">data-ident</code>, for a template where '
                    . 'adding an attribute to the tag is awkward but setting a variable above it is not.',
                'default' => 'unset',
                'limits'  => 'A string. Must be set <em>before</em> b.js executes &mdash; with '
                    . '<code>defer</code> that means anywhere in the document. The attribute wins if both '
                    . 'are present.',
                'switch'  => 'beacon.store_identity',
            ],
            [
                'name'    => 'window.LoghoundSignedIn',
                'kind'    => 'global',
                'what'    => 'The same value as <code class="mono">data-signed-in</code>.',
                'default' => 'unset &mdash; not reported',
                'limits'  => 'A real boolean, or the same strings the attribute accepts. Must be set before '
                    . 'b.js executes.',
                'switch'  => 'beacon.store_signed_in',
            ],
            [
                'name'    => 'window.loghound.identify(ident, signedIn)',
                'kind'    => 'function',
                'what'    => 'Attach either value <strong>after</strong> the page has loaded &mdash; a '
                    . 'single-page application that signs somebody in without a navigation, which no '
                    . 'attribute can express.',
                'default' => 'never called',
                'limits'  => 'Both arguments optional and independent. <strong>Makes no request of its '
                    . 'own:</strong> the values ride the heartbeat that is already scheduled. Safe to call '
                    . 'with anything &mdash; it cannot throw into your code.',
                'switch'  => 'beacon.store_identity / beacon.store_signed_in',
            ],
        ];
    }

    /**
     * Render the option reference, with a live column saying what this installation will keep.
     *
     * The live column is the reason the table is worth having in the application at all rather
     * than only in `docs/BEACON.md`. A reference that lists `data-ident` without saying that
     * `beacon.store_identity` is off HERE sends an operator away to paste a snippet, see
     * nothing, and have no way to find out why. The document cannot know; this page can.
     */
    private function beaconOptionsTable(): void
    {
        $collected = \Loghound\Beacon::normaliseParamNames((array) $this->cfg->get('beacon.query_params', []));

        $state = [
            'beacon.store_identity'  => (bool) $this->cfg->get('beacon.store_identity', false),
            'beacon.store_signed_in' => (bool) $this->cfg->get('beacon.store_signed_in', true),
            'beacon.query_params'    => $collected !== [],
        ];

        echo '<h3>Every option the beacon reads</h3>';
        echo '<p class="muted">The complete list. The last column is <strong>this installation</strong>, read '
            . 'from <code>config/loghound.php</code> as the page was rendered &mdash; so an option whose value '
            . 'would be thrown away here says so, instead of being discovered by pasting a snippet and seeing '
            . 'nothing appear.</p>';

        echo '<div class="table-wrap"><table><thead><tr>'
            . '<th scope="col">Option</th>'
            . '<th scope="col">What it does</th>'
            . '<th scope="col">Default</th>'
            . '<th scope="col">Accepted</th>'
            . '<th scope="col">Stored here?</th>'
            . '</tr></thead><tbody>';

        foreach (self::beaconOptions() as $opt) {
            echo '<tr>';
            echo '<td><code class="mono">' . Security::esc($opt['name']) . '</code>'
                . '<br><span class="faint">' . Security::esc($opt['kind']) . '</span></td>';
            echo '<td>' . $opt['what'] . '</td>';
            echo '<td>' . $opt['default'] . '</td>';
            echo '<td>' . $opt['limits'] . '</td>';
            echo '<td>' . $this->beaconOptionState($opt['switch'], $state, $collected) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table></div>';
    }

    /**
     * The "stored here?" cell for one option.
     *
     * Three answers. An option with no switch is used by the script itself and nothing can
     * discard it. An option whose switch is on names the switch, so the operator knows which
     * line in the config file is doing it. An option whose switch is off says DISCARDED in as
     * many words, because the failure mode it is warning about is completely silent: the
     * snippet works, the collector answers 204, and the value is dropped before anything is
     * written.
     *
     * `beacon.query_params` is answered with the actual parameter names rather than with "on".
     * The page knows them, and "collecting q" is the answer to the question an operator is
     * really asking, where "enabled" would still leave them guessing which names to put in
     * `data-params`.
     *
     * @param array<string,bool> $state
     * @param array<int,string>  $collected
     */
    private function beaconOptionState(?string $switch, array $state, array $collected): string
    {
        if ($switch === null) {
            return '<span class="chip">always</span> <span class="faint">used by the script itself</span>';
        }

        if ($switch === 'beacon.query_params') {
            if ($collected === []) {
                return '<span class="chip chip-accent">discarded</span> <span class="faint">'
                    . '<code class="mono">beacon.query_params</code> is empty, so no parameter is accepted'
                    . '</span>';
            }
            $names = [];
            foreach ($collected as $name) {
                $names[] = '<code class="mono">' . Security::esc($name) . '</code>';
            }
            return '<span class="chip chip-good">yes</span> <span class="faint">accepting '
                . implode(', ', $names) . '</span>';
        }

        /* The identify() row is governed by both switches, so it reports the weaker of the two:
           saying "yes" while half of what it can send is being dropped would be the misleading
           half of the truth. */
        $keys = array_map('trim', explode('/', $switch));
        $off  = [];
        foreach ($keys as $key) {
            if (empty($state[$key])) {
                $off[] = $key;
            }
        }

        if ($off === []) {
            return '<span class="chip chip-good">yes</span> <span class="faint">'
                . '<code class="mono">' . Security::esc($keys[0]) . '</code> is on</span>';
        }

        $named = [];
        foreach ($off as $key) {
            $named[] = '<code class="mono">' . Security::esc($key) . '</code>';
        }

        return '<span class="chip chip-accent">' . (count($off) === count($keys) ? 'discarded' : 'partly discarded')
            . '</span> <span class="faint">' . implode(' and ', $named)
            . (count($off) === 1 ? ' is off' : ' are off') . '</span>';
    }

    /**
     * Measuring a site that lives on another server, and what it costs.
     *
     * The one thing an operator has to understand before pasting the snippet onto a host this
     * machine has no access log for, written where they will read it rather than only in
     * docs/BEACON.md. Three facts, and none of them is comfortable enough to leave out:
     *
     *   - the hostname allowlist is the permission, and it is the only one;
     *   - a listed hostname can have sessions FABRICATED against it by anything that is not a
     *     browser, because Origin only binds browsers;
     *   - which is why a session with no log behind it is published marked as single-plane,
     *     and every count that mixes the two says so.
     *
     * Saying the second one plainly is the point. An interface that presented the allowlist as
     * authentication would be making the claim this product exists to argue against.
     *
     * @param array<int,string> $allowed   Hostnames that may create a session.
     * @param array<int,string> $collected Query parameters kept as search terms.
     */
    private function beaconHostsBlock(array $allowed, array $collected): void
    {
        echo '<h3>Sites on other servers</h3>';

        echo '<p class="muted">The beacon works on a host this machine has no access log for — a search '
            . 'page, a marketing site, anything on another server. Paste the same snippet. The page reports '
            . 'its own hostname, and a session is created for it if that hostname is on '
            . '<code class="mono">beacon.allowed_hosts</code>. Nothing else has to be installed there.</p>';

        if ($allowed === []) {
            echo '<div class="banner banner-warn"><strong>No hostnames are listed.</strong> '
                . '<code class="mono">beacon.allowed_hosts</code> is empty in '
                . '<code>config/loghound.php</code>, so a beacon from a host with no log source here '
                . 'stages a row and nothing more: no session is created and no search term is kept. '
                . 'Add the hostnames you own to measure them.</div>';
        } else {
            echo '<p class="muted">Listed now: ';
            $parts = [];
            foreach ($allowed as $host) {
                $parts[] = '<code class="mono">' . Security::esc($host) . '</code>';
            }
            echo implode(', ', $parts) . '.</p>';
        }

        echo '<p class="muted"><strong>What the list does and does not do.</strong> A browser cannot forge the '
            . '<code>Origin</code> header, so an ordinary web page cannot impersonate a site you listed. '
            . 'Anything that is <em>not</em> a browser can send any header it likes, so somebody who knows a '
            . 'hostname is listed can fabricate sessions attributed to it. That is the same exposure every '
            . 'client-side analytics product carries; it is bounded to the hosts you listed, it cannot read '
            . 'anything, and it cannot reach your log-backed data. It is also exactly why a session measured by '
            . 'the beacon alone is stored as <code class="mono">planes_s:beacon_only</code> and shown as '
            . 'single-plane wherever it is counted. Treat the allowlist as a permission, not as a password.</p>';

        echo '<h3>Search terms</h3>';

        if ($collected === []) {
            echo '<p class="muted">Off. <code class="mono">beacon.query_params</code> is empty, so no URL '
                . 'parameter is collected from anywhere — not by the beacon and not by the log parser. Naming '
                . 'the parameters your search box uses (<code class="mono">q</code>, '
                . '<code class="mono">s</code>, <code class="mono">search</code>) turns them into a facet you '
                . 'can count and filter on.</p>';
        } else {
            $parts = [];
            foreach ($collected as $name) {
                $parts[] = '<code class="mono">' . Security::esc($name) . '</code>';
            }
            echo '<p class="muted">Collecting ' . implode(', ', $parts) . ' as search terms, from the log '
                . 'parser and from the beacon alike. The snippet below carries the same list, so a page on '
                . 'another server sends those parameters and nothing else out of its URL.</p>';
        }

        echo '<p class="muted">This is the one place Loghound stores something a person typed rather than a '
            . 'measurement or a hash, so it is a whitelist of parameter <em>names</em> and never the whole '
            . 'query string: a page URL carries session tokens and password-reset codes, and none of those may '
            . 'become a facet value. Terms are lower-cased, whitespace-collapsed, capped at 96 characters and '
            . 'dropped rather than truncated when longer.</p>';

        echo '<h3>Content-Security-Policy</h3>';
        echo '<p class="muted">A measured site with a CSP needs two directives, and the second is the one that '
            . 'gets forgotten — without it the browser blocks the collector POST silently, the beacon reports '
            . 'nothing, and there is no error anywhere to explain why:</p>';
        echo '<pre class="snippet mono">' . Security::esc(
            'script-src  ' . self::cspOrigin($this->cfg) . ";\n"
            . 'connect-src ' . self::cspOrigin($this->cfg) . ';'
        ) . '</pre>';

        echo '<p class="muted">Both are needed even though the beacon uses '
            . '<code>navigator.sendBeacon</code> first: a browser that does not have it, or refuses the call, '
            . 'falls back to <code>fetch</code>, and <code>connect-src</code> governs both.</p>';
    }

    /**
     * The origin a measured site has to allow in its Content-Security-Policy.
     *
     * The scheme and host of `base_url`, with no path: a CSP source is an origin, and pasting a
     * URL with a path into one is the mistake that makes the directive silently not match.
     */
    private static function cspOrigin(Config $cfg): string
    {
        $base = (string) $cfg->get('base_url', '');
        $parts = $base === '' ? false : parse_url($base);
        if (!is_array($parts) || ($parts['host'] ?? '') === '') {
            return 'https://loghound.example.com';
        }

        return ($parts['scheme'] ?? 'https') . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . (int) $parts['port'] : '');
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
     * A source file, named as the heading of the block that follows it.
     *
     * A path set as another line of monospaced prose is a string the eye slides over, and on a
     * card naming three files there is nothing saying where one file's block ends and the next
     * begins. The band, the size and the literal word FILE are all doing the same job: the
     * reader should know a file is being named without parsing the string first.
     *
     * Rendered through one helper so every card that prints a path agrees — the log sources,
     * the system check and the beacon card all print them and were all printing them
     * differently.
     */
    private static function filePath(string $path): void
    {
        echo '<div class="filepath">';
        echo '<span class="filepath-label" aria-hidden="true">File:</span>';
        echo '<span class="filepath-value"><span class="sr-only">File: </span>'
            . Security::esc($path) . '</span>';
        echo '</div>';
    }

    /**
     * Open a block that is closed until somebody asks for it.
     *
     * The three blocks under a log source — the field mapping, what the format does not log,
     * and five parsed lines — are each correct, each occasionally essential, and each several
     * screens long. On a card carrying all three per file they bury the thing the card is for.
     *
     * THE SUMMARY KEEPS THE HEADING'S OWN WORDS. "Details" would make the reader open it to
     * find out whether they wanted it. The `$note` is the size of what is inside, so the
     * decision to open can be made from the closed state.
     *
     * `$key` is what assets/js/responsive.js remembers the choice under, so an operator who
     * wants field mappings gets them on every file and on every visit. Closed is what somebody
     * who has never touched it gets.
     */
    private static function foldOpen(string $key, string $summary, string $note = ''): void
    {
        echo '<details class="fold lh-keep" data-keep="' . Security::esc($key) . '">';
        echo '<summary>' . Security::esc($summary);
        if ($note !== '') {
            echo '<span class="fold-note">' . Security::esc($note) . '</span>';
        }
        echo '</summary>';
    }

    /** Close the most recently opened fold. */
    private static function foldClose(): void
    {
        echo '</details>';
    }

    /**
     * The setup command for THIS installation, with its real path.
     *
     * A card that says "run bin/loghound-setup" has told the reader half of what they need: an
     * operator reading it is on a shell somewhere else on the machine, and a relative path is a
     * command that fails or, worse, runs a different checkout. The beacon snippet on this page
     * already prints the real host for the same reason, and this is the same class of mistake.
     *
     * The path is resolved rather than concatenated, so there is no `/../..` in the middle of a
     * command somebody is about to paste as root.
     */
    private static function setupCommand(): string
    {
        return 'php ' . self::root() . '/bin/loghound-setup';
    }

    /**
     * That command in the shape commandBlock() already takes, so there is one copy control in
     * this file rather than two that drift.
     *
     * @return array{key:string,title:string,lines:string[],problem:string}
     */
    private static function setupGroup(): array
    {
        return ['key' => 'setup', 'title' => 'Re-run setup', 'lines' => [self::setupCommand()], 'problem' => ''];
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
            echo '<pre class="snippet mono">sudo -u loghound ' . Security::esc(self::setupCommand())
                . ' detect</pre>';
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
            self::filePath($path);
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
                self::foldOpen('src-mapping', 'Field mapping', count($mapping) . ' tokens');
                echo '<div class="table-wrap"><table class="tight"><thead><tr>'
                    . '<th scope="col">Log token</th><th scope="col">Loghound field</th><th scope="col">Example</th>'
                    . '</tr></thead><tbody>';
                foreach ($mapping as $m) {
                    echo '<tr>';
                    echo '<td class="mono">' . Security::esc((string) ($m['token'] ?? '')) . '</td>';
                    echo '<td class="mono">' . Security::esc((string) ($m['field'] ?? '')) . '</td>';
                    /* THE TITLE IS THE ONLY WAY BACK TO THE WHOLE VALUE. `td.clip` truncates at
                       46ch, and 22ch on a phone; core.js's tbody() adds a title for every clip
                       cell it builds, and these server-rendered ones had none — so a referrer
                       or a User-Agent longer than the column was simply gone. */
                    $example = (string) ($m['example'] ?? '');
                    echo '<td class="mono clip" title="' . Security::esc($example) . '">'
                        . Security::esc($example) . '</td>';
                    echo '</tr>';
                }
                echo '</tbody></table></div>';
                self::foldClose();
            }

            $missing = (array) ($src['missing'] ?? []);
            if ($missing !== []) {
                self::foldOpen('src-missing', 'Not logged — and what that costs you',
                    count($missing) . ' fields');
                echo '<ul class="missing">';
                foreach ($missing as $m) {
                    echo '<li><code class="mono">' . Security::esc((string) ($m['token'] ?? '')) . '</code> → '
                        . '<code class="mono">' . Security::esc((string) ($m['field'] ?? '')) . '</code>: '
                        . Security::esc((string) ($m['why'] ?? '')) . '</li>';
                }
                echo '</ul>';
                echo '<p class="muted">The recommended <code>LogFormat</code> in <code>docs/INSTALL.md</code> adds all '
                    . 'of these. Plain <code>combined</code> still works — it just detects less.</p>';
                self::foldClose();
            }

            $samples = array_slice((array) ($src['samples'] ?? []), 0, 5);
            if ($samples !== []) {
                self::foldOpen('src-samples', 'Five lines from this file, parsed',
                    count($samples) . ' lines');
                echo '<p class="muted">Read these. If a value is in the wrong column, the format is wrong, and '
                    . 'confirming it would fill your index with nonsense.</p>';
                foreach ($samples as $s) {
                    echo '<div class="sample">';
                    echo '<pre class="sample-raw mono">' . Security::esc((string) ($s['raw'] ?? '')) . '</pre>';
                    echo '<div class="table-wrap"><table class="tight sample-parsed"><tbody>';
                    foreach ((array) ($s['parsed'] ?? []) as $field => $value) {
                        echo '<tr><th scope="row" class="mono">' . Security::esc((string) $field) . '</th>';
                        echo '<td class="mono clip" title="' . Security::esc((string) $value) . '">'
                            . Security::esc((string) $value) . '</td></tr>';
                    }
                    echo '</tbody></table></div>';
                    echo '</div>';
                }
                self::foldClose();
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
        $this->addSourcePart();
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
            . 'were added by <code class="mono">' . Security::esc(self::setupCommand())
            . '</code>, or the file has moved since.</p>';
        foreach ($orphans as $path => $format) {
            echo '<article class="source">';
            echo '<div class="source-head">';
            self::filePath($path);
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
                . 'run <code class="mono">' . Security::esc(self::setupCommand())
                . '</code> to provision the two indexes. The ingest, '
                . 'scoring and retention daemons refuse to start until you do.</p>';
        }

        echo '<dl class="kv">';
        echo '<dt>Account</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('opensolr.email', '—')) . '</dd>';
        echo '<dt>Region</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('opensolr.region', '—')) . '</dd>';
        echo '<dt>API key</dt><dd>' . ($this->cfg->get('opensolr.api_key')
            ? '<span class="state">Set</span>'
            : '<span class="state state-bad">Missing</span>') . '</dd>';
        echo '<dt>Hits core</dt><dd class="mono">' . Security::esc($this->gw->hitsCore()) . '</dd>';
        echo '<dt>Sessions core</dt><dd class="mono">' . Security::esc($this->gw->sessionsCore()) . '</dd>';
        echo '<dt>Query timeout</dt><dd class="mono">'
            . Security::esc((string) Gateway::queryTimeout($this->cfg)) . 's</dd>';
        echo '</dl>';

        $this->schemaPart();
        $this->opensolrAccountForm();
        $this->pairSwitchPart();

        echo '<h4>Or change it from a shell</h4>';
        echo '<p class="muted">A headless install with no browser access still needs this, and it does exactly '
            . 'what the form above does — same validation, same outcome, same wording. Every prompt is '
            . 'defaulted to what is stored now, so pressing Enter through the rest changes nothing.</p>';
        self::commandBlock('set-solr-setup', self::setupGroup());
        echo '<p class="muted">Or set <code>opensolr.api_key</code> in <code>config/loghound.php</code> by hand, '
            . 'in the directory the command above names — the file is outside the '
            . 'document root and holds the beacon secret too. Whichever route you take, the change applies on '
            . 'the next request; nothing needs restarting for the panel, and the three daemons pick it up when '
            . 'they are next started.</p>';

        echo '<div class="job-actions">';
        echo '<button type="button" class="primary" data-job="solr_connection" data-mount="job-solr">'
            . 'Run connection check</button>';
        echo '<button type="button" data-job="opensolr_check" data-mount="job-solr">'
            . 'Validate Opensolr credentials</button>';
        echo '</div>';
        echo '<div id="job-solr"></div>';
        echo '<p class="muted">Each check runs as a sequence of steps with its own progress, so it cannot time '
            . 'out however slow the backend is. You can close this page and come back to it.</p>';
        self::cardEnd();
    }

    /**
     * Does the schema on the live indexes still match the fields this release writes?
     *
     * THE DEFECT THIS CARD EXISTS FOR. A release adds a field, the operator upgrades the code,
     * and the indexes keep running the configset that was uploaded when they installed. The
     * only dynamic field either schema declares is `*` mapped to `ignored`, so Solr accepts
     * every document carrying the new field and throws the value away — no error from the
     * tailer, none from the platform, none here. The first symptom is a facet that is
     * permanently empty, months later. It is not allowed to be a silent condition, so this card
     * says so, and it carries the `chip-warn` marker that force-opens a folded section.
     *
     * NOTHING HERE TOUCHES THE NETWORK. The verdict comes from Schema::notice(), which reads
     * one small file in var/ and the configuration already in memory; the check that produces
     * that file is the button below, or `bin/loghound-schema` on the shell. That is deliberate
     * and it is why the age of the verdict is printed next to it every time: a cached answer
     * presented without its date is a claim about now made from evidence about then.
     *
     * A cache written before an upgrade is not shown as a clean bill of health. It carries the
     * fingerprint of the field set it was taken against, and a mismatch is reported as saying
     * nothing about the release running now — which is exactly the moment this matters most.
     */
    private function schemaPart(): void
    {
        try {
            $notice = Schema::notice($this->cfg, self::root());
        } catch (\Throwable $e) {
            return;
        }

        echo '<h4>Index schema</h4>';

        /* THE BADGE SAYS WHAT IT IS THE STATUS OF. On screen the heading above it supplies that;
           to a screen reader running the page as a list of controls and states it was a bare
           "Not verified" with nothing attached to it. The `.check-row .chip-warn` shape is load
           bearing — assets/js/responsive.js treats it as trouble and force-opens the card around
           it, so it cannot be folded away — and is kept exactly. */
        if ($notice['severity'] !== 'good') {
            echo '<div class="check-row"><span class="chip chip-warn">'
                . '<span class="sr-only">Index schema: </span>'
                . ($notice['severity'] === 'bad' ? 'Needs attention' : 'Not verified')
                . '</span></div>';
        }

        echo '<p' . ($notice['severity'] === 'bad' ? ' class="pop"' : '') . '><strong>'
            . Security::esc((string) $notice['headline']) . '</strong></p>';
        echo '<p class="muted">' . Security::esc((string) $notice['detail']) . '</p>';

        echo '<p class="muted">' . ($notice['checked_at'] === null
            ? 'No check has been saved on this installation yet.'
            : 'Last checked <span class="mono">'
                . Security::esc(gmdate('m/d/Y H:i:s', (int) $notice['checked_at'])) . ' UTC</span>'
                . ', against the schemas your indexes were running at that moment.') . '</p>';

        $this->schemaRows((array) $notice['indexes']);

        $lines = [Schema::command(self::root())];
        if ((string) $notice['state'] === Schema::BEHIND) {
            $lines[] = Schema::command(self::root()) . ' --apply';
        }
        self::commandBlock('set-solr-schema', [
            'key'     => 'schema',
            'title'   => (string) $notice['state'] === Schema::BEHIND
                ? 'Check it, then push this release\'s configsets'
                : 'Check it from a shell',
            'lines'   => $lines,
            'problem' => '',
        ]);
        echo '<p class="muted">The check changes nothing and exits 0 when both indexes are up to date, '
            . '3 when one is behind and 2 when a schema could not be read, so a deployment script can '
            . 'gate on it. <code class="mono">--apply</code> is additive: it uploads the configsets and '
            . 'reloads the cores, and it does not touch a document already in the index. Run it after '
            . 'every upgrade.</p>';

        if ($this->gw->isDemo()) {
            echo '<p class="muted">Checking is switched off while the panel is showing demo data.</p>';
            return;
        }

        echo '<div class="job-actions">';
        echo '<button type="button" data-job="' . Security::esc(self::KIND_SCHEMA) . '" '
            . 'data-mount="job-schema">Check the live schemas now</button>';
        echo '</div>';
        echo '<div id="job-schema"></div>';
        echo '<p class="muted">One read per index against your Opensolr account. It writes nothing to '
            . 'either index; it only saves the answer, so this card stops asking.</p>';
    }

    /**
     * One row per index from a saved check: what it has, and what it is missing.
     *
     * Only rendered when a check actually describes the release running now — the states that
     * have no rows to show are the ones where showing a table would imply a verification that
     * has not happened.
     *
     * Field names come from the shipped schema and from the live one, both filtered through
     * Storage::schemaFieldNames() to the platform's own field-name alphabet before they reach
     * here, and every one of them is escaped again on the way out.
     *
     * @param array<int,array<string,mixed>> $indexes
     */
    private function schemaRows(array $indexes): void
    {
        if ($indexes === []) {
            return;
        }

        echo '<dl class="kv">';
        foreach ($indexes as $row) {
            $missing = array_map('strval', (array) ($row['missing'] ?? []));
            $state = (string) ($row['state'] ?? '');

            echo '<dt>' . Security::esc((string) ($row['role'] ?? '')) . '</dt><dd>';
            echo '<span class="mono">' . Security::esc((string) ($row['core'] ?? '')) . '</span> — ';

            if ($state === Schema::CURRENT) {
                echo 'all ' . (int) ($row['expected'] ?? 0) . ' fields this release writes are declared';
            } elseif ($missing !== []) {
                echo '<strong>missing ' . count($missing) . '</strong>: <span class="mono wrap">'
                    . Security::esc(Schema::namedList($missing, 12)) . '</span>';
            } else {
                echo Security::esc((string) ($row['message'] ?? 'could not be read'));
            }

            echo '</dd>';
        }
        echo '</dl>';
    }

    /**
     * The form that changes which Opensolr account this installation uses.
     *
     * THE KEY FIELD IS EMPTY AND HAS NO VALUE ATTRIBUTE, on every render, whether or not a key
     * is stored. There is no placeholder carrying a prefix, no masked form of it, no length
     * hint, and nothing about it in the boot JSON: a masked secret in a page is still a secret
     * in a page, and a length is still an oracle. Whether one is configured is shown, because
     * that is a fact the operator needs and reveals nothing.
     *
     * Empty means KEEP. That is what makes changing only the email, or only the region, a safe
     * thing to do from here — and it matches what the shell wizard's prompt does, which is the
     * property the two paths are supposed to share.
     *
     * The region is a text field rather than a menu because the list belongs to the account and
     * cannot be known without a network call, and a card that reached out to opensolr.com on
     * every render of the Settings page would be an outage waiting to be discovered. A value
     * that is not on the account's list is refused on submit, and the refusal names the list.
     *
     * The second-factor field appears only when a second factor is configured, and it is
     * required when it appears; saveOpensolrCredentials() enforces that server-side regardless
     * of what this markup says.
     */
    private function opensolrAccountForm(): void
    {
        $note = self::takeSolrNote();
        if ($note !== null && $note['kind'] === 'bad') {
            self::problemBanner($note['text']);
        } elseif ($note !== null) {
            echo '<div class="banner ' . ($note['kind'] === 'good' ? 'banner-good' : 'banner-warn')
                . '" role="status">' . Security::esc($note['text']) . '</div>';
        }

        $haveKey = (string) $this->cfg->get('opensolr.api_key', '') !== '';
        $twoFactor = TwoFactor::isEnabled((array) $this->cfg->get('auth', []));

        echo '<h4>Changing the API key</h4>';
        echo '<p class="muted">Change the account, the key or the region here. The key is checked against '
            . 'Opensolr before anything is written, so a key that does not authenticate can never replace one '
            . 'that does — a typo leaves the working credentials exactly as they were and tells you what came '
            . 'back.</p>';

        echo '<form method="post" action="?v=settings" class="setup-form" autocomplete="off">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="opensolr_credentials">';

        echo '<label for="opensolr_email">Account email</label>';
        echo '<input type="email" id="opensolr_email" name="opensolr_email" size="34" autocomplete="off" '
            . 'value="' . Security::esc((string) $this->cfg->get('opensolr.email', '')) . '">';

        echo '<label for="opensolr_api_key">API key'
            . ($haveKey ? ' <span class="state">configured</span>' : '') . '</label>';
        echo '<input type="password" id="opensolr_api_key" name="opensolr_api_key" size="34" '
            . 'autocomplete="new-password" spellcheck="false">';
        echo '<p class="muted">' . ($haveKey
            ? 'The stored key is never shown here, in a log, or in anything sent to your browser — only the '
                . 'fact that one is set — and leaving the field blank keeps the key you already have.'
            : 'No key is stored. It is under <strong>Account</strong> in your Opensolr control panel.') . '</p>';

        echo '<label for="opensolr_region">Region</label>';
        echo '<input type="text" id="opensolr_region" name="opensolr_region" size="20" autocomplete="off" '
            . 'spellcheck="false" value="'
            . Security::esc((string) $this->cfg->get('opensolr.region', '')) . '">';
        echo '<p class="muted">Where indexes created from here are placed. Changing it does not move the two '
            . 'you already have — they stay where they were made. A region this account cannot use is refused '
            . 'on save, and the refusal lists the ones it can.</p>';

        if ($twoFactor) {
            echo '<label for="opensolr_code">Code from your authenticator</label>';
            echo '<input type="text" id="opensolr_code" name="code" inputmode="numeric" autocomplete="one-time-code" '
                . 'size="12" spellcheck="false" required>';
            echo '<p class="muted">Changing this credential costs a current second factor, like turning '
                . 'two-factor off does. The key can create, reconfigure and delete every index on the account '
                . 'it belongs to, so a stolen session must not be enough to swap it for somebody else\'s.</p>';
        }

        echo '<label class="check"><input type="checkbox" name="accept_reindex" value="1"> '
            . 'I will choose new indexes — this account does not have to hold the ones in use now</label>';
        echo '<p class="muted">Without this, changing to an account that does not hold '
            . '<span class="mono">' . Security::esc($this->gw->hitsCore()) . '</span> and '
            . '<span class="mono">' . Security::esc($this->gw->sessionsCore()) . '</span> is refused, '
            . 'because it would leave the panel pointing at indexes it cannot read. Tick it if you '
            . 'mean to move this installation onto a pair in the new account.</p>';

        echo '<button type="submit" class="primary">Check and save</button>';
        echo '</form>';
    }

    /**
     * Start the installation over, from the panel.
     *
     * LAST CARD ON THE PAGE, on purpose. It is the most destructive control Loghound has that
     * is not the uninstaller, and nothing below it competes for the attention of somebody who
     * has scrolled this far.
     *
     * The consequences are enumerated before the control rather than summarised after it, and
     * each line names a real thing and says what becomes of it — the indexes, the logs, the
     * sign-in, the sessions database, the daemons. A generic "this cannot be undone" teaches
     * nobody anything; the point of this list is that the two lines people most need are the
     * two that are easiest to get wrong, namely that the data survives and that the sign-in
     * does not.
     *
     * The control is a typed word, not a second button. The list above it is long, and a word
     * that has to be read and copied is the cheapest way to make sure it was.
     */
    private function reinstallSection(): void
    {
        self::cardOpen('set-reinstall', self::sectionNum('set-reinstall'), 'Start the installation over');

        echo '<p class="pop">This resets this machine and walks you back through setup. It does '
            . 'not delete your data.</p>';

        echo '<dl class="kv">';
        foreach (Reset::consequences() as $row) {
            echo '<dt>' . Security::esc($row['what']) . '</dt>';
            echo '<dd>' . Security::esc($row['happens']) . '</dd>';
        }
        echo '</dl>';

        echo '<p class="muted">You stay signed in to this browser for setup itself: pressing the '
            . 'button proves who you are, and that proof is carried into the installer so you are '
            . 'not asked for the token file from the server. It lasts half an hour, it is used '
            . 'once, and it belongs to this browser alone — anyone else reaching the installer '
            . 'still has to read <code class="mono">var/install-token</code> over a shell.</p>';

        echo '<h4>If you want ingestion stopped while you do it</h4>';
        echo '<p class="muted">Optional. The reader keeps the configuration it started with and a '
            . 'reload onto a half-finished one is refused, so leaving it running is safe — it '
            . 'simply carries on writing to the indexes it already had.</p>';
        self::commandBlock('set-reinstall-stop', [
            'key'     => 'stop',
            'title'   => 'Stop ingestion for the duration',
            'lines'   => [Reset::stopCommand()],
            'problem' => '',
        ]);

        echo '<h4>If you meant remove Loghound entirely</h4>';
        echo '<p class="muted">That is a different thing and it has its own tool, which asks '
            . 'before it deletes anything and proves your account owns an index before it removes '
            . 'it. This button never deletes an index.</p>';
        self::commandBlock('set-reinstall-uninstall', [
            'key'     => 'uninstall',
            'title'   => 'Remove Loghound from this machine',
            'lines'   => ['sudo ' . self::root() . '/install/uninstall.sh'],
            'problem' => '',
        ]);

        echo '<form method="post" action="?v=settings" class="setup-form confirm-form">';
        self::csrfField();
        echo '<input type="hidden" name="action" value="reinstall">';

        if (TwoFactor::isEnabled((array) $this->cfg->get('auth', []))) {
            echo '<label for="reinstall_code">Code from your authenticator</label>';
            echo '<input type="text" id="reinstall_code" name="code" inputmode="numeric" '
                . 'autocomplete="one-time-code" size="12" spellcheck="false" required>';
        }

        echo '<label for="reinstall_confirm">Type REINSTALL to confirm</label>';
        echo '<input type="text" id="reinstall_confirm" name="confirm" size="20" autocomplete="off" '
            . 'spellcheck="false" required>';

        echo '<button type="submit" class="primary">Reset and start setup</button>';
        echo '</form>';

        self::cardEnd();
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
        $quota = new Quota($this->cfg);
        $rolling = $quota->enabled();

        self::cardOpen(
            'set-retention',
            self::sectionNum('set-retention'),
            'How much data you keep'
        );

        echo '<p class="pop">' . Security::esc(self::keepHeadline($days, $rolling)) . '</p>';

        echo '<p>Two independent rules decide what survives, and whichever bites first wins.</p>';

        echo '<dl class="kv">';

        echo '<dt>By size — how much disk your plan gives this index</dt>';
        echo '<dd>' . ($rolling
            ? Security::esc(sprintf(
                'ON. When an index reaches %d%% of its Opensolr disk quota, the oldest data is '
                . 'deleted until it is back down to %d%%. The ingest daemon does this BEFORE it '
                . 'writes, so the index never actually reaches the quota, and bin/loghound-retention '
                . 'runs the same pass daily. This is what decides how much history you have on a '
                . 'busy site: more disk on the plan buys more history. The index is never blocked '
                . 'for being full; the oldest data is what gives way.',
                (int) round($quota->highWater() * 100),
                (int) round($quota->target() * 100)
            ))
            : 'OFF. Nothing is deleted for being large, so an index can reach its Opensolr disk '
                . 'quota — and an index at its quota is BLOCKED by the platform: every request is '
                . 'answered 403, reads included.') . '</dd>';

        echo '<dt>By age — how old you let data get</dt>';
        echo '<dd>' . ($days > 0
            ? Security::esc('ON. Hits older than ' . $days . ' days are deleted, however small the '
                . 'index is.')
            : 'OFF, which is a supported setting and not a mistake. Nothing is deleted for being '
                . 'old; how much you keep is then decided by the size rule alone.') . '</dd>';

        echo '<dt>Daily rollups</dt>';
        echo '<dd>' . ((bool) $this->cfg->get('privacy.rollup_forever', true)
            ? 'Kept by both rules. They are tiny — one document per day — and they are what lets the '
                . 'panel show last year after the hits behind it have gone.'
            : 'Deleted along with everything else, so the panel cannot show a period once its hits '
                . 'have gone.') . '</dd>';

        echo '</dl>';

        $this->diskFigures($quota);

        echo '<p class="muted">Both previews below COUNT; neither deletes. Deletion is done by '
            . '<code>bin/loghound-retention</code>, which is deliberately the only thing in the product '
            . 'allowed to issue a delete-by-query.</p>';
        echo '<div class="job-actions">';
        echo '<button type="button" data-job="retention_preview" data-mount="job-retention">'
            . 'Preview what would be deleted</button>';
        echo '</div>';
        echo '<div id="job-retention"></div>';
        self::cardEnd();
    }

    /**
     * The one-line answer to "is anything being deleted", which used to be wrong.
     *
     * THE BUG THIS FIXES. The card read `privacy.retention_days` alone and, on the very common
     * configuration of `0`, printed "Retention is disabled, so nothing is ever deleted." On an
     * installation with the rolling window enabled — the default — that is false: data is
     * deleted, not for being old but for being the oldest when the index reaches its disk
     * high-water mark. It is exactly the kind of sentence somebody believes and then loses data
     * to, and the fix is that no branch here can say "nothing is ever deleted" while the other
     * rule is on.
     *
     * `retention_days = 0` disables ONE rule. It does not disable retention.
     */
    private static function keepHeadline(int $days, bool $rolling): string
    {
        if ($rolling && $days > 0) {
            return 'Data is deleted by two rules: when an index runs out of its plan\'s disk, and '
                . 'when a hit is older than ' . $days . ' days.';
        }
        if ($rolling) {
            return 'Data is deleted when an index runs out of the disk its Opensolr plan gives it — '
                . 'oldest first. There is no age limit on top of that.';
        }
        if ($days > 0) {
            return 'Data is deleted when a hit is older than ' . $days . ' days. Nothing is deleted '
                . 'for size, so an index can reach its plan quota and be blocked.';
        }
        return 'Nothing is deleted at all: neither rule is on. An index that reaches its Opensolr '
            . 'disk quota is blocked by the platform, reads included, so this is not a safe place '
            . 'to leave it.';
    }

    /**
     * The real numbers for THIS installation, rather than an explanation of the mechanism.
     *
     * "Your index will be trimmed at 90%" means nothing without the 90% of what, and how far
     * away it is. An index holding 1.45 MB against a 476 GB quota is nowhere near firing, and
     * saying so with the figures is a completely different message from a threshold quoted in
     * the abstract — it is the difference between an operator worrying and an operator knowing.
     *
     * Reads through Quota, which caches on a clock and a document count, so rendering this card
     * does not put a control-plane round trip on every request. A state that is not 'ok' is
     * reported as itself: "the plan could not be read" is a fact worth showing, and inventing a
     * percentage from a failed read is how a card starts lying.
     */
    private function diskFigures(Quota $quota): void
    {
        $cores = array_filter([
            'Hits'     => $this->gw->hitsCore(),
            'Sessions' => $this->gw->sessionsCore(),
        ]);

        if ($cores === []) {
            return;
        }

        echo '<h4>Where this installation actually stands</h4>';
        echo '<div class="table-wrap"><table class="grid"><thead><tr>';
        foreach (['Index', 'Used', 'Plan quota', 'Of quota', 'History it buys'] as $th) {
            echo '<th scope="col">' . Security::esc($th) . '</th>';
        }
        echo '</tr></thead><tbody>';

        foreach ($cores as $label => $core) {
            $w = $quota->retentionWindow($core);

            echo '<tr>';
            echo '<td>' . Security::esc($label) . ' <span class="mono">'
                . Security::esc($core) . '</span></td>';

            if ($w['state'] !== 'ok') {
                echo '<td colspan="4">' . Security::esc(
                    'The plan could not be read for this index, so there are no figures to show.'
                ) . '</td></tr>';
                continue;
            }

            echo '<td class="mono">' . Security::esc(self::megabytes((float) $w['size_mb'])) . '</td>';
            echo '<td class="mono">' . Security::esc(self::megabytes((float) $w['max_size_mb'])) . '</td>';
            echo '<td class="mono">' . Security::esc(
                $w['max_size_mb'] > 0
                    ? number_format((float) $w['disk_ratio'] * 100, 2) . '%'
                    : '—'
            ) . '</td>';
            echo '<td>' . Security::esc(
                $w['plan_days'] !== null
                    ? 'about ' . $w['plan_days'] . ' days at the current rate'
                    : 'not enough measured traffic to say yet'
            ) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table></div>';

        echo '<p class="muted">"History it buys" is the size rule only: how long the oldest data '
            . 'would survive at the rate this installation is currently writing, before the rolling '
            . 'window starts removing it. A quiet site may never reach the high-water mark at all, '
            . 'in which case the size rule never deletes anything.</p>';
    }

    /** A byte figure a person can read, from the platform's megabytes. */
    private static function megabytes(float $mb): string
    {
        if ($mb <= 0.0) {
            return '—';
        }
        if ($mb < 1.0) {
            return number_format($mb * 1024, 0) . ' KB';
        }
        if ($mb < 1024.0) {
            return number_format($mb, 2) . ' MB';
        }
        return number_format($mb / 1024, 2) . ' GB';
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
        /* Through Security::isHttps(), like everything else that has to answer this. The inline
           expression this replaces said "http" behind every TLS-terminating proxy, so the beacon
           snippet an operator copied off this page pointed at http:// on an https-only site and
           was silently blocked as mixed content. */
        $scheme = Security::isHttps((array) $this->cfg->get('trusted_proxies', [])) ? 'https' : 'http';
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
            . 'long cache headers, and this is what makes an update reach returning visitors. Each tab shows the '
            . 'snippet <strong>with an identity attached</strong>, because that is the part nobody can guess from '
            . 'the one-line version; the attributes are optional and the snippet works without them.</p>';

        /*
         * The snippet the panel prints must be the snippet that works, first time, on the site
         * it is going to be pasted into. So it is BUILT from the live configuration rather than
         * written out as an example: `data-params` appears only when this installation has
         * actually configured parameters to collect, and carries exactly those names, because a
         * snippet advertising an attribute the collector would discard is an instruction that
         * cannot succeed.
         */
        $collected = \Loghound\Beacon::normaliseParamNames((array) $this->cfg->get('beacon.query_params', []));
        $paramsAttr = $collected === [] ? '' : ' data-params="' . implode(',', $collected) . '"';

        $allowed = (new \Loghound\Beacon($this->cfg))->allowedHosts();

        $htmlSnippet = '<script src="' . $src . '"' . $paramsAttr . ' defer></script>';

        /*
         * EVERY TAB SHOWS THE IDENTITY FORM, in the syntax that platform actually uses.
         *
         * The four tabs used to print the same bare one-liner, and the identity attributes
         * existed only in the docblock of public/b.js and in docs/BEACON.md — neither of which
         * anybody installing a snippet reads. An operator could read this entire card and still
         * not know how to pass a visitor's email, which is the most asked-for thing on it.
         *
         * WordPress and Drupal are server-side PHP with the current user in hand, so they show
         * the real API for reading it. Google Tag Manager is not: a tag manager runs in the
         * browser and has no idea who is signed in, so its tab shows the globals route fed from
         * a Data Layer variable, which is the only honest answer for that platform. Repeating
         * the plain HTML line under all four headings would be four instructions of which three
         * do not apply.
         *
         * Each one also carries the two per-platform traps that make the snippet silently wrong
         * rather than broken: a page cache serving one visitor's identity to everybody, and
         * Drupal's render cache doing the same unless the user cache context is declared.
         */
        $identAttrs = ' data-ident="ada@example.com" data-signed-in="1"';

        $htmlIdentSnippet = '<!-- your template renders the two values; omit either to say nothing -->' . "\n"
            . '<script src="' . $src . '"' . $paramsAttr . $identAttrs . ' defer></script>';

        $wpSnippet = <<<PHPCODE
        // wp-content/mu-plugins/loghound.php — a must-use plugin, so it survives a theme change.
        add_action('wp_head', static function (): void {
            \$attrs = ' data-signed-in="0"';
            if (is_user_logged_in()) {
                \$attrs = ' data-ident="' . esc_attr(wp_get_current_user()->user_email) . '"'
                    . ' data-signed-in="1"';
            }
            echo '<script src="{$src}"{$paramsAttr}' . \$attrs . ' defer></script>' . "\\n";
        }, 99);
        PHPCODE;

        $drupalSnippet = <<<DRUPALCODE
        # your_theme.theme  (or a small custom module)
        function your_theme_page_attachments(array &\$attachments): void {
          \$account = \\Drupal::currentUser();

          \$tag = [
            '#type' => 'html_tag',
            '#tag' => 'script',
            '#attributes' => [
              'src' => '{$src}',
              'defer' => TRUE,
              'data-signed-in' => \$account->isAuthenticated() ? '1' : '0',
            ],
          ];
          if (\$account->isAuthenticated()) {
            \$tag['#attributes']['data-ident'] = \$account->getEmail();
          }

          \$attachments['#attached']['html_head'][] = [\$tag, 'loghound'];
          \$attachments['#cache']['contexts'][] = 'user';
        }
        DRUPALCODE;

        $gtmSnippet = <<<GTMCODE
        <script>
          window.LoghoundIdent = "{{Loghound Ident}}";
          window.LoghoundSignedIn = "{{Loghound Signed In}}";
        </script>
        <script src="{$src}"{$paramsAttr} defer></script>
        GTMCODE;

        $snippets = [
            ['id' => 'sn-html', 'label' => 'Plain HTML', 'code' => $htmlIdentSnippet,
                'note' => 'Put it before <code>&lt;/head&gt;</code>. <code>defer</code> never blocks rendering and starts measuring at parse time rather than after every image has loaded. Drop both <code>data-</code> attributes if you do not want to attach an identity — the snippet works without them and Loghound stores nothing for a value you do not send. This is also the whole of the install on a site that runs on a different server; see <em>Sites on other servers</em> below.'],
            ['id' => 'sn-wp', 'label' => 'WordPress', 'code' => $wpSnippet,
                'note' => 'A must-use plugin rather than <code>functions.php</code>, so it survives a theme change. Priority 99 keeps it late in <code>wp_head</code>. <code>is_user_logged_in()</code> and <code>wp_get_current_user()</code> are both available at that hook, and <code>esc_attr()</code> is what keeps an address with a quote in it from breaking the tag. <strong>If you run a page cache</strong> (WP Rocket, W3TC, LiteSpeed, Cloudflare APO) the rendered tag is cached with it, so the first visitor&rsquo;s identity is served to everyone — exclude logged-in users from the cache, which every one of those plugins does by default, or use <code>window.loghound.identify()</code> from an uncached request instead.'],
            ['id' => 'sn-drupal', 'label' => 'Drupal', 'code' => $drupalSnippet,
                'note' => '<code>html_head</code> rather than a library, because a library is declared once in YAML and cannot carry a value that changes per request. <strong>The <code>user</code> cache context is not optional:</strong> without it Drupal&rsquo;s render cache serves the first authenticated visitor&rsquo;s address to every other one. Run <code>drush cr</code> afterwards. Use <code>getAccountName()</code> in place of <code>getEmail()</code> if a username is the identifier you want.'],
            ['id' => 'sn-gtm', 'label' => 'Google Tag Manager', 'code' => $gtmSnippet,
                'note' => 'New tag → Custom HTML → paste → trigger <em>All Pages</em>. Leave <em>Support document.write</em> unchecked. <code>{{Loghound Ident}}</code> and <code>{{Loghound Signed In}}</code> are Data Layer variables you define in GTM and your site pushes — a tag manager runs in the browser and cannot know who is signed in, so the value has to reach it from your own page. Drop the first <code>&lt;script&gt;</code> block entirely if you are not attaching an identity. Note that a tag manager loads asynchronously, so the first fraction of a second of each pageview is not measured.'],
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

        /*
         * ORDER, AND IT IS THE ORDER SOMEBODY READS IN. The snippet first, because that is what
         * they came for. Then how to attach an identity, because it is the commonest next
         * question and it was previously answerable only by opening a JavaScript file. Then the
         * complete option reference. Then the cases that apply to some installations and not
         * others: a site on another server, search terms, and the CSP a measured site needs.
         */
        $this->beaconIdentityBlock();
        $this->beaconOptionsTable();
        $this->beaconHostsBlock($allowed, $collected);

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
            'The hostname of the page it is running on — not the URL, just the host — so a site on another server can be told apart from the rest.',
            'The values of any URL query parameters you named in beacon.query_params, and no other part of the query string. Nothing is collected when you have named none.',
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
            'Its own idea of your IP address, User-Agent or referer — the collector reads those from the connection and ignores whatever the client claims (SPEC §6.3). The hostname is the one value it cannot read from the connection, because the page is on another machine, so it is cross-checked against the Origin the browser set and against your allowlist instead.',
            'The query string. Only the parameters you named are read; the rest of the URL is never looked at.',
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
            . Security::esc((string) $days) . '" inputmode="numeric"> <span class="muted">days'
            . ' (0 means no age limit — it does not switch retention off; the disk rule above is separate)</span>';
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
            /* A CARD CAPTION IS PROSE, so the two Solr field names came out as bare words in the
               middle of a sentence — and cardOpen() escapes its population text, so they cannot
               be marked up as code here even if they belonged. They are not what the reader
               needs: the fact is that the score goes up and that old scores stay identifiable. */
            'Points added to a session\'s bot score when a rule fires. Saving records a new scoring '
            . 'version, so sessions scored under the old weights stay identifiable. Existing documents '
            . 'are not rescored.'
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
            /* EVERY FIELD HAS A NAME. These were the only unlabelled controls in the panel:
               no id, no wrapping <label>, no aria-label, so a screen reader announced N
               identical "edit, blank" boxes with nothing to say which rule each one weighted.
               The column header associates with the CELL, not with the input inside it. The
               rule's own label is already on screen in the first cell, so aria-labelledby
               points at it rather than repeating it — and adds the word "weight", because the
               field is a weight and the row is a rule. */
            $weightId = 'weight-' . preg_replace('/[^a-z0-9_-]/i', '', $code);
            echo '<td class="num"><input type="number" min="0" max="100" id="' . Security::esc($weightId) . '"'
                . ' name="weight[' . Security::esc($code) . ']"'
                . ' value="' . Security::esc((string) $value) . '" inputmode="numeric"'
                . ' aria-label="' . Security::esc('Weight for ' . $meta['label']) . '"></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';

        echo '<fieldset><legend>Verdict thresholds</legend>';
        echo '<p class="muted">A score at or above each threshold gets that verdict. They must descend.</p>';
        /* THE VERDICTS READ IN WORDS. The labels were the stored slugs — the operator was shown
           `likely_bot ≥ [60]` — while Panel\Vocabulary held "Likely bot" two files away and
           every other surface in the panel used it. */
        echo '<div class="thresholds">';
        foreach (['bot' => 80, 'likely_bot' => 60, 'unknown' => 40, 'likely_human' => 20] as $key => $fallback) {
            $v = (int) ($thresholds[$key] ?? $fallback);
            $spoken = Vocabulary::value('bot_verdict_s', $key);
            echo '<label title="' . Security::esc($spoken['why']) . '">'
                . Security::esc($spoken['label'])
                . ' ≥ <input type="number" min="0" max="100" name="threshold['
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
