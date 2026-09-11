<?php
/**
 * Loghound — the browser installer.
 *
 * WHAT IT IS FOR
 *
 * Point a vhost at public/, open the URL, and be walked through setup — the way WordPress,
 * Matomo, phpMyAdmin and Grafana do it. `bin/loghound-setup` still exists and still works;
 * this is an additional path to the same end state, not a replacement, and the two share
 * every piece of logic that decides what setup MEANS (src/Setup/Detector, Storage, Steps).
 *
 * ANY NOT-READY STATE LANDS HERE. The application must never answer a request by printing
 * a configuration error and stopping. No configuration, half a configuration, a
 * configuration with no way to sign in — all of them render this, at the step that fixes
 * them, with the exact command for anything that has to be done in a shell.
 *
 * THE SECURITY MODEL, IN FULL
 *
 *   1. GONE WHEN CONFIGURED. isNeeded() is a hard check at the top of every request. Once
 *      config/loghound.php exists, has a usable sign-in and names both indexes, every
 *      installer route is dead and the panel serves. There is no flag, no query parameter
 *      and no "re-run setup" button that gets past it. The gate is STRUCTURAL and does not
 *      consult Config::validate() — see isNeeded() for why making it do so was a disclosure
 *      bug rather than a stricter check.
 *   2. FILESYSTEM PROOF BEFORE ANY WRITE. Before the configuration can be touched, the
 *      operator must paste the token from var/install-token (mode 0600). Reading it
 *      requires shell access as the service user or root. See Setup\Token.
 *   3. CSRF ON EVERYTHING THAT CHANGES ANYTHING, through Security::requireCsrf(), which
 *      exits 403 for any non-GET without a matching token. No privileged action is
 *      reachable with a GET.
 *   4. NO STEP OUT OF ORDER. A step whose prerequisites are unmet redirects to the first
 *      incomplete one; guessing a URL does not skip ahead.
 *   5. NO SECRET IS EVER RENDERED. Not the Opensolr API key, not the beacon secret, not
 *      the IP salt, not the password — not into HTML, a hidden field, a URL, a job status
 *      payload, a log line or an error message. Presence is shown; values never are.
 *   6. EVERY VALUE OUT GOES THROUGH Security::esc(). Log sample lines are attacker-chosen
 *      bytes by definition, and they are displayed on the review screen on purpose.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Security;

final class Installer
{
    public const STEP_STATUS  = 'status';
    public const STEP_SOURCES = 'sources';
    public const STEP_STORAGE = 'storage';
    public const STEP_ADMIN   = 'admin';

    /**
     * The ordered wizard, after the status page.
     *
     * THERE IS NO PRIVACY STEP. It asked how to store a visitor's address and how long to
     * keep hits, before the operator had seen a single screen of the product, about data
     * their own access log already holds. `privacy.ip_mode` and `privacy.retention_days`
     * keep their defaults from Config::defaults() and are changed in Settings.
     *
     * `?setup=privacy` is consequently not a route. requestedRoute() allowlists this array,
     * so the retired name falls back to the status page like any other unrecognised value.
     */
    public const ORDER = [self::STEP_SOURCES, self::STEP_STORAGE, self::STEP_ADMIN];

    /**
     * What each step is called, in one place because three things name them.
     *
     * The progress rail, the reason a jump was bounced, and any sentence that has to refer to
     * a step the operator has not reached yet. These used to be a `static $labels` local
     * inside View::rail(), which meant a message written anywhere else either repeated the
     * words or invented different ones — and two names for one screen is how an instruction
     * stops being followable.
     *
     * @var array<string,string>
     */
    public const LABELS = [
        self::STEP_STATUS  => 'System check',
        self::STEP_SOURCES => 'Access logs',
        self::STEP_STORAGE => 'Storage',
        self::STEP_ADMIN   => 'Sign-in',
    ];

    /** The name of a step, or the raw value when it is not one. */
    public static function stepLabel(string $step): string
    {
        return self::LABELS[$step] ?? $step;
    }

    private Config $cfg;

    private string $root;

    private Token $token;

    public function __construct(Config $cfg, string $root)
    {
        $this->cfg   = $cfg;
        $this->root  = rtrim($root, '/');
        $this->token = new Token($this->root . '/var');
    }

    /**
     * Should this request be served by the installer rather than by the panel?
     *
     * The three cases that mean "not ready", in order:
     *
     *   - there is no configuration file at all;
     *   - there is one, but no username and password, so the panel could only answer with
     *     an authentication error;
     *   - there is one with credentials, but no index names, so there is nowhere to read
     *     results from and setup genuinely did not finish.
     *
     * Anything else is ready and the installer is unreachable.
     *
     * Demo mode is the single exception: `ui.demo` or LOGHOUND_DEMO=1 is a developer
     * asking for the panel with fabricated data, and tools/panel-preview.php writes
     * exactly such a configuration on purpose.
     *
     * THE GATE MUST STAY STRUCTURAL. It deliberately does not call Config::validate(), and
     * that is a security property rather than a style choice. This runs BEFORE
     * Security::requireAuth(), so whatever makes it return true hands an unauthenticated
     * visitor the installer. It used to return validate() !== [], and validate() reports an
     * error for a log directory it cannot resolve — which is the normal state of the panel
     * process, because the shipped PHP-FPM pool sets an open_basedir that excludes /var/log.
     * A correctly installed instance therefore looked unconfigured forever: the status page
     * disclosed the environment, the paths, the index names and the open_basedir value to
     * anyone who asked, re-minted a live setup token on a machine where it had already been
     * destroyed, and locked the operator out of their own dashboard.
     *
     * Configuration problems that are not "setup never finished" belong in the panel's own
     * warning banner, which Layout::banners() already renders from validate() with a link to
     * Settings. That is the right severity for a log path that does not resolve.
     *
     * Deliberately does NOT probe Solr either. Routing on a live network call would mean a
     * momentary outage on a working installation bounced the operator out of their
     * dashboard and re-opened the installer; Solr reachability is a runtime condition the
     * panel already reports in its own banner.
     */
    public static function isNeeded(Config $cfg): bool
    {
        if (!is_file($cfg->path())) {
            return true;
        }
        if (getenv('LOGHOUND_DEMO') === '1' || $cfg->get('ui.demo') === true) {
            return false;
        }
        if ((string) $cfg->get('auth.mode', 'none') === 'none'
            || (string) $cfg->get('auth.password_hash', '') === '') {
            return true;
        }
        if ((string) $cfg->get('solr.hits_core', '') === ''
            || (string) $cfg->get('solr.sessions_core', '') === '') {
            return true;
        }
        return false;
    }

    /**
     * Serve one installer request and stop.
     *
     * @return never
     */
    public function handle(): void
    {
        Security::sendSecurityHeaders();
        header('Cache-Control: no-store, private');
        header('X-Robots-Tag: noindex, nofollow');

        Job::sweep($this->root . '/var/setup');

        $route = $this->requestedRoute();

        if ($route === 'job') {
            $this->handleJob();
        }

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $this->handlePost($route);
        }

        $this->render($route);
        exit;
    }

    /**
     * The step (or 'job') this request is asking for, taken from the allowlist.
     *
     * Anything unrecognised becomes the status page rather than an error, because an
     * unknown value here is a stale bookmark or a prober, and neither deserves a page
     * that enumerates what the valid values are.
     */
    private function requestedRoute(): string
    {
        $raw = $_POST['step'] ?? ($_GET['setup'] ?? '');
        $raw = is_string($raw) ? $raw : '';

        $allowed = array_merge([self::STEP_STATUS, 'job'], self::ORDER);
        return in_array($raw, $allowed, true) ? $raw : self::STEP_STATUS;
    }

    /**
     * Has this browser proved it can read a 0600 file on this server?
     *
     * The unlock lives in the session and nowhere else: there is no cookie, header or
     * query parameter that carries it, so it cannot be replayed from a link.
     *
     * A SESSION THAT PRESSED REINSTALL IN THE SIGNED-IN PANEL is accepted too, and that is not a
     * weakening of the token. It has already proved more than the token asks for — it held the
     * panel password, and a second factor where one is configured — and carrying that forward is
     * what stops the button from locking a browser-only operator out of both the panel and the
     * installer in one click. It is checked AFTER the ordinary unlock, spent once, and belongs
     * to that session alone; a visitor who did not press the button still has to read
     * var/install-token. See Setup\Token::grant().
     */
    private function unlocked(): bool
    {
        Security::startSession();

        $at = (int) ($_SESSION['lh_setup_unlocked'] ?? 0);

        /* THE UNLOCK HAS ITS OWN CLOCK, AND IT DID NOT. It used to be the bare boolean `true`,
           so a thirty-minute reinstall grant became an unlock that lived as long as the PHP
           session — a window bounded by session.gc_maxlifetime rather than by anything this
           file decided. Storing the instant instead makes the bound explicit and makes an old
           session's unlock expire the way the grant that produced it was always meant to. A
           legacy `true` reads as 0 and is therefore expired, which is the safe direction. */
        if ($at > 0 && (time() - $at) <= self::UNLOCK_TTL) {
            return true;
        }
        unset($_SESSION['lh_setup_unlocked']);

        if (Token::spendGrant()) {
            $_SESSION['lh_setup_unlocked'] = time();
            return true;
        }

        return false;
    }

    /**
     * How long an unlock stands before the token has to be presented again.
     *
     * An hour is far longer than an install takes and short enough that a browser left open on
     * a half-finished installer does not stay a way in indefinitely.
     */
    private const UNLOCK_TTL = 3600;

    /**
     * Refuse the request unless the setup token has been presented.
     *
     * Fails closed and stops the request. Called at the top of every path that writes
     * configuration or contacts a remote service on the operator's behalf.
     *
     * @return never|void
     */
    private function requireUnlock(): void
    {
        if ($this->unlocked()) {
            return;
        }
        $this->flash('error', 'Enter the setup token before changing anything.');
        $this->redirect(self::STEP_STATUS);
    }

    /**
     * Dispatch a state-changing request.
     *
     * CSRF is enforced first, for every action including the unlock itself. The action
     * name is matched against a switch, never used to build a method name.
     *
     * @return never|void
     */
    private function handlePost(string $step): void
    {
        Security::requireCsrf();

        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';

        if ($action === 'unlock') {
            $this->doUnlock();
        }

        $this->requireUnlock();

        switch ($step . ':' . $action) {
            case self::STEP_SOURCES . ':detect':
                $this->startJob(Job::KIND_DETECT, []);
                break;
            case self::STEP_SOURCES . ':confirm':
                $this->doConfirmSources();
                break;
            case self::STEP_SOURCES . ':manual':
                $this->doManualSource();
                break;
            case self::STEP_STORAGE . ':credentials':
                $this->doOpensolrCredentials();
                break;
            case self::STEP_STORAGE . ':indexes':
                $this->doChooseIndexes(
                    is_string($_POST['install_id'] ?? null) ? $_POST['install_id'] : ''
                );
                break;
            /* THE TWO RETRY ALIASES. Step two is one form posting one choice; these exist only
               for the "Try again" button on a job that failed, which re-runs the work that
               failed rather than asking the question again — so the choice is implied by the
               job's kind instead of arriving in the request. Both land in the same handler. */
            case self::STEP_STORAGE . ':provision':
                $this->doChooseIndexes(Pairs::CHOICE_NEW);
                break;
            case self::STEP_STORAGE . ':reuse':
                $this->doChooseIndexes(
                    is_string($_POST['install_id'] ?? null) ? $_POST['install_id'] : ''
                );
                break;
            case self::STEP_STORAGE . ':refresh':
                $this->doRefreshAccount();
                break;
            case self::STEP_STORAGE . ':test':
                $this->startJob(Job::KIND_SOLRTEST, []);
                break;
            case self::STEP_ADMIN . ':finish':
                $this->doFinish();
                break;
        }

        $this->flash('error', 'That action is not available here.');
        $this->redirect($step);
    }

    /**
     * Check the pasted setup token and, on success, unlock this session.
     *
     * The session id is regenerated on success so a fixed id planted before the unlock
     * cannot inherit the privilege.
     *
     * @return never
     */
    private function doUnlock(): void
    {
        $given = is_string($_POST['token'] ?? null) ? $_POST['token'] : '';
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));

        $why = $this->token->verify($given, $ip);
        if ($why !== '') {
            $this->flash('error', $why);
            $this->redirect(self::STEP_STATUS);
        }

        Security::startSession();
        session_regenerate_id(true);
        $_SESSION['lh_setup_unlocked'] = time();

        $this->flash('ok', 'Unlocked. Let\'s set Loghound up.');
        $this->redirect(Steps::firstIncomplete($this->cfg));
    }

    /**
     * Start a background job and send the browser to the step that watches it.
     *
     * An unfinished job of the same kind is reattached to rather than replaced, which is
     * what stops a double-click or a refresh from creating a second pair of indexes.
     *
     * @param array<string,mixed> $params
     * @return never
     */
    private function startJob(string $kind, array $params): void
    {
        $dir = $this->root . '/var/setup';

        $running = Job::findRunning($dir, $kind);
        if ($running !== null) {
            $this->rememberJob($kind, $running->id());
            $this->redirect($this->stepForKind($kind));
        }

        try {
            $job = Job::create($dir, $kind, $params);
        } catch (\Throwable $e) {
            $this->flash('error', 'Could not start: ' . $e->getMessage());
            $this->redirect($this->stepForKind($kind));
        }

        $this->rememberJob($kind, $job->id());
        $this->redirect($this->stepForKind($kind));
    }

    /**
     * Store the chosen sources, after re-validating every path server-side.
     *
     * The browser sends indexes into the detection report, not paths: a path from a form
     * field would have to be trusted or re-derived, and there is no reason to accept one.
     *
     * A PARTIALLY SUCCESSFUL CONFIRMATION IS STORED AND DESCRIBED, NOT ABORTED. This step
     * used to redirect back with an error the moment any single source was refused, which
     * made one un-widened outside-root file a dead end in the middle of an installation: the
     * six files that were perfectly fine could not be confirmed, and there was no control on
     * the screen that changed that. What is storable is now stored, and the refusals are
     * named one by one with the reason for each — a step that did some of what was asked has
     * to say exactly which part, rather than claiming success or pretending nothing happened.
     *
     * The step only fails outright when NOTHING could be stored, because then there is
     * genuinely nothing to carry forward to the storage step.
     *
     * @return never
     */
    private function doConfirmSources(): void
    {
        $report = Detector::lastReport($this->cfg);
        $sources = (array) ($report['sources'] ?? []);

        $chosen = [];
        foreach ((array) ($_POST['pick'] ?? []) as $index) {
            if (!is_string($index) && !is_int($index)) {
                continue;
            }
            $i = (int) $index;
            if (isset($sources[$i])) {
                $chosen[] = (array) $sources[$i];
            }
        }

        if ($chosen === []) {
            $this->flash('error', 'Tick at least one log file, or add one by hand below.');
            $this->redirect(self::STEP_SOURCES);
        }

        $widen = [];
        foreach ((array) ($_POST['widen'] ?? []) as $index) {
            $i = (int) $index;
            if (isset($sources[$i]) && !empty($sources[$i]['outside_roots'])) {
                $widen[] = dirname((string) $sources[$i]['path']);
            }
        }

        $result = Steps::applySourcesReport($this->cfg, $chosen, $widen);

        if ($result['stored'] === []) {
            $this->flash('error', self::sourcesOutcome($result));
            $this->redirect(self::STEP_SOURCES);
        }

        $this->persist(self::STEP_SOURCES);
        Detector::writeReport($this->cfg, Detector::report($sources, $this->cfg));

        $refused = $result['refused'] !== [] || $result['widening'] !== [];
        $this->flash($refused ? 'warn' : 'ok', self::sourcesOutcome($result));
        $this->redirect(self::STEP_STORAGE);
    }

    /**
     * One sentence describing exactly what a confirmation did and did not store.
     *
     * Every refused path is named with its own reason rather than folded into a count: the
     * operator has to be able to act on it — widen the roots, fix the format, remove the
     * file — and "2 sources were refused" is not something anyone can act on.
     *
     * @param array{stored:string[],refused:array<int,array{path:string,message:string}>,widening:string[]} $result
     */
    private static function sourcesOutcome(array $result): string
    {
        $kept = count($result['stored']);
        $text = $kept === 0
            ? 'Nothing was stored.'
            : $kept . ' log file' . ($kept === 1 ? '' : 's') . ' confirmed.';

        $problems = $result['widening'];
        foreach ($result['refused'] as $one) {
            $problems[] = $one['message'];
        }
        if ($problems === []) {
            return $text;
        }

        $count = count($result['refused']);
        if ($count > 0) {
            $text .= ' ' . $count . ($count === 1 ? ' was' : ' were') . ' not stored:';
        }
        return $text . ' ' . implode(' ', $problems);
    }

    /**
     * Add a log file the operator typed in.
     *
     * Detector::manualSource() does the refusing: the path must resolve inside
     * allowed_log_roots through Security::safePath(), and a custom pattern must pass
     * Security::validateUserRegex() before it can be stored.
     *
     * @return never
     */
    private function doManualSource(): void
    {
        $path   = is_string($_POST['path'] ?? null) ? $_POST['path'] : '';
        $format = is_string($_POST['format'] ?? null) ? $_POST['format'] : '';
        $regex  = is_string($_POST['regex'] ?? null) ? $_POST['regex'] : '';

        $result = Detector::manualSource($this->cfg, $path, $format, $regex);
        if (!$result['ok']) {
            $this->flash('error', $result['error']);
            $this->redirect(self::STEP_SOURCES);
        }

        $report = Detector::lastReport($this->cfg);
        $sources = (array) ($report['sources'] ?? []);
        $sources[] = $result['source'];
        Detector::writeReport($this->cfg, Detector::report($sources, $this->cfg));

        $this->flash('ok', 'Added. Check the parsed lines below, then confirm it.');
        $this->redirect(self::STEP_SOURCES);
    }

    /**
     * STEP ONE: record the Opensolr account details, then verify them by listing regions.
     *
     * IT SAVES ON ITS OWN, with nothing said about indexes. That is the shape Settings has been
     * brought round to as well: naming an account is one decision and choosing indexes is
     * another, and this handler finishes the first without asking anything about the second.
     *
     * Verification is a network call, which is why the form is a POST that redirects rather than
     * something checked as the operator types.
     *
     * THE INTERIM STATE IS RECORDED HERE. On a fresh install there is no pair configured and
     * settleOwnership() says so; on a re-run that has moved to another account it writes down
     * that indexes are outstanding, which is what lets the operator close the tab and come back
     * to step two instead of meeting a panel that reads nothing and cannot say why.
     *
     * @return never
     */
    private function doOpensolrCredentials(): void
    {
        $email  = is_string($_POST['email'] ?? null) ? $_POST['email'] : '';
        $key    = is_string($_POST['api_key'] ?? null) ? $_POST['api_key'] : '';
        $region = is_string($_POST['region'] ?? null) ? trim($_POST['region']) : '';

        $errors = Storage::saveCredentials($this->cfg, $email, $key, $region);
        if ($errors !== []) {
            $this->flash('error', implode(' ', $errors));
            $this->redirect(self::STEP_STORAGE);
        }

        $this->persist(self::STEP_STORAGE);
        unset($_POST['api_key']);

        try {
            $regions = Storage::listRegions($this->cfg);
        } catch (\Throwable $e) {
            $this->flash('error', $e->getMessage());
            $this->redirect(self::STEP_STORAGE);
        }

        $chosen = Storage::settleRegion($this->cfg, $regions, $region !== '');
        if ($chosen === null) {
            $this->flash('error', Storage::regionRefusal($region, $regions));
            $this->redirect(self::STEP_STORAGE);
        }
        $this->cfg->set('opensolr.region', $chosen);

        $this->rememberRegions($regions);
        $account   = $this->rememberAccount();
        $ownership = Pairs::settleOwnership($this->cfg, $account);
        $this->persist(self::STEP_STORAGE);

        $this->flash(
            $ownership === 'missing' ? 'error' : 'ok',
            'Opensolr accepted your credentials. ' . ($ownership === 'missing'
                ? Pairs::pendingDetail($this->cfg)
                : Pairs::choiceIntro(count((array) $account['pairs'])))
        );
        $this->redirect(self::STEP_STORAGE);
    }

    /**
     * Re-read what the account holds, on the operator's explicit request.
     *
     * The list is cached per session so that opening the storage step does not make a network
     * call on every render. That cache is the reason this control exists: an operator who has
     * just deleted an index in another tab, or who has had a second machine provision a pair
     * while this page sat open, needs a way to see the account as it is now without retyping
     * their API key.
     *
     * Nothing here decides anything — the list is only ever an offer, and every choice made
     * from it is re-checked against the platform before it is acted on.
     *
     * @return never
     */
    private function doRefreshAccount(): void
    {
        $account = $this->rememberAccount();

        if (!$account['ok']) {
            $this->flash('error', $account['error']);
            $this->redirect(self::STEP_STORAGE);
        }

        Pairs::settleOwnership($this->cfg, $account);
        $this->persist(self::STEP_STORAGE);

        $this->flash('ok', $account['capacity']['sentence']);
        $this->redirect(self::STEP_STORAGE);
    }

    /**
     * STEP TWO: act on the one choice the operator made — a pair from the list, or a new pair.
     *
     * ONE HANDLER, BECAUSE IT IS ONE CHOICE. Joining and creating used to be two separate forms
     * with two separate actions, which made them read as two unrelated offers rather than as the
     * alternatives they are. They are now one radio list submitting one field, and Settings does
     * exactly the same through the same shared decision.
     *
     * NEITHER ARM TRUSTS THE FIELD. An installation id is checked for shape here and for
     * EXISTENCE against the list the account just returned, because a form field is not evidence
     * that an index exists and two names built from an unchecked id are two names this
     * installation would start writing documents into. A region is checked against what the
     * platform offers THIS account, so a region Opensolr adds works without a Loghound release
     * and one the account cannot use is refused before any index is made.
     *
     * Both arms are jobs for the same reason: several control-plane calls, one of which reads a
     * whole schema back, and the operator has to be able to watch it and be told which step
     * refused. The capacity gate is step 2 of the provisioning job, ahead of the first create.
     *
     * @param string $choice An installation id from the list, or Pairs::CHOICE_NEW.
     * @return never
     */
    private function doChooseIndexes(string $choice): void
    {
        if ($choice === Pairs::CHOICE_NEW) {
            $region  = is_string($_POST['region'] ?? null) ? $_POST['region'] : '';
            $offered = $this->regions();

            if ($offered !== [] && !in_array($region, $offered, true)) {
                $this->flash('error', Storage::regionRefusal($region, $offered));
                $this->redirect(self::STEP_STORAGE);
            }
            if (!preg_match('/^[A-Z0-9_]{2,32}$/D', $region)) {
                $this->flash('error', 'Pick a region for the new indexes, then submit again.');
                $this->redirect(self::STEP_STORAGE);
            }

            $this->startJob(Job::KIND_OPENSOLR, ['region' => $region]);
        }

        if (!preg_match('/^[a-f0-9]{4,32}$/D', $choice)) {
            $this->flash('error', 'Pick which indexes this installation should use, then submit again.');
            $this->redirect(self::STEP_STORAGE);
        }

        $account = $this->account();
        if (Pairs::find($account['pairs'], $choice) === null) {
            $this->flash(
                'error',
                'That pair is not in the list this account returned. Check the account again and choose '
                . 'from the list as it stands now.'
            );
            $this->redirect(self::STEP_STORAGE);
        }

        $this->startJob(Job::KIND_REUSE, [
            'install_id'     => $choice,
            'upgrade_schema' => ($_POST['upgrade_schema'] ?? '') === '1',
        ]);
    }

    /**
     * Write the sign-in details, finish, and hand the operator to the dashboard.
     *
     * The configuration is validated as a whole before the account is stored. That order
     * matters: the account is the last thing that makes isNeeded() false, so writing it
     * over an invalid configuration would retire the installer and leave the operator with
     * a panel that cannot work and no way back.
     *
     * On success the setup token is destroyed and the browser is sent to the dashboard,
     * where it is asked for the username and password just chosen.
     *
     * @return never
     */
    private function doFinish(): void
    {
        $errors = Steps::applyBaseUrl($this->cfg, is_string($_POST['base_url'] ?? null) ? $_POST['base_url'] : '');
        $errors = array_merge($errors, Steps::applyAdmin(
            $this->cfg,
            is_string($_POST['user'] ?? null) ? $_POST['user'] : '',
            is_string($_POST['password'] ?? null) ? $_POST['password'] : '',
            is_string($_POST['password2'] ?? null) ? $_POST['password2'] : '',
            is_string($_POST['auth_mode'] ?? null) ? $_POST['auth_mode'] : 'basic'
        ));

        unset($_POST['password'], $_POST['password2']);

        if ($errors !== []) {
            $this->flash('error', implode(' ', $errors));
            $this->redirect(self::STEP_ADMIN);
        }

        Steps::ensureSecrets($this->cfg);

        $problems = $this->cfg->validate();
        if ($problems !== []) {
            $this->cfg->set('auth.password_hash', '');
            $this->cfg->set('auth.mode', 'none');
            $this->flash('error', 'Almost — something earlier is still incomplete: ' . implode(' ', $problems));
            $this->redirect(Steps::firstIncomplete($this->cfg));
        }

        $this->persist(self::STEP_ADMIN);

        $this->token->destroy();
        if (session_status() === PHP_SESSION_ACTIVE) {
            unset(
                $_SESSION['lh_setup_unlocked'],
                $_SESSION['lh_setup_jobs'],
                $_SESSION['lh_setup_regions'],
                $_SESSION['lh_setup_account']
            );
        }

        header('Location: ./', true, 303);
        exit;
    }

    /**
     * Write the configuration, or send the operator back with the reason it failed.
     *
     * A configuration directory that cannot be written is a real and common state on a
     * fresh install — it is one of the rows on the status page — and it must surface as a
     * sentence on the step that tried, never as a blank 500 that leaves the operator with
     * nowhere to go.
     *
     * @return never|void
     */
    private function persist(string $step): void
    {
        try {
            Storage::persist($this->cfg);
        } catch (\Throwable $e) {
            $this->flash(
                'error',
                'The configuration could not be saved: ' . $e->getMessage()
                . ' Check the System check page for the exact command that fixes it.'
            );
            $this->redirect($step);
        }
    }

    /**
     * The job endpoint: advance a job, or report its progress.
     *
     * Both actions are POSTs carrying the CSRF token, and both require the setup unlock.
     * `run` mutates by definition; `status` is read-only but is held to the same rule so
     * there is one policy to audit rather than two.
     *
     * @return never
     */
    private function handleJob(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            $this->json(['error' => 'Not found'], 404);
        }
        Security::requireCsrf();
        if (!$this->unlocked()) {
            $this->json(['error' => 'Locked'], 403);
        }

        $id = is_string($_POST['id'] ?? null) ? $_POST['id'] : '';
        $job = Job::load($this->root . '/var/setup', $id);
        if ($job === null) {
            $this->json(['error' => 'That job no longer exists. Reload the page.'], 404);
        }

        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : 'status';
        if ($action === 'run') {
            $job->run($this->cfg, $this->root);
        }

        $this->json($job->status($this->cfg, $this->root), 200);
    }

    /**
     * Emit a JSON response and stop.
     *
     * JSON_HEX_TAG for the same reason Security::escJs sets it: nothing in a payload
     * derived from log data or a remote API may be able to close a script element if the
     * response is ever rendered somewhere it should not be.
     *
     * @param array<string,mixed> $payload
     * @return never
     */
    private function json(array $payload, int $status): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        echo json_encode(
            $payload,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
            | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
        exit;
    }

    /**
     * Render one step, after clamping it to something the installation is ready for.
     */
    private function render(string $step): void
    {
        $requirements = new Requirements($this->root, $this->cfg);

        $bounced = '';
        if ($step !== self::STEP_STATUS) {
            [$step, $bounced] = $this->clampStep($step, $requirements);
        }

        $view = new View($this->cfg, $this->root, $requirements, $this->token);
        $view->page(
            $step,
            [
                'unlocked'  => $this->unlocked(),
                'flash'     => $this->takeFlash(),
                'bounced'   => $bounced,
                'jobs'      => $this->jobIds(),
                'regions'   => $this->regions(),
                'account'   => $this->account(),
                'progress'  => Steps::progress($this->cfg),
            ]
        );
    }

    /**
     * Keep the operator on the first step that is not finished, AND SAY SO.
     *
     * Going BACK to a finished step is allowed — changing an earlier answer is a normal thing
     * to want. Jumping FORWARD past an unfinished one is not, because the later steps read
     * values the earlier ones write.
     *
     * THE SILENCE WAS THE BUG. This used to return a step and nothing else, so every bounce
     * rendered a page that was byte-identical to the one the operator was already looking at:
     * clicking a link did nothing, three times over, with no way to tell a refusal from a
     * broken link. Whatever it returns now, it returns the reason with it, and the reason
     * NAMES THE MISSING PREREQUISITE rather than restating the rule — "Storage needs an
     * access log" is actionable, "that step is not available yet" is not.
     *
     * A name that is not a step at all is reported as that FIRST, before the lock, so a retired
     * route like `?setup=privacy` is never described as "locked" — which would be a second
     * false statement on top of the silence. Nothing is disclosed by saying so: ORDER is a
     * public constant, and the reply is identical whether or not the caller is unlocked.
     *
     * @return array{0:string,1:string} The step to render, and why it is not the one asked
     *                                  for. The second is an empty string when it is.
     */
    private function clampStep(string $step, Requirements $requirements): array
    {
        $wantedAt = array_search($step, self::ORDER, true);

        if ($wantedAt === false) {
            return [self::STEP_STATUS, 'There is no setup step called "' . $step . '".'];
        }

        if (!$this->unlocked()) {
            return [
                self::STEP_STATUS,
                'Setup is locked, so ' . self::stepLabel($step) . ' cannot be opened yet. Paste '
                . 'the setup token below to unlock it — this page is on the internet and nothing '
                . 'can be saved until this browser has proved it can read a file on the server.',
            ];
        }

        $firstOpen = array_search(Steps::firstIncomplete($this->cfg), self::ORDER, true);
        if ($firstOpen === false || $wantedAt <= $firstOpen) {
            return [$step, ''];
        }

        $blocker = self::ORDER[$firstOpen];
        $why = $this->prerequisite($requirements, $blocker);

        return [
            $blocker,
            self::stepLabel($step) . ' reads answers that ' . self::stepLabel($blocker)
            . ' has not given yet' . ($why === '' ? '' : ': ' . $why)
            . ' This is that step; finishing it leads back to ' . self::stepLabel($step) . '.',
        ];
    }

    /**
     * The unfinished thing a step is waiting on, in the words the status page already uses.
     *
     * Read from Requirements::missing() rather than written again here, so the sentence an
     * operator is bounced with and the sentence in the missing-list are the same sentence.
     */
    private function prerequisite(Requirements $requirements, string $step): string
    {
        foreach ($requirements->missing() as $item) {
            if (($item['step'] ?? '') === $step) {
                return (string) $item['text'];
            }
        }
        return '';
    }

    /**
     * Remember which job belongs to which step, so a reload reattaches to it.
     *
     * Job ids are not secrets, but they are per-operator state and there is no reason to
     * put them in a URL where they would end up in a referer header.
     */
    private function rememberJob(string $kind, string $id): void
    {
        Security::startSession();
        $_SESSION['lh_setup_jobs'][$kind] = $id;
    }

    /**
     * The live job id per kind, preferring a job that is genuinely still on disk.
     *
     * @return array<string,string>
     */
    private function jobIds(): array
    {
        Security::startSession();
        $out = [];
        foreach ((array) ($_SESSION['lh_setup_jobs'] ?? []) as $kind => $id) {
            if (!is_string($kind) || !is_string($id)) {
                continue;
            }
            if (Job::load($this->root . '/var/setup', $id) !== null) {
                $out[$kind] = $id;
            }
        }
        return $out;
    }

    /**
     * Cache the region list returned for this account, for the select on the next render.
     *
     * @param string[] $regions
     */
    private function rememberRegions(array $regions): void
    {
        Security::startSession();
        $_SESSION['lh_setup_regions'] = array_values(array_filter(
            $regions,
            static fn($r): bool => is_string($r) && preg_match('/^[A-Z0-9_]{2,32}$/D', $r) === 1
        ));
    }

    /** @return string[] */
    private function regions(): array
    {
        Security::startSession();
        return (array) ($_SESSION['lh_setup_regions'] ?? []);
    }

    /**
     * Read what the account holds and cache it for this session.
     *
     * ONE control-plane call answers both questions the storage step asks — which Loghound
     * pairs exist, and how many indexes are in use — so it is made where the operator is
     * already waiting for a network round trip, and cached rather than repeated on every
     * render of a page they may sit on for a while.
     *
     * A failure is cached too, deliberately: the reason the list is empty has to stay on the
     * screen next to the credentials that might explain it, rather than being replaced by an
     * empty list on the next render.
     *
     * @return array<string,mixed>
     */
    private function rememberAccount(): array
    {
        $account = Storage::account($this->cfg);

        Security::startSession();
        $_SESSION['lh_setup_account'] = $account;

        return $account;
    }

    /**
     * The cached account snapshot, or a fresh read when there is none and there could be one.
     *
     * Reads through on a first visit that already has credentials — an operator returning to a
     * part-finished install has a stored API key and no session, and showing them an empty
     * storage step because of that would hide the pair they came back to adopt.
     *
     * @return array<string,mixed>
     */
    private function account(): array
    {
        Security::startSession();

        $cached = $_SESSION['lh_setup_account'] ?? null;
        if (is_array($cached)) {
            return $cached;
        }

        /* NO OUTBOUND CALL FOR A CALLER WHO HAS NOT PROVED FILESYSTEM ACCESS. render() asks for
           this on EVERY installer render, and until setup finishes the installer answers the
           whole internet — so a plain `GET ?setup=status` with no cookie went straight past the
           empty session cache into two control-plane reads at a 25-second timeout each. Fifty
           seconds of a PHP-FPM worker and a slice of the operator's API quota, per request, from
           an unauthenticated stranger, repeatable by simply not sending a cookie. A handful of
           concurrent requests is the whole pool.

           The unlock is the gate that already exists for exactly this — proof of access to the
           filesystem — and the panel this feeds is only rendered behind it anyway, so nothing an
           unlocked operator sees changes. */
        if (!$this->unlocked()) {
            return self::emptyAccount();
        }

        if ((string) $this->cfg->get('opensolr.email', '') === ''
            || (string) $this->cfg->get('opensolr.api_key', '') === '') {
            return self::emptyAccount();
        }

        return $this->rememberAccount();
    }

    /**
     * The shape account() returns when there is nothing to report and nothing to ask.
     *
     * @return array<string,mixed>
     */
    private static function emptyAccount(): array
    {
        return [
            'ok'       => false,
            'error'    => '',
            'pairs'    => [],
            'halves'   => [],
            'total'    => 0,
            'counted'  => 0,
            'capacity' => Pairs::capacity(0),
        ];
    }

    /**
     * Queue a one-shot message for the next render.
     *
     * Held in the session rather than passed through the query string: a message can
     * quote a path or an API error, and neither belongs in a URL that ends up in a browser
     * history or a referer header.
     *
     * Three kinds, because two could not describe a step that partly worked: 'ok' did all of
     * it, 'warn' did some of it and says which part it did not, 'error' did none of it.
     * Anything unrecognised is an error — the severity a caller did not ask for is the one
     * that cannot hide a problem.
     */
    private function flash(string $kind, string $text): void
    {
        Security::startSession();
        $_SESSION['lh_setup_flash'] = [
            'kind' => in_array($kind, ['ok', 'warn'], true) ? $kind : 'error',
            'text' => $text,
        ];
    }

    /**
     * Read and clear the queued message.
     *
     * @return array{kind:string,text:string}|null
     */
    private function takeFlash(): ?array
    {
        Security::startSession();
        $flash = $_SESSION['lh_setup_flash'] ?? null;
        unset($_SESSION['lh_setup_flash']);
        return is_array($flash) ? ['kind' => (string) $flash['kind'], 'text' => (string) $flash['text']] : null;
    }

    /** Which step watches a job of this kind. */
    private function stepForKind(string $kind): string
    {
        return $kind === Job::KIND_DETECT ? self::STEP_SOURCES : self::STEP_STORAGE;
    }

    /**
     * Send the browser to a step and stop.
     *
     * Always a relative URL built from the allowlisted step names, so there is nothing
     * here that could become an open redirect.
     *
     * @return never
     */
    private function redirect(string $step): void
    {
        $allowed = array_merge([self::STEP_STATUS], self::ORDER);
        if (!in_array($step, $allowed, true)) {
            $step = self::STEP_STATUS;
        }
        header('Location: ?setup=' . rawurlencode($step), true, 303);
        exit;
    }
}
