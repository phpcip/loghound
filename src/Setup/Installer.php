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

        if (!empty($_SESSION['lh_setup_unlocked'])) {
            return true;
        }

        if (Token::spendGrant()) {
            $_SESSION['lh_setup_unlocked'] = true;
            return true;
        }

        return false;
    }

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
            case self::STEP_STORAGE . ':provision':
                $this->doProvision();
                break;
            case self::STEP_STORAGE . ':reuse':
                $this->doReuse();
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
        $_SESSION['lh_setup_unlocked'] = true;

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
     * Record the Opensolr account details, then verify them by listing regions.
     *
     * Verification is a job because it is a network call: it must not block the request,
     * and its failure must be attributable to this step rather than to "setup".
     *
     * @return never
     */
    private function doOpensolrCredentials(): void
    {
        $email = is_string($_POST['email'] ?? null) ? $_POST['email'] : '';
        $key   = is_string($_POST['api_key'] ?? null) ? $_POST['api_key'] : '';

        $errors = Storage::saveCredentials($this->cfg, $email, $key);
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

        $this->rememberRegions($regions);
        $account = $this->rememberAccount();

        $this->flash(
            'ok',
            'Opensolr accepted your credentials. ' . (
                $account['pairs'] !== []
                    ? 'This account already has Loghound indexes — you can join them or create a new pair.'
                    : 'Choose where the indexes should live.'
            )
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

        $this->flash('ok', $account['capacity']['sentence']);
        $this->redirect(self::STEP_STORAGE);
    }

    /**
     * Join a pair of Loghound indexes this account already holds.
     *
     * The installation id is checked for shape here and checked for EXISTENCE by the job,
     * against the account, before a single configuration key is written. A form field is not
     * evidence that an index exists, and two index names built from one are two names this
     * installation would start writing documents into.
     *
     * Reuse is a job for the same reason provisioning is: it makes several control-plane
     * calls, one of which reads a whole schema back, and the operator has to be able to watch
     * it and to be told which step refused.
     *
     * @return never
     */
    private function doReuse(): void
    {
        $installId = is_string($_POST['install_id'] ?? null) ? $_POST['install_id'] : '';

        if (!preg_match('/^[a-f0-9]{4,32}$/', $installId)) {
            $this->flash('error', 'Choose which pair of indexes to use.');
            $this->redirect(self::STEP_STORAGE);
        }

        $account = $this->account();
        if (Pairs::find($account['pairs'], $installId) === null) {
            $this->flash(
                'error',
                'That pair is not in the list this account returned. Refresh the list and choose again.'
            );
            $this->redirect(self::STEP_STORAGE);
        }

        $this->startJob(Job::KIND_REUSE, [
            'install_id'     => $installId,
            'upgrade_schema' => ($_POST['upgrade_schema'] ?? '') === '1',
        ]);
    }

    /**
     * Start provisioning in the chosen region.
     *
     * The region is checked against the list the platform returned for THIS account, not
     * against a hardcoded one: a region added by Opensolr appears here without a Loghound
     * release, and a region this account cannot use is refused before any index is made.
     *
     * @return never
     */
    private function doProvision(): void
    {
        $region = is_string($_POST['region'] ?? null) ? $_POST['region'] : '';

        if (!preg_match('/^[A-Z0-9_]{2,32}$/', $region)) {
            $this->flash('error', 'Choose a region for your indexes.');
            $this->redirect(self::STEP_STORAGE);
        }

        $this->startJob(Job::KIND_OPENSOLR, ['region' => $region]);
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

        if ($step !== self::STEP_STATUS) {
            $step = $this->clampStep($step);
        }

        $view = new View($this->cfg, $this->root, $requirements, $this->token);
        $view->page(
            $step,
            [
                'unlocked'  => $this->unlocked(),
                'flash'     => $this->takeFlash(),
                'jobs'      => $this->jobIds(),
                'regions'   => $this->regions(),
                'account'   => $this->account(),
                'progress'  => Steps::progress($this->cfg),
            ]
        );
    }

    /**
     * Keep the operator on the first step that is not finished.
     *
     * Going BACK to a finished step is allowed — changing an earlier answer is a normal
     * thing to want. Jumping FORWARD past an unfinished one is not, because the later
     * steps read values the earlier ones write.
     */
    private function clampStep(string $step): string
    {
        if (!$this->unlocked()) {
            return self::STEP_STATUS;
        }

        $wantedAt = array_search($step, self::ORDER, true);
        $firstOpen = array_search(Steps::firstIncomplete($this->cfg), self::ORDER, true);

        if ($wantedAt === false) {
            return self::STEP_STATUS;
        }
        if ($firstOpen !== false && $wantedAt > $firstOpen) {
            return self::ORDER[$firstOpen];
        }
        return $step;
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
            static fn($r): bool => is_string($r) && preg_match('/^[A-Z0-9_]{2,32}$/', $r) === 1
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

        if ((string) $this->cfg->get('opensolr.email', '') === ''
            || (string) $this->cfg->get('opensolr.api_key', '') === '') {
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

        return $this->rememberAccount();
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
