<?php
/**
 * Loghound — shared base for the Opensolr index-analytics views.
 *
 * WHY THIS SECTION EXISTS AT ALL. Loghound already knows, for every IP it has ever seen in
 * a web log, whether it is a bot, what network it sits on and which fingerprint cluster it
 * belongs to. Opensolr already knows, for every request that reached a customer's search
 * index, what was asked, how long it took and how many results came back. Each half is
 * useful; the two together answer questions neither can answer alone, and those questions
 * — how much of my search capacity is serving scrapers, and who is querying my index
 * without ever visiting my site — are the reason this belongs inside Loghound rather than
 * in a separate tool.
 *
 * THE ARCHITECTURAL RULE, WHICH IS NOT OPEN FOR REDESIGN. Loghound never touches a Solr
 * server for any of this. No agent, no log file, no SSH, no log4j2 parsing. Everything on
 * the Solr side is read from the Opensolr platform API, which already holds the data in
 * its analytics shards and already enforces ownership on it. That means there is no format
 * to detect, no volume problem, no second copy of a customer's query log, and no way for
 * Loghound to be blamed for something happening on a customer's node.
 *
 * THREE STATES, AND ALL THREE HAVE TO READ WELL:
 *
 *  1. Credentials configured and Loghound running on the web server — everything works,
 *     including the correlation.
 *  2. Credentials configured, Loghound running somewhere else — the Solr analytics are
 *     shown in full, and the correlation card explains, concretely, what installing
 *     Loghound where the web server runs would add. Not a vague upsell: the specific
 *     question it would answer.
 *  3. No Opensolr credentials — no broken cards, no failed requests. The view explains
 *     what this section is for and where the credentials go. Loghound is completely useful
 *     without Opensolr and must never imply otherwise.
 *
 * THE API KEY never reaches this layer's output. It is held by \Loghound\OpensolrLog,
 * used server-side only, and every message that can escape has been through that class's
 * redact(). Nothing here puts it in HTML, in a URL the browser sees, or in a JSON payload.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Opensolr;
use Loghound\OpensolrLog;
use Loghound\Security;

abstract class OpensolrView extends Controller implements JobHost
{
    /** Terms asked for when faceting client addresses. Bounded; the tail is a long one. */
    protected const IP_FACET_LIMIT = 60;

    /** @var OpensolrLog|null Lazily built, or injected by a test. */
    private ?OpensolrLog $client = null;

    /** @var Opensolr|null Lazily built, or injected by a test. */
    private ?Opensolr $account = null;

    /** @var array<string,mixed>|null Per-request memo of the index list. */
    private ?array $indexMemo = null;

    /**
     * Replace the request-log client, so tests run with no network.
     *
     * One of two setters on this class. A view is otherwise constructed exactly the way
     * every other panel view is, from config plus the Solr gateway.
     */
    public function setLogClient(OpensolrLog $client): void
    {
        $this->client = $client;
    }

    /**
     * Replace the control-plane client, so tests run with no network.
     *
     * Separate from the request-log client because they are separate planes: this one
     * lists and manages indexes, that one reads their traffic. A test that exercises the
     * ownership check needs to control what the account appears to own without also
     * pretending to be the analytics shards.
     */
    public function setAccountClient(Opensolr $client): void
    {
        $this->account = $client;
    }

    /** The platform client, built from the `opensolr` section of the config. */
    protected function log(): OpensolrLog
    {
        if ($this->client === null) {
            $this->client = new OpensolrLog((array) $this->cfg->get('opensolr', []));
        }
        return $this->client;
    }

    /** Are there Opensolr credentials to work with? Decides which of the three states applies. */
    protected function configured(): bool
    {
        return $this->log()->isConfigured();
    }

    /**
     * The index the view is looking at.
     *
     * Validated for shape only. Ownership is not Loghound's to decide and is not decided
     * here: the platform answers ERROR_NOT_CORE_OWNER for an index this account does not
     * hold, and that is handled as an ordinary outcome with a sentence, not as a failure.
     * Re-deriving ownership locally would mean a second API call per request to answer a
     * question the first call already answers.
     */
    protected function core(): string
    {
        $core = $_GET['core'] ?? '';
        if (!is_string($core) || $core === '' || !Security::isSafeCoreName($core)) {
            return '';
        }
        return $core;
    }

    /**
     * The account's indexes, discovered rather than typed.
     *
     * The control-plane client defaults to a sixty-second timeout, which is the whole of
     * PHP-FPM's execution budget on the reference install; the panel cannot afford that, so
     * a shorter one is imposed here. A failure is a state with a sentence, never a throw
     * that takes the page render with it.
     *
     * @return array{state:string,message:string,indexes:array<int,string>}
     */
    protected function indexes(): array
    {
        if ($this->indexMemo !== null) {
            return $this->indexMemo;
        }
        if (!$this->configured()) {
            return $this->indexMemo = [
                'state'   => 'not_configured',
                'message' => 'No Opensolr account is configured.',
                'indexes' => [],
            ];
        }

        try {
            if ($this->account === null) {
                $account = (array) $this->cfg->get('opensolr', []);
                $account['timeout'] = Security::clampInt($account['timeout'] ?? null, 5, 20, 15);
                $this->account = new Opensolr($account);
            }
            $names = $this->account->listIndexes();
            return $this->indexMemo = ['state' => 'ok', 'message' => '', 'indexes' => $names];
        } catch (\Throwable $e) {
            return $this->indexMemo = [
                'state'   => 'unreachable',
                'message' => 'The list of indexes could not be read from Opensolr. '
                    . 'Check outbound HTTPS from this host and the credentials in config/loghound.php.',
                'indexes' => [],
            ];
        }
    }

    /**
     * Read the request log for the selected index, or explain why it was not read.
     *
     * Every action on every one of these views goes through here rather than calling the
     * client directly, so the two conditions that are not "the platform said something"
     * are handled once:
     *
     *  - **Demo mode.** The panel can be run with fabricated web traffic for screenshots
     *    and offline demos. There is no fabricated Opensolr data and there should not be:
     *    the alternative is either inventing somebody's query log, or quietly making a real
     *    billed API call from a session that is showing a "these numbers are fake" banner.
     *    Both are worse than saying so.
     *  - **No index chosen yet.** The picker is filled from the platform, so the very first
     *    render of a card can legitimately have nothing selected.
     *
     * The stub returned in both cases has exactly the shape of a real result, so a caller
     * can read facets off it without a second code path.
     *
     * @param array<string,mixed> $opt Options for OpensolrLog::log().
     * @return array<string,mixed>
     */
    protected function fetch(array $opt): array
    {
        if ($this->gw->isDemo()) {
            return self::stub(
                'demo',
                'Demo mode fabricates web traffic only. Opensolr index analytics are read live from '
                . 'your account, so there is nothing to show while the panel is running on sample data.'
            );
        }

        $core = $this->core();
        if ($core === '') {
            return self::stub('no_index', '');
        }

        return $this->log()->log($core, $opt);
    }

    /**
     * A result-shaped placeholder for a call that was never made.
     *
     * @return array<string,mixed>
     */
    private static function stub(string $state, string $message): array
    {
        return [
            'state'        => $state,
            'message'      => $message,
            'numFound'     => 0,
            'start'        => 0,
            'docs'         => [],
            'facet_fields' => [],
            'facet_ranges' => [],
            'stats'        => [],
        ];
    }

    /**
     * The date filter every request-log query on this page carries.
     *
     * Solr date math evaluated by the platform against its own clock, so there is no
     * timezone skew between this host and the analytics shards to get wrong.
     *
     * @return array<int,string>
     */
    protected function logFqs(): array
    {
        return [OpensolrLog::dateFq((string) $this->range['start'])];
    }

    /* ---------------------------------------------------------------------------------
     * Stepped jobs
     * ------------------------------------------------------------------------------ */

    /**
     * The job kinds this view hosts. A view with no long operations returns none.
     *
     * Fail closed by default: the base class accepts POSTs because it implements JobHost,
     * but with an empty kind list every `job_start` is refused before the store is opened.
     * A subclass opts in by naming its kinds here AND registering a planner for each.
     *
     * @return array<int,string>
     */
    protected function jobKinds(): array
    {
        return [];
    }

    /**
     * Planners for this view's job kinds, keyed by kind.
     *
     * A planner is handed the job's context on every poll — which on the first call is
     * exactly the parameters start() was given — and returns the whole step plan. The plan
     * length must not vary between polls, because the store fixed `total` when the job was
     * created and the progress fraction is read against it.
     *
     * @return array<string,callable(array<string,mixed>):array<int,array{label:string,run:callable}>>
     */
    protected function jobPlans(): array
    {
        return [];
    }

    /**
     * Validate the parameters for one job start, or refuse the whole thing.
     *
     * OWNERSHIP IS DECIDED HERE AND NOWHERE ELSE. Jobs re-checks that parameters are flat,
     * small and well-named; it does not and cannot know whether this account owns the index
     * being named, so a subclass that takes an index name must check it against the
     * account's own list before returning. Returning null refuses the job, and refusing
     * before a job exists is the point: a job that starts and then discovers it may not read
     * its target has already put the target in the store, in a step note and in a poll
     * envelope.
     *
     * @return array<string,scalar|null>|null Null refuses the start.
     */
    protected function jobParams(string $kind): ?array
    {
        return null;
    }

    /** The job store for this view, with this view's planners registered. */
    protected function jobs(): Jobs
    {
        return new Jobs($this->cfg, $this->gw, $this->jobPlans());
    }

    /**
     * The newest job of a requested kind belonging to this operator.
     *
     * The kind is checked against this view's own list before the store is touched, and the
     * store scopes every lookup to the caller's session, so this cannot read somebody
     * else's operation. The job's context comes back with it, which is how a reloaded page
     * decides whether the operation it found is the one it was watching.
     *
     * @return array<string,mixed>
     */
    private function latestJob(): array
    {
        $kinds = $this->jobKinds();
        if ($kinds === []) {
            return ['error' => 'Unknown operation.'];
        }
        $kind = self::param('kind', $kinds, '');
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
     * Handle one of the asynchronous job endpoints, answering with JSON.
     *
     * Declared `never` rather than `void`: both paths out of this method end in sendJson(),
     * which exits. Saying so in the signature is what lets post() write
     * `return $this->jobJson(...)` for each job case and stay exhaustive, instead of relying
     * on a fall-through that happens to be harmless only because this method never comes
     * back. Failure to open the store is reported as a failure, never silently ignored, and
     * the message that reaches the log goes through Jobs::redact() first.
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
     * Handle a POST on one of these views.
     *
     * These views change no configuration; the only state they touch is the job store, so
     * the three job endpoints are the whole of it. CSRF has already been enforced by the
     * front controller before this is reached, and is enforced again here: this method is
     * the boundary that decides whether a scan is started, and a control that is only
     * applied by the caller is a control one refactor away from being gone.
     *
     * EVERY arm of the switch returns. The job cases end in jobJson(), which exits, and
     * saying so in its signature is what keeps that exhaustive rather than a fall-through
     * that is harmless only by accident.
     *
     * @return string The redirect query string to send the browser to.
     */
    public function post(): string
    {
        Security::requireCsrf();

        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';

        switch ($action) {
            case 'job_start':
                return $this->jobJson(function (Jobs $jobs): array {
                    $kind = self::postParam('kind', $this->jobKinds());
                    if ($kind === '') {
                        return ['error' => 'Unknown operation.'];
                    }
                    $params = $this->jobParams($kind);
                    if ($params === null) {
                        return ['error' => 'That operation cannot run against the index you asked for.'];
                    }
                    return $jobs->start($kind, $params);
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
                return '?v=' . rawurlencode($this->slug()) . '&err=unknown_action';
        }
    }

    /**
     * Act on a job only if it is one of THIS view's kinds.
     *
     * The store scopes every lookup to the signed-in operator, so an id can only ever name
     * a job they own — but ownership is not enough here. Every one of these views accepts
     * POSTs, and each registers a different set of planners, so advancing a job of another
     * view's kind would rebuild it against a plan that does not contain its steps: the
     * store would find no step at the job's index and mark a scan that had barely begun as
     * finished. Checking the kind first turns that into a refusal.
     *
     * A job of the wrong kind is reported exactly as one that does not exist, so an id
     * cannot be probed for which view owns it.
     *
     * @param callable(Jobs,string):array<string,mixed> $fn
     * @return array<string,mixed>
     */
    private function onOwnJob(Jobs $jobs, string $id, callable $fn): array
    {
        $kinds = $this->jobKinds();
        if ($kinds === [] || $id === '') {
            return ['error' => 'That operation is no longer available. Start it again.'];
        }
        $job = $jobs->get($id);
        if (!isset($job['kind']) || !in_array($job['kind'], $kinds, true)) {
            return ['error' => 'That operation is no longer available. Start it again.'];
        }
        return $fn($jobs, $id);
    }

    /**
     * Read a POST field constrained to an allowlist.
     *
     * Returns the empty string when the value is absent or not on the list, so a caller
     * that forgets to check gets a value the job store will refuse rather than one it will
     * act on.
     *
     * @param array<int,string> $allowed
     */
    private static function postParam(string $key, array $allowed): string
    {
        $value = $_POST[$key] ?? null;
        return is_string($value) && in_array($value, $allowed, true) ? $value : '';
    }

    /** Read a job id from a POST body, shape-checked before it reaches the store. */
    private static function postJobId(): string
    {
        $value = $_POST['id'] ?? null;
        return is_string($value) && Jobs::isJobId($value) ? $value : '';
    }

    /**
     * Wrap a request-log result in the panel's response envelope.
     *
     * `state` and `message` always travel, so the front end renders "this account does not
     * own that index" as a sentence in the card rather than as a generic failure.
     *
     * @param array<string,mixed> $result A result from OpensolrLog::log().
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    protected function logEnvelope(array $result, array $extra = []): array
    {
        return $this->envelope(array_merge([
            'state'    => (string) $result['state'],
            'note'     => (string) $result['message'],
            'core'     => $this->core(),
            'requests' => (int) $result['numFound'],
        ], $extra));
    }

    /**
     * Answer the actions every Opensolr view shares, or null when it is not one of them.
     *
     * @return array<string,mixed>|null
     */
    protected function sharedApi(string $action): ?array
    {
        if ($action === 'job_latest') {
            return $this->latestJob();
        }
        if ($action !== 'indexes') {
            return null;
        }
        $list = $this->indexes();

        return $this->envelope([
            'state'    => $list['state'],
            'note'     => $list['message'],
            'indexes'  => $list['indexes'],
            'selected' => $this->core(),
        ]);
    }

    /* ---------------------------------------------------------------------------------
     * Shared markup
     * ------------------------------------------------------------------------------ */

    /**
     * The state-3 screen: no Opensolr credentials at all.
     *
     * Not an error and not a nag. Loghound is a complete product without Opensolr, and the
     * only honest thing to do is say what this section would show and where the two values
     * go. Rendered instead of the cards, so nothing on the page can fail.
     */
    protected static function noCredentials(): void
    {
        echo '<section class="card">';
        echo '<div class="card-head"><h2><span class="card-num">01</span>'
            . '<span>Not connected to Opensolr</span></h2></div>';
        echo '<div class="explain">';
        echo '<p>This section reads the request log of your Opensolr search indexes and lines it up '
            . 'against the web traffic Loghound already analyses. Everything else in Loghound works '
            . 'without it — this is the search half, and it is switched off because there is no '
            . 'Opensolr account configured.</p>';
        echo '<p>With an account connected, these pages answer:</p>';
        echo '<ul>';
        echo '<li>how many queries each index served, how long they took, and which node answered;</li>';
        echo '<li>which <strong>shapes</strong> of query run most often — grouped by structure, not by the '
            . 'words a visitor typed — and which of those shapes return no results at all;</li>';
        echo '<li>which addresses query your index, and how much of that work is being done for traffic '
            . 'Loghound has already classified as a bot;</li>';
        echo '<li>which queries reach your index from clients that never appear in your web logs at all.</li>';
        echo '</ul>';
        echo '<p>To connect one, put the email address of your Opensolr account and its API key into the '
            . '<code>opensolr</code> section of <code>config/loghound.php</code>, which lives outside the '
            . 'document root:</p>';
        echo '<pre class="snippet mono">\'opensolr\' =&gt; [' . "\n"
            . '    \'email\'   =&gt; \'you@example.com\',' . "\n"
            . '    \'api_key\' =&gt; \'&hellip;\',' . "\n"
            . '],</pre>';
        echo '<p class="faint">The key is read server-side only. It is never rendered into a page, never '
            . 'put in a URL your browser sees, and never written to a log.</p>';
        echo '</div>';
        self::cardEnd();
    }

    /**
     * The index picker, rendered empty and filled by the front end.
     *
     * Empty on purpose: the list comes from the platform, so populating it server-side
     * would make every page render wait on an API call — the exact blocking this panel is
     * built to avoid.
     */
    protected static function indexPicker(string $id): string
    {
        $e = Security::esc($id);
        return '<div class="controls">'
            . '<label for="' . $e . '">Index</label>'
            . '<select id="' . $e . '" disabled><option value="">Loading&#8230;</option></select>'
            . '</div>';
    }
}
