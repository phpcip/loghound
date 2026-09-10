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
 * The page also owns the settings that change what gets stored about people — IP privacy
 * mode and retention — which are given their own section and plain-language consequences
 * rather than being buried in a list of toggles.
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

use Loghound\Security;

final class Settings extends Controller
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
     * The newest job of a requested kind belonging to this operator.
     *
     * The kind is checked against Jobs::KINDS before the store is touched, and the store
     * scopes every lookup to the caller's own session, so this cannot be used to read
     * somebody else's operation.
     *
     * @return array<string,mixed>
     */
    private function latestJob(): array
    {
        $kind = self::param('kind', Jobs::KINDS, '');
        if ($kind === '') {
            return ['error' => 'Unknown operation.'];
        }
        try {
            $job = (new Jobs($this->cfg, $this->gw))->latest($kind);
        } catch (\Throwable $e) {
            return ['error' => 'The job store is unavailable.'];
        }
        return $this->envelope(['job' => $job]);
    }

    /**
     * Handle one of the asynchronous job endpoints, answering with JSON.
     *
     * Reached through post(), so the front controller has already enforced both
     * authentication and the CSRF token: a job endpoint mutates state and is treated
     * exactly like any other state-changing request. Failure to open the store is
     * reported as a failure, never silently ignored.
     *
     * @param callable(Jobs):array<string,mixed> $fn
     * @return never
     */
    private function jobJson(callable $fn): void
    {
        try {
            $jobs = new Jobs($this->cfg, $this->gw);
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
     * @return string The redirect query string to send the browser to.
     */
    public function post(): string
    {
        $action = is_string($_POST['action'] ?? null) ? $_POST['action'] : '';

        switch ($action) {
            case 'confirm_source':
                return $this->confirmSource();

            case 'privacy':
                return $this->savePrivacy();

            case 'scoring':
                return $this->saveScoring();

            case 'ui':
                return $this->saveUi();

            case 'job_start':
                $this->jobJson(fn (Jobs $jobs): array => $jobs->start(self::postParam('kind', Jobs::KINDS)));

            case 'job_poll':
                $this->jobJson(fn (Jobs $jobs): array => $jobs->advance(self::postJobId()));

            case 'job_cancel':
                $this->jobJson(fn (Jobs $jobs): array => $jobs->cancel(self::postJobId()));

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

        $sources = (array) $this->cfg->get('sources', []);
        $already = false;
        foreach ($sources as $i => $s) {
            if (($s['path'] ?? null) === $path) {
                $sources[$i]['format'] = (string) ($found['format_name'] ?? 'combined');
                $sources[$i]['confirmed'] = true;
                $already = true;
            }
        }
        if (!$already) {
            $sources[] = [
                'path'      => $path,
                'format'    => (string) ($found['format_name'] ?? 'combined'),
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
     * Persist the reviewed flag back into the detection report.
     *
     * Best-effort: the config write above is what matters, and a read-only var/ should
     * not turn a successful confirmation into an error.
     */
    private function markConfirmed(string $path): void
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
                $data['sources'][$i]['confirmed'] = true;
            }
        }
        @file_put_contents(self::DETECT_FILE, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /** Save the privacy section, refusing anything outside the documented values. */
    private function savePrivacy(): string
    {
        $mode = is_string($_POST['ip_mode'] ?? null) ? $_POST['ip_mode'] : '';
        if (!in_array($mode, ['full', 'truncate', 'hash'], true)) {
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
            'privacy_saved'    => 'Privacy settings saved.',
            'scoring_saved'    => 'Scoring weights saved. The rule version was bumped so older verdicts stay traceable.',
            'ui_saved'         => 'Display settings saved.',
            'solr_up'          => 'Solr answered. The connection is working.',
        ];
        $err = [
            'solr_down'       => 'Solr did not answer. Check the base URL, credentials and firewall.',
            'no_such_source'  => 'That log source is not in the detection report any more. Re-run loghound-setup.',
            'path_not_allowed' => 'That path is outside allowed_log_roots and was refused.',
            'save_failed'     => 'The configuration file could not be written. Check ownership and mode 0640 on config/loghound.php.',
            'bad_ip_mode'     => 'Unknown IP privacy mode.',
            'bad_thresholds'  => 'Thresholds must descend: bot > likely_bot > unknown > likely_human.',
            'bad_timezone'    => 'Unknown timezone.',
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

    public function body(): void
    {
        self::flash();
        $this->sourcesSection();
        $this->solrSection();
        $this->beaconSection();
        $this->privacySection();
        $this->retentionSection();
        $this->scoringSection();
        $this->displaySection();
    }

    /**
     * The log-format review. The single most important control on this page.
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
            '01',
            'Log sources',
            'Detected by reading your webserver configuration where possible, and by scoring sample lines against '
            . 'the known-format library where it is not. Nothing is ingested until you confirm the mapping below.'
        );

        if ($sources === []) {
            echo '<div class="empty show">';
            echo '<h3>No log sources detected yet</h3>';
            echo '<p>Run the setup command on the server. It reads your Apache or nginx configuration, finds the '
                . '<code>CustomLog</code> / <code>access_log</code> directives, works out the exact format for each '
                . 'one, and writes the result to <code>var/detect.json</code>:</p>';
            echo '<pre class="snippet mono">sudo -u loghound php bin/loghound-setup detect</pre>';
            echo '<p>Then reload this page to review what it found.</p>';
            echo '</div>';
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
            }
            echo '</article>';
        }
        self::cardEnd();
    }

    /**
     * Solr connection, read-only, with the checks offered as asynchronous jobs.
     *
     * Nothing here contacts Solr while the page renders. Both checks are stepped jobs the
     * operator starts, because a ping to an unreachable host and a document count on a
     * large index are exactly the operations that used to hang a request until PHP-FPM
     * killed it. Credentials are reported as present or absent and never printed.
     */
    private function solrSection(): void
    {
        $mode = (string) $this->cfg->get('solr.mode', 'opensolr');

        self::cardOpen('set-solr', '02', 'Solr connection');
        echo '<dl class="kv">';
        echo '<dt>Mode</dt><dd class="mono">' . Security::esc($mode) . '</dd>';
        if ($mode === 'opensolr') {
            echo '<dt>Account</dt><dd class="mono">'
                . Security::esc((string) $this->cfg->get('opensolr.email', '—')) . '</dd>';
            echo '<dt>Region</dt><dd class="mono">'
                . Security::esc((string) $this->cfg->get('opensolr.region', '—')) . '</dd>';
            echo '<dt>API key</dt><dd>' . ($this->cfg->get('opensolr.api_key')
                ? '<span class="chip chip-good">Set</span>'
                : '<span class="chip chip-warn">Missing</span>') . '</dd>';
        } else {
            echo '<dt>Base URL</dt><dd class="mono">'
                . Security::esc((string) $this->cfg->get('solr.base_url', '—')) . '</dd>';
            echo '<dt>HTTP auth</dt><dd>' . ($this->cfg->get('solr.http_user')
                ? '<span class="chip chip-good">Configured</span>'
                : '<span class="chip">None</span>') . '</dd>';
        }
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
        if ($mode === 'opensolr') {
            echo '<button type="button" data-job="opensolr_check" data-mount="job-solr">'
                . 'Validate Opensolr credentials</button>';
        }
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

        self::cardOpen('set-retention', '05', 'Retention preview');
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
     * question is "does this work at all", not "what happened in the last hour".
     *
     * @return array{ever:int,hour:int,day:int,last:?string,coverage:?float}
     */
    private function beaconStatus(): array
    {
        $f = $this->gw->facet('settings.beacon', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => ['ts_start:[NOW-30DAY TO NOW]'],
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

        self::cardOpen('set-beacon', '03', 'Beacon / JavaScript tracking');
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

    /** IP privacy mode and retention, with the consequence of each spelled out. */
    private function privacySection(): void
    {
        $mode = (string) $this->cfg->get('privacy.ip_mode', 'full');
        $days = (int) $this->cfg->get('privacy.retention_days', 90);

        self::cardOpen('set-privacy', '04', 'Privacy');
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
            '06',
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

        self::cardOpen('set-display', '07', 'Display');
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
