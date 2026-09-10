<?php
/**
 * Loghound — the installer's HTML.
 *
 * One place that emits every screen of the browser installer, so the controller contains
 * no markup and the markup contains no decisions.
 *
 * Three constraints shape this file:
 *
 *  - **The CSP has no 'unsafe-inline' for scripts.** There is no inline <script>, no
 *    `onclick=`, no `javascript:` href anywhere. Behaviour is attached in
 *    public/assets/js/setup.js, which is same-origin.
 *  - **Everything rendered is escaped, without exception.** Most of what appears here is
 *    hostile by construction: a sample log line contains a request path chosen by whoever
 *    sent it, and this screen exists precisely to show those lines to a human.
 *  - **No secret is ever rendered.** The Opensolr API key, the beacon signing key, the
 *    address salt and the password appear nowhere — not as a value, not as a placeholder,
 *    not in a hidden field. Where it matters that one is set, presence is shown instead.
 *
 * The look is the panel's own (public/assets/css/panel.css): flat, 2px corners, one accent
 * colour, monospace for data, 14px floor, dark and light. It is the same product, not a
 * wizard bolted onto the side of it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Security;

final class View
{
    private Config $cfg;

    private string $root;

    private Requirements $req;

    private Token $token;

    /** @var array<string,mixed> Per-render context handed over by the controller. */
    private array $ctx = [];

    public function __construct(Config $cfg, string $root, Requirements $req, Token $token)
    {
        $this->cfg   = $cfg;
        $this->root  = rtrim($root, '/');
        $this->req   = $req;
        $this->token = $token;
    }

    /**
     * Render a whole page.
     *
     * @param array<string,mixed> $ctx unlocked, flash, jobs, regions, progress
     */
    public function page(string $step, array $ctx): void
    {
        $this->ctx = $ctx;

        header('Content-Type: text/html; charset=utf-8');

        $asset = function (string $rel): string {
            $path = $this->root . '/public/' . $rel;
            return $rel . '?v=' . (is_file($path) ? (string) filemtime($path) : '0');
        };

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n<head>\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>Set up Loghound</title>' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/panel.css')) . '">' . "\n";
        echo '<script src="' . Security::esc($asset('assets/js/theme.js')) . '"></script>' . "\n";
        echo "</head>\n<body class=\"setup-body\">\n";

        echo '<script type="application/json" id="lh-setup-boot">'
            . Security::escJs([
                'csrf' => Security::csrfToken(),
                'jobs' => (array) ($ctx['jobs'] ?? []),
            ])
            . "</script>\n";

        echo '<main class="setup" id="main">' . "\n";

        $this->heading($step);
        $this->rail($step);
        $this->flash();

        switch ($step) {
            case Installer::STEP_SOURCES:
                $this->stepSources();
                break;
            case Installer::STEP_STORAGE:
                $this->stepStorage();
                break;
            case Installer::STEP_PRIVACY:
                $this->stepPrivacy();
                break;
            case Installer::STEP_ADMIN:
                $this->stepAdmin();
                break;
            default:
                $this->stepStatus();
        }

        $this->footer();

        echo "</main>\n";
        echo '<script type="module" src="' . Security::esc($asset('assets/js/setup.js')) . '"></script>' . "\n";
        echo "</body>\n</html>\n";
    }

    /**
     * The page title and its one-line lead.
     *
     * Nothing is rendered above the H1 — no badge, no kicker, no logo strip.
     */
    private function heading(string $step): void
    {
        static $titles = [
            Installer::STEP_STATUS  => ['Set up Loghound', 'Everything this server needs, checked one item at a time. Anything that needs fixing comes with the command that fixes it.'],
            Installer::STEP_SOURCES => ['Choose your access logs', 'Loghound reads your webserver\'s own log files. Check that it has understood the format before anything is indexed.'],
            Installer::STEP_STORAGE => ['Where should the index live?', 'Loghound keeps what it learns in two Solr indexes. Let us create them for you, or point at a Solr you already run.'],
            Installer::STEP_PRIVACY => ['What to keep about your visitors', 'You decide what is stored and for how long. This is a real choice, not a formality.'],
            Installer::STEP_ADMIN   => ['Create your sign-in', 'Set the username and password you will use to sign in to Loghound.'],
        ];

        [$title, $lead] = $titles[$step] ?? $titles[Installer::STEP_STATUS];

        echo '<h1>' . Security::esc($title) . '</h1>' . "\n";
        echo '<p class="setup-lead">' . Security::esc($lead) . '</p>' . "\n";
    }

    /**
     * The step rail.
     *
     * Finished steps are links, because going back to change an answer is normal. Steps
     * ahead of the current one are not: they read values the earlier ones write, and the
     * controller refuses them anyway.
     */
    private function rail(string $current): void
    {
        static $labels = [
            Installer::STEP_SOURCES => 'Access logs',
            Installer::STEP_STORAGE => 'Storage',
            Installer::STEP_PRIVACY => 'Privacy',
            Installer::STEP_ADMIN   => 'Sign-in',
        ];

        $progress = (array) ($this->ctx['progress'] ?? []);
        $unlocked = !empty($this->ctx['unlocked']);

        echo '<ol class="setup-rail">' . "\n";

        $done = $current !== Installer::STEP_STATUS;
        echo '<li class="' . ($current === Installer::STEP_STATUS ? 'on' : ($done ? 'done' : '')) . '">'
            . '<a href="?setup=' . Security::esc(Installer::STEP_STATUS) . '">System check</a></li>';

        foreach (Installer::ORDER as $i => $step) {
            $classes = [];
            if ($step === $current) {
                $classes[] = 'on';
            }
            if (!empty($progress[$step])) {
                $classes[] = 'done';
            }
            $label = ($i + 1) . '. ' . ($labels[$step] ?? $step);

            echo '<li class="' . Security::esc(implode(' ', $classes)) . '">';
            if ($unlocked && (!empty($progress[$step]) || $step === $current)) {
                echo '<a href="?setup=' . Security::esc($step) . '">' . Security::esc($label) . '</a>';
            } else {
                echo '<span>' . Security::esc($label) . '</span>';
            }
            echo '</li>';
        }

        echo "\n</ol>\n";
    }

    /** The one-shot message from the previous request, if there is one. */
    private function flash(): void
    {
        $flash = $this->ctx['flash'] ?? null;
        if (!is_array($flash)) {
            return;
        }
        $class = $flash['kind'] === 'ok' ? 'banner-good' : 'banner-bad';
        echo '<div class="banner ' . $class . '" role="' . ($flash['kind'] === 'ok' ? 'status' : 'alert') . '">'
            . Security::esc((string) $flash['text']) . "</div>\n";
    }

    /** The hidden CSRF field every form on every screen carries. */
    private function csrf(string $step, string $action): void
    {
        echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';
        echo '<input type="hidden" name="step" value="' . Security::esc($step) . '">';
        echo '<input type="hidden" name="action" value="' . Security::esc($action) . '">';
    }

    /**
     * The status page: what is wrong, what is missing, and how to unlock.
     *
     * Readable without the setup token on purpose. It contains no secret, and an operator
     * looking at a permission problem needs to be able to see it before they can go and
     * fix it in a shell.
     */
    private function stepStatus(): void
    {
        $rows = $this->req->all();
        $blocked = Requirements::blocked($rows);
        $missing = $this->req->missing();
        $configured = is_file($this->cfg->path());

        echo '<section class="card">';
        echo '<h2>' . ($configured ? 'This installation is not finished' : 'Loghound has not been set up yet') . '</h2>';

        if ($configured) {
            echo '<p>A configuration file already exists, so nothing you have done is lost. '
                . 'These are the pieces that are still missing:</p>';
        } else {
            echo '<p>Nothing has been configured yet. This takes four short steps: which log '
                . 'files to read, where to keep the index, what to store about visitors, and '
                . 'the password you will sign in with.</p>';
        }

        if ($missing !== []) {
            echo '<ul class="setup-missing">';
            foreach ($missing as $item) {
                echo '<li>' . Security::esc($item['text'])
                    . ' <a href="?setup=' . Security::esc($item['step']) . '">Fix this</a></li>';
            }
            echo '</ul>';
        }
        echo '</section>';

        $this->unlockPanel($blocked);
        $this->checksTable($rows);
        $this->storagePanel();
    }

    /**
     * The token gate.
     *
     * Says which file to read and the exact command that prints it. Without this an
     * installer on a live URL would let whoever found it first point Loghound at a Solr
     * they control and set the password.
     */
    private function unlockPanel(bool $blocked): void
    {
        if (!empty($this->ctx['unlocked'])) {
            echo '<section class="card">';
            echo '<h2>Ready to continue</h2>';
            echo '<p><span class="chip chip-good">Unlocked</span> This browser has proved it can read '
                . 'a file on this server.</p>';
            if ($blocked) {
                echo '<p class="muted">Some checks below are still failing. You can carry on, but '
                    . 'fix them before starting the ingest daemon or it will read nothing.</p>';
            }
            echo '<p><a class="btn" href="?setup=' . Security::esc(Steps::firstIncomplete($this->cfg))
                . '">Continue</a></p>';
            echo '</section>';
            return;
        }

        $haveToken = $this->token->ensure();

        echo '<section class="card">';
        echo '<h2>Prove you have access to this server</h2>';
        echo '<p>Anyone can reach this page — it is on the internet, and Loghound is not '
            . 'configured yet. So before anything can be saved, paste the setup token. It is in a '
            . 'file only this server\'s administrator can read:</p>';

        if (!$haveToken) {
            echo '<div class="banner banner-bad" role="alert">The token file could not be created, '
                . 'because Loghound cannot write to its own <code>var</code> directory. Fix that '
                . 'first — the commands are in the table below.</div>';
        }

        echo '<pre class="snippet mono">sudo cat ' . Security::esc($this->token->path()) . '</pre>';

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STATUS) . '" class="setup-form">';
        $this->csrf(Installer::STEP_STATUS, 'unlock');
        echo '<label for="token">Setup token</label>';
        echo '<input type="text" id="token" name="token" autocomplete="off" spellcheck="false" '
            . 'inputmode="latin" size="40" required>';
        echo '<button type="submit" class="primary">Unlock setup</button>';
        echo '</form>';

        echo '<p class="muted">Would rather do it in the shell? '
            . '<code>' . Security::esc($this->req->cliCommand()) . '</code> runs the same setup as a '
            . 'terminal wizard and produces exactly the same configuration.</p>';
        echo '</section>';
    }

    /**
     * The requirement table.
     *
     * @param array<int,array{id:string,label:string,state:string,detail:string,fix:string[]}> $rows
     */
    private function checksTable(array $rows): void
    {
        echo '<section class="card">';
        echo '<h2>System check</h2>';
        echo '<p class="pop">Checked as <code>' . Security::esc(Requirements::phpUser())
            . '</code>, the user this page runs as. A fix below is written for that user.</p>';

        echo '<div class="table-wrap"><table class="tight checks"><thead><tr>'
            . '<th scope="col">Status</th><th scope="col">Requirement</th><th scope="col">Detail</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $state = (string) $row['state'];
            $chip = $state === 'pass' ? 'chip-good' : ($state === 'warn' ? 'chip-warn' : 'chip-bad');
            $word = $state === 'pass' ? 'OK' : ($state === 'warn' ? 'Note' : 'Fix');

            echo '<tr>';
            echo '<td class="nowrap"><span class="chip ' . $chip . '">' . $word . '</span></td>';
            echo '<td class="nowrap">' . Security::esc((string) $row['label']) . '</td>';
            echo '<td class="wrap">' . Security::esc((string) $row['detail']);
            if ((array) $row['fix'] !== []) {
                echo '<pre class="snippet mono">';
                foreach ((array) $row['fix'] as $line) {
                    echo Security::esc((string) $line) . "\n";
                }
                echo '</pre>';
            }
            echo '</td></tr>';
        }

        echo '</tbody></table></div></section>';
    }

    /**
     * The "does the index answer" panel on the status page.
     *
     * The probe itself is a job rather than an inline call: a firewalled Solr would
     * otherwise hold this page open until the gateway killed it, and a status page that
     * hangs is worse than one that has a button.
     */
    private function storagePanel(): void
    {
        if ((string) $this->cfg->get('solr.base_url', '') === '') {
            return;
        }

        $jobs = (array) ($this->ctx['jobs'] ?? []);

        echo '<section class="card">';
        echo '<h2>Search index</h2>';
        echo '<dl class="kv">';
        echo '<dt>Mode</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('solr.mode', 'opensolr')) . '</dd>';
        echo '<dt>Hits index</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('solr.hits_core', '-')) . '</dd>';
        echo '<dt>Sessions index</dt><dd class="mono">'
            . Security::esc((string) $this->cfg->get('solr.sessions_core', '-')) . '</dd>';
        echo '</dl>';

        if (empty($this->ctx['unlocked'])) {
            echo '<p class="muted">Unlock setup above to test the connection.</p>';
            echo '</section>';
            return;
        }

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '">';
        $this->csrf(Installer::STEP_STORAGE, 'test');
        echo '<button type="submit">Test the connection</button>';
        echo '</form>';
        echo '</section>';

        if (isset($jobs[Job::KIND_SOLRTEST])) {
            $this->jobPanel(Job::KIND_SOLRTEST, (string) $jobs[Job::KIND_SOLRTEST], 'Testing the connection');
        }
    }

    /**
     * The log-source review: the one screen SPEC §8 will not let us skip.
     *
     * Every candidate shows where the format came from, how much of a real sample it
     * parses, the token-to-field mapping, and five real lines rendered as records. Nothing
     * is ingested until a human has looked at that and ticked it.
     */
    private function stepSources(): void
    {
        $report = Detector::lastReport($this->cfg);
        $sources = (array) ($report['sources'] ?? []);
        $jobs = (array) ($this->ctx['jobs'] ?? []);
        $jobId = (string) ($jobs[Job::KIND_DETECT] ?? '');

        echo '<section class="card">';
        echo '<h2>Find the logs</h2>';
        echo '<p>Loghound reads your Apache or nginx configuration where it can — that gives the '
            . 'exact format and the virtual host of every access log, with nothing guessed. Where it '
            . 'cannot, it scores real sample lines against the formats it knows.</p>';

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_SOURCES) . '">';
        $this->csrf(Installer::STEP_SOURCES, 'detect');
        echo '<button type="submit" class="primary">'
            . ($sources === [] ? 'Scan this server' : 'Scan again') . '</button>';
        echo '</form>';
        echo '</section>';

        if ($jobId !== '') {
            $this->jobPanel(Job::KIND_DETECT, $jobId, 'Scanning');
        }

        foreach ($sources as $i => $src) {
            $this->sourceCard((int) $i, (array) $src);
        }

        if ($sources !== []) {
            echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_SOURCES) . '" class="card">';
            $this->csrf(Installer::STEP_SOURCES, 'confirm');
            echo '<h2>Confirm</h2>';
            echo '<p>Tick every file above whose parsed lines look right, then confirm. You can '
                . 'change this later in Settings.</p>';
            foreach ($sources as $i => $src) {
                $path = (string) ($src['path'] ?? '');
                echo '<label class="check"><input type="checkbox" name="pick[]" value="' . (int) $i . '"'
                    . (empty($src['outside_roots']) ? ' checked' : '') . '>'
                    . '<span class="mono">' . Security::esc($path) . '</span></label>';
                if (!empty($src['outside_roots'])) {
                    echo '<label class="check setup-widen"><input type="checkbox" name="widen[]" value="' . (int) $i . '">'
                        . '<span>Also allow Loghound to read files under <span class="mono">'
                        . Security::esc(dirname($path)) . '</span> — it is outside the directories it '
                        . 'may read today, and it will be refused without this.</span></label>';
                }
            }
            echo '<button type="submit" class="primary">These look right — continue</button>';
            echo '</form>';
        }

        $this->manualSourceForm();
    }

    /**
     * One detected file, with everything needed to judge it.
     *
     * @param array<string,mixed> $src
     */
    private function sourceCard(int $index, array $src): void
    {
        $confidence = (float) ($src['confidence'] ?? 0);
        $path = (string) ($src['path'] ?? '');

        echo '<section class="card source">';
        echo '<div class="source-head">';
        echo '<h3 class="mono">' . Security::esc($path) . '</h3>';
        $chip = $confidence >= 95 ? 'chip-good' : ($confidence >= 70 ? 'chip-warn' : 'chip-bad');
        echo '<span class="chip ' . $chip . '">'
            . Security::esc(number_format($confidence, 1)) . '% parsed</span>';
        echo '</div>';

        echo '<dl class="kv">';
        echo '<dt>Detected from</dt><dd>' . Security::esc((string) ($src['source'] ?? 'unknown')) . '</dd>';
        echo '<dt>Format</dt><dd class="mono">' . Security::esc((string) ($src['format_name'] ?? '')) . '</dd>';
        if ((string) ($src['format_string'] ?? '') !== '') {
            echo '<dt>Format string</dt><dd><code class="mono wrap">'
                . Security::esc((string) $src['format_string']) . '</code></dd>';
        }
        if (!empty($src['vhost'])) {
            echo '<dt>Virtual host</dt><dd class="mono">' . Security::esc((string) $src['vhost']) . '</dd>';
        }
        echo '<dt>Sample</dt><dd>' . (int) ($src['lines_parsed'] ?? 0) . ' of '
            . (int) ($src['lines_tested'] ?? 0) . ' recent lines parsed cleanly '
            . '<span class="meter" role="img" aria-label="'
            . Security::esc(number_format($confidence, 1)) . ' percent"><span class="meter-fill" style="width:'
            . (int) max(0, min(100, $confidence)) . '%"></span></span></dd>';
        echo '</dl>';

        if (!empty($src['outside_roots'])) {
            echo '<div class="banner banner-warn">This file is outside the directories Loghound is '
                . 'allowed to read. Confirming it needs the extra tick below the list.</div>';
        }

        $this->mappingTable((array) ($src['mapping'] ?? []));
        $this->missingList((array) ($src['missing'] ?? []));
        $this->sampleLines((array) ($src['samples'] ?? []));

        if ((array) ($src['alternatives'] ?? []) !== []) {
            $alts = [];
            foreach ((array) $src['alternatives'] as $alt) {
                $alts[] = (string) $alt['name'] . ' (' . number_format((float) $alt['confidence'], 1) . '%)';
            }
            echo '<p class="muted">Also considered: ' . Security::esc(implode(', ', $alts)) . '</p>';
        }

        echo '</section>';
    }

    /**
     * The token → field mapping.
     *
     * @param array<int,array{token:string,field:string,example:string}> $mapping
     */
    private function mappingTable(array $mapping): void
    {
        if ($mapping === []) {
            return;
        }
        echo '<h4>Field mapping</h4>';
        echo '<div class="table-wrap"><table class="tight"><thead><tr>'
            . '<th scope="col">Log field</th><th scope="col">Loghound field</th><th scope="col">Example</th>'
            . '</tr></thead><tbody>';
        foreach ($mapping as $m) {
            echo '<tr>';
            echo '<td class="mono nowrap">' . Security::esc((string) ($m['token'] ?? '')) . '</td>';
            echo '<td class="mono nowrap">' . Security::esc((string) ($m['field'] ?? '')) . '</td>';
            echo '<td class="mono clip">' . Security::esc((string) ($m['example'] ?? '')) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
    }

    /**
     * What this format cannot see, and the honest cost of each gap.
     *
     * @param array<int,array{field:string,token:string,why:string}> $missing
     */
    private function missingList(array $missing): void
    {
        if ($missing === []) {
            return;
        }
        echo '<h4>Not logged — and what that costs you</h4>';
        echo '<ul class="missing">';
        foreach ($missing as $m) {
            echo '<li><code class="mono">' . Security::esc((string) ($m['token'] ?? '')) . '</code> → '
                . '<code class="mono">' . Security::esc((string) ($m['field'] ?? '')) . '</code>: '
                . Security::esc((string) ($m['why'] ?? '')) . '</li>';
        }
        echo '</ul>';
        echo '<p class="muted">Plain <code>combined</code> works — it just detects less. '
            . '<code>docs/INSTALL.md</code> has a copy-paste <code>LogFormat</code> that adds all of these.</p>';
    }

    /**
     * Five real lines, raw and parsed.
     *
     * These are attacker-controlled bytes by definition: a request path is chosen by
     * whoever sent it, and a User-Agent is whatever a client claimed. Every value is
     * escaped, none is ever rendered as a link, and the raw line is shown in a <pre> so
     * what the operator sees is exactly what is in the file.
     *
     * @param array<int,array{raw:string,parsed:array<string,string>}> $samples
     */
    private function sampleLines(array $samples): void
    {
        if ($samples === []) {
            echo '<p class="muted">No line in this file could be parsed with that format. '
                . 'Confirming it would fill the index with nothing.</p>';
            return;
        }

        echo '<h4>Lines from this file, as Loghound reads them</h4>';
        echo '<p class="muted">Read these. If a value is in the wrong column, the format is wrong.</p>';

        foreach ($samples as $sample) {
            echo '<div class="sample">';
            echo '<pre class="sample-raw mono">' . Security::esc((string) ($sample['raw'] ?? '')) . '</pre>';
            echo '<div class="table-wrap"><table class="tight sample-parsed"><tbody>';
            foreach ((array) ($sample['parsed'] ?? []) as $field => $value) {
                echo '<tr><th scope="row" class="mono nowrap">' . Security::esc((string) $field) . '</th>';
                echo '<td class="mono clip">' . Security::esc((string) $value) . '</td></tr>';
            }
            echo '</tbody></table></div>';
            echo '</div>';
        }
    }

    /**
     * Adding a log file by hand.
     *
     * The path is resolved against `allowed_log_roots` server-side and refused if it falls
     * outside; that list is not widened from a web form. A custom pattern is checked for
     * catastrophic backtracking before it can be stored, because a pattern that stalls the
     * ingest daemon would be discovered at three in the morning otherwise.
     */
    private function manualSourceForm(): void
    {
        $roots = (array) $this->cfg->get('allowed_log_roots', []);

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_SOURCES) . '" class="card">';
        $this->csrf(Installer::STEP_SOURCES, 'manual');
        echo '<h2>Add a log file by hand</h2>';
        echo '<p>If your logs are somewhere unusual, name the file. It has to be inside '
            . Security::esc(implode(', ', $roots)) . '.</p>';

        echo '<label for="path">Path to the access log</label>';
        echo '<input type="text" id="path" name="path" class="mono" size="48" '
            . 'placeholder="/var/log/apache2/example_com_access.log">';

        echo '<label for="format">Format</label>';
        echo '<select id="format" name="format">';
        foreach (Detector::formatChoices() as $value => $label) {
            echo '<option value="' . Security::esc((string) $value) . '">'
                . Security::esc((string) $label) . '</option>';
        }
        echo '</select>';

        echo '<div id="regex-row" hidden>';
        echo '<label for="regex">Pattern, with named groups</label>';
        echo '<input type="text" id="regex" name="regex" class="mono" size="60" '
            . 'placeholder="/^(?&lt;remote_addr&gt;\S+) \S+ \S+ \[(?&lt;time&gt;[^\]]+)\].*$/">';
        echo '<p class="muted">Checked before it is stored: a pattern that does not compile, or one '
            . 'that backtracks badly enough to stall ingestion, is refused here rather than at '
            . 'three in the morning.</p>';
        echo '</div>';

        echo '<button type="submit">Add this file</button>';
        echo '</form>';
    }

    /**
     * The storage step: managed Opensolr, or a Solr the operator already runs.
     *
     * Presented as two equal panels with the managed one first, because it is the answer
     * for anyone who does not already have Solr — which is most people — and it needs no
     * infrastructure at all.
     */
    private function stepStorage(): void
    {
        $mode = (string) $this->cfg->get('solr.mode', 'opensolr');
        $jobs = (array) ($this->ctx['jobs'] ?? []);

        if (isset($jobs[Job::KIND_OPENSOLR])) {
            $this->jobPanel(Job::KIND_OPENSOLR, (string) $jobs[Job::KIND_OPENSOLR], 'Creating your indexes');
        }
        if (isset($jobs[Job::KIND_SOLRTEST])) {
            $this->jobPanel(Job::KIND_SOLRTEST, (string) $jobs[Job::KIND_SOLRTEST], 'Testing the connection');
        }

        if (!empty(((array) ($this->ctx['progress'] ?? []))[Installer::STEP_STORAGE])) {
            echo '<section class="card">';
            echo '<h2>Storage is configured</h2>';
            echo '<dl class="kv">';
            echo '<dt>Hits index</dt><dd class="mono">'
                . Security::esc((string) $this->cfg->get('solr.hits_core')) . '</dd>';
            echo '<dt>Sessions index</dt><dd class="mono">'
                . Security::esc((string) $this->cfg->get('solr.sessions_core')) . '</dd>';
            echo '<dt>Address</dt><dd class="mono wrap">'
                . Security::esc((string) $this->cfg->get('solr.base_url')) . '</dd>';
            echo '</dl>';
            echo '<p><a class="btn primary" href="?setup=' . Security::esc(Installer::STEP_PRIVACY)
                . '">Continue</a></p>';
            echo '</section>';
        }

        $this->opensolrPanel($mode);
        $this->customSolrPanel($mode);
    }

    /**
     * The managed option.
     *
     * Two phases, because the region list belongs to the account and cannot be known until
     * the credentials are: enter the account details, then choose from the regions the
     * platform actually returned for it. The API key is a password field, is never
     * re-rendered, and is never placed in a hidden field.
     */
    private function opensolrPanel(string $mode): void
    {
        $regions = (array) ($this->ctx['regions'] ?? []);
        $haveKey = (string) $this->cfg->get('opensolr.api_key', '') !== '';
        $email = (string) $this->cfg->get('opensolr.email', '');

        echo '<section class="card storage-option' . ($mode === 'opensolr' ? ' on' : '') . '">';
        echo '<h2>Let Opensolr host it</h2>';
        echo '<p><strong>You do not need to run Solr.</strong> Enter your Opensolr account details '
            . 'and Loghound creates both indexes, uploads their configuration and checks that they '
            . 'answer. Backups, downloads and restores are then available in your Opensolr control '
            . 'panel; you never have to learn what a configset is.</p>';

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '" class="setup-form">';
        $this->csrf(Installer::STEP_STORAGE, 'credentials');

        echo '<label for="email">Opensolr account email</label>';
        echo '<input type="email" id="email" name="email" size="34" autocomplete="off" required '
            . 'value="' . Security::esc($email) . '">';

        echo '<label for="api_key">API key'
            . ($haveKey ? ' <span class="chip chip-good">stored</span>' : '') . '</label>';
        echo '<input type="password" id="api_key" name="api_key" size="34" autocomplete="off" '
            . 'spellcheck="false"' . ($haveKey ? '' : ' required') . '>';
        echo '<p class="muted">In your Opensolr control panel it is under <strong>Account</strong>. '
            . 'It is stored in a file outside the web root that only this server can read, and it is '
            . 'never shown again — not here, not in the dashboard, not in a log.</p>';

        echo '<button type="submit" class="primary">Check these credentials</button>';
        echo '</form>';

        if ($regions !== []) {
            echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '" class="setup-form">';
            $this->csrf(Installer::STEP_STORAGE, 'provision');
            echo '<h3>Where should the indexes live?</h3>';
            echo '<label for="region">Region</label>';
            echo '<select id="region" name="region" required>';
            foreach ($regions as $region) {
                $region = (string) $region;
                echo '<option value="' . Security::esc($region) . '"'
                    . ($region === (string) $this->cfg->get('opensolr.region') ? ' selected' : '') . '>'
                    . Security::esc($region) . '</option>';
            }
            echo '</select>';
            echo '<p class="muted">These are the regions your account can use, as the platform '
                . 'returned them. The two index names are generated for you — an Opensolr index name '
                . 'has to be unique across the whole platform, so a fixed name would collide with '
                . 'someone else\'s.</p>';
            echo '<button type="submit" class="primary">Create my indexes</button>';
            echo '</form>';
        }

        echo '</section>';
    }

    /**
     * A generated core name to pre-fill the form with, or an empty string.
     *
     * Config::coreName() refuses an installation id that is not lowercase hex, which is
     * the correct behaviour for a name that is about to be created on a shared platform.
     * A form default is not worth propagating that as an exception, so a refusal here
     * simply means the field is offered empty and the operator names the cores themselves.
     */
    private static function suggestedCoreName(string $installId, string $role): string
    {
        try {
            return Config::coreName($installId, $role);
        } catch (\InvalidArgumentException $e) {
            return '';
        }
    }

    /**
     * The bring-your-own-Solr option.
     *
     * The password field is empty on every render and an empty value means "keep the
     * stored one", so the form can be re-saved without blanking a working credential and
     * without the password ever travelling back to the browser.
     */
    private function customSolrPanel(string $mode): void
    {
        $installId = (string) $this->cfg->get('solr.install_id', '');
        $hits = (string) $this->cfg->get('solr.hits_core', '');
        $sessions = (string) $this->cfg->get('solr.sessions_core', '');

        if ($hits === '') {
            $hits = self::suggestedCoreName($installId, 'hits');
        }
        if ($sessions === '') {
            $sessions = self::suggestedCoreName($installId, 'sessions');
        }

        echo '<section class="card storage-option' . ($mode === 'custom' ? ' on' : '') . '">';
        echo '<h2>Use a Solr you already run</h2>';
        echo '<p>Solr 9 or newer. Loghound needs two cores; create them with the configuration '
            . 'in <code>solr/hits/conf</code> and <code>solr/sessions/conf</code> from this checkout, '
            . 'then give the details here.</p>';

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '" class="setup-form">';
        $this->csrf(Installer::STEP_STORAGE, 'custom');

        echo '<label for="base_url">Solr address</label>';
        echo '<input type="url" id="base_url" name="base_url" class="mono" size="40" required '
            . 'placeholder="http://127.0.0.1:8983/solr" value="'
            . Security::esc((string) $this->cfg->get('solr.base_url', '')) . '">';

        echo '<label for="http_user">Username <span class="muted">(if it needs one)</span></label>';
        echo '<input type="text" id="http_user" name="http_user" size="24" autocomplete="off" value="'
            . Security::esc((string) $this->cfg->get('solr.http_user', '')) . '">';

        echo '<label for="http_pass">Password'
            . ((string) $this->cfg->get('solr.http_pass', '') !== ''
                ? ' <span class="chip chip-good">stored</span>' : '') . '</label>';
        echo '<input type="password" id="http_pass" name="http_pass" size="24" autocomplete="off">';

        echo '<label for="hits_core">Core for hits</label>';
        echo '<input type="text" id="hits_core" name="hits_core" class="mono" size="30" required value="'
            . Security::esc($hits) . '">';

        echo '<label for="sessions_core">Core for sessions</label>';
        echo '<input type="text" id="sessions_core" name="sessions_core" class="mono" size="30" required value="'
            . Security::esc($sessions) . '">';

        echo '<button type="submit" class="primary">Save and test the connection</button>';
        echo '</form>';
        echo '</section>';
    }

    /**
     * The privacy step.
     *
     * Each mode gets a plain sentence for what it does and a plain sentence for what it
     * costs, because an operator choosing what to keep about their visitors deserves both
     * halves of the trade rather than the flattering one.
     */
    private function stepPrivacy(): void
    {
        $current = (string) $this->cfg->get('privacy.ip_mode', 'full');
        $days = (int) $this->cfg->get('privacy.retention_days', 90);

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_PRIVACY) . '" class="card">';
        $this->csrf(Installer::STEP_PRIVACY, 'save');

        echo '<h2>Visitor addresses</h2>';
        echo '<fieldset>';
        echo '<legend>How should an IP address be stored?</legend>';
        foreach (Steps::ipModes() as $key => $mode) {
            echo '<label class="radio"><input type="radio" name="ip_mode" value="' . Security::esc((string) $key) . '"'
                . ($key === $current ? ' checked' : '') . '>';
            echo '<span><strong>' . Security::esc($mode['label']) . '</strong><br>'
                . Security::esc($mode['text'])
                . '<br><span class="muted">' . Security::esc($mode['cost']) . '</span></span></label>';
        }
        echo '</fieldset>';

        echo '<h2>How long to keep it</h2>';
        echo '<label for="retention_days">Delete hits older than</label>';
        echo '<input type="number" id="retention_days" name="retention_days" min="0" max="3650" value="'
            . $days . '"> <span class="muted">days — 0 keeps everything for ever. '
            . 'A timer job does the deleting; this is not a promise in the documentation.</span>';

        echo '<p><button type="submit" class="primary">Save and continue</button></p>';
        echo '</form>';
    }

    /**
     * The last step: the account, the public URL, and what happens next.
     *
     * The next-step commands are shown BEFORE finishing, not after, because finishing
     * hands the operator to the dashboard and this page will not exist any more.
     */
    private function stepAdmin(): void
    {
        $guessed = rtrim((string) $this->cfg->get('base_url', ''), '/');
        if ($guessed === '') {
            $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
            $scheme = (($_SERVER['HTTPS'] ?? '') !== '') ? 'https' : 'http';
            $guessed = $host === '' ? '' : $scheme . '://' . $host;
        }

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_ADMIN) . '" class="card">';
        $this->csrf(Installer::STEP_ADMIN, 'finish');

        echo '<h2>Your sign-in</h2>';
        echo '<p>Loghound shows every visitor, page and address on your site, so it is never served '
            . 'without a password.</p>';

        echo '<label for="user">Username</label>';
        echo '<input type="text" id="user" name="user" size="24" autocomplete="username" required value="'
            . Security::esc((string) $this->cfg->get('auth.user', 'admin')) . '">';

        echo '<label for="password">Password</label>';
        echo '<input type="password" id="password" name="password" size="24" '
            . 'autocomplete="new-password" minlength="' . Steps::MIN_PASSWORD . '" required>';

        echo '<label for="password2">Password again</label>';
        echo '<input type="password" id="password2" name="password2" size="24" '
            . 'autocomplete="new-password" minlength="' . Steps::MIN_PASSWORD . '" required>';
        echo '<p class="muted">At least ' . Steps::MIN_PASSWORD . ' characters. Stored as a hash; '
            . 'nobody, including this page, can read it back.</p>';

        echo '<h2>Address of this panel</h2>';
        echo '<label for="base_url">Public URL</label>';
        echo '<input type="url" id="base_url" name="base_url" class="mono" size="40" value="'
            . Security::esc($guessed) . '">';
        echo '<p class="muted">Used to build the one-line beacon snippet you add to your site.</p>';

        echo '<button type="submit" class="primary">Finish and open the dashboard</button>';
        echo '<p class="muted">Your browser will ask for the username and password you just chose — '
            . 'that is Loghound asking you to sign in for the first time.</p>';
        echo '</form>';

        $this->nextStepsCard();
    }

    /** The commands to run on the server once setup is done. */
    private function nextStepsCard(): void
    {
        echo '<section class="card">';
        echo '<h2>After you finish</h2>';
        echo '<p>Loghound reads logs from a small daemon, not from this page. Copy these now — '
            . 'this screen goes away when setup completes.</p>';

        foreach (Steps::nextSteps($this->cfg, $this->root) as $group) {
            echo '<h4>' . Security::esc($group['title']) . '</h4>';
            echo '<pre class="snippet mono">';
            foreach ($group['lines'] as $line) {
                echo Security::esc($line) . "\n";
            }
            echo '</pre>';
        }

        echo '<p class="muted">' . Security::esc(Steps::beaconRationale()) . '</p>';
        echo '</section>';
    }

    /**
     * The progress panel for a running job.
     *
     * Rendered server-side from the job's state on disk, so a reload mid-provision shows
     * where it got to rather than an empty box, and then kept live by setup.js. The markup
     * is the panel's own job vocabulary (.job / .progress / .job-steps), so a long
     * operation looks identical here and in Settings.
     *
     * The panel carries no secret: step names, human progress lines and index names only.
     */
    private function jobPanel(string $kind, string $id, string $title): void
    {
        $job = Job::load($this->root . '/var/setup', $id);
        if ($job === null) {
            return;
        }
        $status = $job->status($this->cfg, $this->root);
        $running = (string) $status['state'] === 'running';

        echo '<section class="job" data-job-id="' . Security::esc($id) . '" '
            . 'data-job-kind="' . Security::esc($kind) . '" '
            . 'data-job-state="' . Security::esc((string) $status['state']) . '">';

        echo '<div class="job-head">';
        echo '<span class="job-title">' . Security::esc($title) . '</span>';
        echo '<span class="job-meta">' . Security::esc($this->jobMeta($status)) . '</span>';
        echo '</div>';

        echo '<span class="progress"><span class="progress-fill" style="width:'
            . (int) $status['percent'] . '%"></span></span>';

        echo '<div class="loading"><span class="loading-label">'
            . Security::esc($this->latestNote($status)) . '</span>'
            . '<span class="loading-elapsed">' . ($running ? (int) $status['elapsed'] . 's' : '') . '</span></div>';

        echo '<ul class="job-steps">';
        foreach ((array) $status['steps'] as $step) {
            $this->jobStep((array) $step);
        }
        echo '</ul>';

        echo '<div class="job-actions">';
        if ((string) $status['state'] === 'error') {
            echo '<form method="post" action="?setup=' . Security::esc($this->stepFor($kind)) . '">';
            $this->csrf($this->stepFor($kind), $kind === Job::KIND_DETECT ? 'detect' : 'provision');
            if ($kind === Job::KIND_OPENSOLR) {
                echo '<input type="hidden" name="region" value="'
                    . Security::esc((string) $this->cfg->get('opensolr.region', '')) . '">';
            }
            echo '<button type="submit">Try again</button>';
            echo '</form>';
        }
        echo '</div>';

        if ((string) $status['state'] === 'error') {
            echo '<div class="banner banner-bad" role="alert">'
                . Security::esc((string) $status['error']) . '</div>';
        }

        echo '<noscript><p class="muted">This step reports progress with JavaScript. Without it, '
            . 'run <code>' . Security::esc($this->req->cliCommand()) . '</code> in a shell instead — '
            . 'it does exactly the same work.</p></noscript>';

        echo '</section>';
    }

    /**
     * One step of a job, in the shared three-column row.
     *
     * @param array<string,mixed> $step
     */
    private function jobStep(array $step): void
    {
        $state = (string) ($step['state'] ?? 'pending');
        $marks = ['done' => "\u{2713}", 'error' => "\u{2717}", 'running' => "\u{2192}", 'pending' => "\u{00b7}"];
        $mark = $marks[$state] ?? $marks['pending'];
        $class = $state === 'error' ? 'job-step-failed' : 'job-step-' . $state;

        echo '<li class="' . Security::esc($class) . '" data-step="' . Security::esc((string) $step['key']) . '">';
        echo '<span class="job-mark" aria-hidden="true">' . Security::esc($mark) . '</span>';
        echo '<span class="job-step-label">' . Security::esc((string) $step['label']) . '</span>';
        echo '<span class="job-step-note">' . Security::esc($state === 'pending' ? '' : $state) . '</span>';
        echo '<span class="job-step-detail">' . Security::esc((string) ($step['detail'] ?? '')) . '</span>';
        echo '</li>';
    }

    /**
     * The "step 3 of 8 · 12s" line.
     *
     * @param array<string,mixed> $status
     */
    private function jobMeta(array $status): string
    {
        if ((string) $status['state'] === 'running') {
            return 'step ' . min((int) $status['complete'] + 1, (int) $status['total'])
                . ' of ' . (int) $status['total'] . " \u{00b7} " . (int) $status['elapsed'] . 's';
        }
        return (string) $status['state'] . " \u{00b7} " . (int) $status['elapsed'] . 's';
    }

    /**
     * The most recent progress line, which is what a human watches during a slow step.
     *
     * @param array<string,mixed> $status
     */
    private function latestNote(array $status): string
    {
        $notes = (array) ($status['notes'] ?? []);
        return $notes === [] ? '' : (string) end($notes);
    }

    /** Which step a job of this kind is shown on. */
    private function stepFor(string $kind): string
    {
        return $kind === Job::KIND_DETECT ? Installer::STEP_SOURCES : Installer::STEP_STORAGE;
    }

    /** The closing note, and the escape hatch to the shell wizard. */
    private function footer(): void
    {
        echo '<footer class="foot">';
        echo '<span>Loghound setup</span>';
        echo '<span class="mono">' . Security::esc(gmdate('m/d/Y H:i:s')) . ' UTC</span>';
        echo '</footer>' . "\n";
    }
}
