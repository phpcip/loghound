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

use Loghound\Assets;
use Loghound\Config;
use Loghound\Security;

final class View
{
    /**
     * Where an operator without an account goes next.
     *
     * The storage step is the first point at which Loghound asks for something the operator
     * may not have yet, and "an Opensolr account is required" with no way to get one is a
     * dead end in the middle of an installation.
     *
     * The addresses themselves live on Setup\Storage, which is the class both front ends
     * share, so the shell wizard and this screen cannot send an operator to two different
     * pages for the same thing. They are re-exported here only because this file reads better
     * with short names in the markup.
     */
    private const URL_REGISTER = Storage::URL_REGISTER;

    /** Sign-in, for an operator who already has an account and needs the API key. */
    private const URL_LOGIN = Storage::URL_LOGIN;

    /** What each plan holds, since retention is sized to it. */
    private const URL_PLANS = Storage::URL_PLANS;

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

        $asset = fn (string $rel): string => Assets::url($rel, $this->root);

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n<head>\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>Set up Loghound</title>' . "\n";
        echo '<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">' . "\n";
        echo '<meta name="theme-color" content="#111111" media="(prefers-color-scheme: dark)">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/panel.css')) . '">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/mobile.css')) . '">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.svg')) . '" type="image/svg+xml">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.ico')) . '" sizes="any">' . "\n";
        echo '<link rel="apple-touch-icon" href="' . Security::esc($asset('apple-touch-icon.png')) . '">' . "\n";
        echo '<script src="' . Security::esc($asset('assets/js/theme.js')) . '"></script>' . "\n";
        echo Assets::importMapTag($this->root) . "\n";
        echo '<script type="module" src="' . Security::esc($asset('assets/js/responsive.js')) . '"></script>' . "\n";
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
        $this->bounce();

        switch ($step) {
            case Installer::STEP_SOURCES:
                $this->stepSources();
                break;
            case Installer::STEP_STORAGE:
                $this->stepStorage();
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
            Installer::STEP_STORAGE => ['Where should the index live?', 'Loghound keeps what it learns in two Solr indexes that it creates and manages for you on your Opensolr account.'],
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
     * controller refuses them anyway — saying which prerequisite is missing when it does.
     *
     * The names come from Installer::LABELS rather than from a copy kept here, so the rail
     * and any sentence that has to refer to a step cannot call it two different things.
     */
    private function rail(string $current): void
    {
        $progress = (array) ($this->ctx['progress'] ?? []);
        $unlocked = !empty($this->ctx['unlocked']);

        echo '<ol class="setup-rail">' . "\n";

        $done = $current !== Installer::STEP_STATUS;
        echo '<li class="' . ($current === Installer::STEP_STATUS ? 'on' : ($done ? 'done' : '')) . '">'
            . '<a href="?setup=' . Security::esc(Installer::STEP_STATUS) . '">'
            . Security::esc(Installer::stepLabel(Installer::STEP_STATUS)) . '</a></li>';

        foreach (Installer::ORDER as $i => $step) {
            $classes = [];
            if ($step === $current) {
                $classes[] = 'on';
            }
            if (!empty($progress[$step])) {
                $classes[] = 'done';
            }
            $label = ($i + 1) . '. ' . Installer::stepLabel($step);

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

    /**
     * The one-shot message from the previous request, if there is one.
     *
     * Three severities, matching Installer::flash(). 'warn' exists so a step that stored six
     * of seven log sources can say so in one banner without either claiming plain success or
     * shouting failure at an operator whose installation is in fact moving forward.
     */
    private function flash(): void
    {
        $flash = $this->ctx['flash'] ?? null;
        if (!is_array($flash)) {
            return;
        }
        $kind = (string) ($flash['kind'] ?? 'error');
        $class = ['ok' => 'banner-good', 'warn' => 'banner-warn'][$kind] ?? 'banner-bad';
        echo '<div class="banner ' . $class . '" role="' . ($kind === 'error' ? 'alert' : 'status') . '">'
            . Security::esc((string) $flash['text']) . "</div>\n";
    }

    /**
     * Why this is not the screen that was asked for.
     *
     * Its own banner rather than the flash, because a bounce and a flash are different things
     * and can happen at once: the flash is the outcome of something the operator just did,
     * this is the reason the page in front of them is not the one they clicked towards.
     * Rendered as a status rather than an alert — being sent to the right screen is not an
     * error, it only used to LOOK like nothing happening, which is the defect this repairs.
     */
    private function bounce(): void
    {
        $why = (string) ($this->ctx['bounced'] ?? '');
        if ($why === '') {
            return;
        }
        echo '<div class="banner banner-warn" role="status">' . Security::esc($why) . "</div>\n";
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
            echo '<p>Nothing has been configured yet. This takes three short steps: which log '
                . 'files to read, where to keep the index, and the password you will sign in '
                . 'with.</p>';
        }

        if ($missing !== []) {
            echo '<ul class="setup-missing">';
            foreach ($missing as $item) {
                echo '<li>' . Security::esc($item['text']) . $this->missingLink($item) . '</li>';
            }
            echo '</ul>';
        }
        echo '</section>';

        $this->unlockPanel($blocked);
        $this->checksTable($rows);
        $this->storagePanel();
    }

    /**
     * The link that ends one line of the missing-list, or nothing at all.
     *
     * THREE STATES, and two of them used to be rendered as the same dead "Fix this".
     *
     *  - **Not actionable.** The signing key line says, in its own sentence, that finishing
     *    setup generates the key. There is nothing for the operator to go and do, so offering
     *    a link to do it is an instruction that contradicts the sentence beside it.
     *  - **Locked.** Every `?setup=<step>` is clamped to the status page until this browser
     *    has unlocked setup, so a "Fix this" here returned a byte-identical page. Three of the
     *    four links on the first screen anybody sees did nothing at all. They now go to the
     *    unlock panel further down the same page and say what they are for.
     *  - **Unlocked and actionable.** The link the label always promised.
     *
     * @param array{step:string,text:string,actionable:bool} $item
     */
    private function missingLink(array $item): string
    {
        if (empty($item['actionable'])) {
            return '';
        }
        if (empty($this->ctx['unlocked'])) {
            return ' <a href="#unlock">Unlock setup first</a>';
        }
        return ' <a href="?setup=' . Security::esc((string) $item['step']) . '">Fix this</a>';
    }

    /**
     * The token gate.
     *
     * Says which file to read and the exact command that prints it. Without this an
     * installer on a live URL would let whoever found it first point Loghound at a Solr
     * they control and set the password.
     *
     * Carries `id="unlock"`, because the missing-list above it links here while setup is
     * locked and a link has to land somewhere.
     */
    private function unlockPanel(bool $blocked): void
    {
        if (!empty($this->ctx['unlocked'])) {
            echo '<section class="card" id="unlock">';
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

        echo '<section class="card" id="unlock">';
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
     *
     * There is no "mode" row any more. There is one storage backend, so a field that always
     * said the same word was noise; what an operator needs from this panel is the two index
     * names and whether they answer.
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
     *
     * THE TWO TICK BOXES ARE NOT THE SAME KIND OF QUESTION AND MUST NOT BE MERGED.
     *
     *  - `pick[]` asks "ingest this file?", and every discovered source arrives ticked. The
     *    operator ran a scan in order to ingest what it finds; the review is there so they
     *    can untick what looks wrong, not so they can re-select what they just asked for. It
     *    used to be ticked only for sources inside `allowed_log_roots`, so a file the
     *    operator's own webserver config pointed at came up unticked, and clicking straight
     *    through a screen that looked complete silently ingested nothing from it.
     *  - `widen[]` asks "may Loghound read outside the directories it is allowed to read?",
     *    and is NEVER pre-ticked. It is the security control that bounds the log-path
     *    setting away from being an arbitrary-file-read, and a widening nobody consciously
     *    agreed to is precisely what it exists to prevent. Pre-ticking it would grant, by
     *    default, the permission it was added to withhold.
     *
     * Ticking `pick[]` for an outside-root source without ticking `widen[]` is therefore a
     * refusal, not a bug: Steps::applySourcesReport() stores everything else and names that
     * file and its reason.
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
            echo '<p>Everything found is ticked. Untick anything whose parsed lines above look wrong, '
                . 'then confirm. You can change this later in Settings.</p>';
            foreach ($sources as $i => $src) {
                $path = (string) ($src['path'] ?? '');
                echo '<label class="check"><input type="checkbox" name="pick[]" value="' . (int) $i . '" checked>'
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
     * The storage step: provisioning the two indexes on Opensolr.
     *
     * This screen used to be a fork, with a second panel for pointing Loghound at a Solr the
     * operator already ran. That option was removed: Loghound creates its two indexes, uploads
     * their configsets and reloads them, and it can do none of that on a Solr it does not
     * administer. One flow, no choice to get wrong.
     */
    private function stepStorage(): void
    {
        $jobs = (array) ($this->ctx['jobs'] ?? []);

        if (isset($jobs[Job::KIND_OPENSOLR])) {
            $this->jobPanel(Job::KIND_OPENSOLR, (string) $jobs[Job::KIND_OPENSOLR], 'Creating your indexes');
        }
        if (isset($jobs[Job::KIND_REUSE])) {
            $this->jobPanel(Job::KIND_REUSE, (string) $jobs[Job::KIND_REUSE], 'Joining your existing indexes');
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
            echo '<p><a class="btn primary" href="?setup=' . Security::esc(Installer::STEP_ADMIN)
                . '">Continue</a></p>';
            echo '</section>';

            echo '<details class="card">';
            echo '<summary>Point this installation at different indexes</summary>';
            echo '<p class="muted">The two indexes above already exist and answer, so normally '
                . 'there is nothing to do here — carry on with Continue. Opening this shows the '
                . 'same one-choice list as a fresh install: any pair your account already holds, '
                . 'which creates nothing, or a new pair under a fresh name. Picking a new pair '
                . 'leaves the current two on your account, where they keep counting against your '
                . 'plan until you delete them.</p>';
            $this->opensolrPanel();
            echo '</details>';

            return;
        }

        $this->opensolrPanel();
    }

    /**
     * STEP ONE on Opensolr — the only path to storage there is.
     *
     * TWO STEPS, NEVER ONE. This form is the whole of the first: the account email and the API
     * key, checked and saved on their own. It asks nothing about indexes, because the operator is
     * saying which account to use and has not yet said anything about where their traffic lands.
     * Which indexes to use is the panel below, and it only exists once there is an account to
     * read. The API key is a password field, is never re-rendered, and is never placed in a
     * hidden field.
     *
     * The two panels below the form have nothing to say until the account has been read, so the
     * method returns before them. Until credentials are entered the snapshot is a BLANK one
     * rather than a failed one, and rendering it anyway opened the screen with an empty red
     * banner reporting a failure that had not happened.
     */
    private function opensolrPanel(): void
    {
        $regions = (array) ($this->ctx['regions'] ?? []);
        $haveKey = (string) $this->cfg->get('opensolr.api_key', '') !== '';
        $email = (string) $this->cfg->get('opensolr.email', '');

        echo '<section class="card storage-option on">';
        echo '<h2>Let Opensolr host it</h2>';
        echo '<p><strong>You do not need to run Solr.</strong> Enter your Opensolr account details '
            . 'and Loghound creates both indexes, uploads their configuration and checks that they '
            . 'answer. Backups, downloads and restores are then available in your Opensolr control '
            . 'panel; you never have to learn what a configset is.</p>';
        echo '<p class="muted">An Opensolr account is required. Loghound provisions and manages its '
            . 'own two indexes — creating them, uploading their configsets and reloading them — and '
            . 'it cannot do that on a Solr it does not administer, so there is no option to point it '
            . 'at one.</p>';

        echo '<p class="muted"><strong>You need an Opensolr account to get started, and it is free '
            . 'forever to start — no credit card, no expiry date.</strong> Retention scales with the '
            . 'plan rather than being cut off by it: Loghound trims its oldest data before the account '
            . 'reaches its disk limit, so the free tier keeps running and simply holds less history.</p>';

        echo '<p class="muted">'
            . '<a href="' . Security::safeUrl(self::URL_REGISTER) . '" target="_blank" rel="noopener noreferrer">Create a free account</a> &middot; '
            . '<a href="' . Security::safeUrl(self::URL_LOGIN) . '" target="_blank" rel="noopener noreferrer">Sign in</a> &middot; '
            . '<a href="' . Security::safeUrl(self::URL_PLANS) . '" target="_blank" rel="noopener noreferrer">What the plans hold</a>'
            . '</p>';

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

        echo '</section>';

        $account = (array) ($this->ctx['account'] ?? []);
        if (empty($account['ok']) && (string) ($account['error'] ?? '') === '') {
            return;
        }

        $this->accountPanel($account);
        $this->indexChoicePanel($account, $regions);
    }

    /**
     * What this account holds and whether the plan has room, before anything is created.
     *
     * THE NUMBERS COME FIRST, on their own, above both of the choices they bear on. An
     * operator about to pick "create a new pair" has to know the plan is full BEFORE they
     * press it, not after — and an operator whose plan is full has to be able to see that the
     * reason the reuse list matters is sitting right above it.
     *
     * A read that failed is reported as a failed read. It is not rendered as an account with
     * nothing in it, because "you have no Loghound indexes" and "we could not ask" lead to
     * opposite decisions.
     *
     * WHAT IS NOT HERE ANY MORE: the unmatched halves and the ways out of a full plan. Both are
     * things the operator needs while they are looking at the list they have to pick from, so
     * both moved into step two, which is the panel below.
     *
     * @param array<string,mixed> $account
     */
    private function accountPanel(array $account): void
    {
        $capacity = (array) ($account['capacity'] ?? []);
        $blocked  = !empty($capacity['blocked']);
        $failed   = empty($account['ok']);

        echo '<section class="card">';
        echo '<h2>Your Opensolr account</h2>';

        if ($failed) {
            echo '<div class="banner banner-bad" role="alert">'
                . Security::esc((string) ($account['error'] ?? '')) . '</div>';
        } elseif ($blocked) {
            echo '<div class="banner banner-bad" role="alert">'
                . Security::esc((string) ($capacity['sentence'] ?? '')) . '</div>';
        } else {
            echo '<p>' . Security::esc((string) ($capacity['sentence'] ?? '')) . '</p>';
        }

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '" class="setup-form">';
        $this->csrf(Installer::STEP_STORAGE, 'refresh');
        echo '<button type="submit">Check the account again</button>';
        echo '</form>';
        echo '</section>';
    }

    /**
     * STEP TWO: the pairs this account holds, plus the option to make a new one, as one choice.
     *
     * WHY ONE LIST AND NOT TWO PANELS. Joining an existing pair and creating a new one are the
     * alternatives to a single question — which indexes does this installation use — and they
     * used to be two cards with two forms and two buttons, which reads as two offers rather than
     * one decision. Now the operator picks one row and confirms. A single pair is a row like any
     * other: they have said which account to use and have not yet said anything about indexes,
     * so adopting the only pair on their behalf would be Loghound choosing where their traffic
     * lands and calling it a convenience.
     *
     * ONE PAIR CAN SERVE MANY SITES, which is why joining is offered at all. Every document
     * Loghound writes carries the virtual host it came from, so six installations reporting into
     * one pair stay separable in the panel by its Virtual host dimension — and an operator with
     * six sites wants two indexes and six hostnames, not twelve indexes. On a plan with a small
     * index limit it is the only way the sixth machine gets set up at all.
     *
     * An unmatched half is listed as the leftover it is and is not selectable, because half a
     * pair is not somewhere Loghound can work. The provision option is withheld when the plan is
     * known to be full: a control that cannot succeed is not shown as a control, and pressing
     * "create" to watch a job fail on its second step is the experience this screen replaces.
     *
     * Every sentence comes from Pairs::decide(), which is what the Settings card and both shell
     * paths render too.
     *
     * @param array<string,mixed> $account
     * @param array<int,mixed>    $regions
     */
    private function indexChoicePanel(array $account, array $regions): void
    {
        $step = Pairs::decide($this->cfg, $account);

        echo '<section class="card storage-option on">';
        echo '<h2>' . Security::esc($step['heading']) . '</h2>';

        if (!$step['ok']) {
            echo '<p class="muted">' . Security::esc($step['error']) . '</p>';
            echo '</section>';
            return;
        }

        if ($step['dead_end'] !== '') {
            echo '<div class="banner banner-bad" role="alert">'
                . Security::esc($step['dead_end']) . '</div>';
            echo '<p>' . Security::esc($step['ways_heading']) . '</p><ul>';
            foreach ($step['ways'] as $way) {
                echo '<li>' . Security::esc($way['text']);
                if ($way['url'] !== '') {
                    echo ' <a href="' . Security::safeUrl($way['url'])
                        . '" target="_blank" rel="noopener noreferrer">Open your Opensolr account</a>';
                }
                echo '</li>';
            }
            echo '</ul></section>';
            return;
        }

        echo '<p>' . Security::esc($step['intro']) . '</p>';

        foreach ($step['halves'] as $notice) {
            echo '<p class="muted">' . Security::esc($notice) . '</p>';
        }

        echo '<form method="post" action="?setup=' . Security::esc(Installer::STEP_STORAGE) . '" class="setup-form">';
        $this->csrf(Installer::STEP_STORAGE, 'indexes');

        $first = true;
        foreach ($step['pairs'] as $pair) {
            echo '<label class="radio">';
            echo '<input type="radio" name="install_id" value="' . Security::esc($pair['install_id']) . '"'
                . ($first ? ' checked' : '') . ' required>';
            echo '<span><span class="mono">' . Security::esc($pair['hits']) . '</span><br>'
                . '<span class="mono">' . Security::esc($pair['sessions']) . '</span>'
                . ($pair['current'] ? ' <span class="chip chip-good">already in use here</span>' : '')
                . '</span>';
            echo '</label>';
            $first = false;
        }

        if ($step['can_new'] && $regions !== []) {
            echo '<label class="radio">';
            echo '<input type="radio" name="install_id" value="' . Security::esc(Pairs::CHOICE_NEW) . '"'
                . ($first ? ' checked' : '') . ' required>';
            echo '<span>' . Security::esc($step['new_label']) . '</span>';
            echo '</label>';

            echo '<label for="region">Region for a new pair</label>';
            echo '<select id="region" name="region">';
            foreach ($regions as $region) {
                $region = (string) $region;
                echo '<option value="' . Security::esc($region) . '"'
                    . ($region === (string) $this->cfg->get('opensolr.region') ? ' selected' : '') . '>'
                    . Security::esc($region) . '</option>';
            }
            echo '</select>';
            echo '<p class="muted">' . Security::esc($step['new_detail'])
                . ' These are the regions your account can use, as the platform returned them.</p>';
        } elseif ($step['new_blocked'] !== '') {
            echo '<p class="muted">' . Security::esc($step['new_blocked']) . '</p>';
        }

        if ($step['pairs'] !== []) {
            echo '<p class="muted">' . Security::esc($step['consequence']) . '</p>';
            echo '<label class="check"><input type="checkbox" name="upgrade_schema" value="1"> '
                . 'If the pair you pick was made by an older Loghound, add the fields this version '
                . 'writes</label>';
            echo '<p class="muted">Left unticked, the shape is checked first and nothing changes if it '
                . 'does not match. Ticked, the missing fields are added, which only ever adds and does '
                . 'not alter or remove a single document already in there.</p>';
        }

        echo '<button type="submit" class="primary">Use these indexes</button>';
        echo '</form>';
        echo '</section>';
    }

    /**
     * The last step: the account, the public URL, and what happens next.
     *
     * The next-step commands are shown BEFORE finishing, not after, because finishing
     * hands the operator to the dashboard and this page will not exist any more.
     */
    private function stepAdmin(): void
    {
        $guessed = Steps::effectiveBaseUrl($this->cfg, true);

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

        $this->authModeChoice();

        echo '<h2>Address of this panel</h2>';
        echo '<label for="base_url">Public URL</label>';
        echo '<input type="url" id="base_url" name="base_url" class="mono" size="40" value="'
            . Security::esc($guessed) . '">';
        echo '<p class="muted">Used to build the one-line beacon snippet you add to your site.</p>';

        echo '<button type="submit" class="primary">Finish and open the dashboard</button>';
        echo '<p class="muted">Loghound will then ask you to sign in for the first time, with the '
            . 'username and password you just chose — either through your browser\'s own prompt or '
            . 'through its sign-in page, depending on which you picked above.</p>';
        echo '</form>';

        $this->nextStepsCard();
    }

    /**
     * How the operator wants to sign in, as a real choice rather than a default.
     *
     * Both options are shown with what they cost, not only what they give: Basic cannot be
     * styled and has no sign-out, and the sign-in page cannot be used by curl or by a
     * monitoring check. Neither of those is discoverable after the fact without an
     * afternoon of confusion, and this is the one screen where saying so is cheap.
     *
     * The choice is changeable afterwards, and the text says so, because an operator who
     * believes a decision is permanent will stall on it.
     */
    private function authModeChoice(): void
    {
        $current = (string) $this->cfg->get('auth.mode', 'basic');
        if (!array_key_exists($current, Steps::authModes())) {
            $current = 'basic';
        }

        echo '<h2>How you sign in</h2>';
        echo '<fieldset>';
        echo '<legend>Which sign-in should Loghound use?</legend>';

        foreach (Steps::authModes() as $key => $mode) {
            echo '<label class="radio"><input type="radio" name="auth_mode" value="'
                . Security::esc((string) $key) . '"' . ($key === $current ? ' checked' : '') . '>';
            echo '<span><strong>' . Security::esc($mode['label']) . '</strong><br>'
                . Security::esc($mode['text'])
                . '<br><span class="muted">' . Security::esc($mode['cost']) . '</span></span></label>';
        }

        echo '</fieldset>';
        echo '<p class="muted">You can change this later under Settings without setting the password '
            . 'again.</p>';
    }

    /**
     * The commands to run on the server once setup is done.
     *
     * The same Steps::nextSteps() the panel renders under Settings, so this screen and that
     * card cannot drift. It no longer claims to be the operator's only chance to read them:
     * closing this tab used to lose the one thing that makes Loghound collect anything.
     */
    private function nextStepsCard(): void
    {
        echo '<section class="card">';
        echo '<h2>After you finish</h2>';
        echo '<p>Loghound reads logs from a small daemon, not from this page. These commands are kept '
            . 'under <strong>Settings</strong> in the panel as well, together with whether each one has '
            . 'actually taken effect, so nothing here is lost when this screen goes away.</p>';

        foreach (Steps::nextSteps($this->cfg, $this->root, true) as $group) {
            echo '<h4>' . Security::esc($group['title']) . '</h4>';
            self::commandBlock('finish-cmd-' . (string) $group['key'], $group);
        }

        echo '<p class="muted">' . Security::esc(Steps::beaconRationale()) . '</p>';
        echo '<p class="muted">' . Security::esc(Steps::beaconIdentityNote()) . '</p>';
        echo '</section>';
    }

    /**
     * One pasteable command, with the copy control the panel uses for the same thing.
     *
     * The button is a real element with a `data-copy` attribute and no handler on it: the
     * CSP is `script-src 'self'`, so the listener is attached by
     * public/assets/js/copy.js, which the panel imports as well. A group that has a
     * `problem` instead of a command renders the sentence and NO button — a copy control
     * over an empty block would hand the operator an empty clipboard.
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
     * The progress panel for a running job.
     *
     * Rendered server-side from the job's state on disk, so a reload mid-provision shows
     * where it got to rather than an empty box, and then kept live by setup.js. The markup
     * is the panel's own job vocabulary (.job / .progress / .job-steps), so a long
     * operation looks identical here and in Settings.
     *
     * The panel carries no secret: step names, human progress lines and index names only.
     *
     * "TRY AGAIN" RE-RUNS THE SAME KIND OF WORK, which is why the action posted is chosen from
     * the job's kind rather than being 'provision' for everything that is not detection.
     * Posting 'provision' for a failed REUSE job would quietly turn "join the indexes I picked"
     * into "create two more" — the one thing an operator reusing a pair is trying to avoid, and
     * on a full plan something that could only fail a second time. The chosen pair travels with
     * the retry for the same reason: without it there is nothing to adopt.
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
            $action = [
                Job::KIND_DETECT   => 'detect',
                Job::KIND_REUSE    => 'reuse',
                Job::KIND_SOLRTEST => 'test',
            ][$kind] ?? 'provision';

            echo '<form method="post" action="?setup=' . Security::esc($this->stepFor($kind)) . '">';
            $this->csrf($this->stepFor($kind), $action);
            if ($kind === Job::KIND_OPENSOLR) {
                echo '<input type="hidden" name="region" value="'
                    . Security::esc((string) $this->cfg->get('opensolr.region', '')) . '">';
            }
            if ($kind === Job::KIND_REUSE) {
                $params = $job->params();
                echo '<input type="hidden" name="install_id" value="'
                    . Security::esc((string) ($params['install_id'] ?? '')) . '">';
                if (!empty($params['upgrade_schema'])) {
                    echo '<input type="hidden" name="upgrade_schema" value="1">';
                }
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
