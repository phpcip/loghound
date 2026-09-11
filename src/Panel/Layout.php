<?php
/**
 * Loghound — the panel's HTML chrome.
 *
 * One place that emits <head>, the navigation, the range picker, the banners and the
 * script tags, so that a view file contains nothing but its own content.
 *
 * Two constraints shape this file:
 *
 *  - **The CSP has no 'unsafe-inline' for scripts.** There is therefore no inline
 *    <script>, no `onclick=`, no `javascript:` href anywhere in the panel. The theme
 *    bootstrap — normally the one place people cheat, because a themed page flashes
 *    white otherwise — is an external synchronous script in <head> instead.
 *  - **Nothing log-derived is rendered by PHP.** Values from Solr reach the page as JSON
 *    over fetch() and are placed in the DOM with textContent. The only PHP-rendered
 *    dynamic values here are config strings the operator typed themselves, and they still
 *    go through Security::esc().
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\Security;
use Loghound\Setup\Steps;

final class Layout
{
    /**
     * The navigation, in the order SPEC §10 lists the views.
     *
     * @return array<int,array{slug:string,label:string,hint:string}>
     */
    public static function nav(): array
    {
        return [
            ['slug' => 'overview',     'label' => 'Overview',     'hint' => 'Who came, and how long they really stayed'],
            ['slug' => 'bots',         'label' => 'Bot forensics','hint' => 'Why each verdict was reached'],
            ['slug' => 'fingerprints', 'label' => 'Fingerprints', 'hint' => 'One header signature, many IPs'],
            ['slug' => 'networks',     'label' => 'Networks',     'hint' => 'ASN, netname and geography'],
            ['slug' => 'sessions',     'label' => 'Sessions',     'hint' => 'Search and drill into one visit'],
            ['slug' => 'performance',  'label' => 'Performance',  'hint' => 'Latency percentiles and status codes'],
            ['slug' => 'hosts',        'label' => 'Virtual hosts','hint' => 'Every site on this machine, side by side'],
            ['slug' => 'indexes',      'label' => 'Index analytics', 'hint' => 'What your Opensolr search indexes are being asked'],
            ['slug' => 'queries',      'label' => 'Query analysis',  'hint' => 'Query shapes, and which of them find nothing'],
            ['slug' => 'callers',      'label' => 'Who is querying', 'hint' => 'Search clients, cross-referenced with web traffic'],
            ['slug' => 'usage',        'label' => 'Storage & bandwidth', 'hint' => 'How much history your plan holds, and what is left'],
            ['slug' => 'settings',     'label' => 'Settings',     'hint' => 'Log sources, privacy, scoring, beacon'],
        ];
    }

    /**
     * Emit the whole page around a view.
     *
     * @param array<string,mixed> $boot Data handed to the front-end bootstrap.
     */
    public static function render(Config $cfg, Gateway $gw, Controller $view, array $boot): void
    {
        $siteName = (string) $cfg->get('site_name', 'Loghound');
        $slug = $view->slug();

        $v = static function (string $rel): string {
            $path = __DIR__ . '/../../public/' . $rel;
            $stamp = is_file($path) ? (string) filemtime($path) : '0';
            return $rel . '?v=' . $stamp;
        };

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n";
        echo '<head>' . "\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>' . Security::esc($view->title() . ' — ' . $siteName) . '</title>' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($v('assets/css/panel.css')) . '">' . "\n";
        echo '<script src="' . Security::esc($v('assets/js/theme.js')) . '"></script>' . "\n";
        echo '</head>' . "\n";
        echo '<body data-view="' . Security::esc($slug) . '">' . "\n";

        echo '<script type="application/json" id="lh-boot">' . Security::escJs($boot) . '</script>' . "\n";

        self::skipLink();
        self::sidebar($siteName, $slug, (string) $cfg->get('auth.mode', 'none') === 'session');

        echo '<main id="main">' . "\n";
        self::header($view);
        self::banners($gw, $cfg);

        echo '<div class="view">' . "\n";
        $view->body();
        echo "</div>\n";

        self::footer($gw);
        echo "</main>\n";

        echo '<script src="' . Security::esc($v('assets/vendor/echarts.min.js')) . '" defer></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/app.js')) . '"></script>' . "\n";
        echo "</body>\n</html>\n";
    }

    /** Keyboard users land here first; the nav is long and skipping it matters. */
    private static function skipLink(): void
    {
        echo '<a class="skip" href="#main">Skip to content</a>' . "\n";
    }

    /**
     * The left-hand navigation (a horizontal bar under ~900px, see the stylesheet).
     *
     * The sign-out control is a real form with a CSRF token rather than a link, because
     * ending a session changes state: a GET route would let any page on the internet sign
     * the operator out with an <img> tag. It appears only in session mode — HTTP Basic has
     * no sign-out to offer, and a button that did nothing would be worse than none.
     */
    private static function sidebar(string $siteName, string $active, bool $sessionAuth = false): void
    {
        echo '<nav class="side" aria-label="Views">' . "\n";
        echo '<div class="brand"><span class="brand-mark" aria-hidden="true"></span>'
            . '<span class="brand-name">' . Security::esc($siteName) . '</span></div>' . "\n";
        echo '<ul>';
        foreach (self::nav() as $item) {
            $is = $item['slug'] === $active;
            echo '<li><a href="?v=' . Security::esc($item['slug']) . '"'
                . ($is ? ' class="on" aria-current="page"' : '')
                . ' title="' . Security::esc($item['hint']) . '">'
                . Security::esc($item['label']) . '</a></li>';
        }
        echo "</ul>\n";
        echo '<button type="button" id="theme-toggle" class="theme-toggle" aria-live="polite">Theme: auto</button>' . "\n";

        if ($sessionAuth) {
            $user = Security::sessionUser();
            echo '<form method="post" action="?logout=1" class="signout">';
            echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';
            echo '<button type="submit" class="ghost small">Sign out'
                . ($user === '' ? '' : ' <span class="signout-who">' . Security::esc($user) . '</span>')
                . '</button>';
            echo "</form>\n";
        }

        echo "</nav>\n";
    }

    /**
     * Demo and configuration notices.
     *
     * NOTE WHAT IS NOT HERE: there is no Solr ping. This method used to call one, which
     * meant EVERY page in the panel blocked on a network round trip before it rendered a
     * single byte — the exact failure the async rule exists to prevent. Connection
     * trouble now surfaces two better ways: inside whichever card failed, with a retry,
     * and in the banner slot below, which the front end reveals when a card reports a
     * transport error. Both cost no extra request.
     *
     * The two checks that remain are free: demo mode is a config flag, and
     * Config::validate() touches no network.
     *
     * The ingest banner is free on the same terms — Steps::ingestStatus() stats and reads
     * one small local file that the tailer rewrites every second, and asks nothing of Solr.
     * It is here rather than only on the Settings page because an operator who clicked
     * through the installer's last screen has never been told that ingestion needs starting,
     * and an empty dashboard does not say why it is empty. Suppressed in demo mode, where
     * the numbers are fabricated and no daemon is meant to be running.
     */
    private static function banners(Gateway $gw, Config $cfg): void
    {
        if ($gw->isDemo()) {
            echo '<div class="banner banner-demo" role="status">'
                . '<strong>Demo data.</strong> These numbers are generated locally and have nothing to do with your traffic. '
                . 'Turn it off by removing <code>LOGHOUND_DEMO=1</code> from the environment '
                . 'or <code>\'demo\' =&gt; true</code> from the <code>ui</code> section of <code>config/loghound.php</code>.'
                . '</div>' . "\n";
        }

        echo '<div class="banner banner-bad" id="lh-conn" role="alert" hidden>'
            . '<strong>Solr is not answering.</strong> '
            . '<span id="lh-conn-detail"></span> '
            . 'Run the connection check under <a href="?v=settings">Settings</a>, or set '
            . '<code>LOGHOUND_DEMO=1</code> to explore the panel with sample data.'
            . '</div>' . "\n";

        if (!$gw->isDemo()) {
            $ingest = Steps::ingestStatus(dirname(__DIR__, 2));
            if ($ingest['state'] !== 'live') {
                $headline = match ((string) $ingest['state']) {
                    'refused' => 'The log reader refused to start.',
                    'absent'  => 'Nothing is reading your logs.',
                    default   => 'The log reader has stopped.',
                };
                $detail = match ((string) $ingest['state']) {
                    'refused' => 'It started, found the configuration unusable and stopped, and systemd will '
                        . 'not retry that on its own.',
                    'absent'  => 'The ingest daemon has never reported in on this machine, so every number in '
                        . 'this panel will stay empty until it is started.',
                    default   => 'The ingest daemon is not reporting any more, so nothing new is arriving.',
                };

                echo '<div class="banner banner-warn" role="alert"><strong>'
                    . Security::esc($headline) . '</strong> ' . Security::esc($detail)
                    . ' <a href="?v=settings#set-finish-card">What to do</a></div>' . "\n";
            }
        }

        $errors = $cfg->validate();
        if ($errors !== []) {
            echo '<div class="banner banner-warn" role="alert"><strong>Configuration needs attention:</strong> '
                . Security::esc(implode(' · ', array_slice($errors, 0, 3)))
                . ' <a href="?v=settings">Open settings</a></div>' . "\n";
        }
    }

    /**
     * The page head: H1, lead, then a hairline rule carrying the range picker.
     *
     * Nothing sits above the H1 — no kicker, no badge, no breadcrumb. That is rule 5 of
     * the editorial system and it is not negotiable per page.
     */
    private static function header(Controller $view): void
    {
        echo '<header class="head">' . "\n";
        echo '<h1>' . Security::esc($view->title()) . '</h1>';
        echo '<p class="sub">' . Security::esc($view->subtitle()) . '</p>';

        $current = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
        $slug = $view->slug();
        echo '<div class="head-tools">';
        echo '<div class="ranges" role="group" aria-label="Time range">';
        foreach (Query::ranges() as $key => $def) {
            $on = $key === $current['key'];
            $qs = self::urlWith(['v' => $slug, 'range' => $key]);
            echo '<a href="' . Security::esc($qs) . '"' . ($on ? ' class="on" aria-current="true"' : '') . '>'
                . Security::esc(strtoupper($key)) . '</a>';
        }
        echo '</div>';
        echo '<span class="job-meta" id="lh-page-status"></span>';
        echo "</div>\n";
        echo "</header>\n";
    }

    /**
     * Build a panel URL preserving the current filters.
     *
     * Only keys we recognise are carried over: the query string is rebuilt from scratch
     * rather than string-patched, so nothing unexpected survives a navigation.
     *
     * @param array<string,string> $overrides
     */
    public static function urlWith(array $overrides): string
    {
        $params = [];
        if (isset($_GET['f']) && is_array($_GET['f'])) {
            $allowed = Query::filterFields();
            foreach ($_GET['f'] as $field => $values) {
                if (is_string($field) && isset($allowed[$field]) && Security::isSafeFieldName($field)) {
                    $params['f'][$field] = array_values(array_filter((array) $values, 'is_string'));
                }
            }
        }
        foreach ($overrides as $k => $v) {
            $params[$k] = $v;
        }
        return '?' . http_build_query($params);
    }

    /** The footer: honest about where the numbers came from and what they cost. */
    private static function footer(Gateway $gw): void
    {
        $log = $gw->queryLog();
        echo '<footer class="foot">';
        echo '<span>Loghound panel</span>';
        if ($log !== []) {
            $total = 0.0;
            foreach ($log as $q) {
                $total += (float) $q['ms'];
            }
            echo '<span class="mono">' . count($log) . ' Solr '
                . (count($log) === 1 ? 'query' : 'queries') . ' · '
                . Security::esc(number_format($total, 1)) . ' ms</span>';
        }
        echo '<span class="mono">' . Security::esc(gmdate('m/d/Y H:i:s')) . ' UTC</span>';
        echo "</footer>\n";
    }
}
