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

        // Cache-buster derived from the asset's own mtime: no build step, but a changed
        // stylesheet is still picked up immediately instead of after a hard refresh.
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
        // Synchronous, tiny, and first: applies the stored theme before the first paint.
        echo '<script src="' . Security::esc($v('assets/js/theme.js')) . '"></script>' . "\n";
        echo '</head>' . "\n";
        echo '<body data-view="' . Security::esc($slug) . '">' . "\n";

        // Boot payload. A type="application/json" block is inert — the browser never
        // executes it — and JSON_HEX_TAG in escJs means a "</script>" inside any value
        // cannot terminate the element early.
        echo '<script type="application/json" id="lh-boot">' . Security::escJs($boot) . '</script>' . "\n";

        self::skipLink();
        self::sidebar($siteName, $slug);

        echo '<main id="main">' . "\n";
        self::banners($gw, $cfg);
        self::header($view);

        echo '<div class="view">' . "\n";
        $view->body();
        echo "</div>\n";

        self::footer($gw);
        echo "</main>\n";

        // ECharts first (it is a classic UMD script exposing window.echarts), then the
        // application as an ES module. Both are same-origin, which is what lets the CSP
        // stay at script-src 'self' and what lets the panel run air-gapped.
        echo '<script src="' . Security::esc($v('assets/vendor/echarts.min.js')) . '" defer></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/app.js')) . '"></script>' . "\n";
        echo "</body>\n</html>\n";
    }

    /** Keyboard users land here first; the nav is long and skipping it matters. */
    private static function skipLink(): void
    {
        echo '<a class="skip" href="#main">Skip to content</a>' . "\n";
    }

    /** The left-hand navigation (a horizontal bar under ~900px, see the stylesheet). */
    private static function sidebar(string $siteName, string $active): void
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
        echo "</nav>\n";
    }

    /**
     * Connection / demo banners.
     *
     * Demo mode gets a permanent, unmissable banner. A dashboard that shows fabricated
     * numbers without saying so is the single worst thing this project could ship.
     */
    private static function banners(Gateway $gw, Config $cfg): void
    {
        if ($gw->isDemo()) {
            echo '<div class="banner banner-demo" role="status">'
                . '<strong>Demo data.</strong> These numbers are generated locally and have nothing to do with your traffic. '
                . 'Turn it off by removing <code>LOGHOUND_DEMO=1</code> from the environment '
                . 'or <code>\'demo\' =&gt; true</code> from the <code>ui</code> section of <code>config/loghound.php</code>.'
                . '</div>' . "\n";
            return;
        }
        if (!$gw->ping()) {
            echo '<div class="banner banner-bad" role="alert">'
                . '<strong>Solr is not reachable.</strong> '
                . Security::esc((string) ($gw->error() ?? 'No further detail.'))
                . ' Check the connection under <a href="?v=settings">Settings</a>, or set '
                . '<code>LOGHOUND_DEMO=1</code> to explore the panel with sample data.'
                . '</div>' . "\n";
        }

        // Config problems are worth surfacing on every page, not just in Settings: a
        // panel that renders zeroes because the beacon secret is missing is a support ticket.
        $errors = $cfg->validate();
        if ($errors !== []) {
            echo '<div class="banner banner-warn" role="alert"><strong>Configuration needs attention:</strong> '
                . Security::esc(implode(' · ', array_slice($errors, 0, 3)))
                . ' <a href="?v=settings">Open settings</a></div>' . "\n";
        }
    }

    /** Page title, subtitle and the time-range picker. */
    private static function header(Controller $view): void
    {
        echo '<header class="head">' . "\n";
        echo '<div class="head-text">';
        echo '<h1>' . Security::esc($view->title()) . '</h1>';
        echo '<p class="sub">' . Security::esc($view->subtitle()) . '</p>';
        echo "</div>\n";

        // The range picker is a set of links, not a <select>: it survives with JS off,
        // every range is a bookmarkable URL, and there is no state to keep in sync.
        $current = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
        $slug = $view->slug();
        echo '<div class="ranges" role="group" aria-label="Time range">';
        foreach (Query::ranges() as $key => $def) {
            $on = $key === $current['key'];
            $qs = self::urlWith(['v' => $slug, 'range' => $key]);
            echo '<a href="' . Security::esc($qs) . '"' . ($on ? ' class="on" aria-current="true"' : '') . '>'
                . Security::esc(strtoupper($key)) . '</a>';
        }
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
