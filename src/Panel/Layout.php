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
 * It also owns the sticky section nav, because that bar has to be a sibling of `.view`
 * rather than a child of it — see sectionNav() for the flex/sticky reason — and because the
 * numbering it derives is then the one source every card's number comes from.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Assets;
use Loghound\Config;
use Loghound\Security;
use Loghound\Setup\Pairs;
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
            ['slug' => 'attacks',      'label' => 'Attacks',      'hint' => 'What was attempted, and what the server answered'],
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

        $v = static fn (string $rel): string => Assets::url($rel);

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n";
        echo '<head>' . "\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>' . Security::esc($view->title() . ' — ' . $siteName) . '</title>' . "\n";
        echo '<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">' . "\n";
        echo '<meta name="theme-color" content="#111111" media="(prefers-color-scheme: dark)">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($v('assets/css/panel.css')) . '">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($v('assets/css/mobile.css')) . '">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($v('favicon.svg')) . '" type="image/svg+xml">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($v('favicon.ico')) . '" sizes="any">' . "\n";
        echo '<link rel="apple-touch-icon" href="' . Security::esc($v('apple-touch-icon.png')) . '">' . "\n";
        echo '<script src="' . Security::esc($v('assets/js/theme.js')) . '"></script>' . "\n";
        echo Assets::importMapTag() . "\n";
        echo '</head>' . "\n";
        echo '<body data-view="' . Security::esc($slug) . '">' . "\n";

        echo '<script type="application/json" id="lh-boot">' . Security::escJs($boot) . '</script>' . "\n";

        self::skipLink();
        self::sidebar($siteName, $slug, (string) $cfg->get('auth.mode', 'none') === 'session');

        /* The body is rendered into a buffer BEFORE anything after it is emitted, because the
           jump bar has to appear above the page head and is built out of the cards the body
           produced. A view that declares sections() names them itself; one that does not gets
           a bar derived from the cards it actually rendered, so every page in the panel has
           one rather than only the four that have been converted. Buffering costs nothing:
           body() emits static markup and fetches no data. */
        ob_start();
        $view->body();
        $body = (string) ob_get_clean();

        echo '<main id="main">' . "\n";
        self::sectionNav($view, $body);
        self::header($view, $boot);
        self::banners($gw, $cfg);

        echo '<div class="view">' . "\n";
        echo $body;
        echo "</div>\n";

        self::footer($gw);
        echo "</main>\n";

        echo '<script src="' . Security::esc($v('assets/vendor/echarts.min.js')) . '" defer></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/sectionnav.js')) . '"></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/app.js')) . '"></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/responsive.js')) . '"></script>' . "\n";
        echo "</body>\n</html>\n";
    }

    /**
     * The sticky jump bar, built from the view's own card list.
     *
     * WHERE IT IS AND WHY IT HAS TO BE THERE. First child of <main>, a SIBLING of `.view`
     * rather than a child of it. `.view` is `display: flex; flex-direction: column`, and a
     * `position: sticky` element inside a flex container is sticky within its own flex item
     * box — a box exactly as tall as the bar itself, so it has no travel and scrolls away
     * with the rest of the page. Rendered here its containing block is <main>, which is the
     * whole document, and it pins for the entire scroll including the last card.
     *
     * It sits ABOVE the H1, which is the one place the editorial system's "nothing above the
     * H1" rule is set aside, deliberately: this is page chrome in the same class as the left
     * sidebar, not an eyebrow or a badge on the article.
     *
     * ONE ROW, ALWAYS. The list scrolls horizontally and never wraps — eleven entries at
     * full heading length do not fit on one line at any realistic width, and a bar that
     * costs two rows of every screen is worse than the scrolling it was added to fix. The
     * labels in the list are therefore short by contract, and assets/js/sectionnav.js keeps
     * the active entry scrolled into view so a narrow window still says where the reader is.
     *
     * Plain anchors: the bar works with scripting off, and every entry is a real link that
     * can be opened in a new tab or sent to somebody. Marking the active entry as the reader
     * scrolls needs script, and is the only part that does.
     *
     * A view that declares sections() names its own entries and gets its card numbers from the
     * same list. A view that does not gets a bar derived from the cards it just rendered, so
     * EVERY page has one — several of them are six cards long and had the same unbroken-scroll
     * problem Settings had. Declaring the list is still better: it gives short labels written
     * for a one-row bar, and it takes the card numbering out of the call sites.
     *
     * @param string $body The view's already-rendered markup, for the derived case.
     */
    private static function sectionNav(Controller $view, string $body): void
    {
        $sections = $view instanceof Sections ? $view->sections() : self::cardsIn($body);
        if (count($sections) < 2) {
            return;
        }

        echo '<nav class="set-nav" id="lh-section-nav" aria-label="Sections on this page">';
        echo '<ul>';
        foreach ($sections as $i => $entry) {
            $id = (string) ($entry[0] ?? '');
            $label = (string) ($entry[1] ?? $id);
            if ($id === '') {
                continue;
            }
            /* THE UNTRUNCATED HEADING TRAVELS WITH THE ENTRY, WHEN THERE IS ONE TO TRAVEL.
               The bar cuts a derived label to 22 characters, so "Declared versus evasive, by
               week" reaches the reader as "Declared versus evasi…" and the rest of it existed
               nowhere on the page — not in the markup, not in a title. The stylesheet shows it
               on hover and on focus from this attribute, and assets/js/responsive.js uses the
               same value as the anchor's accessible name.

               Emitted only when it differs from what is rendered: an entry that fits needs no
               tooltip, and one that repeats a fully visible label is noise. A view that
               declares sections() chooses labels written for this bar, returns three elements,
               and correctly gets nothing. */
            $full = (string) ($entry[3] ?? '');

            echo '<li><a href="#' . Security::esc($id) . '-card" data-sect="' . Security::esc($id) . '"'
                . ($full !== '' && $full !== $label ? ' data-full="' . Security::esc($full) . '"' : '')
                . '>'
                . '<span class="set-nav-num">' . Security::esc(self::pad($i)) . '</span>'
                . '<span class="set-nav-label">' . Security::esc($label) . '</span></a></li>';
        }
        echo '</ul>';
        echo "</nav>\n";
    }

    /**
     * The cards a view rendered, read back out of its own markup.
     *
     * The fallback for a view that has not declared sections() yet. It matches exactly what
     * Controller::cardOpen() emits — an id, a number and a heading — so it cannot pick up
     * anything else on the page, and it skips a card with no id (the "not connected to
     * Opensolr" explainer is one).
     *
     * The heading captured here has ALREADY been through Security::esc() inside cardOpen(),
     * so it is decoded before it goes back out through esc() at the sink. Escaping an escaped
     * string is how `&amp;` becomes `&amp;amp;` on screen, and re-escaping at the sink rather
     * than trusting the capture is what keeps the rule "escape where you output" intact.
     *
     * Headings are written for a card, not for a one-row bar, so they are trimmed to a length
     * the bar can carry. A view that wants a label chosen rather than cut declares sections().
     *
     * @return array<int,array{0:string,1:string,2:string,3:string}>
     */
    private static function cardsIn(string $body): array
    {
        $pattern = '#<section class="card" id="([A-Za-z0-9_-]+)-card"[^>]*>'
            . '<div class="card-head"><h2>'
            . '<span class="card-num">[^<]*</span>'
            . '<span>([^<]*)</span>#';

        if (!preg_match_all($pattern, $body, $matches, PREG_SET_ORDER)) {
            return [];
        }

        $out = [];
        foreach ($matches as $match) {
            $full = html_entity_decode($match[2], ENT_QUOTES, 'UTF-8');
            $label = $full;
            if (mb_strlen($label) > 22) {
                $label = rtrim(mb_substr($label, 0, 21)) . '…';
            }
            $out[] = [$match[1], $label, '', $full];
        }
        return $out;
    }

    /**
     * The number a card carries, derived from its position in the view's own list.
     *
     * Called at the `cardOpen()` site instead of a literal, so inserting a card renumbers
     * everything below it and the jump bar cannot disagree with the cards. An id that is not
     * in the list gets no number rather than a wrong one: a card the view forgot to declare
     * is a bug to see, not a figure to invent.
     *
     * @param array<int,array<int,string>> $sections The view's section list.
     */
    public static function cardNum(array $sections, string $id): string
    {
        foreach ($sections as $i => $entry) {
            if ((string) ($entry[0] ?? '') === $id) {
                return self::pad($i);
            }
        }
        return '';
    }

    /** Zero-padded section number from a zero-based index. */
    private static function pad(int $index): string
    {
        return sprintf('%02d', $index + 1);
    }

    /** Keyboard users land here first; the nav is long and skipping it matters. */
    private static function skipLink(): void
    {
        echo '<a class="skip" href="#main">Skip to content</a>' . "\n";
    }

    /**
     * The left-hand navigation (a horizontal bar under ~900px, see the stylesheet).
     *
     * THE LABEL IS WRAPPED. It was a bare text node inside the link, and a text node cannot be
     * addressed by a selector — so the collapsed icon rail, which hides everything in a link
     * except its mark, could not hide the words and rendered twelve clipped fragments down a
     * 60px column. One span is the whole fix.
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
        /* THE NAVIGATION CARRIES THE DASHBOARD'S STATE. These were bare `?v=<slug>` links, so
           every move between views threw away the time range and every filter in force. The
           filter bar exists precisely because a filtered number that does not say it is
           filtered is a wrong number on every page — and the navigation was quietly clearing
           the filters it was there to announce. urlWith() re-validates every key it carries. */
        foreach (self::nav() as $item) {
            $is = $item['slug'] === $active;
            echo '<li><a href="' . Security::esc(self::urlWith(['v' => $item['slug']])) . '"'
                . ($is ? ' class="on" aria-current="page"' : '')
                . ' title="' . Security::esc($item['hint']) . '">'
                . '<span class="navlabel">' . Security::esc($item['label']) . '</span></a></li>';
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

        /* The heading is a placeholder the front end rewrites. Two different systems can fail
           here — the search index the panel reads, and the Opensolr control plane the analytics
           views ask — and they have different next steps, so a fixed "Solr is not answering"
           sent an operator to check the wrong one half the time. assets/js/core.js's
           raiseConnectionBanner() decides which, from the diagnosis it was given. */
        echo '<div class="banner banner-bad" id="lh-conn" role="alert" hidden>'
            . '<strong>A service this panel depends on is not answering.</strong> '
            . '<span id="lh-conn-detail"></span> '
            . 'Run the connection check under <a href="' . Security::esc(self::urlWith(['v' => 'settings'])) . '">Settings</a>, or set '
            . '<code>LOGHOUND_DEMO=1</code> to explore the panel with sample data.'
            . '</div>' . "\n";

        /* AN ACCOUNT IS SET AND ITS INDEXES HAVE NOT BEEN CHOSEN YET. Without this the panel
           answered that state with "A service this panel depends on is not answering" on every
           view, which is true of the symptom and useless about the cause: nothing is broken,
           a question has not been answered yet, and the answer is two clicks away. Saying so
           here rather than only on Settings is what makes the state recoverable from wherever
           the operator happens to be — including after they close the tab and sign in again.

           Free, like every other check in this method: the verdict was recorded at the one
           moment it was known and is read from config, so no page pays a control-plane call
           for it. */
        if (Pairs::isPending($cfg)) {
            echo '<div class="banner banner-warn" role="alert"><strong>'
                . Security::esc(Pairs::pendingHeadline()) . '</strong> '
                . Security::esc(Pairs::pendingDetail($cfg))
                . ' <a href="' . Security::esc(self::urlWith(['v' => 'settings'])) . '#set-solr">'
                . 'Choose them</a></div>' . "\n";
        }

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
                    . ' <a href="' . Security::esc(self::urlWith(['v' => 'settings'])) . '#set-finish-card">What to do</a></div>' . "\n";
            }
        }

        $errors = $cfg->validate();
        if ($errors !== []) {
            echo '<div class="banner banner-warn" role="alert"><strong>Configuration needs attention:</strong> '
                . Security::esc(implode(' · ', array_slice($errors, 0, 3)))
                . ' <a href="' . Security::esc(self::urlWith(['v' => 'settings'])) . '">Open settings</a></div>' . "\n";
        }
    }

    /**
     * The page head: H1, lead, then a hairline rule carrying the range picker.
     *
     * Nothing sits above the H1 — no kicker, no badge, no breadcrumb. That is rule 5 of
     * the editorial system and it is not negotiable per page.
     */
    private static function header(Controller $view, array $boot = []): void
    {
        echo '<header class="head">' . "\n";
        echo '<h1>' . Security::esc($view->title()) . '</h1>';
        echo '<p class="sub">' . Security::esc($view->subtitle()) . '</p>';

        $current = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
        $slug = $view->slug();

        echo '<div class="head-tools">';

        /* THE PICKER IS RENDERED ONLY WHERE IT DOES SOMETHING. See Controller::toolbar() for
           why this is asked of the view rather than special-cased: on Settings and on Storage
           & bandwidth the six links changed nothing at all, and a control that answers a press
           by doing nothing is worse than no control.

           The CHOICE still travels — urlWith() carries `range` through every navigation — so a
           reader who picks 7D, opens Settings and comes back is still on 7D even though the
           page in between had nowhere to show it. */
        if ($view->honours(Controller::SCOPE_RANGE)) {
            echo '<div class="ranges" role="group" aria-label="Time range">';
            foreach (Query::ranges() as $key => $def) {
                $on = $key === $current['key'];
                $qs = self::urlWith(['v' => $slug, 'range' => $key]);
                echo '<a href="' . Security::esc($qs) . '"' . ($on ? ' class="on" aria-current="true"' : '') . '>'
                    . Security::esc(strtoupper($key)) . '</a>';
            }
            echo '</div>';
        }

        self::clearCache($view, $boot, $slug);

        echo '<span class="job-meta" id="lh-page-status"></span>';
        echo "</div>\n";

        /* The bandwidth strip is a READOUT, not a control, and it used to be injected into the
           row above beside the range links — which put a status line in a group of controls and
           made it look like one more thing to press. It keeps its own slot here, outside the
           toolbar, so it can stay on every view (it is the one quota that cannot be reclaimed,
           and once exceeded the panel itself answers 403) without pretending to be an input. */
        echo '<div class="head-readout" id="lh-readout"></div>' . "\n";
        echo "</header>\n";
    }

    /**
     * The Clear cache control, and the one line that follows a press.
     *
     * WHY IT IS IN THE PAGE HEAD AND NOT IN SETTINGS. It undoes something the reader is looking
     * at: the numbers on this page may have been computed up to the cache duration ago, and the
     * question "is this current?" is asked where the number is, not two pages away. The stamp
     * each card carries answers the question; this answers the follow-up.
     *
     * IT IS A FORM, NOT A LINK. Clearing state is a POST with a CSRF token, for the ordinary
     * reason — a GET route would let any page on the internet empty an operator's cache with an
     * <img> tag. The front controller answers it with a redirect, so a refresh cannot clear
     * twice and the outcome arrives as a validated query parameter rather than a rendered POST.
     *
     * WHERE IT DOES NOT APPEAR. Only on a view that actually reads cached Solr answers, by the
     * same declaration that governs the other three controls — see Controller::SCOPE_CACHE.
     * Index analytics and Query analysis read the Opensolr request log, which is not cached, so
     * a button there would discard nothing and say it had. And on no view at all when the cache
     * is switched off or is not reachable, which is what `enabled` reports: an installation with
     * nothing to clear is not offered a control that would do nothing.
     *
     * @param array<string,mixed> $boot
     */
    private static function clearCache(Controller $view, array $boot, string $slug): void
    {
        $cache = (array) ($boot['cache'] ?? []);
        if (empty($cache['enabled']) || !$view->honours(Controller::SCOPE_CACHE)) {
            return;
        }

        $cleared = $cache['cleared'] ?? null;

        echo '<form method="post" action="' . Security::esc(self::urlWith(['v' => $slug])) . '" class="cacheclear">';
        echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';
        echo '<button type="submit" name="clear_cache" value="1" class="ghost small">Clear cache</button>';

        if ($cleared !== null) {
            $n = (int) $cleared;
            $said = $n < 0
                ? 'Nothing was cleared — the cache did not answer.'
                : ($n === 1 ? '1 cached answer discarded.' : number_format($n) . ' cached answers discarded.');
            echo '<span class="job-meta" role="status">' . Security::esc($said) . '</span>';
        }

        echo "</form>\n";
    }

    /**
     * Build a panel URL preserving the current filters.
     *
     * Only keys we recognise are carried over: the query string is rebuilt from scratch
     * rather than string-patched, so nothing unexpected survives a navigation.
     *
     * Four namespaces travel, and each is re-validated here rather than trusted because it
     * arrived in a URL the panel itself produced:
     *
     *  - `f[…]`  the sessions/hits sidebar filters, against Query::filterFields();
     *  - `lf[…]` the Opensolr request-log filters, against OpensolrView::logFilterFields();
     *  - `outcome` the request-log outcome slice, against its own small allowlist;
     *  - `core`  the selected Opensolr index, shape-checked as an index name.
     *
     * The last three were missing, which meant changing the time range on any of the three
     * Opensolr views silently dropped the index and every filter the reader had set and
     * quietly answered a different question under the same chips.
     *
     * @param array<string,string> $overrides
     */
    public static function urlWith(array $overrides): string
    {
        $params = [];

        foreach ([['f', Query::filterFields()], ['lf', OpensolrView::logFilterFields()]] as [$key, $allowed]) {
            $raw = $_GET[$key] ?? null;
            if (!is_array($raw)) {
                continue;
            }
            foreach ($raw as $field => $values) {
                if (!is_string($field) || !isset($allowed[$field]) || !Security::isSafeFieldName($field)) {
                    continue;
                }

                /* THE OPERATOR TRAVELS WITH THE VALUES, AND IT DID NOT. `f[field][op]=none` lives
                   in the same array as the values (Panel\Facets, "the URL is the state"), and
                   array_values() re-indexed it — so changing the time range turned an exclusion
                   into an inclusion AND added the literal string "none" as a value. The chips
                   still said "None of" while the numbers underneath were the exact opposite: a
                   silently inverted filter, which is the worst shape a wrong number can take. */
                $clean = [];
                foreach ((array) $values as $k => $value) {
                    if (!is_string($value)) {
                        continue;
                    }
                    if ($k === 'op') {
                        if (in_array($value, Facets::OPERATORS, true)) {
                            $clean['op'] = $value;
                        }
                        continue;
                    }
                    if (is_int($k) || ctype_digit((string) $k)) {
                        $clean[] = $value;
                    }
                }
                if ($clean !== []) {
                    $params[$key][$field] = $clean;
                }
            }
        }

        $outcome = $_GET['outcome'] ?? null;
        if (is_string($outcome) && isset(OpensolrView::OUTCOMES[$outcome])) {
            $params['outcome'] = $outcome;
        }

        $core = $_GET['core'] ?? null;
        if (is_string($core) && $core !== '' && Security::isSafeCoreName($core)) {
            $params['core'] = $core;
        }

        /* THE RANGE TRAVELS TOO, AND IT DID NOT. Every other piece of dashboard state was
           carried across a navigation and the time window was not, so an operator who chose
           7D and moved to another view silently landed back on the 24h default — and the
           page said 24H while they believed they were still on 7D, which is the same class
           of wrong number as a filter that inverts itself.

           It matters more now that a view which is not scoped by time does not render the
           picker at all: without this, going to such a view and coming back would discard
           the choice, because the URL that took them there had nowhere to keep it.

           Validated against the table rather than passed through, like every other key here:
           an unknown token is dropped, and Query::range() would default it anyway. */
        $range = $_GET['range'] ?? null;
        if (is_string($range) && isset(Query::ranges()[$range])) {
            $params['range'] = $range;
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
