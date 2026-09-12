<?php
/**
 * Loghound — the panel's HTML chrome.
 *
 * One place that emits <head>, the two-level navigation, the sticky top bar, the banners and
 * the script tags, so that a view file contains nothing but its own content.
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
 * ---------------------------------------------------------------------------------
 * A SECTION IS A PAGE
 * ---------------------------------------------------------------------------------
 * There used to be a jump bar pinned above every view, listing that view's cards, and each
 * card was a stop on one very long page. It is gone. Every section a view declares is now its
 * own page with its own URL — `?v=attacks&s=patterns` — reached from the left navigation,
 * which is two levels deep as a result. A page carries one section and nothing else, so the
 * question "which of these eleven numbers am I looking at" stops being a scrolling problem.
 *
 * The view files did not have to be rewritten for it: Controller::renderOnlySection() gates
 * the one pair of methods every card in the product is built from, so body() still emits the
 * whole view and this class keeps the card the URL names. See Controller for why output
 * OUTSIDE a card is kept rather than dropped.
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
     * The route table. Keys are the only values `?v=` may take.
     *
     * HERE RATHER THAN IN THE FRONT CONTROLLER, because the navigation needs it too: a
     * two-level navigation has to ask every view class what sections it has, and a second copy
     * of the slug-to-class map is a second place for a deleted view to survive. There is no
     * dynamic class resolution from the URL anywhere — a route is a key in this map, and an
     * unknown key is the default view rather than an attempt to load a class named after
     * user input.
     *
     * @return array<string,class-string<Controller>>
     */
    public static function routes(): array
    {
        return [
            'overview'     => Overview::class,
            'live'         => Live::class,
            'sources'      => Sources::class,
            'pages'        => Pages::class,
            'searches'     => Searches::class,
            'engagement'   => Engagement::class,
            'rhythm'       => Rhythm::class,
            'bots'         => Bots::class,
            'attacks'      => Attacks::class,
            'fingerprints' => Fingerprints::class,
            'networks'     => Networks::class,
            'sessions'     => Sessions::class,
            'performance'  => Performance::class,
            'hosts'        => Hosts::class,
            'indexes'      => Indexes::class,
            'usage'        => Usage::class,
            'settings'     => Settings::class,
        ];
    }

    /** The view a request with no `v=`, or an unknown one, lands on. */
    public const DEFAULT_VIEW = 'overview';

    /**
     * The navigation, with each view's own pages.
     *
     * THE SESSION EXPLORER SITS UNDER LIVE, not down among the analyses. Both answer "show me
     * the actual traffic" — Live as it is written, the explorer as it can be searched — and a
     * reader who wants one wants the other next. It used to sit eleventh, after every breakdown,
     * which put the panel's most-used page behind the ones you visit when you already know what
     * you are looking for. Everything below it keeps the order SPEC §10 gives.
     *
     * TWO LEVELS, AND THE PARENT IS A LINK. A parent that is only a group would make the view
     * name unpressable — twelve headings you can read and not go to — and a parent that is a
     * page of its own would need a thirteenth page per view with nothing on it. So a parent
     * goes to its FIRST section, which is the page a reader arriving at that view wants, and it
     * carries a twist control that opens its list without navigating. The current view's list
     * is open on arrival; the others are a press away.
     *
     * A view with fewer than two sections — the session explorer is the only one — has no
     * sub-list at all and is an ordinary link, because splitting a single section into a
     * sub-item would be a second name for the same page.
     *
     * @return array<int,array{slug:string,label:string,hint:string,sections:array<int,array{slug:string,label:string,id:string}>}>
     */
    public static function nav(): array
    {
        $views = [
            ['slug' => 'overview',     'label' => 'Overview',     'hint' => 'Who came, and how long they really stayed'],
            ['slug' => 'live',         'label' => 'Live',         'hint' => 'The access log as it is written'],
            ['slug' => 'sessions',     'label' => 'Sessions',     'hint' => 'Search and drill into one visit'],
            ['slug' => 'sources',      'label' => 'Where they came from', 'hint' => 'What kind of thing sent each visit, and which site actually did'],
            ['slug' => 'pages',        'label' => 'Pages',        'hint' => 'Where people arrive, where the log last saw them, and what is moving'],
            ['slug' => 'searches',     'label' => 'Site search',   'hint' => 'What visitors typed into your own search box'],
            ['slug' => 'engagement',   'label' => 'Engagement',    'hint' => 'Bounce measured on what people did, not on how many pages loaded'],
            ['slug' => 'rhythm',       'label' => 'When they come','hint' => 'Hour of day against day of week'],
            ['slug' => 'bots',         'label' => 'Bot forensics','hint' => 'Why each verdict was reached'],
            ['slug' => 'attacks',      'label' => 'Attacks',      'hint' => 'What was attempted, and what the server answered'],
            ['slug' => 'fingerprints', 'label' => 'Fingerprints', 'hint' => 'One header signature, many IPs'],
            ['slug' => 'networks',     'label' => 'Networks',     'hint' => 'ASN, netname and geography'],
            ['slug' => 'performance',  'label' => 'Performance',  'hint' => 'Latency percentiles and status codes'],
            ['slug' => 'hosts',        'label' => 'Virtual hosts','hint' => 'Every site on this machine, side by side'],
            ['slug' => 'indexes',      'label' => 'Solr',         'hint' => 'What your Opensolr search indexes are being asked'],
            ['slug' => 'usage',        'label' => 'Storage & bandwidth', 'hint' => 'How much history your plan holds, and what is left'],
            ['slug' => 'settings',     'label' => 'Settings',     'hint' => 'Log sources, privacy, scoring, beacon'],
        ];

        $routes = self::routes();
        $out = [];
        foreach ($views as $view) {
            $class = $routes[$view['slug']] ?? null;
            $view['sections'] = $class === null ? [] : self::sectionsOf($class);
            $out[] = $view;
        }
        return $out;
    }

    /**
     * One view class's sections, shaped for the navigation.
     *
     * Read from the class constant rather than from an instance, so building the navigation
     * costs no constructor and no request parsing — and certainly no render of eleven view
     * bodies, which is what deriving the list from the markup would have cost on every page.
     *
     * @param class-string<Controller> $class
     * @return array<int,array{slug:string,label:string,id:string}>
     */
    private static function sectionsOf(string $class): array
    {
        $sections = $class::sectionList();
        if (count($sections) < 2) {
            return [];
        }

        $out = [];
        foreach ($sections as $entry) {
            $id = (string) ($entry[0] ?? '');
            if ($id === '') {
                continue;
            }
            $out[] = [
                'slug'  => Controller::sectionSlug($id),
                'label' => (string) ($entry[1] ?? $id),
                'id'    => $id,
            ];
        }
        return $out;
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
        $section = (string) ($boot['section'] ?? '');

        $v = static fn (string $rel): string => Assets::url($rel);

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n";
        echo '<head>' . "\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>' . Security::esc(self::pageTitle($view, $section, $siteName)) . '</title>' . "\n";
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
        echo '<body data-view="' . Security::esc($slug) . '" data-section="' . Security::esc($section) . '">' . "\n";

        echo '<script type="application/json" id="lh-boot">' . Security::escJs($boot) . '</script>' . "\n";

        self::skipLink();
        self::sidebar($siteName, $slug, $section, (string) $cfg->get('auth.mode', 'none') === 'session');

        echo '<main id="main">' . "\n";
        self::topBar($view, $boot, $slug, $section);
        self::header($view);
        self::banners($gw, $cfg);

        echo '<div class="view">' . "\n";
        echo self::sectionBody($view, $section);
        echo "</div>\n";

        self::footer($gw);
        echo "</main>\n";

        echo '<script src="' . Security::esc($v('assets/vendor/echarts.min.js')) . '" defer></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/app.js')) . '"></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($v('assets/js/responsive.js')) . '"></script>' . "\n";
        echo "</body>\n</html>\n";
    }

    /**
     * The document title: the page first, then the view, then the installation.
     *
     * The section comes first because it is what distinguishes one browser tab from the six
     * other tabs of the same view, and a bookmark bar shows the beginning of a title and not
     * the end.
     */
    private static function pageTitle(Controller $view, string $section, string $siteName): string
    {
        $label = self::sectionLabel($view, $section);
        return ($label === '' ? '' : $label . ' — ') . $view->title() . ' — ' . $siteName;
    }

    /** The declared label of one section of one view, or '' when it has none. */
    private static function sectionLabel(Controller $view, string $section): string
    {
        if ($section === '') {
            return '';
        }
        foreach ($view->sections() as $entry) {
            if ((string) ($entry[0] ?? '') === $section) {
                return (string) ($entry[1] ?? '');
            }
        }
        return '';
    }

    /**
     * The view's markup, reduced to the one section this page is.
     *
     * TWO RENDERS, AND THE SECOND ONE IS THE CHEAP PART. body() emits static markup and fetches
     * nothing — every number on every card arrives later over fetch() — so running it twice
     * costs string concatenation and no I/O at all. The first pass is what proves the gate found
     * something; without it, a view that took an early return before reaching the wanted card
     * would render an empty page rather than the state it was trying to explain.
     *
     * THE FALLBACK IS THE WHOLE BODY, deliberately. The one view that returns early is Index
     * analytics with no Opensolr credentials configured, and what it returns is a card
     * explaining exactly that — which is the page the operator needs, whichever section they
     * asked for.
     */
    private static function sectionBody(Controller $view, string $section): string
    {
        ob_start();
        $view->body();
        $whole = (string) ob_get_clean();

        if ($section === '') {
            return $whole;
        }

        /* THE BUFFER LEVEL IS RECORDED AND UNWOUND TO, not popped once. The gate opens a buffer
           per card and closes it at cardClose()/cardEnd(); a view that ever opened a card and
           returned without closing it would leave one behind, and a single ob_get_clean() would
           then discard the card's buffer and hand back the wrong string while the page's own
           buffer stayed open. Unwinding to the level this method started at cannot do that
           whatever a view does. */
        $depth = ob_get_level();
        Controller::renderOnlySection($section);
        ob_start();
        $view->body();
        $one = '';
        while (ob_get_level() > $depth) {
            $one = (string) ob_get_clean() . $one;
        }
        $hit = Controller::sectionWasRendered();
        Controller::renderOnlySection(null);

        return $hit ? $one : $whole;
    }

    /**
     * The number a card carries, derived from its position in the view's own list.
     *
     * Called at the `cardOpen()` site instead of a literal, so inserting a section renumbers
     * everything below it and the navigation cannot disagree with the cards. An id that is not
     * in the list gets no number rather than a wrong one: a card the view forgot to declare
     * is a bug to see, not a figure to invent.
     *
     * It still matters now that a section is a page: the number is the page's position in its
     * view, which is what tells a reader they are on the third of eight rather than on a card
     * that happens to be third on screen.
     *
     * @param array<int,array<int,string>> $sections The view's section list.
     */
    public static function cardNum(array $sections, string $id): string
    {
        foreach ($sections as $i => $entry) {
            if ((string) ($entry[0] ?? '') === $id) {
                return sprintf('%02d', $i + 1);
            }
        }
        return '';
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
     * EVERY VIEW'S SUB-LIST IS IN THE DOCUMENT, not only the current view's, and that is what
     * makes the collapsed icon rail work: with the labels hidden, a mark is the whole of the
     * navigation, and a reader has to be able to reach `Attacks → Patterns` without first
     * landing on `Attacks → Answered`. The lists are real links either way, so the rail's
     * flyout is a stylesheet rule over markup that is already there, keyboard reachable with
     * nothing scripted, and present with scripting off.
     *
     * The sign-out control is a real form with a CSRF token rather than a link, because
     * ending a session changes state: a GET route would let any page on the internet sign
     * the operator out with an <img> tag. It appears only in session mode — HTTP Basic has
     * no sign-out to offer, and a button that did nothing would be worse than none.
     */
    private static function sidebar(string $siteName, string $active, string $section, bool $sessionAuth = false): void
    {
        echo '<nav class="side" aria-label="Views">' . "\n";
        echo '<div class="brand"><span class="brand-mark" aria-hidden="true"></span>'
            . '<span class="brand-name">' . Security::esc($siteName) . '</span></div>' . "\n";
        echo '<ul>';

        foreach (self::nav() as $item) {
            $current = $item['slug'] === $active;
            $sections = $item['sections'];
            $first = $sections === [] ? null : $sections[0];

            /* THE NAVIGATION CARRIES THE DASHBOARD'S STATE. These were bare `?v=<slug>` links,
               so every move between views threw away the time range and every filter in force.
               urlWith() re-validates every key it carries, and the section is named explicitly
               rather than carried, because a section belongs to one view and carrying `s`
               across a navigation would ask Attacks for a page of Settings. */
            $href = self::urlWith($first === null
                ? ['v' => $item['slug']]
                : ['v' => $item['slug'], 's' => $first['slug']]);

            $listId = 'lh-nav-' . $item['slug'];

            echo '<li class="navgroup' . ($current ? ' is-current' : '')
                . ($sections !== [] ? ' has-sub' : '') . '">';
            echo '<span class="navrow">';
            echo '<a class="navlink' . ($current ? ' on' : '') . '"'
                . ' href="' . Security::esc($href) . '"'
                . ($current && $sections === [] ? ' aria-current="page"' : '')
                . ' title="' . Security::esc($item['hint']) . '">'
                . '<span class="navlabel">' . Security::esc($item['label']) . '</span></a>';

            if ($sections !== []) {
                echo '<button type="button" class="navtwist" aria-expanded="' . ($current ? 'true' : 'false') . '"'
                    . ' aria-controls="' . Security::esc($listId) . '"'
                    . ' aria-label="Sections of ' . Security::esc($item['label']) . '">'
                    . '<span class="navtwist-mark" aria-hidden="true"></span></button>';
            }
            echo '</span>';

            if ($sections !== []) {
                echo '<ul class="navsub" id="' . Security::esc($listId) . '"' . ($current ? '' : ' hidden') . '>';
                echo '<li class="navsub-head" aria-hidden="true">' . Security::esc($item['label']) . '</li>';
                foreach ($sections as $entry) {
                    $on = $current && $entry['id'] === $section;
                    echo '<li><a class="navsub-link' . ($on ? ' on' : '') . '"'
                        . ' href="' . Security::esc(self::urlWith(['v' => $item['slug'], 's' => $entry['slug']])) . '"'
                        . ($on ? ' aria-current="page"' : '') . '>'
                        . '<span class="navsub-label">' . Security::esc($entry['label']) . '</span></a></li>';
                }
                echo '</ul>';
            }

            echo '</li>';
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

    /* ---------------------------------------------------------------------------------
     * The top bar
     * ------------------------------------------------------------------------------ */

    /**
     * The controls that scope the page, in one bar that is pinned for the whole scroll.
     *
     * ---------------------------------------------------------------------------------
     * WHAT THIS REPLACES, AND WHY IT IS ONE BAR
     * ---------------------------------------------------------------------------------
     * There were four different filter-bar layouts across four pages, assembled at runtime by a
     * front-end pass that MOVED whatever furniture it found — the range links, the host
     * selector, the applied-filter chips, a bandwidth readout — into a strip that condensed on
     * scroll. Four layouts is four things to get right, and on the session explorer the bar
     * clipped: "Clear all" and the sentence after it were sliced off the right edge, because the
     * row was assembled from parts none of which knew how much room the others had taken.
     *
     * This is one bar, rendered server-side, from what the view DECLARES it honours
     * (Controller::toolbar()). A control that is not declared is not drawn, which is the rule
     * that already governed the range picker and now governs all of them: a control that answers
     * a press by doing nothing is worse than no control.
     *
     * ---------------------------------------------------------------------------------
     * IT IS A FORM, AND IT IS STICKY ALWAYS
     * ---------------------------------------------------------------------------------
     * A GET form, so the duration and the hostname work with scripting switched off: change and
     * submit. assets/js/topbar.js submits it on change, which is the only thing script adds. The
     * page's other state travels as hidden fields, re-validated on the way out by urlWith()'s
     * own allowlists, so submitting the bar cannot lose a filter or a section.
     *
     * Sticky always rather than sticky-once-scrolled: a bar that changes shape when the page
     * moves is a second design to maintain, and the scope of the numbers being read is wanted
     * at the top of the page as much as at the bottom.
     *
     * @param array<string,mixed> $boot
     */
    private static function topBar(Controller $view, array $boot, string $slug, string $section): void
    {
        $range = $view->honours(Controller::SCOPE_RANGE);
        $host = $view->honours(Controller::SCOPE_HOST);
        $filters = $view->honours(Controller::SCOPE_FACETS) || $view instanceof OpensolrView;
        $applied = self::appliedCount($boot);

        echo '<div class="topbar" id="lh-topbar">' . "\n";
        echo '<div class="topbar-in">';

        if ($filters) {
            /* SHOWN ONLY WHEN SOMETHING IS APPLIED. A permanent "0 filters" button is furniture
               that reports nothing; what an operator needs is to notice, from anywhere on the
               page, that the numbers in front of them are narrowed. The badge is the count and
               the dialog is where they are listed and removed. */
            echo '<button type="button" class="tb-filters" id="lh-tb-filters"'
                . ($applied === 0 ? ' hidden' : '')
                . ' aria-haspopup="dialog">'
                . '<span class="tb-filters-label">Applied filters</span>'
                . '<span class="tb-badge" id="lh-tb-badge">' . Security::esc((string) $applied) . '</span>'
                . '</button>';
        }

        /* THE FORM EXISTS ONLY WHERE IT HAS A CONTROL IN IT. On Settings and Storage & bandwidth
           nothing is scoped by anything, so there is no duration and no hostname — and an empty
           form with a submit button in it would be a control that answers a press by doing
           nothing, which is the one thing Controller::toolbar() exists to prevent. */
        if ($range || $host) {
            echo '<form class="tb-scope" method="get" action="" id="lh-scope-form">';
            self::hiddenState(['v' => $slug, 's' => Controller::sectionSlug($section)], $range, $host);

            if ($range) {
                $current = Query::range(isset($_GET['range']) && is_string($_GET['range']) ? $_GET['range'] : null);
                echo '<span class="tb-field">';
                echo '<label for="lh-range">Duration</label>';
                echo '<select id="lh-range" name="range" data-smart="Duration">';
                foreach (Query::ranges() as $key => $def) {
                    echo '<option value="' . Security::esc($key) . '"'
                        . ($key === $current['key'] ? ' selected' : '') . '>'
                        . Security::esc((string) $def['short']) . '</option>';
                }
                echo '</select></span>';
            }

            if ($host) {
                /* THE LIST ARRIVES LATER, THE CHOICE IS HERE NOW. Populating this server-side
                   would make every page render wait on a Solr facet, which is the one thing this
                   panel does not do. The selected value is rendered so the form round-trips
                   correctly and so the current scope is on screen before any fetch lands;
                   assets/js/topbar.js fills in the rest of the hosts when the facet answers. */
                $chosen = self::chosenHost();
                echo '<span class="tb-field" id="lh-hostfield">';
                echo '<label for="lh-host">Hostname</label>';
                echo '<select id="lh-host" name="f[host_s][]" data-smart="Hostname">';
                echo '<option value=""' . ($chosen === '' ? ' selected' : '') . '>All hosts</option>';
                if ($chosen !== '') {
                    echo '<option value="' . Security::esc($chosen) . '" selected>'
                        . Security::esc($chosen) . '</option>';
                }
                echo '</select></span>';

                /* AN EMPTY HOST HAS TO BE ABLE TO MEAN "ALL HOSTS", AND A SILENT URL MEANS
                   "WHATEVER I HAD". Panel\Scope restores a remembered host into a request that
                   says nothing about one, so choosing "All hosts" — which submits an empty value
                   the facet reader drops — would otherwise be undone on the next page load by the
                   host that was just cleared. `fx` is how the URL states an empty filter set out
                   loud; assets/js/topbar.js sets it on submit when nothing is selected. */
                echo '<input type="hidden" name="fx" id="lh-scope-fx" value="" disabled>';
            }

            /* THE ONLY CONTROL HERE THAT SUBMITS ITSELF. With script running, changing a select
               submits the form and this is never needed, so the stylesheet takes it off screen
               the moment `lh-js` lands on the root element. With script off it is the whole
               mechanism. */
            echo '<button type="submit" class="tb-go">Apply</button>';
            echo '</form>';
        }

        echo '<button type="button" class="tb-res" id="lh-tb-resources" aria-haspopup="dialog"'
            . ' title="Opensolr resources: what this account is using against what the plan allows"'
            . ' aria-label="Opensolr resources">'
            . self::resourceMark()
            . '</button>';

        echo '<span class="job-meta" id="lh-page-status"></span>';
        echo '</div>';
        echo "</div>\n";
    }

    /**
     * The mark on the resources control: a stack, drawn on the same grid as assets/js/icons.js.
     *
     * Inline SVG rather than an icon font or an image, for the reason every other mark in the
     * panel is: the CSP allows no outside origin, and the panel ships no binary asset it could
     * point at instead.
     */
    private static function resourceMark(): string
    {
        return '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor"'
            . ' stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"'
            . ' aria-hidden="true" focusable="false">'
            . '<path d="M8 2.6c3 0 5.2.8 5.2 1.8S11 6.2 8 6.2 2.8 5.4 2.8 4.4 5 2.6 8 2.6Z"></path>'
            . '<path d="M2.8 4.4v7.2c0 1 2.2 1.8 5.2 1.8s5.2-.8 5.2-1.8V4.4"></path>'
            . '<path d="M2.8 8c0 1 2.2 1.8 5.2 1.8S13.2 9 13.2 8"></path>'
            . '</svg>';
    }

    /**
     * How many filter VALUES are applied on this page, over both filter planes.
     *
     * Counted from the payload the server already computed for the front end rather than from
     * the query string, so the badge and the dialog behind it can never disagree about what is
     * in force — they are reading the same object.
     *
     * @param array<string,mixed> $boot
     */
    private static function appliedCount(array $boot): int
    {
        $count = 0;
        foreach (['filters', 'log_filters'] as $key) {
            $active = (array) (((array) ($boot[$key] ?? []))['active'] ?? []);
            foreach ($active as $values) {
                $count += is_array($values) ? count($values) : 1;
            }
        }
        return $count;
    }

    /** The virtual host currently selected, or '' for all of them. */
    private static function chosenHost(): string
    {
        $values = Facets::all($_GET)->values(Query::HOST_FIELD);
        return $values === [] ? '' : (string) $values[0];
    }

    /**
     * The page's state as hidden fields, so submitting the bar changes one thing and keeps the rest.
     *
     * A GET form REPLACES the query string; it does not merge with it. Without these, choosing a
     * duration would drop the section, every filter, the chosen index and the outcome slice —
     * silently answering a different question under the same controls, which is the defect the
     * filter bar exists to prevent.
     *
     * The fields the bar's own controls own are excluded, or the browser would submit two values
     * for them. `f[host_s][]` is excluded only when the host selector is actually drawn; on a
     * view that does not draw one the filter still has to travel, because it is in force on the
     * pages that do.
     *
     * @param array<string,string> $fixed Parameters the form always carries as they are.
     */
    private static function hiddenState(array $fixed, bool $ownsRange, bool $ownsHost): void
    {
        $skip = [];
        if ($ownsRange) {
            $skip[] = 'range';
        }

        $params = self::stateParams($ownsHost ? [Query::HOST_FIELD] : []);
        foreach ($skip as $key) {
            unset($params[$key]);
        }
        foreach ($fixed as $key => $value) {
            if ($value !== '') {
                $params[$key] = $value;
            }
        }

        foreach (self::flatten($params) as $name => $value) {
            echo '<input type="hidden" name="' . Security::esc($name) . '"'
                . ' value="' . Security::esc($value) . '">';
        }
    }

    /**
     * A nested parameter array flattened into the `name=value` pairs a form submits.
     *
     * `f[host_s][0]` rather than `f[host_s][]`, because a hidden field has to name its index for
     * the browser to send more than one of them in a stable order, and PHP reads both spellings
     * into the same array.
     *
     * @param array<string,mixed> $params
     * @return array<string,string>
     */
    private static function flatten(array $params, string $prefix = ''): array
    {
        $out = [];
        foreach ($params as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($value)) {
                foreach (self::flatten($value, $name) as $k => $v) {
                    $out[$k] = $v;
                }
                continue;
            }
            if (is_string($value) || is_int($value)) {
                $out[$name] = (string) $value;
            }
        }
        return $out;
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
            . 'Run the connection check under <a href="' . Security::esc(self::settingsUrl('check')) . '">Settings</a>, or set '
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
                . ' <a href="' . Security::esc(self::settingsUrl('solr')) . '">'
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
                    . ' <a href="' . Security::esc(self::settingsUrl('finish')) . '">What to do</a></div>' . "\n";
            }
        }

        $errors = $cfg->validate();
        if ($errors !== []) {
            echo '<div class="banner banner-warn" role="alert"><strong>Configuration needs attention:</strong> '
                . Security::esc(implode(' · ', array_slice($errors, 0, 3)))
                . ' <a href="' . Security::esc(self::settingsUrl('')) . '">Open settings</a></div>' . "\n";
        }
    }

    /**
     * A link to one page of Settings.
     *
     * These used to be fragments — `?v=settings#set-solr` — which worked only because every
     * section of Settings was on one page. They are separate pages now, so the section is a
     * parameter; the fragment form would have landed the reader on the first Settings page with
     * an anchor that is not in the document.
     */
    public static function settingsUrl(string $section): string
    {
        return self::urlWith($section === ''
            ? ['v' => 'settings']
            : ['v' => 'settings', 's' => $section]);
    }

    /**
     * The page head: H1 and lead. The controls are in the bar above it.
     *
     * Nothing sits above the H1 in the content column — no kicker, no badge, no breadcrumb.
     * That is rule 5 of the editorial system and it is not negotiable per page. The top bar is
     * page chrome in the same class as the left sidebar, not an eyebrow on the article.
     */
    private static function header(Controller $view): void
    {
        echo '<header class="head">' . "\n";
        echo '<h1>' . Security::esc($view->title()) . '</h1>';
        echo '<p class="sub">' . Security::esc($view->subtitle()) . '</p>';
        echo "</header>\n";
    }

    /**
     * The parameters that describe the current scope, for a link or for a form.
     *
     * Four namespaces travel, and each is re-validated here rather than trusted because it
     * arrived in a URL the panel itself produced:
     *
     *  - `f[…]`  the sessions/hits filters, against Query::filterFields();
     *  - `lf[…]` the Opensolr request-log filters, against OpensolrView::logFilterFields();
     *  - `outcome` the request-log outcome slice, against its own small allowlist;
     *  - `core`  the selected Opensolr index, shape-checked as an index name;
     *  - `range` the time window, against the range table.
     *
     * @param array<int,string> $dropFields Filter fields to leave out, because the caller owns them.
     * @return array<string,mixed>
     */
    private static function stateParams(array $dropFields = []): array
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
                if (in_array($field, $dropFields, true)) {
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
                    if (!is_string($value) || $value === '') {
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

        $range = $_GET['range'] ?? null;
        if (is_string($range) && isset(Query::ranges()[$range])) {
            $params['range'] = $range;
        }

        return $params;
    }

    /**
     * Build a panel URL preserving the current scope.
     *
     * Only keys we recognise are carried over: the query string is rebuilt from scratch
     * rather than string-patched, so nothing unexpected survives a navigation.
     *
     * `s` is NOT carried automatically. A section belongs to one view, so carrying it across a
     * navigation would ask the next view for a page it does not have; every caller that means to
     * stay on a section names it.
     *
     * @param array<string,string> $overrides
     */
    public static function urlWith(array $overrides): string
    {
        $params = self::stateParams();
        foreach ($overrides as $k => $v) {
            $params[$k] = $v;
        }

        /* `f[field][]`, NEVER `f[field][0]`. http_build_query() numbers every array it is given,
           and the browser reads the filter state back with a parser that matches the empty-bracket
           spelling this product writes everywhere else (Panel\Facets::urlFor). A numbered key
           parsed as no selection at all, so after following one of these links the sidebar could
           switch a value on and never off again. The operator keeps its literal key. */
        $pairs = [];
        foreach ($params as $key => $value) {
            if (!is_array($value)) {
                $pairs[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
                continue;
            }
            foreach ($value as $field => $entries) {
                $base = (string) $key . '[' . (string) $field . ']';
                foreach ((array) $entries as $k => $entry) {
                    $suffix = $k === 'op' ? '[op]' : '[]';
                    $pairs[] = rawurlencode($base . $suffix) . '=' . rawurlencode((string) $entry);
                }
            }
        }

        return '?' . implode('&', $pairs);
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
