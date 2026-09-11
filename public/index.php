<?php
/**
 * Loghound — panel front controller.
 *
 * The only PHP file in the document root that renders the dashboard. It does five things,
 * in this order, and the order matters:
 *
 *   1. Send the security headers, before any output can commit them.
 *   2. Load configuration from OUTSIDE the document root.
 *   3. Hand over to the installer when this installation is not ready to serve. An
 *      unconfigured or half-configured Loghound never answers with a configuration error;
 *      it answers with the screen that fixes the problem.
 *   4. Hand over to the sign-in page for `?login` and `?logout`, in session mode only.
 *      These are the ONLY two routes that are allowed past step 5 unauthenticated, and
 *      neither of them can reach a view.
 *   5. Authenticate. Fails closed: with no auth configured the panel refuses to serve at
 *      all, because an analytics dashboard left open on the internet is a data breach and
 *      defaults decide outcomes.
 *   6. Enforce CSRF on anything that is not a GET or HEAD.
 *   7. Route to exactly one of the seven views, by an allowlist. There is no dynamic
 *      class resolution from the URL — a route is a key in a map, and an unknown key is a
 *      404, not an attempt to load a class named after user input.
 *
 * There is deliberately no "run this Solr query" endpoint here or anywhere else. Every
 * query the panel issues is constructed server-side by a Panel controller.
 *
 * ---------------------------------------------------------------------------------
 * THE DECISIONS BEHIND EACH STEP
 * ---------------------------------------------------------------------------------
 * HEADERS. The panel renders live operational data behind authentication, so caching any
 * of it — in a browser, in a proxy, in a back/forward cache — is wrong in every case.
 *
 * CONFIGURATION. The session cookie is hardened before any session is started, because
 * Security::csrfToken() and session auth both start one lazily. The cookie is marked Secure
 * only when the request actually arrived over TLS; marking it unconditionally would make a
 * plain-HTTP install silently lose its session on every request.
 *
 * SETUP. Once the configuration exists, has credentials and passes validation,
 * Installer::isNeeded() is false and every installer route is dead.
 *
 * SIGN-IN. In Basic mode the browser's own prompt is the sign-in, so Login::handles() is
 * false and `?login` is simply an unrecognised parameter on the dashboard. In session mode
 * the two routes are handled by Panel\Login, which enforces CSRF and the per-address
 * attempt limiter itself and always exits — a refused sign-in never falls through to the
 * authentication step below, and a successful one redirects rather than rendering.
 *
 * AUTHENTICATION is given the install prefix's var/ directory, which is where the
 * failed-attempt ledger lives, and the trusted-proxy list, without which the limiter would
 * key on the proxy's address and lock out every visitor at once.
 *
 * CSRF. The check returns immediately for GET and HEAD, and exits 403 for anything else
 * that arrives without a valid token.
 *
 * ROUTING. An unknown view is a typo or a probe, so the operator is sent to the default
 * rather than shown an error page that would tell a prober which slugs exist.
 *
 * State changes arrive as POSTs, only a view implementing JobHost accepts them, and it answers with a
 * redirect target so the browser follows POST/Redirect/GET: a refresh never re-submits, and
 * the page works with JavaScript disabled.
 *
 * The JSON data endpoints are `?v=<view>&api=<action>`. The action name is passed to the
 * view, which matches it against its own allowlist and returns 'Unknown action' for anything
 * else; it is also checked here to be a bare identifier, never a path or a field name. An
 * exception message is never leaked to the browser — it can contain a Solr URL, a credential
 * fragment or a filesystem path — and the detail goes to the error log instead. The HTML POST
 * path is held to the same rule for the same reason: an unhandled throw there would surface
 * as a PHP fatal, and with display_errors on it renders that message straight into the page.
 *
 * For HTML, the boot payload is everything the front end needs that it cannot work out for
 * itself. It carries no log-derived data; that arrives over fetch(). The timezone in it is
 * for rendering only, since Solr stores UTC. The active filters are echoed back so the front
 * end can render the "remove" chips without re-parsing the query string; they were
 * allowlisted on the way in by Controller.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Persistence;
use Loghound\Config;
use Loghound\Geo\Countries;
use Loghound\Panel\Bots;
use Loghound\Panel\Callers;
use Loghound\Panel\Controller;
use Loghound\Panel\Fingerprints;
use Loghound\Panel\Gateway;
use Loghound\Panel\Hosts;
use Loghound\Panel\Indexes;
use Loghound\Panel\JobHost;
use Loghound\Panel\Jobs;
use Loghound\Panel\Layout;
use Loghound\Panel\Login;
use Loghound\Panel\Networks;
use Loghound\Panel\Overview;
use Loghound\Panel\Performance;
use Loghound\Panel\Queries;
use Loghound\Panel\Query;
use Loghound\Panel\Sessions;
use Loghound\Panel\Settings;
use Loghound\Panel\Usage;
use Loghound\Panel\Vocabulary;
use Loghound\Security;
use Loghound\Setup\Installer;

Security::sendSecurityHeaders();

header('Cache-Control: no-store, private');

$configPath = __DIR__ . '/../config/loghound.php';
$cfg = Config::load($configPath);

/* The trusted-proxy list is read once and handed to the two places that need it before any
   session or cookie exists. Security::isHttps() is what decides whether a cookie is marked
   Secure, and behind a TLS-terminating proxy that question can only be answered from a
   forwarded header — which may be believed only when the immediate peer is a proxy this
   operator configured. */
$proxies = (array) $cfg->get('trusted_proxies', []);
Persistence::trustProxies($proxies);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => Security::isHttps($proxies),
        'path'     => '/',
    ]);
}

if (Installer::isNeeded($cfg)) {
    (new Installer($cfg, dirname(__DIR__)))->handle();
}

if (Login::handles($cfg)) {
    (new Login($cfg, dirname(__DIR__)))->handle();
}

Security::requireAuth(
    (array) $cfg->get('auth', []),
    dirname(__DIR__) . '/var',
    $proxies
);

Security::requireCsrf();

$gw = Gateway::fromConfig($cfg);

/**
 * The route table. Keys are the only values `?v=` may take.
 *
 * @var array<string,class-string<Controller>> $routes
 */
$routes = [
    'overview'     => Overview::class,
    'bots'         => Bots::class,
    'fingerprints' => Fingerprints::class,
    'networks'     => Networks::class,
    'sessions'     => Sessions::class,
    'performance'  => Performance::class,
    'hosts'        => Hosts::class,
    'indexes'      => Indexes::class,
    'queries'      => Queries::class,
    'callers'      => Callers::class,
    'usage'        => Usage::class,
    'settings'     => Settings::class,
];

$slug = $_GET['v'] ?? 'overview';
if (!is_string($slug) || !isset($routes[$slug])) {
    $slug = 'overview';
}

/** @var Controller $view */
$view = new $routes[$slug]($cfg, $gw);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    /* CLEAR CACHE, handled here rather than in a view because it belongs to no view. The
       control is in the page header of every page that reads cached data, so its POST can
       arrive with any `v=`, and the thing it clears is one installation-wide keyspace. It is a
       POST for the ordinary reason — it changes server state — and it has therefore already
       passed Security::requireCsrf() above and the authentication step before that.

       The outcome travels in the redirect rather than in a rendered response, so the browser
       follows POST/Redirect/GET and a refresh cannot clear the cache a second time. `cleared`
       is a count and `v` is re-validated against the route table, so nothing an attacker can
       put in the form reaches the Location header as text. */
    if (isset($_POST['clear_cache'])) {
        $outcome = $gw->cache()->clear();
        $target = Layout::urlWith(['v' => $slug])
            . '&cleared=' . ($outcome['cleared'] ? (string) $outcome['entries'] : 'no');
        header('Location: ' . $target, true, 303);
        exit;
    }

    if ($view instanceof JobHost) {
        try {
            $target = $view->post();
        } catch (\Throwable $e) {
            error_log('loghound/panel: POST failed: ' . Jobs::redact($e->getMessage()));
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            exit("The action could not be completed. See the server error log for details.\n");
        }
        header('Location: ' . $target, true, 303);
        exit;
    }
    http_response_code(405);
    header('Allow: GET, HEAD');
    header('Content-Type: text/plain; charset=utf-8');
    exit("This view does not accept POST.\n");
}

/* The CSV export path: `?v=<view>&export=<dataset>`.
 *
 * A READ, on a GET, behind exactly the same Security::requireAuth() gate as the JSON path
 * above — which is why it sits here rather than in a file of its own: a second entry point is a
 * second place for the authentication step to be forgotten, and this product has one door.
 * There is no CSRF token because there is nothing to protect: the request changes no state, and
 * a GET that changed state would be the defect, not the missing token.
 *
 * The slug is checked to be a bare identifier here and matched against the view's OWN declared
 * datasets in Controller::export(); an unknown one is a 404 with no list of what does exist. No
 * field list, no filter, no core name and no sort order reaches Solr from this request except
 * through the view's existing `api()` action and its allowlists.
 *
 * The response streams, so a throw after the first byte cannot become a 500 — the status is
 * already committed. It is logged, redacted, and the stream stops where it stopped; the
 * alternative is buffering the whole file to keep the option of an error page, which is the
 * memory footprint this endpoint is written to avoid. */
$export = $_GET['export'] ?? null;
if (is_string($export) && $export !== '') {
    if (!preg_match('/^[a-z0-9_-]{1,32}$/D', $export)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store, private');
        exit("This view has no such export.\n");
    }

    try {
        $view->export($export);
    } catch (Throwable $e) {
        error_log('[loghound-panel] export: ' . Jobs::redact($e->getMessage()));
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain; charset=utf-8');
            exit("The export could not be produced. See the server error log.\n");
        }
    }
    exit;
}

$action = $_GET['api'] ?? null;
if (is_string($action) && $action !== '') {
    if (!preg_match('/^[a-z_]{1,32}$/D', $action)) {
        json_out(['error' => 'Unknown action'], 400);
    }

    try {
        $payload = $view->api($action);
    } catch (Throwable $e) {
        error_log('[loghound-panel] ' . Jobs::redact($e->getMessage()));
        json_out(['error' => 'The panel could not complete that request. See the server error log.'], 500);
    }

    /* WHEN THESE NUMBERS WERE COMPUTED, on every payload without exception. Attached here
       rather than by each view because every card is entitled to it and a view that forgot
       would be presenting a two-hour-old figure as a live one — which is the same defect as a
       number that does not say what it counts, and this project already refuses that one. An
       uncached read reports `cached: false` and the current time, so the front end has one
       shape to render and no branch for installs with no cache.

       The key cannot collide with a view's own data: `cache` is set after api() has returned,
       so if a view ever used that name for something of its own the provenance would win, which
       is the right way round. */
    $payload['cache'] = $gw->cacheStamp();

    json_out($payload, isset($payload['error']) ? 400 : 200);
}

$boot = [
    'view'    => $slug,
    'range'   => Query::range(is_string($_GET['range'] ?? null) ? $_GET['range'] : null)['key'],
    'csrf'    => Security::csrfToken(),
    'demo'    => $gw->isDemo(),
    'tz'      => (string) $cfg->get('ui.timezone', 'UTC'),
    'query'   => $_SERVER['QUERY_STRING'] ?? '',
    'labels'  => Query::populationLabels(),

    /* ONE country table, served once. Every surface in the panel shows a country as its flag
       and its full English name — a facet list of `SC VE ZA` names nothing a reader knows —
       and the mapping is Geo\Countries, in PHP, so there is exactly one of it. The browser
       gets it here rather than shipping a second copy inside a module, which is how the two
       drift. It is about 4 KB and the page is behind authentication and never cached. */
    'countries' => Countries::all(),

    /* ONE vocabulary table, on the same reasoning as the countries above. A verdict is stored as
       `likely_human`, a fired signal as `fp_cluster_proxy_fleet`, a network type as `hosting`:
       the right things to store, to filter on and to grep for, and the wrong things to print at
       somebody who has not read src/Score/Rules.php. Panel\Vocabulary is the authority for the
       words and for which values exist; assets/js/icons.js is the authority for the MARK in
       front of one and for nothing else. */
    'vocabulary' => Vocabulary::all(),

    /* The whole filter state, straight from the one component that owns it: which values are
       selected on each dimension, the boolean operator in force, and which operators that
       dimension can offer. This used to be re-parsed out of `$_GET['f']` right here, which was a
       fourth copy of the reading rules and knew nothing about the operator. */
    'filters' => $view->facetLayer()->payload(),
    'dimensions' => Query::filterFields(),

    /* Which page-toolbar controls this view actually honours, straight from the view
       itself. The host selector and the filter bar are injected by the front end, so the
       decision Controller::toolbar() makes has to reach the browser; without this the
       two JS-injected controls would still appear on pages that ignore them, which is
       half the defect fixed and the visible half left in place. */
    'toolbar' => $view->toolbar(),

    /* What the page needs to render the Clear cache control and the line that follows a press.
       Only three facts travel: whether the cache is actually working (so a page with nothing to
       clear does not advertise a button that would do nothing), how long an entry lives (so the
       control can say what it is undoing), and the outcome of the press that just redirected
       here. The server address and the failure reason stay out of the boot payload — they are
       the Settings page's business, and the fewer places a hostname appears the better. */
    'cache' => [
        'enabled' => $gw->cache()->isEnabled(),
        'ttl'     => $gw->cache()->ttl(),
        'cleared' => (static function () {
            $v = $_GET['cleared'] ?? null;
            if ($v === 'no') {
                return -1;
            }
            return is_string($v) && preg_match('/^\d{1,9}$/D', $v) === 1 ? (int) $v : null;
        })(),
    ],
];

header('Content-Type: text/html; charset=utf-8');
Layout::render($cfg, $gw, $view, $boot);

/**
 * Emit a JSON response and stop.
 *
 * JSON_HEX_TAG is set for the same reason Security::escJs sets it: a User-Agent
 * containing "</script>" must not be able to do anything if this response is ever
 * rendered somewhere it should not be. `nosniff` is already set by sendSecurityHeaders().
 *
 * @param array<string,mixed> $payload
 * @return never
 */
function json_out(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    echo json_encode(
        $payload,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
    );
    exit;
}
