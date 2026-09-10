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
 *   4. Authenticate. Fails closed: with no auth configured the panel refuses to serve at
 *      all, because an analytics dashboard left open on the internet is a data breach and
 *      defaults decide outcomes.
 *   5. Enforce CSRF on anything that is not a GET or HEAD.
 *   6. Route to exactly one of the seven views, by an allowlist. There is no dynamic
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
 * CSRF. The check returns immediately for GET and HEAD, and exits 403 for anything else
 * that arrives without a valid token.
 *
 * ROUTING. An unknown view is a typo or a probe, so the operator is sent to the default
 * rather than shown an error page that would tell a prober which slugs exist.
 *
 * State changes arrive as POSTs, only the Settings view accepts them, and it answers with a
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

use Loghound\Config;
use Loghound\Panel\Bots;
use Loghound\Panel\Controller;
use Loghound\Panel\Fingerprints;
use Loghound\Panel\Gateway;
use Loghound\Panel\Layout;
use Loghound\Panel\Networks;
use Loghound\Panel\Overview;
use Loghound\Panel\Performance;
use Loghound\Panel\Query;
use Loghound\Panel\Sessions;
use Loghound\Panel\Settings;
use Loghound\Security;
use Loghound\Setup\Installer;

Security::sendSecurityHeaders();

header('Cache-Control: no-store, private');

$configPath = __DIR__ . '/../config/loghound.php';
$cfg = Config::load($configPath);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => (($_SERVER['HTTPS'] ?? '') !== ''),
        'path'     => '/',
    ]);
}

if (Installer::isNeeded($cfg)) {
    (new Installer($cfg, dirname(__DIR__)))->handle();
}

Security::requireAuth((array) $cfg->get('auth', []));

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
    'settings'     => Settings::class,
];

$slug = $_GET['v'] ?? 'overview';
if (!is_string($slug) || !isset($routes[$slug])) {
    $slug = 'overview';
}

/** @var Controller $view */
$view = new $routes[$slug]($cfg, $gw);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    if ($view instanceof Settings) {
        try {
            $target = $view->post();
        } catch (\Throwable $e) {
            error_log('loghound/panel: POST failed: ' . $e->getMessage());
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

$action = $_GET['api'] ?? null;
if (is_string($action) && $action !== '') {
    if (!preg_match('/^[a-z_]{1,32}$/', $action)) {
        json_out(['error' => 'Unknown action'], 400);
    }

    try {
        $payload = $view->api($action);
    } catch (Throwable $e) {
        error_log('[loghound-panel] ' . $e->getMessage());
        json_out(['error' => 'The panel could not complete that request. See the server error log.'], 500);
    }

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
    'filters' => (function (): array {
        $out = [];
        $allowed = Query::filterFields();
        foreach ((array) ($_GET['f'] ?? []) as $field => $values) {
            if (is_string($field) && isset($allowed[$field])) {
                $out[$field] = array_values(array_filter((array) $values, 'is_string'));
            }
        }
        return $out;
    })(),
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
