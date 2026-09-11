<?php
/**
 * Loghound — the sign-in page and the sign-out route.
 *
 * WHAT THIS IS FOR
 *
 * `auth.mode = 'session'` used to be a value the configuration accepted and nothing
 * implemented: an operator who chose it got a panel that answered 403 forever, with no
 * form to sign in with and no route back. This is the missing half — the only place in
 * the project that turns a password into a signed-in session.
 *
 * THE SECURITY MODEL
 *
 *   1. REACHABLE WITHOUT AUTHENTICATION, AND ONLY THIS. The front controller lets `?login`
 *      and `?logout` past Security::requireAuth() and nothing else. Both are handled here
 *      and both exit; there is no path from this file into a panel view.
 *   2. CSRF ON THE POST, like every other state-changing request in the project. A sign-in
 *      form that can be submitted cross-origin lets a third party log the operator into an
 *      account of the attacker's choosing, and a sign-out that can be triggered by an
 *      image tag is a nuisance vector.
 *   3. RATE LIMITED BEFORE THE PASSWORD IS EVEN LOOKED AT, by the same per-address
 *      fixed-window ledger Basic mode uses (Security::loginGate). Fails closed: a ledger
 *      that cannot be consulted refuses the sign-in rather than allowing it.
 *   4. THE SESSION ID CHANGES AT SIGN-IN. Security::sessionSignIn() regenerates it before
 *      writing the identity, so a planted id is worthless.
 *   5. NO OPEN REDIRECT. Success always goes to the dashboard at a fixed relative URL.
 *      There is no `next` parameter to smuggle an off-site destination through, which is
 *      the usual way a sign-in page becomes a phishing hop.
 *   6. THE FORM NEVER SAYS WHICH HALF WAS WRONG. One message for a bad username and a bad
 *      password alike, so the form cannot be used to enumerate account names.
 *
 * The page is rendered here rather than through Panel\Layout because the layout carries
 * the navigation, the range picker and the data-fetching front end — every one of which
 * belongs to a signed-in operator. A sign-in page that loads the panel's application code
 * is a sign-in page that ships its own attack surface.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Config;
use Loghound\Security;

final class Login
{
    private Config $cfg;

    private string $root;

    /**
     * @param string $root The installation prefix; var/ under it holds the attempt ledger.
     */
    public function __construct(Config $cfg, string $root)
    {
        $this->cfg  = $cfg;
        $this->root = rtrim($root, '/');
    }

    /**
     * Is this request one of ours?
     *
     * Only in session mode. In Basic mode the browser's own prompt is the sign-in and
     * there is nothing to sign out of, so `?login` there is just an unrecognised query
     * parameter on the dashboard and is treated as one.
     */
    public static function handles(Config $cfg): bool
    {
        if ((string) $cfg->get('auth.mode', 'none') !== 'session') {
            return false;
        }
        return isset($_GET['login']) || isset($_GET['logout']);
    }

    /**
     * Serve the sign-in page, the sign-in attempt, or the sign-out, and stop.
     *
     * @return never
     */
    public function handle(): void
    {
        header('Cache-Control: no-store, private');
        header('X-Robots-Tag: noindex, nofollow');

        if (isset($_GET['logout'])) {
            $this->doLogout();
        }

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $this->doLogin();
        }

        if (Security::sessionResume() && Security::sessionUser() !== '') {
            $this->go('./?v=overview');
        }

        $this->form($this->reason());
        exit;
    }

    /**
     * End the session and return to the sign-in page.
     *
     * POST only, with a CSRF token: sign-out changes state, and a GET route would let any
     * page on the internet end the operator's session with an <img> tag. The session is
     * destroyed even when it had already expired, so the button always does what it says
     * rather than depending on the session still being valid.
     *
     * @return never
     */
    private function doLogout(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
            http_response_code(405);
            header('Allow: POST');
            header('Content-Type: text/plain; charset=utf-8');
            exit("Sign out is a POST.\n");
        }

        Security::requireCsrf();
        Security::sessionSignOut();

        $this->go('./?login=1&why=out');
    }

    /**
     * Check a submitted username and password.
     *
     * The order is deliberate: CSRF, then the rate limiter, then the password. Checking
     * the password first would let an attacker measure whether a guess was right before
     * the limiter ever refused them.
     *
     * @return never
     */
    private function doLogin(): void
    {
        Security::requireCsrf();

        $auth = (array) $this->cfg->get('auth', []);
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));
        $varDir = $this->root . '/var';

        $gate = Security::loginGate($ip, $auth, $varDir);
        if (!$gate['available']) {
            http_response_code(503);
            $this->form('store');
            exit;
        }
        if (!$gate['allowed']) {
            http_response_code(429);
            header('Retry-After: ' . max(1, $gate['retry']));
            $this->form('locked', $gate['retry']);
            exit;
        }

        $user = is_string($_POST['user'] ?? null) ? $_POST['user'] : '';
        $pass = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';

        if (!Security::verifyPassword($auth, $user, $pass)) {
            Security::loginFailure($ip, $auth, $varDir);
            usleep(random_int(150000, 400000));
            http_response_code(401);
            $this->form('bad');
            exit;
        }

        if ($gate['count'] > 0) {
            Security::loginSuccess($ip, $auth, $varDir);
        }
        Security::sessionSignIn((string) ($auth['user'] ?? $user));

        $this->go('./?v=overview');
    }

    /**
     * Which message the sign-in page should carry, from an allowlist.
     *
     * The value arrives in the query string, so it is matched against the known keys and
     * the KEY is what selects the sentence. Nothing from the URL is ever echoed.
     */
    private function reason(): string
    {
        $why = is_string($_GET['why'] ?? null) ? $_GET['why'] : '';
        return isset(self::messages()[$why]) ? $why : '';
    }

    /**
     * Every sentence this page can show, keyed.
     *
     * @return array<string,array{kind:string,text:string}>
     */
    private static function messages(): array
    {
        return [
            'bad' => [
                'kind' => 'bad',
                'text' => 'That username and password did not match. Try again.',
            ],
            'idle' => [
                'kind' => 'warn',
                'text' => 'You were signed out because nothing happened for a while. Sign in to carry on.',
            ],
            'absolute' => [
                'kind' => 'warn',
                'text' => 'Your session reached its maximum age and was ended. Sign in again.',
            ],
            'out' => [
                'kind' => 'good',
                'text' => 'Signed out. The session was destroyed on the server, not just in this browser.',
            ],
            'locked' => [
                'kind' => 'bad',
                'text' => 'Too many failed sign-in attempts from your address.',
            ],
            'store' => [
                'kind' => 'bad',
                'text' => 'Loghound cannot record failed sign-in attempts, because it cannot write to its '
                    . 'var directory. It refuses to sign anyone in rather than skip the check — give that '
                    . 'directory to the user this panel runs as.',
            ],
        ];
    }

    /**
     * Render the sign-in page.
     *
     * The panel's own stylesheet and the installer's page shell, so this is recognisably
     * the same product rather than a bare form. No inline script and no inline event
     * handler: the panel's CSP has no 'unsafe-inline' for scripts and this page lives
     * inside it like every other.
     *
     * @param string $why   A key from messages(), or '' for no message.
     * @param int    $retry Seconds until a lockout lifts, when $why is 'locked'.
     */
    private function form(string $why = '', int $retry = 0): void
    {
        $siteName = (string) $this->cfg->get('site_name', 'Loghound');
        $csrf = Security::csrfToken();

        $asset = function (string $rel): string {
            $path = $this->root . '/public/' . $rel;
            return $rel . '?v=' . (is_file($path) ? (string) filemtime($path) : '0');
        };

        header('Content-Type: text/html; charset=utf-8');

        echo "<!doctype html>\n";
        echo '<html lang="en" data-theme="auto">' . "\n<head>\n";
        echo '<meta charset="utf-8">' . "\n";
        echo '<meta name="viewport" content="width=device-width, initial-scale=1">' . "\n";
        echo '<meta name="robots" content="noindex, nofollow">' . "\n";
        echo '<title>' . Security::esc('Sign in — ' . $siteName) . '</title>' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/panel.css')) . '">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.svg')) . '" type="image/svg+xml">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.ico')) . '" sizes="any">' . "\n";
        echo '<link rel="apple-touch-icon" href="' . Security::esc($asset('apple-touch-icon.png')) . '">' . "\n";
        echo '<script src="' . Security::esc($asset('assets/js/theme.js')) . '"></script>' . "\n";
        echo "</head>\n<body class=\"setup-body\">\n";

        echo '<main class="setup login" id="main">' . "\n";
        echo '<h1>' . Security::esc('Sign in to ' . $siteName) . '</h1>' . "\n";
        echo '<p class="setup-lead">This panel shows every visitor, page and address on your site, '
            . 'so it is never served without a password.</p>' . "\n";

        $this->message($why, $retry);

        echo '<form method="post" action="?login=1" class="card setup-form login-form">';
        echo '<input type="hidden" name="csrf" value="' . Security::esc($csrf) . '">';

        echo '<label for="user">Username</label>';
        echo '<input type="text" id="user" name="user" size="28" autocomplete="username" '
            . 'autocapitalize="none" spellcheck="false" required autofocus>';

        echo '<label for="password">Password</label>';
        echo '<input type="password" id="password" name="password" size="28" '
            . 'autocomplete="current-password" required>';

        echo '<button type="submit" class="primary">Sign in</button>';
        echo '</form>' . "\n";

        echo '<p class="muted login-note">Forgotten it? There is no reset by email — Loghound has no '
            . 'mail path and would not use one for this. Run <code>'
            . Security::esc($this->root . '/bin/loghound-setup')
            . '</code> on the server and answer yes when it offers to set a new username and password. '
            . 'Being able to run that is already proof enough of who you are.</p>' . "\n";

        echo '<footer class="foot"><span>' . Security::esc($siteName) . '</span>';
        echo '<span class="mono">' . Security::esc(gmdate('m/d/Y H:i:s')) . ' UTC</span></footer>' . "\n";

        echo "</main>\n</body>\n</html>\n";
    }

    /**
     * The banner above the form, if this render has something to say.
     *
     * The lockout sentence gets the remaining time appended and the real mechanism named.
     * The old setup-token limiter tells operators to "restart PHP-FPM to clear the
     * counter", which has never been true — the counter is a file, and a restart does
     * nothing to it. Saying so here would be the same lie in a second place.
     */
    private function message(string $why, int $retry): void
    {
        $messages = self::messages();
        if (!isset($messages[$why])) {
            return;
        }

        $text = $messages[$why]['text'];
        if ($why === 'locked') {
            $text .= ' Try again in ' . max(1, (int) ceil($retry / 60)) . ' minute(s). '
                . 'To clear it now, delete ' . Security::ledgerPath($this->root . '/var') . ' on the server.';
        }

        $class = 'banner-' . ($messages[$why]['kind'] === 'good' ? 'good'
            : ($messages[$why]['kind'] === 'warn' ? 'warn' : 'bad'));
        $role = $messages[$why]['kind'] === 'good' ? 'status' : 'alert';

        echo '<div class="banner ' . $class . '" role="' . $role . '">'
            . Security::esc($text) . "</div>\n";
    }

    /**
     * Redirect to a fixed relative destination and stop.
     *
     * Every caller passes a literal. Nothing from the request reaches this, which is what
     * keeps a sign-in page from becoming an open redirect.
     *
     * @return never
     */
    private function go(string $to): void
    {
        header('Location: ' . $to, true, 303);
        exit;
    }
}
