<?php
/**
 * Loghound — the sign-in page, the second-factor step, and the sign-out route.
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
 *   2. CSRF ON EVERY POST, like every other state-changing request in the project. A sign-in
 *      form that can be submitted cross-origin lets a third party log the operator into an
 *      account of the attacker's choosing, and a sign-out that can be triggered by an
 *      image tag is a nuisance vector.
 *   3. RATE LIMITED BEFORE THE PASSWORD IS EVEN LOOKED AT, by the same per-address
 *      fixed-window ledger Basic mode uses (Security::loginGate). Fails closed: a ledger
 *      that cannot be consulted refuses the sign-in rather than allowing it. The second
 *      factor is behind the same gate, and so is the persistent-login cookie.
 *   4. THE SESSION ID CHANGES AT EVERY STEP. Security::sessionSignIn() and sessionPending()
 *      both regenerate it before writing anything, so a planted id is worthless at the first
 *      step as well as the last.
 *   5. NO OPEN REDIRECT. Success always goes to the dashboard at a fixed relative URL.
 *      There is no `next` parameter to smuggle an off-site destination through, which is
 *      the usual way a sign-in page becomes a phishing hop.
 *   6. THE FORM NEVER SAYS WHICH HALF WAS WRONG. One message for a bad username and a bad
 *      password alike, so the form cannot be used to enumerate account names.
 *   7. THE ATTEMPT COUNTER IS ONLY CLEARED BY A COMPLETE SIGN-IN. With a second factor
 *      configured, a correct password alone must not reset the lockout — otherwise anyone
 *      holding the password would get unlimited guesses at the six digits.
 *
 * WHY A CSRF FAILURE ON THIS FORM WAS REPORTED ON A SIGN-IN THAT WORKED
 *
 * Security::sessionSignIn() calls rotateCsrf(), so the instant a sign-in succeeds the token in
 * the form that produced it is dead. doLogin() then ran requireCsrf() before looking at whether
 * the caller was already signed in — so a second submission of that same form (a double-click
 * whose second request lands after the first response, a tab the browser restored, the form
 * still sitting in another window) arrived with a stale token on a session that was by then
 * perfectly authenticated, and was answered with "CSRF token mismatch" while the operator was
 * in fact signed in and Settings worked.
 *
 * THE FIX IS NOT TO ACCEPT A BAD TOKEN. It is to stop generating the situation: a POST to this
 * page from a session that is ALREADY signed in is redirected to the panel before the token is
 * examined, because the work that POST was asking for is done. Nothing is relaxed for anyone
 * who is not signed in — a request without a valid session cookie still meets requireCsrf()
 * and still gets its 403. tests/test_auth.php pins both halves.
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

use Loghound\Auth\Persistence;
use Loghound\Auth\TwoFactor;
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
     * Serve the sign-in page, a sign-in attempt, the second-factor step, or the sign-out.
     *
     * `no-store` is sent first and unconditionally. It is what stops a browser re-presenting a
     * form whose CSRF token has since been rotated, and Security now starts every session with
     * the cache limiter disabled so that PHP cannot replace this header with a weaker one of
     * its own — on a pool configured with `session.cache_limiter = private` it replaced it with
     * `private, max-age=10800`, which made this page cacheable for three hours.
     *
     * A VISITOR CARRYING A "STAY SIGNED IN" COOKIE IS SENT TO THE PANEL RATHER THAN SHOWN A
     * FORM. This route runs before Security::requireAuth(), so it is the one place a remembered
     * browser could be asked to sign in again — which is the single thing the option exists to
     * prevent. The bounce cannot loop: if the token turns out to be stale, revoked or replayed,
     * Persistence::consume() clears the cookie before requireAuth sends the browser back here,
     * so the second pass has no cookie and renders the form.
     *
     * @return never
     */
    public function handle(): void
    {
        header('Cache-Control: no-store, private');
        header('Pragma: no-cache');
        header('X-Robots-Tag: noindex, nofollow');

        if (isset($_GET['logout'])) {
            $this->doLogout();
        }

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
            $this->doPost();
        }

        if (Security::sessionResume() && Security::sessionUser() !== '') {
            $this->go('./?v=overview');
        }

        if (Security::pendingUser() !== '') {
            $this->secondFactorForm($this->reason());
            exit;
        }

        if (Persistence::present()) {
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
     * EVERY PERSISTENT-LOGIN TOKEN GOES TOO, not only the one this browser presented. There is
     * one operator, and "sign me out" from somebody who has chosen to stay signed in
     * indefinitely can only reasonably mean "everywhere" — a sign-out that left another browser
     * profile signed in for the next decade would be a sign-out in name only. It is also the
     * only revocation available without shell access, so it has to be the complete one.
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
        Persistence::revokeAll($this->varDir());
        Security::sessionSignOut();

        $this->go('./?login=1&why=out');
    }

    /**
     * Dispatch a POST to this page.
     *
     * THE ORDER OF THE FIRST TWO CHECKS IS THE WHOLE CSRF FIX. An already-authenticated session
     * is redirected to the panel before the token is looked at, because the POST is asking for
     * something that has already happened. It is not a bypass: no password is checked, no state
     * changes, nothing is written — it is a 303 to a dashboard the caller's own session already
     * grants. Everyone else meets requireCsrf() unchanged.
     *
     * @return never
     */
    private function doPost(): void
    {
        if (Security::sessionResume() && Security::sessionUser() !== '') {
            $this->go('./?v=overview');
        }

        Security::requireCsrf();

        if (is_string($_POST['code'] ?? null) && Security::pendingUser() !== '') {
            $this->doSecondFactor();
        }

        $this->doLogin();
    }

    /**
     * Check a submitted username and password.
     *
     * The order is deliberate: CSRF (in doPost), then the rate limiter, then the password.
     * Checking the password first would let an attacker measure whether a guess was right
     * before the limiter ever refused them.
     *
     * A correct password does NOT finish the job when a second factor is configured. It moves
     * the session into the pending state — which grants access to nothing — and the operator is
     * sent to the code form. Nor does it clear the address's failed attempts: that happens only
     * in finish(), when the sign-in is actually complete.
     *
     * @return never
     */
    private function doLogin(): void
    {
        $auth = (array) $this->cfg->get('auth', []);
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));
        $varDir = $this->varDir();

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
        $remember = Persistence::requested();

        if (!Security::verifyPassword($auth, $user, $pass)) {
            Security::loginFailure($ip, $auth, $varDir);
            usleep(random_int(150000, 400000));
            http_response_code(401);
            $this->form('bad');
            exit;
        }

        $account = (string) ($auth['user'] ?? $user);

        if (TwoFactor::isEnabled($auth)) {
            Security::sessionPending($account, $remember);
            $this->go('./?login=1');
        }

        $this->finish($account, $remember, $auth, $ip, $varDir);
    }

    /**
     * Check a submitted second factor, and finish the sign-in when it is right.
     *
     * A TOTP code or a recovery code; TwoFactor::check() decides which was presented and
     * consumes a recovery code when it accepts one. Both are rate limited on the same ledger as
     * the password, because both are guessable in a way a password is not: six digits is a
     * million possibilities, and the lockout is what makes that a wall.
     *
     * A CONSUMED RECOVERY CODE MUST REACH DISK BEFORE IT LETS ANYBODY IN. If the config write
     * fails, the code would still be valid and could be replayed, so the sign-in is refused
     * instead — the operator sees a storage error and their remaining codes are intact.
     *
     * @return never
     */
    private function doSecondFactor(): void
    {
        $auth = (array) $this->cfg->get('auth', []);
        $ip = Security::clientIp((array) $this->cfg->get('trusted_proxies', []));
        $varDir = $this->varDir();

        $gate = Security::loginGate($ip, $auth, $varDir);
        if (!$gate['available']) {
            http_response_code(503);
            $this->secondFactorForm('store');
            exit;
        }
        if (!$gate['allowed']) {
            http_response_code(429);
            header('Retry-After: ' . max(1, $gate['retry']));
            $this->secondFactorForm('locked', $gate['retry']);
            exit;
        }

        $pending = Security::pendingUser();
        if ($pending === '') {
            Security::clearPending();
            http_response_code(401);
            $this->form('stale');
            exit;
        }

        $code = is_string($_POST['code'] ?? null) ? $_POST['code'] : '';
        $kind = TwoFactor::check($this->cfg, $code, $varDir);

        if ($kind === 'no') {
            Security::loginFailure($ip, $auth, $varDir);
            usleep(random_int(150000, 400000));
            http_response_code(401);
            $this->secondFactorForm('badcode');
            exit;
        }

        if ($kind === 'recovery') {
            try {
                $this->cfg->save();
            } catch (\Throwable $e) {
                error_log('loghound/login: could not record a used recovery code: ' . $e->getMessage());
                http_response_code(503);
                $this->secondFactorForm('store');
                exit;
            }
        }

        $this->finish($pending, Security::pendingRemember(), $auth, $ip, $varDir);
    }

    /**
     * Sign the operator in, having satisfied every factor that is configured.
     *
     * The attempt counter is cleared here and only here, and the persistent-login token is
     * issued here and only here — both for the same reason: this is the first point at which
     * the sign-in is actually complete.
     *
     * NOT TICKING THE BOX REVOKES. An operator who signs in with "stay signed in" unticked has
     * said they do not want to be remembered, so any token from a previous sign-in in this
     * browser is destroyed. Leaving it would mean their next idle timeout silently handed them
     * back a permanent session they had just declined, which is the opposite of what the
     * unticked box says.
     *
     * A token store that cannot be written does not fail the sign-in — the operator is signed in
     * and told that this browser will not be remembered. Failing a whole sign-in over an
     * unwritable var/ would lock somebody out of their panel over a convenience feature.
     *
     * @param array<string,mixed> $auth
     * @return never
     */
    private function finish(string $user, bool $remember, array $auth, string $ip, ?string $varDir): void
    {
        Security::sessionSignIn($user, $remember);
        Security::loginSuccess($ip, $auth, $varDir);
        Persistence::takeAlert($varDir);

        if (!$remember) {
            Persistence::revokeAll($varDir);
            $this->go('./?v=overview');
        }

        if (!Persistence::issue($user, $varDir, Persistence::lifetime($auth))) {
            $this->go('./?v=overview&err=remember_failed');
        }

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
            'badcode' => [
                'kind' => 'bad',
                'text' => 'That code was not right. Enter the current code from your authenticator app, '
                    . 'or one of your recovery codes.',
            ],
            'idle' => [
                'kind' => 'warn',
                'text' => 'You were signed out because nothing happened for a while. Sign in to carry on.',
            ],
            'absolute' => [
                'kind' => 'warn',
                'text' => 'Your session reached its maximum age and was ended. Sign in again.',
            ],
            'stale' => [
                'kind' => 'warn',
                'text' => 'That sign-in took too long to finish. Enter your username and password again.',
            ],
            'out' => [
                'kind' => 'good',
                'text' => 'Signed out. The session was destroyed on the server, not just in this browser, '
                    . 'and every "stay signed in" token was revoked.',
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

        $this->head('Sign in — ' . $siteName, 'Sign in to ' . $siteName);

        echo '<p class="setup-lead">This panel shows every visitor, page and address on your site, '
            . 'so it is never served without a password.</p>' . "\n";

        $this->theftWarning();
        $this->message($why, $retry);

        echo '<form method="post" action="?login=1" class="card setup-form login-form">';
        echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';

        echo '<label for="user">Username</label>';
        echo '<input type="text" id="user" name="user" size="28" autocomplete="username" '
            . 'autocapitalize="none" spellcheck="false" required autofocus>';

        echo '<label for="password">Password</label>';
        echo '<input type="password" id="password" name="password" size="28" '
            . 'autocomplete="current-password" required>';

        echo '<label class="check"><input type="checkbox" id="remember" name="'
            . Security::esc(Persistence::FIELD) . '" value="1">'
            . '<span>Stay signed in on this browser</span></label>';
        echo '<p class="setup-widen">Keeps you signed in after you close the browser or restart the '
            . 'machine, with no timeout at all. Whoever has this browser profile stays signed in to this '
            . 'panel indefinitely, and the only way back out is the Sign out button. Leave it unticked on '
            . 'a shared or portable machine.</p>';

        echo '<button type="submit" class="primary">Sign in</button>';
        echo '</form>' . "\n";

        echo '<p class="muted login-note">Forgotten it? There is no reset by email — Loghound has no '
            . 'mail path and would not use one for this. Run <code>'
            . Security::esc($this->root . '/bin/loghound-setup')
            . '</code> on the server and answer yes when it offers to set a new username and password. '
            . 'Being able to run that is already proof enough of who you are.</p>' . "\n";

        $this->foot();
    }

    /**
     * Render the second-factor step.
     *
     * A page of its own rather than a field on the sign-in form, because the two are separate
     * decisions: the password is checked before this is ever shown, and the session that shows
     * it is authenticated for nothing. The field is `inputmode="numeric"` and
     * `autocomplete="one-time-code"` so that a phone offers the code it has just received and a
     * password manager does not try to fill it with a username.
     *
     * Recovery codes go in the same field. A six-digit string and a sixteen-character one cannot
     * be confused, and a second field would be one more thing to explain on the screen an
     * operator reaches when they have already lost their phone.
     */
    private function secondFactorForm(string $why = '', int $retry = 0): void
    {
        $siteName = (string) $this->cfg->get('site_name', 'Loghound');

        $this->head('Two-factor code — ' . $siteName, 'Two-factor code');

        echo '<p class="setup-lead">Your password was accepted. Enter the current code from your '
            . 'authenticator app to finish signing in.</p>' . "\n";

        $this->message($why, $retry);

        echo '<form method="post" action="?login=1" class="card setup-form login-form">';
        echo '<input type="hidden" name="csrf" value="' . Security::esc(Security::csrfToken()) . '">';

        echo '<label for="code">Six-digit code</label>';
        echo '<input type="text" id="code" name="code" size="14" inputmode="numeric" '
            . 'autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" required autofocus>';

        echo '<button type="submit" class="primary">Finish signing in</button>';
        echo '</form>' . "\n";

        echo '<p class="muted login-note">Lost the phone? Type one of the recovery codes you saved when '
            . 'you turned two-factor on into the same field. Each one works once. If those are gone too, '
            . 'run <code>' . Security::esc($this->root . '/bin/loghound-setup')
            . '</code> on the server to set a new password, which also turns two-factor off.</p>' . "\n";

        $this->foot();
    }

    /**
     * The warning shown when a persistent-login token was replayed.
     *
     * Told here because the sign-in page is the screen the operator is guaranteed to see next,
     * and because there is no mail path in this project to tell them any other way. The sentence
     * names no address, no time and no username, so what a passing stranger can learn from it is
     * that this installation offers "stay signed in" and once saw a token replayed — which is
     * worth less than the operator not being told at all. The flag is cleared by the next
     * successful sign-in rather than by rendering, so a bot hitting the login page cannot erase
     * the warning before the operator reads it.
     */
    private function theftWarning(): void
    {
        if (!Persistence::hasAlert($this->varDir())) {
            return;
        }

        echo '<div class="banner banner-bad" role="alert">'
            . Security::esc(
                'A "stay signed in" token for this panel was presented twice. That can only happen if a '
                . 'copy of it was taken, so every one of those tokens has been destroyed and every browser '
                . 'has to sign in again. Sign in now, then change your password with bin/loghound-setup if '
                . 'you cannot account for it.'
            )
            . "</div>\n";
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
                . 'To clear it now, delete ' . Security::ledgerPath($this->varDir()) . ' on the server.';
        }

        $class = 'banner-' . ($messages[$why]['kind'] === 'good' ? 'good'
            : ($messages[$why]['kind'] === 'warn' ? 'warn' : 'bad'));
        $role = $messages[$why]['kind'] === 'good' ? 'status' : 'alert';

        echo '<div class="banner ' . $class . '" role="' . $role . '">'
            . Security::esc($text) . "</div>\n";
    }

    /**
     * The page shell down to the heading.
     *
     * Shared by the two forms so they cannot drift apart in anything but their content, and so
     * that neither of them can accidentally load the panel's application JavaScript.
     */
    private function head(string $title, string $heading): void
    {
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
        echo '<title>' . Security::esc($title) . '</title>' . "\n";
        echo '<meta name="theme-color" content="#ffffff" media="(prefers-color-scheme: light)">' . "\n";
        echo '<meta name="theme-color" content="#111111" media="(prefers-color-scheme: dark)">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/panel.css')) . '">' . "\n";
        echo '<link rel="stylesheet" href="' . Security::esc($asset('assets/css/mobile.css')) . '">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.svg')) . '" type="image/svg+xml">' . "\n";
        echo '<link rel="icon" href="' . Security::esc($asset('favicon.ico')) . '" sizes="any">' . "\n";
        echo '<link rel="apple-touch-icon" href="' . Security::esc($asset('apple-touch-icon.png')) . '">' . "\n";
        echo '<script src="' . Security::esc($asset('assets/js/theme.js')) . '"></script>' . "\n";
        echo '<script type="module" src="' . Security::esc($asset('assets/js/responsive.js')) . '"></script>' . "\n";
        echo "</head>\n<body class=\"setup-body\">\n";

        echo '<main class="setup login" id="main">' . "\n";
        echo '<h1>' . Security::esc($heading) . '</h1>' . "\n";
    }

    /** The footer and the closing tags. */
    private function foot(): void
    {
        $siteName = (string) $this->cfg->get('site_name', 'Loghound');

        echo '<footer class="foot"><span>' . Security::esc($siteName) . '</span>';
        echo '<span class="mono">' . Security::esc(gmdate('m/d/Y H:i:s')) . ' UTC</span></footer>' . "\n";

        echo "</main>\n</body>\n</html>\n";
    }

    /** Where this installation's authentication state lives. */
    private function varDir(): string
    {
        return $this->root . '/var';
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
