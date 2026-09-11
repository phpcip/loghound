<?php
/**
 * Loghound — every instruction the installer gives can actually be followed.
 *
 * THE CLASS OF BUG THIS FILE IS ABOUT. Not a crash, not a wrong number: a control that does
 * nothing, and an instruction that cannot be carried out. A UI sweep measured eight of them at
 * once, and three were on the first screen anybody sees:
 *
 *  - all four "Fix this" links on the status page returned a byte-identical page while setup
 *    was locked, because every `?setup=<step>` was clamped to the status page and the clamp
 *    said nothing about why;
 *  - one of those four offered to fix a thing its own sentence said needs no fixing;
 *  - a forward jump was bounced in the same silence, even when unlocked;
 *  - three lines of English sat inside a `<pre>` that the panel renders with a Copy button, so
 *    anyone who used the button pasted prose into a shell;
 *  - the command to install a newer PHP named a hardcoded series;
 *  - a refusal told the operator to run `bin/loghound-setup` — relative, so it works from one
 *    directory and, on a machine with two checkouts, configures the wrong installation;
 *  - the beacon card told the operator to hand-edit `base_url` in a file while the input for
 *    it was fifty lines up the same screen, where the form was about to overwrite it.
 *
 * A screenshot cannot catch any of these and neither can a type checker. What catches them is
 * asking, of each rendered instruction: is there a thing to press, does pressing it go
 * somewhere, and would the line survive being pasted where the page implies it should be.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\Setup\Detector;
use Loghound\Setup\Installer;
use Loghound\Setup\Requirements;
use Loghound\Setup\Steps;
use Loghound\Setup\Token;
use Loghound\Setup\View;

/** The repository root. */
function lh_ins_root(): string
{
    return dirname(__DIR__);
}

/**
 * A throwaway installation with nothing configured — the state the status page is for.
 *
 * @return array{0:string,1:Config}
 */
function lh_ins_install(): array
{
    $dir = lh_tmpdir('lh-instr');
    @mkdir($dir . '/config', 0750, true);
    @mkdir($dir . '/var', 0750, true);

    return [$dir, Config::load($dir . '/config/loghound.php')];
}

/**
 * Render the installer's status page and hand back the HTML.
 *
 * The real View against a real Config, because the defect being pinned is in what the page
 * emits — a stub that returned markup would be testing the stub.
 */
function lh_ins_status(Config $cfg, bool $unlocked, string $bounced = ''): string
{
    $root = lh_ins_root();
    $view = new View(
        $cfg,
        $root,
        new Requirements($root, $cfg),
        new Token(dirname($cfg->path(), 2) . '/var')
    );

    /*
     * The `@` is for one diagnostic and one only: page() sends a Content-Type, and the runner
     * has already written to stdout, so PHP warns that headers cannot be sent. That is an
     * artefact of rendering a page inside a test process, not a property of the page.
     */
    ob_start();
    @$view->page(Installer::STEP_STATUS, [
        'unlocked' => $unlocked,
        'flash'    => null,
        'bounced'  => $bounced,
        'jobs'     => [],
        'regions'  => [],
        'account'  => [],
        'progress' => [],
    ]);
    return (string) ob_get_clean();
}

/**
 * Every `<li>` of the missing-list, as [visible text, href or ''].
 *
 * @return array<int,array{0:string,1:string}>
 */
function lh_ins_missing_items(string $html): array
{
    if (!preg_match('#<ul class="setup-missing">(.*?)</ul>#s', $html, $ul)) {
        lh_fail('the status page rendered no missing-list at all');
    }
    preg_match_all('#<li>(.*?)</li>#s', $ul[1], $items);

    $out = [];
    foreach ($items[1] as $li) {
        $href = preg_match('/href="([^"]*)"/', $li, $h) ? $h[1] : '';
        $out[] = [trim(html_entity_decode(strip_tags($li))), $href];
    }
    return $out;
}

/**
 * Ask the controller what it would render for a requested step, and why.
 *
 * clampStep() is private, which is right — it is not API. Reflection here rather than widening
 * it, because the property under test is the CONTROLLER'S decision and testing a public
 * paraphrase of it would not be testing the thing that was broken.
 *
 * @return array{0:string,1:string}
 */
function lh_ins_clamp(Config $cfg, string $step, bool $unlocked): array
{
    if ($unlocked) {
        @session_start();
        $_SESSION['lh_setup_unlocked'] = time();
    } else {
        $_SESSION['lh_setup_unlocked'] = false;
    }

    $root = lh_ins_root();
    $installer = new Installer($cfg, $root);
    $clamp = (new ReflectionClass(Installer::class))->getMethod('clampStep');

    return (array) $clamp->invoke($installer, $step, new Requirements($root, $cfg));
}

/**
 * Is this line safe to paste into a shell?
 *
 * A comment is. A command is. A sentence of English is not, and the test for "sentence" that
 * matters here is the one a shell applies: the first word has to be something it could run.
 */
function lh_ins_pasteable(string $line): bool
{
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#')) {
        return true;
    }
    if (str_starts_with($line, '<script')) {
        return true;
    }
    if (str_starts_with($line, 'php_admin_value[') || str_starts_with($line, 'php_value[')) {
        return true;
    }
    return (bool) preg_match('#^[A-Za-z0-9_./-]+(\s|$)#', $line)
        && !preg_match('#^[A-Z][a-z]+\s+[a-z]+\s+#', $line);
}

return [

    /* ---------------------------------------------------------------------------------
     * The four links on the first screen
     * ------------------------------------------------------------------------------ */

    'while setup is locked, no missing-list link leads to a page that is not the one showing'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();
            $html = lh_ins_status($cfg, false);

            $items = lh_ins_missing_items($html);
            lh_true(count($items) >= 3, 'an unconfigured installation is missing several things');

            foreach ($items as [$text, $href]) {
                lh_false(
                    str_starts_with($href, '?setup='),
                    'while locked every ?setup= URL is clamped back to this same page, so this link '
                    . 'renders a byte-identical response and reads as broken: ' . $text
                );
                if ($href !== '') {
                    lh_same('#unlock', $href, 'a locked link goes to the unlock panel instead');
                    lh_contains($text, 'Unlock setup first', 'and says what it will do');
                }
            }

            lh_contains($html, 'id="unlock"', 'the panel those links point at has to exist');
            lh_rmtree($dir);
        },

    'once unlocked, each actionable line links to the step that fixes it'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            $seen = [];
            foreach (lh_ins_missing_items(lh_ins_status($cfg, true)) as [$text, $href]) {
                if ($href === '') {
                    continue;
                }
                lh_true(str_starts_with($href, '?setup='), 'an unlocked fix link goes to its step');
                $step = substr($href, strlen('?setup='));
                lh_true(
                    in_array($step, Installer::ORDER, true),
                    $href . ' names something that is not a step, so it would land on the status page'
                );
                $seen[] = $step;
            }

            lh_same(
                [Installer::STEP_SOURCES, Installer::STEP_STORAGE, Installer::STEP_ADMIN],
                $seen,
                'the three things an empty installation is missing, each pointing at its own step'
            );
            lh_rmtree($dir);
        },

    'nothing offers to fix the signing key, because its own sentence says there is nothing to fix'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            foreach ([true, false] as $unlocked) {
                foreach (lh_ins_missing_items(lh_ins_status($cfg, $unlocked)) as [$text, $href]) {
                    if (!str_contains($text, 'signing key')) {
                        continue;
                    }
                    lh_same(
                        '',
                        $href,
                        'the line says finishing setup generates the key, and then offered a link to '
                        . 'go and do it — an instruction contradicting the sentence beside it'
                    );
                    lh_contains($text, 'nothing to do here');
                }
            }

            $found = false;
            foreach ((new Requirements(lh_ins_root(), $cfg))->missing() as $item) {
                lh_has_key($item, 'actionable', 'every missing-list row says whether it can be acted on');
                if (str_contains($item['text'], 'signing key')) {
                    $found = true;
                    lh_false($item['actionable']);
                }
            }
            lh_true($found, 'the signing-key row must still be REPORTED — only its link went away');

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * The bounce
     * ------------------------------------------------------------------------------ */

    'a step that cannot be opened says so, and names what it is waiting on'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            [$step, $why] = lh_ins_clamp($cfg, Installer::STEP_ADMIN, true);
            lh_same(Installer::STEP_SOURCES, $step, 'the jump is still refused');
            lh_true($why !== '', 'and it is no longer refused in silence — that was the whole defect');
            lh_contains($why, Installer::stepLabel(Installer::STEP_ADMIN), 'it names the step asked for');
            lh_contains($why, Installer::stepLabel(Installer::STEP_SOURCES), 'and the step it landed on');
            lh_contains(
                $why,
                'No access log has been chosen',
                'and the PREREQUISITE, in the same words the missing-list uses, because "not '
                . 'available yet" tells an operator nothing they can act on'
            );

            lh_rmtree($dir);
        },

    'a locked jump and an unknown step are two different answers, and neither is silence'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            [$step, $why] = lh_ins_clamp($cfg, Installer::STEP_STORAGE, false);
            lh_same(Installer::STEP_STATUS, $step);
            lh_contains($why, 'locked');
            lh_contains($why, 'setup token');

            [$step, $why] = lh_ins_clamp($cfg, 'privacy', false);
            lh_same(Installer::STEP_STATUS, $step);
            lh_contains(
                $why,
                'no setup step called',
                'a retired route is reported as what it is even while locked; calling it "locked" '
                . 'would be a second false statement on top of the silence'
            );

            lh_rmtree($dir);
        },

    'the reason a page is not the one asked for is rendered where it will be read'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            $html = lh_ins_status($cfg, false, 'Setup is locked, so Storage cannot be opened yet.');
            lh_contains($html, 'banner banner-warn', 'it is a banner, at the top, not a footnote');
            lh_contains($html, 'Setup is locked, so Storage cannot be opened yet.');

            lh_false(
                str_contains(lh_ins_status($cfg, false), 'banner banner-warn'),
                'and there is no banner when nothing was bounced'
            );

            lh_rmtree($dir);
        },

    'a step is called the same thing everywhere it is named'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();
            $html = lh_ins_status($cfg, true);

            foreach (Installer::ORDER as $step) {
                lh_contains(
                    $html,
                    Installer::stepLabel($step),
                    'the rail has to use the shared label, or a bounce message and the rail end up '
                    . 'calling one screen two different things'
                );
            }
            lh_same('Access logs', Installer::stepLabel(Installer::STEP_SOURCES));
            lh_same('nope', Installer::stepLabel('nope'), 'an unknown step is its own name, never blank');

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * Anything under a Copy button
     * ------------------------------------------------------------------------------ */

    'every line the system check offers to copy is a line a shell would accept'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();
            $req = new Requirements('/opt/loghound', $cfg);

            $checked = 0;
            foreach ($req->all() as $row) {
                foreach ((array) $row['fix'] as $line) {
                    $checked++;
                    lh_true(
                        lh_ins_pasteable((string) $line),
                        $row['id'] . ' offers this under a Copy button, and it is prose: ' . $line
                        . ' — the convention in this file is a # prefix, and anything that will not '
                        . 'fit in one belongs in `detail`, which has no copy button'
                    );
                }
            }
            lh_true($checked > 0, 'this test needs at least one fix line to look at');

            lh_rmtree($dir);
        },

    'every fix line the file can EVER produce is pasteable, not only the ones failing here'
        => static function (): void {
            /*
             * The runtime test above can only see rows that fail on the machine running it, and
             * on a healthy machine that is two of them. The PHP-too-old row and the open_basedir
             * row — two of the three that carried prose — are unreachable from a passing box, so
             * reintroducing the bug there would go straight past a green suite. This reads the
             * source instead: every element of every `fix` array, whatever the state it needs.
             *
             * The first string literal of an element is what a shell sees first, which is the
             * thing being judged, and concatenation after it does not change that.
             */
            $source = (string) preg_replace(
                ['#/\*.*?\*/#s', '#^\s*//[^\n]*$#m'],
                '',
                (string) file_get_contents(lh_ins_root() . '/src/Setup/Requirements.php')
            );

            if (!preg_match_all("#'fix'\s*=>\s*(?:[^\[\n]*\?\s*\[\]\s*:\s*)?\[(.*?)\n\s*\],#s", $source, $blocks)) {
                lh_fail('no fix blocks could be read out of Requirements.php; re-read this test');
            }

            $checked = 0;
            foreach ($blocks[1] as $block) {
                foreach (explode("\n", $block) as $line) {
                    $line = trim($line);
                    if ($line === '' || $line[0] !== "'") {
                        continue;
                    }
                    if (!preg_match("#^'((?:[^'\\\\]|\\\\.)*)'#", $line, $literal)) {
                        continue;
                    }
                    $checked++;
                    lh_true(
                        lh_ins_pasteable(str_replace("\\'", "'", $literal[1])),
                        'this is offered under a Copy button and a shell would choke on it: '
                        . $literal[1] . ' — prefix it with #, or move it into `detail`'
                    );
                }
            }

            lh_true($checked >= 12, 'every fix line in the file has to be reached, not a handful');
        },

    /* A COPY BUTTON PROMISES THE BLOCK RUNS. Three fix blocks broke that promise in ways a
       "would a shell choke on this token" test cannot see, because each line was individually
       well-formed:

         - the extension block offered `apt install …` AND `dnf install …` in one paste, so
           whichever machine you are on, half the block fails — and the `systemctl restart`
           that makes the extension take effect sat behind a `#` and never ran;
         - the directory blocks ran `chown` and `chmod` with no `sudo`, which is root-only
           without exception, under a caption promising the block is written for the
           (never-root) user the page runs as;
         - the open_basedir block put a PHP-FPM pool directive on line 2 of a shell paste.

       So this judges the block as a whole: one package manager, sudo on the verbs that need
       it, and nothing that is not a shell command outside a comment. */
    'a fix block is one runnable sequence, not a menu and not a config file'
        => static function (): void {
            $root = lh_ins_root();
            $req = new \Loghound\Setup\Requirements($root, \Loghound\Config::load('/nonexistent-lh-req'));

            $rows = $req->all();
            lh_true(count($rows) > 5, 'the requirement rows were produced');

            $blocks = [];
            foreach ($rows as $row) {
                if ((array) $row['fix'] !== []) {
                    $blocks[(string) $row['id']] = array_map('strval', (array) $row['fix']);
                }
            }

            /* The rows that only fail on another kind of machine are unreachable from here, so
               their blocks are asked for directly rather than left untested. */
            $method = new \ReflectionMethod(\Loghound\Setup\Requirements::class, 'extensionFix');
            $blocks['ext_intl'] = array_map('strval', (array) $method->invoke(null, 'intl'));

            lh_true(count($blocks) >= 1, 'at least one fix block was available to judge');

            foreach ($blocks as $id => $lines) {
                $runnable = array_values(array_filter(
                    $lines,
                    static fn (string $l): bool => trim($l) !== '' && !str_starts_with(trim($l), '#')
                ));

                $managers = 0;
                foreach (['apt-get', 'apt ', 'dnf', 'yum', 'zypper', 'pacman'] as $pm) {
                    foreach ($runnable as $line) {
                        if (str_contains($line, $pm)) {
                            $managers++;
                            break;
                        }
                    }
                }
                lh_true(
                    $managers <= 1,
                    $id . ': the block offers ' . $managers . ' package managers in one paste, so '
                    . 'on any real machine at least one line cannot work'
                );

                foreach ($runnable as $line) {
                    foreach (['chown', 'chmod', 'mkdir -p /', 'systemctl', 'apt-get install',
                        'apt install', 'dnf install', 'yum install'] as $needsRoot) {
                        if (!str_starts_with($line, $needsRoot) && !str_contains($line, ' ' . $needsRoot)) {
                            continue;
                        }
                        lh_true(
                            str_starts_with($line, 'sudo '),
                            $id . ': "' . $line . '" cannot succeed as the user this page runs as, '
                            . 'and the caption above the block says it is written for that user'
                        );
                    }

                    lh_false(
                        (bool) preg_match('/^[a-z_]+\[[a-z_]+\]\s*=/', $line),
                        $id . ': "' . $line . '" is a PHP-FPM directive in a shell paste — a '
                        . 'syntax error before anything below it runs'
                    );
                }
            }
        },

    'every line the next-steps and operations cards offer to copy is too'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            $groups = array_merge(
                Steps::nextSteps($cfg, '/opt/loghound'),
                Steps::nextSteps($cfg, '/opt/loghound', true),
                Steps::operations('/opt/loghound')
            );

            foreach ($groups as $group) {
                foreach ((array) $group['lines'] as $line) {
                    lh_true(
                        lh_ins_pasteable((string) $line),
                        $group['key'] . ' offers prose under a Copy button: ' . $line
                    );
                }
            }

            lh_rmtree($dir);
        },

    'the command for a PHP that is too old names a series that would pass the check'
        => static function (): void {
            $min = (new ReflectionClass(Requirements::class))->getMethod('minPhpSeries')->invoke(null);

            lh_true(
                version_compare($min . '.0', Requirements::MIN_PHP, '>='),
                'the row fires BECAUSE the running PHP is too old, so naming the running series — '
                . 'which is what its sibling rows correctly do — would print "apt install php8.0-cli" '
                . 'to somebody on PHP 8.0: an instruction to reinstall the version that just failed'
            );

            /*
             * Comments are stripped first. The docblock on minPhpSeries() QUOTES the broken
             * command to explain why the method exists, which is exactly the sentence worth
             * keeping — and a test that cannot tell an explanation from the bug it describes
             * would force it to be deleted.
             */
            $source = (string) preg_replace(
                ['#/\*.*?\*/#s', '#//[^\n]*#'],
                '',
                (string) file_get_contents(lh_ins_root() . '/src/Setup/Requirements.php')
            );
            lh_false(
                (bool) preg_match('/apt install php\d+\.\d+-/', $source),
                'and it must not be hardcoded either, which is what it was: a literal php8.3 goes '
                . 'stale silently the moment MIN_PHP moves or that series leaves the distro'
            );
        },

    /* ---------------------------------------------------------------------------------
     * A command names the installation it belongs to
     * ------------------------------------------------------------------------------ */

    'no refusal tells the operator to run a command by a relative path'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();
            $cfg->set('allowed_log_roots', ['/var/log']);

            $refusal = Detector::manualSource($cfg, '/etc/passwd', 'combined', '')['error'];
            lh_contains($refusal, 'bin/loghound-setup', 'the way out is still named');
            lh_false(
                (bool) preg_match('#(?<![A-Za-z0-9_./-])bin/loghound-setup#', $refusal),
                'relative, it is a command that works from exactly one directory — and on a machine '
                . 'with two checkouts it configures the wrong installation without saying so'
            );
            lh_contains($refusal, $dir . '/bin/loghound-setup', 'so it names this installation');

            $bare = Config::load('/nonexistent/loghound.php');
            lh_true(str_starts_with($bare->setupCommand(), '/'), 'the fallback is absolute as well');
            lh_false(str_contains($bare->setupCommand(), '//'), 'and not a path with a hole in it');

            foreach ($bare->validate() as $error) {
                lh_false(
                    (bool) preg_match('#(?<![A-Za-z0-9_./-])bin/loghound-#', $error),
                    'a validation error is read over SSH and in a journal: ' . $error
                );
            }

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * An instruction that points at the screen the reader is on
     * ------------------------------------------------------------------------------ */

    'the beacon card points at the field on the same screen, when there is one'
        => static function (): void {
            [$dir, $cfg] = lh_ins_install();

            $installer = Steps::beaconSnippet($cfg, true)[1];
            $panel = Steps::beaconSnippet($cfg, false)[1];

            lh_true($installer !== '' && $panel !== '', 'both refuse when there is no address');

            lh_contains($installer, 'Public URL', 'on the installer screen the input is fifty lines up');
            lh_false(
                str_contains($installer, 'config/loghound.php'),
                'telling that operator to hand-edit the file is worse than saying nothing: they will '
                . 'do it, and the form on the same screen overwrites it when they press the button'
            );

            lh_contains($panel, 'config/loghound.php', 'in the panel there is no such field, and the '
                . 'file is the honest answer');
            lh_false(str_contains($panel, 'Public URL'));

            $cfg->set('base_url', 'https://user:secret@example.com'); // lh-scanner-fixture
            lh_contains(Steps::beaconSnippet($cfg, true)[1], 'Public URL', 'and the same for a bad one');
            lh_contains(Steps::beaconSnippet($cfg, false)[1], 'config/loghound.php');

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * Something small enough to miss is something too small to press
     * ------------------------------------------------------------------------------ */

    'the missing-list links are given a real tap target, at every width'
        => static function (): void {
            $panel = (string) file_get_contents(lh_ins_root() . '/public/assets/css/panel.css');
            $mobile = (string) file_get_contents(lh_ins_root() . '/public/assets/css/mobile.css');

            lh_contains(
                $panel,
                '.setup-missing a {',
                'measured at 51x18 in both themes at every width, on the links that are the entire '
                . 'call to action of the first screen anybody sees'
            );

            if (!preg_match('/\.setup-missing a \{(.*?)\}/s', $panel, $rule)) {
                lh_fail('the rule is there but could not be read back');
            }
            lh_contains($rule[1], 'padding: 11px', '18px of line plus 22px of padding reaches the 40px floor');
            lh_contains(
                $rule[1],
                'margin: -11px',
                'with a matching negative margin, so the hit box grows and the line box does not — '
                . 'the technique mobile.css already uses for an inline link inside a banner'
            );

            lh_contains($mobile, '.setup-missing a', 'and 44px on a coarse pointer, with the rest');
        },
];
