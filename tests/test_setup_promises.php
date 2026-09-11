<?php
/**
 * Loghound — anything an installer tells you to do has to work when it tells you.
 *
 * THE RULE THESE ENFORCE. A command printed next to a copy button, a variable named in a help
 * text, a sentence that says "do X instead" — each is a promise, and a normal operator does
 * not check it, they paste it and trust it. Every one of these tests exists because a promise
 * in this repository was once broken:
 *
 *   - `install.sh --help` sent people to `bin/loghound-setup --help` for "the full list" of
 *     environment variables, and that command printed one usage line.
 *   - A log path outside `allowed_log_roots` was refused with "add the directory with the
 *     shell wizard", and the shell wizard called the same refusal and printed the same
 *     sentence: the only instruction on the screen was a loop.
 *   - The shell wizard checked no prerequisites at all, while the browser installer opens on a
 *     system-check page — and the browser installer names the shell wizard as the way out of an
 *     open_basedir that hides the logs.
 *
 * They are deliberately structural rather than textual where they can be: a test that greps for
 * a sentence goes stale, a test that reads which variables the code actually consults does not.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Setup\Installer;
use Loghound\Setup\Requirements;
use Loghound\Setup\Storage;
use Loghound\Setup\View;

/** The repository root, whatever directory the suite was started from. */
function lh_promise_root(): string
{
    return dirname(__DIR__);
}

/** The wizard's source, as text. */
function lh_promise_wizard(): string
{
    return (string) file_get_contents(lh_promise_root() . '/bin/loghound-setup');
}

/**
 * Run the wizard with the given arguments and hand back stdout and the exit code.
 *
 * @return array{0:string,1:int}
 */
function lh_promise_run(array $args): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_promise_root() . '/bin/loghound-setup');
    foreach ($args as $arg) {
        $cmd .= ' ' . escapeshellarg((string) $arg);
    }
    $cmd .= ' 2>&1';

    $proc = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, lh_promise_root());
    if (!is_resource($proc)) {
        lh_skip('cannot start the wizard here');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [$out, proc_close($proc)];
}

return [

    'every environment variable the wizard reads is in its own help text' => static function (): void {
        $src = lh_promise_wizard();

        preg_match_all("/'(LOGHOUND_[A-Z0-9_]+)'/", $src, $m);
        $read = array_values(array_unique($m[1]));
        lh_true(count($read) > 10, 'the wizard reads a good number of variables: ' . count($read));

        [$help, $code] = lh_promise_run(['--help']);
        lh_same(0, $code, '--help must succeed');

        foreach ($read as $name) {
            if ($name === 'LOGHOUND_PREFIX') {
                continue;
            }
            lh_true(
                str_contains($help, $name),
                $name . ' is consulted by the wizard but is not in --help, which install.sh '
                . 'sends people to for "the full list"'
            );
        }
    },

    'the help that install.sh points at is a real list, not a usage line' => static function (): void {
        $installer = (string) file_get_contents(lh_promise_root() . '/install/install.sh');
        lh_contains(
            $installer,
            'bin/loghound-setup --help',
            'install.sh still points at that command for the variable list'
        );

        [$help, $code] = lh_promise_run(['--help']);
        lh_same(0, $code);
        lh_true(
            substr_count($help, "\n") > 30,
            'and the command it points at must actually hold the list: got '
            . substr_count($help, "\n") . ' lines'
        );
        lh_contains($help, 'LOGHOUND_OPENSOLR_API_KEY', 'including the awkward ones');
        lh_contains($help, 'LOGHOUND_OPENSOLR_REUSE', 'including the ones added last');
    },

    'an unknown option is refused rather than ignored' => static function (): void {
        [, $code] = lh_promise_run(['--make-me-a-sandwich']);
        lh_same(2, $code, 'a typo in an automated deploy must fail loudly, not run the wizard');
    },

    'both front ends check the same prerequisites, from the same place' => static function (): void {
        $src = lh_promise_wizard();
        lh_contains(
            $src,
            'new Requirements(',
            'the shell wizard must run the same checks the browser installer opens on — it is '
            . 'named on that page as the way out of an open_basedir, and a wizard that checks '
            . 'nothing is not an escape hatch'
        );

        $root = lh_tmpdir('lh-promise');
        @mkdir($root . '/config', 0750, true);
        @mkdir($root . '/var', 0750, true);
        $cfg = Config::load($root . '/config/loghound.php');

        $rows = (new Requirements($root, $cfg))->all();
        $ids = array_column($rows, 'id');

        foreach (['php_version', 'dir_config', 'dir_var'] as $needed) {
            lh_true(in_array($needed, $ids, true), $needed . ' is checked');
        }
        foreach (Requirements::REQUIRED_EXTENSIONS as $ext) {
            lh_true(in_array('ext_' . $ext, $ids, true), 'ext-' . $ext . ' is checked by name');
        }

        foreach ($rows as $row) {
            if ($row['state'] === 'pass') {
                lh_same([], $row['fix'], $row['id'] . ' passes, so it must not print a command to run');
            }
        }

        lh_rmtree($root);
    },

    'a prerequisite that is failing stops the wizard before it asks anything' => static function (): void {
        $src = lh_promise_wizard();

        lh_true(
            (bool) preg_match('/if \(!checkRequirements\(.*\) && !\$detectOnly\) \{\s*\n\s*exit\(1\);/', $src),
            'a failing check must exit, not warn and carry on'
        );
        lh_true(
            strpos($src, 'checkRequirements(') < strpos($src, 'Detector::runSync('),
            'and it must run before detection, which is the first thing that touches the disk'
        );
    },

    'the wizard stops at the step that failed instead of collecting a password first'
        => static function (): void {
            $src = lh_promise_wizard();

            lh_true(
                (bool) preg_match('/if \(!configureOpensolr\(/', $src),
                'the storage step reports whether it finished'
            );
            lh_true(
                strpos($src, 'if (!configureOpensolr(') < strpos($src, "step(5, 'Panel access')"),
                'and the run ends there, before the panel account is asked for'
            );
            lh_contains(
                $src,
                'saveProgress(',
                'saving what has already been decided, so an abandoned run loses nothing'
            );
        },

    'the refusal for a log outside the allowed roots names a way that works' => static function (): void {
        $root = lh_tmpdir('lh-roots');
        @mkdir($root . '/config', 0750, true);
        @mkdir($root . '/elsewhere', 0750, true);
        file_put_contents($root . '/elsewhere/access.log', "nothing\n");

        $cfg = Config::load($root . '/config/loghound.php');
        $cfg->set('allowed_log_roots', ['/var/log']);

        $refused = \Loghound\Setup\Detector::manualSource($cfg, $root . '/elsewhere/access.log', 'apache_combined', '');
        lh_false($refused['ok'], 'a path outside the roots is refused, and always will be');

        lh_false(
            str_contains($refused['error'], 'with the shell wizard, then come back'),
            'the refusal must not send the operator to a command that prints this same refusal'
        );

        $src = lh_promise_wizard();
        lh_contains(
            $src,
            'addManualSource(',
            'the wizard takes a typed path through its own helper, which asks for the widening '
            . 'itself — that is what makes the refusal above a way out rather than a loop'
        );
        lh_contains(
            $src,
            'Steps::allowLogRoot(',
            'and that helper can genuinely widen the list, after asking'
        );
        lh_contains($src, "'LOGHOUND_ALLOW_LOG_ROOTS'", 'with the same variable a detected file uses');

        lh_rmtree($root);
    },

    'widening is explicit, exact, and never reaches the root of the filesystem'
        => static function (): void {
            $root = lh_tmpdir('lh-widen');
            @mkdir($root . '/config', 0750, true);
            @mkdir($root . '/logs', 0750, true);

            $cfg = Config::load($root . '/config/loghound.php');
            $cfg->set('allowed_log_roots', ['/var/log']);

            lh_same(null, \Loghound\Setup\Steps::allowLogRoot($cfg, $root . '/logs'), 'a real directory is allowed');
            lh_true(
                in_array(realpath($root . '/logs'), (array) $cfg->get('allowed_log_roots'), true),
                'and it is the exact directory that lands in the list'
            );
            lh_true(
                in_array('/var/log', (array) $cfg->get('allowed_log_roots'), true),
                'without disturbing what was there'
            );

            lh_true(
                \Loghound\Setup\Steps::allowLogRoot($cfg, $root . '/no-such-dir') !== null,
                'a directory that does not exist is refused rather than stored hopefully'
            );
            lh_true(
                \Loghound\Setup\Steps::allowLogRoot($cfg, '/') !== null,
                'and / is refused outright: allowing it would make every file on the box a log'
            );
            lh_false(
                in_array('/', (array) $cfg->get('allowed_log_roots'), true),
                'so it never reaches the list'
            );

            lh_rmtree($root);
        },

    'both front ends send an operator to the same Opensolr pages' => static function (): void {
        $view = (string) file_get_contents(lh_promise_root() . '/src/Setup/View.php');
        $wizard = lh_promise_wizard();

        preg_match_all('#https://opensolr\.com/[A-Za-z0-9_/\-]*#', $view . $wizard, $m);
        $known = [
            Storage::URL_REGISTER,
            Storage::URL_LOGIN,
            Storage::URL_PLANS,
            Storage::URL_INDEXES,
        ];

        foreach (array_unique($m[0]) as $url) {
            lh_true(
                in_array($url, $known, true),
                $url . ' is hardcoded in a front end instead of coming from Setup\\Storage, which '
                . 'is how the terminal and the browser end up naming two different pages'
            );
        }

        foreach ($known as $url) {
            lh_true(str_starts_with($url, 'https://opensolr.com/'), $url . ' is an Opensolr address');
        }
    },

    // Every action a form posts must have a case in the dispatcher; one that has none falls
    // through to "That action is not available here", a dead end in the middle of setup.
    'the reuse action the installer offers is one the installer accepts' => static function (): void {
        $view = (string) file_get_contents(lh_promise_root() . '/src/Setup/View.php');
        $ctrl = (string) file_get_contents(lh_promise_root() . '/src/Setup/Installer.php');

        preg_match_all("/csrf\(Installer::(STEP_[A-Z]+), '([a-z_]+)'\)/", $view, $m, PREG_SET_ORDER);
        lh_true(count($m) > 5, 'the view posts a fair number of actions: ' . count($m));

        $steps = [
            'STEP_STATUS'  => Installer::STEP_STATUS,
            'STEP_SOURCES' => Installer::STEP_SOURCES,
            'STEP_STORAGE' => Installer::STEP_STORAGE,
            'STEP_ADMIN'   => Installer::STEP_ADMIN,
        ];

        foreach ($m as $one) {
            [, $stepConst, $action] = $one;
            if ($action === 'unlock') {
                continue;
            }
            $case = "case self::" . $stepConst . " . ':" . $action . "':";
            lh_true(
                str_contains($ctrl, $case),
                'the view offers ' . $steps[$stepConst] . '/' . $action
                . ' but the controller has no case for it, so pressing it is a dead end'
            );
        }
    },

    'a failed job offers a retry of the work that failed, not of different work'
        => static function (): void {
            $view = (string) file_get_contents(lh_promise_root() . '/src/Setup/View.php');

            lh_contains(
                $view,
                "Job::KIND_REUSE    => 'reuse'",
                'a reuse job that failed must retry reuse: posting "provision" would turn '
                . '"join the indexes I picked" into "create two more", which on a full plan '
                . 'could only fail again'
            );
            lh_contains(
                $view,
                'name="install_id"',
                'and it has to carry the pair that was chosen, or the retry has nothing to adopt'
            );
        },
];
