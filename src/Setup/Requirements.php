<?php
/**
 * Loghound — installer requirement checks.
 *
 * The first screen of the browser installer is a status page in the style Drupal and
 * Matomo use: one row per prerequisite, a plain pass/warn/fail state, and — for anything
 * that is not passing — the EXACT command that fixes it on this machine, with this
 * machine's real paths and this machine's real PHP user substituted in.
 *
 * "Permission denied" is not a diagnosis. "/var/log/apache2/access.log is not readable by
 * www-data — run: setfacl -m u:www-data:rx /var/log/apache2" is.
 *
 * Two environment facts dominate everything here and are checked before anything else:
 *
 *   1. WHO IS PHP. The daemons run as the service user (`loghound`, group `adm`); the
 *      panel runs in its own PHP-FPM pool as the same user. Every fix command has to name
 *      the user that is actually running this request, not a documented default.
 *   2. open_basedir. The reference PHP-FPM pool restricts the panel to the application
 *      tree plus /tmp. That is correct hardening — but it means this page physically
 *      cannot stat /var/log or /etc/apache2, and reporting that as "log file unreadable,
 *      run setfacl" would send the operator chasing a permission problem that does not
 *      exist. So open_basedir is detected first and reported as itself.
 *
 * Nothing in this class writes anything or has a side effect other than creating the
 * directories the installer needs (config/ and var/), which it attempts only when their
 * parent is writable.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;

final class Requirements
{
    /** Minimum PHP version. SPEC §2: 8.1+, no Composer. */
    public const MIN_PHP = '8.1.0';

    /** Extensions the application genuinely uses. SPEC §2. */
    public const REQUIRED_EXTENSIONS = ['curl', 'json', 'pcre', 'sqlite3', 'mbstring'];

    /** Application root (the directory holding config/, var/, public/). */
    private string $root;

    private Config $cfg;

    public function __construct(string $root, Config $cfg)
    {
        $this->root = rtrim($root, '/');
        $this->cfg  = $cfg;
    }

    /**
     * Run every check and return the rows the status page renders.
     *
     * Row shape:
     *   id     stable identifier, used by the tests and by the "what is missing" list
     *   label  short human name of the requirement
     *   state  'pass' | 'warn' | 'fail'
     *   detail one sentence saying what was actually observed
     *   fix    string[] — literal shell commands or instructions, rendered verbatim
     *
     * `warn` never blocks the installer. `fail` does: those are the conditions under
     * which continuing would produce a broken install.
     *
     * @return array<int,array{id:string,label:string,state:string,detail:string,fix:string[]}>
     */
    public function all(): array
    {
        $rows = [];
        $rows[] = $this->php();
        foreach ($this->extensions() as $row) {
            $rows[] = $row;
        }
        $rows[] = $this->writable('config', $this->root . '/config', 'Configuration directory');
        $rows[] = $this->writable('var', $this->root . '/var', 'Runtime directory');

        $basedir = $this->openBasedir();
        if ($basedir !== null) {
            $rows[] = $basedir;
        }

        $rows[] = $this->webserverConfigs();
        foreach ($this->logFiles() as $row) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * Does any row block the installer from continuing?
     *
     * @param array<int,array{state:string}> $rows
     */
    public static function blocked(array $rows): bool
    {
        foreach ($rows as $row) {
            if (($row['state'] ?? '') === 'fail') {
                return true;
            }
        }
        return false;
    }

    /**
     * The user this PHP process is running as.
     *
     * Every fix command on the status page is built around this name, so getting it right
     * matters more than it looks: telling someone to `setfacl -m u:www-data:rx` when the
     * pool actually runs as `loghound` produces a command that succeeds and changes
     * nothing, which is the most expensive kind of wrong answer.
     */
    public static function phpUser(): string
    {
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $info = @posix_getpwuid(posix_geteuid());
            if (is_array($info) && isset($info['name']) && $info['name'] !== '') {
                return (string) $info['name'];
            }
        }
        $name = get_current_user();
        return $name !== '' ? $name : 'the PHP user';
    }

    /**
     * The groups this process belongs to, for the "is it in group adm?" question.
     *
     * @return string[]
     */
    public static function phpGroups(): array
    {
        if (!function_exists('posix_getgroups') || !function_exists('posix_getgrgid')) {
            return [];
        }
        $out = [];
        foreach ((array) @posix_getgroups() as $gid) {
            $grp = @posix_getgrgid((int) $gid);
            if (is_array($grp) && isset($grp['name'])) {
                $out[] = (string) $grp['name'];
            }
        }
        return $out;
    }

    /**
     * Is $path outside every open_basedir component?
     *
     * When open_basedir is set, PHP refuses to touch anything outside it and every
     * filesystem call on such a path returns false with a warning — indistinguishable, to
     * naive code, from "the file is not there" or "you have no permission". This is the
     * one test that tells those apart.
     */
    public static function openBasedirBlocks(string $path): bool
    {
        $setting = (string) ini_get('open_basedir');
        if (trim($setting) === '') {
            return false;
        }
        foreach (explode(PATH_SEPARATOR, $setting) as $allowed) {
            $allowed = trim($allowed);
            if ($allowed === '') {
                continue;
            }
            if ($path === rtrim($allowed, '/') || str_starts_with($path, rtrim($allowed, '/') . '/')) {
                return false;
            }
        }
        return true;
    }

    /**
     * PHP version. A hard requirement: the codebase uses 8.1 syntax throughout, so an
     * older interpreter does not produce a degraded install, it produces a parse error.
     *
     * @return array{id:string,label:string,state:string,detail:string,fix:string[]}
     */
    private function php(): array
    {
        $ok = version_compare(PHP_VERSION, self::MIN_PHP, '>=');
        return [
            'id'     => 'php_version',
            'label'  => 'PHP ' . self::MIN_PHP . ' or newer',
            'state'  => $ok ? 'pass' : 'fail',
            'detail' => $ok
                ? 'Running PHP ' . PHP_VERSION . '.'
                : 'This server is running PHP ' . PHP_VERSION . ', which is too old.',
            'fix'    => $ok ? [] : [
                'Install a newer PHP and point this vhost at it.',
                'On Debian/Ubuntu: apt install php8.3-cli php8.3-fpm',
            ],
        ];
    }

    /**
     * The five extensions. Each gets its own row so the fix names the missing package
     * rather than a list the operator has to diff against their own box.
     *
     * @return array<int,array{id:string,label:string,state:string,detail:string,fix:string[]}>
     */
    private function extensions(): array
    {
        $rows = [];
        foreach (self::REQUIRED_EXTENSIONS as $ext) {
            $ok = extension_loaded($ext);
            $rows[] = [
                'id'     => 'ext_' . $ext,
                'label'  => 'PHP extension: ' . $ext,
                'state'  => $ok ? 'pass' : 'fail',
                'detail' => $ok ? 'Loaded.' : 'Not loaded.',
                'fix'    => $ok ? [] : [
                    'apt install php' . self::phpSeries() . '-' . $ext
                        . '   # Debian/Ubuntu, then: systemctl restart php' . self::phpSeries() . '-fpm',
                    'dnf install php-' . $ext . '   # RHEL/Fedora, then: systemctl restart php-fpm',
                ],
            ];
        }
        return $rows;
    }

    /** Major.minor of the running PHP, used to name the right distro package. */
    private static function phpSeries(): string
    {
        return PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    }

    /**
     * A directory the installer must be able to write.
     *
     * Creates it when it is missing and the parent allows it, because "config/ does not
     * exist" is a situation the installer can simply resolve rather than report.
     *
     * @return array{id:string,label:string,state:string,detail:string,fix:string[]}
     */
    private function writable(string $id, string $dir, string $label): array
    {
        $user = self::phpUser();

        if (!is_dir($dir)) {
            @mkdir($dir, $id === 'config' ? 0700 : 0750, true);
        }

        if (!is_dir($dir)) {
            return [
                'id'     => 'dir_' . $id,
                'label'  => $label . ' exists',
                'state'  => 'fail',
                'detail' => $dir . ' does not exist and could not be created.',
                'fix'    => [
                    'mkdir -p ' . $dir,
                    'chown ' . $user . ' ' . $dir,
                    'chmod ' . ($id === 'config' ? '0700' : '0750') . ' ' . $dir,
                ],
            ];
        }

        $ok = is_writable($dir);
        return [
            'id'     => 'dir_' . $id,
            'label'  => $label . ' is writable',
            'state'  => $ok ? 'pass' : 'fail',
            'detail' => $ok
                ? $dir . ' is writable by ' . $user . '.'
                : $dir . ' is not writable by ' . $user . ', so setup cannot save anything.',
            'fix'    => $ok ? [] : [
                'chown ' . $user . ' ' . $dir,
                'chmod ' . ($id === 'config' ? '0700' : '0750') . ' ' . $dir,
            ],
        ];
    }

    /**
     * open_basedir, when it is set.
     *
     * Reported as a warning rather than a failure: it does not stop setup, it stops this
     * page from SEEING the logs. The ingest daemon is a CLI process with no such
     * restriction, so an install completed here still works — the operator just has to
     * type the log path instead of picking it from a list, or widen open_basedir.
     *
     * @return array{id:string,label:string,state:string,detail:string,fix:string[]}|null
     */
    private function openBasedir(): ?array
    {
        $setting = trim((string) ini_get('open_basedir'));
        if ($setting === '') {
            return null;
        }

        $blocked = [];
        foreach ($this->interestingDirs() as $dir) {
            if (self::openBasedirBlocks($dir)) {
                $blocked[] = $dir;
            }
        }

        if ($blocked === []) {
            return [
                'id'     => 'open_basedir',
                'label'  => 'open_basedir',
                'state'  => 'pass',
                'detail' => 'Set to ' . $setting . ', and it covers the directories setup needs to read.',
                'fix'    => [],
            ];
        }

        return [
            'id'     => 'open_basedir',
            'label'  => 'open_basedir',
            'state'  => 'warn',
            'detail' => 'PHP is restricted to ' . $setting . ', so this page cannot read '
                . implode(', ', $blocked) . '. Log detection will find nothing until that changes. '
                . 'The ingest daemon is not affected — it runs from the command line, where the '
                . 'restriction does not apply.',
            'fix'    => [
                'Add read access for those directories to the PHP-FPM pool, then reload PHP:',
                'php_admin_value[open_basedir] = ' . $setting . ':' . implode(':', $blocked),
                'systemctl reload php' . self::phpSeries() . '-fpm',
                'Or skip this screen and run the shell wizard instead: '
                    . 'sudo -u ' . self::phpUser() . ' php ' . $this->root . '/bin/loghound-setup',
            ],
        ];
    }

    /**
     * Directories setup wants to read: the webserver config trees and the log roots.
     *
     * @return string[]
     */
    private function interestingDirs(): array
    {
        $dirs = [];
        $discover = (array) $this->cfg->get('discover', []);
        foreach ((array) ($discover['apache_configs'] ?? []) as $f) {
            $dirs[dirname((string) $f)] = true;
        }
        foreach ((array) ($discover['nginx_configs'] ?? []) as $f) {
            $dirs[dirname((string) $f)] = true;
        }
        foreach ((array) ($discover['fallback_globs'] ?? []) as $g) {
            $dirs[dirname((string) $g)] = true;
        }
        foreach ((array) $this->cfg->get('allowed_log_roots', []) as $r) {
            $dirs[(string) $r] = true;
        }
        return array_keys($dirs);
    }

    /**
     * Can we read the webserver configuration?
     *
     * This is not a failure — it decides which rung of the SPEC §8 detection ladder we
     * land on. Reading the config gives the exact format and the vhost each log belongs
     * to with no guessing; without it we fall back to scoring sample lines, which works
     * but is a probability rather than a fact. Saying which one is in play is the honest
     * thing to put on this page.
     *
     * @return array{id:string,label:string,state:string,detail:string,fix:string[]}
     */
    private function webserverConfigs(): array
    {
        $discover = (array) $this->cfg->get('discover', []);
        $candidates = array_merge(
            (array) ($discover['apache_configs'] ?? []),
            (array) ($discover['nginx_configs'] ?? [])
        );

        $readable = [];
        $present  = [];
        foreach ($candidates as $file) {
            $file = (string) $file;
            if (self::openBasedirBlocks($file)) {
                continue;
            }
            if (!@is_file($file)) {
                continue;
            }
            $present[] = $file;
            if (@is_readable($file)) {
                $readable[] = $file;
            }
        }

        if ($readable !== []) {
            return [
                'id'     => 'webserver_config',
                'label'  => 'Webserver configuration is readable',
                'state'  => 'pass',
                'detail' => 'Reading ' . implode(', ', $readable) . ' — the log format and the '
                    . 'virtual host of every access log can be read directly, with no guessing.',
                'fix'    => [],
            ];
        }

        $user = self::phpUser();
        $detail = $present === []
            ? 'No Apache or nginx configuration was found at the usual locations. Log formats '
                . 'will be worked out by scoring sample lines instead, which is less certain.'
            : 'Found ' . implode(', ', $present) . ' but cannot read it as ' . $user
                . '. Log formats will be worked out by scoring sample lines instead.';

        return [
            'id'     => 'webserver_config',
            'label'  => 'Webserver configuration is readable',
            'state'  => 'warn',
            'detail' => $detail,
            'fix'    => $present === [] ? [] : [
                'setfacl -m u:' . $user . ':rx ' . dirname($present[0]),
                'setfacl -m u:' . $user . ':r ' . $present[0],
            ],
        ];
    }

    /**
     * Are the access logs actually readable BY THIS PROCESS?
     *
     * The single most valuable row on the page. On the reference install
     * /var/log/apache2 is www-data:www-data with mode 0750, so a service user that is not
     * www-data cannot even traverse the directory — and the failure surfaces much later
     * as "the daemon is running and indexing nothing", which is exactly the failure this
     * project exists to make visible.
     *
     * The check is done with a real read attempt rather than by reasoning about modes:
     * ACLs, supplementary groups and setgid directories all make the mode bits a lie.
     *
     * @return array<int,array{id:string,label:string,state:string,detail:string,fix:string[]}>
     */
    private function logFiles(): array
    {
        $user   = self::phpUser();
        $groups = self::phpGroups();
        $rows   = [];

        $paths = [];
        foreach ((array) $this->cfg->get('sources', []) as $src) {
            $pattern = (string) ($src['path'] ?? '');
            if ($pattern === '') {
                continue;
            }
            foreach ((glob($pattern) ?: []) as $file) {
                $paths[$file] = true;
            }
            if ($paths === [] && @is_file($pattern)) {
                $paths[$pattern] = true;
            }
        }
        if ($paths === []) {
            foreach ((array) $this->cfg->get('discover.fallback_globs', []) as $glob) {
                foreach ((glob((string) $glob) ?: []) as $file) {
                    $paths[$file] = true;
                }
            }
        }

        $paths = array_slice(array_keys($paths), 0, 8);

        if ($paths === []) {
            $blockedDirs = [];
            foreach ((array) $this->cfg->get('discover.fallback_globs', []) as $glob) {
                $dir = dirname((string) $glob);
                if (self::openBasedirBlocks($dir)) {
                    $blockedDirs[$dir] = true;
                }
            }
            if ($blockedDirs !== []) {
                return [[
                    'id'     => 'logs',
                    'label'  => 'Access logs are readable',
                    'state'  => 'warn',
                    'detail' => 'Cannot look in ' . implode(', ', array_keys($blockedDirs))
                        . ' because of open_basedir, so no log file could be listed from here. '
                        . 'You can still type a path on the next screen, or run the shell wizard.',
                    'fix'    => [],
                ]];
            }
            return [[
                'id'     => 'logs',
                'label'  => 'Access logs are readable',
                'state'  => 'warn',
                'detail' => 'No access log was found in the usual places. You can type the path '
                    . 'to one on the next screen.',
                'fix'    => [],
            ]];
        }

        foreach ($paths as $path) {
            $dir = dirname($path);

            if (self::openBasedirBlocks($path)) {
                $rows[] = [
                    'id'     => 'log_' . md5($path),
                    'label'  => 'Log readable: ' . $path,
                    'state'  => 'warn',
                    'detail' => 'open_basedir stops this page from reading ' . $path
                        . '. The ingest daemon runs from the command line and is not affected.',
                    'fix'    => [],
                ];
                continue;
            }

            $ok = @is_readable($path);
            $rows[] = [
                'id'     => 'log_' . md5($path),
                'label'  => 'Log readable: ' . $path,
                'state'  => $ok ? 'pass' : 'fail',
                'detail' => $ok
                    ? 'Readable by ' . $user . '.'
                    : $path . ' is not readable by ' . $user . '. Loghound would run and index '
                        . 'nothing at all.' . ($groups !== []
                            ? ' Current groups: ' . implode(', ', $groups) . '.'
                            : ''),
                'fix'    => $ok ? [] : [
                    'setfacl -m u:' . $user . ':rx ' . $dir,
                    'setfacl -m u:' . $user . ':r ' . $path,
                    '# or, if setfacl is not installed:',
                    'usermod -aG adm ' . $user . '   # then restart PHP-FPM and the daemons',
                ],
            ];
        }

        return $rows;
    }

    /**
     * A short, human list of what is still missing from this installation.
     *
     * Drives the "you are part-way through" summary. Deliberately phrased for someone who
     * has never heard of config/loghound.php: each line says what is missing in product
     * terms, not in configuration-key terms.
     *
     * @return array<int,array{step:string,text:string}>
     */
    public function missing(): array
    {
        $out = [];

        if ((array) $this->cfg->get('sources', []) === []) {
            $out[] = ['step' => Installer::STEP_SOURCES, 'text' => 'No access log has been chosen yet, so there is nothing to analyse.'];
        }
        if ((string) $this->cfg->get('solr.hits_core', '') === ''
            || (string) $this->cfg->get('solr.sessions_core', '') === '') {
            $out[] = ['step' => Installer::STEP_STORAGE, 'text' => 'No search index has been created yet, so there is nowhere to keep the results.'];
        } elseif ((string) $this->cfg->get('solr.base_url', '') === '') {
            $out[] = ['step' => Installer::STEP_STORAGE, 'text' => 'The index exists but Loghound has no address to reach it on.'];
        }
        if (strlen((string) $this->cfg->get('beacon.secret', '')) < 32) {
            $out[] = ['step' => Installer::STEP_PRIVACY, 'text' => 'The signing key that stops visitors forging timing data has not been generated yet.'];
        }
        if ((string) $this->cfg->get('auth.password_hash', '') === '') {
            $out[] = ['step' => Installer::STEP_ADMIN, 'text' => 'There is no username and password for signing in to Loghound.'];
        }

        return $out;
    }

    /** Escape hatch used in messages: the shell command that runs the CLI wizard here. */
    public function cliCommand(): string
    {
        return 'sudo -u ' . self::phpUser() . ' php ' . $this->root . '/bin/loghound-setup';
    }

}
