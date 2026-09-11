<?php
/**
 * Loghound — tests that install.sh can actually reach both setup front ends.
 *
 * The documentation says configuration happens either in a browser or in a shell and that
 * neither is a lesser version of the other. That was true of the code in src/Setup/ and
 * false of the installer: install.sh handed over to the shell wizard unconditionally, with
 * no way to decline, and a configuration finished there leaves the browser installer with
 * nothing to do — Installer::isNeeded() goes false as soon as an auth mode is set and both
 * indexes are named. Anyone wanting the browser path had to interrupt the wizard.
 *
 * These tests pin the flag and the claim together, so the two cannot drift apart again.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

/** The installer script as text. */
function lh_installer_source(): string
{
    return (string) file_get_contents(__DIR__ . '/../install/install.sh');
}

return [

    'install.sh accepts --skip-setup' => static function (): void {
        $src = lh_installer_source();

        if (!str_contains($src, '--skip-setup)')) {
            throw new \RuntimeException('There is no --skip-setup arm in the argument parser.');
        }
        if (!preg_match('/^SKIP_SETUP=0$/m', $src)) {
            throw new \RuntimeException('SKIP_SETUP has no default, so an unset variable decides the branch.');
        }
        if (!str_contains($src, '  --skip-setup ')) {
            throw new \RuntimeException('--skip-setup is not listed in --help, so nobody will find it.');
        }
    },

    'the flag actually prevents the handover' => static function (): void {
        $src = lh_installer_source();

        if (!preg_match('/if \(\( SKIP_SETUP \)\); then\s+SETUP_OK=0/', $src)) {
            throw new \RuntimeException(
                'The flag does not stop run_setup, or does not mark setup incomplete — which would let '
                . 'start_and_verify run against a configuration that does not exist yet.'
            );
        }
    },

    'the closing report matches the front end that was chosen' => static function (): void {
        $src = lh_installer_source();

        $pos = strpos($src, 'Sign in with the username and password you chose during setup');
        if ($pos === false) {
            throw new \RuntimeException('The completed-setup report is gone.');
        }

        if (!str_contains($src, 'FINISH SETUP IN YOUR BROWSER')) {
            throw new \RuntimeException(
                'Skipping the wizard still tells the operator to sign in with a password they were '
                . 'never asked for.'
            );
        }
        if (!str_contains($src, 'var/install-token')) {
            throw new \RuntimeException(
                'The report does not say how to read the setup token, which is the first thing the '
                . 'browser installer asks for.'
            );
        }
    },

    'the installer is valid shell' => static function (): void {
        $out = [];
        $code = 0;
        exec('bash -n ' . escapeshellarg(__DIR__ . '/../install/install.sh') . ' 2>&1', $out, $code);
        if ($code !== 0) {
            throw new \RuntimeException('install.sh does not parse: ' . implode("\n", $out));
        }
    },

    'the documentation tells people the flag exists' => static function (): void {
        $docs = [
            'README.md',
            'docs/INSTALL.md',
            'docs/INSTALL-WEB.md',
        ];

        foreach ($docs as $doc) {
            $text = (string) file_get_contents(__DIR__ . '/../' . $doc);
            if (!str_contains($text, '--skip-setup')) {
                throw new \RuntimeException(
                    $doc . ' describes two interchangeable installers without saying how to choose '
                    . 'the browser one.'
                );
            }
        }
    },
];
