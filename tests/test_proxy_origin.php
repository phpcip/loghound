<?php
/**
 * Loghound — the origin behind a proxy is not a second site.
 *
 * The standard three-layer setup puts Apache in front to terminate TLS, a cache behind it,
 * and Apache again serving the application. BOTH Apache layers write an access log, and
 * with RemoteIP restoring the client address the two files are line-for-line the same
 * traffic. Ingesting both counts every visit twice, and dilutes every share and percentage
 * by an amount that depends on which sites happen to sit behind a cache — a wrong number
 * that is both plausible and unattributable.
 *
 * The evidence is the bind address, not the file name and not the ServerName: a vhost bound
 * to loopback cannot be reached from outside the machine, so everything in its log arrived
 * through something in front of it. A name like `drupal-backend.internal` is a convention
 * somebody chose; `127.0.0.1` is a fact about the socket.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\LogDetect;
use Loghound\Setup\Detector;

/**
 * Call the private judgement directly — it is the whole decision, and a test that went
 * through candidates() would depend on a machine's real webserver configuration.
 */
function lh_is_proxy_origin(string $listen): bool
{
    $m = new ReflectionMethod(Detector::class, 'isProxyOrigin');

    return (bool) $m->invoke(null, $listen);
}

/** A throwaway Apache config, returned with its path. */
function lh_proxy_conf(string $body): string
{
    $dir = sys_get_temp_dir() . '/lh-proxy-' . bin2hex(random_bytes(6));
    mkdir($dir, 0700, true);
    file_put_contents($dir . '/site.conf', $body);

    return $dir;
}

return [

    'a loopback-bound vhost is an origin behind something' => static function (): void {
        foreach (['127.0.0.1:8080', '127.0.0.1', '127.1.2.3:8081', '[::1]:8080', '::1'] as $listen) {
            if (!lh_is_proxy_origin($listen)) {
                throw new \RuntimeException($listen . ' was not recognised as loopback-only.');
            }
        }
    },

    'a publicly reachable vhost is a site' => static function (): void {
        foreach (['*:80', '*:443', '*', '', '0.0.0.0:80', '5.161.242.87:443', '[2a01:4f8::1]:443'] as $listen) {
            if (lh_is_proxy_origin($listen)) {
                throw new \RuntimeException($listen . ' was wrongly treated as a proxy origin.');
            }
        }
    },

    'a private address that is not loopback is still a site' => static function (): void {
        foreach (['10.0.0.5:80', '192.168.1.10:8080', '172.16.4.1'] as $listen) {
            if (lh_is_proxy_origin($listen)) {
                throw new \RuntimeException(
                    $listen . ' was excluded, but a vhost on a private network is reachable from '
                    . 'that network and may well be the site somebody actually uses.'
                );
            }
        }
    },

    'the bind address survives parsing, which is what the judgement reads'
        => static function (): void {
            $dir = lh_proxy_conf(
                "<VirtualHost *:443>\n"
                . "    ServerName example.test\n"
                . "    CustomLog /var/log/apache2/example_access.log combined\n"
                . "</VirtualHost>\n"
                . "<VirtualHost 127.0.0.1:8080>\n"
                . "    ServerName example-backend.internal\n"
                . "    CustomLog /var/log/apache2/example_backend.log combined\n"
                . "</VirtualHost>\n"
            );

            try {
                $found = LogDetect::discoverAll([
                    'apache_configs'    => [],
                    'apache_vhost_dirs' => [$dir],
                    'allow_roots'       => [$dir],
                ]);

                $front = $found['/var/log/apache2/example_access.log'] ?? null;
                $back  = $found['/var/log/apache2/example_backend.log'] ?? null;

                if (!is_array($front) || !is_array($back)) {
                    throw new \RuntimeException('Both logs should have been discovered.');
                }
                if (($front['listen'] ?? null) !== '*:443') {
                    throw new \RuntimeException(
                        'The front bind address was lost: ' . var_export($front['listen'] ?? null, true)
                    );
                }
                if (($back['listen'] ?? null) !== '127.0.0.1:8080') {
                    throw new \RuntimeException(
                        'The origin bind address was lost, so nothing can tell the two apart: '
                        . var_export($back['listen'] ?? null, true)
                    );
                }
                if (lh_is_proxy_origin((string) $front['listen'])) {
                    throw new \RuntimeException('The public vhost was excluded.');
                }
                if (!lh_is_proxy_origin((string) $back['listen'])) {
                    throw new \RuntimeException('The origin was offered as a separate site.');
                }
            } finally {
                @unlink($dir . '/site.conf');
                @rmdir($dir);
            }
        },
];
