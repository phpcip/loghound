<?php
/**
 * Loghound — PSR-4 style autoloader.
 *
 * Deliberately dependency-free. The whole point of this project is that `git clone` plus
 * `install.sh` works on a bare Ubuntu box with nothing but php-cli installed: no Composer,
 * no vendor directory, no network access at install time.
 *
 * Maps the \Loghound\ namespace onto this directory, so \Loghound\Enrich\Geo resolves to
 * src/Enrich/Geo.php.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'Loghound\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

/**
 * Marks that we are running inside the application, so the generated config file will
 * return its array instead of exiting. See Config::save().
 */
if (!defined('LOGHOUND')) {
    define('LOGHOUND', '1.0.0');
}
