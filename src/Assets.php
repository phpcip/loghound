<?php
/**
 * Loghound — one version stamp for every static asset the product serves.
 *
 * ## The bug this file exists to close
 *
 * Assets under `/assets/` are served with a long `Cache-Control`. That is only ever correct
 * if the URL changes when the file changes, and for most of this product's life it did not.
 * Three page shells — the panel, the sign-in page and the setup wizard — each carried their
 * own private copy of a `?v=<filemtime>` closure, which covered the files they named in a
 * `<script src>` or `<link href>` and nothing else.
 *
 * Nothing else is the important part. The panel's JavaScript is an ES MODULE GRAPH:
 * `app.js` is the only file the HTML names, and it pulls in `core.js`, `charts.js`,
 * `identity.js` and a dozen view modules through `import` statements. A module specifier is
 * resolved against the importing module's URL with the query string DROPPED, so
 * `import { boot } from './core.js'` inside `app.js?v=1757600000` requests a bare
 * `/assets/js/core.js` — no version, and therefore the copy the browser cached whenever this
 * operator first opened the panel.
 *
 * The effect is a release that half-lands. `app.js` re-downloads because its stamp moved, and
 * then imports a year-old `core.js` alongside a year-old `views/overview.js`. New cards sit on
 * their skeletons with no network request against them at all, because the module that would
 * have fetched them was never re-fetched. Nothing errors, so nothing says why.
 *
 * ## How the graph is versioned
 *
 * With an IMPORT MAP, emitted by every page shell that loads a module. It lists every `.js`
 * file under `public/assets/` and maps its bare URL onto the same URL carrying that file's
 * modification time:
 *
 *     {"imports":{"assets/js/core.js":"assets/js/core.js?v=1757600000", …}}
 *
 * A relative specifier is resolved to a URL first and then looked up in the map, so
 * `./core.js` from `app.js` and `../core.js` from `views/overview.js` both land on the same
 * key and both get the versioned URL. Static imports, dynamic `import()` and every depth of
 * the graph are covered by the one mechanism, and no file on disk has to be rewritten — which
 * matters, because this product has no build step and is not going to grow one.
 *
 * Map keys are relative, exactly like the `src` and `href` attributes beside them, so they
 * resolve against the same document base URL and keep working wherever the panel is mounted.
 *
 * ## Why this is allowed under a CSP with no 'unsafe-inline'
 *
 * An import map has to be inline — there is no interoperable external form — and it is an
 * executable script as far as `script-src` is concerned, so `script-src 'self'` alone blocks
 * it. It is admitted by HASH: the JSON is generated once, `sha256Csp()` hashes those exact
 * bytes, and Security::sendSecurityHeaders() puts `'sha256-…'` into the policy. A hash permits
 * one known string and nothing else, so the policy is not loosened; 'unsafe-inline' is never
 * introduced and no nonce has to be plumbed through three shells.
 *
 * If a browser too old for import maps ever loads the panel it ignores the map and resolves
 * bare specifiers as before — the old behaviour, not a broken page.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Assets
{
    /**
     * Memoised import maps, keyed by application root.
     *
     * The map is read by sendSecurityHeaders() to hash it and by the page shell to emit it,
     * and the two MUST agree byte for byte or the browser drops the map and the graph goes
     * stale again — silently, which is the failure mode this whole file is about. Building it
     * once per request per root is what guarantees they cannot disagree.
     *
     * @var array<string,string>
     */
    private static array $maps = [];

    /**
     * The application root — the directory holding `public/`.
     *
     * Callers that already track their own root (the sign-in page and the setup wizard both
     * do, because their tests run them against a temporary tree) pass it explicitly.
     */
    public static function root(): string
    {
        return dirname(__DIR__);
    }

    /**
     * A versioned URL for one asset, relative to the document base.
     *
     * The stamp is the file's modification time, which is the mechanism already used for the
     * beacon and already explained to operators in the Settings card and in docs/INSTALL.md.
     * A missing file yields `?v=0` rather than a bare URL, so an asset that is referenced but
     * not deployed still cannot be cached under a versionless URL.
     *
     * @param string      $rel  Path under `public/`, e.g. `assets/js/app.js`.
     * @param string|null $root Application root; defaults to this installation's.
     */
    public static function url(string $rel, ?string $root = null): string
    {
        $base = $root ?? self::root();
        $path = $base . '/public/' . $rel;
        $stamp = is_file($path) ? (string) filemtime($path) : '0';

        return $rel . '?v=' . $stamp;
    }

    /**
     * The import map JSON, exactly as it is emitted and exactly as it is hashed.
     *
     * Every `.js` file under `public/assets/` is listed, not only the ones something imports
     * today: a map entry for a file nobody imports costs a few bytes, while a missing entry is
     * the silent staleness bug returning for whichever module was added last.
     *
     * Keys are sorted so the JSON is byte-stable for a given set of files and modification
     * times. An unstable key order would change the CSP hash on every request while the map
     * itself stayed semantically identical, which breaks nothing but makes the policy header
     * impossible to reason about or cache.
     *
     * JSON_HEX_TAG is what stops a file named with a `<` from closing the script element. The
     * `/` in every path is left unescaped because `\/` would be legal JSON but would change
     * the bytes for no benefit.
     *
     * @param string|null $root Application root; defaults to this installation's.
     */
    public static function importMap(?string $root = null): string
    {
        $base = $root ?? self::root();
        if (isset(self::$maps[$base])) {
            return self::$maps[$base];
        }

        $imports = [];
        foreach (self::scripts($base) as $rel) {
            $imports[$rel] = self::url($rel, $base);
        }
        ksort($imports);

        $json = json_encode(
            ['imports' => (object) $imports],
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
        );

        return self::$maps[$base] = is_string($json) ? $json : '{"imports":{}}';
    }

    /**
     * The `<script type="importmap">` element, ready to emit.
     *
     * It must be in the document before the first module script, because a map that arrives
     * after resolution has begun is ignored — so every shell emits it in <head>.
     *
     * @param string|null $root Application root; defaults to this installation's.
     */
    public static function importMapTag(?string $root = null): string
    {
        return '<script type="importmap">' . self::importMap($root) . '</script>';
    }

    /**
     * The CSP source expression that admits the import map.
     *
     * Hashes cover the element's text content only, with no surrounding whitespace, which is
     * why importMapTag() emits the JSON tight against the tags.
     *
     * @param string|null $root Application root; defaults to this installation's.
     */
    public static function importMapCspHash(?string $root = null): string
    {
        return self::sha256Csp(self::importMap($root));
    }

    /** A `'sha256-…'` CSP source expression for a literal script body. */
    public static function sha256Csp(string $body): string
    {
        return "'sha256-" . base64_encode(hash('sha256', $body, true)) . "'";
    }

    /**
     * Every `.js` file under `public/assets/`, as paths relative to `public/`.
     *
     * Walked rather than listed, so a module added under `assets/js/views/` is versioned the
     * day it lands without anybody remembering to register it. Sorted for determinism.
     *
     * @return array<int,string>
     */
    public static function scripts(?string $root = null): array
    {
        $base = ($root ?? self::root()) . '/public';
        $dir = $base . '/assets';
        if (!is_dir($dir)) {
            return [];
        }

        $out = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile()) {
                continue;
            }
            if (strtolower($file->getExtension()) !== 'js') {
                continue;
            }
            $rel = substr($file->getPathname(), strlen($base) + 1);
            $out[] = str_replace(DIRECTORY_SEPARATOR, '/', $rel);
        }
        sort($out);

        return $out;
    }
}
