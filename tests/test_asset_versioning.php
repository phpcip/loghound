<?php
/**
 * Loghound — every asset URL the product emits must carry a version.
 *
 * These tests exist because of a release that half-landed. Assets under `/assets/` are served
 * with a long `Cache-Control`, and the three page shells each versioned only the handful of
 * files they named in a `<script src>` or `<link href>`. The panel's JavaScript is an ES module
 * graph, so `app.js` was the only script the HTML named and `core.js`, `identity.js` and every
 * view module arrived through bare `import` specifiers — which resolve with the query string
 * dropped, and therefore requested a versionless URL that the browser already had cached.
 *
 * The visible symptom was two new Overview cards sitting on their skeletons with NO network
 * request against them at all. Nothing errored, because nothing was broken: the browser simply
 * ran a year-old module graph against freshly rendered markup.
 *
 * The guarantee these tests pin is narrow and total: **no URL the product emits for a file
 * under `public/assets/` may be reachable without a version**, and that includes the URLs no
 * shell ever writes down because a module resolved them at runtime.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Assets;

/**
 * Resolve a JavaScript module specifier against the module that imported it.
 *
 * Mirrors what a browser does before it consults the import map: join, then normalise `.` and
 * `..`. Only relative specifiers are resolved — a bare specifier is not a URL and is reported
 * as such by returning an empty string, so a test can fail on one rather than silently skip it.
 */
function lh_av_resolve(string $fromRel, string $spec): string
{
    if (!str_starts_with($spec, './') && !str_starts_with($spec, '../')) {
        return '';
    }

    $parts = explode('/', dirname($fromRel));
    foreach (explode('/', $spec) as $segment) {
        if ($segment === '.' || $segment === '') {
            continue;
        }
        if ($segment === '..') {
            array_pop($parts);
            continue;
        }
        $parts[] = $segment;
    }

    return implode('/', array_filter($parts, static fn (string $p): bool => $p !== ''));
}

/**
 * Every module specifier one module imports.
 *
 * Three forms are matched and nothing else: a single-line or multi-line `import … from '…'`,
 * a side-effect `import '…'`, and a dynamic `import('…')`.
 *
 * The character class between the keyword and `from` excludes `;`, `(`, `)` and `=` on purpose.
 * A lazy `[\s\S]*?` instead matched an `export function …(…) {` line and then ran on to the
 * next `from '` that happened to appear inside a prose comment further down the file, which
 * reported charts.js as importing a paragraph of English.
 *
 * @return array<int,string>
 */
function lh_av_imports(string $source): array
{
    $out = [];

    if (preg_match_all('~^[ \t]*import\b[^;()=]*?\bfrom\s*[\'"]([^\'"]+)[\'"]~m', $source, $m)) {
        foreach ($m[1] as $spec) {
            $out[] = $spec;
        }
    }
    if (preg_match_all('~^[ \t]*import\s*[\'"]([^\'"]+)[\'"]\s*;~m', $source, $m)) {
        foreach ($m[1] as $spec) {
            $out[] = $spec;
        }
    }
    if (preg_match_all('~\bimport\s*\(\s*[\'"]([^\'"]+)[\'"]~', $source, $m)) {
        foreach ($m[1] as $spec) {
            $out[] = $spec;
        }
    }

    return $out;
}

/** The PHP sources of the three page shells that emit asset URLs. */
function lh_av_shells(): array
{
    $root = dirname(__DIR__);

    return [
        'src/Panel/Layout.php' => (string) file_get_contents($root . '/src/Panel/Layout.php'),
        'src/Panel/Login.php'  => (string) file_get_contents($root . '/src/Panel/Login.php'),
        'src/Setup/View.php'   => (string) file_get_contents($root . '/src/Setup/View.php'),
    ];
}

return [

    /* ------------------------------------------------------------------ the map itself */

    'the import map lists every JavaScript file under public/assets' => function (): void {
        $map = json_decode(Assets::importMap(), true);
        lh_true(is_array($map), 'the import map is JSON');
        lh_has_key($map, 'imports', 'import map');

        $files = Assets::scripts();
        lh_true($files !== [], 'the scan found module files at all');

        foreach ($files as $rel) {
            lh_has_key(
                $map['imports'],
                $rel,
                $rel . ' is a module on disk and is missing from the import map, so anything that '
                    . 'imports it would be served from cache forever'
            );
        }

        lh_same(
            count($files),
            count($map['imports']),
            'the map has exactly one entry per module file and no invented ones'
        );
    },

    'every import map target carries a version derived from the file' => function (): void {
        $map = json_decode(Assets::importMap(), true);
        $root = dirname(__DIR__);

        foreach ($map['imports'] as $rel => $target) {
            lh_contains($target, '?v=', $rel . ' is mapped to a URL with no version');

            $stamp = (string) filemtime($root . '/public/' . $rel);
            lh_same($rel . '?v=' . $stamp, $target, $rel . ' is mapped to its own modification time');
        }
    },

    /* -------------------------------------------------- the graph, not only the entries */

    'every relative import in every module resolves to a file the map versions' => function (): void {
        $root = dirname(__DIR__);
        $map = json_decode(Assets::importMap(), true)['imports'];
        $checked = 0;

        foreach (Assets::scripts() as $rel) {
            $source = (string) file_get_contents($root . '/public/' . $rel);

            foreach (lh_av_imports($source) as $spec) {
                lh_true(
                    str_starts_with($spec, './') || str_starts_with($spec, '../'),
                    $rel . ' imports the bare specifier ' . lh_show($spec) . ', which the import map '
                        . 'does not cover — every module must be imported by a relative path'
                );

                $target = lh_av_resolve($rel, $spec);
                lh_has_key(
                    $map,
                    $target,
                    $rel . ' imports ' . $spec . ' which resolves to ' . $target
                        . ', and that URL has no import map entry, so the browser would request it '
                        . 'unversioned and get whatever it cached last'
                );
                $checked++;
            }
        }

        lh_true($checked > 20, 'the graph walk actually found imports, got ' . $checked);
    },

    /* ------------------------------------------------------ the shells, by their source */

    'no page shell references an asset without a version' => function (): void {
        foreach (lh_av_shells() as $file => $source) {
            if (preg_match_all('~(?:src|href)="(assets/[^"]*|favicon[^"]*|apple-touch-icon[^"]*)"~', $source, $m)) {
                foreach ($m[1] as $literal) {
                    lh_fail(
                        $file . ' references ' . $literal . ' as a literal with no version. Every asset '
                            . 'URL must go through Assets::url() so it carries ?v=<mtime>.'
                    );
                }
            }

            lh_contains(
                $source,
                'Assets::url(',
                $file . ' must build its asset URLs with Assets::url()'
            );
        }
    },

    'every shell that loads a module also emits the import map' => function (): void {
        foreach (lh_av_shells() as $file => $source) {
            if (!str_contains($source, 'type="module"')) {
                continue;
            }
            lh_contains(
                $source,
                'Assets::importMapTag(',
                $file . ' loads an ES module but emits no import map, so everything that module '
                    . 'imports would be requested without a version'
            );
        }
    },

    'the import map is emitted before the first module script' => function (): void {
        foreach (lh_av_shells() as $file => $source) {
            $map = strpos($source, 'Assets::importMapTag(');
            if ($map === false) {
                continue;
            }
            $module = strpos($source, 'type="module"');
            lh_true(
                $module === false || $map < $module,
                $file . ' emits the import map after its first module script; a map that arrives '
                    . 'after resolution has begun is ignored by the browser'
            );
        }
    },

    /* ------------------------------------------------------------------------- the CSP */

    'the CSP admits the import map by hash and never by unsafe-inline' => function (): void {
        $hash = Assets::importMapCspHash();
        lh_true((bool) preg_match("~^'sha256-[A-Za-z0-9+/]+=*'$~", $hash), 'the hash is a CSP source expression');

        $expected = "'sha256-" . base64_encode(hash('sha256', Assets::importMap(), true)) . "'";
        lh_same($expected, $hash, 'the hash covers the exact bytes the map is emitted as');

        $source = (string) file_get_contents(dirname(__DIR__) . '/src/Security.php');
        lh_contains($source, 'Assets::importMapCspHash()', 'sendSecurityHeaders() puts the hash in the policy');
        lh_false(
            str_contains($source, "script-src 'self' 'unsafe-inline'"),
            'the import map must never be admitted by loosening script-src to unsafe-inline'
        );
    },

    'the import map tag has no whitespace around the JSON a hash would not cover' => function (): void {
        $tag = Assets::importMapTag();
        lh_same(
            '<script type="importmap">' . Assets::importMap() . '</script>',
            $tag,
            'the tag wraps the hashed bytes exactly'
        );
    },

    /* ------------------------------------------------- a changed file changes its URL */

    'touching a module changes its URL and the policy that admits the map' => function (): void {
        $dir = lh_tmpdir('lh_assets');
        mkdir($dir . '/public/assets/js/views', 0o755, true);

        file_put_contents($dir . '/public/assets/js/core.js', "export const a = 1;\n");
        file_put_contents($dir . '/public/assets/js/views/x.js', "import { a } from '../core.js';\n");
        touch($dir . '/public/assets/js/core.js', 1000000000);

        $before = json_decode(Assets::importMap($dir), true)['imports']['assets/js/core.js'];
        $hashBefore = Assets::importMapCspHash($dir);
        lh_same('assets/js/core.js?v=1000000000', $before, 'the stamp is the modification time');

        clearstatcache();
        touch($dir . '/public/assets/js/core.js', 1000000042);

        $fresh = dirname(__DIR__) . '/.lh-assets-probe';
        rename($dir, $fresh);
        $after = json_decode(Assets::importMap($fresh), true)['imports']['assets/js/core.js'];
        $hashAfter = Assets::importMapCspHash($fresh);
        rename($fresh, $dir);

        lh_same('assets/js/core.js?v=1000000042', $after, 'a changed file produces a different URL');
        lh_true($before !== $after, 'the URL genuinely changed');
        lh_true($hashBefore !== $hashAfter, 'the CSP hash tracks the map');

        lh_rmtree($dir);
    },

    'a missing file is still versioned rather than served from a bare URL' => function (): void {
        $dir = lh_tmpdir('lh_assets_missing');
        mkdir($dir . '/public', 0o755, true);

        lh_same('assets/js/nope.js?v=0', Assets::url('assets/js/nope.js', $dir), 'absent files get ?v=0');

        lh_rmtree($dir);
    },

    /* ------------------------------------------------------- the header that makes it matter */

    'a long immutable cache is only claimed where every URL is versioned' => function (): void {
        $root = dirname(__DIR__);
        $configs = [
            'install/install.sh',
            'install/apache-vhost.conf.example',
            'install/nginx-vhost.conf.example',
        ];

        foreach ($configs as $rel) {
            $source = (string) file_get_contents($root . '/' . $rel);

            if (!preg_match_all('~Cache-Control[^\n]*immutable~', $source, $m)) {
                lh_fail($rel . ' no longer sets an immutable cache anywhere; if that was deliberate, '
                    . 'update this test to say what the policy is now');
            }

            foreach ($m[0] as $line) {
                lh_true(
                    str_contains($line, 'max-age='),
                    $rel . ' has an immutable Cache-Control with no max-age: ' . $line
                );
            }
        }
    },

    'the served asset paths in the vhosts are the ones the shells emit' => function (): void {
        $root = dirname(__DIR__);
        foreach (['install/apache-vhost.conf.example', 'install/nginx-vhost.conf.example'] as $rel) {
            $source = (string) file_get_contents($root . '/' . $rel);
            lh_contains($source, '/assets/', $rel . ' must carry a policy for the assets directory');
        }
    },
];
