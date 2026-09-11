<?php
/**
 * Loghound — the one description of the beacon, rendered in every medium.
 *
 * WHY THIS CLASS EXISTS. The beacon snippet used to be built in four places and described in
 * six. They disagreed: the installer and the shell wizard handed out `b.js?v=1`, hardcoded,
 * while the panel built the same tag from the file's modification time and explained, next to
 * it, that the `?v=` is what makes an update reach a returning visitor. An operator who pasted
 * the snippet they were given at the end of setup pinned every visitor of their site to the
 * first version of the beacon for good, because `b.js` is served `immutable` for a week.
 *
 * So there is one structured description here, and every surface renders it in its own medium:
 * HTML for the panel and the installer, plain text for `install.sh` and `bin/loghound-setup`,
 * Markdown for `docs/BEACON.md`. A shell script cannot call a PHP array, so `install.sh` shells
 * out to `bin/loghound-setup --beacon-doc` and prints what comes back rather than carrying a
 * copy of the words.
 *
 * THE PROSE IS WRITTEN ONCE, IN AN INLINE MARKUP OF TWO MARKERS. `` `x` `` is an identifier and
 * `**x**` is emphasis; inlineHtml(), inlineText() and inlineMarkdown() turn either into the
 * right thing for the medium. Nothing here contains HTML, so nothing here can leak a `<code>`
 * tag into a terminal.
 *
 * THE OPTION LIST IS HELD AGAINST `public/b.js` BY TEST. Every `attr('data-…')`, every
 * `attrInt('data-…')` and every `w.Loghound…` in that file is derivable from its source, and
 * tests/test_standalone.php asserts that each one appears in options() and on every surface
 * that renders them. An option added to the script cannot be documented in one place and
 * missing from five.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Beacon;

use Loghound\Config;

final class Doc
{
    /** The script a site embeds, relative to the public root. */
    public const FILE = 'b.js';

    /** The collector the script posts to, relative to the same root. */
    public const COLLECTOR = 'collect.php';

    /**
     * The cache-busting version for `b.js`, from the file's own modification time.
     *
     * The beacon is served with a long `Cache-Control` (SPEC §3), so the only thing that makes a
     * fix reach a visitor who already has the old file is a different URL. Using the mtime means
     * there is no number to remember to bump and no build step to run — and, because this is the
     * only place it is worked out, no second surface can hand out a version of its own.
     *
     * Falls back to `1` only when the file cannot be seen at all, which is a checkout with no
     * public directory rather than an installation anybody is measuring a site with.
     */
    public static function version(): string
    {
        $path = \dirname(__DIR__, 2) . '/public/' . self::FILE;
        $mtime = is_file($path) ? filemtime($path) : false;

        return $mtime === false ? '1' : (string) $mtime;
    }

    /**
     * The full URL of the beacon script for an installation reachable at `$base`.
     *
     * @param string $base Public URL of the panel, without a trailing slash.
     */
    public static function src(string $base): string
    {
        return rtrim($base, '/') . '/' . self::FILE . '?v=' . self::version();
    }

    /**
     * The one-line script tag, with whatever attributes the caller has to ship.
     *
     * EVERY SURFACE THAT PRINTS A SNIPPET COMES THROUGH HERE. That is the whole point: the tag
     * an operator copies off the last screen of setup and the tag the panel shows them a week
     * later are the same string, built once, carrying the same version.
     *
     * @param array<string,string> $attrs Extra attributes, in the order they should appear.
     */
    public static function snippet(string $base, array $attrs = []): string
    {
        $rendered = '';
        foreach ($attrs as $name => $value) {
            $rendered .= ' ' . $name . '="' . $value . '"';
        }

        return '<script src="' . self::src($base) . '"' . $rendered . ' defer></script>';
    }

    /**
     * The attributes THIS installation's snippet has to carry to work as printed.
     *
     * Only `data-params` qualifies. It is the one option whose value has to agree with a server
     * setting for anything to be stored, so a snippet that advertised it on an installation with
     * an empty `beacon.query_params` would be an instruction that cannot succeed — and one that
     * omitted it on an installation that has configured names would silently collect nothing
     * from the pages that needed it most.
     *
     * @return array<string,string>
     */
    public static function configuredAttrs(Config $cfg): array
    {
        $collected = \Loghound\Beacon::normaliseParamNames((array) $cfg->get('beacon.query_params', []));

        return $collected === [] ? [] : ['data-params' => implode(',', $collected)];
    }

    /**
     * Every option `public/b.js` reads: six attributes, two globals, one function.
     *
     * Each entry says what the option does, what happens when it is absent, what values are
     * accepted, and which configuration key decides whether what it sends is actually STORED. A
     * null `switch` means nothing can discard it — the value is used by the script itself.
     *
     * The strings carry the inline markup described in this file's header, never HTML, so the
     * same entry renders correctly in a browser, in a terminal and in a Markdown file.
     *
     * @return array<int,array{name:string,kind:string,what:string,default:string,limits:string,example:string,switch:?string}>
     */
    public static function options(): array
    {
        return [
            [
                'name'    => 'data-endpoint',
                'kind'    => 'attribute',
                'what'    => 'Collector URL, when it is not a sibling of `b.js`.',
                'default' => 'the script’s own `src` with `' . self::FILE . '` → `' . self::COLLECTOR . '`',
                'limits'  => 'Any URL. Set it only if you serve the script from a CDN or a different path.',
                'example' => 'data-endpoint="https://loghound.example.com/collect.php"',
                'switch'  => null,
            ],
            [
                'name'    => 'data-hb',
                'kind'    => 'attribute',
                'what'    => 'Heartbeat interval, in milliseconds. A beat is sent only when engaged time '
                    . 'actually advanced, so an idle tab produces one, not hundreds.',
                'default' => '15000',
                'limits'  => 'Integer, clamped to 2 000–300 000. Anything else is ignored and the default '
                    . 'is used.',
                'example' => 'data-hb="30000"',
                'switch'  => null,
            ],
            [
                'name'    => 'data-idle',
                'kind'    => 'attribute',
                'what'    => 'How long after a real interaction a visitor still counts as engaged, in '
                    . 'milliseconds. This is the definition of the **Engaged** clock.',
                'default' => '30000',
                'limits'  => 'Integer, clamped to 1 000–600 000.',
                'example' => 'data-idle="60000"',
                'switch'  => null,
            ],
            [
                'name'    => 'data-ident',
                'kind'    => 'attribute',
                'what'    => 'An identity **your site** attaches to the session — an email address, a '
                    . 'customer number, whatever you call the person. Never guessed.',
                'default' => 'absent, and absent is not empty',
                'limits'  => 'Free text, truncated to ' . \Loghound\Beacon::MAX_IDENT . ' bytes. Control '
                    . 'characters stripped, invalid UTF-8 repaired.',
                'example' => 'data-ident="<?= htmlspecialchars($user->email, ENT_QUOTES) ?>"',
                'switch'  => 'beacon.store_identity',
            ],
            [
                'name'    => 'data-signed-in',
                'kind'    => 'attribute',
                'what'    => 'Whether the visitor was signed in. Splits every number in the panel into '
                    . 'signed-in and anonymous.',
                'default' => 'absent — which means **not reported**, never “no”. An attribute that is '
                    . 'present but empty is an answer, and the answer is **no**',
                'limits'  => '`1`/`0` or `true`/`false`. An empty attribute — the usual shape of a '
                    . 'template that renders nothing for a visitor who is not signed in — is read as '
                    . '**false**, so `data-signed-in="{{ user.id }}"` works unchanged for both. Any '
                    . 'other value is read as not reported.',
                'example' => 'data-signed-in="<?= $user->isSignedIn() ? \'1\' : \'0\' ?>"',
                'switch'  => 'beacon.store_signed_in',
            ],
            [
                'name'    => 'data-params',
                'kind'    => 'attribute',
                'what'    => 'URL query parameter **names** whose values are kept as search terms. Nothing '
                    . 'else in the query string is read.',
                'default' => 'absent — no parameter is collected',
                'limits'  => 'Comma separated. At most ' . \Loghound\Beacon::MAX_TERMS . ' names, each at '
                    . 'most 40 characters of `a-z 0-9 _ - . [ ]`. Each value is capped at '
                    . \Loghound\Beacon::MAX_TERM . ' characters and dropped, not truncated, if longer.',
                'example' => 'data-params="q,category,sort"',
                'switch'  => 'beacon.query_params',
            ],
            [
                'name'    => 'window.LoghoundIdent',
                'kind'    => 'global',
                'what'    => 'The same value as `data-ident`, for a template where adding an attribute to '
                    . 'the tag is awkward but setting a variable above it is not.',
                'default' => 'unset',
                'limits'  => 'A string. Must be set **before** b.js executes — with `defer` that means '
                    . 'anywhere in the document. The attribute wins if both are present.',
                'example' => '<script>window.LoghoundIdent = "ada@example.com";</script>',
                'switch'  => 'beacon.store_identity',
            ],
            [
                'name'    => 'window.LoghoundSignedIn',
                'kind'    => 'global',
                'what'    => 'The same value as `data-signed-in`.',
                'default' => 'unset — not reported',
                'limits'  => 'A real boolean, or the same strings the attribute accepts. Must be set '
                    . 'before b.js executes.',
                'example' => '<script>window.LoghoundSignedIn = true;</script>',
                'switch'  => 'beacon.store_signed_in',
            ],
            [
                'name'    => 'window.loghound.identify(ident, signedIn)',
                'kind'    => 'function',
                'what'    => 'Attach either value **after** the page has loaded — a single-page '
                    . 'application that signs somebody in without a navigation, which no attribute can '
                    . 'express.',
                'default' => 'never called',
                'limits'  => 'Both arguments optional and independent. **Makes no request of its own:** '
                    . 'the values ride the heartbeat that is already scheduled. Safe to call with '
                    . 'anything — it cannot throw into your code.',
                'example' => 'window.loghound.identify(user.email, true);',
                'switch'  => 'beacon.store_identity / beacon.store_signed_in',
            ],
        ];
    }

    /**
     * The three ways a site supplies an identity, and the situation each one is the answer to.
     *
     * They are not alternatives to pick between on taste, which is why each carries the
     * situation rather than only the syntax. The code is written the way somebody would actually
     * paste it — out of the user object their framework already has — because a literal address
     * in an example is the one form nobody can use unedited.
     *
     * @param string $base Public URL of this installation; given one, the tag carries the real
     *                     address and version instead of a shape the reader has to fill in.
     * @return array<int,array{key:string,title:string,when:string,code:string}>
     */
    public static function routes(string $base = ''): array
    {
        $src = $base === '' ? self::FILE . '?v=…' : self::src($base);

        return [
            [
                'key'   => 'attributes',
                'title' => 'Attributes on the script tag',
                'when'  => '**When your server already knows who it is at render time.** The normal case: '
                    . 'the template that renders the page renders the tag, in the same response, so there '
                    . 'is no second request, no extra script and no ordering problem.',
                'code'  => '<script src="' . $src . '"' . "\n"
                    . '        data-ident="<?= htmlspecialchars($user->email, ENT_QUOTES) ?>"' . "\n"
                    . '        data-signed-in="<?= $user->isSignedIn() ? \'1\' : \'0\' ?>"' . "\n"
                    . '        defer></script>',
            ],
            [
                'key'   => 'globals',
                'title' => '`window.LoghoundIdent` / `window.LoghoundSignedIn`',
                'when'  => '**When adding an attribute to the tag is awkward but setting a variable above '
                    . 'it is not** — a tag manager, a templating system that owns the script element, a '
                    . 'CMS block you cannot edit. They must be set **before** b.js executes, which with '
                    . '`defer` means anywhere in the document.',
                'code'  => '<script>' . "\n"
                    . '  window.LoghoundIdent = "<?= htmlspecialchars($user->email, ENT_QUOTES) ?>";' . "\n"
                    . '  window.LoghoundSignedIn = <?= $user->isSignedIn() ? \'true\' : \'false\' ?>;' . "\n"
                    . '</script>',
            ],
            [
                'key'   => 'identify',
                'title' => '`window.loghound.identify(ident, signedIn)`',
                'when'  => '**When the identity arrives after the page has loaded** — a single-page '
                    . 'application that signs somebody in without a navigation, which no attribute can '
                    . 'express. It **makes no request of its own**: the values ride the heartbeat that is '
                    . 'already scheduled, so attaching an identity costs your site nothing extra.',
                'code'  => 'window.loghound.identify(user.email, true);',
            ],
        ];
    }

    /**
     * The paragraphs every surface has to carry, in the order somebody reads them.
     *
     * Four subjects, and none of them is comfortable enough to leave out of a surface: what
     * `beacon.store_identity` being off by default means for a pasted snippet, what `data-params`
     * is and what the server-side half of it does, what the hostname allowlist protects against
     * and what it does not, and the two CSP directives with the symptom of missing the second.
     *
     * @return array<int,array{key:string,title:string,paras:array<string,string>}>
     */
    public static function sections(): array
    {
        return [
            [
                'key'   => 'storage',
                'title' => 'What is stored, and what is quietly thrown away',
                'paras' => [
                    'default' => '`beacon.store_identity` is `false` in a new installation. Paste a snippet carrying '
                        . '`data-ident` before you change it and the address is dropped by the collector '
                        . 'before anything is written: the tag loads, the collector answers `204`, the '
                        . 'panel shows nothing, and there is no error anywhere to explain it. Set it to '
                        . '`true` first, or leave the attribute out.',
                    'independent' => '`beacon.store_signed_in` is on in a new installation, so the signed-in split works '
                        . 'as soon as a page declares it. The two switches are independent on purpose: '
                        . 'the boolean identifies nobody and splits engaged time, paths and bot verdicts '
                        . 'between signed-in and anonymous traffic, while the identity string is personal '
                        . 'data that lands on the session document, shows in the panel, lives in the '
                        . 'search index and sits in every backup of it until retention deletes the '
                        . 'session. Plenty of sites want the first and not the second.',
                    'third_state' => 'A site that says nothing is **not reported**, which is a third state and not '
                        . '“anonymous”. `signed_in_b` is written only when a page actually said one or '
                        . 'the other, so a site that has not adopted the attribute cannot be read as a '
                        . 'site full of anonymous visitors.',
                ],
            ],
            [
                'key'   => 'params',
                'title' => 'Search terms, and the two halves of the whitelist',
                'paras' => [
                    'names' => '`data-params` names the URL query parameters whose values are kept — `q`, `s`, '
                        . '`search`, whatever your search box uses. Nothing else in the query string is '
                        . 'read. This is the one place Loghound stores something a person typed rather '
                        . 'than a measurement or a hash, so it is a whitelist of parameter **names** and '
                        . 'never the whole URL: a page address carries session tokens and password-reset '
                        . 'codes, and none of those may become a facet value.',
                    'server_half' => 'The attribute is only half of it. `beacon.query_params` on the server is the other '
                        . 'half and it is authoritative: a name the page sends and the server has not '
                        . 'listed is discarded on arrival. The attribute is a promise to the visitor '
                        . 'about what leaves their browser; the setting is the decision about what is '
                        . 'stored. Both are empty in a new installation, so upgrading the beacon cannot '
                        . 'start shipping URLs that were not being shipped before.',
                ],
            ],
            [
                'key'   => 'standalone',
                'title' => 'A site on another server',
                'paras' => [
                    'allowlist' => 'The beacon works unchanged on a host this machine has no access log for — a search '
                        . 'page, a marketing site, anything on another server. Paste the same snippet, '
                        . 'and nothing else has to be installed there. The page reports its own hostname '
                        . 'and a session is created for it when that hostname is listed in '
                        . '`beacon.allowed_hosts`, which is empty in a new installation.',
                    'limits' => '**Treat the allowlist as a permission, not as a password.** A browser cannot forge '
                        . 'the `Origin` header, so an ordinary web page cannot impersonate a site you '
                        . 'listed. Anything that is not a browser can send any header it likes, so '
                        . 'somebody who knows a hostname is listed can fabricate sessions attributed to '
                        . 'it. That exposure is bounded to the hosts you listed, it cannot read anything '
                        . 'and it cannot reach your log-backed data — and it is exactly why a session '
                        . 'measured by the beacon alone is stored as `planes_s:beacon_only` and shown as '
                        . 'single-plane wherever it is counted.',
                ],
            ],
            [
                'key'   => 'ordering',
                'title' => 'What has to be in the page before b.js runs',
                'paras' => [
                    'globals' => 'The six `data-` attributes are read off the script tag itself, so where they sit '
                        . 'in the document cannot be wrong. The two globals can be: '
                        . '`window.LoghoundIdent` and `window.LoghoundSignedIn` are read **once**, at the '
                        . 'moment b.js executes, so a script that sets them after that has set them for '
                        . 'nothing — the beacon has already sent its first payload and neither value is '
                        . 'in it. With `defer` on the tag, b.js runs only after the document is parsed, '
                        . 'which means anywhere in the page is early enough.',
                    'late' => 'For a value that genuinely is not known until later — a single-page application '
                        . 'that signs somebody in without a navigation — the globals are the wrong '
                        . 'instrument and `window.loghound.identify(ident, signedIn)` is the right one. It '
                        . 'may be called at any point after b.js has run, and it sends nothing by itself: '
                        . 'the values ride the next heartbeat.',
                ],
            ],
            [
                'key'   => 'csp',
                'title' => 'Content-Security-Policy on the measured site',
                'paras' => [
                    'directives' => 'A site that sends a Content-Security-Policy needs two directives, and the second is '
                        . 'the one that gets forgotten: `script-src` for the tag and `connect-src` for '
                        . 'the collector the beacon posts back to. Without `connect-src` the browser '
                        . 'blocks the POST silently — the script loads, nothing arrives, and there is no '
                        . 'error to find.',
                    'fallback' => 'Both are needed even though the beacon tries `navigator.sendBeacon` first: a '
                        . 'browser that does not have it, or refuses the call, falls back to `fetch`, and '
                        . '`connect-src` governs both. The beacon uses no `eval`, no `new Function`, no '
                        . 'inline handler and no `innerHTML`, so nothing else has to be relaxed.',
                ],
            ],
        ];
    }

    /**
     * One paragraph out of sections(), by name.
     *
     * Named rather than numbered because a surface that renders three of the four sections in a
     * different order — the panel does — would otherwise be holding a positional index into a
     * list somebody else maintains, and a paragraph inserted above it would silently move.
     */
    public static function para(string $section, string $key): string
    {
        foreach (self::sections() as $one) {
            if ($one['key'] === $section) {
                return (string) ($one['paras'][$key] ?? '');
            }
        }

        return '';
    }

    /**
     * Why the beacon is worth the one line of HTML, in one paragraph.
     *
     * Plain sentences with no markup, because the surfaces that print it — the installer's last
     * screen, the panel's finish card, the shell wizard — all render it as escaped prose.
     */
    public static function rationale(): string
    {
        return 'If your site sends a Content-Security-Policy, the browser will refuse this script '
            . 'until you allow it: add this panel\'s origin to script-src and to connect-src, '
            . 'because the tag loads from there and the beacon posts back to the same place. '
            . 'Miss connect-src and the browser blocks the POST silently, so the script loads and '
            . 'nothing ever arrives. The measured site does not have to be on this machine — the '
            . 'same snippet is the whole installation on another server, provided that hostname is '
            . 'listed in beacon.allowed_hosts, which is a permission rather than a password. '
            . 'Without the beacon Loghound still works, but the execution plane is blind — '
            . 'headless automation is inferred rather than proven, and time-on-site falls back '
            . 'to the weak log-derived number every other log analyser reports.';
    }

    /**
     * Every option in one paragraph, with its default, its limit and the switch over it.
     *
     * THE INSTALLER'S LAST SCREEN HAS TWO PROSE SLOTS AND THIS IS ONE OF THEM, which is why nine
     * options are described in a paragraph rather than in a table. The moment somebody is pasting
     * the tag into their template is the moment adding an attribute costs nothing, and it is also
     * the moment they should be told that one of them stores personal data and is switched off
     * until they say otherwise. A capability documented only in docs/BEACON.md is a capability
     * nobody uses.
     *
     * Plain sentences with no markup, for the same reason rationale() is.
     */
    public static function optionsNote(): string
    {
        return 'Optional, and only your site can supply them: add data-signed-in="1" or "0" to '
            . 'record whether the visitor was signed in, and data-ident="..." to attach an '
            . 'identity — an email address, a customer number, whatever you call the person. '
            . 'Omit an attribute and Loghound stores nothing for it; it never guesses either, '
            . 'reads no cookie and scrapes no form. The signed-in flag is a boolean that '
            . 'identifies nobody and is stored by default, and it is the more useful of the two: '
            . 'it splits engaged time, paths and bot verdicts between signed-in and anonymous '
            . 'traffic. The identity string is personal data — it is written to the session '
            . 'document, shows in the panel, lives in the search index and is in every backup of '
            . 'it until retention deletes the session — so beacon.store_identity is false until '
            . 'you set it to true, and the two switches are independent. The same two values can '
            . 'come from window.LoghoundIdent and window.LoghoundSignedIn, set before b.js runs, '
            . 'or from window.loghound.identify(ident, signedIn) when somebody signs in after the '
            . 'page loaded; identify() sends nothing of its own, the values ride the heartbeat '
            . 'that is already scheduled. An identity is truncated to ' . \Loghound\Beacon::MAX_IDENT
            . ' bytes. data-params names the URL query parameters kept as search terms, at most '
            . \Loghound\Beacon::MAX_TERMS . ' of them and each value capped at '
            . \Loghound\Beacon::MAX_TERM . ' characters, and the server\'s own beacon.query_params '
            . 'list decides which of those names are stored — both are empty until you fill them '
            . 'in, and no other part of the query string is ever read. The three remaining '
            . 'attributes tune the script itself and nothing can discard what they do: data-hb is '
            . 'the heartbeat in milliseconds and defaults to 15000, clamped to 2000-300000; '
            . 'data-idle is how long after a real interaction a visitor still counts as engaged '
            . 'and defaults to 30000, clamped to 1000-600000; data-endpoint overrides the '
            . 'collector URL, which otherwise is the script\'s own src with b.js swapped for '
            . 'collect.php, and is only needed behind a CDN or a different path.';
    }

    /**
     * The origin a measured site has to name in its Content-Security-Policy.
     *
     * The scheme and host of the panel's own URL, with no path: a CSP source is an origin, and
     * pasting a URL with a path into one is the mistake that makes the directive silently not
     * match. An address that cannot be parsed yields an empty string rather than a plausible
     * placeholder, so a caller can refuse instead of printing a host nobody owns.
     */
    public static function cspOrigin(string $base): string
    {
        $parts = $base === '' ? false : parse_url($base);
        if (!is_array($parts) || ($parts['host'] ?? '') === '') {
            return '';
        }

        return ($parts['scheme'] ?? 'https') . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . (int) $parts['port'] : '');
    }

    /**
     * The two directives a measured site adds, as one pasteable line.
     *
     * One line rather than two because it sits under a copy button on three surfaces, and
     * because that is the shape a CSP header is written in anyway.
     */
    public static function cspDirectives(string $origin): string
    {
        return 'script-src ' . $origin . '; connect-src ' . $origin . ';';
    }

    /**
     * Whether THIS installation will keep what an option sends.
     *
     * The reason the reference is worth rendering inside the application at all rather than only
     * in a document. A reference that lists `data-ident` without saying that `beacon.store_identity`
     * is off HERE sends an operator away to paste a snippet, see nothing, and have no way to find
     * out why. The document cannot know; a running installation can.
     *
     * Four answers. `always` is an option nothing can discard, because the script uses it itself.
     * `yes` names the switch that is on, so the operator knows which line in the config file is
     * doing it. `discarded` says so in as many words, because the failure it warns about is
     * completely silent. `partly` is for the one option governed by both switches, and it reports
     * the weaker of the two: saying yes while half of what it can send is dropped would be the
     * misleading half of the truth.
     *
     * @return array{state:string,detail:string} `detail` carries the inline markup of this file.
     */
    public static function optionState(?string $switch, Config $cfg): array
    {
        if ($switch === null) {
            return ['state' => 'always', 'detail' => 'used by the script itself'];
        }

        if ($switch === 'beacon.query_params') {
            $collected = \Loghound\Beacon::normaliseParamNames((array) $cfg->get('beacon.query_params', []));
            if ($collected === []) {
                return [
                    'state'  => 'discarded',
                    'detail' => '`beacon.query_params` is empty, so no parameter is accepted',
                ];
            }
            $names = [];
            foreach ($collected as $name) {
                $names[] = '`' . $name . '`';
            }

            return ['state' => 'yes', 'detail' => 'accepting ' . implode(', ', $names)];
        }

        $state = [
            'beacon.store_identity'  => (bool) $cfg->get('beacon.store_identity', false),
            'beacon.store_signed_in' => (bool) $cfg->get('beacon.store_signed_in', true),
        ];

        $keys = array_map('trim', explode('/', $switch));
        $off  = [];
        foreach ($keys as $key) {
            if (empty($state[$key])) {
                $off[] = $key;
            }
        }

        if ($off === []) {
            return ['state' => 'yes', 'detail' => '`' . $keys[0] . '` is on'];
        }

        $named = [];
        foreach ($off as $key) {
            $named[] = '`' . $key . '`';
        }

        return [
            'state'  => count($off) === count($keys) ? 'discarded' : 'partly',
            'detail' => implode(' and ', $named) . (count($off) === 1 ? ' is off' : ' are off'),
        ];
    }

    /**
     * Inline markup as HTML: identifiers become `code`, emphasis becomes `strong`.
     *
     * The whole string is escaped FIRST and the two markers are converted afterwards, so a value
     * that arrived from a configuration file cannot open a tag. Escaping introduces no backtick
     * and no asterisk, so the order is safe in both directions.
     */
    public static function inlineHtml(string $text): string
    {
        $out = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $out = (string) preg_replace('~`([^`]+)`~', '<code class="mono">$1</code>', $out);

        return (string) preg_replace('~\*\*([^*]+)\*\*~', '<strong>$1</strong>', $out);
    }

    /** Inline markup as plain text: both markers are simply dropped. */
    public static function inlineText(string $text): string
    {
        return str_replace(['`', '**'], '', $text);
    }

    /** Inline markup as Markdown: the markers already are Markdown. */
    public static function inlineMarkdown(string $text): string
    {
        return $text;
    }

    /**
     * The complete reference as plain text, for a terminal.
     *
     * What `install.sh` prints at the end of an install and what `bin/loghound-setup --beacon-doc`
     * writes to stdout. Wrapped at 76 columns so it survives an 80-column terminal and a copied
     * install log, and indented rather than boxed so that copying a snippet out of it is one
     * selection.
     *
     * @param string $base Public URL of this installation; an empty one prints the reference
     *                     without a snippet, rather than one pointing at an invented host.
     */
    public static function renderText(Config $cfg, string $base): string
    {
        $base = rtrim(trim($base), '/');
        $out = [];

        $out[] = 'THE BEACON — one line of JavaScript, optional, on every page you measure.';
        $out[] = '';

        if ($base === '') {
            $out[] = self::wrap('No public address is configured for this installation, so there is '
                . 'no snippet to print. Set base_url in config/loghound.php to the URL your '
                . 'visitors would reach this panel at, and the snippet is on the Settings page.', 2);
        } else {
            $out[] = '  ' . self::snippet($base, self::configuredAttrs($cfg));
        }

        $out[] = '';
        $out[] = self::wrap(self::rationale(), 2);
        $out[] = '';
        $out[] = 'EVERY OPTION IT READS';
        $out[] = '';

        foreach (self::options() as $opt) {
            $state = self::optionState($opt['switch'], $cfg);
            $out[] = '  ' . $opt['name'] . '   (' . $opt['kind'] . ')';
            $out[] = self::wrap(self::inlineText($opt['what']), 6);
            $out[] = self::wrap('Default: ' . self::inlineText($opt['default']), 6);
            $out[] = self::wrap('Accepted: ' . self::inlineText($opt['limits']), 6);
            $out[] = '      In code: ' . $opt['example'];
            $out[] = self::wrap('Stored here: ' . self::stateLabel($state['state']) . ' — '
                . self::inlineText($state['detail']), 6);
            $out[] = '';
        }

        $out[] = 'THREE WAYS TO SUPPLY AN IDENTITY, FOR THREE SITUATIONS';
        $out[] = '';

        foreach (self::routes($base) as $route) {
            $out[] = '  ' . self::inlineText($route['title']);
            $out[] = self::wrap(self::inlineText($route['when']), 6);
            $out[] = '';
            foreach (explode("\n", $route['code']) as $line) {
                $out[] = '      ' . $line;
            }
            $out[] = '';
        }

        foreach (self::sections() as $section) {
            $out[] = strtoupper($section['title']);
            $out[] = '';
            foreach ($section['paras'] as $para) {
                $out[] = self::wrap(self::inlineText($para), 2);
                $out[] = '';
            }
            if ($section['key'] === 'csp' && self::cspOrigin($base) !== '') {
                $out[] = '  ' . self::cspDirectives(self::cspOrigin($base));
                $out[] = '';
            }
        }

        $out[] = self::wrap('The same reference, with a column saying what this installation keeps, '
            . 'is on the panel under Settings → Beacon. The long form is in docs/BEACON.md.', 2);

        return implode("\n", $out);
    }

    /**
     * The option table as Markdown, which is what `docs/BEACON.md` carries.
     *
     * The document is a file in the repository and there is no build step to regenerate it, so
     * the test holds the file against this output instead: change an option here and the
     * documentation test fails until the table in docs/BEACON.md is the string this returns.
     */
    public static function markdownOptions(): string
    {
        $rows = [
            '| Option | Kind | What it does | Default | Accepted | In code | Stored |',
            '|---|---|---|---|---|---|---|',
        ];

        foreach (self::options() as $opt) {
            $stored = 'always — the script uses it itself';
            if ($opt['switch'] !== null) {
                $keys = array_map('trim', explode('/', $opt['switch']));
                $stored = '**`' . implode('`** / **`', $keys) . '`**';
            }
            $rows[] = '| `' . $opt['name'] . '` | ' . $opt['kind'] . ' | '
                . self::inlineMarkdown($opt['what']) . ' | '
                . self::inlineMarkdown($opt['default']) . ' | '
                . self::inlineMarkdown($opt['limits']) . ' | `' . $opt['example'] . '` | ' . $stored . ' |';
        }

        return implode("\n", $rows);
    }

    /** The word a terminal prints in the "stored here" column. */
    private static function stateLabel(string $state): string
    {
        $labels = [
            'always'    => 'always',
            'yes'       => 'yes',
            'partly'    => 'PARTLY DISCARDED',
            'discarded' => 'DISCARDED',
        ];

        return $labels[$state] ?? $state;
    }

    /**
     * One paragraph, wrapped to 76 columns and indented by `$indent` spaces.
     *
     * 76 keeps the whole block inside an 80-column terminal once the indent is added, which is
     * the width an install log is read at over SSH.
     */
    private static function wrap(string $text, int $indent): string
    {
        $pad = str_repeat(' ', $indent);

        return $pad . wordwrap($text, 76 - $indent, "\n" . $pad);
    }
}
