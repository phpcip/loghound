<?php
/**
 * Loghound — the dashboard scope, remembered between pages.
 *
 * WHAT THIS FIXES. Every control that narrows the dashboard — the time range, the virtual host,
 * every facet value, the chosen Opensolr index, the request-log outcome slice — lived in the
 * query string and nowhere else. That is the right place for it to be VISIBLE, because a
 * filtered page is then a link somebody can send; it is the wrong place for it to be the ONLY
 * copy, because every link that forgot to carry a key silently dropped it. An operator who set a
 * host, moved to another view and came back was reading unfiltered numbers under the impression
 * they were still narrowed, which is the one failure this whole product refuses everywhere else.
 *
 * ---------------------------------------------------------------------------------
 * THE RULE: THE URL WINS WHEN IT SPEAKS; THE SESSION FILLS THE SILENCE.
 * ---------------------------------------------------------------------------------
 * Per namespace, not per request. A namespace the URL names is taken from the URL and written to
 * the session, so a link somebody shares scopes the page exactly as its author saw it. A
 * namespace the URL says nothing about is restored from the session, so moving between pages
 * keeps what the operator had.
 *
 * "SAYS NOTHING" HAS TO BE DISTINGUISHABLE FROM "SAYS NONE", which is why the two clearing
 * markers exist. Removing the last filter produces a URL with no `f[…]` keys in it, and under
 * the rule above that URL would be silent — so the next page load would restore the filters that
 * were just thrown away. `fx=1` and `lfx=1` are how a URL states an empty set out loud. Nothing
 * else in the panel needs them: they are minted by the controls that clear, and they are read
 * here.
 *
 * THE RESTORED STATE IS PUT BACK IN THE URL, with one redirect, rather than being applied
 * invisibly. Three things read the query string and cannot be reached from here: the JSON
 * endpoint each card fetches (assets/js/core.js builds its URL from window.location.search), the
 * CSV export links, and every link the page renders through Layout::urlWith(). Applying the
 * scope server-side alone would leave all three unscoped, so the numbers on the page and the
 * numbers in the file would disagree. It also keeps the product's first promise intact: what is
 * on screen is described by the URL in the address bar.
 *
 * NOTHING TRUSTED IS STORED. Values go into the session through the same allowlists the request
 * readers use — Query::filterFields(), OpensolrView::logFilterFields(), Facets::OPERATORS,
 * Query::ranges(), Security::isSafeCoreName() — and are re-validated on the way out by
 * Panel\Facets and Panel\Query, which do not know or care where the request came from.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Scope
{
    /** Where the remembered scope lives inside the session. */
    private const KEY = 'lh_scope';

    /** Most values kept per dimension. The same ceiling Panel\Facets applies to a request. */
    private const MAX_VALUES = 40;

    /** Longest value kept. Longer ones are dropped rather than cut: half a value is a wrong one. */
    private const MAX_VALUE = 400;

    /**
     * Read the remembered scope, merge it with this request, and say what had to be added.
     *
     * Mutates `$_GET`, because that is what every reader in the panel is written against: a
     * controller asks `$_GET` and gets the whole scope, restored or not, with no second code path
     * and no chance of a view being written against the request and missing the session.
     *
     * @return array<string,mixed> The keys that were restored, for the caller's canonical redirect.
     */
    public static function apply(): array
    {
        if (!self::sessionUp()) {
            return [];
        }

        $stored = isset($_SESSION[self::KEY]) && is_array($_SESSION[self::KEY])
            ? $_SESSION[self::KEY]
            : [];

        $added = [];
        $keep = $stored;

        foreach (['range' => 'ranges', 'core' => 'core', 'outcome' => 'outcome'] as $key => $kind) {
            $spoken = self::scalar($key, $kind);
            if ($spoken !== null) {
                $keep[$key] = $spoken;
                continue;
            }
            $held = isset($stored[$key]) && is_string($stored[$key]) ? $stored[$key] : '';
            if ($held !== '' && self::validScalar($kind, $held)) {
                $_GET[$key] = $held;
                $added[$key] = $held;
            }
        }

        foreach (['f' => 'fx', 'lf' => 'lfx'] as $ns => $marker) {
            $labels = $ns === 'f' ? Query::filterFields() : OpensolrView::logFilterFields();

            if (isset($_GET[$ns]) && is_array($_GET[$ns])) {
                $keep[$ns] = self::cleanFilters($_GET[$ns], $labels);
                continue;
            }
            if (isset($_GET[$marker])) {
                $keep[$ns] = [];
                continue;
            }
            $held = isset($stored[$ns]) && is_array($stored[$ns])
                ? self::cleanFilters($stored[$ns], $labels)
                : [];
            if ($held !== []) {
                $_GET[$ns] = $held;
                $added[$ns] = $held;
            }
        }

        $_SESSION[self::KEY] = $keep;

        return $added;
    }

    /**
     * Hand the session lock back.
     *
     * NOT AN OPTIMISATION. PHP's file session handler holds an exclusive lock for the life of a
     * request, and a panel page puts a dozen card fetches in flight at once — every one of them
     * carrying the session cookie. Without this they would serialise behind each other, turning a
     * page that loads twelve cards in parallel into one that loads them one at a time, and the
     * slowest card would decide the page.
     *
     * Called by the front controller once the scope is settled, on the request shapes that have
     * no further use for the session. A page render keeps it, because Security::csrfToken() is
     * about to mint a token into it.
     */
    public static function release(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }

    /**
     * Forget everything this browser had narrowed the dashboard to.
     *
     * The panel offers no control for this today — the filter dialog clears filters, and the
     * duration and index controls always name a value — but the state is the operator's and
     * there has to be a way to drop it that does not involve a cookie jar.
     */
    public static function forget(): void
    {
        if (self::sessionUp()) {
            unset($_SESSION[self::KEY]);
        }
    }

    /**
     * Start the session, or report that there is none to be had.
     *
     * A session is already started by this point on most requests — Panel\Login and
     * Security::csrfToken() both start one — so this is usually a no-op. Headers already sent
     * means something has rendered, which is a bug elsewhere; the scope is not worth a fatal, so
     * the panel carries on with the URL as its only state, which is exactly how it behaved before
     * this class existed.
     */
    private static function sessionUp(): bool
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return true;
        }
        if (headers_sent()) {
            return false;
        }
        return @session_start();
    }

    /**
     * One scalar parameter as this request states it, or null when the request is silent on it.
     *
     * An INVALID value counts as silence rather than as an instruction. A mistyped `range` in a
     * hand-edited URL should leave the operator on the window they were on, not clear it — and it
     * must never be written to the session, where it would be restored on every later page.
     */
    private static function scalar(string $key, string $kind): ?string
    {
        $raw = $_GET[$key] ?? null;
        if (!is_string($raw) || $raw === '') {
            return null;
        }
        return self::validScalar($kind, $raw) ? $raw : null;
    }

    /** Is this a value the panel would accept for that parameter? */
    private static function validScalar(string $kind, string $value): bool
    {
        return match ($kind) {
            'ranges'  => isset(Query::ranges()[$value]),
            'core'    => Security::isSafeCoreName($value),
            'outcome' => isset(OpensolrView::OUTCOMES[$value]),
            default   => false,
        };
    }

    /**
     * A filter namespace reduced to what is allowed to be remembered.
     *
     * The same shape the query string carries — `field => [values…, 'op' => …]` — with every
     * field checked against the plane's allowlist, every value length-capped, and the operator
     * checked against the three that exist. A field the plane does not define is dropped rather
     * than kept for later, because a stored filter naming a field no schema has is a filter that
     * would match nothing and say it was narrowing.
     *
     * @param array<mixed> $raw
     * @param array<string,string> $labels
     * @return array<string,array<int|string,string>>
     */
    private static function cleanFilters(array $raw, array $labels): array
    {
        $out = [];
        foreach ($raw as $field => $spec) {
            if (!is_string($field) || !isset($labels[$field]) || !Security::isSafeFieldName($field)
                || !is_array($spec)) {
                continue;
            }

            $values = [];
            $op = '';
            foreach ($spec as $key => $value) {
                if (!is_string($value) || $value === '' || mb_strlen($value) > self::MAX_VALUE) {
                    continue;
                }
                if ($key === 'op') {
                    if (in_array($value, Facets::OPERATORS, true)) {
                        $op = $value;
                    }
                    continue;
                }
                if (!is_int($key) && !ctype_digit((string) $key)) {
                    continue;
                }
                if (count($values) < self::MAX_VALUES) {
                    $values[] = $value;
                }
            }

            /* AN OPERATOR WITH NO VALUES IS NOT A FILTER. It narrows nothing, it would be
               restored on every later page, and "None of — nothing" is a chip the reader cannot
               act on. The dimension is dropped whole. */
            if ($values === []) {
                continue;
            }
            if ($op !== '') {
                $values['op'] = $op;
            }
            $out[$field] = $values;
        }
        return $out;
    }
}
