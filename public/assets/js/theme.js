/*
 * Loghound — theme bootstrap.
 *
 * Loaded synchronously in <head>, before anything paints, so a reader who chose dark
 * never sees a white flash on navigation. That is normally the one place people reach
 * for an inline <script>; the panel's CSP is script-src 'self' with no 'unsafe-inline',
 * so it is an external file instead. It is deliberately tiny for that reason.
 *
 * Three states:
 *   'auto'  — follow prefers-color-scheme (the default; nothing stored)
 *   'light' — force light
 *   'dark'  — force dark
 *
 * The stylesheet keys off data-theme on <html>: bare :root is the light palette,
 * :root:not([data-theme="light"]) inside a dark media query is the system-follows case,
 * and :root[data-theme="dark"] is the explicit override.
 */
(function () {
    'use strict';
    var mode = 'auto';
    try {
        // localStorage throws outright in some privacy configurations, and returns null
        // in a fresh profile. Both mean "no preference stored", not "broken".
        var stored = window.localStorage.getItem('lh-theme');
        if (stored === 'dark' || stored === 'light') {
            mode = stored;
        }
    } catch (e) {
        /* No stored preference is available. Fall through to 'auto'. */
    }
    document.documentElement.setAttribute('data-theme', mode);
})();
