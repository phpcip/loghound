<?php
/**
 * Loghound — tests for the configuration files the project SHIPS.
 *
 * A Solr schema and a PHP-FPM pool are not documentation: they decide what an installation
 * actually does, and nothing in the PHP test suite exercises them, so a wrong value in
 * either survives every other test in this directory. Both bugs pinned here were exactly
 * that shape — silent, delivered, and invisible from inside the application.
 *
 *  - The sessions schema declared none of the eleven client-hint and TLS fields that
 *    Sessionizer::identityOf() collects and buildSessionDoc() writes, so the catch-all
 *    `ignored` dynamic field ate them on the way in. The work was being done and the result
 *    thrown away, and no session could be faceted by a client hint.
 *  - The shipped FPM pool set the session cookie attributes with php_admin_value, which
 *    LOCKS an ini entry. public/index.php asks for SameSite=Strict and a TLS-aware Secure
 *    flag through session_set_cookie_params(); locked, neither request could take effect,
 *    so every install delivered SameSite=Lax and forced Secure on even over plain HTTP,
 *    where it stops the browser returning the session cookie at all.
 *
 * Nothing here touches the network, Solr, or anything outside the repository.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

/** Repository root. */
function lh_cfgroot(): string
{
    return dirname(__DIR__);
}

/**
 * Read a shipped file, failing the test rather than returning an empty string.
 */
function lh_shipped(string $relative): string
{
    $path = lh_cfgroot() . '/' . $relative;
    if (!is_file($path)) {
        lh_fail($relative . ' is missing from the repository');
    }
    return (string) file_get_contents($path);
}

/**
 * The `name` of every <field> a schema declares.
 *
 * @return array<string,array<string,string>> field name => its attributes
 */
function lh_schema_fields(string $relative): array
{
    $previous = libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $loaded = $doc->loadXML(lh_shipped($relative));
    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    if (!$loaded) {
        lh_fail($relative . ' is not well-formed XML');
    }

    $out = [];
    foreach ($doc->getElementsByTagName('field') as $node) {
        $attrs = [];
        foreach ($node->attributes as $attr) {
            $attrs[$attr->name] = $attr->value;
        }
        if (isset($attrs['name'])) {
            $out[$attrs['name']] = $attrs;
        }
    }
    return $out;
}

/**
 * The eleven fields Sessionizer::identityOf() collects that the sessions schema used to
 * swallow. Listed literally rather than derived, so that adding one to the Sessionizer
 * without adding it to the schema fails here instead of going quiet again.
 *
 * @return string[]
 */
function lh_client_hint_fields(): array
{
    return [
        'accept_s', 'accept_enc_s',
        'sec_ch_ua_s', 'sec_ch_platform_s', 'sec_ch_mobile_b',
        'sec_fetch_site_s', 'sec_fetch_mode_s', 'sec_fetch_dest_s', 'sec_fetch_user_s',
        'tls_proto_s', 'tls_cipher_s',
    ];
}

/**
 * Every `php_admin_value[...]`/`php_value[...]` key in an FPM pool body, with which of the
 * two directives set it.
 *
 * @return array<string,string> ini name => 'php_admin_value'|'php_value'|'php_admin_flag'|'php_flag'
 */
function lh_pool_directives(string $body): array
{
    $out = [];
    if (preg_match_all('/^\s*(php_admin_value|php_value|php_admin_flag|php_flag)\[([^\]]+)\]/m', $body, $m, PREG_SET_ORDER)) {
        foreach ($m as $one) {
            $out[trim($one[2])] = $one[1];
        }
    }
    return $out;
}

/**
 * The value an FPM pool body assigns to one ini name.
 */
function lh_pool_value(string $body, string $name): ?string
{
    $quoted = preg_quote($name, '/');
    if (preg_match('/^\s*php(?:_admin)?_(?:value|flag)\[' . $quoted . '\]\s*=\s*(\S+)/m', $body, $m)) {
        return $m[1];
    }
    return null;
}

return [
    'the sessions schema declares every client-hint field the sessionizer writes'
        => static function (): void {
        $fields = lh_schema_fields('solr/sessions/conf/managed-schema.xml');

        foreach (lh_client_hint_fields() as $name) {
            if (!isset($fields[$name])) {
                lh_fail(
                    $name . ' is written onto every session document and is not declared in the sessions '
                    . 'schema, so the catch-all `ignored` dynamic field discards it'
                );
            }
        }
    },

    'those fields are indexed and faceted but never stored' => static function (): void {
        $fields = lh_schema_fields('solr/sessions/conf/managed-schema.xml');

        foreach (lh_client_hint_fields() as $name) {
            $f = $fields[$name] ?? null;
            if ($f === null) {
                lh_skip($name . ' is not declared yet');
            }
            lh_same('true', $f['indexed'] ?? '', $name . ' must be indexed to be filterable');
            lh_same('true', $f['docValues'] ?? '', $name . ' must have docValues to be facetable');
            lh_same(
                'false',
                $f['stored'] ?? '',
                $name . ' must not be stored: Panel\Query::sessionFl() never asks for it and the scorer '
                . 'reads it off the in-memory aggregate, so a stored copy is disk nobody reads'
            );
        }
    },

    'their flags match the hits schema, which is where the same header is already declared'
        => static function (): void {
        $sessions = lh_schema_fields('solr/sessions/conf/managed-schema.xml');
        $hits     = lh_schema_fields('solr/hits/conf/managed-schema.xml');

        foreach (lh_client_hint_fields() as $name) {
            if (!isset($sessions[$name], $hits[$name])) {
                lh_skip($name . ' is not declared in both schemas');
            }
            foreach (['type', 'indexed', 'stored', 'docValues'] as $attr) {
                lh_same(
                    $hits[$name][$attr] ?? null,
                    $sessions[$name][$attr] ?? null,
                    $name . '.' . $attr . ' must agree between the two schemas'
                );
            }
        }
    },

    'the sessions schema still discriminates the two document types it holds'
        => static function (): void {
        $fields = lh_schema_fields('solr/sessions/conf/managed-schema.xml');
        lh_has_key($fields, 'doc_type_s', 'the sessions schema');
        lh_same('true', $fields['doc_type_s']['indexed'] ?? '', 'doc_type_s must be filterable');
    },

    'the shipped pool does not lock a session cookie attribute the application sets'
        => static function (): void {
        $body = lh_shipped('install/php-fpm-pool.conf.example');
        $set  = lh_pool_directives($body);

        foreach (['session.cookie_samesite', 'session.cookie_secure', 'session.cookie_httponly'] as $name) {
            $how = $set[$name] ?? null;
            if ($how === null) {
                continue;
            }
            lh_true(
                $how === 'php_value' || $how === 'php_flag',
                $name . ' is set with ' . $how . ', which locks the entry; public/index.php calls '
                . 'session_set_cookie_params() and cannot then override it'
            );
        }
    },

    'the shipped pool does not deliver a weaker SameSite than the application asks for'
        => static function (): void {
        $body = lh_shipped('install/php-fpm-pool.conf.example');
        $value = lh_pool_value($body, 'session.cookie_samesite');

        if ($value === null) {
            return;
        }
        lh_same(
            'Strict',
            $value,
            'public/index.php asks for SameSite=Strict; a pool default below that is what the install '
            . 'actually delivers'
        );
    },

    'the pool install.sh generates carries the same fix' => static function (): void {
        $body = lh_shipped('install/install.sh');
        $set  = lh_pool_directives($body);

        foreach (['session.cookie_samesite', 'session.cookie_secure', 'session.cookie_httponly'] as $name) {
            $how = $set[$name] ?? null;
            if ($how === null) {
                continue;
            }
            lh_true(
                $how === 'php_value' || $how === 'php_flag',
                'install.sh writes ' . $name . ' as ' . $how . '; the generated pool is what a real '
                . 'install gets, so fixing only the example fixes nothing'
            );
        }

        $value = lh_pool_value($body, 'session.cookie_samesite');
        if ($value !== null) {
            lh_same('Strict', $value, 'the generated pool must not ship a weaker SameSite either');
        }
    },

    'the pool still locks the settings the application never sets' => static function (): void {
        $body = lh_shipped('install/php-fpm-pool.conf.example');
        $set  = lh_pool_directives($body);

        foreach (['session.save_path', 'session.use_strict_mode', 'open_basedir', 'disable_functions'] as $name) {
            $how = $set[$name] ?? null;
            if ($how === null) {
                lh_fail($name . ' has gone from the shipped pool');
            }
            lh_true(
                $how === 'php_admin_value' || $how === 'php_admin_flag',
                $name . ' must stay locked: nothing in the application sets it, and application code '
                . 'must not be able to relax it'
            );
        }
    },
];
