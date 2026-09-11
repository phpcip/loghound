<?php
/**
 * Loghound tests — a scripted Opensolr control plane, shared by every test that drives a
 * storage step for real.
 *
 * WHY IT IS A FILE OF ITS OWN. Two test files need the same fake platform, and one of them needs
 * it INSIDE A SUBPROCESS: the browser installer's refusals are `exit`s, so it can only be
 * observed from outside, and Storage::useTestTransport() takes a closure, which cannot travel
 * through an environment variable. A generated one-line stub requires this file and installs the
 * closure, so the process on the far side of proc_open() is answering from exactly the same
 * fixtures as the process on this side — which is the whole point when the assertion is that two
 * front ends produce the same configuration.
 *
 * It answers every endpoint the reuse and provisioning jobs touch, plus the Solr query the verify
 * steps make, so a complete run happens with no socket opened anywhere. SPEC §12 forbids network
 * access in the suite and nothing here comes close to it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

if (!function_exists('lh_plane_schema')) {
    /** The managed schema this checkout ships for a role, which a joinable index must have. */
    function lh_plane_schema(string $role): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/solr/' . $role . '/conf/managed-schema.xml');
    }
}

if (!function_exists('lh_opensolr_plane')) {
    /**
     * A control plane that knows one key, remembers what it holds, and enforces a plan limit.
     *
     * The key is checked only when the request carries one, because a configset upload posts its
     * credentials in the body rather than the query string; a WRONG key in the query is still
     * refused, which is what the credential tests need.
     *
     * @param array<int,string> $held  Index names the account holds. Taken by reference so a
     *                                 create is observable to the caller.
     * @param string            $key   The one API key this account accepts.
     * @param int|null          $limit Plan allowance; null means the platform reports none.
     */
    function lh_opensolr_plane(array &$held, string $key, ?int $limit = null): callable
    {
        return static function (array $req) use (&$held, $key, $limit): array {
            $url = (string) $req['url'];

            $param = static function (string $k) use ($url): string {
                return preg_match('/[?&]' . $k . '=([^&]*)/', $url, $m) === 1 ? urldecode($m[1]) : '';
            };

            if (str_contains($url, '/solr/')) {
                return [
                    'status' => 200,
                    'body'   => (string) json_encode([
                        'responseHeader' => ['status' => 0],
                        'response'       => ['numFound' => 0, 'docs' => []],
                    ]),
                    'error'  => '',
                ];
            }

            if ($param('api_key') !== '' && $param('api_key') !== $key) {
                return [
                    'status' => 200,
                    'body'   => (string) json_encode(['status' => false, 'msg' => 'ERROR_AUTHENTICATION_FAILED']),
                    'error'  => '',
                ];
            }

            $body = ['status' => true, 'msg' => 'OK'];

            if (str_contains($url, '/regions')) {
                $body = ['FINLAND9', 'GERMANY9'];
            } elseif (str_contains($url, '/get_index_list')) {
                $body = array_map(
                    static fn (string $n): array => ['index_name' => $n, 'index_type' => '-1'],
                    array_values($held)
                );
            } elseif (str_contains($url, '/get_account_summary')) {
                $body = $limit === null
                    ? ['status' => true, 'msg' => ['plan' => 'Free']]
                    : ['status' => true, 'msg' => [
                        'plan'              => 'Free',
                        'index_limit'       => $limit,
                        'indexes_used'      => count($held),
                        'indexes_available' => max(0, $limit - count($held)),
                    ]];
            } elseif (str_contains($url, '/create_index')) {
                if ($limit !== null && count($held) >= $limit) {
                    $body = ['status' => false, 'msg' => 'ERROR_CANNOT_ADD_MORE_THAN_' . $limit . '_CORES'];
                } else {
                    $held[] = $param('index_name');
                }
            } elseif (str_contains($url, '/delete_index')) {
                $gone = $param('index_name');
                $held = array_values(array_filter($held, static fn (string $n): bool => $n !== $gone));
            } elseif (str_contains($url, '/get_file')) {
                $core = $param('index_name');
                $body = [
                    'status' => true,
                    'msg'    => lh_plane_schema(str_ends_with($core, '_hits') ? 'hits' : 'sessions'),
                ];
            } elseif (str_contains($url, '/get_core_info')) {
                $body = ['status' => true, 'msg' => ['info' => [
                    'connection_url' => 'https://fi.solrcluster.com/solr/' . $param('core_name'),
                    'auth_username'  => 'solr-user',
                    'auth_password'  => 'solr-pass',
                ]]];
            }

            return ['status' => 200, 'body' => (string) json_encode($body), 'error' => ''];
        };
    }
}

if (!function_exists('lh_opensolr_plane_stub')) {
    /**
     * Write a one-line PHP file that installs the plane, for a subprocess to require.
     *
     * @param array<int,string> $held
     * @return string The path to require.
     */
    function lh_opensolr_plane_stub(string $path, array $held, string $key, ?int $limit = null): string
    {
        file_put_contents($path, "<?php\n"
            . 'require ' . var_export(__FILE__, true) . ";\n"
            . '$lhHeld = ' . var_export($held, true) . ";\n"
            . '\Loghound\Setup\Storage::useTestTransport(lh_opensolr_plane($lhHeld, '
            . var_export($key, true) . ', ' . var_export($limit, true) . "));\n");

        return $path;
    }
}
