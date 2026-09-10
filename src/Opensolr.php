<?php
/**
 * Loghound — Opensolr managed-backend client.
 *
 * SPEC §9: setup asks one question, "[Opensolr managed] or [my own Solr]". This class is
 * the managed half. It provisions the two indexes, pushes the configset, and reports
 * health, so the operator never has to learn what a configset is.
 *
 * IMPORTANT — this is the CONTROL PLANE, not the data plane. It talks to
 * https://opensolr.com/solr_manager/api, which creates and configures indexes. Documents
 * are never written through here; that is src/Solr.php, which talks directly to the Solr
 * node this class tells it about.
 *
 * ---------------------------------------------------------------------------------------
 * THE API KEY
 * ---------------------------------------------------------------------------------------
 * The Opensolr API key is a full account credential: it can create, reconfigure and DELETE
 * every index on the account, not just Loghound's two. Accordingly:
 *
 *   * it is never echoed, never printed, never written to a log, and never included in an
 *     exception message — see redact() and the way every error path below is built;
 *   * it is sent as a POST field, not a URL query parameter, wherever the endpoint allows
 *     it, so it does not land in an intermediate proxy's access log;
 *   * it lives in config/loghound.php at mode 0640, outside the docroot (SPEC §1).
 *
 * If you add a method here, the test for whether you got this right is simple: grep your
 * new code for the variable holding the key and confirm it only ever reaches a request
 * field.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Opensolr
{
    /** Default control-plane base. Overridable in config for staging. */
    public const DEFAULT_API_BASE = 'https://opensolr.com/solr_manager/api';

    private string $apiBase;

    private string $email;

    private string $apiKey;

    private int $timeout;

    /** @var callable Transport, injectable so tests run with no network. */
    private $transport;

    /**
     * @param array<string,mixed> $cfg      The 'opensolr' section of the config.
     * @param callable|null       $transport fn(array $req): array{status:int,body:string,error:string}
     */
    public function __construct(array $cfg, ?callable $transport = null)
    {
        $this->apiBase = rtrim((string) ($cfg['api_base'] ?? self::DEFAULT_API_BASE), '/');
        $this->email   = (string) ($cfg['email'] ?? '');
        $this->apiKey  = (string) ($cfg['api_key'] ?? '');
        $this->timeout = max(5, (int) ($cfg['timeout'] ?? 60));

        // Reuse the Solr client's curl transport: identical shape, identical hardening
        // (no redirect following, certificate verification on), one implementation to audit.
        $this->transport = $transport ?? [Solr::class, 'curlTransport'];
    }

    /**
     * List the regions (Opensolr calls them environments) available to this account.
     *
     * GET /regions returns a bare JSON array of country codes, e.g. ["FINLAND9","GERMANY9"].
     * The setup wizard shows these; nothing is hardcoded client-side, so a region added by
     * Opensolr appears without a Loghound release.
     *
     * @return string[]
     */
    public function listRegions(): array
    {
        $res = $this->call('regions', [], 'GET');

        // The endpoint returns a list, not an object, so decode() hands it back under a
        // synthetic key rather than pretending it is a map.
        $list = $res['_list'] ?? [];
        $out = [];
        foreach ((array) $list as $entry) {
            // Entries are plain strings today. Be tolerant of the object form used by
            // /vector_regions in case the two endpoints converge later.
            if (is_string($entry)) {
                $out[] = $entry;
            } elseif (is_array($entry) && isset($entry['environment'])) {
                $out[] = (string) $entry['environment'];
            }
        }
        return $out;
    }

    /**
     * Create a managed index.
     *
     * Endpoint: GET /create_index?index_name=&region=&email=&api_key=
     *
     * Idempotency: Opensolr refuses a duplicate name with an error rather than clobbering
     * the existing index, which is the behaviour we want — a re-run of setup must not
     * silently destroy the operator's data. The caller decides whether an "already exists"
     * response is a failure or a no-op.
     *
     * @return array<string,mixed> Decoded response.
     */
    public function createIndex(string $indexName, string $region): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        // Region codes are uppercase identifiers; anything else is a caller bug or an
        // injection attempt into the query string.
        if (!preg_match('/^[A-Z0-9_]{2,32}$/', $region)) {
            throw new \InvalidArgumentException('Opensolr: invalid region: ' . $region);
        }

        return $this->call('create_index', [
            'index_name' => $indexName,
            'region'     => $region,
        ], 'GET');
    }

    /**
     * Did this create_index response fail because the name is already taken?
     *
     * Opensolr index names are unique across the ENTIRE PLATFORM, not per
     * account, so a collision is a normal outcome to be retried with a fresh
     * name — not an error to show the operator. The platform signals it with
     * ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME.
     *
     * Matched on a substring of the code rather than the whole string so that a
     * future rewording of the message does not turn a retryable collision into
     * a hard install failure.
     *
     * @param array<string,mixed> $response A decoded createIndex() response.
     */
    public static function isNameTaken(array $response): bool
    {
        if (!empty($response['status'])) {
            return false;
        }
        $msg = self::stringifyMsg($response['msg'] ?? '');
        return stripos($msg, 'CORE_NAME_TAKEN') !== false;
    }

    /**
     * Create both indexes for an installation, retrying on name collisions.
     *
     * Both cores must share one installation id so the pair is recognisable as
     * belonging together, which means a collision on EITHER name invalidates
     * the whole id and both are retried with a new one. Retrying only the
     * colliding half would leave a mismatched pair that is confusing to
     * identify in an account holding hundreds of indexes.
     *
     * Any index created during a failed attempt is deleted before the next one,
     * so a collision cannot leave orphaned indexes accumulating in the
     * operator's account (which they may well be billed for).
     *
     * @param callable(string):void|null $progress Optional status callback.
     * @return array{install_id:string,hits:string,sessions:string}
     * @throws \RuntimeException When no free name pair could be obtained.
     */
    public function provisionIndexPair(
        string $region,
        int $attempts = 5,
        ?callable $progress = null
    ): array {
        $say = $progress ?? static function (string $m): void {
        };

        for ($attempt = 1; $attempt <= $attempts; $attempt++) {
            $installId = Config::newInstallId();
            $names = [
                'hits'     => Config::coreName($installId, 'hits'),
                'sessions' => Config::coreName($installId, 'sessions'),
            ];

            $created = [];
            $collided = false;

            foreach ($names as $role => $name) {
                $say(sprintf('Creating index %s ...', $name));
                $res = $this->createIndex($name, $region);

                if (!empty($res['status'])) {
                    $created[] = $name;
                    continue;
                }
                if (self::isNameTaken($res)) {
                    $say(sprintf('Name %s is already taken, choosing another.', $name));
                    $collided = true;
                    break;
                }
                // A genuine failure (bad key, quota, region down). Roll back
                // whatever this attempt created, then surface it — retrying
                // with a different name would not help and would just make
                // the real error harder to find.
                $this->rollbackIndexes($created, $say);
                throw new \RuntimeException(
                    'Opensolr refused to create ' . $name . ': ' . self::stringifyMsg($res['msg'] ?? 'unknown error')
                );
            }

            if (!$collided) {
                return ['install_id' => $installId] + $names;
            }

            $this->rollbackIndexes($created, $say);
        }

        throw new \RuntimeException(
            'Could not find a free index name pair after ' . $attempts . ' attempts.'
        );
    }

    /**
     * Delete indexes created during an attempt that did not complete.
     *
     * Best effort by design: if the cleanup itself fails the operator still
     * needs the original error, so a failure here is reported and swallowed
     * rather than replacing the exception that caused the rollback.
     *
     * @param string[] $names
     */
    private function rollbackIndexes(array $names, callable $say): void
    {
        foreach ($names as $name) {
            try {
                $say(sprintf('Removing partially created index %s ...', $name));
                $this->call('delete_index', ['index_name' => $name], 'GET');
            } catch (\Throwable $e) {
                $say(sprintf(
                    'WARNING: could not remove %s — delete it from your Opensolr control panel.',
                    $name
                ));
            }
        }
    }

    /**
     * Health of a managed index.
     *
     * Endpoint: GET /get_core_status?core_name=
     *
     * This is the "Healthy ✓" the operator sees. It is the platform's view of the index
     * (is the node up, is the core loaded), which is a different question from
     * Solr::ping() — that one proves Loghound itself can reach and authenticate to the
     * node. Setup shows both, because "Opensolr says it is fine but we cannot connect"
     * is a firewall problem and the operator needs to be told which of the two failed.
     *
     * @return array<string,mixed>
     */
    public function indexStatus(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        return $this->call('get_core_status', ['core_name' => $indexName], 'GET');
    }

    /**
     * Connection details for a managed index.
     *
     * Endpoint: GET /get_core_info?core_name=
     * Returns msg.info.connection_url, msg.info.auth_username, msg.info.auth_password.
     *
     * This is how managed mode fills in solr.base_url / http_user / http_pass. SPEC §9 does
     * not say where those come from in managed mode; this is the answer — setup calls this
     * once after createIndex() and writes the result into the config, after which
     * src/Solr.php is mode-agnostic and simply talks to a Solr node it has credentials for.
     *
     * @return array{base_url:string,http_user:string,http_pass:string}
     */
    public function connectionDetails(string $indexName): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }
        $res = $this->call('get_core_info', ['core_name' => $indexName], 'GET');

        $info = $res['msg']['info'] ?? [];
        $url  = (string) ($info['connection_url'] ?? '');
        if ($url === '') {
            throw new \RuntimeException('Opensolr: no connection_url returned for index ' . $indexName);
        }

        // connection_url points at the core (…/solr/<index>). src/Solr.php builds
        // <base>/<core>/<handler> itself, so strip the trailing core segment to get the
        // base. Doing it here keeps the "what shape is a base URL" knowledge in one place.
        $base = preg_replace('#/' . preg_quote($indexName, '#') . '/?$#', '', $url) ?? $url;

        return [
            'base_url'  => rtrim((string) $base, '/'),
            'http_user' => (string) ($info['auth_username'] ?? ''),
            'http_pass' => (string) ($info['auth_password'] ?? ''),
        ];
    }

    /**
     * Push a configset (managed-schema.xml + solrconfig.xml) to a managed index.
     *
     * Endpoint: POST /upload_config_file, multipart/form-data, file field `userfile`,
     * plus core_name / email / api_key as POST fields.
     *
     * The platform accepts one file per call and reloads the core, so this walks the
     * directory and uploads each file in a deliberate order: SCHEMA FIRST, then
     * solrconfig. Reversed, the core reloads against a solrconfig that references field
     * types the old schema does not define, and the reload fails — leaving the index in a
     * state the operator has to fix from the Opensolr control panel.
     *
     * @param string $confDir Local directory, e.g. solr/hits/conf
     * @return array<int,array{file:string,ok:bool,msg:string}> One row per file, for the
     *                                                          setup wizard to display.
     */
    public function pushConfigSet(string $indexName, string $confDir): array
    {
        if (!Security::isSafeCoreName($indexName)) {
            throw new \InvalidArgumentException('Opensolr: invalid index name: ' . $indexName);
        }

        $real = realpath($confDir);
        if ($real === false || !is_dir($real)) {
            throw new \InvalidArgumentException('Opensolr: configset directory not found: ' . $confDir);
        }

        // Explicit order and an explicit allowlist. Not a glob: a stray .bak or an editor
        // swap file left in the directory would otherwise be uploaded to the Solr node.
        $order = ['managed-schema.xml', 'solrconfig.xml'];
        $results = [];

        foreach ($order as $name) {
            $path = $real . '/' . $name;
            if (!is_file($path)) {
                $results[] = ['file' => $name, 'ok' => false, 'msg' => 'missing locally'];
                continue;
            }

            try {
                $res = $this->uploadFile($indexName, $path);
                // The platform answers {"status":true|false,"msg":...}. Anything without a
                // truthy status is a failure the operator must see, not a warning to hide.
                $ok = (bool) ($res['status'] ?? false);
                $results[] = [
                    'file' => $name,
                    'ok'   => $ok,
                    'msg'  => $ok ? 'uploaded' : self::stringifyMsg($res['msg'] ?? 'rejected'),
                ];
            } catch (\Throwable $e) {
                $results[] = ['file' => $name, 'ok' => false, 'msg' => $e->getMessage()];
            }
        }

        return $results;
    }

    // =====================================================================================
    // INTERNALS
    // =====================================================================================

    /**
     * Call a control-plane endpoint.
     *
     * Credentials are appended here and nowhere else, which is what makes the "never log
     * the key" rule auditable: there is exactly one place the key enters a request.
     *
     * @param array<string,string> $params
     * @return array<string,mixed>
     */
    private function call(string $endpoint, array $params, string $method): array
    {
        if (!preg_match('/^[a-z0-9_]{1,64}$/', $endpoint)) {
            throw new \InvalidArgumentException('Opensolr: invalid endpoint: ' . $endpoint);
        }
        if ($this->email === '' || $this->apiKey === '') {
            throw new \RuntimeException('Opensolr: email and api_key are required in managed mode.');
        }

        $params['email']   = $this->email;
        $params['api_key'] = $this->apiKey;

        $url = $this->apiBase . '/' . $endpoint;
        $qs  = http_build_query($params, '', '&', PHP_QUERY_RFC3986);

        // GET endpoints on this API read their credentials from the query string; that is
        // the platform's contract and we cannot change it from this side. POST endpoints
        // take them as fields, which is the safer of the two and is what uploadFile() uses.
        $res = ($this->transport)([
            'method'          => $method,
            'url'             => $method === 'GET' ? $url . '?' . $qs : $url,
            'headers'         => ['Accept: application/json'],
            'body'            => $method === 'GET' ? null : $qs,
            'timeout'         => $this->timeout,
            'connect_timeout' => 10,
            'user'            => '',
            'pass'            => '',
        ]);

        return $this->decode($res, $endpoint);
    }

    /**
     * Upload one configset file as multipart/form-data.
     *
     * Built by hand rather than with CURLFile so the transport stays a plain callable that
     * a test can replace. The boundary is random, and every field value is written
     * verbatim into the body — which is safe here because the only caller-influenced value
     * is the index name, already validated against [A-Za-z0-9_].
     *
     * @return array<string,mixed>
     */
    private function uploadFile(string $indexName, string $path): array
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new \RuntimeException('Opensolr: cannot read ' . $path);
        }
        // The platform caps uploads at ~3.5 MB and only accepts xml|txt|zip|aff|dic.
        if (strlen($contents) > 3_000_000) {
            throw new \RuntimeException('Opensolr: configset file is too large: ' . basename($path));
        }

        // basename() so a path can never travel in the filename field.
        $filename = basename($path);

        $boundary = '----loghound' . bin2hex(random_bytes(16));
        $eol = "\r\n";

        $fields = [
            'core_name' => $indexName,
            'email'     => $this->email,
            'api_key'   => $this->apiKey,
        ];

        $body = '';
        foreach ($fields as $name => $value) {
            $body .= '--' . $boundary . $eol;
            $body .= 'Content-Disposition: form-data; name="' . $name . '"' . $eol . $eol;
            $body .= $value . $eol;
        }
        // CodeIgniter's do_upload() reads the field named `userfile` by default; that is
        // what the platform's upload_config_file endpoint calls.
        $body .= '--' . $boundary . $eol;
        $body .= 'Content-Disposition: form-data; name="userfile"; filename="' . $filename . '"' . $eol;
        $body .= 'Content-Type: application/xml' . $eol . $eol;
        $body .= $contents . $eol;
        $body .= '--' . $boundary . '--' . $eol;

        $res = ($this->transport)([
            'method'          => 'POST',
            'url'             => $this->apiBase . '/upload_config_file',
            'headers'         => [
                'Content-Type: multipart/form-data; boundary=' . $boundary,
                'Accept: application/json',
            ],
            'body'            => $body,
            'timeout'         => $this->timeout,
            'connect_timeout' => 10,
            'user'            => '',
            'pass'            => '',
        ]);

        return $this->decode($res, 'upload_config_file');
    }

    /**
     * Decode a control-plane response.
     *
     * Every failure message is passed through redact() before it can reach a caller, an
     * exception, or a log file. The platform echoes request parameters back in some error
     * paths, and one of those parameters is the API key.
     *
     * @param array<string,mixed> $res
     * @return array<string,mixed>
     */
    private function decode(array $res, string $endpoint): array
    {
        $status = (int) ($res['status'] ?? 0);
        $body   = (string) ($res['body'] ?? '');

        if ($status === 0) {
            throw new \RuntimeException(
                'Opensolr: cannot reach the control plane (' . $endpoint . '): '
                . $this->redact((string) ($res['error'] ?? 'no response'))
            );
        }

        $decoded = json_decode($body, true);
        if ($decoded === null) {
            throw new \RuntimeException(
                'Opensolr: HTTP ' . $status . ' from ' . $endpoint . ' with an unparseable body.'
            );
        }

        // /regions answers with a bare JSON array. Wrap it so callers always get a map.
        if (array_is_list((array) $decoded)) {
            return ['_list' => $decoded];
        }

        if ($status >= 400) {
            throw new \RuntimeException(
                'Opensolr: HTTP ' . $status . ' from ' . $endpoint . ': '
                . $this->redact(self::stringifyMsg($decoded['msg'] ?? ''))
            );
        }

        return (array) $decoded;
    }

    /**
     * Remove the API key from any string that is about to be shown or logged.
     *
     * The last line of defence, not the first: nothing should be constructing a message
     * containing the key in the first place. It exists because the platform occasionally
     * echoes the request back in an error body, and a secret in an exception message ends
     * up in a stack trace, in a support paste, and in an issue on a public repo.
     */
    private function redact(string $text): string
    {
        if ($this->apiKey !== '') {
            $text = str_replace($this->apiKey, '[api_key redacted]', $text);
        }
        // Also catch the key appearing inside an echoed query string, in case the platform
        // returned a normalised or partially encoded form of it.
        return (string) preg_replace('/(api_key=)[^&"\s]+/i', '$1[redacted]', $text);
    }

    /**
     * Flatten the platform's `msg`, which is sometimes a string and sometimes a structure.
     *
     * @param mixed $msg
     */
    private static function stringifyMsg($msg): string
    {
        if (is_string($msg)) {
            return $msg;
        }
        return (string) json_encode($msg, JSON_UNESCAPED_SLASHES);
    }
}
