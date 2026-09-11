<?php
/**
 * Loghound — the supported way to bring a live index's schema up to date.
 *
 * THE BUG THIS FILE PINS. A release added three fields — `planes_s`, `search_terms_ss`,
 * `install_s` — and the live indexes were still running the configset uploaded at install
 * time. The only dynamic field either schema declares is `*` mapped to `ignored`, so every one
 * of those values was accepted by Solr, mapped to a type that indexes nothing and stores
 * nothing, and discarded. No error was raised anywhere, by anything. It was fixed by hand with
 * a throwaway script calling Opensolr::pushConfigSet(), because the only code that compared
 * the two schemas lived inside a private setup step.
 *
 * So the properties asserted here are the ones that failure was made of:
 *
 *   - a field this release writes and the index does not declare is REPORTED, by name;
 *   - a field the index declares and this release does not write is NOT an error;
 *   - a schema that could not be read is NEVER reported as matching;
 *   - a push is never made over a schema that was not read first;
 *   - a half-applied push says which file was rejected and what state the index is in;
 *   - the panel's cached verdict is never presented as describing a release it was not taken
 *     against, which is exactly the state an upgrade creates;
 *   - the exit codes tell "up to date", "out of date" and "failed" apart, because a deployment
 *     script has nothing else to read.
 *
 * No network: every control-plane call goes through an injected transport, and the subprocess
 * tests point the API base at a closed port on localhost.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Panel\Gateway;
use Loghound\Panel\Settings;
use Loghound\Setup\Schema;
use Loghound\Setup\Storage;
use Loghound\Solr;

/** The repository root, so the script under test is the one in this checkout. */
function lh_sch_root(): string
{
    return dirname(__DIR__);
}

/**
 * A managed schema declaring exactly the named fields, in the shape the real ones use.
 *
 * @param string[] $fields
 */
function lh_sch_xml(array $fields): string
{
    $out = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . '<schema name="test" version="1.6">' . "\n";
    foreach ($fields as $name) {
        $out .= '    <field name="' . $name . '" type="string" indexed="true" stored="false"/>' . "\n";
    }
    $out .= '    <dynamicField name="*" type="ignored" multiValued="true"/>' . "\n";
    return $out . '</schema>' . "\n";
}

/**
 * A throwaway installation: a config, a var/ and a configset for each role.
 *
 * @param array<string,string[]> $fields role => the fields this fake release writes
 * @return array{0:string,1:Config}
 */
function lh_sch_install(array $fields = []): array
{
    $root = lh_tmpdir('lh-schema');
    @mkdir($root . '/config', 0750, true);
    @mkdir($root . '/var', 0750, true);

    $fields += [
        'hits'     => ['id', 'ts', 'ip_s', 'install_s'],
        'sessions' => ['id', 'ts_start', 'planes_s', 'search_terms_ss'],
    ];

    foreach (Schema::ROLES as $role) {
        @mkdir($root . '/solr/' . $role . '/conf', 0750, true);
        file_put_contents(
            $root . '/solr/' . $role . '/conf/schema.xml',
            lh_sch_xml($fields[$role])
        );
        file_put_contents(
            $root . '/solr/' . $role . '/conf/solrconfig.xml',
            '<config><schemaFactory class="ClassicIndexSchemaFactory"/></config>'
        );
        /* The configset ships THREE files now and pushConfigSet() refuses to start when one of
           them is missing locally, so a fixture that stopped at two would exercise the refusal
           path rather than the push. */
        file_put_contents(
            $root . '/solr/' . $role . '/conf/mapping-ISOLatin1Accent.txt',
            '"\u00E9" => "e"' . "\n"
        );
    }

    $cfg = Config::load($root . '/config/loghound.php');
    $cfg->set('solr.mode', 'opensolr');
    $cfg->set('opensolr.email', 'operator@example.com');
    $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-9f3c17ab');
    $cfg->set('solr.hits_core', 'loghound_9f3c17ab_hits');
    $cfg->set('solr.sessions_core', 'loghound_9f3c17ab_sessions');
    $cfg->save();

    return [$root, $cfg];
}

/**
 * A scripted control plane: it hands back a live schema per index and accepts uploads.
 *
 * @param array<string,string|null>  $live    index name => the schema it is running,
 *                                            or null for "the platform will not hand it back"
 * @param array<int,array<string,string>> $uploads Filled with one row per accepted upload.
 * @param callable|null $reject fn(string $core, string $file): ?string — a rejection message.
 * @param array<int,string> $managed Index names still running Solr's MANAGED schema factory.
 *                                   Everything else answers with the classic one, which is what
 *                                   this release uploads.
 */
function lh_sch_transport(array $live, array &$uploads, ?callable $reject = null, array $managed = []): callable
{
    return static function (array $req) use ($live, &$uploads, $reject, $managed): array {
        $url = (string) ($req['url'] ?? '');
        $body = (string) ($req['body'] ?? '');

        $ok = static fn ($msg): array => [
            'status' => 200,
            'body'   => (string) json_encode(['status' => true, 'msg' => $msg]),
            'error'  => '',
        ];
        $no = static fn (string $msg): array => [
            'status' => 200,
            'body'   => (string) json_encode(['status' => false, 'msg' => $msg]),
            'error'  => '',
        ];

        if (str_contains($url, '/get_file')) {
            $q = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            $core = (string) ($q['index_name'] ?? '');
            $name = (string) ($q['file_name'] ?? '');

            /* THE FACTORY PROBE IS A DIFFERENT QUESTION FROM THE SCHEMA, so the fake plane has
               to answer it as one. Returning the schema for every file name would make
               Schema::check() read a document with no <schemaFactory> in it and conclude every
               index is still on the managed factory — a state in which no push can fix
               anything. */
            if ($name === 'solrconfig') {
                return in_array($core, $managed, true)
                    ? $ok('<config><schemaFactory class="ManagedIndexSchemaFactory"/></config>')
                    : $ok('<config><schemaFactory class="ClassicIndexSchemaFactory"/></config>');
            }

            $xml = $live[$core] ?? null;
            return $xml === null ? $no('NOT_OWNER_ERROR') : $ok($xml);
        }

        if (str_contains($url, '/upload_config_file')) {
            $core = '';
            if (preg_match('/name="core_name"\r\n\r\n([^\r]+)/', $body, $m) === 1) {
                $core = $m[1];
            }
            $file = '';
            if (preg_match('/filename="([^"]+)"/', $body, $m) === 1) {
                $file = $m[1];
            }
            $why = $reject === null ? null : $reject($core, $file);
            if (is_string($why)) {
                return $no($why);
            }
            $uploads[] = ['core' => $core, 'file' => $file];
            return $ok('UPLOAD_OK');
        }

        return $no('UNEXPECTED_ENDPOINT');
    };
}

/** Every field name the real shipped schema for one role declares. */
function lh_sch_shipped(string $role): array
{
    return Storage::schemaFieldNames(
        (string) file_get_contents(lh_sch_root() . '/solr/' . $role . '/conf/schema.xml')
    );
}

/**
 * Run bin/loghound-schema against a config and return [exit code, output].
 *
 * @param array<int,string> $flags
 * @return array{0:int,1:string}
 */
function lh_sch_run(string $configPath, array $flags = []): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(lh_sch_root() . '/bin/loghound-schema');
    foreach ($flags as $flag) {
        $cmd .= ' ' . escapeshellarg($flag);
    }
    $cmd .= ' 2>&1';

    $proc = proc_open(
        $cmd,
        [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        dirname($configPath, 2),
        ['LOGHOUND_CONFIG' => $configPath, 'PATH' => (string) getenv('PATH')]
    );
    if (!is_resource($proc)) {
        lh_skip('cannot start a PHP subprocess here');
    }
    $out = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [proc_close($proc), $out];
}

/**
 * A configuration a subprocess will accept, pointing at a control plane that is not there.
 *
 * Port 9 is the discard port and nothing listens on it, which is what makes "the platform
 * could not be reached" reproducible without a network and without a mock.
 *
 * @param array<string,mixed> $over
 */
function lh_sch_cli_config(string $dir, array $over = []): string
{
    @mkdir($dir . '/config', 0700, true);
    @mkdir($dir . '/var', 0700, true);

    $path = $dir . '/config/loghound.php';
    $cfg = Config::load($path);
    $cfg->set('opensolr.email', 'operator@example.com');
    $cfg->set('opensolr.api_key', 'SENTINEL-APIKEY-9f3c17ab');
    $cfg->set('opensolr.api_base', 'http://127.0.0.1:9/solr_manager/api');
    $cfg->set('solr.base_url', 'http://127.0.0.1:9/solr');
    $cfg->set('solr.hits_core', 'lh_cli_hits');
    $cfg->set('solr.sessions_core', 'lh_cli_sessions');
    $cfg->set('beacon.enabled', false);
    $cfg->set('privacy.ip_mode', 'truncate');
    $cfg->set('privacy.retention_days', 0);
    $cfg->set('quota.enabled', false);
    $cfg->set('auth.mode', 'basic');
    $cfg->set('auth.user', 'operator');
    $cfg->set('auth.password_hash', password_hash('a-long-enough-password', PASSWORD_DEFAULT));
    foreach ($over as $key => $value) {
        $cfg->set($key, $value);
    }
    $cfg->save();

    return $path;
}

return [

    /* ---------------------------------------------------------------------------------
     * The fingerprint: what makes "a different release" a question with an answer
     * ------------------------------------------------------------------------------ */

    'the release fingerprint follows the field set and ignores everything else'
        => static function (): void {
            $root = lh_tmpdir('lh-fp');
            @mkdir($root . '/solr/hits/conf', 0750, true);
            $path = $root . '/solr/hits/conf/schema.xml';

            file_put_contents($path, lh_sch_xml(['id', 'ts', 'ip_s']));
            $first = Schema::releaseFor($root, 'hits');

            file_put_contents(
                $path,
                "<schema>\n\n<!-- reworded, reindented, reordered -->\n"
                . '<field  name="ip_s"  type="string"/>' . "\n"
                . '<field name="ts" type="string"/>' . "\n"
                . '<field name="id" type="string"/>' . "\n"
                . '<dynamicField name="*" type="ignored" multiValued="true"/>' . "\n</schema>\n"
            );
            lh_same($first, Schema::releaseFor($root, 'hits'), 'reformatting must not look like a schema change');

            file_put_contents($path, lh_sch_xml(['id', 'ts', 'ip_s', 'planes_s']));
            lh_true(
                Schema::releaseFor($root, 'hits') !== $first,
                'adding a field MUST move the fingerprint — that is the event the whole feature is for'
            );

            lh_rmtree($root);
        },

    'a document that declares no fields is refused rather than fingerprinted as an empty release'
        => static function (): void {
            $root = lh_tmpdir('lh-fp2');
            @mkdir($root . '/solr/hits/conf', 0750, true);
            file_put_contents($root . '/solr/hits/conf/schema.xml', '<html>404 Not Found</html>');

            lh_throws(
                static fn () => Schema::releaseFor($root, 'hits'),
                'a schema with no fields is a broken checkout, not a release expecting nothing'
            );

            lh_rmtree($root);
        },

    /* ---------------------------------------------------------------------------------
     * The comparison
     * ------------------------------------------------------------------------------ */

    'a field this release writes and the index does not declare is reported by name'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));

            lh_same(Schema::BEHIND, $report['state'], 'one index behind makes the installation behind');
            lh_same(Schema::BEHIND, $report['indexes'][0]['state']);
            lh_same(['install_s'], $report['indexes'][0]['missing'], 'and the field is named');
            lh_same(Schema::CURRENT, $report['indexes'][1]['state'], 'the other index is untouched by that');
            lh_contains($report['indexes'][0]['message'], 'install_s', 'the sentence names it too');
            lh_contains(
                $report['indexes'][0]['message'],
                'discarded',
                'and says what happens to the value, because that is the part nobody expects'
            );

            lh_rmtree($root);
        },

    'a field the index has and this release does not write is not a mismatch'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s', 'install_s', 'from_the_future_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));

            lh_same(Schema::CURRENT, $report['state'], 'an extra field is not an error');
            lh_same(['from_the_future_s'], $report['indexes'][0]['extra'], 'it is reported, as information');
            lh_same([], $report['indexes'][0]['missing']);
        },

    'a schema that cannot be read is never reported as matching'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => null,
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));

            lh_same(Schema::UNREADABLE, $report['indexes'][0]['state']);
            lh_same(Schema::UNREADABLE, $report['state'], 'and it outranks a perfect second index');
            lh_contains(
                $report['indexes'][0]['message'],
                'NOT_OWNER_ERROR',
                'the reason the platform gave is carried through, because that is the actionable half'
            );
            lh_false(
                str_contains(strtolower($report['indexes'][0]['message']), 'up to date and'),
                'and it is never worded as a pass'
            );
        },

    'a live document that is not a managed schema reads as unreadable, not as an empty schema'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => '<html><body>Gateway Timeout</body></html>',
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));

            lh_same(
                Schema::UNREADABLE,
                $report['indexes'][0]['state'],
                'an error page read as a schema would make every field look missing'
            );
            lh_same([], $report['indexes'][0]['missing'], 'and it must not produce a list of phantom fields');
        },

    'an index that was never provisioned reads as unconfigured, not as behind'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $cfg->set('solr.hits_core', '');
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([], $uploads));

            lh_same(Schema::UNCONFIGURED, $report['indexes'][0]['state']);
            lh_same(Schema::UNCONFIGURED, $report['state'], 'which is the worst state of the two');
            lh_same([], $uploads, 'and nothing was asked of the platform for an index that does not exist');
        },

    'the shipped schemas are what the check measures against'
        => static function (): void {
            foreach (Schema::ROLES as $role) {
                $shipped = lh_sch_shipped($role);
                lh_true(count($shipped) > 20, $role . ' must declare a real field list');
                lh_same(
                    $shipped,
                    Schema::expectedFields(lh_sch_root(), $role),
                    'the expectation is read from the configset this release ships, with nothing in between'
                );
            }

            $hits = Schema::expectedFields(lh_sch_root(), 'hits');
            $sessions = Schema::expectedFields(lh_sch_root(), 'sessions');
            lh_true(in_array('install_s', $hits, true), 'install_s is one of the fields the incident was about');
            lh_true(in_array('search_terms_ss', $hits, true));
            lh_true(in_array('planes_s', $sessions, true));
        },

    /* ---------------------------------------------------------------------------------
     * Pushing
     * ------------------------------------------------------------------------------ */

    'applying pushes the index that is behind and leaves the one that is not alone'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];
            $transport = lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads);

            $report = Schema::inspect($cfg, $root, $transport);
            $result = Schema::apply($cfg, $root, $report, $transport);

            lh_same('applied', $result['state']);
            lh_same(1, $result['changed'], 'exactly one index was reconfigured');
            lh_same(
                [
                    ['core' => 'loghound_9f3c17ab_hits', 'file' => 'mapping-ISOLatin1Accent.txt'],
                    ['core' => 'loghound_9f3c17ab_hits', 'file' => 'schema.xml'],
                    ['core' => 'loghound_9f3c17ab_hits', 'file' => 'solrconfig.xml'],
                ],
                $uploads,
                'dependencies before dependants: the file the schema names, then the schema, then '
                . 'the solrconfig that makes it authoritative — and nothing at all to the index '
                . 'that was already current'
            );
            lh_same('skipped', $result['indexes'][1]['state']);

            lh_rmtree($root);
        },

    'applying refuses to push over a schema it could not read'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];
            $transport = lh_sch_transport([
                'loghound_9f3c17ab_hits'     => null,
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads);

            $report = Schema::inspect($cfg, $root, $transport);
            $result = Schema::apply($cfg, $root, $report, $transport);

            lh_same('failed', $result['state'], 'a refusal is a failure, not a quiet skip');
            lh_same('refused', $result['indexes'][0]['state']);
            lh_same([], $uploads, 'a push replaces the whole schema, so an unread index is never pushed to');
            lh_contains(
                $result['indexes'][0]['message'],
                'will not overwrite a schema it has not read',
                'and the refusal says why'
            );

            lh_rmtree($root);
        },

    'a rejected schema stops the push and reports the index as untouched'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];
            $transport = lh_sch_transport(
                [
                    'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                    'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
                ],
                $uploads,
                static fn (string $core, string $file): ?string
                    => $file === 'schema.xml' ? 'ERROR_SCHEMA_REJECTED' : null
            );

            $report = Schema::inspect($cfg, $root, $transport);
            $result = Schema::apply($cfg, $root, $report, $transport);

            lh_same('failed', $result['state']);
            lh_same(
                [['core' => 'loghound_9f3c17ab_hits', 'file' => 'mapping-ISOLatin1Accent.txt']],
                $uploads,
                'the support file lands first and is inert; solrconfig.xml must NOT be uploaded '
                . 'after the schema was refused, because it is what would switch the factory'
            );
            lh_contains($result['indexes'][0]['message'], 'schema.xml was rejected');
            lh_contains($result['indexes'][0]['message'], 'ERROR_SCHEMA_REJECTED', 'with the platform\'s reason');
            lh_contains(
                $result['indexes'][0]['message'],
                'the schema in force on this index is unchanged',
                'because an operator has to know whether a re-run is safe'
            );

            lh_rmtree($root);
        },

    'a rejected solrconfig says the fields landed and the index is on its old configuration'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];
            $transport = lh_sch_transport(
                [
                    'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                    'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
                ],
                $uploads,
                static fn (string $core, string $file): ?string
                    => $file === 'solrconfig.xml' ? 'ERROR_CONFIG_REJECTED' : null
            );

            $report = Schema::inspect($cfg, $root, $transport);
            $result = Schema::apply($cfg, $root, $report, $transport);

            lh_same('failed', $result['state']);
            lh_same(2, count($uploads), 'the support file and the schema both landed');
            lh_contains($result['indexes'][0]['message'], 'solrconfig.xml was rejected');
            lh_contains(
                $result['indexes'][0]['message'],
                'still on the MANAGED factory',
                'the three halting states are not the same state and are not described the same way'
            );
            lh_contains(
                $result['indexes'][0]['message'],
                'IGNORED',
                'a schema that landed on a managed index changed nothing, and saying otherwise is '
                . 'the misreading this message exists to prevent'
            );

            lh_rmtree($root);
        },

    'a successful push records which release configured that index'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];
            $transport = lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads);

            lh_same('', Schema::recordedRelease($cfg, 'hits'), 'nothing is claimed before a push');

            $report = Schema::inspect($cfg, $root, $transport);
            Schema::apply($cfg, $root, $report, $transport);

            lh_same(
                Schema::releaseFor($root, 'hits'),
                Schema::recordedRelease($cfg, 'hits'),
                'the marker is what lets the panel notice an upgrade without a network call'
            );
            lh_same('', Schema::recordedRelease($cfg, 'sessions'), 'and only for the index that was pushed');

            $reread = Config::load($root . '/config/loghound.php');
            lh_same(
                Schema::releaseFor($root, 'hits'),
                Schema::recordedRelease($reread, 'hits'),
                'and it survives, because it is written to the config file'
            );

            lh_rmtree($root);
        },

    'a rejected file stops the configset push inside the client itself'
        => static function (): void {
            $dir = lh_tmpdir('lh-push');
            @mkdir($dir . '/conf', 0750, true);
            file_put_contents($dir . '/conf/mapping-ISOLatin1Accent.txt', '"a" => "a"' . "\n");
            file_put_contents($dir . '/conf/schema.xml', lh_sch_xml(['id']));
            file_put_contents($dir . '/conf/solrconfig.xml', '<config/>');

            $uploads = [];
            $client = new Opensolr(
                ['email' => 'operator@example.com', 'api_key' => 'SENTINEL-APIKEY-9f3c17ab'],
                lh_sch_transport(
                    [],
                    $uploads,
                    static fn (string $core, string $file): ?string
                        => $file === 'schema.xml' ? 'ERROR_SCHEMA_REJECTED' : null
                )
            );

            $rows = $client->pushConfigSet('loghound_9f3c17ab_hits', $dir . '/conf');

            lh_same(
                [['core' => 'loghound_9f3c17ab_hits', 'file' => 'mapping-ISOLatin1Accent.txt']],
                $uploads,
                'the file the schema DEPENDS ON went first and was accepted; nothing after the '
                . 'rejection is sent'
            );
            lh_same(
                count(Opensolr::CONFIGSET_FILES),
                count($rows),
                'and every file is still reported, rather than vanishing from the result'
            );
            lh_false($rows[1]['ok'], 'the schema is the one that was rejected');
            lh_false($rows[2]['ok'], 'and solrconfig.xml was therefore not attempted');
            lh_contains(
                $rows[2]['msg'],
                'not uploaded',
                'solrconfig.xml is what switches the schema factory, so sending it after a '
                . 'rejected schema would make the index authoritative on a file that was refused'
            );

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * What the panel says, without touching the network
     * ------------------------------------------------------------------------------ */

    'a saved check about this release is what the card shows, with the moment it was taken'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));
            Schema::writeCache($cfg, $report);

            $notice = Schema::notice($cfg, $root);

            lh_same(Schema::BEHIND, $notice['state']);
            lh_same('bad', $notice['severity'], 'a missing field is not a note, it is a fault');
            lh_same($report['checked_at'], $notice['checked_at'], 'the age of the answer travels with it');
            lh_same(2, count($notice['indexes']), 'and the per-index detail is there to render');
            lh_contains($notice['command'], 'bin/loghound-schema', 'with the command that fixes it');
            lh_contains($notice['command'], $root, 'named with this installation\'s own path');

            lh_rmtree($root);
        },

    'a check taken against a different release is reported as saying nothing about this one'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $report = Schema::inspect($cfg, $root, lh_sch_transport([
                'loghound_9f3c17ab_hits'     => lh_sch_xml(['id', 'ts', 'ip_s', 'install_s']),
                'loghound_9f3c17ab_sessions' => lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss']),
            ], $uploads));
            lh_same(Schema::CURRENT, $report['state'], 'the installation was up to date when it was checked');
            Schema::writeCache($cfg, $report);

            file_put_contents(
                $root . '/solr/hits/conf/schema.xml',
                lh_sch_xml(['id', 'ts', 'ip_s', 'install_s', 'brand_new_field_s'])
            );

            $notice = Schema::notice($cfg, $root);

            lh_same(
                Schema::SUPERSEDED,
                $notice['state'],
                'THIS is the upgrade: a clean verdict from before the release changed the schema'
            );
            lh_false($notice['severity'] === 'good', 'and it must never be rendered as reassurance');
            lh_same($report['checked_at'], $notice['checked_at'], 'its age is still stated plainly');
            lh_same([], $notice['indexes'], 'and the stale per-index detail is not shown as current');

            lh_rmtree($root);
        },

    'markers that do not match this release are reported as drift before anybody checks'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();

            foreach (Schema::ROLES as $role) {
                Schema::recordRelease($cfg, $role, $root);
            }
            lh_same(Schema::PUSHED, Schema::notice($cfg, $root)['state'], 'matching markers are the quiet case');

            file_put_contents(
                $root . '/solr/sessions/conf/schema.xml',
                lh_sch_xml(['id', 'ts_start', 'planes_s', 'search_terms_ss', 'added_by_this_release_s'])
            );

            $notice = Schema::notice($cfg, $root);
            lh_same(Schema::DRIFTED, $notice['state']);
            lh_same('bad', $notice['severity']);
            lh_contains($notice['detail'], 'silently', 'because that is the reason this is not a footnote');

            lh_rmtree($root);
        },

    'an installation with no evidence at all is reported as unverified, never as current'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();

            $notice = Schema::notice($cfg, $root);

            lh_same(Schema::UNVERIFIED, $notice['state']);
            lh_same(null, $notice['checked_at'], 'and it does not invent a date');
            lh_false($notice['severity'] === 'good', 'an absence of evidence is not evidence of a match');
            lh_contains($notice['detail'], 'after every upgrade');

            lh_rmtree($root);
        },

    'a cache file that is damaged is treated as absent rather than half-read'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();

            file_put_contents(Schema::cachePath($cfg), '{"state":"current"');
            lh_same(null, Schema::readCache($cfg), 'truncated JSON is not a verdict');

            file_put_contents(Schema::cachePath($cfg), '{"state":"current","release":"x"}');
            lh_same(null, Schema::readCache($cfg), 'and neither is half a verdict');

            lh_same(Schema::UNVERIFIED, Schema::notice($cfg, $root)['state'], 'so the card asks for a check');

            lh_rmtree($root);
        },

    /* ---------------------------------------------------------------------------------
     * The command, run as the process it really is
     * ------------------------------------------------------------------------------ */

    'the command refuses to run under a web SAPI'
        => static function (): void {
            $source = (string) file_get_contents(lh_sch_root() . '/bin/loghound-schema');

            lh_contains(
                $source,
                "if (PHP_SAPI !== 'cli') {",
                'a tool that reconfigures and reloads a live index must not be reachable over HTTP'
            );
            lh_contains($source, 'http_response_code(404)', 'and it says nothing about itself when it refuses');
        },

    'every command in bin/ is delivered executable, this one included'
        => static function (): void {
            $installer = (string) file_get_contents(lh_sch_root() . '/install/install.sh');

            lh_false(
                (bool) preg_match('/for cmd in loghound-[a-z -]+; do/', $installer),
                'the installer chmods every file under bin/ to 0640 and then restores the execute '
                . 'bit. It did that from a hardcoded list of four names, so bin/loghound-schema '
                . 'shipped non-executable. A list that has to be edited in step with a directory is '
                . 'a list that gets forgotten; it is derived from the directory now'
            );
            lh_contains($installer, '"$PREFIX/bin" -maxdepth 1 -type f -exec chmod 0750');
            lh_contains(
                $installer,
                'for target in "$PREFIX"/bin/*',
                'the /usr/local/bin symlinks are derived from the directory too, or a new command '
                . 'is runnable only by its full path while its siblings can be typed from anywhere'
            );
            lh_contains(
                $installer,
                '[[ "$target" == "$PREFIX/bin/"* ]]',
                'and the uninstaller matches a link by where it POINTS, so a command a later release '
                . 'adds cannot be left behind as a dangling symlink by an uninstall that reported '
                . 'success'
            );

            foreach ((array) glob(lh_sch_root() . '/bin/*') as $command) {
                $path = (string) $command;
                lh_true(is_executable($path), basename($path) . ' must be executable in the repository');
                lh_contains(
                    (string) file_get_contents($path),
                    '#!/usr/bin/env php',
                    basename($path) . ' is in bin/, so it is a command and needs a shebang'
                );
            }
        },

    '--help exits 0 and publishes the exit codes a deployment script reads'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-help');
            $path = lh_sch_cli_config($dir);

            [$code, $out] = lh_sch_run($path, ['--help']);

            lh_same(0, $code);
            lh_contains($out, '--apply');
            lh_contains($out, '--check');
            lh_contains($out, '0  up to date');
            lh_contains($out, '3  out of date');

            lh_rmtree($dir);
        },

    'an unknown option is refused rather than treated as --check'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-flag');
            $path = lh_sch_cli_config($dir);

            [$code, $out] = lh_sch_run($path, ['--push-everything']);

            lh_same(1, $code, 'a misspelt flag must not run something else');
            lh_contains($out, 'unknown option');

            lh_rmtree($dir);
        },

    'a control plane that cannot be reached exits 2, never 0'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-down');
            $path = lh_sch_cli_config($dir);

            [$code, $out] = lh_sch_run($path);

            lh_same(2, $code, '"could not tell" and "up to date" must not share an exit code');
            lh_contains($out, 'UNREADABLE');
            lh_contains($out, 'never reported as matching');

            lh_rmtree($dir);
        },

    'applying against an unreachable control plane changes nothing and still exits 2'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-apply');
            $path = lh_sch_cli_config($dir);

            [$code, $out] = lh_sch_run($path, ['--apply']);

            lh_same(2, $code);
            lh_contains($out, 'REFUSED');
            lh_contains($out, 'Nothing was uploaded');

            lh_rmtree($dir);
        },

    'an installation with no indexes exits 1, which is a different problem from a failed check'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-bare');
            $path = lh_sch_cli_config($dir, ['solr.hits_core' => '', 'solr.sessions_core' => '']);

            [$code, $out] = lh_sch_run($path);

            lh_same(1, $code);
            lh_contains($out, 'loghound-setup', 'and it points at the tool that fixes it');

            lh_rmtree($dir);
        },

    'the verdict the command saves is the file the panel reads'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-cache');
            $path = lh_sch_cli_config($dir);

            lh_sch_run($path);

            $cfg = Config::load($path);
            $cache = Schema::readCache($cfg);
            lh_true(is_array($cache), 'the run left a verdict behind');
            lh_same(Schema::UNREADABLE, $cache['state']);
            lh_same(
                Schema::release(lh_sch_root()),
                $cache['release'],
                'stamped with the release it describes, so it cannot be read as describing another'
            );

            lh_rmtree($dir);
        },

    /* ---------------------------------------------------------------------------------
     * The credential
     * ------------------------------------------------------------------------------ */

    'the API key reaches neither the output, the saved verdict nor a job note'
        => static function (): void {
            $dir = lh_tmpdir('lh-cli-secret');
            $path = lh_sch_cli_config($dir);

            [, $out] = lh_sch_run($path, ['--apply']);
            lh_false(str_contains($out, 'SENTINEL-APIKEY'), 'the key must never be printed to a terminal');
            lh_false(str_contains($out, 'api_key='), 'nor echoed back inside a URL');

            $saved = (string) @file_get_contents($dir . '/var/schema-check.json');
            lh_true($saved !== '', 'the verdict was saved');
            lh_false(str_contains($saved, 'SENTINEL-APIKEY'), 'and it is a file with a wider audience');

            lh_rmtree($dir);
        },

    'the saved verdict carries no credential from a refusal that echoed the request'
        => static function (): void {
            [$root, $cfg] = lh_sch_install();
            $uploads = [];

            $echo = static function (array $req) use (&$uploads): array {
                return [
                    'status' => 200,
                    'body'   => (string) json_encode([
                        'status' => false,
                        'msg'    => 'REFUSED for ' . (string) ($req['url'] ?? ''),
                    ]),
                    'error'  => '',
                ];
            };

            $report = Schema::inspect($cfg, $root, $echo);
            Schema::writeCache($cfg, $report);

            $saved = (string) file_get_contents(Schema::cachePath($cfg));
            lh_false(
                str_contains($saved, 'SENTINEL-APIKEY-9f3c17ab'),
                'the platform echoes request parameters back on some error paths, and one of them is the key'
            );
            lh_contains($saved, 'redacted', 'it is redacted rather than dropped, so the reason survives');

            lh_rmtree($root);
        },

    /* ---------------------------------------------------------------------------------
     * Upgrading is not upgrading until it is written down
     * ------------------------------------------------------------------------------ */

    'the upgrade instructions name the command, in every document that describes upgrading'
        => static function (): void {
            foreach (['README.md', 'docs/INSTALL.md', 'docs/SCHEMA.md'] as $doc) {
                $body = (string) @file_get_contents(lh_sch_root() . '/' . $doc);
                lh_true($body !== '', $doc . ' must exist');
                lh_contains(
                    $body,
                    'loghound-schema',
                    $doc . ' describes upgrading and must say that a schema change needs this command — '
                    . 'an upgrade instruction that omits it recreates the silent-field-loss bug'
                );
            }
        },

    'the release notes carry it too, where somebody reads what an upgrade involves'
        => static function (): void {
            $body = (string) @file_get_contents(lh_sch_root() . '/CHANGELOG.md');
            lh_contains($body, 'loghound-schema');
        },

    'the Settings page says a behind schema out loud, and prints the command that fixes it'
        => static function (): void {
            $dir = lh_tmpdir('lh-panel-schema');
            @mkdir($dir . '/config', 0750, true);
            @mkdir($dir . '/var', 0750, true);

            $cfg = Config::load($dir . '/config/loghound.php');
            $cfg->set('solr.base_url', 'http://127.0.0.1:65535/solr');
            $cfg->set('solr.hits_core', 'loghound_9f3c17ab_hits');
            $cfg->set('solr.sessions_core', 'loghound_9f3c17ab_sessions');

            Schema::writeCache($cfg, [
                'checked_at' => 1757500000,
                'release'    => Schema::release(lh_sch_root()),
                'state'      => Schema::BEHIND,
                'indexes'    => [
                    [
                        'role'     => 'hits',
                        'core'     => 'loghound_9f3c17ab_hits',
                        'state'    => Schema::BEHIND,
                        'expected' => 74,
                        'live'     => 71,
                        'missing'  => ['planes_s', 'search_terms_ss', 'install_s'],
                        'extra'    => [],
                        'message'  => 'missing three fields',
                    ],
                ],
            ]);

            $transport = static fn (array $req): array => [
                'status' => 200,
                'body'   => (string) json_encode([
                    'responseHeader' => ['status' => 0],
                    'response'       => ['numFound' => 0, 'docs' => []],
                ]),
                'error'  => '',
            ];
            $gw = new Gateway($cfg, new Solr((array) $cfg->get('solr'), $transport), false);

            ob_start();
            (new Settings($cfg, $gw))->body();
            $html = (string) ob_get_clean();

            lh_contains($html, 'Index schema', 'the card has a section for it');
            lh_contains($html, 'missing fields this release writes', 'and says so in the headline');
            lh_contains($html, 'chip-warn', 'carrying the marker that force-opens a folded card');
            lh_contains($html, 'search_terms_ss', 'the missing fields are named');
            lh_contains(
                $html,
                lh_sch_root() . '/bin/loghound-schema --apply',
                'and the fix is printed with this installation\'s real path, ready to paste'
            );
            lh_contains($html, '09/10/2025 10:26:40 UTC', 'with the moment the verdict was taken');
            lh_contains($html, 'data-job="schema_check"', 'and a way to refresh it without a shell');

            lh_rmtree($dir);
        },

    'the panel offers the check as a job rather than doing it while the page renders'
        => static function (): void {
            $body = (string) file_get_contents(lh_sch_root() . '/src/Panel/Settings.php');

            lh_contains($body, "KIND_SCHEMA = 'schema_check'");
            lh_contains($body, 'data-job="\' . Security::esc(self::KIND_SCHEMA)');
            lh_contains($body, 'Schema::notice(', 'the card renders from the saved verdict');
            lh_false(
                str_contains($body, 'Schema::inspect('),
                'and never reaches the control plane from a page render, which is what a job is for'
            );
        },
];
