<?php
/**
 * Loghound — keeping a live index's schema in step with the release that writes to it.
 *
 * ---------------------------------------------------------------------------------------
 * THE FAILURE THIS EXISTS TO STOP
 * ---------------------------------------------------------------------------------------
 * A release adds a field. The operator upgrades the code. The two indexes on their Opensolr
 * account are still running the configset that was uploaded when they installed, and the only
 * dynamic field either schema declares is `*` mapped to `ignored`. So Solr accepts every
 * document carrying the new field, maps it to a type that indexes nothing and stores nothing,
 * and answers 200. The write succeeds, the value disappears, and NOTHING ANYWHERE REPORTS AN
 * ERROR — not the tailer, not the scorer, not the panel. The first symptom is a facet that is
 * permanently empty, months later, with no way to recover the values that were dropped.
 *
 * Until this class existed the comparison lived inside Setup\Storage::reconcileSchema(), which
 * is private and reachable only from a setup job, so an operator upgrading an installation had
 * exactly two options: re-run setup, or have a broken installation and no way to find out. This
 * is the supported third one — `bin/loghound-schema` on the shell, a card in Settings in the
 * browser, and one implementation underneath both.
 *
 * ---------------------------------------------------------------------------------------
 * NOTHING HERE IS A SECOND IMPLEMENTATION
 * ---------------------------------------------------------------------------------------
 * The comparison is Storage::schemaShortfall() and Storage::schemaFieldNames(), which is what
 * the reuse path in setup uses, so an index the installer calls current cannot be called behind
 * here or the other way round. The push is Opensolr::pushConfigSet(), which is what provisioning
 * uses: same file allowlist, same schema-then-solrconfig order, same per-file reporting. This
 * class is the operator-facing shape around those two, plus the memory that makes the panel able
 * to say something true without a network call on every page load.
 *
 * ---------------------------------------------------------------------------------------
 * WHAT COUNTS AS BEHIND, AND WHAT DOES NOT
 * ---------------------------------------------------------------------------------------
 * A field this release writes and the live schema does not declare is a MISMATCH: the value is
 * being discarded on every document. A field the live schema declares and this release does not
 * write is NOT a mismatch — that is a newer schema, or a field a later release removed, and it
 * costs nothing but the line it occupies. Reporting it as an error would tell operators to
 * "fix" an installation that is running fine, and the fix would be a downgrade.
 *
 * ---------------------------------------------------------------------------------------
 * TWO PLACES THE VERDICT CAN COME FROM, BOTH HONEST ABOUT THEIR AGE
 * ---------------------------------------------------------------------------------------
 * Reading a live schema is a control-plane round trip, so the panel must not do it while a page
 * renders. Two cheaper sources stand in, and notice() ranks them:
 *
 *   1. **The cache** at `var/schema-check.json`, written by the command and by the panel's own
 *      check job. It carries the field-shape fingerprint of the release it was taken against,
 *      so a cache written before an upgrade is reported as saying nothing about this release
 *      rather than being read as a clean bill of health. That is the whole reason the
 *      fingerprint is in there.
 *   2. **The marker** `solr.schema_release`, one fingerprint per role, written whenever this
 *      installation successfully uploads a configset. It costs nothing to read and it answers
 *      the question the defect above is made of: were the files on that index uploaded by a
 *      release that expected the same fields this one does? A marker that does not match is
 *      not proof of a missing field, and it is not reported as one — it is reported as a
 *      reason to run the check.
 *
 * An installation with neither is reported as unverified, never as current. A schema that
 * cannot be read is reported as unreadable, never as current. There is no path through this
 * file that answers "fine" from an absence of evidence.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Security;
use Loghound\Opensolr;

final class Schema
{
    /** The two indexes, in the order every operator-facing list shows them. */
    public const ROLES = ['hits', 'sessions'];

    /** The live schema declares every field this release writes. */
    public const CURRENT = 'current';

    /** The live schema is missing at least one field this release writes. */
    public const BEHIND = 'behind';

    /** The live schema could not be read, so nothing can be concluded about it. */
    public const UNREADABLE = 'unreadable';

    /** There is no index name in the configuration — this installation is not set up. */
    public const UNCONFIGURED = 'unconfigured';

    /** No check has been made that describes the release running now. */
    public const UNVERIFIED = 'unverified';

    /**
     * A check exists, but it was taken against a release expecting different fields.
     *
     * Distinct from UNVERIFIED on purpose: the operator is told there IS a result and told
     * why it is not being used, which is what stops the next person re-reading the stale
     * verdict off the cache file and believing it.
     */
    public const SUPERSEDED = 'superseded';

    /**
     * The configsets were uploaded by a release that expected this same set of fields.
     *
     * The strongest thing that can be said without a network call, and deliberately not called
     * CURRENT: it is evidence about what this installation uploaded, not about what the index
     * is running. An index reconfigured from the Opensolr control panel, or shared with an
     * installation running another release, would still say this.
     */
    public const PUSHED = 'pushed';

    /**
     * The configset files were uploaded by a release expecting a different set of fields.
     *
     * The marker case that matters: this is what an upgrade across a schema change looks like
     * before anybody runs the check.
     */
    public const DRIFTED = 'drifted';

    /** Severity order, worst first, for reducing per-index states to one verdict. */
    private const SEVERITY = [
        self::UNCONFIGURED,
        self::UNREADABLE,
        self::BEHIND,
        self::CURRENT,
    ];

    /** Where the cached verdict lives, relative to the installation root. */
    private const CACHE_RELATIVE = '/var/schema-check.json';

    /** The configuration key holding one uploaded-release fingerprint per role. */
    private const MARKER_KEY = 'solr.schema_release';

    /**
     * The installation root: the directory holding `bin/`, `solr/` and `config/`.
     *
     * Derived from this file rather than from the caller, so a command run through a symlink
     * from `/usr/local/bin` still finds the configsets belonging to the code that is executing.
     */
    public static function root(): string
    {
        $root = dirname(__DIR__, 2);
        $real = realpath($root);
        return $real === false ? $root : $real;
    }

    /** The command an operator runs to check or fix an installation, with its real path. */
    public static function command(string $root): string
    {
        return 'php ' . rtrim($root, '/') . '/bin/loghound-schema';
    }

    /** The configset directory for one role in this checkout. */
    public static function confDir(string $root, string $role): string
    {
        return rtrim($root, '/') . '/solr/' . self::role($role) . '/conf';
    }

    /**
     * The managed schema this release ships for one role.
     *
     * @throws \RuntimeException When the checkout does not contain it, which is a broken
     *                           installation rather than a broken index and is said as much.
     */
    public static function localSchema(string $root, string $role): string
    {
        $path = self::confDir($root, $role) . '/managed-schema.xml';
        $xml = @file_get_contents($path);
        if (!is_string($xml) || $xml === '') {
            throw new \RuntimeException('The schema is missing from this installation: ' . $path);
        }
        return $xml;
    }

    /**
     * Every field name this release writes into one index.
     *
     * @return string[]
     * @throws \RuntimeException When the shipped schema declares none, which means the file is
     *                           not a managed schema at all — a truncated checkout, not an
     *                           index with nothing in it.
     */
    public static function expectedFields(string $root, string $role): array
    {
        $names = Storage::schemaFieldNames(self::localSchema($root, $role));
        if ($names === []) {
            throw new \RuntimeException(
                'The schema shipped for the ' . self::role($role) . ' index declares no fields, so it '
                . 'is not a usable managed schema. Re-install the code before touching an index.'
            );
        }
        return $names;
    }

    /**
     * The field shape one role expects, as a short stable fingerprint.
     *
     * Over the SORTED FIELD NAMES and nothing else, which is the property that makes it usable
     * as a marker: reformatting a schema, rewording a comment or reordering a declaration does
     * not move it, so an operator is never told to push a configset that would change nothing.
     * Adding or removing a field does move it, which is exactly the event worth reporting.
     */
    public static function releaseFor(string $root, string $role): string
    {
        $names = self::expectedFields($root, $role);
        sort($names);
        return substr(hash('sha256', self::role($role) . "\n" . implode("\n", $names)), 0, 16);
    }

    /**
     * The field shape of the whole release — both roles at once.
     *
     * Stamped into the cache file so a verdict can be matched to the release that produced it.
     */
    public static function release(string $root): string
    {
        $parts = [];
        foreach (self::ROLES as $role) {
            $parts[] = $role . '=' . self::releaseFor($root, $role);
        }
        return substr(hash('sha256', implode(';', $parts)), 0, 16);
    }

    /** The configured index name for one role, or an empty string when there is none. */
    public static function core(Config $cfg, string $role): string
    {
        return (string) $cfg->get('solr.' . self::role($role) . '_core', '');
    }

    /**
     * Compare this release against both live schemas.
     *
     * ONE CONTROL-PLANE READ PER INDEX, and nothing is written anywhere: this is the whole of
     * `--check`, and it is also the first half of `--apply`, because pushing without first
     * reading what is there would mean pushing over a schema that might be newer than this one.
     *
     * @param callable|null $transport Injectable so the suite runs with no network.
     * @return array{checked_at:int,release:string,state:string,indexes:array<int,array<string,mixed>>}
     */
    public static function inspect(Config $cfg, string $root, ?callable $transport = null): array
    {
        $client = Storage::client($cfg, $transport);

        $rows = [];
        foreach (self::ROLES as $role) {
            $rows[] = self::inspectOne($cfg, $root, $role, $client);
        }

        return [
            'checked_at' => time(),
            'release'    => self::release($root),
            'state'      => self::worst(array_column($rows, 'state')),
            'indexes'    => $rows,
        ];
    }

    /**
     * Compare one index, and say what was found in a sentence rather than a code.
     *
     * The live schema is fetched with Opensolr::fetchConfigFile(), which answers null for every
     * kind of failure there is. A null, and a document that yields no field names at all, are
     * both treated as UNREADABLE — never as an empty schema, because there is no such thing as
     * a managed schema with no fields, and reading one that way would make every field look
     * missing and every index look catastrophically behind.
     *
     * @return array<string,mixed>
     */
    private static function inspectOne(Config $cfg, string $root, string $role, Opensolr $client): array
    {
        $role = self::role($role);
        $core = self::core($cfg, $role);

        $row = [
            'role'     => $role,
            'core'     => $core,
            'state'    => self::UNREADABLE,
            'expected' => 0,
            'live'     => 0,
            'missing'  => [],
            'extra'    => [],
            'message'  => '',
        ];

        if ($core === '') {
            $row['state'] = self::UNCONFIGURED;
            $row['message'] = 'No ' . $role . ' index is configured, so there is nothing to compare. '
                . 'Run setup before running this.';
            return $row;
        }

        $localXml = self::localSchema($root, $role);
        $expected = self::expectedFields($root, $role);
        $row['expected'] = count($expected);

        $why = null;
        $liveXml = $client->fetchConfigFile($core, 'managed-schema', 'xml', $why);
        $live = is_string($liveXml) ? Storage::schemaFieldNames($liveXml) : [];

        if ($liveXml === null || $live === []) {
            $row['message'] = 'Opensolr would not hand back a readable schema for ' . $core . '. '
                . ($why !== null && $why !== ''
                    ? rtrim($why, ' .') . '. '
                    : 'What came back was not a managed schema. ')
                . 'Loghound will not report an index it could not read as up to date, so this is '
                . 'reported as unknown. Try again; if it keeps happening, check the account still '
                . 'owns this index.';
            return $row;
        }

        $row['live'] = count($live);
        $row['missing'] = Storage::schemaShortfall($localXml, $liveXml);
        $row['extra'] = array_values(array_diff($live, $expected));

        if ($row['missing'] === []) {
            $row['state'] = self::CURRENT;
            $row['message'] = $core . ' declares every field this release writes'
                . ($row['extra'] === []
                    ? '.'
                    : ', and ' . count($row['extra']) . ' more this release does not write, which is '
                        . 'not a problem and is left alone.');
            return $row;
        }

        $row['state'] = self::BEHIND;
        $one = count($row['missing']) === 1;
        $row['message'] = $core . ' is missing ' . count($row['missing']) . ' of the '
            . count($expected) . ' fields this release writes (' . self::namedList($row['missing'])
            . '). ' . ($one ? 'A document carrying it is' : 'Documents carrying them are')
            . ' accepted and the value' . ($one ? ' is' : 's are') . ' discarded, because the only '
            . 'dynamic field in this schema maps everything unknown to the ignored type.';

        return $row;
    }

    /**
     * Push this release's configsets to the indexes that need them.
     *
     * WHAT IS NOT DONE, and why. An index whose live schema could not be read is REFUSED rather
     * than pushed to. A push replaces the whole configset, so pushing blind to an index that
     * might be running a NEWER schema would remove the fields that newer release writes — the
     * very failure this file exists to stop, caused by the tool meant to prevent it. Refusing
     * costs a re-run when the control plane answers again; pushing blind costs data. Setup's
     * reuse path makes the same choice for the same reason.
     *
     * An index already current is skipped, not re-pushed. There is nothing to gain from a core
     * reload on a live index that is already right.
     *
     * @param array{indexes:array<int,array<string,mixed>>} $report From inspect(), so that this
     *                                                              never pushes without having
     *                                                              read what is there.
     * @param callable|null $say Progress sink, one line at a time.
     * @return array{state:string,changed:int,indexes:array<int,array<string,mixed>>}
     */
    public static function apply(
        Config $cfg,
        string $root,
        array $report,
        ?callable $transport = null,
        ?callable $say = null
    ): array {
        $note = $say ?? static function (string $line): void {
        };
        $client = Storage::client($cfg, $transport);

        $rows = [];
        $failed = false;
        $changed = 0;

        foreach ((array) ($report['indexes'] ?? []) as $found) {
            $role = self::role((string) ($found['role'] ?? ''));
            $core = (string) ($found['core'] ?? '');
            $state = (string) ($found['state'] ?? self::UNREADABLE);

            if ($state === self::CURRENT) {
                $rows[] = [
                    'role'    => $role,
                    'core'    => $core,
                    'state'   => 'skipped',
                    'files'   => [],
                    'message' => $core . ' already has every field this release writes; nothing was uploaded.',
                ];
                continue;
            }

            if ($state !== self::BEHIND) {
                $failed = true;
                $rows[] = [
                    'role'    => $role,
                    'core'    => $core,
                    'state'   => 'refused',
                    'files'   => [],
                    'message' => (string) ($found['message'] ?? 'This index could not be read.')
                        . ' Nothing was uploaded to it: a configset push replaces the whole schema, and '
                        . 'Loghound will not overwrite a schema it has not read.',
                ];
                continue;
            }

            $note('Uploading this release\'s configset to ' . $core . ' …');
            $files = $client->pushConfigSet($core, self::confDir($root, $role));
            $rejected = array_values(array_filter($files, static fn (array $f): bool => !$f['ok']));

            foreach ($files as $file) {
                $note('  ' . $file['file'] . ': ' . $file['msg']);
            }

            if ($rejected === []) {
                $changed++;
                self::recordRelease($cfg, $role, $root);
                $rows[] = [
                    'role'    => $role,
                    'core'    => $core,
                    'state'   => 'pushed',
                    'files'   => $files,
                    'message' => 'Added ' . count((array) ($found['missing'] ?? [])) . ' field'
                        . (count((array) ($found['missing'] ?? [])) === 1 ? '' : 's') . ' to ' . $core
                        . ', uploaded solrconfig.xml, and reloaded the core. Documents already in the '
                        . 'index were not touched.',
                ];
                continue;
            }

            $failed = true;
            $rows[] = [
                'role'    => $role,
                'core'    => $core,
                'state'   => 'failed',
                'files'   => $files,
                'message' => self::rejectionMessage($core, $files),
            ];
        }

        return [
            'state'   => $failed ? 'failed' : ($changed > 0 ? 'applied' : self::CURRENT),
            'changed' => $changed,
            'indexes' => $rows,
        ];
    }

    /**
     * Say exactly which file was rejected and what state that leaves the index in.
     *
     * The two halves of a configset are not equivalent and a half-applied push is not a vague
     * "something went wrong": the schema is uploaded first and a rejected schema means the
     * solrconfig upload is not attempted at all, so the index is untouched and a re-run is
     * completely safe. A rejected solrconfig after an accepted schema is the other case — the
     * new fields are live and the old solrconfig still is — and an operator has to be told
     * which of the two they are looking at before they decide what to do next.
     *
     * @param array<int,array{file:string,ok:bool,msg:string}> $files
     */
    private static function rejectionMessage(string $core, array $files): string
    {
        $byName = [];
        foreach ($files as $file) {
            $byName[(string) $file['file']] = $file;
        }

        $schema = $byName['managed-schema.xml'] ?? null;
        $config = $byName['solrconfig.xml'] ?? null;

        if ($schema !== null && !$schema['ok']) {
            return $core . ': managed-schema.xml was rejected (' . (string) $schema['msg'] . '). '
                . 'solrconfig.xml was not uploaded, so nothing on this index changed and it is still '
                . 'running the configset it had. It is safe to run this again.';
        }

        if ($config !== null && !$config['ok']) {
            return $core . ': the new schema was uploaded and the core reloaded with it, but '
                . 'solrconfig.xml was rejected (' . (string) $config['msg'] . '). The fields this '
                . 'release writes are now there; the index is still running its previous solrconfig. '
                . 'Run this again to finish. If it keeps being rejected, upload solrconfig.xml for this '
                . 'index from the Opensolr control panel by hand.';
        }

        $names = [];
        foreach ($files as $file) {
            if (!$file['ok']) {
                $names[] = (string) $file['file'] . ' (' . (string) $file['msg'] . ')';
            }
        }
        return $core . ': the upload was rejected — ' . implode(', ', $names)
            . '. The index is still running the configset it had.';
    }

    /**
     * Remember that this installation uploaded this release's configset to one index.
     *
     * Written only after a push the platform accepted in full, so the marker can never claim an
     * upload that did not land. Best effort on the write itself: a configuration file that
     * cannot be saved must not turn a successful push into a reported failure, because the push
     * really did happen and re-running it would be the wrong advice.
     */
    public static function recordRelease(Config $cfg, string $role, string $root): void
    {
        $role = self::role($role);

        try {
            $markers = (array) $cfg->get(self::MARKER_KEY, []);
            $markers[$role] = self::releaseFor($root, $role);
            $cfg->set(self::MARKER_KEY, $markers);
            Storage::persist($cfg);
        } catch (\Throwable $e) {
            return;
        }
    }

    /** The release fingerprint last uploaded to one index by this installation, if any. */
    public static function recordedRelease(Config $cfg, string $role): string
    {
        $markers = (array) $cfg->get(self::MARKER_KEY, []);
        $value = $markers[self::role($role)] ?? '';
        return is_string($value) ? $value : '';
    }

    /** Where the cached verdict is kept, derived from the config so two installations cannot share one. */
    public static function cachePath(Config $cfg): string
    {
        return dirname($cfg->path(), 2) . self::CACHE_RELATIVE;
    }

    /**
     * Save a verdict for the panel to read.
     *
     * Best effort, like Detector::writeReport(): a read-only `var/` must not turn a successful
     * check into a failure. The caller is told whether it landed so it can say so rather than
     * implying a panel that is about to show nothing has been updated.
     */
    public static function writeCache(Config $cfg, array $report): ?string
    {
        $path = self::cachePath($cfg);
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || !Security::writePrivateFile($path, $json)) {
            return null;
        }
        return $path;
    }

    /**
     * Read the cached verdict, or null when there is not a usable one.
     *
     * A file that is unreadable, is not JSON, or does not carry the three fields a verdict is
     * made of is treated as absent. There is no partial reading of it: half a verdict would be
     * reported to an operator as a whole one.
     *
     * @return array<string,mixed>|null
     */
    public static function readCache(Config $cfg): ?array
    {
        $path = self::cachePath($cfg);
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data)
            || !isset($data['state'], $data['release'])
            || !is_string($data['state'])
            || !is_string($data['release'])
            || !is_array($data['indexes'] ?? null)) {
            return null;
        }
        $data['checked_at'] = (int) ($data['checked_at'] ?? 0);
        return $data;
    }

    /**
     * What can be said about this installation's schemas WITHOUT touching the network.
     *
     * This is what the Settings card renders on every page load, so it does no I/O beyond one
     * small local file and the configuration that is already in memory.
     *
     * The ladder, strongest evidence first, and every rung names its own age:
     *
     *   1. a cached check taken against THIS release — its verdict, with the date it was taken;
     *   2. a cached check taken against a different release — SUPERSEDED, because a verdict
     *      about a different set of fields is not a verdict about this one;
     *   3. no usable cache, but a marker for both indexes matching this release — PUSHED: this
     *      installation uploaded these exact fields, which is evidence and not a guarantee;
     *   4. a marker that does not match — DRIFTED, the shape an upgrade across a schema change
     *      has before anybody checks;
     *   5. nothing at all — UNVERIFIED.
     *
     * Rungs 2 to 5 are all "please run the check", which is why each one prints the command.
     * None of them is ever rendered as reassurance.
     *
     * @return array{state:string,severity:string,headline:string,detail:string,
     *               checked_at:?int,command:string,indexes:array<int,array<string,mixed>>}
     */
    public static function notice(Config $cfg, string $root): array
    {
        $command = self::command($root);

        try {
            $release = self::release($root);
        } catch (\Throwable $e) {
            return [
                'state'      => self::UNREADABLE,
                'severity'   => 'bad',
                'headline'   => 'The schemas are missing from this installation.',
                'detail'     => $e->getMessage() . ' Until the code is complete, Loghound cannot tell '
                    . 'you whether your indexes carry the fields it writes.',
                'checked_at' => null,
                'command'    => $command,
                'indexes'    => [],
            ];
        }

        $cache = self::readCache($cfg);

        if ($cache !== null && (string) $cache['release'] === $release) {
            return self::noticeFromCache($cache, $command);
        }

        if ($cache !== null) {
            return [
                'state'      => self::SUPERSEDED,
                'severity'   => 'warn',
                'headline'   => 'The last schema check was made against a different release.',
                'detail'     => 'There is a saved result, but it was taken when Loghound expected a '
                    . 'different set of fields, so it says nothing about the one running now. This is '
                    . 'the upgrade case: new fields are written to an index that may not declare them, '
                    . 'and Solr discards them without an error. Check it again.',
                'checked_at' => (int) $cache['checked_at'],
                'command'    => $command,
                'indexes'    => [],
            ];
        }

        return self::noticeFromMarkers($cfg, $root, $release, $command);
    }

    /**
     * Turn a cached verdict about this release into the card's wording.
     *
     * @param array<string,mixed> $cache
     * @return array<string,mixed>
     */
    private static function noticeFromCache(array $cache, string $command): array
    {
        $state = (string) $cache['state'];
        $indexes = (array) $cache['indexes'];
        $checked = (int) $cache['checked_at'];

        $headline = match ($state) {
            self::CURRENT      => 'Both indexes declare every field this release writes.',
            self::BEHIND       => 'Your indexes are missing fields this release writes.',
            self::UNCONFIGURED => 'There is no index to check yet.',
            default            => 'One of your indexes could not be read.',
        };

        $detail = match ($state) {
            self::CURRENT => 'Checked against the live schemas on your Opensolr account. Nothing to do '
                . 'until the next release changes the schema, at which point this card says so.',
            self::BEHIND => 'Solr accepts documents carrying a field its schema does not declare and '
                . 'throws the value away, with no error anywhere, so this does not show up as a failure '
                . '— it shows up as a facet that is permanently empty. Push this release\'s configsets '
                . 'to fix it; it is additive and it does not touch a document already in the index.',
            self::UNCONFIGURED => 'Finish setup first — there is no index name in the configuration.',
            default => 'A schema that cannot be read is never reported as matching. Run the check again; '
                . 'if it keeps failing, confirm the account still owns both indexes.',
        };

        return [
            'state'      => $state,
            'severity'   => match ($state) {
                self::CURRENT => 'good',
                self::BEHIND  => 'bad',
                default       => 'warn',
            },
            'headline'   => $headline,
            'detail'     => $detail,
            'checked_at' => $checked,
            'command'    => $command,
            'indexes'    => $indexes,
        ];
    }

    /**
     * What the upload markers alone can say, when no check describes this release.
     *
     * @return array<string,mixed>
     */
    private static function noticeFromMarkers(Config $cfg, string $root, string $release, string $command): array
    {
        $matched = 0;
        $seen = 0;
        foreach (self::ROLES as $role) {
            $marker = self::recordedRelease($cfg, $role);
            if ($marker === '') {
                continue;
            }
            $seen++;
            if ($marker === self::releaseFor($root, $role)) {
                $matched++;
            }
        }

        if ($seen === count(self::ROLES) && $matched === $seen) {
            return [
                'state'      => self::PUSHED,
                'severity'   => 'good',
                'headline'   => 'Both configsets were last set up by a release expecting these same fields.',
                'detail'     => 'That is evidence, not a verification: it says what this installation '
                    . 'last uploaded or last confirmed, not what the indexes are running now. Run the '
                    . 'check to compare against the live schemas — and run it after every upgrade.',
                'checked_at' => null,
                'command'    => $command,
                'indexes'    => [],
            ];
        }

        if ($seen > 0) {
            return [
                'state'      => self::DRIFTED,
                'severity'   => 'bad',
                'headline'   => 'These indexes were configured by a release that expected different fields.',
                'detail'     => 'The configsets on your indexes were last uploaded by a version of '
                    . 'Loghound whose schema declared a different set of fields from the one running '
                    . 'here. Fields this release writes may be missing, and a missing field is '
                    . 'discarded silently by Solr rather than refused. Check it, and push the '
                    . 'configsets if it says they are behind.',
                'checked_at' => null,
                'command'    => $command,
                'indexes'    => [],
            ];
        }

        return [
            'state'      => self::UNVERIFIED,
            'severity'   => 'warn',
            'headline'   => 'The live schemas have never been checked from this installation.',
            'detail'     => 'Loghound has not compared the fields this release writes against the '
                . 'schemas your two indexes are actually running. It is one read per index and it '
                . 'changes nothing. Do it after every upgrade: a release that adds a field to an index '
                . 'that does not declare it loses every one of those values, silently.',
            'checked_at' => null,
            'command'    => $command,
            'indexes'    => [],
        ];
    }

    /**
     * The panel's check, as the stepped job the Settings card starts.
     *
     * A job rather than a page-load read for the reason stated at the top of this file: it is
     * two control-plane round trips, each of which can be slow or hang, and a settings page
     * that waits on the network is a settings page that eventually does not render at all.
     *
     * The last step writes the cache, so the card the operator returns to shows the result
     * without asking again. Field names travel back to the browser in the step notes, which is
     * safe: both sides of the comparison are filtered through Storage::schemaFieldNames() to
     * the platform's own field-name alphabet, and no credential is ever in a job's context.
     *
     * @return array<int,array{label:string,run:callable}>
     */
    public static function checkPlan(string $root): array
    {
        return [
            [
                'label' => 'Reading the schemas your indexes are running',
                'run'   => static function (array $ctx, Config $cfg, $gw) use ($root): array {
                    $report = self::inspect($cfg, $root);
                    $behind = 0;
                    foreach ($report['indexes'] as $row) {
                        $behind += count((array) $row['missing']);
                    }

                    return [
                        'note'    => $report['state'] === self::CURRENT
                            ? 'both up to date'
                            : $report['state'],
                        'detail'  => self::summary($report),
                        'context' => ['report' => $report, 'missing_total' => $behind],
                    ];
                },
            ],
            [
                'label' => 'Saving the result',
                'run'   => static function (array $ctx, Config $cfg, $gw) use ($root): array {
                    $report = is_array($ctx['report'] ?? null) ? $ctx['report'] : self::inspect($cfg, $root);
                    $path = self::writeCache($cfg, $report);

                    return [
                        'note'   => $path === null ? 'not saved' : 'saved',
                        'detail' => $path === null
                            ? 'The result could not be written to var/, so this card will ask you to '
                                . 'check again next time. The verdict above still stands.'
                            : 'Reload this page to see the verdict on the card above.',
                    ];
                },
            ],
        ];
    }

    /**
     * One paragraph describing a whole report, for a job note and for the command's output.
     *
     * @param array<string,mixed> $report
     */
    public static function summary(array $report): string
    {
        $lines = [];
        foreach ((array) ($report['indexes'] ?? []) as $row) {
            $lines[] = (string) ($row['message'] ?? '');
        }
        return implode(' ', array_filter($lines));
    }

    /**
     * The worst state in a list, so two indexes reduce to one verdict.
     *
     * Worst wins, always. One unreadable index makes the installation unverified even when the
     * other is perfect, because the question an operator is asking is "is my data landing", and
     * half an answer to that is no answer.
     *
     * @param array<int,string> $states
     */
    public static function worst(array $states): string
    {
        foreach (self::SEVERITY as $candidate) {
            if (in_array($candidate, $states, true)) {
                return $candidate;
            }
        }
        return self::CURRENT;
    }

    /**
     * A bounded, readable list of field names for a message.
     *
     * @param string[] $names
     */
    public static function namedList(array $names, int $limit = 8): string
    {
        $shown = array_slice($names, 0, $limit);
        $rest = count($names) - count($shown);
        return implode(', ', $shown) . ($rest > 0 ? ' and ' . $rest . ' more' : '');
    }

    /**
     * Accept only the two roles that exist.
     *
     * The value reaches a filesystem path and a configuration key, so it is checked against a
     * closed list rather than sanitised — there are exactly two of them and there will not be a
     * third without a code change that comes past here.
     *
     * @throws \InvalidArgumentException
     */
    private static function role(string $role): string
    {
        if (!in_array($role, self::ROLES, true)) {
            throw new \InvalidArgumentException('Loghound: unknown index role: ' . $role);
        }
        return $role;
    }
}
