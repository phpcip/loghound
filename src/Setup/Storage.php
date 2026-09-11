<?php
/**
 * Loghound — where the index lives (SPEC §9).
 *
 * This is the centre of setup, and the one screen an operator must not have to read
 * documentation to get through. There is exactly one answer to "where should the index
 * live?": you give Loghound your Opensolr account email and API key, and it creates,
 * configures and verifies the two indexes for you.
 *
 * WHY THERE IS NO "POINT IT AT MY OWN SOLR" OPTION
 *
 * There used to be one, and it was removed. Loghound does not merely read and write two
 * indexes — it OWNS them: it creates them, uploads the configsets under solr/hits/conf and
 * solr/sessions/conf, reloads the cores, verifies they answer, and later reports and trims
 * them against the account's plan. None of that is possible on a Solr somebody else
 * administers, where Loghound has no route to create a core or install a configset and no way
 * to keep the schema right. Offering the option therefore promised something the product
 * could not deliver, and the failure surfaced late — after ingestion had begun against a
 * schema nobody had checked. An Opensolr account is now a hard requirement.
 *
 * This class ends at the configuration keys the rest of the product reads, which is what makes
 * the browser installer and `bin/loghound-setup` interchangeable:
 *
 *     solr.mode  solr.hits_core  solr.sessions_core  solr.install_id
 *     solr.base_url  solr.http_user  solr.http_pass
 *     opensolr.email  opensolr.api_key  opensolr.region
 *
 * `solr.base_url`, `solr.http_user` and `solr.http_pass` are still real keys and still
 * required: fetchConnection() fills them in from Opensolr::connectionDetails(), and
 * src/Solr.php remains mode-agnostic — it talks to a node it has credentials for and does not
 * care how they got there. What went away is the door that let a caller supply them.
 *
 * THE INDEX NAMES ARE GENERATED, NEVER TYPED
 *
 * An Opensolr index name is unique across the WHOLE PLATFORM — not per account — and is
 * permanent once created. A fixed `loghound_hits` would therefore work for exactly one
 * person on earth and collide for everybody after them. Every installation gets a random
 * id from Config::newInstallId() and its names from Config::coreName(); a collision with
 * an index somebody else holds is retried with a completely fresh id, and any index created
 * during the failed attempt is deleted first so nobody is billed for an orphan.
 *
 * A name taken by an index THIS account already holds is a different case and is reused
 * rather than abandoned, because a failed attempt leaves exactly that: the id is persisted,
 * the names are derived from it, and a retry re-derives them. See createOne().
 *
 * THE API KEY
 *
 * It comes from what the operator types, and from nowhere else: no default, no pre-filled
 * value, no environment variable, no fallback account. It is written straight into
 * config/loghound.php (mode 0640, outside the document root) and is never rendered back
 * into a page, a hidden field, a job file, a session, a log line or an error message.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Setup;

use Loghound\Config;
use Loghound\Opensolr;
use Loghound\Security;
use Loghound\Solr;

final class Storage
{
    /**
     * Per-request network timeout for setup traffic, in seconds.
     *
     * Deliberately short and explicit. A control-plane call that hangs must fail with a
     * message the operator can act on, not sit there until the gateway kills PHP.
     */
    public const NET_TIMEOUT = 25;

    /**
     * The Opensolr pages setup links to, in one place because two front ends link to them.
     *
     * A link, never a description of where to click: only the operator's own account page
     * knows what their plan looks like, and a sentence explaining which menu to open is
     * wrong the moment the platform moves a menu.
     */
    public const URL_REGISTER = 'https://opensolr.com/register';

    public const URL_LOGIN = 'https://opensolr.com/users/login';

    public const URL_PLANS = 'https://opensolr.com/solr-hosting';

    public const URL_INDEXES = 'https://opensolr.com/solr_manager/admin';

    /**
     * Turn a control-plane failure into a sentence with a next action in it.
     *
     * EVERY PATH OUT OF THE CONTROL PLANE COMES THROUGH HERE. It used to be applied to the
     * create_index refusal alone, so the very first thing an operator with a mistyped key
     * saw was `Opensolr: HTTP 403 from regions: ERROR_AUTHENTICATION_FAILED` — a sentence
     * that names a transport, an endpoint and a platform constant, and tells them nothing
     * they can do. The platform's codes are stable, few, and worth translating once.
     *
     * The raw text is NOT appended to a translated sentence. A message that has been
     * recognised is complete; pasting the constant after it only invites the operator to
     * search for a string that means nothing outside the platform's own source.
     *
     * An unrecognised failure keeps its text, because a message nobody has translated yet is
     * still the only evidence there is — but it is passed through the same credential
     * scrubbing as everything else on its way out.
     *
     * Classification runs on a copy with the credential parameters DELETED, not merely
     * redacted. The platform echoes the request back in some error bodies, and a body carrying
     * `api_key=…` would otherwise match the authentication branch on the parameter name alone,
     * turning any echoed request into "your key is wrong" — a confident wrong diagnosis, which
     * is the most expensive kind.
     */
    public static function explainApi(string $raw): string
    {
        $raw = self::scrub($raw);

        $probe = (string) preg_replace(
            '/\b(api_key|apikey|password|passwd|token|secret)=\S*/i',
            '',
            $raw
        );
        $upper = strtoupper($probe);

        if (preg_match('/CANNOT_ADD_MORE_THAN_(\d{1,6})_CORES/', $upper, $m) === 1) {
            return 'Your Opensolr plan allows ' . (int) $m[1] . ' '
                . ((int) $m[1] === 1 ? 'index' : 'indexes') . ', and they are all in use, so no '
                . 'more can be created. Reuse a pair of Loghound indexes this account already '
                . 'has, delete an index you no longer need, or move to a larger plan.';
        }
        if (str_contains($upper, 'AUTHENTICATION_FAILED')
            || str_contains($upper, 'INVALID_API_KEY')
            || str_contains($upper, 'INVALID_USER')) {
            return 'Opensolr did not accept this email address and API key. Check both in your '
                . 'Opensolr control panel under Account — the key is a single line of letters and '
                . 'digits, and it is bound to the account the email belongs to.';
        }
        if (str_contains($upper, 'INVALID_SIGNATURE')) {
            return 'Opensolr rejected the signature on the request. That is an API key which no '
                . 'longer matches the account; issue a new one under Account and enter it again.';
        }
        if (str_contains($upper, 'CORE_NAME_TAKEN')) {
            return 'That index name is already taken somewhere on the platform. Loghound picks '
                . 'another and tries again by itself; if you are seeing this, it ran out of attempts.';
        }
        if (str_contains($upper, 'NOT_OWNER') || str_contains($upper, 'INVALID_CORE_NAME')) {
            return 'This Opensolr account does not own that index, so the platform will not act on '
                . 'it. Check the account email and API key, and that the index has not been deleted '
                . 'in the Opensolr control panel.';
        }
        if (str_contains($upper, 'WRONG_API_HOST')) {
            return 'That request went to the wrong Opensolr host. Leave opensolr.api_base at its '
                . 'default unless Opensolr has told you otherwise.';
        }
        if (str_contains($upper, 'INVALID_SERVER_COUNTRY')
            || str_contains($upper, 'SERVER_COUNTRY_DOES_NOT_EXIST')) {
            return 'Opensolr does not offer that region to this account. Choose one of the regions '
                . 'in the list, which is the list the platform returned for these credentials.';
        }
        if (str_contains($probe, 'cannot reach the control plane')) {
            return 'opensolr.com could not be reached from this server. Check that outbound HTTPS is '
                . 'allowed here, then try again — nothing has been created or changed.';
        }
        if (str_contains($probe, 'unparseable body')) {
            return 'Opensolr answered with something that is not a response Loghound understands. '
                . 'Nothing has been created; try again, and if it persists say so in your Opensolr '
                . 'control panel.';
        }

        return $raw;
    }

    /**
     * Everything the storage step needs to know about the account.
     *
     * `get_index_list` answers two of the three questions at once — which Loghound pairs exist,
     * and how many indexes are in use — and `get_account_summary` answers the third, the plan's
     * allowance. Both are asked on every visit to the step, which is what keeps the screen
     * honest when a second machine created a pair, or the operator changed plan, a minute ago.
     * Nothing about the allowance is cached: a remembered number goes stale silently, and this
     * is the number that decides whether indexes get created.
     *
     * The allowance costs an index to ask, because get_account_summary is scoped to one core
     * the account owns. An account holding NOTHING has nothing to name, so its allowance comes
     * back unknown — and unknown is reported as unknown, never as room.
     *
     * Failure is a STATE, not an exception. "The control plane is unreachable" has to be
     * shown on the storage step next to the credentials that might be wrong, and a screen
     * that cannot render because a network call failed is a screen the operator cannot use to
     * fix the network call.
     *
     * @return array{ok:bool,error:string,pairs:array<int,array{install_id:string,hits:string,sessions:string}>,
     *               halves:array<int,array{install_id:string,role:string,name:string,missing:string}>,
     *               total:int,counted:int,
     *               capacity:array{counted:int,limit:?int,needed:int,room:?int,blocked:bool,sentence:string}}
     */
    public static function account(Config $cfg, ?callable $transport = null): array
    {
        $blank = [
            'pairs'   => [],
            'halves'  => [],
            'total'   => 0,
            'counted' => 0,
        ];

        $client = self::client($cfg, $transport);

        try {
            $entries = $client->listIndexEntries();
        } catch (\Throwable $e) {
            return [
                'ok'       => false,
                'error'    => self::explainApi($e->getMessage()),
                'capacity' => Pairs::capacity(0),
            ] + $blank;
        }

        $grouped = Pairs::group($entries);
        $summary = self::allowance($client, $cfg, $entries);

        return [
            'ok'       => true,
            'error'    => '',
            'capacity' => Pairs::capacity(
                $grouped['counted'],
                $summary['index_limit'],
                $summary['indexes_used'],
                $summary['indexes_available']
            ),
        ] + $grouped;
    }

    /**
     * Ask the platform what this account's plan allows, naming an index it owns.
     *
     * get_account_summary is scoped to a single core: it wants a core name and a signature over
     * it, and it refuses one the account does not hold. So a probe has to be chosen, and the
     * order is deliberate — this installation's own hits index first, because if the account
     * holds it then it is certainly valid and certainly still there, and otherwise whatever the
     * account listed first.
     *
     * A FAILURE HERE IS NOT A FAILURE OF THE STEP. The allowance is one of three things the
     * storage screen reports and the other two came back fine; an account that cannot answer
     * this one still has pairs worth offering. Every field comes back null, which reads as
     * unknown all the way up and never blocks.
     *
     * @param array<int,array{name:string,type:string}> $entries
     * @return array{index_limit:?int,indexes_used:?int,indexes_available:?int}
     */
    private static function allowance(Opensolr $client, Config $cfg, array $entries): array
    {
        $unknown = ['index_limit' => null, 'indexes_used' => null, 'indexes_available' => null];

        $names = array_column($entries, 'name');
        if ($names === []) {
            return $unknown;
        }

        $hits  = (string) $cfg->get('solr.hits_core', '');
        $probe = in_array($hits, $names, true) ? $hits : (string) $names[0];

        try {
            $summary = $client->accountSummary($probe);
        } catch (\Throwable $e) {
            return $unknown;
        }

        if (!$summary['ok']) {
            return $unknown;
        }

        return [
            'index_limit'       => $summary['index_limit'],
            'indexes_used'      => $summary['indexes_used'],
            'indexes_available' => $summary['indexes_available'],
        ];
    }

    /** How many times a colliding index-name pair is retried with a fresh id. */
    private const MAX_NAME_ATTEMPTS = 5;

    /**
     * Test-only HTTP transport.
     *
     * The provisioning state machine — create, collide, roll back, retry with a fresh id,
     * upload, verify — is the most consequential code in setup: getting it wrong leaves
     * indexes in someone's account that they are billed for. It therefore has to be
     * testable without touching the network, and the steps build their own clients, so
     * there is nowhere to pass a transport in from the outside.
     *
     * Inert unless LOGHOUND_TEST=1 is in the environment, which only tests/run.php sets.
     * It is a seam, not a switch: production code cannot reach it.
     *
     * @var callable|null
     */
    private static $testTransport = null;

    /**
     * Install the test transport. Refuses to do anything outside the test suite.
     *
     * @param callable|null $transport fn(array $req): array{status:int,body:string,error:string}
     * @throws \RuntimeException When called anywhere but under tests/run.php.
     */
    public static function useTestTransport(?callable $transport): void
    {
        if (getenv('LOGHOUND_TEST') !== '1') {
            throw new \RuntimeException('Storage::useTestTransport() is available under tests only.');
        }
        self::$testTransport = $transport;
    }

    /**
     * The transport a client should use when the caller did not supply one.
     *
     * @param callable|null $given
     */
    private static function transport(?callable $given): ?callable
    {
        if ($given !== null) {
            return $given;
        }
        return getenv('LOGHOUND_TEST') === '1' ? self::$testTransport : null;
    }

    /**
     * Validate and store the Opensolr account credentials.
     *
     * Nothing is contacted here; this only records what was typed, so the (slow) network
     * validation can run as a job with visible progress. The key is written to the config
     * because that is the only place it is allowed to live — holding it in a session or a
     * hidden form field to "verify it first" would put it somewhere less safe.
     *
     * THE REGION IS PART OF THE ACCOUNT, so it is recorded here with the other two. It used to
     * be written by the Settings card directly while the installer set it inside a job, which
     * meant two spellings of one operation and two chances for them to diverge. Only its SHAPE
     * is checked here, because whether the account may use it is a question only the platform
     * can answer — settleRegion() asks that, immediately afterwards, on every path.
     *
     * @param string $region Blank keeps whatever is stored.
     * @return string[] Human-readable problems; empty means accepted.
     */
    public static function saveCredentials(Config $cfg, string $email, string $apiKey, string $region = ''): array
    {
        $errors = [];

        $email = trim($email);
        if ($email === '') {
            $errors[] = 'Enter the email address of your Opensolr account.';
        } elseif (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'That does not look like an email address.';
        }

        $apiKey = trim($apiKey);
        $stored = (string) $cfg->get('opensolr.api_key', '');
        if ($apiKey === '' && $stored === '') {
            $errors[] = 'Enter your Opensolr API key. You will find it under Account in your '
                . 'Opensolr control panel.';
        } elseif ($apiKey !== '' && !preg_match('/^[A-Za-z0-9_\-]{8,128}$/D', $apiKey)) {
            $errors[] = 'That API key does not look right — it should be a single line of '
                . 'letters, digits, hyphens or underscores with no spaces.';
        }

        $region = trim($region);
        if ($region !== '' && !preg_match('/^[A-Z0-9_]{2,32}$/D', $region)) {
            $errors[] = 'A region is a name like FINLAND9 — capital letters, digits and '
                . 'underscores. Leave it blank to keep the one you have.';
        }

        if ($errors !== []) {
            return $errors;
        }

        $cfg->set('solr.mode', Config::SOLR_MODE);
        $cfg->set('opensolr.email', $email);
        if ($apiKey !== '') {
            $cfg->set('opensolr.api_key', $apiKey);
        }
        if ($region !== '') {
            $cfg->set('opensolr.region', $region);
        }

        return [];
    }

    /**
     * Hold the stored region to the list the platform just returned for this account.
     *
     * A REGION THE OPERATOR TYPED IS REFUSED IF THE ACCOUNT CANNOT USE IT, and the refusal names
     * the list. A region merely carried over from an earlier run is not refused: an account can
     * legitimately stop being offered a region it once had, and turning that into a refusal would
     * block the very credential edit that fixes the account. In that case it is cleared, and the
     * caller says so.
     *
     * One implementation, because this is a refusal — and the brief every front end works to is
     * that the same condition produces the same sentence wherever the operator meets it.
     *
     * @param string[] $regions What the platform offers this account.
     * @param bool     $explicit Whether the operator typed or chose this value in THIS request.
     * @return string|null The region to store, or null when it must be refused.
     */
    public static function settleRegion(Config $cfg, array $regions, bool $explicit): ?string
    {
        $wanted = (string) $cfg->get('opensolr.region', '');

        if ($wanted === '' || in_array($wanted, $regions, true)) {
            return $wanted;
        }

        return $explicit ? null : '';
    }

    /**
     * The refusal for a region this account cannot use, naming the ones it can.
     *
     * @param string[] $regions
     */
    public static function regionRefusal(string $wanted, array $regions): string
    {
        return 'Opensolr does not offer the region "' . $wanted . '" to this account. '
            . 'It offers: ' . implode(', ', $regions) . '.';
    }

    /**
     * Build the control-plane client from the stored credentials.
     *
     * @param callable|null $transport Injected by tests so the suite never touches the network.
     */
    public static function client(Config $cfg, ?callable $transport = null): Opensolr
    {
        $section = (array) $cfg->get('opensolr', []);
        $section['timeout'] = self::NET_TIMEOUT;
        return new Opensolr($section, self::transport($transport));
    }

    /**
     * Ask the platform which regions this account may use.
     *
     * Doubles as the credential check: the endpoint needs a valid email and API key, and
     * it is the cheapest, most harmless call on the whole API — it creates nothing and
     * changes nothing.
     *
     * @return string[]
     * @throws \RuntimeException With a message safe to show; the key is redacted upstream.
     */
    public static function listRegions(Config $cfg, ?callable $transport = null): array
    {
        try {
            $regions = self::client($cfg, $transport)->listRegions();
        } catch (\Throwable $e) {
            throw new \RuntimeException(self::explainApi($e->getMessage()));
        }
        if ($regions === []) {
            throw new \RuntimeException(
                'Opensolr accepted the request but returned no regions for this account. '
                . 'Check in your Opensolr control panel that the account is active.'
            );
        }
        return $regions;
    }

    /**
     * The provisioning step list.
     *
     * Every step is small, individually named, and idempotent enough to be re-run after a
     * failure — which is what makes the "Try again" button safe.
     *
     * "Try again" does NOT resume the failed job. A failed job is no longer running, so
     * Installer::startJob() cannot reattach to it and creates a fresh one, whose step states
     * are all pending. Every step therefore runs again from the top. That is safe only
     * because each one is idempotent against work an earlier attempt already did:
     * checkCredentials() only reads, createOne() reuses an index this account already holds
     * under this installation's id, fetchConnection() re-reads the connection details,
     * pushConfigset() re-uploads and reloads, and verifyCore() only queries.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function opensolrSteps(Job $job, Config $cfg, string $root): array
    {
        $region = (string) ($job->params()['region'] ?? '');

        return [
            [
                'key'   => 'verify',
                'label' => 'Checking your Opensolr credentials',
                'run'   => static fn(Job $j, Config $c): string => self::checkCredentials($j, $c, $region),
            ],

            [
                'key'   => 'capacity',
                'label' => 'Checking your plan has room for two indexes',
                'run'   => static fn(Job $j, Config $c): string => self::checkCapacity($j, $c),
            ],

            [
                'key'   => 'create_hits',
                'label' => 'Creating the hits index',
                'run'   => static function (Job $j, Config $c) use ($region): array|string {
                    return self::createOne($j, $c, $region, 'hits');
                },
            ],

            [
                'key'   => 'create_sessions',
                'label' => 'Creating the sessions index',
                'run'   => static function (Job $j, Config $c) use ($region): array|string {
                    return self::createOne($j, $c, $region, 'sessions');
                },
            ],

            [
                'key'   => 'connect',
                'label' => 'Fetching the connection details',
                'run'   => static fn(Job $j, Config $c): string => self::fetchConnection($j, $c),
            ],

            [
                'key'   => 'schema_hits',
                'label' => 'Uploading the hits schema',
                'run'   => static function (Job $j, Config $c) use ($root): string {
                    return self::pushConfigset(
                        $j,
                        $c,
                        (string) $c->get('solr.hits_core'),
                        $root . '/solr/hits/conf',
                        'hits'
                    );
                },
            ],

            [
                'key'   => 'schema_sessions',
                'label' => 'Uploading the sessions schema',
                'run'   => static function (Job $j, Config $c) use ($root): string {
                    return self::pushConfigset(
                        $j,
                        $c,
                        (string) $c->get('solr.sessions_core'),
                        $root . '/solr/sessions/conf',
                        'sessions'
                    );
                },
            ],

            [
                'key'   => 'verify_hits',
                'label' => 'Verifying the hits index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.hits_core'));
                },
            ],

            [
                'key'   => 'verify_sessions',
                'label' => 'Verifying the sessions index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.sessions_core'));
                },
            ],
        ];
    }

    /**
     * Adopt a pair of indexes this account already holds.
     *
     * REUSE IS JOINING, NOT TAKING OVER. Every step here either reads or writes the local
     * configuration; not one of them creates, clears, reshapes or reloads an index. That is
     * the whole contract: the pair may hold another site's traffic, and this installation is
     * about to add its own alongside it, told apart by the hostname on every document.
     *
     * The schema steps are the exception that proves it. They compare what the index HAS
     * against what this version WRITES, and on a mismatch they stop — unless the operator has
     * explicitly agreed to the upgrade, in which case the configset is pushed and that is
     * said plainly. Writing into a shape that does not match is the one way reuse could
     * silently lose data, so it is the one thing that cannot happen by default.
     *
     * The steps mirror opensolrSteps() in name and order wherever they do the same work, so
     * an operator who has seen one recognises the other, and both front ends render them from
     * the same list.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function reuseSteps(Job $job, Config $cfg, string $root): array
    {
        $params    = $job->params();
        $installId = (string) ($params['install_id'] ?? '');
        $upgrade   = !empty($params['upgrade_schema']);

        return [
            [
                'key'   => 'verify',
                'label' => 'Checking your Opensolr credentials',
                'run'   => static fn(Job $j, Config $c): string => self::checkCredentials($j, $c, ''),
            ],

            [
                'key'   => 'adopt',
                'label' => 'Confirming the indexes are still on your account',
                'run'   => static function (Job $j, Config $c) use ($installId): string {
                    return self::adoptPair($j, $c, $installId);
                },
            ],

            [
                'key'   => 'connect',
                'label' => 'Fetching the connection details',
                'run'   => static fn(Job $j, Config $c): string => self::fetchConnection($j, $c),
            ],

            [
                'key'   => 'schema_hits',
                'label' => 'Checking the hits index has the shape this version writes',
                'run'   => static function (Job $j, Config $c) use ($root, $upgrade): string {
                    return self::reconcileSchema($j, $c, 'hits', $root, $upgrade);
                },
            ],

            [
                'key'   => 'schema_sessions',
                'label' => 'Checking the sessions index has the shape this version writes',
                'run'   => static function (Job $j, Config $c) use ($root, $upgrade): string {
                    return self::reconcileSchema($j, $c, 'sessions', $root, $upgrade);
                },
            ],

            [
                'key'   => 'verify_hits',
                'label' => 'Verifying the hits index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.hits_core'));
                },
            ],

            [
                'key'   => 'verify_sessions',
                'label' => 'Verifying the sessions index answers',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.sessions_core'));
                },
            ],
        ];
    }

    /**
     * Point this installation at an existing pair, after proving the pair is really there.
     *
     * The installation id arrives from a form field or a shell argument, and a pair of index
     * names built from an unchecked id is a pair of names this installation would then write
     * documents into. So the account is asked what it holds and the id is matched against
     * that answer — nothing is adoptable that the platform did not just confirm.
     *
     * ADOPTING TAKES THE PAIR'S CORE NAMES AND NOTHING ELSE. `solr.install_id` stays this
     * machine's own, and a machine that has none gets a fresh one here — it is NOT set to the id
     * embedded in the pair's names, and that distinction is load-bearing rather than tidy.
     *
     * The id is the per-installation salt in a hit's document id: `sha1(install_id \0 src:offset)`.
     * Two machines both tailing /var/log/apache2/access.log produce identical `src:offset` pairs,
     * so with a shared pair of indexes and a shared id every document one wrote would silently
     * overwrite the other's — the same byte offset in the same filename is the same id. Copying
     * the pair's id in here would reintroduce exactly that, and reuse is the feature that makes
     * it reachable. The id also scopes `install_s` and retention, so two installations sharing
     * one pair have to stay distinguishable by it.
     *
     * Which pair an installation is using is not lost by this: it is written in the core names,
     * and Pairs::parse() reads it back out of them.
     *
     * @throws \RuntimeException When the pair is not on the account.
     */
    private static function adoptPair(Job $job, Config $cfg, string $installId): string
    {
        $job->note('Asking Opensolr which Loghound indexes this account holds …');

        $account = self::account($cfg);
        if (!$account['ok']) {
            throw new \RuntimeException($account['error']);
        }

        $pair = Pairs::find($account['pairs'], $installId);
        if ($pair === null) {
            throw new \RuntimeException(
                'That pair of indexes is no longer on this Opensolr account. It may have been '
                . 'deleted, or these credentials may belong to a different account. Go back a step '
                . 'and choose from the list again.'
            );
        }

        if ((string) $cfg->get('solr.install_id', '') === '') {
            $cfg->set('solr.install_id', Config::newInstallId());
        }
        $cfg->set('solr.hits_core', $pair['hits']);
        $cfg->set('solr.sessions_core', $pair['sessions']);
        self::persist($cfg);

        return 'Using ' . $pair['hits'] . ' and ' . $pair['sessions'] . '.';
    }

    /**
     * Does this index have the shape this version of Loghound writes, and what if not?
     *
     * HOW THE COMPARISON IS MADE, and why it is not a version number. The control plane will
     * hand back a managed index's own configset file, so the schema the index is actually
     * running is compared against the schema in this checkout, field by field. That is exact
     * and it needs nothing kept in step by hand: a version marker has to be remembered and
     * bumped by whoever edits the schema, and the day somebody forgets is the day this check
     * says yes to an index it should have refused.
     *
     * What counts as a mismatch is one-directional on purpose. A field this version writes
     * and the index does not have is a mismatch — the value would be dropped or refused, and
     * either way the data is lost. A field the index has and this version does not write is
     * NOT a mismatch: that is a newer schema, or another product's, and it costs nothing.
     *
     * A schema that cannot be read at all is reported as exactly that and stops the step. It
     * is not treated as "probably fine": the entire point of the check is the case where
     * assuming fine is expensive.
     *
     * Either outcome that ends with the index in the right shape — nothing missing, or the
     * configset pushed — records `solr.schema_release` for that role, because both of them
     * established the same fact. See Schema::notice() for what the panel does with it, and
     * bin/loghound-schema for the same comparison made outside a setup job, which is what an
     * operator upgrading an existing installation runs.
     *
     * @param string $role     'hits' or 'sessions'
     * @param bool   $upgrade  Whether the operator agreed to push this version's configset.
     * @throws \RuntimeException On a mismatch the operator has not agreed to fix.
     */
    private static function reconcileSchema(Job $job, Config $cfg, string $role, string $root, bool $upgrade): string
    {
        $core = (string) $cfg->get($role === 'hits' ? 'solr.hits_core' : 'solr.sessions_core', '');
        if ($core === '') {
            throw new \RuntimeException('The index name is missing — the previous step did not finish.');
        }

        $localPath = rtrim($root, '/') . '/solr/' . $role . '/conf/managed-schema.xml';
        $localXml  = @file_get_contents($localPath);
        if (!is_string($localXml) || $localXml === '') {
            throw new \RuntimeException('The schema is missing from this checkout: ' . $localPath);
        }

        $job->note('Reading the schema ' . $core . ' is running …');
        $liveXml = self::client($cfg)->fetchConfigFile($core, 'managed-schema', 'xml');

        if ($liveXml === null || self::schemaFieldNames($liveXml) === []) {
            throw new \RuntimeException(
                'Opensolr would not hand back a readable schema for ' . $core . ', so Loghound '
                . 'cannot tell whether it has the shape this version writes — and it will not write '
                . 'into an index it has not checked. Try again; if it keeps happening, create a new '
                . 'pair of indexes instead of reusing this one.'
            );
        }

        $missing = self::schemaShortfall($localXml, $liveXml);

        if ($missing === []) {
            Schema::recordRelease($cfg, $role, rtrim($root, '/'));
            return $core . ' already has every field this version writes.';
        }

        $named = implode(', ', array_slice($missing, 0, 8))
            . (count($missing) > 8 ? ' and ' . (count($missing) - 8) . ' more' : '');

        if (!$upgrade) {
            throw new \RuntimeException(
                $core . ' was created by an older version of Loghound: it is missing '
                . count($missing) . ' of the fields this version writes (' . $named . '). Nothing '
                . 'has been changed. Go back a step and tick "update the schema on these indexes" '
                . 'to add the missing fields — that is additive and it does not touch a single '
                . 'document already in there — or choose a different pair, or create a new one.'
            );
        }

        $job->note('Adding the missing fields to ' . $core . ' …');
        $pushed = self::pushConfigset($job, $cfg, $core, rtrim($root, '/') . '/solr/' . $role . '/conf', $role);

        return 'Added ' . count($missing) . ' missing field'
            . (count($missing) === 1 ? '' : 's') . ' to ' . $core . '. ' . $pushed;
    }

    /**
     * The fields this version writes that an index does not have.
     *
     * Both schemas are read with a regular expression rather than an XML parser, deliberately.
     * The live document is bytes from a remote service, and handing those to an XML parser is
     * how a setup step acquires an entity-expansion bug; matching two attribute shapes needs
     * none of that power. Names outside the platform's own field-name alphabet are ignored on
     * both sides, so nothing that could not be a real field reaches a comparison or a message.
     *
     * Dynamic fields are compared alongside static ones and by their pattern, because a
     * dynamic field is exactly what makes a missing static field silent: with `*_s` present,
     * an index accepts a field it was never told about and the mismatch surfaces as a value
     * nobody can search rather than as an error.
     *
     * @return string[] Field names, in the order the local schema declares them.
     */
    public static function schemaShortfall(string $localXml, string $liveXml): array
    {
        $live = self::schemaFieldNames($liveXml);

        $missing = [];
        foreach (self::schemaFieldNames($localXml) as $name) {
            if (!in_array($name, $live, true)) {
                $missing[] = $name;
            }
        }
        return $missing;
    }

    /**
     * Every field and dynamic-field name a managed schema declares.
     *
     * A schema that yields NONE is not an empty schema — there is no such thing — it is a
     * document that is not a managed schema: an error page, a truncated transfer, a file the
     * node handed back from somewhere else. Callers check for the empty array and treat it as
     * "could not be read", which is the only safe reading and the opposite of the one a naive
     * comparison would reach, since an empty live schema makes every local field look missing
     * and an empty local one makes every index look fine.
     *
     * @return string[] In declaration order, without duplicates.
     */
    public static function schemaFieldNames(string $xml): array
    {
        if (preg_match_all(
            '/<(?:field|dynamicField)\s[^>]*\bname\s*=\s*"([A-Za-z0-9_*.\-]{1,128})"/i',
            $xml,
            $m
        ) < 1) {
            return [];
        }

        /* THE LIST IS BOUNDED, because the XML it came from is a control-plane response and a
           schema is not a stream. Every name that comes back is compared against the local set
           in a nested loop, diffed, written into var/schema-check.json and re-read by the panel
           on every Settings render, so an answer with a million field declarations in it is a
           million-element array doing all four of those things. Two thousand is an order of
           magnitude more than either of this product's schemas declares; past it the comparison
           is meaningless anyway and the honest answer is the one the caller already handles. */
        $names = array_values(array_unique($m[1]));
        return count($names) > self::MAX_SCHEMA_FIELDS ? [] : $names;
    }

    /**
     * Most field names a live schema may declare before it is treated as unreadable.
     *
     * Returning the empty list rather than a truncated one is deliberate and is the same
     * choice the surrounding docblock makes for a schema that could not be parsed: a partial
     * field list makes every absent name look missing, and the caller reports "could not be
     * read", which is the only safe reading.
     */
    public const MAX_SCHEMA_FIELDS = 2000;

    /**
     * Prove the stored credentials work, and that the chosen region exists on this account.
     *
     * Listing regions is the cheapest and most harmless authenticated call the control
     * plane offers: it creates nothing, changes nothing, and fails loudly on a bad email
     * or API key. Doing it as the first provisioning step is what stops a mistyped key
     * from surfacing three screens later, halfway through creating billable indexes.
     *
     * AN EMPTY REGION IS WHAT THE REUSE PATH PASSES: adopting indexes that already exist asks
     * no region question, because they are already wherever they were created. Writing that
     * empty value through would erase the region a previous provisioning run stored, so
     * `opensolr.region` is only ever moved by a step that actually chose one.
     *
     * @throws \RuntimeException When the credentials are refused or the region is not offered.
     */
    private static function checkCredentials(Job $job, Config $cfg, string $region): string
    {
        $job->note('Contacting opensolr.com …');
        $regions = self::listRegions($cfg);
        $job->setResult('regions', $regions);

        if ($region !== '' && !in_array($region, $regions, true)) {
            throw new \RuntimeException(self::regionRefusal($region, $regions));
        }

        if ($region !== '') {
            $cfg->set('opensolr.region', $region);
            self::persist($cfg);

            return 'Credentials accepted; region ' . $region . ' is available.';
        }

        return 'Credentials accepted.';
    }

    /**
     * Refuse to start creating indexes the account has no room for.
     *
     * THIS IS THE STEP THE WHOLE ORDERING EXISTS FOR. Provisioning creates two indexes, and
     * discovering the plan is full between the first and the second leaves one index in the
     * account, unreferenced by any configuration and billed for, with an error message that
     * explains none of it. So the count is read from the platform BEFORE the first create,
     * and when the limit is known the step refuses outright and nothing is touched.
     *
     * When the limit is NOT known — the platform publishes an account's index allowance
     * nowhere, and it has not yet refused a create on this installation, so no number exists
     * to check against — this step still does real work: it states the usage it did read,
     * and it leaves the guarantee to createOne(), which rolls the first index back if the
     * second is the one refused. A check that cannot be made is said out loud rather than
     * skipped silently.
     *
     * The check is not a promise either way, and that is deliberate rather than a gap:
     * another machine or another browser tab can take the last slot between this step and
     * the create two steps later. The rollback is what makes that safe; this step is what
     * makes it rare and what makes it explainable.
     *
     * @throws \RuntimeException When the plan is known to be too small.
     */
    private static function checkCapacity(Job $job, Config $cfg): string
    {
        $job->note('Asking Opensolr what this account already holds …');

        $account = self::account($cfg);
        if (!$account['ok']) {
            throw new \RuntimeException($account['error']);
        }

        $capacity = $account['capacity'];

        if ($capacity['blocked']) {
            throw new \RuntimeException(
                $capacity['sentence'] . ' ' . self::waysForwardSentence($account['pairs'] !== [])
            );
        }

        if ($account['halves'] !== []) {
            foreach ($account['halves'] as $half) {
                $job->note(
                    'Note: ' . $half['name'] . ' is on this account without its matching '
                    . $half['missing'] . ', which is what a setup run that stopped half way leaves '
                    . 'behind. It still counts against the plan.'
                );
            }
        }

        return $capacity['sentence'];
    }

    /**
     * The ways out of a full plan, as one sentence for a place that has only a sentence.
     *
     * The same three routes Pairs::waysForward() lists for a screen that can render links,
     * flattened for the shell and for a job note. The URLs are spelled out rather than
     * described, so the line stays useful when it is read out of a log file.
     */
    public static function waysForwardSentence(bool $haveReusable): string
    {
        $text = $haveReusable
            ? 'This account already holds a pair of Loghound indexes, and reusing it creates '
                . 'nothing — go back a step and choose it. '
            : '';

        return $text . 'Otherwise delete an index you no longer need at ' . self::URL_INDEXES
            . ', or move to a plan that allows more at ' . self::URL_PLANS . '.';
    }

    /**
     * Ask the platform where the new indexes live, and store the answer.
     *
     * This is how managed mode fills in solr.base_url, solr.http_user and solr.http_pass,
     * after which src/Solr.php is mode-agnostic and simply talks to a node it has
     * credentials for.
     *
     * Opensolr::connectionDetails() returns the keys `base_url`, `http_user` and
     * `http_pass`. Reading `user`/`pass` instead — the obvious guess — silently yields
     * empty credentials and a later HTTP 401 that is miserable to trace back to here.
     *
     * The returned progress line names the HOST only. The credentials that came back in
     * the same response are written to the configuration and never rendered.
     *
     * THIS IS ALSO WHERE "INDEXES NOT CHOSEN YET" STOPS BEING TRUE, for both provisioning and
     * reuse, and it is the only place that clears Pairs::PENDING_KEY. The flag is a claim about
     * ownership, so it may only be dropped on proof of ownership — and the proof is right here:
     * the control plane has just returned connection details for solr.hits_core, which it does
     * not do for an index the account does not hold. Clearing it any earlier would be clearing
     * it on an intention.
     *
     * @throws \RuntimeException When the platform has no connection URL for the index.
     */
    private static function fetchConnection(Job $job, Config $cfg): string
    {
        $hits = (string) $cfg->get('solr.hits_core', '');
        $job->note('Asking where ' . $hits . ' lives …');

        $conn = self::client($cfg)->connectionDetails($hits);

        /* THE PLATFORM'S ANSWER IS VALIDATED BEFORE IT BECOMES THE PLACE WE SEND A PASSWORD.
           `base_url` here is a raw read of `msg.info.connection_url` out of a control-plane
           response, and the next two lines store the Solr HTTP credentials beside it. Every
           later probe builds a Solr client from that config and sends those credentials as
           Basic auth to whatever host the string named — so a compromised control plane, a
           MITM, or an `opensolr.api_base` pointed at somebody else's host returns
           `http://attacker/solr/x` and the next connection test hands over the Solr password.
           It is a standing SSRF primitive out of the panel process as well.

           src/Solr.php asserts that "base_url is operator configuration and is validated where
           it is stored". On this path it was neither operator configuration nor validated.
           Security::safeOutboundUrl() is the same check opensolr.api_base and the geolocation
           endpoint now get: https, a public host, no embedded credentials. */
        if (Security::safeOutboundUrl((string) $conn['base_url']) === null) {
            throw new \RuntimeException(
                'Opensolr gave a connection URL for ' . $hits . ' that this installation will not '
                . 'use: it has to be an https URL on a public host with no credentials in it. '
                . 'Nothing has been saved.'
            );
        }

        $cfg->set('solr.base_url', $conn['base_url']);
        $cfg->set('solr.http_user', $conn['http_user']);
        $cfg->set('solr.http_pass', $conn['http_pass']);
        Pairs::clearPending($cfg);
        self::persist($cfg);

        $host = (string) parse_url($conn['base_url'], PHP_URL_HOST);

        return 'Your indexes are on ' . ($host !== '' ? $host : 'the Opensolr platform') . '.';
    }

    /**
     * Create one of the two indexes, handling the platform-wide name collision.
     *
     * Returns a `goto` instruction rather than throwing when the name is taken: the job
     * rewinds to `create_hits` with a brand-new installation id, because the pair must
     * share one id to be recognisable as a pair in an account holding hundreds of indexes.
     *
     * A NAME THAT IS TAKEN IS NOT NECESSARILY SOMEBODY ELSE'S. `solr.install_id` is
     * persisted, and the two names are derived from it, so an attempt that created an index
     * and then failed at a later step leaves a name that THIS account already holds. Pressing
     * "Try again" starts a fresh job, and a fresh job's result is empty — so the in-job reuse
     * check below cannot see the earlier attempt at all. Treating that as a stranger's name
     * and rewinding with a new id abandons an index the account is billed for, silently, once
     * per retry. Ownership is therefore established against the platform rather than against
     * this job's memory: accountOwns() answers the question the job result cannot.
     *
     * @param string $role 'hits' or 'sessions'
     * @return array{goto:string,detail:string}|string
     */
    private static function createOne(Job $job, Config $cfg, string $region, string $role): array|string
    {
        $installId = (string) $cfg->get('solr.install_id', '');
        if ($installId === '') {
            $installId = Config::newInstallId();
            $cfg->set('solr.install_id', $installId);
        }

        $key  = $role === 'hits' ? 'solr.hits_core' : 'solr.sessions_core';
        $name = Config::coreName($installId, $role);
        $cfg->set($key, $name);
        self::persist($cfg);

        $job->note('Creating index ' . $name . ' …');
        $res = self::client($cfg)->createIndex($name, $region);

        if (!empty($res['status'])) {
            $job->setResult($role, $name);
            $job->setResult('install_id', $installId);
            return 'Created ' . $name . '.';
        }

        if (!Opensolr::isNameTaken($res)) {
            $atLimit = Opensolr::isAtIndexLimit($res);
            self::abandonAttempt($job, $cfg, $role);
            throw new \RuntimeException(
                $atLimit ? self::limitRefusal($cfg) : self::readableApiError($res)
            );
        }

        if (($job->result()[$role] ?? null) === $name || self::accountOwns($cfg, $name)) {
            $job->setResult($role, $name);
            $job->setResult('install_id', $installId);
            return 'Index ' . $name . ' already exists from an earlier attempt — reusing it.';
        }

        $attempt = $job->nextAttempt();
        if ($attempt >= self::MAX_NAME_ATTEMPTS) {
            throw new \RuntimeException(
                'Could not find a free index name after ' . $attempt . ' attempts. '
                . 'That is unusual — try again, and if it persists say so in your Opensolr control panel.'
            );
        }

        $job->note('The name ' . $name . ' is already taken on the platform; choosing another.');

        self::abandonAttempt($job, $cfg, $role);

        $cfg->set('solr.install_id', Config::newInstallId());
        $cfg->set('solr.hits_core', '');
        $cfg->set('solr.sessions_core', '');
        self::persist($cfg);

        return ['goto' => 'create_hits', 'detail' => 'Name taken; retrying with a new id.'];
    }

    /**
     * The plan-is-full refusal, when it arrives DESPITE the check meant to prevent it.
     *
     * Reaching here means the capacity step read the allowance, found room, and the platform
     * refused anyway — the race a check cannot win, because another session or another machine
     * can take the last slot in between. It is rare, it is not the operator's mistake, and
     * saying so is better than a message implying they were told wrong.
     *
     * The account is re-read so the numbers quoted are true NOW, after the rollback has given
     * the orphan back — which is what the operator will see if they go and look. That read also
     * says whether there is actually a Loghound pair to reuse, which is what stops the message
     * offering a way out that does not apply. A read that fails does not replace the message;
     * the generic routes are a reasonable fallback.
     */
    private static function limitRefusal(Config $cfg): string
    {
        $account = self::account($cfg);

        $text = 'Opensolr refused the second index because the plan is full. Loghound checked before '
            . 'it started and there was room then, so something else on this account took the last '
            . 'slot in between. Nothing has been left behind. ';

        if ($account['ok']) {
            $text .= $account['capacity']['sentence'] . ' ';
        }

        return $text . self::waysForwardSentence($account['ok'] && $account['pairs'] !== []);
    }

    /**
     * Give back whatever this attempt created before it failed.
     *
     * THE HALF-WAY FAILURE, HANDLED WHATEVER CAUSED IT. Creating the sessions index is the
     * second of two creates, and everything that can refuse it — a plan that filled up
     * between the two calls, a region that went down, a key revoked mid-install, a name
     * collision — leaves the hits index sitting in the account with nothing pointing at it.
     * It used to be deleted on exactly one of those, the name collision, and left behind on
     * all the others: the rollback lived inside the collision branch, while every other
     * refusal threw straight past it. That is the orphan an operator gets billed for and
     * never hears about.
     *
     * So the rollback is here, is called from both exits, and cares only about what was
     * created — not about why the attempt is being abandoned.
     *
     * Best effort, and loudly so. If the delete itself fails the operator is told the name
     * and where to remove it, because the alternative is a silent charge. A failure here
     * never replaces the error that caused the rollback; that one is what they came for.
     *
     * @param string $role The half that has just failed. Nothing to give back on the first.
     */
    private static function abandonAttempt(Job $job, Config $cfg, string $role): void
    {
        if ($role !== 'sessions') {
            return;
        }

        $hits = (string) $cfg->get('solr.hits_core', '');
        if ($hits === '') {
            return;
        }

        $job->note('Removing ' . $hits . ', which this attempt created and will not be using …');
        try {
            self::client($cfg)->deleteIndex($hits);
            $job->note('Removed ' . $hits . '. Nothing has been left behind on your account.');
        } catch (\Throwable $e) {
            $job->note(
                'Could not remove ' . $hits . '. It is still on your Opensolr account and still '
                . 'counts against your plan — delete it at ' . self::URL_INDEXES . '.'
            );
        }
    }

    /**
     * Does this Opensolr account already hold an index of this name?
     *
     * Asked only on the collision branch, which is rare, so the extra control-plane call
     * costs nothing in the normal path. `get_index_list` is filtered by the platform to the
     * indexes this API key may see, which is exactly the question being asked: an index that
     * comes back in this list belongs to the account, and because the name is derived from
     * this installation's own `solr.install_id`, it belongs to this installation.
     *
     * A failure to answer is NOT treated as "not ours". Assuming a stranger owns the name is
     * what abandons a billable index, so an unreachable control plane fails the step with a
     * sentence instead — the operator can press "Try again" once the network is back, and
     * nothing has been thrown away in the meantime.
     *
     * ONE RESIDUAL AMBIGUITY, stated rather than hidden. Opensolr::listIndexes() returns an
     * empty array both for an account that holds nothing and for a refusal the platform sent
     * as HTTP 200 with `status:false`, because the endpoint's success shape is a bare JSON
     * list and a refusal is a map. An empty list is therefore read here as "holds nothing",
     * which is the right reading in the case that actually occurs: the `verify` step at the
     * top of this same job has already proved the credentials by listing regions, so a
     * refusal at this point is not a documented outcome, while a brand-new account holding
     * no indexes at all and colliding with a stranger's name is a real one — and refusing
     * that would strand the first install on an unrecoverable screen.
     *
     * @throws \RuntimeException When the account's index list could not be read.
     */
    private static function accountOwns(Config $cfg, string $name): bool
    {
        try {
            $held = self::client($cfg)->listIndexes();
        } catch (\Throwable $e) {
            throw new \RuntimeException(
                'The name ' . $name . ' is already taken, and Opensolr could not be asked whether '
                . 'this account is the one holding it. Nothing has been changed or removed. '
                . 'Check outbound HTTPS from this server and press Try again.'
            );
        }

        return in_array($name, $held, true);
    }

    /**
     * Push the configset for one index and report file by file.
     *
     * Order matters and is enforced inside Opensolr::pushConfigSet(): schema first, then
     * solrconfig. Reversed, the core reloads against a solrconfig referring to field types
     * the old schema does not define, and the reload fails.
     *
     * A SUCCESSFUL PUSH IS REMEMBERED, in `solr.schema_release`. That marker is what lets the
     * panel say something true about an index without a control-plane call on every page load:
     * it records which set of fields the configset on that index was uploaded for, so an
     * upgrade that changes the schema is visible for free, before anybody runs a check. It is
     * written only here and in Schema::apply(), only after the platform accepted every file,
     * and it is evidence rather than proof — see Schema::notice(), which never reports it as a
     * verification.
     *
     * @param string $role 'hits' or 'sessions', the index this configset belongs to.
     */
    private static function pushConfigset(
        Job $job,
        Config $cfg,
        string $core,
        string $confDir,
        string $role = ''
    ): string {
        if ($core === '') {
            throw new \RuntimeException('The index name is missing — the previous step did not finish.');
        }
        if (!is_dir($confDir)) {
            throw new \RuntimeException('The configset directory is missing from this checkout: ' . $confDir);
        }

        $job->note('Uploading the schema to ' . $core . ' …');
        $results = self::client($cfg)->pushConfigSet($core, $confDir);

        $failed = [];
        foreach ($results as $row) {
            $job->note($row['file'] . ': ' . $row['msg']);
            if (!$row['ok']) {
                $failed[] = $row['file'] . ' (' . $row['msg'] . ')';
            }
        }
        if ($failed !== []) {
            throw new \RuntimeException(
                'The index was created but its configuration was rejected: ' . implode(', ', $failed)
                . '. The index is in your Opensolr control panel; you can upload the files from '
                . 'solr/ by hand there, or press Try again.'
            );
        }

        if ($role !== '') {
            Schema::recordRelease($cfg, $role, dirname($confDir, 3));
        }

        return 'Schema and solrconfig uploaded, index reloaded.';
    }

    /** Prove Loghound itself can reach and authenticate to a core. */
    private static function verifyCore(Job $job, Config $cfg, string $core): string
    {
        $job->note('Querying ' . $core . ' …');
        $probe = self::probeCore($cfg, $core);
        if (!$probe['ok']) {
            throw new \RuntimeException($probe['message']);
        }
        return $probe['message'];
    }

    /**
     * Connectivity test for the two provisioned indexes, as a two-step job.
     *
     * Reads the stored connection details and asks each core for zero rows. It is
     * mode-agnostic by construction — it only needs a base URL and credentials, which
     * fetchConnection() has already written — so it serves both the end of provisioning and
     * the "Test the connection" button on the setup status page.
     *
     * @return array<int,array{key:string,label:string,run:callable}>
     */
    public static function solrTestSteps(Job $job, Config $cfg): array
    {
        return [
            [
                'key'   => 'hits',
                'label' => 'Querying the hits core',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.hits_core'));
                },
            ],
            [
                'key'   => 'sessions',
                'label' => 'Querying the sessions core',
                'run'   => static function (Job $j, Config $c): string {
                    return self::verifyCore($j, $c, (string) $c->get('solr.sessions_core'));
                },
            ],
        ];
    }

    /**
     * Ask one core for zero rows and turn the outcome into a sentence a human can act on.
     *
     * "Could not connect to Solr" is useless. This produces, for example:
     *   "Connection refused to fi.solrcluster.com:443 — check the address and that this
     *    server is allowed to reach it."
     *
     * NOTHING HERE IS BUILT FROM `solr.base_url`. Every sentence names the target through
     * hostPort(), which keeps the host and the port and drops everything else, and that stays
     * true now that no form can supply the base URL at all: this method reads whatever is in
     * the config file, and a config file hand-edited to `https://user:pass@host/solr` is
     * exactly the case that no refusal at an input can reach. The `fix` list used to be
     * assembled by interpolating the base URL into ready-to-paste `curl` commands; it was
     * rendered nowhere, so it was deleted rather than repaired. If a caller ever wants those
     * hints back, build them from hostPort() and the core name and add a test that a
     * password in the base URL cannot reach the returned strings.
     *
     * @return array{ok:bool,message:string,fix:string[]}
     */
    public static function probeCore(Config $cfg, string $core, ?callable $transport = null): array
    {
        $base = (string) $cfg->get('solr.base_url', '');
        $where = self::hostPort($base);

        if ($base === '') {
            return [
                'ok' => false,
                'message' => 'No Solr address has been configured yet.',
                'fix' => [],
            ];
        }
        if ($core === '' || !Security::isSafeCoreName($core)) {
            return [
                'ok' => false,
                'message' => 'The index name is missing or invalid.',
                'fix' => [],
            ];
        }

        try {
            $solrCfg = (array) $cfg->get('solr', []);
            $solrCfg['timeout'] = 10;
            $solr = new Solr($solrCfg, self::transport($transport));
            $res = $solr->query($core, ['q' => '*:*', 'rows' => 0]);
        } catch (\Throwable $e) {
            return [
                'ok'      => false,
                'message' => self::readableSolrError($e->getMessage(), $where, $core),
                'fix'     => [],
            ];
        }

        $found = (int) ($res['response']['numFound'] ?? 0);
        return [
            'ok' => true,
            'message' => $core . ' answered on ' . $where . ' and holds '
                . number_format($found) . ' document' . ($found === 1 ? '' : 's') . '.',
            'fix' => [],
        ];
    }

    /**
     * The whole-installation health probe used by the status page and the CLI.
     *
     * @return array{ok:bool,message:string,fix:string[]}
     */
    public static function probe(Config $cfg, ?callable $transport = null): array
    {
        return self::probeCore($cfg, (string) $cfg->get('solr.hits_core', ''), $transport);
    }

    /**
     * host:port of a base URL, with the scheme's default port filled in.
     *
     * This is the ONLY thing any message in this class is allowed to say about the Solr
     * address, so a URL it cannot parse degrades to a generic phrase rather than being
     * echoed back verbatim: an unparseable base URL is exactly the shape a mistyped
     * `https://user:pass@host/solr` takes, and printing it would print the password.
     */
    private static function hostPort(string $base): string
    {
        $host = (string) parse_url($base, PHP_URL_HOST);
        if ($host === '') {
            return 'the configured address';
        }
        $port = parse_url($base, PHP_URL_PORT);
        if ($port === null || $port === false) {
            $port = parse_url($base, PHP_URL_SCHEME) === 'https' ? 443 : 80;
        }
        return $host . ':' . $port;
    }

    /**
     * Translate a transport or Solr error into something with a next action in it.
     *
     * The input is expected to be credential-free — Solr::curlTransport never puts the
     * password in an error, and Opensolr redacts the API key before any message escapes —
     * but the last branch passes the raw text through to the operator, so "expected" is not
     * good enough. Any `scheme://user:pass@` in it is stripped before anything is built from
     * it, which costs one regex and removes the whole class of "some transport helpfully
     * included the URL it was given".
     */
    private static function readableSolrError(string $raw, string $where, string $core): string
    {
        $raw = (string) preg_replace('~([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s@]*@~', '$1', $raw);
        $lower = strtolower($raw);

        if (str_contains($lower, 'connection refused')) {
            return 'Connection refused to ' . $where . ' — nothing is listening there. Check the '
                . 'address, and that Solr is running.';
        }
        if (str_contains($lower, 'could not resolve') || str_contains($lower, 'name or service not known')) {
            return 'The name in the address could not be resolved from this server (' . $where . ').';
        }
        if (str_contains($lower, 'timed out') || str_contains($lower, 'timeout')) {
            return 'No answer from ' . $where . ' before the timeout. Usually a firewall between '
                . 'this server and Solr.';
        }
        if (str_contains($lower, 'certificate') || str_contains($lower, 'ssl')) {
            return 'The TLS certificate of ' . $where . ' was rejected. Loghound will not send '
                . 'credentials over an unverified connection.';
        }
        if (str_contains($lower, '401') || str_contains($lower, 'unauthorized')) {
            return $where . ' answered, but refused the username and password.';
        }
        if (str_contains($lower, '403') || str_contains($lower, 'forbidden')) {
            return $where . ' answered, but this account is not allowed to read ' . $core . '.';
        }
        if (str_contains($lower, '404') || str_contains($lower, 'not found')) {
            return $where . ' answered, but there is no core called ' . $core . ' on it.';
        }
        return $where . ' did not answer as expected: ' . $raw;
    }

    /**
     * Turn a control-plane refusal into a sentence, without ever echoing the key.
     *
     * @param array<string,mixed> $res
     */
    private static function readableApiError(array $res): string
    {
        $msg = $res['msg'] ?? '';
        $msg = is_string($msg) ? $msg : (string) json_encode($msg, JSON_UNESCAPED_SLASHES);

        $explained = self::explainApi($msg);
        if ($explained !== self::scrub($msg)) {
            return $explained;
        }

        return 'Opensolr refused the request: ' . $explained;
    }

    /**
     * Remove anything credential-shaped from text that is about to be shown.
     *
     * Opensolr::redact() already strips the API key from its own messages, and Job::redact()
     * strips it again at the boundary. This is the third pass and it is not redundant: the
     * sentences this class builds are also printed by the shell wizard, which never goes
     * through a job at all, and a boundary that is only applied on one of two paths is not a
     * boundary.
     */
    private static function scrub(string $text): string
    {
        $text = (string) preg_replace('~([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s@]*@~', '$1', $text);
        $text = (string) preg_replace('/\b(api_key|apikey|password|passwd|token|secret)=[^&\s"\']+/i', '$1=[redacted]', $text);
        return trim($text);
    }

    /**
     * Write the configuration, keeping the running process's view of it authoritative.
     *
     * Every step persists as soon as it has something worth keeping, which is what makes
     * the whole installer resumable: the partly-written config file IS the wizard's state,
     * so nothing is held in a session that a lost cookie could throw away.
     */
    public static function persist(Config $cfg): void
    {
        $cfg->save();
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($cfg->path(), true);
        }
    }
}
