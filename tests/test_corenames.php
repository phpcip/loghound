<?php
/**
 * Loghound — tests for per-installation core naming.
 *
 * Opensolr index names live in a GLOBAL namespace shared by every account on
 * the platform and are permanent once created. A hardcoded default name would
 * therefore work for exactly one person and collide for everybody afterwards,
 * so setup generates a unique pair per installation and retries on collision.
 * These tests pin that behaviour, including the rollback that stops a failed
 * attempt from leaving billable orphan indexes behind.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Config;
use Loghound\Opensolr;

/**
 * Build an Opensolr client whose transport is a scripted list of responses.
 *
 * Each entry is returned in order for successive API calls, and the requests
 * are recorded so a test can assert what was actually sent — in particular
 * that a rollback really did issue delete_index.
 */
function lh_scripted_opensolr(array $responses, array &$calls): Opensolr
{
    // Matches Opensolr's real transport contract: fn(array $req): array.
    // The request is a single associative array, not (string $url, array $opts) —
    // getting this wrong makes every test here fail with an argument-type error
    // rather than testing anything.
    $transport = static function (array $req) use (&$responses, &$calls): array {
        $calls[] = $req['url'];
        $next = array_shift($responses);
        if ($next === null) {
            throw new \RuntimeException('Scripted transport ran out of responses for ' . $req['url']);
        }
        return ['status' => 200, 'body' => json_encode($next), 'error' => ''];
    };

    return new Opensolr([
        'api_base' => 'https://opensolr.test/solr_manager/api',
        'email'    => 'test@example.com',
        'api_key'  => 'SECRET_KEY_SHOULD_NEVER_APPEAR',
        'region'   => 'FINLAND9',
    ], $transport);
}

return [
    'install id is 8 lowercase hex characters' => static function (): bool {
        for ($i = 0; $i < 50; $i++) {
            $id = Config::newInstallId();
            if (!preg_match('/^[a-f0-9]{8}$/', $id)) {
                throw new \RuntimeException('Bad install id: ' . $id);
            }
        }
        return true;
    },

    'install ids are not repeated' => static function (): bool {
        $seen = [];
        for ($i = 0; $i < 200; $i++) {
            $seen[Config::newInstallId()] = true;
        }
        // 200 draws from a 4.3-billion space: a repeat here means the source is
        // not random, not that we got unlucky.
        return count($seen) === 200;
    },

    'core names are unique, prefixed, and within the platform limit' => static function (): bool {
        $id = Config::newInstallId();
        $hits = Config::coreName($id, 'hits');
        $sessions = Config::coreName($id, 'sessions');

        if ($hits === $sessions) {
            throw new \RuntimeException('hits and sessions cores must differ');
        }
        foreach ([$hits, $sessions] as $name) {
            if (!preg_match('/^[A-Za-z0-9_]+$/', $name)) {
                throw new \RuntimeException('Illegal characters in core name: ' . $name);
            }
            if (strlen($name) > 50) {
                throw new \RuntimeException('Core name exceeds the 50 char limit: ' . $name);
            }
            if (strpos($name, 'loghound_') !== 0) {
                throw new \RuntimeException('Core name lost its prefix: ' . $name);
            }
        }
        return true;
    },

    'core name rejects a non-hex install id and an unknown role' => static function (): bool {
        $rejected = 0;
        foreach ([['../etc', 'hits'], ['ZZZZ', 'hits'], ['a1b2c3d4', 'other']] as [$id, $role]) {
            try {
                Config::coreName($id, $role);
            } catch (\InvalidArgumentException $e) {
                $rejected++;
            }
        }
        return $rejected === 3;
    },

    'a taken name is recognised as retryable, other failures are not' => static function (): bool {
        $taken = ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'];
        $other = ['status' => false, 'msg' => 'ERROR_INVALID_API_KEY'];
        $ok    = ['status' => true,  'msg' => 'CORE_CREATED_OK'];

        if (!Opensolr::isNameTaken($taken)) {
            throw new \RuntimeException('Did not recognise the real platform error string');
        }
        if (Opensolr::isNameTaken($other)) {
            throw new \RuntimeException('Treated an auth failure as a name collision');
        }
        if (Opensolr::isNameTaken($ok)) {
            throw new \RuntimeException('Treated a success as a name collision');
        }
        return true;
    },

    'provisioning returns a matched pair on the happy path' => static function (): bool {
        $calls = [];
        $api = lh_scripted_opensolr([
            ['status' => true, 'msg' => 'CORE_CREATED_OK'],
            ['status' => true, 'msg' => 'CORE_CREATED_OK'],
        ], $calls);

        $result = $api->provisionIndexPair('FINLAND9');

        if ($result['hits'] !== Config::coreName($result['install_id'], 'hits')) {
            throw new \RuntimeException('hits core does not match the install id');
        }
        if ($result['sessions'] !== Config::coreName($result['install_id'], 'sessions')) {
            throw new \RuntimeException('sessions core does not match the install id');
        }
        return count($calls) === 2;
    },

    'a collision retries with a completely new install id' => static function (): bool {
        $calls = [];
        // First attempt: hits collides. Both names must then be abandoned, not
        // just the colliding one, so the pair stays recognisably a pair.
        $api = lh_scripted_opensolr([
            ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'],
            ['status' => true,  'msg' => 'CORE_CREATED_OK'],
            ['status' => true,  'msg' => 'CORE_CREATED_OK'],
        ], $calls);

        $result = $api->provisionIndexPair('FINLAND9');

        $firstAttemptName = null;
        if (preg_match('/index_name=([A-Za-z0-9_]+)/', $calls[0], $m)) {
            $firstAttemptName = $m[1];
        }
        if ($firstAttemptName === $result['hits']) {
            throw new \RuntimeException('Reused the name that had already been taken');
        }
        return true;
    },

    'a collision on the SECOND core rolls back the first' => static function (): bool {
        $calls = [];
        $api = lh_scripted_opensolr([
            ['status' => true,  'msg' => 'CORE_CREATED_OK'],                                  // hits ok
            ['status' => false, 'msg' => 'ERROR_CORE_NAME_TAKEN_CHOOSE_ANOTHER_CORE_NAME'],   // sessions taken
            ['status' => true,  'msg' => 'CORE_DELETED_OK'],                                  // rollback of hits
            ['status' => true,  'msg' => 'CORE_CREATED_OK'],
            ['status' => true,  'msg' => 'CORE_CREATED_OK'],
        ], $calls);

        $api->provisionIndexPair('FINLAND9');

        $deletes = array_filter($calls, static fn(string $u): bool => strpos($u, 'delete_index') !== false);
        if (count($deletes) !== 1) {
            throw new \RuntimeException(
                'Expected exactly one delete_index rollback, saw ' . count($deletes)
                . ' — an orphaned index would be left in the account'
            );
        }
        return true;
    },

    'a real API failure aborts instead of burning through names' => static function (): bool {
        $calls = [];
        $api = lh_scripted_opensolr([
            ['status' => false, 'msg' => 'ERROR_INVALID_API_KEY'],
        ], $calls);

        try {
            $api->provisionIndexPair('FINLAND9');
        } catch (\RuntimeException $e) {
            // One attempt only: retrying a bad API key with a different index
            // name would just hide the real problem behind five more failures.
            if (count($calls) !== 1) {
                throw new \RuntimeException('Retried a non-retryable failure');
            }
            if (strpos($e->getMessage(), 'SECRET_KEY_SHOULD_NEVER_APPEAR') !== false) {
                throw new \RuntimeException('API key leaked into the error message');
            }
            return true;
        }
        throw new \RuntimeException('A hard API failure should not have been swallowed');
    },

    'config rejects an unset or duplicated core name' => static function (): bool {
        $cfg = Config::load('/nonexistent/loghound.php');
        $errors = implode(' | ', $cfg->validate());
        /*
         * The wizard is named by its ABSOLUTE path, and this assertion says so on purpose.
         * These messages are read over SSH and in a journal, where a relative
         * `bin/loghound-setup` is a command that works from exactly one directory — and on a
         * machine with two checkouts it configures the wrong installation without saying so.
         */
        if (strpos($errors, $cfg->setupCommand()) === false
            || !str_starts_with($cfg->setupCommand(), '/')
            || str_contains($cfg->setupCommand(), '//')) {
            throw new \RuntimeException('Empty core names should point at the setup wizard: ' . $errors);
        }

        $id = Config::newInstallId();
        $cfg->set('solr.hits_core', Config::coreName($id, 'hits'));
        $cfg->set('solr.sessions_core', Config::coreName($id, 'hits')); // deliberately the same
        $errors = implode(' | ', $cfg->validate());
        if (strpos($errors, 'must be different indexes') === false) {
            throw new \RuntimeException('Duplicate core names were accepted: ' . $errors);
        }
        return true;
    },
];
