<?php
/**
 * Loghound — where a visit really came from when its first request names this site.
 *
 * A session whose first request carries a referer on the visited host did not come from that
 * host. The visitor was already here: a tab restored from memory, a session split by the idle
 * timeout, a page left open overnight. Publishing the site's own address as the source of the
 * visit makes the operator's own hostname the top "referring site" and hides the real origin.
 *
 * The rule: the source of such a session is the most recent request from the same address to
 * the same host whose referer is external, at or before the session's first request. When there
 * is none, the visit is direct. The site's own host is never a source.
 *
 * Two places answer the question, newest first: the referers this process has already seen,
 * which covers hits not yet committed to Solr, and the `hits` core, sorted by `ts desc`.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class RefererOrigin
{
    /** The three session fields this class decides. */
    public const FIELDS = ['referer_s', 'referer_host_s', 'referer_type_s'];

    /** Referer types that are not a source: no referer at all, or this site. */
    private const NOT_A_SOURCE = ['direct', 'internal'];

    /** Addresses remembered in memory before the oldest is dropped. */
    private const MEMO_CAP = 5000;

    /** Seconds Solr lookups are skipped after one fails, so an outage cannot stall ingest. */
    private const PAUSE_AFTER_FAILURE = 60;

    private ?Solr $solr = null;

    private string $hitsCore = '';

    /** @var array<string,array{ts:int,fields:array<string,string>}> Latest external referer per ip|host. */
    private array $memo = [];

    private int $pausedUntil = 0;

    /**
     * Enable the `hits` core lookup. Without it only referers seen by this process are used.
     */
    public function useSolr(Solr $solr, string $hitsCore): void
    {
        $this->solr = $solr;
        $this->hitsCore = $hitsCore;
    }

    /**
     * Remember the hit's referer when it is an external source.
     *
     * @param array<string,mixed> $hit
     */
    public function remember(array $hit, int $tsMs): void
    {
        $fields = self::sourceFields($hit);
        $key = self::key($hit);
        if ($fields === null || $key === null) {
            return;
        }
        if (isset($this->memo[$key]) && $this->memo[$key]['ts'] > $tsMs) {
            return;
        }

        unset($this->memo[$key]);
        $this->memo[$key] = ['ts' => $tsMs, 'fields' => $fields];

        if (count($this->memo) > self::MEMO_CAP) {
            unset($this->memo[array_key_first($this->memo)]);
        }
    }

    /**
     * Return the hit with its referer replaced by the visit's real source when it names this site.
     *
     * A hit whose referer is not internal is returned unchanged. An internal one gets the latest
     * external referer of the same address on the same host, or no referer and type `direct`.
     *
     * @param array<string,mixed> $hit
     * @return array<string,mixed>
     */
    public function resolve(array $hit, int $tsMs): array
    {
        if (($hit['referer_type_s'] ?? null) !== 'internal') {
            return $hit;
        }

        $found = null;
        $key = self::key($hit);
        if ($key !== null) {
            if (isset($this->memo[$key]) && $this->memo[$key]['ts'] <= $tsMs) {
                $found = $this->memo[$key]['fields'];
            } else {
                $found = $this->lookup((string) $hit['ip_s'], (string) $hit['host_s'], $tsMs);
            }
        }

        return self::apply($hit, $found);
    }

    /**
     * Latest external referer of an address on a host, at or before an instant, from `hits`.
     *
     * Returns null when there is none, when Solr is not configured, or when the lookup failed.
     *
     * @return array<string,string>|null
     */
    public function lookup(string $ip, string $host, int $tsMs): ?array
    {
        if ($this->solr === null || $this->hitsCore === '' || $ip === '' || $host === '') {
            return null;
        }
        if ($this->pausedUntil > time()) {
            return null;
        }

        try {
            $res = $this->solr->query($this->hitsCore, [
                'q'    => '*:*',
                'fq'   => [
                    Solr::termFilter('ip_s', $ip),
                    Solr::termFilter('host_s', $host),
                    'referer_host_s:[* TO *]',
                    '-referer_type_s:(direct OR internal)',
                    'ts:[* TO ' . Solr::escapeTerm(self::isoMillis($tsMs)) . ']',
                ],
                'sort' => 'ts desc',
                'rows' => 1,
                'fl'   => implode(',', self::FIELDS),
            ]);
        } catch (\Throwable $e) {
            $this->pausedUntil = time() + self::PAUSE_AFTER_FAILURE;
            return null;
        }

        $doc = $res['response']['docs'][0] ?? null;

        return is_array($doc) ? self::sourceFields($doc) : null;
    }

    /**
     * Whether the last Solr lookup failed and lookups are paused, so a null answer means unknown.
     */
    public function failed(): bool
    {
        return $this->pausedUntil > time();
    }

    /**
     * Put a source on a hit or session array, or remove the referer and mark it direct.
     *
     * @param array<string,mixed>       $row
     * @param array<string,string>|null $source
     * @return array<string,mixed>
     */
    public static function apply(array $row, ?array $source): array
    {
        if ($source === null) {
            unset($row['referer_s'], $row['referer_host_s']);
            $row['referer_type_s'] = 'direct';
            return $row;
        }

        return array_merge($row, $source);
    }

    /**
     * The three referer fields of a row when they describe an external source, else null.
     *
     * The host is derived from the URL when the row does not carry it, and the type falls back
     * to `link`, the parser's residual for an external referer.
     *
     * @param array<string,mixed> $row
     * @return array<string,string>|null
     */
    private static function sourceFields(array $row): ?array
    {
        $referer = self::scalar($row['referer_s'] ?? null);
        $type = self::scalar($row['referer_type_s'] ?? null);
        if ($referer === '' || in_array($type, self::NOT_A_SOURCE, true)) {
            return null;
        }

        $host = self::scalar($row['referer_host_s'] ?? null);
        if ($host === '') {
            $parsed = parse_url($referer, PHP_URL_HOST);
            $host = is_string($parsed) ? strtolower($parsed) : '';
        }
        if ($host === '' || Parser::sameSite($host, self::scalar($row['host_s'] ?? null))) {
            return null;
        }

        return [
            'referer_s'      => $referer,
            'referer_host_s' => $host,
            'referer_type_s' => $type !== '' ? $type : 'link',
        ];
    }

    /**
     * The memo key, or null when the row has no address or no host.
     *
     * @param array<string,mixed> $row
     */
    private static function key(array $row): ?string
    {
        $ip = self::scalar($row['ip_s'] ?? null);
        $host = self::scalar($row['host_s'] ?? null);

        return ($ip === '' || $host === '') ? null : $ip . '|' . strtolower($host);
    }

    /**
     * A single string out of a stored value, which Solr may return as a one-element list.
     */
    private static function scalar(mixed $value): string
    {
        if (is_array($value)) {
            $value = $value[0] ?? '';
        }

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * Epoch milliseconds as a Solr date string.
     */
    private static function isoMillis(int $tsMs): string
    {
        return gmdate('Y-m-d\TH:i:s', intdiv($tsMs, 1000)) . '.' . sprintf('%03d', $tsMs % 1000) . 'Z';
    }
}
