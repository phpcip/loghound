<?php
/**
 * Loghound — Attacks.
 *
 * ---------------------------------------------------------------------------------------
 * WHAT THIS PAGE IS
 * ---------------------------------------------------------------------------------------
 * Hostile probing has been sitting in every access log this product reads since the day it
 * shipped, and nothing surfaced it. The owner found his own case by accident: a session
 * claiming the `OAI-SearchBot` User-Agent asking for `/proc/self/environ` and `.env` from a
 * Google Cloud VM, which is not where OpenAI's crawler lives. He only saw it because he
 * happened to open a dialog.
 *
 * ---------------------------------------------------------------------------------------
 * WHAT IT IS NOT, AND THIS IS NOT A DISCLAIMER — IT IS THE DESIGN
 * ---------------------------------------------------------------------------------------
 * IT IS NOT A WAF. It reads a log after the fact. It has no place in the request path, it
 * blocked nothing, it could not have blocked anything, and no word on this page may be
 * phrased as though it had. "Blocked", "stopped", "prevented" and "protected" do not appear
 * on it. What appears is what was ATTEMPTED and what the server ANSWERED.
 *
 * ---------------------------------------------------------------------------------------
 * THE STATUS CODE IS THE WHOLE PAGE
 * ---------------------------------------------------------------------------------------
 * Every other tool in this category prints a list of scary-looking request strings and leaves
 * the operator to panic. That list is almost entirely noise: any address on the public
 * internet collects thousands of traversal attempts a day and the webserver answers every one
 * of them with a 404, which is the webserver working.
 *
 * What matters is the handful that got a 2xx or a 3xx. So that is CARD 01 — first, on its own,
 * small in number and large in importance — and every other card on the page is ordered by it.
 * A severity-high pattern answered 404 ranks below a severity-medium one answered 200, because
 * what the server did outranks what was tried.
 *
 * AND THE SAME HONESTY IN THE OTHER DIRECTION, because without it this page would be worse
 * than nothing: A 200 IS NOT PROOF OF COMPROMISE. A site whose error page is served with a 200
 * — a single-page-app shell, a CMS catch-all route, a misconfigured ErrorDocument — is
 * indistinguishable in a log from one that handed over `/etc/passwd`. Card 01 says "the server
 * answered these with a body" and tells the operator to fetch one and look. It never says
 * "disclosed".
 *
 * ---------------------------------------------------------------------------------------
 * WHICH PLANE ANSWERS WHICH QUESTION
 * ---------------------------------------------------------------------------------------
 * Most of this view is a HITS query, and that is forced rather than chosen. `status_i` exists
 * only on the hits core, and the path and the status have to be read off the SAME document: a
 * session that recorded one 2xx and one 4xx tells you nothing about which of its requests was
 * the hostile one. Cards 01 to 04 and 06 are therefore hits-plane.
 *
 * Card 05 is the exception and is a SESSIONS query, because "who" is a session question —
 * identity, network, fingerprint, whether one campaign is behind many addresses — and
 * re-deriving that per request would be both slower and less accurate. The session document
 * carries the union of its hits' flags for exactly this.
 *
 * ---------------------------------------------------------------------------------------
 * THE PERIOD THIS PAGE CAN SPEAK FOR
 * ---------------------------------------------------------------------------------------
 * Detection runs at ingest (Score\Attacks explains why it cannot run at query time), so a
 * document written before the detector existed has no verdict — and "no attack codes" on such
 * a document means NOBODY LOOKED, not "nothing was there". `hit_rules_i` is what separates the
 * two, and card 01 prints the split. A page that reported a deployment gap as a quiet week
 * would be the same class of lie as a number that does not say what it counts.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Score\Attacks as Rules;
use Loghound\Security;

final class Attacks extends Controller implements Sections
{
    /**
     * The pages this view has, in render order. Drives the navigation and every card's number.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['atk-answered', 'Answered'],
        ['atk-patterns', 'Patterns'],
        ['atk-requests', 'Requests'],
        ['atk-who', 'Who'],
        ['atk-impersonation', 'Impersonation'],
        ['atk-when', 'When'],
        ['atk-pivot', 'By status'],
        ['atk-explain', 'Limits'],
    ];

    /**
     * Most individual requests card 03 will list.
     *
     * The one card on this page that reads DOCUMENTS rather than facets, and the cap is what
     * makes that defensible. It exists because a pattern name is not actionable — an operator
     * cannot check whether `/api/../../.env` really disclosed anything without the actual URL —
     * and because the population it reads is small by construction: the attempts that got a 2xx
     * or a 3xx. On a healthy site that is single digits. On an unhealthy one the operator needs
     * every one of them, which is why this is generous rather than tight.
     */
    private const MAX_REQUESTS = 200;

    /**
     * Statuses that mean the server returned something.
     *
     * A RANGE AND NOT A LIST, and 3xx is in it deliberately. A probe redirected to a login page
     * received no content, but it learned the path exists and that something is listening — a
     * 302 on `/wp-admin` on a site that does not run WordPress would be very odd indeed. The
     * two classes are counted separately everywhere so the reader can weigh them differently.
     */
    private const FQ_ANSWERED = 'status_i:[200 TO 399]';

    /** The evaluated population: documents the detector has actually looked at. */
    private const FQ_EVALUATED = 'hit_rules_i:[* TO *]';

    /**
     * Which page-toolbar controls this view honours.
     *
     * All six queries run under hitFqs() or sessionFqs(), so the range, the host and the filter
     * bar all reach them. Session-only dimensions a hits query cannot honour are reported
     * through `filters_ignored` rather than dropped in silence.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'attacks';
    }

    public function title(): string
    {
        return 'Attacks';
    }

    public function subtitle(): string
    {
        return 'What was attempted against this site, and what the server answered.';
    }

    /**
     * The card number for one card id, from the single ordered list above.
     *
     * Delegated to Layout so the jump bar and the number printed on the card come from the same
     * arithmetic over the same list. Named `cardNumber` and not `num`: Controller::num() is the
     * static "read a numeric aggregate, preserving null" helper, and a second meaning for that
     * name on a subclass is both a fatal signature clash and a trap for the next reader.
     */
    private function cardNumber(string $id): string
    {
        return Layout::cardNum(self::SECTIONS, $id);
    }

    /** The hits-plane `fq` list every card on this view starts from. */
    private function attackFqs(): array
    {
        $fqs = $this->hitFqs();
        $fqs[] = Query::attackFq();
        return $fqs;
    }

    /**
     * The status breakdown every pattern row and every actor row carries.
     *
     * Nested inside whatever facet asks for it, so a row's answered-count arrives in the SAME
     * round trip as the row. It is the one number on this page that must never be a second
     * query: a table that showed the patterns first and filled the status column afterwards
     * would be sorted wrongly for as long as the second request took.
     *
     * @return array<string,mixed>
     */
    private static function statusFacets(): array
    {
        return [
            'answered' => ['type' => 'query', 'q' => self::FQ_ANSWERED],
            'ok'       => ['type' => 'query', 'q' => 'status_i:[200 TO 299]'],
            'redirect' => ['type' => 'query', 'q' => 'status_i:[300 TO 399]'],
            'refused'  => ['type' => 'query', 'q' => 'status_i:[400 TO 499]'],
            'broke'    => ['type' => 'query', 'q' => 'status_i:[500 TO 599]'],
        ];
    }

    /**
     * Pull the status breakdown out of a bucket.
     *
     * `unknown` is derived rather than faceted: a request whose status did not parse carries no
     * `status_i` at all, and the four classes therefore do not have to sum to the row total.
     * Computing the remainder here means the table can show it instead of letting the reader
     * discover the arithmetic does not work.
     *
     * @param array<string,mixed> $bucket
     * @return array<string,int>
     */
    private static function statusOf(array $bucket, int $total): array
    {
        $ok = self::qcount($bucket, 'ok');
        $redirect = self::qcount($bucket, 'redirect');
        $refused = self::qcount($bucket, 'refused');
        $broke = self::qcount($bucket, 'broke');

        return [
            'answered' => self::qcount($bucket, 'answered'),
            'ok'       => $ok,
            'redirect' => $redirect,
            'refused'  => $refused,
            'broke'    => $broke,
            'unknown'  => max(0, $total - $ok - $redirect - $refused - $broke),
        ];
    }

    /**
     * The exports, and the one that is deliberately missing.
     *
     * `patterns` and `actors` are aggregates and export cleanly. `requests` is the individual
     * answered requests, which is the row an operator forwards to somebody else, so it carries
     * the full path AND the query string — the two most attacker-chosen strings in the product.
     * Csv::text() neutralises a leading `=`, `+`, `-`, `@`, tab and CR so a crafted path cannot
     * become a spreadsheet formula; the columns are declared `text`/`id` for exactly that
     * reason, since only those two kinds get the treatment.
     *
     * THE STATUS DISTRIBUTION CHART IS NOT EXPORTABLE. It is the same numbers `patterns`
     * carries, bucketed over time for the eye. A second file of the same rows under a
     * different name is how two exports start disagreeing.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        $ignored = [
            'filters_ignored' => ['Filters this plane could not honour', static function ($v): string {
                return is_array($v) && $v !== [] ? implode('; ', $v) : 'None';
            }],
        ];

        $notClaimed = 'A 2xx means the server returned a body. It does NOT mean anything was '
            . 'disclosed: a site whose error page is served with a 200 looks identical in a log. '
            . 'Loghound reads the log after the fact and blocked none of this.';

        return [
            'patterns' => [
                'label'   => 'Attack patterns',
                'action'  => 'patterns',
                'key'     => 'patterns',
                'unit'    => 'patterns',
                'ranked'  => 'ranked by how many of their attempts the server answered',
                'cap'     => 100,
                'note'    => $notClaimed . ' The four status columns need not sum to the request '
                    . 'total: a log line whose status did not parse is in none of them and is '
                    . 'counted under Status not recorded.',
                'scope'   => $ignored + [
                    'evaluated'   => 'Requests the detector has evaluated',
                    'unevaluated' => 'Requests written before detection and never evaluated',
                ],
                'columns' => [
                    ['Pattern', 'label', 'text'],
                    ['Pattern code', 'code', 'id'],
                    ['Family', 'family', 'text'],
                    ['Severity of a match', 'severity', 'text'],
                    ['Requests', 'count', 'number'],
                    ['Answered (2xx or 3xx)', 'answered', 'number'],
                    ['Answered with a body (2xx)', 'ok', 'number'],
                    ['Redirected (3xx)', 'redirect', 'number'],
                    ['Refused (4xx)', 'refused', 'number'],
                    ['Server error (5xx)', 'broke', 'number'],
                    ['Status not recorded', 'unknown', 'number'],
                    ['Distinct addresses', 'uniq_ips', 'number'],
                    ['Distinct sessions', 'uniq_sessions', 'number'],
                    ['Last seen', 'last', 'date'],
                    ['What this pattern matches', 'what', 'text'],
                    ['What it misses', 'misses', 'text'],
                    ['What it over-reports', 'over', 'text'],
                ],
            ],

            'actors' => [
                'label'   => 'Addresses probing this site',
                'action'  => 'who',
                'key'     => 'actors',
                'unit'    => 'addresses',
                'ranked'  => 'ranked by how many of their attempts the server answered',
                'cap'     => 200,
                'note'    => $notClaimed . ' Distinct-pattern counts come from Solr\'s unique(), '
                    . 'which is exact for small counts and approximate for large ones. An address '
                    . 'is not a person: one host can carry many clients and one campaign can rent '
                    . 'many hosts, which is what the network and fingerprint columns are for.',
                'scope'   => $ignored,
                'columns' => [
                    ['Address', 'ip', 'id'],
                    ['Reverse DNS', 'rdns', 'id'],
                    ['Network', 'org', 'text'],
                    ['Network type', 'as_type', 'vocab', 'as_type_s'],
                    ['Requests that matched a pattern', 'count', 'number'],
                    ['Answered (2xx or 3xx)', 'answered', 'number'],
                    ['Answered with a body (2xx)', 'ok', 'number'],
                    ['Refused (4xx)', 'refused', 'number'],
                    ['Distinct patterns tried', 'uniq_patterns', 'number'],
                    ['Distinct paths tried', 'uniq_paths', 'number'],
                    ['First seen', 'first', 'date'],
                    ['Last seen', 'last', 'date'],
                ],
            ],

            'requests' => [
                'label'   => 'Requests the server answered',
                'action'  => 'requests',
                'key'     => 'requests',
                'unit'    => 'requests',
                'ranked'  => 'most recent first',
                'cap'     => self::MAX_REQUESTS,
                'params'  => ['rows' => self::MAX_REQUESTS],
                'note'    => 'INDIVIDUAL REQUESTS, not aggregates, and every one of them matched a '
                    . 'pattern AND was answered with a 2xx or a 3xx. ' . $notClaimed . ' The path '
                    . 'and the query string are reproduced exactly as the client sent them, so '
                    . 'they are hostile text: they are neutralised against spreadsheet formula '
                    . 'execution on the way into this file, and they should not be pasted into a '
                    . 'shell.',
                'scope'   => $ignored + ['total' => 'Answered requests in scope'],
                'columns' => [
                    ['When', 'ts', 'date'],
                    ['Virtual host', 'host', 'text'],
                    ['Method', 'method', 'id'],
                    ['Path', 'path', 'text'],
                    ['Query string', 'query', 'text'],
                    ['Status', 'status', 'number'],
                    ['Bytes returned', 'bytes', 'number'],
                    ['Patterns matched', 'patterns', 'text'],
                    ['Address', 'ip', 'id'],
                    ['Country', 'country', 'id'],
                    ['City', 'city', 'text'],
                    ['Session', 'session', 'id'],
                ],
            ],

            'pivot' => [
                'label'  => 'Pattern by status class',
                'action' => 'patterns',
                'shape'  => 'pivot',
                'key'    => 'pivot',
                'unit'   => 'pattern and status pairs',
                'cap'    => 200,
                'note'   => 'One record per pair. The status breakdown of a pattern is a LIMITED '
                    . 'facet, so its rows do not add up to that pattern\'s request total.',
            ],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'answered'      => $this->answered(),
            'patterns'      => $this->patterns(),
            'requests'      => $this->requests(),
            'who'           => $this->who(),
            'impersonation' => $this->impersonation(),
            'when'          => $this->when(),
            default         => ['error' => 'Unknown action'],
        };
    }

    /**
     * Every payload says which filters this plane could not honour.
     *
     * A verdict, a bot class and a fired scoring signal are conclusions about a whole session
     * and live only on the sessions core. Dropping one silently would put a number on screen
     * under a chip claiming a scope the number does not have.
     *
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    protected function envelope(array $extra = []): array
    {
        return parent::envelope($extra + ['filters_ignored' => $this->ignoredHitFilters()]);
    }

    /**
     * CARD 01. What was answered, and what this page can actually speak for.
     *
     * Two things in one round trip, because they are one thought. The headline is the answered
     * count — the number the operator came for. The coverage beside it is the number that says
     * whether the headline means anything: requests the detector has evaluated, against
     * requests written before it existed and therefore never looked at.
     *
     * The four status classes are counted SEPARATELY and are never summed into a single "attack
     * traffic" figure, for the same reason Bots never sums declared and evasive crawlers: the
     * whole product claim is that those groups are different, and one number would erase it.
     *
     * @return array<string,mixed>
     */
    private function answered(): array
    {
        $base = $this->hitFqs();

        $f = $this->gw->facet('atk.answered', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $base,
        ], [
            'evaluated'   => ['type' => 'query', 'q' => self::FQ_EVALUATED],
            'unevaluated' => ['type' => 'query', 'q' => '-' . self::FQ_EVALUATED],
            'matched'     => [
                'type'  => 'query',
                'q'     => Query::attackFq(),
                'facet' => self::statusFacets() + [
                    'uniq_ips'      => 'unique(ip_s)',
                    'uniq_sessions' => 'unique(session_id_s)',
                    'uniq_patterns' => 'unique(hit_flags_ss)',
                    'first'         => 'min(ts)',
                    'last'          => 'max(ts)',
                ],
            ],
        ]);

        $matched = is_array($f['matched'] ?? null) ? $f['matched'] : [];
        $total = (int) ($matched['count'] ?? 0);

        return $this->envelope([
            'requests'      => (int) ($f['count'] ?? 0),
            'evaluated'     => self::qcount($f, 'evaluated'),
            'unevaluated'   => self::qcount($f, 'unevaluated'),
            'matched'       => $total,
            'status'        => self::statusOf($matched, $total),
            'uniq_ips'      => (int) (self::num($matched, 'uniq_ips') ?? 0),
            'uniq_sessions' => (int) (self::num($matched, 'uniq_sessions') ?? 0),
            'uniq_patterns' => (int) (self::num($matched, 'uniq_patterns') ?? 0),
            'first'         => is_string($matched['first'] ?? null) ? $matched['first'] : null,
            'last'          => is_string($matched['last'] ?? null) ? $matched['last'] : null,
        ]);
    }

    /**
     * CARD 02 and the cross-tab. What is being tried, GROUPED BY PATTERN.
     *
     * Grouped by pattern and never by exact string, and that is the same lesson the query-shape grouping
     * learned about Solr queries: every probe is unique — a different path, a different payload,
     * a different encoding — so a table of exact strings is a list of one-hit wonders and the
     * shape underneath it never surfaces. `hit_flags_ss` IS the shape, computed at ingest, which
     * is what makes this one cheap facet instead of a scan.
     *
     * SORTED BY WHAT THE SERVER ANSWERED, not by count. A facet cannot sort by a nested query
     * count, so the ordering is applied here after the buckets arrive; the facet asks for every
     * code in the table, which is bounded at the size of the rule table and therefore complete
     * rather than a top-N.
     *
     * @return array<string,mixed>
     */
    private function patterns(): array
    {
        $f = $this->gw->facet('atk.patterns', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $this->attackFqs(),
        ], [
            'patterns' => [
                'type'  => 'terms',
                'field' => 'hit_flags_ss',
                'limit' => count(Rules::codes()) + 10,
                'sort'  => 'count desc',
                'facet' => self::statusFacets() + [
                    'uniq_ips'      => 'unique(ip_s)',
                    'uniq_sessions' => 'unique(session_id_s)',
                    'uniq_paths'    => 'unique(path_s)',
                    'last'          => 'max(ts)',
                    'classes'       => ['type' => 'terms', 'field' => 'status_class_s', 'limit' => 6],
                ],
            ],
        ]);

        $rows = [];
        $pivot = [];
        foreach (self::buckets($f, 'patterns') as $bucket) {
            $code = (string) ($bucket['val'] ?? '');
            $count = (int) ($bucket['count'] ?? 0);
            $rule = Rules::describe($code);
            $status = self::statusOf($bucket, $count);

            $rows[] = array_merge([
                'code'          => $code,
                'label'         => $rule['label'],
                'family'        => $rule['family'],
                'severity'      => $rule['severity'],
                'what'          => $rule['what'],
                'misses'        => $rule['misses'],
                'over'          => $rule['over'],
                'count'         => $count,
                'uniq_ips'      => (int) (self::num($bucket, 'uniq_ips') ?? 0),
                'uniq_sessions' => (int) (self::num($bucket, 'uniq_sessions') ?? 0),
                'uniq_paths'    => (int) (self::num($bucket, 'uniq_paths') ?? 0),
                'last'          => is_string($bucket['last'] ?? null) ? $bucket['last'] : null,
            ], $status);

            $cells = [];
            $covered = 0;
            foreach (self::buckets($bucket, 'classes') as $class) {
                $value = (string) ($class['val'] ?? '');
                $n = (int) ($class['count'] ?? 0);
                $covered += $n;
                $cells[] = [
                    'value' => $value,
                    'label' => Vocabulary::label('status_class_s', $value),
                    'count' => $n,
                ];
            }
            $pivot[] = [
                'value'   => $code,
                'label'   => $rule['label'],
                'count'   => $count,
                'covered' => $covered,
                'cells'   => $cells,
            ];
        }

        usort($rows, static function (array $a, array $b): int {
            return [$b['answered'], $b['ok'], $b['count']] <=> [$a['answered'], $a['ok'], $a['count']];
        });

        return $this->envelope([
            'matched'  => (int) ($f['count'] ?? 0),
            'patterns' => $rows,
            'families' => Rules::families(),
            'pivot'    => [
                'outer'       => 'hit_flags_ss',
                'inner'       => 'status_class_s',
                'outer_label' => 'Attack pattern',
                'inner_label' => 'Status class',
                'question'    => 'What the server actually answered each kind of probe with.',
                'rows'        => $pivot,
            ],
        ]);
    }

    /**
     * CARD 03. The individual requests the server ANSWERED.
     *
     * THE ONLY CARD ON THIS PAGE THAT READS DOCUMENTS, and it is why the page is worth having.
     * An operator cannot act on "seventeen traversal attempts got a 200"; they can act on the
     * seventeen URLs. The population is small by construction — answered attempts only — so
     * this is a bounded read and not a scan.
     *
     * Everything on a row is attacker-chosen: the path, the query string, the method. Nothing
     * is interpreted here; it is shaped, capped and handed to the front end, which escapes it
     * for the exact context it lands in.
     *
     * @return array<string,mixed>
     */
    private function requests(): array
    {
        $start = Paging::start();
        $rows = Security::clampInt($_GET['rows'] ?? null, 1, self::MAX_REQUESTS, Paging::PAGE);

        $fqs = $this->attackFqs();
        $fqs[] = self::FQ_ANSWERED;

        $res = $this->gw->select('atk.requests', $this->gw->hitsCore(), [
            'q'     => '*:*',
            'fq'    => $fqs,
            'sort'  => 'ts desc',
            'rows'  => $rows,
            'start' => $start,
            /* THE TWO FIELDS THIS CARD ACTUALLY READS, which Query::hitFl() does not carry.
               The mapper below reads `session_id_s` and `ip_s` off every document and the
               query never asked Solr for either, so both came back null on every row of every
               installation. That is two permanently empty columns in this dataset's CSV export
               — "Address" and "Session" — and a drill-through that never fires: the row is
               only made clickable when `session` is non-null, so the "row opens the session
               that made the request" this card's own docblock promises has never happened.
               Both are docValues, so they return in `fl` despite stored="false". Added here
               rather than to hitFl() because the other caller is a timeline already scoped to
               one session, where a session id on every row is dead weight. */
            'fl'   => Query::hitFl() . ',session_id_s,ip_s,country_s,city_s',
        ]);

        $out = [];
        foreach ($res['docs'] as $doc) {
            $codes = array_values(array_map('strval', (array) ($doc['hit_flags_ss'] ?? [])));
            $labels = [];
            foreach ($codes as $code) {
                $labels[] = Rules::describe($code)['label'];
            }

            $out[] = [
                'id'       => (string) ($doc['id'] ?? ''),
                'ts'       => (string) ($doc['ts'] ?? ''),
                'host'     => isset($doc['host_s']) && is_scalar($doc['host_s']) ? (string) $doc['host_s'] : null,
                'method'   => (string) ($doc['method_s'] ?? ''),
                'path'     => (string) ($doc['path_s'] ?? ''),
                'query'    => isset($doc['query_s']) ? (string) $doc['query_s'] : null,
                'status'   => isset($doc['status_i']) ? (int) $doc['status_i'] : null,
                'bytes'    => isset($doc['bytes_l']) ? (int) $doc['bytes_l'] : null,
                'codes'    => $codes,
                'patterns' => implode('; ', $labels),
                'ip'       => isset($doc['ip_s']) ? (string) $doc['ip_s'] : null,
                'country'  => isset($doc['country_s']) ? (string) $doc['country_s'] : null,
                'city'     => isset($doc['city_s']) ? (string) $doc['city_s'] : null,
                'session'  => isset($doc['session_id_s']) ? (string) $doc['session_id_s'] : null,
            ];
        }

        return $this->envelope([
            'requests'  => $out,
            'total'     => (int) $res['numFound'],
            'limit'     => $rows,
            'page'      => Paging::block($start, $rows, (int) $res['numFound'], 'requests', count($out)),
        ]);
    }

    /**
     * CARD 04. Who is doing it — address, network, reverse DNS.
     *
     * A hits query rather than a sessions one, because the counts that make a row worth reading
     * are per-REQUEST: how many of this address's attempts were answered. The network columns
     * ride along as single-bucket sub-facets, so the row arrives complete in one round trip.
     *
     * An address is NOT a person and the page says so beside the table: one host can carry many
     * clients through NAT, and one campaign can rent many hosts. The distinct-pattern and
     * distinct-path columns are what separate a single misconfigured client from a scanner
     * walking a list, and the fingerprint work on Panel\Fingerprints is where "one campaign,
     * many addresses" is actually answered.
     *
     * @return array<string,mixed>
     */
    private function who(): array
    {
        $limit = Security::clampInt($_GET['limit'] ?? null, 10, 200, 50);

        $f = $this->gw->facet('atk.who', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $this->attackFqs(),
        ], [
            'actors' => [
                'type'  => 'terms',
                'field' => 'ip_s',
                'limit' => $limit,
                'sort'  => 'count desc',
                'facet' => self::statusFacets() + [
                    'uniq_patterns' => 'unique(hit_flags_ss)',
                    'uniq_paths'    => 'unique(path_s)',
                    'first'         => 'min(ts)',
                    'last'          => 'max(ts)',
                    'org'           => ['type' => 'terms', 'field' => 'as_org_s', 'limit' => 1],
                    'astype'        => ['type' => 'terms', 'field' => 'as_type_s', 'limit' => 1],
                    'country'       => ['type' => 'terms', 'field' => 'country_s', 'limit' => 1],
                    'rdns'          => ['type' => 'terms', 'field' => 'rdns_s', 'limit' => 1],
                    'asn'           => ['type' => 'terms', 'field' => 'asn_i', 'limit' => 1],
                ],
            ],
            'networks' => [
                'type'  => 'terms',
                'field' => 'as_org_s',
                'limit' => 12,
                'sort'  => 'count desc',
                'facet' => self::statusFacets() + ['uniq_ips' => 'unique(ip_s)'],
            ],
        ]);

        $one = static function (array $bucket, string $key): ?string {
            $bs = self::buckets($bucket, $key);
            return $bs === [] ? null : (string) ($bs[0]['val'] ?? '');
        };

        $actors = [];
        foreach (self::buckets($f, 'actors') as $bucket) {
            $count = (int) ($bucket['count'] ?? 0);
            $actors[] = array_merge([
                'ip'            => (string) ($bucket['val'] ?? ''),
                'count'         => $count,
                'uniq_patterns' => (int) (self::num($bucket, 'uniq_patterns') ?? 0),
                'uniq_paths'    => (int) (self::num($bucket, 'uniq_paths') ?? 0),
                'first'         => is_string($bucket['first'] ?? null) ? $bucket['first'] : null,
                'last'          => is_string($bucket['last'] ?? null) ? $bucket['last'] : null,
                'org'           => $one($bucket, 'org'),
                'as_type'       => $one($bucket, 'astype'),
                'country'       => $one($bucket, 'country'),
                'rdns'          => $one($bucket, 'rdns'),
                'asn'           => $one($bucket, 'asn'),
            ], self::statusOf($bucket, $count));
        }

        usort($actors, static function (array $a, array $b): int {
            return [$b['answered'], $b['ok'], $b['count']] <=> [$a['answered'], $a['ok'], $a['count']];
        });

        $networks = [];
        foreach (self::buckets($f, 'networks') as $bucket) {
            $count = (int) ($bucket['count'] ?? 0);
            $networks[] = array_merge([
                'org'      => (string) ($bucket['val'] ?? ''),
                'count'    => $count,
                'uniq_ips' => (int) (self::num($bucket, 'uniq_ips') ?? 0),
            ], self::statusOf($bucket, $count));
        }

        return $this->envelope([
            'matched'  => (int) ($f['count'] ?? 0),
            'actors'   => $actors,
            'networks' => $networks,
            'limit'    => $limit,
        ]);
    }

    /**
     * CARD 05. Crawler impersonation — its own card, because this is the one that found it.
     *
     * A SESSIONS query, and the only one on the page. Impersonation is a claim about an IDENTITY
     * rather than about a request: a User-Agent, a reverse DNS name and a network, which the
     * session document already carries together and already has the scorer's verdict on.
     *
     * TWO KINDS, counted separately, because they are found by different means and an operator
     * should not have to guess which is which:
     *
     *  - `rdns_claim_failed`, which the SCORER already produces, covers the ten crawlers whose
     *    operators publish forward-confirmable reverse DNS. Googlebot that does not resolve to
     *    Google is this.
     *  - `atk_crawler_impersonation`, which is new here, covers the case the scorer cannot see:
     *    a named search or AI crawler answering from a GENERAL-PURPOSE CLOUD TENANT address.
     *    `OAI-SearchBot` from `7.32.89.34.bc.googleusercontent.com` is this, and it is why the
     *    page exists — no published rDNS to check against, and yet the claim is plainly false,
     *    because OpenAI's crawler does not run on somebody's Compute Engine VM.
     *
     * The roll-call beneath them is every crawler name that declared itself, with how many of
     * its sessions verified. A name with sessions and no verified ones is the row to read.
     *
     * @return array<string,mixed>
     */
    private function impersonation(): array
    {
        $f = $this->gw->facet('atk.impersonation', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'declared' => ['type' => 'query', 'q' => 'ua_bot_b:true', 'facet' => [
                'verified'   => ['type' => 'query', 'q' => 'rdns_ok_b:true'],
                'rdns_failed' => ['type' => 'query', 'q' => 'bot_reasons_ss:rdns_claim_failed'],
                'tenant'     => ['type' => 'query', 'q' => 'hit_flags_ss:atk_crawler_impersonation'],
                'names'      => [
                    'type'  => 'terms',
                    'field' => 'ua_bot_name_s',
                    'limit' => 40,
                    'sort'  => 'count desc',
                    'facet' => [
                        'verified'    => ['type' => 'query', 'q' => 'rdns_ok_b:true'],
                        'rdns_failed' => ['type' => 'query', 'q' => 'bot_reasons_ss:rdns_claim_failed'],
                        'tenant'      => ['type' => 'query', 'q' => 'hit_flags_ss:atk_crawler_impersonation'],
                        'uniq_ips'    => 'unique(ip_s)',
                        'hits'        => 'sum(hits_i)',
                        'last'        => 'max(ts_end)',
                        'cat'         => ['type' => 'terms', 'field' => 'ua_bot_cat_s', 'limit' => 1],
                    ],
                ],
            ]],
        ]);

        $declared = is_array($f['declared'] ?? null) ? $f['declared'] : [];

        $rows = [];
        foreach (self::buckets($declared, 'names') as $bucket) {
            $sessions = (int) ($bucket['count'] ?? 0);
            $cats = self::buckets($bucket, 'cat');
            $rows[] = [
                'name'        => (string) ($bucket['val'] ?? ''),
                'category'    => (string) ($cats[0]['val'] ?? 'other'),
                'sessions'    => $sessions,
                'verified'    => self::qcount($bucket, 'verified'),
                'rdns_failed' => self::qcount($bucket, 'rdns_failed'),
                'tenant'      => self::qcount($bucket, 'tenant'),
                'uniq_ips'    => (int) (self::num($bucket, 'uniq_ips') ?? 0),
                'hits'        => self::num($bucket, 'hits'),
                'last'        => is_string($bucket['last'] ?? null) ? $bucket['last'] : null,
            ];
        }

        usort($rows, static function (array $a, array $b): int {
            $an = $a['rdns_failed'] + $a['tenant'];
            $bn = $b['rdns_failed'] + $b['tenant'];
            return [$bn, $b['sessions']] <=> [$an, $a['sessions']];
        });

        /* THE ONE SESSIONS-PLANE CARD ON A HITS-PLANE VIEW, so it reports the other plane's
           drops. envelope() below defaults every card to ignoredHitFilters(), which can never
           name a status filter because a status is not a sessions field at all — so with
           `status_i` active this card quietly answered a different question from the five
           around it and declared nothing ignored. `+` keeps the left operand's key, which is
           what lets a card override the default. */
        return $this->envelope([
            'declared'        => (int) ($declared['count'] ?? 0),
            'verified'        => self::qcount($declared, 'verified'),
            'rdns_failed'     => self::qcount($declared, 'rdns_failed'),
            'tenant'          => self::qcount($declared, 'tenant'),
            'crawlers'        => $rows,
            'filters_ignored' => $this->ignoredSessionFilters(),
        ]);
    }

    /**
     * CARD 06. When — so a burst is visible AS a burst.
     *
     * Two series over the same buckets: everything that matched a pattern, and the subset the
     * server answered. One line rising while the other stays flat is the ordinary state of the
     * internet; the two rising together is the thing to look at. Drawn from one range facet, so
     * the two series can never be out of step with each other.
     *
     * @return array<string,mixed>
     */
    private function when(): array
    {
        $f = $this->gw->facet('atk.when', $this->gw->hitsCore(), [
            'q'  => '*:*',
            'fq' => $this->attackFqs(),
        ], [
            'over_time' => [
                'type'  => 'range',
                'field' => 'ts',
                'start' => $this->range['start'],
                'end'   => 'NOW',
                'gap'   => $this->range['gap'],
                'facet' => [
                    'answered' => ['type' => 'query', 'q' => self::FQ_ANSWERED],
                    'uniq_ips' => 'unique(ip_s)',
                ],
            ],
        ]);

        $times = [];
        $matched = [];
        $answered = [];
        $ips = [];
        foreach (self::buckets($f, 'over_time') as $bucket) {
            $times[] = (string) ($bucket['val'] ?? '');
            $matched[] = (int) ($bucket['count'] ?? 0);
            $answered[] = self::qcount($bucket, 'answered');
            $ips[] = (int) (self::num($bucket, 'uniq_ips') ?? 0);
        }

        return $this->envelope([
            'total'    => (int) ($f['count'] ?? 0),
            'times'    => $times,
            'matched'  => $matched,
            'answered' => $answered,
            'ips'      => $ips,
        ]);
    }

    public function body(): void
    {
        $this->answeredCard();
        $this->patternsCard();
        $this->requestsCard();
        $this->whoCard();
        $this->impersonationCard();
        $this->whenCard();
        $this->attackPivotCard();
        $this->explainCard();
    }

    /** CARD 01. The headline, and the honest coverage line under it. */
    private function answeredCard(): void
    {
        self::cardOpen(
            'atk-answered',
            $this->cardNumber('atk-answered'),
            'What the server answered',
            'Requests in range that matched a detection pattern, counted by what the server replied '
            . 'with. The four classes are counted separately and are never added together.'
        );
        self::skeleton('atk-answered', 'stats', 0, 'Correlating matched requests with response codes');

        echo '<div class="split-card">';

        echo '<div class="split-half split-evasive">';
        echo '<h2>Answered</h2>';
        echo '<p class="split-note">The server returned a body or a redirect. <strong>That does not '
            . 'prove a disclosure</strong> — a site whose error page carries a 200 status looks exactly '
            . 'like this in a log. It is where to start looking, not what to conclude.</p>';
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="status_ok">—</span>'
            . '<span class="stat-label">Answered 2xx</span></div>';
        echo '<div><span class="stat-value mono" data-field="status_redirect">—</span>'
            . '<span class="stat-label">Redirected 3xx</span></div>';
        echo '<div><span class="stat-value mono" data-field="status_broke">—</span>'
            . '<span class="stat-label">Server error 5xx</span></div>';
        echo '</div></div>';

        echo '<div class="split-half split-declared">';
        echo '<h2>Refused</h2>';
        echo '<p class="split-note">The server declined: not found, forbidden, unauthorised. This is '
            . 'the webserver doing its job, and on any address on the public internet it is almost '
            . 'all of the traffic on this page.</p>';
        /* TWO WHOLE-CARD TOTALS WERE PARKED UNDER "Refused" TO BALANCE THE LAYOUT, and a tile
           takes its population from the heading above it. "Matched in all" and "Distinct
           addresses" count every matched request and every address on the card — not the
           refused subset — so under that heading they read as a claim about refusals and were
           wrong by a factor of whatever the answered share happens to be. They belong in the
           block below with the other card-wide figures, where every tile also carries a hint
           saying what it counts. The Refused half keeps the one figure that is about refusals. */
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="status_refused">—</span>'
            . '<span class="stat-label">Refused 4xx</span></div>';
        echo '</div></div>';

        echo '</div>';

        echo '<div class="stats">';
        foreach ([
            ['matched',     'Matched, all classes', 'Every request in range that matched a pattern, whatever the server answered'],
            ['uniq_ips',    'Distinct addresses',   'Addresses behind those matched requests, across all four status classes'],
            ['evaluated',   'Requests evaluated',  'Requests the detector has actually looked at'],
            ['unevaluated', 'Never evaluated',     'Indexed before detection existed. NOT the same as clean'],
            ['uniq_patterns', 'Distinct patterns', 'How many of the named patterns appeared at all'],
            ['last',        'Most recent match',   'The last request in range that matched anything'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';

        echo '<p class="note" id="atk-coverage"></p>';

        self::cardClose('atk-answered');
    }

    /** CARD 02. Patterns, ordered by what the server answered. */
    private function patternsCard(): void
    {
        self::cardOpen(
            'atk-patterns',
            $this->cardNumber('atk-patterns'),
            'What is being tried',
            'Grouped by PATTERN, not by request string — every probe is unique, so a list of exact '
            . 'strings would be a list of one-hit wonders. Ordered by how many attempts the server '
            . 'answered, so the rows that matter are at the top whatever their volume.',
            $this->exportTool('patterns')
        );
        self::skeleton('atk-patterns', 'chart', 360, 'Faceting detection patterns against status codes');

        echo '<div class="chart" id="atk-patterns-chart" style="height:360px"></div>';
        echo '<div class="table-wrap"><table id="atk-patterns-table" class="table-fixed"><colgroup>'
            . '<col style="width:28%"><col style="width:12%">'
            . '<col style="width:11%"><col style="width:11%"><col style="width:12%">'
            . '<col style="width:12%"><col style="width:14%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Pattern</th>'
            . '<th scope="col" class="num">Answered</th>'
            . '<th scope="col" class="num">Redirected</th>'
            . '<th scope="col" class="num">Refused</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Addresses</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('atk-patterns');
    }

    /** CARD 03. The answered requests themselves. */
    private function requestsCard(): void
    {
        self::cardOpen(
            'atk-requests',
            $this->cardNumber('atk-requests'),
            'The requests the server answered',
            'Individual requests that matched a pattern AND were answered with a 2xx or a 3xx — the '
            . 'small set worth a person\'s time. Every path and query string here was chosen by '
            . 'whoever sent it; do not paste one into a shell.',
            $this->exportTool('requests')
        );
        self::skeleton('atk-requests', 'rows', 0, 'Reading the answered requests');

        /* THE OPENER COLUMN, which this table did not have. Its rows open the session that
           made the request — identity.js documents that as the drill-through that makes a URL
           actionable — and the only thing saying so was a `title` on the <tr>. Every other
           drillable table in the panel ends in one explicit control with an accessible name,
           and a row that does something on click with no visible affordance is a control
           nobody finds. Widths re-cut so the colgroup still sums to 100. */
        /* THE SAME FIVE COLUMNS EVERY OTHER TABLE OF EVENTS IN THIS PANEL SHOWS: date, address,
           country, page, verdict. The method and the byte count left — both are on the row's own
           request and both are in the visit the row opens — and the two columns that carry this
           page's entire argument were MERGED rather than dropped: what the server answered and
           which pattern matched are one judgement about one request, which is what a verdict is
           here, and they share the fifth column. */
        echo '<div class="table-wrap"><table id="atk-requests-table" class="table-fixed visits"><colgroup>'
            . '<col style="width:17%"><col style="width:15%"><col style="width:14%">'
            . '<col style="width:33%"><col style="width:21%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Date</th>'
            . '<th scope="col">IP</th>'
            . '<th scope="col">Country</th>'
            . '<th scope="col">Page</th>'
            . '<th scope="col" class="visit-verdict">Verdict</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div id="atk-requests-pager"></div>';

        self::cardClose('atk-requests');
    }

    /** CARD 04. Addresses and networks. */
    private function whoCard(): void
    {
        self::cardOpen(
            'atk-who',
            $this->cardNumber('atk-who'),
            'Who is doing it',
            'Addresses whose requests matched a pattern, ordered by how many of them the server '
            . 'answered. An address is not a person: one host can carry many clients, and one '
            . 'campaign can rent many hosts — the network column and the Fingerprints view are '
            . 'where that question is actually answered.',
            $this->exportTool('actors')
        );
        self::skeleton('atk-who', 'rows', 0, 'Faceting addresses and networks');

        echo '<div class="table-wrap"><table id="atk-who-table" class="table-fixed"><colgroup>'
            . '<col style="width:18%"><col style="width:24%"><col style="width:11%">'
            . '<col style="width:11%"><col style="width:11%"><col style="width:11%">'
            . '<col style="width:14%"></colgroup><thead><tr>'
            . '<th scope="col">Address</th>'
            . '<th scope="col">Network</th>'
            . '<th scope="col" class="num">Answered</th>'
            . '<th scope="col" class="num">Refused</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Patterns</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        echo '<div class="table-wrap"><table id="atk-networks-table" class="table-fixed"><colgroup>'
            . '<col style="width:42%"><col style="width:15%"><col style="width:15%">'
            . '<col style="width:14%"><col style="width:14%"></colgroup><thead><tr>'
            . '<th scope="col">Network</th>'
            . '<th scope="col" class="num">Answered</th>'
            . '<th scope="col" class="num">Refused</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Addresses</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('atk-who');
    }

    /** CARD 05. Impersonation, as its own card. */
    private function impersonationCard(): void
    {
        self::cardOpen(
            'atk-impersonation',
            $this->cardNumber('atk-impersonation'),
            'Crawlers that are not what they say',
            'Sessions whose User-Agent declared a named crawler. Verified means forward-confirmed '
            . 'reverse DNS backed the claim up. A name with sessions and none verified is an '
            . 'impersonator, not a crawler.'
        );
        self::skeleton('atk-impersonation', 'rows', 0, 'Checking declared crawler claims');

        echo '<div class="stats">';
        foreach ([
            ['declared',    'Declared a crawler', 'Sessions whose User-Agent named a bot'],
            ['verified',    'Claim verified',     'Forward-confirmed reverse DNS backed the name up'],
            ['rdns_failed', 'rDNS check failed',  'A crawler whose operator publishes rDNS, and it did not match'],
            ['tenant',      'On a rented cloud VM', 'A named search or AI crawler answering from general-purpose cloud tenant space'],
        ] as [$key, $label, $hint]) {
            echo '<div class="stat"><span class="stat-label">' . Security::esc($label) . '</span>';
            echo '<span class="stat-value mono" data-field="' . Security::esc($key) . '">—</span>';
            echo '<span class="stat-hint">' . Security::esc($hint) . '</span></div>';
        }
        echo '</div>';

        echo '<div class="table-wrap"><table id="atk-crawlers-table" class="table-fixed"><colgroup>'
            . '<col style="width:22%"><col style="width:15%"><col style="width:11%">'
            . '<col style="width:11%"><col style="width:12%"><col style="width:12%">'
            . '<col style="width:17%"></colgroup><thead><tr>'
            . '<th scope="col">Crawler</th>'
            . '<th scope="col">Category</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Verified</th>'
            . '<th scope="col" class="num">rDNS failed</th>'
            . '<th scope="col" class="num">Cloud tenant</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('atk-impersonation');
    }

    /** CARD 06. The timeline. */
    private function whenCard(): void
    {
        self::cardOpen(
            'atk-when',
            $this->cardNumber('atk-when'),
            'When',
            'Matched requests over the selected range, with the answered subset drawn beneath them. '
            . 'One line rising alone is ordinary background probing; both rising together is a burst '
            . 'worth opening.'
        );
        self::skeleton('atk-when', 'chart', 300, 'Bucketing matched requests over time');
        echo '<div class="chart" id="atk-when-chart" style="height:300px"></div>';
        self::cardClose('atk-when');
    }

    /**
     * CARD 07. The cross-tab, which is the page's whole claim in one grid.
     *
     * Rendered here rather than through Controller::pivotCard() because that helper draws its
     * rows from Query::pivots() and the sessions-plane facet layer; this pivot is computed
     * inside patterns() on the HITS plane, arrives on that card's payload, and its outer values
     * are rule codes that have to be spoken through the rule table rather than through a
     * dimension label.
     */
    private function attackPivotCard(): void
    {
        $pivot = Query::pivots()['attacks'] ?? null;
        $question = is_array($pivot) ? (string) ($pivot[2] ?? '') : '';

        self::cardOpen(
            'atk-pivot',
            $this->cardNumber('atk-pivot'),
            'Pattern by status class',
            $question,
            $this->exportTool('pivot')
        );
        self::skeleton('atk-pivot', 'rows', 0, 'Cross-tabulating patterns by status class');

        echo '<div class="table-wrap"><table id="atk-pivot-table" class="table-fixed pivot">'
            . '<colgroup><col style="width:32%"><col style="width:12%"><col style="width:56%"></colgroup>'
            . '<thead><tr>'
            . '<th scope="col">Attack pattern</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col">Status class</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('atk-pivot');
    }

    /**
     * CARD 08. What this page does not claim, and every pattern's failure modes.
     *
     * NOT AN APPENDIX. A security page that implies completeness is worse than none, and this
     * product's stated position on bot detection is that a detector which guesses is worse than
     * no detector because people believe it. So the misses and the over-reports are rendered on
     * the page, from the same table that produced the findings, rather than being left in
     * documentation the reader would have to go and find.
     */
    private function explainCard(): void
    {
        self::cardOpen('atk-explain', $this->cardNumber('atk-explain'), 'What this page does not claim');

        echo '<div class="explain">';
        echo '<p><strong>Loghound is not a firewall and blocked none of this.</strong> It reads the '
            . 'access log after the fact. Every request on this page was served — or refused — by the '
            . 'webserver long before Loghound saw the line. Nothing here was stopped, prevented or '
            . 'protected against, and no number on this page should be read as though it had been.</p>';
        echo '<p><strong>A 2xx does not prove a disclosure.</strong> It proves the server returned a '
            . 'body. A site that serves its error page with a 200 status — a single-page-app shell, a '
            . 'CMS catch-all route, a misconfigured ErrorDocument — is indistinguishable in a log from '
            . 'one that handed over its environment. The only way to know is to fetch the URL and look '
            . 'at what comes back. That is why this page leads with the answered requests and their '
            . 'exact paths rather than with a verdict.</p>';
        echo '<p><strong>A 404 is not nothing, it is just not an incident.</strong> Every address on '
            . 'the public internet collects thousands of these a day from untargeted scanners. They are '
            . 'worth knowing about in aggregate — a hundred distinct paths from one address in ten '
            . 'seconds is a scanner, whatever the status codes say — and they are worth almost nothing '
            . 'individually. The ordering on this page reflects that.</p>';
        echo '<p><strong>Detection runs at ingest, so it can only speak for what it was there for.</strong> '
            . 'A request indexed before this feature existed carries no verdict at all, and the coverage '
            . 'line on the first card says how many of those are in the selected range. "No attacks" over '
            . 'a period the detector was not running is not a finding.</p>';
        echo '<p><strong>The request line is all there is.</strong> An access log records the method, '
            . 'the path and the query string. It does not record the request body, so injection through '
            . 'a POST — which is where most real injection goes — is invisible here, and it does not '
            . 'record headers, so a payload in a User-Agent or a Referer is invisible too unless the '
            . 'log format captures them. Nothing on this page should be read as a survey of what was '
            . 'attempted, only of what was attempted where a log can see it.</p>';
        echo '</div>';

        echo '<div class="table-wrap"><table id="atk-rules-table" class="table-fixed"><colgroup>'
            . '<col style="width:18%"><col style="width:10%"><col style="width:24%">'
            . '<col style="width:24%"><col style="width:24%"></colgroup><thead><tr>'
            . '<th scope="col">Pattern</th>'
            . '<th scope="col">Family</th>'
            . '<th scope="col">What it matches</th>'
            . '<th scope="col">What it misses</th>'
            . '<th scope="col">What it over-reports</th>'
            . '</tr></thead><tbody>';

        $families = Rules::families();
        foreach (Rules::RULES as $code => $rule) {
            echo '<tr>';
            echo '<td>' . Security::esc($rule['label'])
                . '<br><code class="mono muted">' . Security::esc($code) . '</code></td>';
            echo '<td>' . Security::esc($families[$rule['family']] ?? $rule['family']) . '</td>';
            echo '<td>' . Security::esc($rule['what']) . '</td>';
            echo '<td>' . Security::esc($rule['misses']) . '</td>';
            echo '<td>' . Security::esc($rule['over']) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table></div>';
        self::cardEnd();
    }
}
