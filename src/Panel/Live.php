<?php
/**
 * Loghound — the log as it is written.
 *
 * Every other view in this panel is history: a range, an aggregate, a conclusion reached after
 * the fact. This one answers the only question none of them can — what is happening now — and
 * it is also the shortest explanation of the product there is. A line arrives, and beside it is
 * what Loghound made of it.
 *
 * ---------------------------------------------------------------------------------
 * WHAT A ROW CLAIMS, AND WHAT IT REFUSES TO
 * ---------------------------------------------------------------------------------
 * A verdict belongs to a SESSION. It is a correlation over many requests, scored once the
 * session settles, and this page has seen one request. So no row on it carries a verdict, and
 * no row ever will. What a row carries is what the line itself shows — a declared crawler in
 * the User-Agent, a path that matched a named pattern, a status the server returned, a
 * sub-resource rather than a page — every one of which is checkable against the bytes on
 * screen.
 *
 * The other half, what the index already knows about this client, is real and is worth having,
 * so it is in the dialog: settled verdicts from sessions that have already been scored,
 * fetched on demand, under its own heading, never mixed into the row. Two planes, two
 * headings, and the words on each say which one they belong to.
 *
 * ---------------------------------------------------------------------------------
 * THE TRANSPORT, AND WHAT BOUNDS IT
 * ---------------------------------------------------------------------------------
 * Server-sent events. One connection, the browser reconnects on its own, and the event id is
 * the cursor — so a reconnect resumes where the last one stopped rather than skipping whatever
 * arrived in between.
 *
 * A stream holds a PHP-FPM worker for as long as it is open, and the shipped pool has eight of
 * them, so it is bounded twice. The server ends every connection after MAX_SECONDS, which is
 * inside the pool's own execution limit and is invisible to the reader because EventSource
 * reconnects by itself. The browser stops asking altogether after its own watch limit, and
 * says so with a control to resume. A heartbeat goes down the wire whether or not there is
 * traffic, so a connection that has died is noticed rather than sat on.
 *
 * ---------------------------------------------------------------------------------
 * WHICH FILES ARE READ
 * ---------------------------------------------------------------------------------
 * The ones in `sources`, resolved by \Loghound\Live\Reader through the same guards the ingest
 * daemon uses, and never anything a request parameter named. The reader opens them read-only,
 * moves no cursor and writes nothing: the tailer is reading the same bytes and must not have
 * the ground moved under it.
 *
 * A HOST IS NOT A FILE, so the host selector filters the parsed LINE. One file can carry many
 * virtual hosts and one host can be spread over several files; filtering on the filename would
 * be wrong in both directions.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Live\Reader;
use Loghound\Security;

final class Live extends Controller
{
    /**
     * One card, so the view is one page and an ordinary link in the navigation.
     *
     * @var array<int,array{0:string,1:string}>
     */
    public const SECTIONS = [
        ['lv-stream', 'Live stream'],
    ];

    /** Seconds one connection is held before the server ends it and the browser reconnects. */
    private const MAX_SECONDS = 45;

    /** Pause between reads of the log files. */
    private const POLL_US = 400000;

    /** Seconds of silence before the stream says out loud that it is alive and the log is quiet. */
    private const HEARTBEAT_SEC = 12;

    /**
     * Seconds of silence before a bare comment goes down the wire.
     *
     * Two different intervals because they answer to two different readers. The heartbeat above
     * is for the operator: it carries how far behind the stream is and refreshes the state line.
     * This one is for whatever sits between the browser and PHP — a reverse proxy with an idle
     * read timeout will close a connection that has said nothing for thirty seconds, and the
     * page would report a dropped connection on a perfectly healthy quiet site. A comment is one
     * line, reaches no listener, and keeps the socket warm.
     */
    private const KEEPALIVE_SEC = 4;

    /**
     * The shapes `ip_s` can legitimately hold, and the only ones that are looked up.
     *
     * Three, and \Loghound\Security::applyIpPrivacy() is where they come from: the address
     * itself under `full`, a `203.0.113.0/24` or `2001:db8::/48` prefix under `truncate`, and a
     * keyed hex digest under `hash`. All of them fit hex digits, dots, colons and a slash.
     *
     * A value outside that set is a malformed `remote_addr` the parser passed through — a log
     * line can carry anything in that column — and there is no client behind it to look up. It
     * is refused HERE rather than bound and sent, because \Loghound\Solr refuses a local-param
     * sequence anywhere in a filter and would answer with a transport error, which reads as "the
     * panel is broken" rather than as "that is not an address".
     */
    private const ADDRESS_RE = '/^[0-9a-fA-F:.\/]{1,64}$/D';

    /**
     * Which page-toolbar controls this view honours.
     *
     * The host selector, and only that. The stream filters its lines by the selected host and
     * the dialog's index lookup goes through `$this->facets->fqs(['host_s'])`, so the chip
     * narrows both planes of this page.
     *
     * NOT THE TIME RANGE, because this page is the present tense and a picker offering 90 days
     * over a live tail would be a control that cannot mean anything. NOT THE FILTER BAR: its
     * dimensions are session conclusions, and a session conclusion cannot be applied to a line
     * that arrived a second ago — which is the same claim this whole page refuses to make.
     * NOT THE CACHE: nothing here is cached, and a button that discarded nothing while saying
     * it had is the defect that declaration exists to prevent.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_HOST];
    }

    public function slug(): string
    {
        return 'live';
    }

    public function title(): string
    {
        return 'Live';
    }

    public function subtitle(): string
    {
        return 'The access log as it is written, translated on the way past.';
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'stream' => $this->stream(),
            'client' => $this->client(),
            default  => ['error' => 'Unknown action'],
        };
    }

    /**
     * The hosts the operator has selected, as plain strings.
     *
     * Read from the facet layer rather than from `$_GET`, so the selection is the same one
     * every other view is scoped by and the allowlisting has already happened.
     *
     * @return array<int,string>
     */
    private function selectedHosts(): array
    {
        $flat = $this->facets->flat();
        return array_values(array_filter(
            (array) ($flat[Query::HOST_FIELD] ?? []),
            static fn ($h): bool => is_string($h) && $h !== ''
        ));
    }

    /**
     * Hold the connection open and send each line as it lands.
     *
     * NEVER RETURNS. The front controller's JSON path is for a payload; this is a response with
     * a shape of its own, so it writes its own headers and exits. It is still a GET on the same
     * authenticated route as every other action, behind the same Security::requireAuth() the
     * front controller applied before this method could be reached.
     *
     * The output buffers are unwound before the first byte, because an event that sits in a
     * buffer is not an event. Three things can hold one and all three are addressed here:
     * PHP's own buffers, zlib compression when an operator has turned it on globally, and
     * nginx, which buffers a FastCGI response by default until `X-Accel-Buffering` says not to.
     *
     * @return array<string,mixed>
     */
    private function stream(): array
    {
        $reader = new Reader($this->cfg, $this->selectedHosts());
        $reader->open($this->requestedCursor());

        ignore_user_abort(false);
        @ini_set('zlib.output_compression', '0');
        while (ob_get_level() > 0) {
            ob_end_flush();
        }

        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-store, no-transform, private');
        header('X-Accel-Buffering: no');
        header('Connection: keep-alive');

        echo "retry: 3000\n\n";
        self::event('hello', [
            'watching' => $reader->watching(),
            'open'     => $reader->openCount(),
            'sources'  => $reader->sourceCount(),
            'hosts'    => $this->selectedHosts(),
            'seconds'  => self::MAX_SECONDS,
        ], $reader->cursor());
        self::push();

        $deadline = microtime(true) + self::MAX_SECONDS;
        $spoke = microtime(true);
        $wrote = microtime(true);

        while (microtime(true) < $deadline) {
            if (connection_aborted() !== 0) {
                break;
            }

            $batch = $reader->poll();
            $now = microtime(true);

            if ($batch['rows'] !== []) {
                self::event('lines', [
                    'rows'     => $batch['rows'],
                    'lag'      => $batch['lag'],
                    'unparsed' => $batch['unparsed'],
                    'why'      => $batch['unparsed_why'],
                    'dropped'  => $batch['dropped'],
                ], $batch['cursor']);
                self::push();
                $spoke = $wrote = $now;
            } elseif ($now - $spoke >= self::HEARTBEAT_SEC) {
                self::event('quiet', [
                    'lag'      => $batch['lag'],
                    'unparsed' => $batch['unparsed'],
                    'why'      => $batch['unparsed_why'],
                ], $batch['cursor']);
                self::push();
                $spoke = $wrote = $now;
            } elseif ($now - $wrote >= self::KEEPALIVE_SEC) {
                echo ":\n\n";
                self::push();
                $wrote = $now;
            }

            usleep(self::POLL_US);
        }

        self::event('pause', ['cursor' => $reader->cursor()], $reader->cursor());
        self::push();
        $reader->close();
        exit;
    }

    /**
     * The cursor the browser is resuming from.
     *
     * EventSource puts the last id it saw in `Last-Event-ID` by itself; the explicit Resume
     * control passes `cursor` instead, because a stream the reader stopped on purpose is a
     * fresh EventSource with no memory of the previous one. Both are untrusted and both are
     * validated inside the reader, which will not follow anything that does not resolve to a
     * file it already chose from the configuration.
     */
    private function requestedCursor(): string
    {
        $header = $_SERVER['HTTP_LAST_EVENT_ID'] ?? '';
        if (is_string($header) && $header !== '') {
            return $header;
        }
        $param = $_GET['cursor'] ?? '';
        return is_string($param) ? $param : '';
    }

    /**
     * Write one event.
     *
     * Every value goes through json_encode, so a User-Agent full of newlines cannot forge an
     * event boundary and a path full of angle brackets cannot do anything if this payload is
     * ever rendered somewhere it should not be. The id is the reader's cursor, which is digits
     * and punctuation by construction.
     *
     * The opening event is `hello` rather than `open`, because EventSource fires an `open` of its
     * own with no payload and two events of one name on one connection is a listener that has to
     * tell them apart by whether the data parsed.
     *
     * @param array<string,mixed> $data
     */
    private static function event(string $name, array $data, string $id = ''): void
    {
        if ($id !== '') {
            echo 'id: ' . $id . "\n";
        }
        echo 'event: ' . $name . "\n";
        echo 'data: ' . (string) json_encode(
            $data,
            JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
            | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        ) . "\n\n";
    }

    /** Get what has been written onto the wire rather than into a buffer. */
    private static function push(): void
    {
        if (ob_get_level() > 0) {
            @ob_flush();
        }
        @flush();
    }

    /**
     * What the index already knows about the client a row named.
     *
     * THE OTHER PLANE, ASKED ON DEMAND. This is the half the stream deliberately does not
     * carry: sessions that have been scored, with verdicts that are real conclusions rather
     * than readings of one line. It is a separate request because it is a separate claim, and
     * because a Solr round trip inside the tail loop would stall the thing the page exists to
     * do.
     *
     * The address is bound through Query::term(), never spliced. It arrived from a log line, so
     * it is attacker-chosen bytes by definition; under `privacy.ip_mode` it may not even be an
     * address, which is another reason nothing here assumes a shape for it.
     *
     * Scoped by the host chip when one is set, on the same reasoning as every other page: a
     * narrowed page shows narrowed numbers, and the dialog says which it is.
     *
     * @return array<string,mixed>
     */
    private function client(): array
    {
        $ip = self::text('ip', 64);
        if ($ip === '') {
            return ['error' => 'No client was named.'];
        }
        if (preg_match(self::ADDRESS_RE, $ip) !== 1) {
            return ['error' => 'That is not the shape of a client address, so there is nothing to look up.'];
        }

        $hosts = $this->selectedHosts();
        $scope = array_merge(
            [self::FQ_SESSION_DOCS, Query::term('ip_s', $ip)],
            $this->facets->fqs(['host_s'])
        );

        $facets = $this->gw->facet('live.client', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $scope,
        ], [
            'verdicts' => [
                'type'     => 'terms',
                'field'    => 'bot_verdict_s',
                'limit'    => 8,
                'mincount' => 1,
                'sort'     => 'count desc',
            ],
            'classes' => [
                'type'     => 'terms',
                'field'    => 'bot_class_s',
                'limit'    => 8,
                'mincount' => 1,
                'sort'     => 'count desc',
            ],
            'settled' => ['type' => 'query', 'q' => Query::SETTLED_SESSIONS],
            'first'   => ['type' => 'query', 'q' => '*:*', 'facet' => ['at' => 'min(ts_start)']],
        ]);

        $start = Paging::start();
        $rows = Paging::rows();

        $res = $this->gw->select('live.visits', $this->gw->sessionsCore(), [
            'q'     => '*:*',
            'fq'    => $scope,
            'sort'  => 'ts_start desc',
            'rows'  => $rows,
            'start' => $start,
            'fl'    => Query::sessionFl(),
        ]);

        $visits = [];
        foreach ($res['docs'] as $doc) {
            $visits[] = self::shapeVisit($doc);
        }

        return [
            'ip'       => $ip,
            'scope'    => $hosts === [] ? '' : implode(', ', $hosts),
            'sessions' => (int) ($facets['count'] ?? 0),
            'settled'  => self::qcount($facets, 'settled'),
            'first'    => self::firstSeen($facets),
            'verdicts' => self::countedBuckets($facets, 'verdicts'),
            'classes'  => self::countedBuckets($facets, 'classes'),
            'visits'   => $visits,
            'page'     => Paging::block($start, $rows, (int) $res['numFound'], 'visits', count($visits)),
            'demo'     => $this->gw->isDemo(),
            'error'    => $this->gw->error(),
        ];
    }

    /**
     * When this client was first seen, or null when it has never been.
     *
     * Null rather than a date-shaped placeholder: "no session has this address" is a finding
     * the dialog states in words, and a fabricated instant would be a wrong number.
     *
     * @param array<string,mixed> $facets
     */
    private static function firstSeen(array $facets): ?string
    {
        $node = $facets['first'] ?? null;
        if (!is_array($node) || (int) ($node['count'] ?? 0) === 0) {
            return null;
        }
        $at = $node['at'] ?? null;
        return is_string($at) && $at !== '' ? $at : null;
    }

    /**
     * A terms facet as a plain value/count list.
     *
     * @param array<string,mixed> $facets
     * @return array<int,array{value:string,count:int}>
     */
    private static function countedBuckets(array $facets, string $key): array
    {
        $out = [];
        foreach (self::buckets($facets, $key) as $bucket) {
            $out[] = [
                'value' => (string) ($bucket['val'] ?? ''),
                'count' => (int) ($bucket['count'] ?? 0),
            ];
        }
        return $out;
    }

    /**
     * One session document in the five-column shape assets/js/visits.js renders.
     *
     * The same keys Panel\Sessions produces, so the dialog reuses that table rather than
     * growing a sixth column of its own. No session id and no fingerprint leave here beyond
     * the id the row needs to open the visit itself.
     *
     * @param array<string,mixed> $d
     * @return array<string,mixed>
     */
    private static function shapeVisit(array $d): array
    {
        $str = static fn (string $k) => isset($d[$k]) && is_scalar($d[$k]) ? (string) $d[$k] : null;

        return [
            'id'       => (string) ($d['id'] ?? ''),
            'ts_start' => $str('ts_start'),
            'ip'       => $str('ip_s'),
            'country'  => $str('country_s'),
            'region'   => $str('region_s'),
            'city'     => $str('city_s'),
            'host'     => $str('host_s'),
            'entry'    => $str('entry_path_s'),
            'verdict'  => $str('bot_verdict_s'),
        ];
    }

    /**
     * The static skeleton.
     *
     * Rendered server-side and NOT through Controller::skeleton(), because this card has no
     * load to wait for: it has a connection, which the reader starts and stops. A progress
     * strip would be a promise of an answer that is not coming, and the refresh control every
     * async card gets would be a second, worse Resume.
     *
     * Nothing log-derived is printed here. The file list is configuration the operator typed,
     * and it still goes through Security::esc().
     */
    public function body(): void
    {
        $reader = new Reader($this->cfg, $this->selectedHosts());
        $watching = $reader->watching();

        self::cardOpen(
            'lv-stream',
            Layout::cardNum(self::SECTIONS, 'lv-stream'),
            'As it happens',
            'Requests as they reach the log, one row each.',
            '<div class="controls"><button type="button" class="small" id="lv-toggle">Pause</button></div>'
        );

        echo '<div class="live-bar">'
            . '<span class="live-state" id="lv-state" data-state="off">'
            . '<span class="live-dot" aria-hidden="true"></span>'
            . '<span id="lv-state-text">Connecting</span>'
            . '</span>'
            . '<span class="live-counts muted" id="lv-counts"></span>'
            . '</div>';

        echo '<div class="note"><p><strong>One line is not a session.</strong> A verdict is scored over '
            . 'a whole visit; the last column says what this request shows. Open a row for what the index '
            . 'already knows about the client.</p></div>';

        echo '<div class="table-wrap"><table id="lv-table" class="table-fixed live-table"><colgroup>'
            . '<col style="width:9%"><col style="width:16%"><col style="width:15%">'
            . '<col style="width:29%"><col style="width:7%"><col style="width:13%">'
            . '<col style="width:11%"></colgroup><thead><tr>'
            . '<th scope="col">Time</th>'
            . '<th scope="col">Host</th>'
            . '<th scope="col">Client address</th>'
            . '<th scope="col">Request</th>'
            . '<th scope="col" class="num">Status</th>'
            . '<th scope="col">Client</th>'
            . '<th scope="col">This line</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        echo '<p class="pop" id="lv-empty-note">Waiting for the first request.</p>';

        self::watchingBlock($watching);

        self::cardEnd();
    }

    /**
     * Which files are being read, named so an empty stream is explicable.
     *
     * A live page with nothing on it has two completely different causes — nobody is visiting
     * the site, or nothing is being read — and an operator cannot tell them apart from an empty
     * table. Folded away because it is reference rather than news.
     *
     * @param array<int,array{label:string,host:?string,format:string,readable:bool}> $watching
     */
    private static function watchingBlock(array $watching): void
    {
        echo '<details class="fold live-sources"><summary>Files being read ('
            . count($watching) . ')</summary>';

        if ($watching === []) {
            echo '<p class="muted">No log source is configured, or none of the configured paths is '
                . 'readable by the panel. Settings is where the sources are listed.</p></details>';
            return;
        }

        echo '<table class="tight"><thead><tr>'
            . '<th scope="col">File</th><th scope="col">Pinned host</th>'
            . '<th scope="col">Format</th><th scope="col">Readable</th>'
            . '</tr></thead><tbody>';

        foreach ($watching as $src) {
            echo '<tr>'
                . '<td class="mono">' . Security::esc($src['label']) . '</td>'
                . '<td>' . ($src['host'] === null
                    ? '<span class="muted">every host in the line</span>'
                    : Security::esc($src['host'])) . '</td>'
                . '<td class="mono">' . Security::esc(mb_substr($src['format'], 0, 40)) . '</td>'
                . '<td>' . ($src['readable']
                    ? '<span class="state">yes</span>'
                    : '<span class="state">no</span>') . '</td>'
                . '</tr>';
        }

        echo '</tbody></table></details>';
    }
}
