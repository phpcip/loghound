<?php
/**
 * Loghound — Bot forensics.
 *
 * Built around the rule in SPEC §7: honest crawlers are not the enemy. Googlebot and
 * GPTBot get a `bot` verdict because they are bots, but putting them in the same bar as a
 * headless Chrome fleet on rotating residential proxies is what makes every other
 * analytics tool useless for this. So the page is split down the middle — declared
 * crawlers on one side, evasive automation on the other — and the two are never summed
 * into one "bot traffic" figure.
 *
 * The second thing the view owes the operator is the why. SPEC §1: a verdict with no
 * reasons is a bug. Every bar is a `bot_reasons_ss` code and every code carries the
 * plain-English description of the rule that fired it.
 *
 * Each section is an independent request. The reason facet over `bot_reasons_ss` is the
 * expensive one, and separating it means the split, the verdict donut and the crawler
 * roll-call are on screen long before it lands.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Bots extends Controller
{
    /**
     * Human-readable descriptions of the scoring rules from SPEC §7.
     *
     * Kept in the view rather than read from Score/Rules.php because the panel must still
     * explain a reason code produced by an older `rule_version_i` than the one currently
     * installed. An unknown code falls through to being displayed raw rather than hidden.
     *
     * @return array<string,array{label:string,why:string,severity:string}>
     */
    public static function reasonCatalogue(): array
    {
        return [
            'automation_marker'      => ['label' => 'Automation marker', 'severity' => 'high', 'why' => 'The page exposed a definitive driver artefact — navigator.webdriver, a chromedriver global, Puppeteer/Playwright/Selenium hooks. Browsers do not have these; drivers do.'],
            'headless_renderer'      => ['label' => 'Headless renderer', 'severity' => 'high', 'why' => 'WebGL reported SwiftShader, llvmpipe, Mesa OffScreen or Microsoft Basic Render: software rasterisation, which is what you get when there is no screen.'],
            'ua_claim_failed'        => ['label' => 'UA claim failed', 'severity' => 'high', 'why' => 'The User-Agent claimed a Chrome version whose engine features the page does not actually have. A spoofed UA string cannot retrofit V8.'],
            'no_js_on_html'          => ['label' => 'No JS on HTML', 'severity' => 'med', 'why' => 'An HTML page was served with a 200 and no beacon ever arrived, while the User-Agent claimed a real browser. Real browsers run scripts.'],
            'fp_cluster_proxy_fleet' => ['label' => 'Proxy fleet fingerprint', 'severity' => 'high', 'why' => 'Five or more distinct IPs shared this exact header fingerprint within 24 hours on non-mobile networks. One client, many exits.'],
            'ua_secch_mismatch'      => ['label' => 'Sec-CH-UA mismatch', 'severity' => 'high', 'why' => 'A Chrome User-Agent arrived without Sec-CH-UA, or with one that contradicts it. Chrome always sends its own client hints.'],
            'platform_mismatch'      => ['label' => 'Platform mismatch', 'severity' => 'med', 'why' => 'Sec-CH-UA-Platform disagrees with the operating system the User-Agent claims.'],
            'rdns_claim_failed'      => ['label' => 'rDNS claim failed', 'severity' => 'high', 'why' => 'It declared itself Googlebot or Bingbot and forward-confirmed reverse DNS did not back that up. Impersonating a crawler is not a mistake anyone makes by accident.'],
            'hosting_asn_browser_ua' => ['label' => 'Datacentre + browser UA', 'severity' => 'low', 'why' => 'A consumer browser User-Agent arriving from a hosting ASN. Weak alone — VPNs and corporate egress look like this — meaningful when stacked.'],
            'tz_mismatch'            => ['label' => 'Timezone mismatch', 'severity' => 'low', 'why' => 'The browser timezone disagrees with the timezone of the IP geolocation.'],
            'no_interaction'         => ['label' => 'No interaction', 'severity' => 'med', 'why' => 'The beacon ran, the session ended, and not one scroll, click or keypress ever happened.'],
            'no_304_on_repeat'       => ['label' => 'No conditional requests', 'severity' => 'low', 'why' => 'The same assets were fetched again with no If-None-Match or If-Modified-Since. A browser cache would have asked.'],
            'periodic_timing'        => ['label' => 'Periodic timing', 'severity' => 'med', 'why' => 'The gaps between requests are too regular across four or more requests. People are not metronomes.'],
            'single_page_10s'        => ['label' => 'Single page, under 10s', 'severity' => 'low', 'why' => 'One page, gone in under ten seconds. Very weak on its own; a bounce looks the same.'],
            'no_assets'              => ['label' => 'No sub-resources', 'severity' => 'med', 'why' => 'HTML was fetched and not a single stylesheet, script, font or image followed it.'],
            'beacon_forged'          => ['label' => 'Forged beacon timing', 'severity' => 'high', 'why' => 'The claimed dwell time is impossible against the issue time of its own token. The lie is recorded rather than discarded, because the lie is the evidence.'],
            'ua_declared_bot'        => ['label' => 'Declared crawler', 'severity' => 'info', 'why' => 'It said it was a bot and it was telling the truth. Verdict bot, threat none.'],
        ];
    }

    /**
     * Which page-toolbar controls this view honours.
     *
     * All six queries run under sessionFqs(), so all three controls reach them.
     *
     * @return array<int,string>
     */
    public function toolbar(): array
    {
        return [self::SCOPE_RANGE, self::SCOPE_HOST, self::SCOPE_FACETS, self::SCOPE_CACHE];
    }

    public function slug(): string
    {
        return 'bots';
    }

    public function title(): string
    {
        return 'Bot forensics';
    }

    public function subtitle(): string
    {
        return 'Every verdict, and the evidence behind it.';
    }

    /**
     * The three tables on this view worth taking out as CSV.
     *
     * The declared/evasive split above them is six headline numbers and is deliberately not
     * exportable: the two halves are counted separately and must never be summed, and a
     * spreadsheet is the first place somebody would sum them. The verdict histogram and the
     * score distribution are charts over a continuous quantity, which a top-N CSV cannot
     * represent honestly either.
     *
     * All three row limits are FIXED in the facet definitions rather than caller-settable, so
     * each export carries its card's own limit and the coverage line says whether the facet came
     * back short of it — which, for the closed signal and class vocabularies, it always does.
     *
     * @return array<string,array<string,mixed>>
     */
    public function exports(): array
    {
        return [
            'signals' => [
                'label'   => 'Signals fired',
                'action'  => 'reasons',
                'key'     => 'reasons',
                'unit'    => 'signals',
                'ranked'  => 'ranked by the number of sessions they fired on',
                'cap'     => 25,
                'note'    => 'A session fires several signals, so these counts sum to more than the '
                    . 'session total. The population is sessions judged Bot or Likely bot.',
                'scope'   => ['botlike' => 'Sessions judged Bot or Likely bot'],
                'columns' => [
                    ['Signal', 'label', 'text'],
                    ['Signal code', 'code', 'id'],
                    ['What it means', 'why', 'text'],
                    ['Severity', 'severity', 'text'],
                    ['Sessions', 'count', 'number'],
                    ['Of which declared', 'declared', 'number'],
                    ['Of which evasive', 'evasive', 'number'],
                    ['Average bot score', 'avg_score', 'number'],
                    ['Distinct IPs', 'uniq_ips', 'number'],
                ],
            ],

            'classes' => [
                'label'   => 'Bot classes',
                'action'  => 'classes',
                'key'     => 'classes',
                'unit'    => 'bot classes',
                'ranked'  => 'ranked by session count',
                'cap'     => 20,
                'scope'   => ['botlike' => 'Sessions judged Bot or Likely bot'],
                'columns' => [
                    ['Class', 'class', 'vocab', 'bot_class_s'],
                    ['Class code', 'class', 'id'],
                    ['Declared itself', 'declared', 'bool'],
                    ['Sessions', 'count', 'number'],
                    ['Distinct IPs', 'uniq_ips', 'number'],
                    ['Requests', 'hits', 'number'],
                    ['Average bot score', 'avg_score', 'number'],
                ],
            ],

            'crawlers' => [
                'label'   => 'Declared crawlers',
                'action'  => 'crawlers',
                'key'     => 'crawlers',
                'unit'    => 'crawlers',
                'ranked'  => 'ranked by session count',
                'cap'     => 40,
                'note'    => 'Verified counts the sessions whose crawler claim passed forward-confirmed '
                    . 'reverse DNS. A name with sessions and no verified ones is an impersonator.',
                'scope'   => ['declared' => 'Sessions that declared themselves'],
                'columns' => [
                    ['Crawler', 'name', 'text'],
                    ['Category', 'category', 'vocab', 'ua_bot_cat_s'],
                    ['Category code', 'category', 'id'],
                    ['AI crawler', 'ai', 'bool'],
                    ['Sessions', 'sessions', 'number'],
                    ['Requests', 'hits', 'number'],
                    ['Distinct IPs', 'uniq_ips', 'number'],
                    ['Verified sessions', 'verified', 'number'],
                    ['Last seen', 'last', 'date'],
                ],
            ],

            'pivot' => [
                'label'  => 'Bot class by network type',
                'action' => 'split',
                'shape'  => 'pivot',
                'key'    => 'pivot',
                'unit'   => 'class and network type pairs',
                'cap'    => 200,
                'note'   => 'One record per pair. The network-type breakdown of a class is a LIMITED '
                    . 'facet, so its rows do not add up to that class\'s session total.',
            ],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'split'     => $this->split(),
            'reasons'   => $this->reasons(),
            'verdicts'  => $this->verdicts(),
            'histogram' => $this->histogram(),
            'classes'   => $this->classes(),
            'crawlers'  => $this->crawlers(),
            default     => ['error' => 'Unknown action'],
        };
    }

    /**
     * The declared / evasive halves, counted separately and never summed.
     *
     * @return array<string,mixed>
     */
    private function split(): array
    {
        $counts = ['hits' => 'sum(hits_i)', 'uniq_ips' => 'unique(ip_s)'];

        $f = $this->gw->facet('bots.split', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], array_merge([
            'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED, 'facet' => $counts],
            'ai'       => ['type' => 'query', 'q' => Query::POP_AI, 'facet' => $counts],
            'evasive'  => ['type' => 'query', 'q' => Query::POP_EVASIVE, 'facet' => $counts],
            'human'    => ['type' => 'query', 'q' => Query::POP_HUMAN],
        ], $this->pivotDef(8, 5)));

        $half = function (string $key) use ($f): array {
            $node = is_array($f[$key] ?? null) ? $f[$key] : [];
            return [
                'sessions' => (int) ($node['count'] ?? 0),
                'hits'     => self::num($node, 'hits'),
                'uniq_ips' => self::num($node, 'uniq_ips'),
            ];
        };

        return $this->envelope([
            'total'    => (int) ($f['count'] ?? 0),
            'declared' => $half('declared'),
            'ai'       => $half('ai'),
            'evasive'  => $half('evasive'),
            'human'    => ['sessions' => self::qcount($f, 'human')],

            /* Bot class crossed with network type, on this request rather than one of its own. It
               answers the question the two separate facets cannot: a declared crawler on hosting
               address space is ordinary, and a headless browser on consumer broadband is not. */
            'pivot'    => $this->pivotRows($f),
        ]);
    }

    /**
     * Reason codes over bot-like sessions, split by whether the session declared itself.
     *
     * The scoping is a nested `query` facet rather than a `domain` filter because
     * Solr::sanitiseFacet() accepts only `domain.excludeTags` — an arbitrary domain filter
     * is a query fragment the client did not build, and it refuses to pass one.
     *
     * @return array<string,mixed>
     */
    private function reasons(): array
    {
        $f = $this->gw->facet('bots.reasons', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'botlike' => ['type' => 'query', 'q' => Query::POP_BOTLIKE, 'facet' => [
                'reasons' => [
                    'type'  => 'terms',
                    'field' => 'bot_reasons_ss',
                    'limit' => 25,
                    'sort'  => 'count desc',
                    'facet' => [
                        'score'    => 'avg(bot_score_f)',
                        'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED_ANY],
                        'uniq_ips' => 'unique(ip_s)',
                    ],
                ],
            ]],
        ]);

        $botlike = is_array($f['botlike'] ?? null) ? $f['botlike'] : [];
        $catalogue = self::reasonCatalogue();
        $rows = [];
        foreach (self::buckets($botlike, 'reasons') as $bucket) {
            $code = (string) ($bucket['val'] ?? '');
            $meta = $catalogue[$code] ?? [
                'label'    => $code,
                'why'      => 'No description for this rule code in this panel version.',
                'severity' => 'med',
            ];
            $count = (int) ($bucket['count'] ?? 0);
            $declared = self::qcount($bucket, 'declared');
            $rows[] = [
                'code'      => $code,
                'label'     => $meta['label'],
                'why'       => $meta['why'],
                'severity'  => $meta['severity'],
                'count'     => $count,
                'declared'  => $declared,
                'evasive'   => max(0, $count - $declared),
                'avg_score' => self::num($bucket, 'score'),
                'uniq_ips'  => self::num($bucket, 'uniq_ips'),
            ];
        }

        return $this->envelope([
            'botlike' => (int) ($botlike['count'] ?? 0),
            'reasons' => $rows,
        ]);
    }

    /**
     * Verdict distribution across everything scored.
     *
     * @return array<string,mixed>
     */
    private function verdicts(): array
    {
        $f = $this->gw->facet('bots.verdicts', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'verdicts' => ['type' => 'terms', 'field' => 'bot_verdict_s', 'limit' => 8],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'verdicts') as $bucket) {
            $rows[] = ['verdict' => (string) ($bucket['val'] ?? ''), 'count' => (int) ($bucket['count'] ?? 0)];
        }

        return $this->envelope(['total' => (int) ($f['count'] ?? 0), 'verdicts' => $rows]);
    }

    /**
     * Bot-score distribution in five-point buckets.
     *
     * Shows whether the ruleset is producing a confident bimodal split or a mush in the
     * middle, which is how an operator knows the weights need tuning.
     *
     * @return array<string,mixed>
     */
    private function histogram(): array
    {
        $f = $this->gw->facet('bots.histogram', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'histogram' => ['type' => 'range', 'field' => 'bot_score_f', 'start' => 0, 'end' => 100, 'gap' => 5],
        ]);

        $rows = [];
        foreach (self::buckets($f, 'histogram') as $bucket) {
            $rows[] = ['from' => (float) ($bucket['val'] ?? 0), 'count' => (int) ($bucket['count'] ?? 0)];
        }

        return $this->envelope(['total' => (int) ($f['count'] ?? 0), 'histogram' => $rows]);
    }

    /**
     * Bot classes, restricted to bot-like sessions.
     *
     * `none` on a human session is not information, it is noise, which is why the facet is
     * scoped rather than run over everything.
     *
     * @return array<string,mixed>
     */
    private function classes(): array
    {
        $f = $this->gw->facet('bots.classes', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'botlike' => ['type' => 'query', 'q' => Query::POP_BOTLIKE, 'facet' => [
                'classes' => [
                    'type'  => 'terms',
                    'field' => 'bot_class_s',
                    'limit' => 12,
                    'facet' => [
                        'uniq_ips' => 'unique(ip_s)',
                        'hits'     => 'sum(hits_i)',
                        'score'    => 'avg(bot_score_f)',
                    ],
                ],
            ]],
        ]);

        $botlike = is_array($f['botlike'] ?? null) ? $f['botlike'] : [];
        $rows = [];
        foreach (self::buckets($botlike, 'classes') as $bucket) {
            $value = (string) ($bucket['val'] ?? '');
            $rows[] = [
                'class'     => $value,
                'count'     => (int) ($bucket['count'] ?? 0),
                'hits'      => self::num($bucket, 'hits'),
                'uniq_ips'  => self::num($bucket, 'uniq_ips'),
                'avg_score' => self::num($bucket, 'score'),
                'declared'  => in_array($value, ['declared_crawler', 'ai_crawler', 'monitor'], true),
            ];
        }

        return $this->envelope(['botlike' => (int) ($botlike['count'] ?? 0), 'classes' => $rows]);
    }

    /**
     * Named crawlers, from the population that self-declares.
     *
     * The domain is `ua_bot_b:true` and not the verdict on purpose: a crawler that failed
     * forward-confirmed rDNS still declared itself, and it must appear here so the
     * operator can see that the claim was rejected.
     *
     * @return array<string,mixed>
     */
    private function crawlers(): array
    {
        $f = $this->gw->facet('bots.crawlers', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], [
            'selfdeclared' => ['type' => 'query', 'q' => 'ua_bot_b:true', 'facet' => [
                'crawlers' => [
                    'type'  => 'terms',
                    'field' => 'ua_bot_name_s',
                    'limit' => 25,
                    'sort'  => 'count desc',
                    'facet' => [
                        'hits'     => 'sum(hits_i)',
                        'uniq_ips' => 'unique(ip_s)',
                        'last'     => 'max(ts_end)',
                        'cat'      => ['type' => 'terms', 'field' => 'ua_bot_cat_s', 'limit' => 1],
                        'ai'       => ['type' => 'query', 'q' => 'ai_crawler_b:true'],
                        'verified' => ['type' => 'query', 'q' => 'rdns_ok_b:true'],
                    ],
                ],
            ]],
        ]);

        $declared = is_array($f['selfdeclared'] ?? null) ? $f['selfdeclared'] : [];
        $rows = [];
        foreach (self::buckets($declared, 'crawlers') as $bucket) {
            $categories = self::buckets($bucket, 'cat');
            $rows[] = [
                'name'     => (string) ($bucket['val'] ?? ''),
                'category' => (string) ($categories[0]['val'] ?? 'other'),
                'sessions' => (int) ($bucket['count'] ?? 0),
                'hits'     => self::num($bucket, 'hits'),
                'uniq_ips' => self::num($bucket, 'uniq_ips'),
                'last'     => is_string($bucket['last'] ?? null) ? $bucket['last'] : null,
                'ai'       => self::qcount($bucket, 'ai') > 0,
                'verified' => self::qcount($bucket, 'verified'),
            ];
        }

        return $this->envelope(['declared' => (int) ($declared['count'] ?? 0), 'crawlers' => $rows]);
    }

    public function body(): void
    {
        $this->splitCard();
        $this->reasonsCard();

        echo '<div class="grid-2">';
        self::chart(
            'bf-verdicts',
            '03',
            'Verdict distribution',
            'All scored sessions in the selected range.',
            300,
            'Faceting verdicts'
        );
        self::chart(
            'bf-histogram',
            '04',
            'Score distribution',
            'All scored sessions. A healthy ruleset is bimodal — a pile-up in the middle means the weights need tuning.',
            300,
            'Bucketing bot scores'
        );
        echo '</div>';

        $this->classesCard();
        $this->crawlersCard();
        $this->pivotCard('bf-pivot', '07');
    }

    /** The two halves, stated before anything else on the page. */
    private function splitCard(): void
    {
        self::cardOpen('bf-split', '01', 'Declared versus evasive');
        self::skeleton('bf-split', 'stats', 0, 'Separating declared crawlers from evasive automation');

        echo '<div class="split-card">';

        echo '<div class="split-half split-declared">';
        echo '<h2>Declared crawlers</h2>';
        echo '<p class="split-note">Told us what they were, and the claim held up. Verdict <code>bot</code>, '
            . 'threat none. They are counted separately everywhere in this panel.</p>';
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="declared_sessions">—</span>'
            . '<span class="stat-label">Search &amp; SEO</span></div>';
        echo '<div><span class="stat-value mono" data-field="ai_sessions">—</span>'
            . '<span class="stat-label">AI crawlers</span></div>';
        echo '<div><span class="stat-value mono" data-field="declared_hits">—</span>'
            . '<span class="stat-label">Requests</span></div>';
        echo '</div></div>';

        echo '<div class="split-half split-evasive">';
        echo '<h2>Evasive automation</h2>';
        echo '<p class="split-note">Scored as automation and did not say so: headless browsers, scripted clients, '
            . 'spoofed User-Agents, rotating-proxy fleets. This is the half that matters.</p>';
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="evasive_sessions">—</span>'
            . '<span class="stat-label">Sessions</span></div>';
        echo '<div><span class="stat-value mono" data-field="evasive_ips">—</span>'
            . '<span class="stat-label">Distinct IPs</span></div>';
        echo '<div><span class="stat-value mono" data-field="evasive_hits">—</span>'
            . '<span class="stat-label">Requests</span></div>';
        echo '</div></div>';

        echo '</div>';
        self::cardClose('bf-split');
    }

    /** The reason bars and the table that explains every code. */
    private function reasonsCard(): void
    {
        self::cardOpen(
            'bf-reasons',
            '02',
            'Why each session was scored',
            'Sessions judged Bot or Likely bot. A session fires several rules, so the bars sum to more than '
            . 'the session count.',
            $this->exportTool('signals')
        );
        self::skeleton('bf-reasons', 'chart', 420, 'Faceting signal codes');

        echo '<div class="chart" id="bf-reasons-chart" style="height:460px"></div>';
        echo '<div class="table-wrap"><table id="bf-reason-table" class="table-fixed"><colgroup>'
            . '<col style="width:24%"><col style="width:40%"><col style="width:12%">'
            . '<col style="width:12%"><col style="width:12%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Signal</th>'
            . '<th scope="col">What it means</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col" class="num">Declared</th>'
            . '<th scope="col" class="num">Avg score</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('bf-reasons');
    }

    /** Bot class table. */
    private function classesCard(): void
    {
        self::cardOpen(
            'bf-classes',
            '05',
            'Bot classes',
            'Sessions judged Bot or Likely bot, grouped by what kind of automation they are. '
            . 'Declared classes are marked.',
            $this->exportTool('classes')
        );
        self::skeleton('bf-classes', 'rows', 0, 'Faceting bot classes');

        echo '<div class="table-wrap"><table id="bf-classes-table" class="table-fixed"><colgroup>'
            . '<col style="width:26%"><col style="width:16%"><col style="width:14%">'
            . '<col style="width:16%"><col style="width:14%"><col style="width:14%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Class</th>'
            . '<th scope="col">Kind</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Distinct IPs</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Avg score</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('bf-classes');
    }

    /** Declared crawler roll-call. */
    private function crawlersCard(): void
    {
        self::cardOpen(
            'bf-crawlers',
            '06',
            'Declared crawlers, by name',
            'Sessions whose User-Agent self-identifies as a bot. Verified means forward-confirmed reverse DNS '
            . 'passed; an unverified Googlebot is an impersonator, not a crawler.',
            $this->exportTool('crawlers')
        );
        self::skeleton('bf-crawlers', 'rows', 0, 'Faceting crawler names');

        echo '<div class="table-wrap"><table id="bf-crawlers-table" class="table-fixed"><colgroup>'
            . '<col style="width:20%"><col style="width:16%"><col style="width:11%">'
            . '<col style="width:12%"><col style="width:9%"><col style="width:12%">'
            . '<col style="width:20%">'
            . '</colgroup><thead><tr>'
            . '<th scope="col">Crawler</th>'
            . '<th scope="col">Category</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Verified</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';

        self::cardClose('bf-crawlers');
    }
}
