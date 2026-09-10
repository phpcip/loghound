<?php
/**
 * Loghound — Bot forensics.
 *
 * The rule this view is built around, from SPEC §7: **honest crawlers are not the enemy.**
 * Googlebot and GPTBot get a `bot` verdict because they are bots, but lumping them into
 * the same red bar as a headless Chrome fleet on rotating residential proxies is exactly
 * what makes every other analytics tool useless for this. So the page is split down the
 * middle: declared crawlers on one side, evasive automation on the other, and the two
 * are never summed into a single "bot traffic" figure.
 *
 * The second thing this view owes the operator is the *why*. SPEC §1: a verdict with no
 * reasons is a bug. Every bar here is a `bot_reasons_ss` code, and every code carries the
 * plain-English description of the rule that fired it.
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
     * Kept here, in the view, rather than fetched from Score/Rules.php: the panel must
     * still explain a reason code that came from an older `rule_version_i` than the one
     * currently installed, and an unknown code falls through to being displayed raw
     * rather than hidden.
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
            'rdns_claim_failed'      => ['label' => 'rDNS claim failed', 'severity' => 'high', 'why' => 'It declared itself Googlebot/Bingbot and forward-confirmed reverse DNS did not back that up. Impersonating a crawler is not a mistake anyone makes by accident.'],
            'hosting_asn_browser_ua' => ['label' => 'Datacentre + browser UA', 'severity' => 'low', 'why' => 'A consumer browser User-Agent arriving from a hosting ASN. Weak alone — VPNs and corporate egress look like this — meaningful when stacked.'],
            'tz_mismatch'            => ['label' => 'Timezone mismatch', 'severity' => 'low', 'why' => 'The browser timezone disagrees with the timezone of the IP geolocation.'],
            'no_interaction'         => ['label' => 'No interaction', 'severity' => 'med', 'why' => 'The beacon ran, the session ended, and not one scroll, click or keypress ever happened.'],
            'no_304_on_repeat'       => ['label' => 'No conditional requests', 'severity' => 'low', 'why' => 'The same assets were fetched again with no If-None-Match/If-Modified-Since. A browser cache would have asked.'],
            'periodic_timing'        => ['label' => 'Periodic timing', 'severity' => 'med', 'why' => 'The gaps between requests are too regular across four or more requests. People are not metronomes.'],
            'single_page_10s'        => ['label' => 'Single page, under 10s', 'severity' => 'low', 'why' => 'One page, gone in under ten seconds. Very weak on its own; a bounce looks the same.'],
            'no_assets'              => ['label' => 'No sub-resources', 'severity' => 'med', 'why' => 'HTML was fetched and not a single stylesheet, script, font or image followed it.'],
            'beacon_forged'          => ['label' => 'Forged beacon timing', 'severity' => 'high', 'why' => 'The claimed dwell time is impossible against the issue time of its own token. The lie is recorded rather than discarded, because the lie is the evidence.'],
            'ua_declared_bot'        => ['label' => 'Declared crawler', 'severity' => 'info', 'why' => 'It said it was a bot and it was telling the truth. Verdict bot, threat none.'],
        ];
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
     * @return array<string,mixed>
     */
    public function api(string $action): array
    {
        return match ($action) {
            'summary' => $this->summary(),
            default   => ['error' => 'Unknown action'],
        };
    }

    /**
     * One request covering verdicts, classes, reasons, the score histogram and both
     * halves of the declared/evasive split.
     *
     * @return array<string,mixed>
     */
    private function summary(): array
    {
        $facet = [
            // Verdict distribution across everything scored.
            'verdicts' => ['type' => 'terms', 'field' => 'bot_verdict_s', 'limit' => 8],

            // Class breakdown and reason bars, both restricted to bot-like sessions.
            //
            // They sit inside a `query` facet rather than using a `domain` filter,
            // because \Loghound\Solr::sanitiseFacet() accepts only `domain.excludeTags`
            // — an arbitrary domain filter is a query fragment, and that class refuses to
            // pass one it did not build. A nested query facet expresses the same
            // restriction through a `q` it does validate.
            'botlike' => ['type' => 'query', 'q' => Query::POP_BOTLIKE, 'facet' => [
                // `none` on a human session is not information, it is noise, which is why
                // this is scoped rather than faceted over everything.
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

                // The reason bars, split so the UI can show how much of each reason comes
                // from crawlers that declared themselves.
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

            // Score histogram, 5-point buckets. Shows whether the ruleset is producing a
            // confident bimodal distribution or a mush in the middle — which is how you
            // tell that weights need tuning.
            'histogram' => [
                'type'  => 'range',
                'field' => 'bot_score_f',
                'start' => 0,
                'end'   => 100,
                'gap'   => 5,
            ],

            // --- The split ---------------------------------------------------------
            'declared' => ['type' => 'query', 'q' => Query::POP_DECLARED, 'facet' => ['hits' => 'sum(hits_i)', 'uniq_ips' => 'unique(ip_s)']],
            'ai'       => ['type' => 'query', 'q' => Query::POP_AI, 'facet' => ['hits' => 'sum(hits_i)', 'uniq_ips' => 'unique(ip_s)']],
            'evasive'  => ['type' => 'query', 'q' => Query::POP_EVASIVE, 'facet' => ['hits' => 'sum(hits_i)', 'uniq_ips' => 'unique(ip_s)']],
            'human'    => ['type' => 'query', 'q' => Query::POP_HUMAN],

            // Named crawlers, from the population that self-declares. Note the domain is
            // `ua_bot_b:true` and not the verdict: a crawler that failed forward-confirmed
            // rDNS still declared itself, and it must appear here so the operator can see
            // that the claim was rejected.
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
        ];

        $f = $this->gw->facet('bots.summary', $this->gw->sessionsCore(), [
            'q'  => '*:*',
            'fq' => $this->sessionFqs(),
        ], $facet);

        // Nested facet blocks, unwrapped once so the readers below stay flat.
        $botlike = is_array($f['botlike'] ?? null) ? $f['botlike'] : [];
        $selfDeclared = is_array($f['selfdeclared'] ?? null) ? $f['selfdeclared'] : [];

        // --- Reasons ---------------------------------------------------------------
        $catalogue = self::reasonCatalogue();
        $reasons = [];
        foreach (self::buckets($botlike, 'reasons') as $b) {
            $code = (string) ($b['val'] ?? '');
            $meta = $catalogue[$code] ?? ['label' => $code, 'why' => 'No description for this rule code in this panel version.', 'severity' => 'med'];
            $count = (int) ($b['count'] ?? 0);
            $declared = self::qcount($b, 'declared');
            $reasons[] = [
                'code'      => $code,
                'label'     => $meta['label'],
                'why'       => $meta['why'],
                'severity'  => $meta['severity'],
                'count'     => $count,
                'declared'  => $declared,
                'evasive'   => max(0, $count - $declared),
                'avg_score' => self::num($b, 'score'),
                'uniq_ips'  => self::num($b, 'uniq_ips'),
            ];
        }

        // --- Verdicts / classes ----------------------------------------------------
        $verdicts = [];
        foreach (self::buckets($f, 'verdicts') as $b) {
            $verdicts[] = ['verdict' => (string) ($b['val'] ?? ''), 'count' => (int) ($b['count'] ?? 0)];
        }

        $classes = [];
        foreach (self::buckets($botlike, 'classes') as $b) {
            $classes[] = [
                'class'     => (string) ($b['val'] ?? ''),
                'count'     => (int) ($b['count'] ?? 0),
                'hits'      => self::num($b, 'hits'),
                'uniq_ips'  => self::num($b, 'uniq_ips'),
                'avg_score' => self::num($b, 'score'),
                // Which side of the split this class belongs to, decided here so the UI
                // never has to re-derive it.
                'declared'  => in_array((string) ($b['val'] ?? ''), ['declared_crawler', 'ai_crawler', 'monitor'], true),
            ];
        }

        // --- Histogram -------------------------------------------------------------
        $histogram = [];
        foreach (self::buckets($f, 'histogram') as $b) {
            $histogram[] = ['from' => (float) ($b['val'] ?? 0), 'count' => (int) ($b['count'] ?? 0)];
        }

        // --- Declared crawler table ------------------------------------------------
        $crawlers = [];
        foreach (self::buckets($selfDeclared, 'crawlers') as $b) {
            $catBuckets = self::buckets($b, 'cat');
            $crawlers[] = [
                'name'     => (string) ($b['val'] ?? ''),
                'category' => (string) ($catBuckets[0]['val'] ?? 'other'),
                'sessions' => (int) ($b['count'] ?? 0),
                'hits'     => self::num($b, 'hits'),
                'uniq_ips' => self::num($b, 'uniq_ips'),
                'last'     => is_string($b['last'] ?? null) ? $b['last'] : null,
                'ai'       => self::qcount($b, 'ai') > 0,
                'verified' => self::qcount($b, 'verified'),
            ];
        }

        $node = static fn (string $k): array => is_array($f[$k] ?? null) ? $f[$k] : [];

        return $this->envelope([
            'total'     => (int) ($f['count'] ?? 0),
            'reasons'   => $reasons,
            'verdicts'  => $verdicts,
            'classes'   => $classes,
            'histogram' => $histogram,
            'crawlers'  => $crawlers,
            'split' => [
                'declared' => ['sessions' => self::qcount($f, 'declared'), 'hits' => self::num($node('declared'), 'hits'), 'uniq_ips' => self::num($node('declared'), 'uniq_ips')],
                'ai'       => ['sessions' => self::qcount($f, 'ai'), 'hits' => self::num($node('ai'), 'hits'), 'uniq_ips' => self::num($node('ai'), 'uniq_ips')],
                'evasive'  => ['sessions' => self::qcount($f, 'evasive'), 'hits' => self::num($node('evasive'), 'hits'), 'uniq_ips' => self::num($node('evasive'), 'uniq_ips')],
                'human'    => ['sessions' => self::qcount($f, 'human')],
            ],
        ]);
    }

    public function body(): void
    {
        // ---- The split, stated before anything else --------------------------
        echo '<section class="split-card">';
        echo '<div class="split-half split-declared">';
        echo '<h2>Declared crawlers</h2>';
        echo '<p class="split-note">Told us what they were, and the claim held up. Verdict <code>bot</code>, threat none. '
            . 'They are counted separately everywhere in this panel.</p>';
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="declared_sessions">—</span><span class="stat-label">Search &amp; SEO sessions</span></div>';
        echo '<div><span class="stat-value mono" data-field="ai_sessions">—</span><span class="stat-label">AI crawler sessions</span></div>';
        echo '<div><span class="stat-value mono" data-field="declared_hits">—</span><span class="stat-label">Requests</span></div>';
        echo '</div></div>';

        echo '<div class="split-half split-evasive">';
        echo '<h2>Evasive automation</h2>';
        echo '<p class="split-note">Scored as automation and did not say so: headless browsers, scripted clients, '
            . 'spoofed User-Agents, rotating-proxy fleets. This is the half that matters.</p>';
        echo '<div class="split-stats">';
        echo '<div><span class="stat-value mono" data-field="evasive_sessions">—</span><span class="stat-label">Sessions</span></div>';
        echo '<div><span class="stat-value mono" data-field="evasive_ips">—</span><span class="stat-label">Distinct IPs</span></div>';
        echo '<div><span class="stat-value mono" data-field="evasive_hits">—</span><span class="stat-label">Requests</span></div>';
        echo '</div></div>';
        echo '</section>';

        // ---- Reason bars -------------------------------------------------------
        echo '<section class="card">';
        echo '<h2>Why each session was scored</h2>';
        self::pop('Sessions with verdict bot or likely_bot. A session fires several rules, so the bars sum to more than the session count.');
        echo '<div class="chart" id="bf-reasons" style="height:480px"></div>';
        echo '<div class="empty" id="bf-reasons-empty" hidden></div>';
        echo '<div class="table-wrap"><table id="bf-reason-table"><thead><tr>'
            . '<th scope="col">Signal</th>'
            . '<th scope="col">What it means</th>'
            . '<th scope="col" class="num">Evasive</th>'
            . '<th scope="col" class="num">Declared</th>'
            . '<th scope="col" class="num">Avg score</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '</section>';

        // ---- Verdict + class + histogram --------------------------------------
        echo '<div class="grid-2">';
        self::chart('bf-verdicts', 'Verdict distribution', 'All scored sessions in the selected range.', '280px');
        self::chart('bf-histogram', 'Score distribution', 'All scored sessions. A healthy ruleset is bimodal — a pile-up in the middle means the weights need tuning.', '280px');
        echo '</div>';

        echo '<section class="card">';
        echo '<h2>Bot classes</h2>';
        self::pop('Sessions with verdict bot or likely_bot, grouped by bot_class_s. Declared classes are marked.');
        echo '<div class="table-wrap"><table id="bf-classes"><thead><tr>'
            . '<th scope="col">Class</th>'
            . '<th scope="col">Kind</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Distinct IPs</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">Avg score</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="bf-classes-empty" hidden></div>';
        echo '</section>';

        // ---- Declared crawler roll-call ---------------------------------------
        echo '<section class="card">';
        echo '<h2>Declared crawlers, by name</h2>';
        self::pop('Sessions whose User-Agent self-identifies as a bot (ua_bot_b). Verified = forward-confirmed reverse DNS passed; an unverified Googlebot is an impersonator, not a crawler.');
        echo '<div class="table-wrap"><table id="bf-crawlers"><thead><tr>'
            . '<th scope="col">Crawler</th>'
            . '<th scope="col">Category</th>'
            . '<th scope="col" class="num">Sessions</th>'
            . '<th scope="col" class="num">Requests</th>'
            . '<th scope="col" class="num">IPs</th>'
            . '<th scope="col" class="num">Verified</th>'
            . '<th scope="col">Last seen</th>'
            . '</tr></thead><tbody></tbody></table></div>';
        echo '<div class="empty" id="bf-crawlers-empty" hidden></div>';
        echo '</section>';
    }
}
