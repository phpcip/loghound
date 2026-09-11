<?php
/**
 * Loghound — the scoring ruleset (SPEC §7).
 *
 * Weighted additive, 0–100, with an explicit reason code and a human-readable sentence for
 * every point added. A verdict with no reasons is a bug and this file throws on it.
 *
 * ---------------------------------------------------------------------------------------
 * WHY ADDITIVE AND NOT A MODEL
 * ---------------------------------------------------------------------------------------
 * A trained classifier would score better on a benchmark and would be useless here. The
 * product's claim is not "we detect bots", it is "we can tell you WHY this is a bot", and
 * an operator has to be able to disagree with a specific rule, change its weight, and
 * re-run. Seventeen readable rules with published weights is the feature.
 *
 * ---------------------------------------------------------------------------------------
 * WHY THESE NUMBERS
 * ---------------------------------------------------------------------------------------
 * The weights follow one principle: a weight of 80 or more is a claim that this signal
 * ALONE is enough to call something a bot, because 80 is the `bot` threshold. So the
 * question for every rule is not "how suspicious is this" but "am I willing to publish a
 * verdict on this evidence and nothing else". Seven of the seventeen clear that bar —
 * automation_marker, ua_declared_bot, rdns_claim_failed, headless_renderer, beacon_forged,
 * ua_claim_failed and fp_cluster_proxy_fleet — and each one is a fact about the client that
 * has no innocent explanation.
 *
 * Everything below 80 is designed to STACK. Three 30-point behavioural rules reaching 90
 * is the intended path for a scraper that leaves no single decisive mark, and it is why
 * the weak rules are worth having at all — `single_page_10s` at 15 is meaningless alone
 * and decisive as the third signal.
 *
 * ---------------------------------------------------------------------------------------
 * HONEST CRAWLERS ARE NOT THE ENEMY
 * ---------------------------------------------------------------------------------------
 * Googlebot and GPTBot get verdict `bot` — they are bots — and class `declared_crawler` or
 * `ai_crawler`. That classification is enforced HERE, in classify(), not left to a checkbox
 * in the UI, because every consumer of a session document (the dashboard, an export, an
 * alert) must see the same separation. Conflating a search crawler with an evasive scraper
 * is the failure that makes existing tools useless, and a UI-level filter is not a fix, it
 * is a suggestion.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Score;

final class Rules
{
    /**
     * Bumped on EVERY change to a rule condition or a default weight.
     *
     * Written onto every session as rule_version_i so a historical verdict can be traced to
     * the logic that produced it, and so a rescoring pass can find everything judged by an
     * older ruleset. Changing a weight without bumping this makes past and present verdicts
     * silently incomparable.
     *
     * The provisional gate (DEFERRED_CODES, below) deliberately did NOT bump it. A CLOSED
     * session's verdict is identical with and without that gate, byte for byte, so bumping would
     * declare the whole of a site's history incomparable with itself and send a rescoring pass
     * over all of it to no effect. What a consumer actually needs to know — "was this verdict
     * reached before the session ended" — is a property of the DOCUMENT, not of the ruleset, and
     * it is on the document as `provisional_b`.
     */
    public const RULE_VERSION = 1;

    /**
     * Rules that may not be evaluated until the session has ENDED.
     *
     * Every one of them fires on the ABSENCE of something the session may still go on to do, so
     * on an open session each is a statement about the future dressed up as evidence — and each
     * would accuse a live human visitor:
     *
     *   no_js_on_html     the beacon reports on pagehide. Someone still reading the page has
     *                     not sent one, and this is 70 points: it would call the entire live
     *                     audience of a beacon-equipped site likely_bot.
     *   no_assets         the sub-resource lines are written to the log after the HTML line,
     *                     and a scorer run can land between them.
     *   no_304_on_repeat  nothing has been re-fetched yet, and no 304 has arrived yet. Both
     *                     halves of the rule read "not yet" as "never".
     *   no_interaction    the beacon may have reported the first pageview before the visitor
     *                     scrolled or clicked. "Has not interacted yet" is not "did not".
     *   single_page_10s   at second one EVERY session is one page inside ten seconds. This one
     *                     fires on literally every visitor, human or not.
     *
     * What is left is every rule that reads evidence already PRESENT — a declared bot UA,
     * contradictory client hints, a failed rDNS check, a datacentre address, a software
     * rasteriser, a shared fingerprint, a measured rhythm. All seven of the decisive-alone
     * rules are in that set, which is why a provisional verdict can still call
     * `navigator.webdriver` a bot on the first request rather than in half an hour.
     *
     * @var string[]
     */
    public const DEFERRED_CODES = [
        'no_js_on_html',
        'no_assets',
        'no_304_on_repeat',
        'no_interaction',
        'single_page_10s',
    ];

    /**
     * The verdict a provisional session may not be better than.
     *
     * A session that has tripped nothing scores 0 and would be called `human`. On one request,
     * with five rules not yet evaluated, that is not a finding — it is the absence of one, and
     * publishing it as `human` is the trap this whole feature could have walked into: the
     * verdict would then FLIP as the session continued, and a bot detector that exonerates and
     * then accuses is worse than one that waits. So a provisional verdict is floored here. It
     * can be worse than this on positive evidence; it can never be better.
     */
    public const PROVISIONAL_FLOOR = 'unknown';

    /**
     * The reason code recorded when the floor above changes the verdict.
     *
     * Not a rule and worth no points — it explains an absence of evidence rather than adding
     * any, exactly like `no_bot_signals`, and it exists because SPEC §1 requires every verdict
     * to carry a reason somebody can read. An operator looking at an `unknown` session is owed
     * the sentence "this session has not ended yet" rather than a shrug.
     */
    public const PROVISIONAL_REASON = 'provisional_session';

    /**
     * Default weights (SPEC §7). Overridable per rule from scoring.weights.
     *
     * The per-rule justification for each number is in the method that implements it —
     * look for the "WEIGHT" paragraph in each rule's docblock.
     *
     * The table is grouped by how much a rule can do on its own: first the ones that are
     * decisive alone, at or above the `bot` threshold; then the strong ones, which are
     * designed to be corroborated; then the behavioural ones, which are meant to stack.
     *
     * @var array<string,int>
     */
    public const WEIGHTS = [
        'automation_marker'      => 100,
        'ua_declared_bot'        => 100,
        'rdns_claim_failed'      => 95,
        'headless_renderer'      => 90,
        'beacon_forged'          => 90,
        'ua_claim_failed'        => 85,
        'fp_cluster_proxy_fleet' => 80,

        'ua_secch_mismatch'      => 75,
        'platform_mismatch'      => 70,
        'no_js_on_html'          => 70,

        'hosting_asn_browser_ua' => 45,
        'periodic_timing'        => 45,
        'no_interaction'         => 40,
        'tz_mismatch'            => 35,
        'no_304_on_repeat'       => 30,
        'no_assets'              => 25,
        'single_page_10s'        => 15,
    ];

    /**
     * Minimum distinct IPs sharing one fingerprint before it is called a fleet.
     *
     * Five, per SPEC §7. The reasoning: a household or small office NAT can legitimately
     * present two to four addresses for one browser fingerprint over twelve hours (dual
     * stack, a mobile handoff, a DHCP renewal). Five is the point where "one browser, many
     * networks" stops having an innocent explanation. Configurable via
     * scoring.fp_fleet_min_ips because a site whose audience is behind carrier-grade NAT
     * may want it higher.
     */
    public const FP_FLEET_MIN_IPS = 5;

    /** @var array<string,int> Effective weights after config overrides. */
    private array $weights;

    /** @var array<string,int> Verdict thresholds. */
    private array $thresholds;

    /** Minimum cluster size for fp_cluster_proxy_fleet. */
    private int $fpFleetMinIps;

    /** Effective rule version (config may pin it during a migration). */
    private int $ruleVersion;

    /**
     * An override for a rule that does not exist is refused rather than ignored: silently
     * dropping it would leave an operator convinced they had disabled something.
     *
     * A weight of 0 disables a rule entirely, which is a legitimate thing to want. The upper
     * bound is 200 rather than 100, so that an operator can make a single rule decisive even
     * after another one is subtracted, but not so high that one typo turns every session into
     * a bot.
     *
     * @param array<string,mixed> $scoringCfg The 'scoring' section of the config.
     */
    public function __construct(array $scoringCfg = [])
    {
        $this->weights = self::WEIGHTS;

        foreach ((array) ($scoringCfg['weights'] ?? []) as $code => $weight) {
            if (!isset(self::WEIGHTS[$code])) {
                throw new \InvalidArgumentException('Rules: unknown rule code in scoring.weights: ' . $code);
            }
            if (!is_numeric($weight)) {
                throw new \InvalidArgumentException('Rules: weight for ' . $code . ' must be numeric.');
            }
            $this->weights[$code] = (int) max(0, min(200, (int) $weight));
        }

        $t = (array) ($scoringCfg['thresholds'] ?? []);
        $this->thresholds = [
            'bot'          => (int) ($t['bot'] ?? 80),
            'likely_bot'   => (int) ($t['likely_bot'] ?? 60),
            'unknown'      => (int) ($t['unknown'] ?? 40),
            'likely_human' => (int) ($t['likely_human'] ?? 20),
        ];

        $this->fpFleetMinIps = (int) max(2, (int) ($scoringCfg['fp_fleet_min_ips'] ?? self::FP_FLEET_MIN_IPS));
        $this->ruleVersion   = (int) ($scoringCfg['rule_version'] ?? self::RULE_VERSION);
    }

    /**
     * Every rule code, in evaluation order.
     *
     * Order does not affect the score (addition commutes) but it does affect the order
     * reasons appear in the UI, so the decisive ones come first.
     *
     * @return string[]
     */
    public static function codes(): array
    {
        return array_keys(self::WEIGHTS);
    }

    /**
     * Evaluate ONE rule.
     *
     * Public and single-rule on purpose: SPEC §12 requires a test per rule proving it fires
     * when it should and does not misfire when it should not, and that test should not have
     * to run the whole scorer and infer which rule was responsible.
     *
     * `ctx['provisional']` silences every rule in DEFERRED_CODES, and it is checked here rather
     * than in score() so that both entry points give the same answer to "does this rule fire on
     * this session". A test that asks fired() directly and a scorer that asks score() must never
     * be able to disagree about a rule.
     *
     * @param array<string,mixed> $s   Signal map from Signals::fromSession().
     * @param array<string,mixed> $ctx Scoring context (see score()).
     * @return string|null             A human-readable explanation when the rule fires,
     *                                 null when it does not.
     */
    public function fired(string $code, array $s, array $ctx = []): ?string
    {
        if (!empty($ctx['provisional']) && in_array($code, self::DEFERRED_CODES, true)) {
            return null;
        }

        switch ($code) {
            case 'automation_marker':      return $this->ruleAutomationMarker($s);
            case 'ua_declared_bot':        return $this->ruleUaDeclaredBot($s);
            case 'rdns_claim_failed':      return $this->ruleRdnsClaimFailed($s);
            case 'headless_renderer':      return $this->ruleHeadlessRenderer($s);
            case 'beacon_forged':          return $this->ruleBeaconForged($s);
            case 'ua_claim_failed':        return $this->ruleUaClaimFailed($s);
            case 'fp_cluster_proxy_fleet': return $this->ruleFpClusterProxyFleet($s);
            case 'ua_secch_mismatch':      return $this->ruleUaSecChMismatch($s);
            case 'platform_mismatch':      return $this->rulePlatformMismatch($s);
            case 'no_js_on_html':          return $this->ruleNoJsOnHtml($s, $ctx);
            case 'hosting_asn_browser_ua': return $this->ruleHostingAsnBrowserUa($s);
            case 'periodic_timing':        return $this->rulePeriodicTiming($s);
            case 'no_interaction':         return $this->ruleNoInteraction($s);
            case 'tz_mismatch':            return $this->ruleTzMismatch($s);
            case 'no_304_on_repeat':       return $this->ruleNo304OnRepeat($s, $ctx);
            case 'no_assets':              return $this->ruleNoAssets($s);
            case 'single_page_10s':        return $this->ruleSinglePage10s($s);
        }
        throw new \InvalidArgumentException('Rules: unknown rule code: ' . $code);
    }

    /**
     * Score a session.
     *
     * A rule disabled by config is skipped entirely rather than evaluated and contributing
     * zero, so that a disabled rule cannot appear in the reasons with no contribution and
     * confuse whoever is reading them.
     *
     * SPEC §1 requires bot_score_f always to be accompanied by bot_reasons_ss, so a clean
     * session is given a positive reason of its own rather than an empty array — which also
     * makes "how many sessions tripped nothing at all" a one-facet question.
     *
     * A clean PROVISIONAL session gets PROVISIONAL_REASON instead of `no_bot_signals`, and that
     * is not an oversight: five rules were not evaluated, so "nothing fired" is not yet a fact
     * about the session. The facet stays honest by counting only sessions that were fully tested.
     *
     * That invariant is asserted rather than merely documented. If the assertion ever throws,
     * the bug is that a rule contributed points without recording why, which would produce a
     * verdict nobody can defend and that someone would nonetheless act on.
     *
     * A PROVISIONAL session — one that has not ended — is scored with the DEFERRED_CODES rules
     * silenced and the verdict floored at PROVISIONAL_FLOOR. Both halves are needed and neither
     * is sufficient: silencing the absence-based rules stops the detector accusing a live human,
     * and the floor stops it exonerating a bot whose only incriminating act has not happened yet.
     * The floor records PROVISIONAL_REASON so the verdict still explains itself, which also keeps
     * the "no verdict without a reason" assertion below meaningful rather than bypassed.
     *
     * @param array<string,mixed> $s   Signal map from Signals::fromSession().
     * @param array<string,mixed> $ctx Context:
     *                                 beacon_deployed (bool) — is the beacon actually live
     *                                 on this site? Controls no_js_on_html; see that rule.
     *                                 site_sends_304 (bool) — does this site emit validators?
     *                                 Controls no_304_on_repeat; see that rule.
     *                                 provisional (bool) — is this session still open?
     *                                 See DEFERRED_CODES and PROVISIONAL_FLOOR.
     * @return array{
     *     score:float, verdict:string, reasons:string[], class:string,
     *     rule_version:int, detail:array<string,array{weight:int,why:string}>
     * }
     */
    public function score(array $s, array $ctx = []): array
    {
        $total  = 0.0;
        $reasons = [];
        $detail  = [];

        foreach (self::codes() as $code) {
            $weight = $this->weights[$code];
            if ($weight === 0) {
                continue;
            }
            $why = $this->fired($code, $s, $ctx);
            if ($why === null) {
                continue;
            }
            $total    += $weight;
            $reasons[] = $code;
            $detail[$code] = ['weight' => $weight, 'why' => $why];
        }

        $score   = Signals::clampScore($total);
        $verdict = $this->verdictFor($score);

        if (!empty($ctx['provisional']) && self::isBetterThanFloor($verdict)) {
            $verdict = self::PROVISIONAL_FLOOR;
            $reasons[] = self::PROVISIONAL_REASON;
            $detail[self::PROVISIONAL_REASON] = [
                'weight' => 0,
                'why'    => 'This session has not ended yet, so the ' . count(self::DEFERRED_CODES)
                    . ' signals that can only be read once it has were not evaluated. '
                    . 'Not enough evidence to call it human.',
            ];
        }

        $class = $this->classify($s, $reasons, $verdict);

        if ($reasons === []) {
            $reasons[] = 'no_bot_signals';
            $detail['no_bot_signals'] = [
                'weight' => 0,
                'why'    => 'No bot signal fired on this session.',
            ];
        }

        if ($score > 0 && $detail === []) {
            throw new \LogicException('Rules: scored ' . $score . ' with no reasons. This is a bug.');
        }
        if ($verdict !== 'human' && $reasons === ['no_bot_signals']) {
            throw new \LogicException('Rules: verdict ' . $verdict . ' with no supporting reason. This is a bug.');
        }

        return [
            'score'        => $score,
            'verdict'      => $verdict,
            'reasons'      => $reasons,
            'class'        => $class,
            'rule_version' => $this->ruleVersion,
            'detail'       => $detail,
        ];
    }

    /**
     * The five verdicts from most human to most bot.
     *
     * Ordered rather than derived from the thresholds, because the thresholds are configurable
     * and their ORDER is not: an operator who sets `likely_bot` above `bot` has misconfigured
     * the tool, and the provisional floor must not become a ceiling as a result.
     *
     * @var string[]
     */
    private const VERDICT_ORDER = ['human', 'likely_human', 'unknown', 'likely_bot', 'bot'];

    /**
     * Is this verdict a stronger claim of humanity than a provisional session is allowed to make?
     *
     * An unrecognised verdict answers false, which leaves it untouched: the floor exists to
     * suppress an overclaim, never to invent a verdict nobody asked for.
     */
    private static function isBetterThanFloor(string $verdict): bool
    {
        $rank  = array_search($verdict, self::VERDICT_ORDER, true);
        $floor = array_search(self::PROVISIONAL_FLOOR, self::VERDICT_ORDER, true);
        if ($rank === false || $floor === false) {
            return false;
        }
        return $rank < $floor;
    }

    /**
     * Map a 0–100 score onto a verdict (SPEC §7 thresholds).
     */
    public function verdictFor(float $score): string
    {
        if ($score >= $this->thresholds['bot']) {
            return 'bot';
        }
        if ($score >= $this->thresholds['likely_bot']) {
            return 'likely_bot';
        }
        if ($score >= $this->thresholds['unknown']) {
            return 'unknown';
        }
        if ($score >= $this->thresholds['likely_human']) {
            return 'likely_human';
        }
        return 'human';
    }

    /**
     * Assign bot_class_s.
     *
     * The class answers "what KIND of thing is this", which is a different question from
     * "how confident are we", and the order below is the priority order in which those
     * answers are decided.
     *
     * 1. A DECLARED CRAWLER IS CLASSIFIED FIRST, ALWAYS. This is not a stylistic choice:
     *    Googlebot legitimately shows the same cross-IP fingerprint pattern as a proxy
     *    fleet (hundreds of addresses, one header tuple), so if the fleet check ran first
     *    every search engine on earth would be filed under `proxy_fleet` and the
     *    "declared crawlers listed separately" requirement in SPEC §10 would be dead on
     *    arrival.
     *
     * 2. A crawler that FAILED forward-confirmed rDNS is `spoofed_ua`, not
     *    `declared_crawler`. Something claiming to be Googlebot from an address Google
     *    does not own is the opposite of honest, and putting it in the honest bucket would
     *    let anyone whitelist themselves by setting a User-Agent.
     *
     * 3. `proxy_fleet` outranks `headless`. Both may be true of the same session, and the
     *    fleet is the more useful answer: `headless` describes one client, `proxy_fleet`
     *    describes an organised operation across many networks, which is the thing an
     *    operator can actually act on.
     *
     * 4. Automation proven on the execution plane comes next, then a set of headers that
     *    contradict each other, which means something is lying about what it is.
     *
     * 5. Last is `scripted`, for a session with no single tell whose behaviour nonetheless
     *    adds up. It is the honest label for "we are confident this is not a person, and we
     *    cannot say what it is".
     *
     * @param array<string,mixed> $s
     * @param string[]            $reasons
     */
    public function classify(array $s, array $reasons, string $verdict): string
    {
        $fired = array_flip($reasons);

        if (isset($fired['ua_declared_bot'])) {
            if (isset($fired['rdns_claim_failed'])) {
                return 'spoofed_ua';
            }
            if (!empty($s['ai_crawler'])) {
                return 'ai_crawler';
            }
            $cat = strtolower((string) ($s['ua_bot_cat'] ?? ''));
            if ($cat === 'monitor') {
                return 'monitor';
            }
            return 'declared_crawler';
        }

        if (isset($fired['fp_cluster_proxy_fleet'])) {
            return 'proxy_fleet';
        }

        if (isset($fired['automation_marker'])
            || isset($fired['headless_renderer'])
            || isset($fired['ua_claim_failed'])
            || ($s['headless'] ?? null) === true
        ) {
            return 'headless';
        }

        if (isset($fired['ua_secch_mismatch']) || isset($fired['platform_mismatch'])) {
            return 'spoofed_ua';
        }

        if ($verdict === 'bot' || $verdict === 'likely_bot') {
            return 'scripted';
        }

        return 'none';
    }

    /**
     * automation_marker — a definitive automation property was present in the page.
     *
     * WEIGHT 100. navigator.webdriver, chromedriver's $cdc_ object, Playwright's and
     * Puppeteer's injected globals: none of these exist on a browser a human is using.
     * There is no innocent explanation, so this is the one rule that reaches a verdict of
     * `bot` with no corroboration at all.
     *
     * @param array<string,mixed> $s
     */
    private function ruleAutomationMarker(array $s): ?string
    {
        $markers = (array) ($s['definitive_markers'] ?? []);
        if ($markers === []) {
            return null;
        }
        return 'Browser automation marker present in the page: '
            . implode(', ', $markers)
            . '. These properties only exist when a browser is driven by an automation framework.';
    }

    /**
     * ua_declared_bot — the client says it is a bot.
     *
     * WEIGHT 100, and this is the rule most likely to be misread. It produces the verdict
     * `bot` because the thing IS a bot; it does NOT produce a threat. classify() sends it
     * to `declared_crawler` / `ai_crawler` / `monitor`, and every view must present those
     * separately. Googlebot being called a bot is correct. Googlebot appearing in a list
     * titled "evasive traffic" is a product defect.
     *
     * The weight is 100 rather than, say, 60 because a self-declaration is the most
     * reliable statement in the whole detector: no scraper trying to blend in sets
     * User-Agent to GPTBot.
     *
     * @param array<string,mixed> $s
     */
    private function ruleUaDeclaredBot(array $s): ?string
    {
        if (empty($s['ua_bot'])) {
            return null;
        }
        $name = (string) ($s['ua_bot_name'] ?? 'unknown crawler');
        $cat  = (string) ($s['ua_bot_cat'] ?? 'other');
        return 'The User-Agent declares itself a bot (' . $name . ', category ' . $cat . '). '
            . 'Self-declaring crawlers are honest traffic and are classified separately from evasive clients.';
    }

    /**
     * rdns_claim_failed — it claims to be a verifiable crawler and the DNS says otherwise.
     *
     * WEIGHT 95. Forward-confirmed reverse DNS is the method Google, Microsoft and Yandex
     * all publish for verifying their crawlers: the address's PTR must resolve to a name in
     * their domain, and that name must resolve back to the same address. Failing it means
     * something is impersonating a crawler most sites allowlist — which is the whole point
     * of the impersonation.
     *
     * The rule fires ONLY for crawlers on Signals::VERIFIABLE_CRAWLERS, and only when the
     * check actually ran (rdns_ok is a real false, not null). An unverifiable crawler is
     * taken at its word: being unable to check a claim is not evidence against it. A null
     * rdns_ok means the lookup did not happen or did not resolve — unknown, not failed.
     *
     * @param array<string,mixed> $s
     */
    private function ruleRdnsClaimFailed(array $s): ?string
    {
        if (empty($s['crawler_verifiable'])) {
            return null;
        }
        if (($s['rdns_ok'] ?? null) !== false) {
            return null;
        }
        return 'Claims to be ' . (string) ($s['ua_bot_name'] ?? 'a verifiable crawler')
            . ' but forward-confirmed reverse DNS failed'
            . (isset($s['rdns']) && $s['rdns'] !== null ? ' (PTR: ' . $s['rdns'] . ')' : '')
            . '. The real crawler always passes this check.';
    }

    /**
     * headless_renderer — WebGL reports a software rasteriser.
     *
     * WEIGHT 90. SwiftShader, llvmpipe, Mesa OffScreen and Microsoft Basic Render mean
     * there is no GPU behind the browser, which for a UA claiming a consumer desktop
     * browser means it is not running on a consumer desktop.
     *
     * Not 100, because a real population reports these: virtual desktops, remote sessions,
     * and Linux machines with a broken driver. Ninety still reaches `bot` alone, which is
     * the deliberate call — those users are rare and the alternative is missing most
     * headless traffic — but docs/DETECTION.md names this as the first weight to lower if
     * you serve a VDI-heavy audience.
     *
     * @param array<string,mixed> $s
     */
    private function ruleHeadlessRenderer(array $s): ?string
    {
        if (($s['headless_renderer'] ?? null) !== true) {
            return null;
        }
        return 'WebGL reports a software rasteriser ("' . (string) ($s['webgl'] ?? '?') . '"), '
            . 'meaning there is no GPU behind this browser. Standard for headless Chrome, '
            . 'very rare on a real desktop.';
    }

    /**
     * beacon_forged — the client's timing claims are impossible.
     *
     * WEIGHT 90. The collector issues an HMAC token stamped with an issue time. A payload
     * claiming four hours of engagement thirty seconds after that stamp is not a
     * measurement error, it is a lie — and per SPEC §6.3 the lie is recorded as evidence
     * rather than discarded, because a client that bothers to forge engagement metrics is
     * doing so to look human.
     *
     * @param array<string,mixed> $s
     */
    private function ruleBeaconForged(array $s): ?string
    {
        if (empty($s['beacon_forged'])) {
            return null;
        }
        return 'The beacon reported timings that are impossible against its own signed token '
            . '(engagement exceeding visibility, or dwell time exceeding the token age). '
            . 'A client forging engagement metrics is trying to look human.';
    }

    /**
     * ua_claim_failed — the engine does not have the features its Chrome version should.
     *
     * WEIGHT 85. The beacon probes a handful of JavaScript features across a wide Chrome
     * version span. A UA string is a free-text header anyone can set; V8's feature set is
     * not. A client claiming Chrome 152 that lacks something shipped in Chrome 120, or that
     * has something that only shipped later, is not the browser it says it is.
     *
     * Slightly below 90 because the probe table itself can go stale — a browser genuinely
     * newer than the table is the known false-positive path — and docs/DETECTION.md
     * documents how to extend it.
     *
     * @param array<string,mixed> $s
     */
    private function ruleUaClaimFailed(array $s): ?string
    {
        if (($s['ua_claim_ok'] ?? null) !== false) {
            return null;
        }
        return 'The JavaScript engine does not match the browser version the User-Agent claims'
            . (isset($s['browser'], $s['browser_ver'])
                ? ' (' . $s['browser'] . ' ' . $s['browser_ver'] . ')'
                : '')
            . '. A spoofed User-Agent cannot retrofit V8.';
    }

    /**
     * fp_cluster_proxy_fleet — one header fingerprint, many unrelated IP addresses.
     *
     * WEIGHT 80. THE SIGNAL THIS PRODUCT EXISTS FOR.
     *
     * A residential-proxy fleet's entire advantage is that every request comes from a
     * different, legitimate-looking consumer address. What it cannot rotate is the header
     * tuple of the browser it is driving — change that and it stops being a convincing
     * Chrome. So the fingerprint stays fixed while the address moves, and counting distinct
     * addresses per fingerprint turns the fleet's own evasion into its signature.
     *
     * THE WINDOW IS ±12 HOURS, WHICH IS 24 HOURS WIDE — hence the field name fp_ips_24h_i,
     * and hence the wording of the sentence returned below. bin/loghound-score computes it
     * as [bucketStart-12h, bucketStart+13h] around the hour a session ended; the extra hour
     * is the bucketing slack it documents. Saying "within 12 hours" to an operator, as this
     * message used to, understates the window by half and makes the count look twice as
     * damning as it is.
     *
     * Eighty, so it reaches `bot` alone. That is justified because five distinct networks
     * behind one browser fingerprint has no innocent explanation — but two guards keep it
     * from being reckless:
     *
     *   * `as_type != mobile`, per SPEC §7: a phone on a carrier network genuinely changes
     *     address repeatedly, and mobile CGNAT would otherwise flag real people.
     *
     *   * NOT a forward-confirmed declared crawler. THIS IS A CORRECTION TO SPEC §7, which
     *     omits it. Googlebot crawls from hundreds of addresses with one fingerprint and
     *     would sail past the ≥5 test; without this guard every verified search and AI
     *     crawler would be scored 180 and classified `proxy_fleet`, which is exactly the
     *     conflation SPEC §7 says makes existing tools useless. The guard requires a PASSED
     *     rDNS check, not merely a UA claim, so an impersonator gets no benefit from it. The
     *     exemption has to be EARNED.
     *
     * Null fp_ips_24h (the scorer could not reach Solr) does not fire. "We could not check"
     * is not "this fingerprint is unique".
     *
     * @param array<string,mixed> $s
     */
    private function ruleFpClusterProxyFleet(array $s): ?string
    {
        $ips = $s['fp_ips_24h'] ?? null;
        if ($ips === null || (int) $ips < $this->fpFleetMinIps) {
            return null;
        }
        if (($s['as_type'] ?? null) === 'mobile') {
            return null;
        }
        if (!empty($s['ua_bot']) && ($s['rdns_ok'] ?? null) === true) {
            return null;
        }

        return 'This exact browser fingerprint was seen from ' . (int) $ips
            . ' distinct IP addresses in a 24-hour window around this session'
            . (isset($s['as_type']) && $s['as_type'] !== null ? ' (network type: ' . $s['as_type'] . ')' : '')
            . '. One browser cannot be on ' . (int) $ips
            . ' unrelated networks; this is a rotating-proxy fleet.';
    }

    /**
     * ua_secch_mismatch — Sec-CH-UA is missing from, or contradicts, a Chromium client.
     *
     * WEIGHT 75. Chromium has sent Sec-CH-UA on every secure-context request since version
     * 89. A client presenting a Chrome 152 User-Agent without it is not Chrome 152, and one
     * whose Sec-CH-UA advertises a different major version is assembling its headers from
     * two different sources — the classic tell of a scraper that updated its UA string and
     * forgot the client hints.
     *
     * Seventy-five rather than 85: this depends on the operator logging the header, and on
     * our model of which browsers send it. Signals::secChMismatch() returns null in every
     * ambiguous case, so on a site running plain `combined` this rule simply never fires
     * rather than firing on everyone.
     *
     * @param array<string,mixed> $s
     */
    private function ruleUaSecChMismatch(array $s): ?string
    {
        if (($s['secch_mismatch'] ?? null) !== true) {
            return null;
        }
        return 'The User-Agent claims a Chromium browser that always sends Sec-CH-UA, but the '
            . 'header is absent or advertises a different version. The headers were not assembled '
            . 'by the browser they claim to come from.';
    }

    /**
     * platform_mismatch — Sec-CH-UA-Platform disagrees with the User-Agent's OS.
     *
     * WEIGHT 70. The same "assembled from two sources" tell as ua_secch_mismatch, one layer
     * down: a UA string saying Windows with a platform hint saying Linux is a scraper
     * running on a Linux box with a Windows UA pasted in. Genuinely common in the wild.
     *
     * Kept below the 80 line because a contradiction here is occasionally produced by
     * legitimate middleware (some corporate proxies rewrite User-Agent and leave client
     * hints untouched), so it is asked to corroborate rather than to decide alone.
     *
     * @param array<string,mixed> $s
     */
    private function rulePlatformMismatch(array $s): ?string
    {
        if (($s['platform_mismatch'] ?? null) !== true) {
            return null;
        }
        return 'Sec-CH-UA-Platform and the operating system in the User-Agent disagree. '
            . 'The two are produced by the same browser and cannot legitimately differ.';
    }

    /**
     * no_js_on_html — HTML was served, the client claims a real browser, no beacon arrived.
     *
     * WEIGHT 70. This is the plane-1 / plane-3 cross-check from SPEC §0 and it is the rule
     * that catches ordinary scrapers: curl, requests, Scrapy and every HTTP library with a
     * Chrome User-Agent pasted in. They fetch the HTML and never execute the script tag,
     * and no amount of header spoofing fixes that.
     *
     * IT ONLY FIRES WHEN THE BEACON IS ACTUALLY DEPLOYED. ctx['beacon_deployed'] is the
     * guard, and it is not optional: on a site that never installed the beacon, silence
     * from the execution plane means nothing, and firing here would score every single
     * visitor 70 and call the whole audience likely_bot. bin/loghound-score computes the
     * flag from evidence — the beacon is enabled in config AND at least one session in the
     * batch actually reported in — rather than from the config flag alone, because config
     * says what the operator intended and evidence says what is true.
     *
     * Seventy rather than higher because a real browser can fail to report for innocent
     * reasons: an ad blocker, a strict CSP, a network error on the beacon request, JS
     * disabled. Those users exist, so this asks for one corroborating signal before
     * reaching a verdict of `bot`.
     *
     * A crawler that never claimed to be a browser is not contradicting itself by not running
     * JavaScript, so it is excluded.
     *
     * @param array<string,mixed> $s
     * @param array<string,mixed> $ctx
     */
    private function ruleNoJsOnHtml(array $s, array $ctx): ?string
    {
        if (empty($ctx['beacon_deployed'])) {
            return null;
        }
        if (empty($s['html_200'])) {
            return null;
        }
        if (!empty($s['beacon'])) {
            return null;
        }
        if (empty($s['claims_browser'])) {
            return null;
        }
        return 'HTML was served and the client claims to be '
            . (string) ($s['browser'] ?? 'a browser')
            . ', but the page script never reported. This client does not execute JavaScript.';
    }

    /**
     * hosting_asn_browser_ua — a consumer browser running in a datacentre.
     *
     * WEIGHT 45. Nobody browses the web from an AWS, Hetzner or DigitalOcean address with
     * Chrome. Traffic from hosting ASNs presenting a consumer browser UA is automation that
     * has not bothered with residential proxies.
     *
     * Only 45 because the exceptions are real and identifiable: corporate VPN egress,
     * cloud-hosted browser services, some VPN providers on hosting-classified space, and
     * link-preview fetchers that borrow a browser UA. It is a strong hint that needs a
     * second signal, which it usually gets.
     *
     * @param array<string,mixed> $s
     */
    private function ruleHostingAsnBrowserUa(array $s): ?string
    {
        if (($s['as_type'] ?? null) !== 'hosting') {
            return null;
        }
        if (empty($s['claims_browser'])) {
            return null;
        }
        return 'A consumer browser User-Agent (' . (string) ($s['browser'] ?? '?')
            . ') arriving from hosting/datacentre address space'
            . (isset($s['asn']) && $s['asn'] !== null ? ' (AS' . (int) $s['asn'] . ')' : '')
            . '. People do not browse from servers.';
    }

    /**
     * periodic_timing — the requests arrive on a schedule.
     *
     * WEIGHT 45. A human's inter-request gaps are wildly irregular: read, scroll, click,
     * pause, click twice quickly. A scripted client's are not. Signals::isPeriodic() does
     * the work and is written defensively — it requires at least four gaps, a median gap of
     * at least one second, and a coefficient of variation under 0.10.
     *
     * The median-gap floor is the part that matters, and it exists because of a real false
     * positive: a browser loading a page fetches every sub-resource at once, producing gaps
     * of 0,0,0,0,1 with a near-zero standard deviation. That is a burst, not a schedule,
     * and a naive "low stddev" rule fires on every human page load in
     * tests/fixtures/apache_combined_human.log. Requiring a real interval asks the actual
     * question: is something waking up on a timer.
     *
     * Forty-five rather than more: uptime monitors and legitimate feed readers are periodic
     * and harmless, and they usually declare themselves anyway.
     *
     * @param array<string,mixed> $s
     */
    private function rulePeriodicTiming(array $s): ?string
    {
        if (empty($s['periodic'])) {
            return null;
        }
        $p50 = (int) ($s['gap_p50_ms'] ?? 0);
        $sd  = (int) ($s['gap_stddev_ms'] ?? 0);
        return 'Requests arrive on a schedule: median gap ' . $p50 . ' ms with a standard deviation of '
            . $sd . ' ms across ' . (int) ($s['gap_count'] ?? 0)
            . ' intervals. Human request timing is never this regular.';
    }

    /**
     * no_interaction — the beacon reported, and nobody touched the page.
     *
     * WEIGHT 40. A real visit produces mouse movement, a scroll, a key press, a tap. A page
     * that loaded, ran our script, reported, and recorded not one interaction was not being
     * read by a person.
     *
     * Forty because the innocent case is common enough to matter: someone who opens a tab,
     * glances at it, and closes it without touching anything. That is a real human with a
     * bounce, and it must not be called a bot on this evidence alone. Note that this rule
     * requires the beacon to have ARRIVED — it is a statement about a measured absence of
     * interaction, not about the absence of a measurement. A beacon that arrived without an
     * interaction count is unknown, and does not fire it either.
     *
     * @param array<string,mixed> $s
     */
    private function ruleNoInteraction(array $s): ?string
    {
        if (empty($s['beacon'])) {
            return null;
        }
        if (($s['interactions'] ?? null) === null) {
            return null;
        }
        if ((int) $s['interactions'] > 0) {
            return null;
        }
        return 'The page script ran and reported, but recorded zero interactions '
            . '(no movement, scroll, key or tap) for the whole session.';
    }

    /**
     * tz_mismatch — the browser's timezone does not match the address's geography.
     *
     * WEIGHT 35. A browser reports Intl timezone Europe/Bucharest while the IP geolocates
     * to Ohio. Bots on rented proxies routinely forget to align the two.
     *
     * Only 35, and deliberately the weakest of the "contradiction" family, because the
     * innocent population is enormous: every VPN user, every traveller, everyone who never
     * changed their laptop's timezone after moving, and everyone whose IP geolocation is
     * simply wrong — which is a large fraction of all IP geolocation. This rule exists to
     * corroborate, never to decide.
     *
     * @param array<string,mixed> $s
     */
    private function ruleTzMismatch(array $s): ?string
    {
        if (($s['tz_match'] ?? null) !== false) {
            return null;
        }
        return 'The browser timezone and the timezone implied by the IP address disagree. '
            . 'Weak on its own (VPNs and travellers do this), meaningful alongside other signals.';
    }

    /**
     * no_304_on_repeat — sub-resources were re-fetched and never revalidated.
     *
     * WEIGHT 30. A browser with a warm cache sends If-None-Match / If-Modified-Since and
     * collects a 304. A client that re-fetches the identical asset with a full 200 every
     * time has no HTTP cache, which most scripted clients do not.
     *
     * THIS RULE AS WRITTEN IN SPEC §7 MISFIRES ON HUMANS, AND THE FIX IS THREE GUARDS.
     * Measured, not theorised: run the naive version against
     * tests/fixtures/apache_combined_human.log and it fires on four of the five real human
     * sessions. Each guard removes one cause.
     *
     *  1. Repeats are counted on the FULL request target, path AND query, and only for
     *     SUB-RESOURCES. Cache-busted assets (/app.css?a=1832196438) are a different URL on
     *     every deploy, so the browser has nothing to revalidate; and re-navigating to the
     *     same page, or polling a status endpoint, is ordinary human behaviour that says
     *     nothing about a cache. Both are handled in Sessionizer::accumulate().
     *
     *  2. At least TWO distinct sub-resources must have repeated. One is noise.
     *
     *  3. ctx['site_sends_304'] — THE IMPORTANT ONE. A 304 requires the SERVER to send an
     *     ETag or Last-Modified; without a validator the browser cannot make a conditional
     *     request and a full 200 is its only option. So on a site that serves its static
     *     files with no validators, this rule measures the server's configuration and
     *     blames the client for it. opensolr.com is such a site, which is why the human
     *     fixture trips the naive rule. bin/loghound-score sets the flag from evidence —
     *     at least one session in the batch actually received a 304 — so the rule only
     *     speaks where conditional requests demonstrably work.
     *
     * @param array<string,mixed> $s
     * @param array<string,mixed> $ctx
     */
    private function ruleNo304OnRepeat(array $s, array $ctx): ?string
    {
        if (empty($ctx['site_sends_304'])) {
            return null;
        }
        if ((int) ($s['repeat_assets'] ?? 0) < 2) {
            return null;
        }
        if (!empty($s['got_304'])) {
            return null;
        }
        return (int) $s['repeat_assets'] . ' sub-resources were fetched more than once and the '
            . 'client never sent a conditional request — every fetch was a full 200, on a site '
            . 'where other clients do receive 304s. This client has no HTTP cache.';
    }

    /**
     * no_assets — an HTML page was served and nothing else was fetched.
     *
     * WEIGHT 25. A browser rendering a page pulls its stylesheet, its scripts, its fonts
     * and its images. A client that takes the HTML and leaves wanted the markup, not the
     * page.
     *
     * Twenty-five because the innocent cases are ordinary: a warm cache means a returning
     * visitor legitimately re-fetches nothing, and a text-mode or accessibility client may
     * skip sub-resources. It is a good stacking signal and a terrible standalone one.
     *
     * The test is on SUB-RESOURCES, which includes the favicon. SPEC §4.1 gives the favicon
     * its own kind_s, but a client that fetched /favicon.ico did go back to the server for
     * something the markup referenced, so "fetched no sub-resources at all" is simply false
     * for it. Counting only kind_s=asset fires this rule on a real session in
     * tests/fixtures/apache_combined_bot_fleet.log whose only sub-resource was the favicon.
     *
     * @param array<string,mixed> $s
     */
    private function ruleNoAssets(array $s): ?string
    {
        if (empty($s['html_200'])) {
            return null;
        }
        if ((int) ($s['sub_resources'] ?? 0) > 0) {
            return null;
        }
        return 'An HTML page was served with a 200 and the client fetched no stylesheets, scripts, '
            . 'fonts, images or even a favicon. It wanted the markup, not the page.';
    }

    /**
     * single_page_10s — one page, in and out inside ten seconds.
     *
     * WEIGHT 15, and SPEC §7 is right to call it "weak alone, meaningful stacked". This is
     * also the shape of a perfectly normal human bounce: land from a search result, see it
     * is not what they wanted, leave. Fifteen points cannot reach any verdict but `human`
     * on its own, which is the intent — it exists to be the third signal that pushes a
     * session already carrying two others over a threshold.
     *
     * @param array<string,mixed> $s
     */
    private function ruleSinglePage10s(array $s): ?string
    {
        if ((int) ($s['hits'] ?? 0) === 0) {
            return null;
        }
        if ((int) ($s['pages'] ?? 0) > 1) {
            return null;
        }
        if ((int) ($s['log_span_ms'] ?? 0) > 10000) {
            return null;
        }
        return 'One page, in and out in ' . round(((int) ($s['log_span_ms'] ?? 0)) / 1000, 1)
            . ' seconds. Weak on its own — a human bounce looks identical — but it stacks.';
    }
}
