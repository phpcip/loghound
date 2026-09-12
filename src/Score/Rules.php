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
 * re-run. A readable table of rules with published weights is the feature, and the table is
 * WEIGHTS below — never a count written down somewhere else, which goes stale the moment a rule
 * is added and has already done so twice.
 *
 * ---------------------------------------------------------------------------------------
 * WHY THESE NUMBERS
 * ---------------------------------------------------------------------------------------
 * The weights follow one principle: a weight of 80 or more is a claim that this signal
 * ALONE is enough to call something a bot, because 80 is the `bot` threshold. So the
 * question for every rule is not "how suspicious is this" but "am I willing to publish a
 * verdict on this evidence and nothing else". The rules that clear that bar are
 * automation_marker, ua_declared_bot, rdns_claim_failed, headless_renderer, beacon_forged,
 * ua_claim_failed, hostile_probe, fp_cluster_proxy_fleet and never_served — and each one is a
 * fact about the client that has no innocent explanation.
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
     *
     * BUMPED TO 2. Three changes in one pass, each of which genuinely alters what a past session
     * would score today, which is precisely the condition this field exists to record:
     * `hostile_probe` and `probe_sweep` are new rules, and the `fp_cluster_proxy_fleet` mobile
     * exemption was narrowed from "any client on a mobile ASN" to "a client that is actually a
     * handset". A rescoring pass over anything judged under version 1 has real work to do.
     */
    public const RULE_VERSION = 2;

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
     *   probe_sweep       two of its three conditions are absences — "the server has answered
     *                     nothing with a body" and "no sub-resource was fetched" — and a
     *                     visitor who has just followed a stale bookmark to an admin path has
     *                     both of them true for the moment between the 404 line and the error
     *                     page's stylesheet. Same trap as no_assets, same answer.
     *
     * `hostile_probe` is deliberately NOT here, though it reads the same attack plane: a request
     * for `/etc/passwd` that has already been made is a fact about the past, not a prediction,
     * so there is nothing to wait for and a sweep is called what it is on its first line.
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
        'probe_sweep',

        /* Both read a ratio over a session that is still growing. "Every request so far was
           refused" and "four fifths of them were" are statements about the future while the
           visitor is still here, and the scorer can land between a 403 and the 200 after it. */
        'never_served',
        'mostly_refused',
    ];

    /**
     * The rules that read the TRANSPORT plane, silenced when there is no transport plane.
     *
     * A beacon-only session — a site on another machine, measured by the beacon alone — has no
     * access log behind it anywhere in this installation. No status code, no bytes, no server
     * timing, no conditional-request behaviour, no inter-request rhythm, no reverse DNS from a
     * log line. bin/loghound-score writes NONE of those fields on such a document, which is
     * half the guarantee; this is the other half, and both are needed. Without it,
     * Signals::fromSession() would read the absent counters back as the zeros PHP hands out,
     * and `assets == 0` and `pages == 1` are not neutral values here — they are two of the
     * accusations in the ruleset. `no_assets` is 25 points for fetching sub-resources that were
     * never observable from here, and `no_304_on_repeat` and `single_page_10s` read the same
     * absent counters, so the arithmetic is not the whole of the risk either.
     *
     * Each of those rules also has a guard of its own that happens to decline on a beacon-only
     * session — ruleNoAssets() needs `html_200`, ruleSinglePage10s() needs a hit count — and
     * that is EXACTLY why the list exists rather than being left to them. A rule that is inert
     * because of a predicate written for another purpose is one edit away from firing, and the
     * edit would look harmless. This list makes it a guarantee instead of a coincidence.
     *
     * A rule firing on evidence that was never collected is the exact failure this project
     * exists to stop publishing, and it is worse than a missed detection: it is a finding
     * manufactured out of an absence, reported with the same confidence as a real one.
     *
     * Why each entry is here, and not one more:
     *
     *   no_js_on_html     asks whether HTML was served and no beacon followed. On a
     *                     beacon-only session the beacon is the ONLY thing that happened.
     *   no_assets         asks what else the client fetched. Nothing was logged, so nothing
     *                     was fetched as far as this installation can see.
     *   no_304_on_repeat  needs a repeated request and a validator, both log facts.
     *   single_page_10s   counts pages and measures a log span. Neither exists.
     *   periodic_timing   measures inter-request gaps from log lines. There are none, and an
     *                     empty gap list must not read as a perfectly regular rhythm.
     *   hostile_probe     reads the attack codes Score\Attacks matched on LOG LINES. A
     *                     beacon-only session has none, and an empty list would otherwise be
     *                     indistinguishable from "the detector looked and found nothing".
     *   probe_sweep       reads those codes AND the status-class counters, and every one of
     *                     those is a log fact. On a beacon-only session `st2` is absent, which
     *                     PHP hands back as zero — and "the server answered nothing with a body"
     *                     is half of this rule's accusation. This is the exact shape of the
     *                     danger the list exists for: an absent counter read as a finding.
     *
     * `no_interaction` is deliberately NOT in this list, though it is in DEFERRED_CODES: it
     * reads the beacon's own interaction count, which a beacon-only session has, and it is one
     * of the few pieces of evidence that still means something on one plane.
     *
     * @var string[]
     */
    public const TRANSPORT_CODES = [
        'no_js_on_html',
        'no_assets',
        'no_304_on_repeat',
        'single_page_10s',
        'periodic_timing',
        'hostile_probe',
        'probe_sweep',

        /* Both count status classes, which exist only where there is a request log. On a
           beacon-only session every counter is absent and reads back as zero, and "nothing was
           ever served" built out of four zeros is a verdict manufactured from an absence. */
        'never_served',
        'mostly_refused',
    ];

    /**
     * The reason recorded on a session that has only the execution plane behind it.
     *
     * Worth no points, like PROVISIONAL_REASON, and present for the same reason: SPEC §1
     * requires a verdict to carry something a person can read, and somebody looking at a
     * beacon-only session is owed the sentence "this rests on one plane, and one plane can be
     * faked" rather than a verdict that looks exactly like a three-plane one.
     *
     * It rides in `bot_reasons_ss`, so "how many of my sessions were scored on one plane" is a
     * facet question on a field the panel already lists, in the same place an operator looks to
     * see why a session was called what it was called.
     */
    public const SINGLE_PLANE_REASON = 'beacon_only_session';

    /**
     * The verdict a provisional session may not be better than.
     *
     * A session that has tripped nothing scores 0 and would be called `human`. On one request,
     * with the absence-based rules not yet evaluated, that is not a finding — it is the absence of
     * one, and
     * publishing it as `human` is the trap this whole feature could have walked into: the
     * verdict would then FLIP as the session continued, and a bot detector that exonerates and
     * then accuses is worse than one that waits. So a provisional verdict is floored here. It
     * can be worse than this on positive evidence; it can never be better.
     */
    public const PROVISIONAL_FLOOR = 'unknown';

    /**
     * The verdict a session nobody could actually TEST may not be better than.
     *
     * ------------------------------------------------------------------------------------
     * THE HOLE THIS CLOSES, WHICH IS THE LARGEST ONE IN THE FILE
     * ------------------------------------------------------------------------------------
     * `human` is what a score of 0 maps to, and a score of 0 means "no rule fired". Those are
     * not the same statement, and for most of this ruleset's life the ladder has treated them
     * as one: a session on which almost nothing COULD be evaluated scored 0 and was published
     * as a person.
     *
     * The file already knew this. CLEAN_REASON's own docblock says, in as many words, that a
     * session carrying it "has not been shown to be human; it has been shown not to be caught",
     * and that reading it as a positive finding is a fabricated conclusion. Nothing enforced it.
     * The reason code was emitted, labelled `info`, worth no points, and the verdict came out
     * `human` regardless.
     *
     * Three separate field reports were the same defect wearing different clothes:
     *
     *   * `GET /de-at/opensolr-search?f_product_category_sm=…` answered 403 by a captcha wall.
     *     One request, no assets, no validators, a deep faceted URL nothing links to. Verdict
     *     human, score 15, the only rule that fired being the weakest in the set.
     *   * `/xmlrpc.php`, `/main/xmlrpc.php`, `/new/xmlrpc.php`. Verdict human.
     *   * A macOS desktop User-Agent on China Mobile sharing a fingerprint with ten addresses.
     *     Verdict human.
     *
     * ------------------------------------------------------------------------------------
     * WHY A FLOOR AND NOT MORE RULES
     * ------------------------------------------------------------------------------------
     * Because the specific mechanism is general. `no_js_on_html`, `no_assets` and
     * `no_304_on_repeat` — the three rules that catch an ordinary scraper — all need the site to
     * have SERVED something before they can speak, which is correct on its own terms: you cannot
     * hold a client to account for not fetching the stylesheet of a page it was never given. But
     * the consequence is that THE MOMENT A SITE DEFENDS ITSELF, THE ATTACKER GOES QUIET. A 403,
     * a 401, a captcha wall or a rate limiter removes exactly the evidence that would have
     * condemned the client, and on a defended site that is the majority case, so the default
     * verdict — human — is handed out most freely to precisely the traffic the product exists
     * to name.
     *
     * Adding a rule per symptom would leave the mechanism intact and the next symptom
     * undetected. So the ladder itself is fixed: a verdict of `human` or `likely_human` is a
     * POSITIVE claim about a session, and this file will not publish one unless at least one
     * plane of evidence actually spoke. See hadTestableEvidence() for what counts and why.
     *
     * ------------------------------------------------------------------------------------
     * THE HONEST DIRECTION
     * ------------------------------------------------------------------------------------
     * A real person hits a 403 too, and a captcha in front of a search page refuses humans
     * daily. So this deliberately does NOT say "a refusal is suspicious" — it adds no points, it
     * changes no score, and it cannot push a session toward `bot`. It says the narrower and
     * defensible thing: nothing exculpating was observable, so the answer is `unknown`, which is
     * a finding rather than a shrug (Panel\Vocabulary says so where the operator reads it).
     *
     * It is the same device as PROVISIONAL_FLOOR one step further out: that one refuses to
     * exonerate a session that has not FINISHED, this one refuses to exonerate a session that
     * was never TESTABLE.
     */
    public const UNTESTED_FLOOR = 'unknown';

    /**
     * The reason code recorded when the evidence floor changes the verdict.
     *
     * Worth no points, like the other two synthetic reasons, and it rides in `bot_reasons_ss` so
     * that "how much of my traffic could this installation not actually test" is a one-facet
     * question — which is also the question that tells an operator whether deploying the beacon
     * or widening their LogFormat would pay for itself.
     */
    public const UNTESTED_REASON = 'no_testable_evidence';

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
        'hostile_probe'          => 85,
        'fp_cluster_proxy_fleet' => 80,
        'never_served'           => 80,

        'ua_secch_mismatch'      => 75,
        'platform_mismatch'      => 70,
        'no_js_on_html'          => 70,

        'probe_sweep'            => 50,
        'mostly_refused'         => 45,
        'hosting_asn_browser_ua' => 45,
        'periodic_timing'        => 45,
        'no_interaction'         => 40,
        'desktop_on_mobile_asn'  => 40,
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

    /**
     * The shortest visit that may be called `human` outright.
     *
     * Below this the verdict is capped at `likely_human`. Thirty seconds rather than ten — the
     * engagement threshold — because these two answer different questions: ten seconds is enough
     * to say a page was read rather than bounced off, and half a minute is the least that makes
     * "this was a person" a conclusion instead of a guess.
     */
    private const HUMAN_FLOOR_MS = 30000;

    /** The reason code the floor records, so the verdict is never unexplained. */
    private const SHORT_VISIT_REASON = 'short_visit';

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
     * The reason code recorded when a session was fully tested and tripped nothing.
     *
     * Worth no points, and the wording of its label matters more than most: it is the ABSENCE
     * of evidence. A session carrying only this one has not been shown to be human; it has
     * been shown not to be caught. Anything in the interface that reads it as a positive
     * finding is a fabricated conclusion.
     */
    public const CLEAN_REASON = 'no_bot_signals';

    /**
     * Every reason code the scorer can emit, with the words a person reads instead of the slug.
     *
     * THE ONE SOURCE OF TRUTH FOR THIS WORDING. `bot_reasons_ss` holds slugs —
     * `fp_cluster_proxy_fleet`, `hosting_asn_browser_ua`, `no_bot_signals` — and a slug is the
     * right thing to store, to filter on, to put in a URL and to grep for in a log. It is the
     * wrong thing to show somebody who has never read this file, and it was being shown in
     * every facet, table, dialog and chart label in the panel.
     *
     * So each entry carries three things:
     *
     *   label     Two or three plain words. The primary text everywhere the dimension appears.
     *   why       One sentence saying what the rule actually TESTS, for a tooltip or the value
     *             browser, where there is room for it.
     *   severity  How much the rule can do alone: `high` reaches a bot verdict unaided, `med`
     *             is designed to be corroborated, `low` is meant to stack, `info` is not an
     *             accusation at all.
     *
     * EVERY LABEL IS DERIVED FROM THE IMPLEMENTATION BELOW, NOT FROM THE SLUG, and two of them
     * are deliberately longer than the slug suggests because the short reading would overstate
     * the finding:
     *
     *   ua_declared_bot   is honest traffic. It produces the verdict `bot` because the thing
     *                     IS a bot, and it produces no threat whatsoever; severity `info`.
     *   no_bot_signals    is the absence of evidence, never evidence of a person.
     *   provisional_session  means the session had not ended when it was scored, so the deferred rules
     *                     were not evaluated. Nothing was detected.
     *
     * A code with no entry here renders as its own slug — never as a wrong-but-plausible
     * label, never as blank — and tests/test_facets.php fails if a code the scorer can emit is
     * missing one, so a rule added later cannot reach the interface as a slug by accident.
     *
     * @var array<string,array{label:string,why:string,severity:string}>
     */
    public const REASONS = [
        'automation_marker' => [
            'label' => 'Automation marker',
            'severity' => 'high',
            'why' => 'The page exposed a definitive driver artefact — navigator.webdriver, a chromedriver global, Puppeteer/Playwright/Selenium hooks. Browsers do not have these; drivers do.',
        ],
        'ua_declared_bot' => [
            'label' => 'Declared crawler',
            'severity' => 'info',
            'why' => 'It said it was a bot and it was telling the truth. Verdict bot, threat none.',
        ],
        'rdns_claim_failed' => [
            'label' => 'rDNS claim failed',
            'severity' => 'high',
            'why' => 'It declared itself Googlebot or Bingbot and forward-confirmed reverse DNS did not back that up. Impersonating a crawler is not a mistake anyone makes by accident.',
        ],
        'headless_renderer' => [
            'label' => 'Headless renderer',
            'severity' => 'high',
            'why' => 'WebGL reported SwiftShader, llvmpipe, Mesa OffScreen or Microsoft Basic Render: software rasterisation, which is what you get when there is no screen.',
        ],
        'beacon_forged' => [
            'label' => 'Forged beacon timing',
            'severity' => 'high',
            'why' => 'The claimed dwell time is impossible against the issue time of its own token. The lie is recorded rather than discarded, because the lie is the evidence.',
        ],
        'ua_claim_failed' => [
            'label' => 'UA claim failed',
            'severity' => 'high',
            'why' => 'The User-Agent claimed a Chrome version whose engine features the page does not actually have. A spoofed UA string cannot retrofit V8.',
        ],
        'fp_cluster_proxy_fleet' => [
            'label' => 'Proxy fleet fingerprint',
            'severity' => 'high',
            'why' => 'Five or more distinct IPs shared this exact header fingerprint within 24 hours on non-mobile networks. One client, many exits.',
        ],
        'hostile_probe' => [
            'label' => 'Exploit probe',
            'severity' => 'high',
            'why' => 'This session requested something no browser asks for by accident: a JNDI lookup, a '
                . 'credentials file, a published CVE path, shell syntax, a server-side-fetch address, or it '
                . 'arrived under a User-Agent that names a fuzzer. Only the patterns with no innocent browser '
                . 'explanation count here — the noisy ones are listed on the Attacks view and are not worth a '
                . 'verdict on their own.',
        ],
        'probe_sweep' => [
            'label' => 'Refused probe sweep',
            'severity' => 'med',
            'why' => 'Every request in this session matched a named attack pattern or a well-known admin path, '
                . 'the server answered none of them with a body, and the client fetched no stylesheet, script, '
                . 'font, image or favicon. A person whose browser lands on a 404 still renders the error page.',
        ],
        'never_served' => [
            'label' => 'Never served anything',
            'severity' => 'high',
            'why' => 'The site refused every single request this client made and served it nothing at all — '
                . 'no page, no redirect, not one byte of body. Somebody browsing a site gets something back; '
                . 'a client that collects nothing but refusals and keeps asking, or asks once and leaves, is '
                . 'not reading anything. Authentication challenges and rate-limit responses do not count '
                . 'towards this on their own.',
        ],
        'mostly_refused' => [
            'label' => 'Mostly refused',
            'severity' => 'med',
            'why' => 'This session opened with a refusal and the great majority of everything it asked for '
                . 'afterwards was refused too, with only occasional success. That is the shape of something '
                . 'enumerating paths until one works, rather than of a visitor who happened to find a dead '
                . 'link partway through reading.',
        ],
        'ua_secch_mismatch' => [
            'label' => 'Sec-CH-UA mismatch',
            'severity' => 'high',
            'why' => 'A Chrome User-Agent arrived without Sec-CH-UA, or with one that contradicts it. Chrome always sends its own client hints.',
        ],
        'platform_mismatch' => [
            'label' => 'Platform mismatch',
            'severity' => 'med',
            'why' => 'Sec-CH-UA-Platform disagrees with the operating system the User-Agent claims.',
        ],
        'no_js_on_html' => [
            'label' => 'No JS on HTML',
            'severity' => 'med',
            'why' => 'An HTML page was served with a 200 and no beacon ever arrived, while the User-Agent claimed a real browser. Real browsers run scripts.',
        ],
        'hosting_asn_browser_ua' => [
            'label' => 'Datacentre + browser UA',
            'severity' => 'low',
            'why' => 'A consumer browser User-Agent arriving from a hosting ASN. Weak alone — VPNs and corporate egress look like this — meaningful when stacked.',
        ],
        'periodic_timing' => [
            'label' => 'Periodic timing',
            'severity' => 'med',
            'why' => 'The gaps between requests are too regular across four or more requests. People are not metronomes.',
        ],
        'no_interaction' => [
            'label' => 'No interaction',
            'severity' => 'med',
            'why' => 'The beacon ran, the session ended, and not one scroll, click or keypress ever happened.',
        ],
        'desktop_on_mobile_asn' => [
            'label' => 'Desktop on a mobile carrier',
            'severity' => 'low',
            'why' => 'A User-Agent claiming a desktop operating system arriving from cellular address space. '
                . 'Weak alone — tethering a laptop to a phone looks exactly like this — and meaningful when it '
                . 'stacks, because a mobile ASN is also where an address rotates fastest.',
        ],
        'tz_mismatch' => [
            'label' => 'Timezone mismatch',
            'severity' => 'low',
            'why' => 'The browser timezone disagrees with the timezone of the IP geolocation.',
        ],
        'no_304_on_repeat' => [
            'label' => 'No conditional requests',
            'severity' => 'low',
            'why' => 'The same assets were fetched again with no If-None-Match or If-Modified-Since. A browser cache would have asked.',
        ],
        'no_assets' => [
            'label' => 'No sub-resources',
            'severity' => 'med',
            'why' => 'HTML was fetched and not a single stylesheet, script, font or image followed it.',
        ],
        'single_page_10s' => [
            'label' => 'Single page, under 10s',
            'severity' => 'low',
            'why' => 'One page, gone in under ten seconds. Very weak on its own; a bounce looks the same.',
        ],
        self::SHORT_VISIT_REASON => [
            'label' => 'Too short to call human',
            'severity' => 'low',
            'why' => 'The visit lasted under ' . (self::HUMAN_FLOOR_MS / 1000) . ' seconds. Nothing in it '
                . 'says automation — there is simply not enough of it to call a person a person, so the '
                . 'verdict stops at likely human.',
        ],
        self::PROVISIONAL_REASON => [
            'label' => 'Session still open',
            'severity' => 'info',
            'why' => 'The session had not ended when it was scored, so the signals that can only be read after it ends were not evaluated and the verdict is held at unknown. Nothing was detected.',
        ],
        self::UNTESTED_REASON => [
            'label' => 'Nothing testable',
            'severity' => 'info',
            'why' => 'No beacon reported, the log format captured no client hints to check the User-Agent '
                . 'against, the client fetched no sub-resource and sent no conditional request — so nothing '
                . 'that could exculpate this session was observable, and the verdict is held at unknown. '
                . 'Nothing was detected: this is the absence of a test, not the result of one. It is the '
                . 'usual shape of a request a site REFUSED, because a refusal removes the evidence a '
                . 'successful page would have produced.',
        ],
        self::SINGLE_PLANE_REASON => [
            'label' => 'One plane only',
            'severity' => 'info',
            'why' => 'This site has no access log in this installation, so the session was measured by the beacon alone and every signal that reads the request log was not evaluated. Nothing was detected — but the evidence that remains is the plane a determined client controls, so treat the verdict as weaker than the same verdict on a session with a log behind it.',
        ],
        self::CLEAN_REASON => [
            'label' => 'Nothing fired',
            'severity' => 'info',
            'why' => 'Every rule was evaluated and none of them fired. This is the absence of evidence, not evidence that a person was driving.',
        ],
    ];

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
     * Every code that can appear in `bot_reasons_ss`, weighted rules plus the synthetic ones.
     *
     * The synthetic three are not rules and carry no weight, but they are reason codes on real
     * documents and therefore real facet values, so anything enumerating what the dimension can
     * hold has to include them. Leaving them out is why "Signal fired" showed
     * `provisional_session` raw.
     *
     * @return string[]
     */
    public static function reasonCodes(): array
    {
        return array_merge(
            array_keys(self::WEIGHTS),
            [
                self::PROVISIONAL_REASON,
                self::SINGLE_PLANE_REASON,
                self::UNTESTED_REASON,
                self::CLEAN_REASON,
            ]
        );
    }

    /**
     * The label, explanation and severity for one reason code.
     *
     * An unknown code answers with itself as the label and says so, rather than guessing. A
     * value from an index written by a newer Loghound, or a rule an operator added, must read
     * as the thing it is.
     *
     * @return array{label:string,why:string,severity:string}
     */
    public static function reason(string $code): array
    {
        return self::REASONS[$code] ?? [
            'label'    => $code,
            'severity' => 'med',
            'why'      => 'This panel version has no description for the rule code "' . $code . '".',
        ];
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
        if (!empty($ctx['no_transport']) && in_array($code, self::TRANSPORT_CODES, true)) {
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
            case 'hostile_probe':          return $this->ruleHostileProbe($s);
            case 'probe_sweep':            return $this->ruleProbeSweep($s);
            case 'never_served':           return $this->ruleNeverServed($s);
            case 'mostly_refused':         return $this->ruleMostlyRefused($s);
            case 'ua_secch_mismatch':      return $this->ruleUaSecChMismatch($s);
            case 'platform_mismatch':      return $this->rulePlatformMismatch($s);
            case 'no_js_on_html':          return $this->ruleNoJsOnHtml($s, $ctx);
            case 'hosting_asn_browser_ua': return $this->ruleHostingAsnBrowserUa($s);
            case 'desktop_on_mobile_asn':  return $this->ruleDesktopOnMobileAsn($s);
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
     * is not an oversight: the deferred rules were not evaluated, so "nothing fired" is not yet a fact
     * about the session. The facet stays honest by counting only sessions that were fully tested.
     *
     * That invariant is asserted rather than merely documented. If the assertion ever throws,
     * the bug is that a rule contributed points without recording why, which would produce a
     * verdict nobody can defend and that someone would nonetheless act on.
     *
     * TWO FLOORS APPLY TO THE VERDICT, IN THIS ORDER, and neither can make a session look more
     * like a bot — both only refuse to publish a claim of humanity that the evidence does not
     * support. PROVISIONAL_FLOOR refuses to exonerate a session that has not FINISHED.
     * UNTESTED_FLOOR refuses to exonerate one that was never TESTABLE: no beacon, no client
     * hints in the log format, no sub-resource fetched, no conditional request — a session made
     * of request lines and nothing else, which is the usual shape of traffic a site REFUSED,
     * because a refusal removes the very evidence that would have condemned the client. The
     * second is checked only when the first did not already apply, so a session never collects
     * both explanations for one decision.
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

        /* THIRTY SECONDS IS THE FLOOR FOR CALLING SOMEBODY HUMAN. A visit that lasted less than
           that has not shown enough of itself to earn the strongest verdict the panel can give:
           `human` means "we are confident", and half a minute of traffic is not confidence, it
           is an absence of evidence against. It is demoted to `likely_human`, which is exactly
           what the reading is — probably a person, not yet proven one.

           MEASURED ON THE BEST CLOCK AVAILABLE. The engaged clock is the honest one where the
           beacon ran; the log span is the fallback and is blind to the final page, so a visit
           whose span is short may well have been longer. Both err the same way here, which is
           the safe direction: this rule only ever weakens a verdict, never strengthens one. A
           visit with no duration at all is left alone — nothing was measured, so there is
           nothing to demote on. */
        if ($verdict === 'human') {
            $engaged = $s['engaged_ms'] ?? null;
            $best = $engaged !== null && (int) $engaged > 0
                ? (int) $engaged
                : (int) ($s['log_span_ms'] ?? 0);

            if ($best > 0 && $best < self::HUMAN_FLOOR_MS) {
                $verdict = 'likely_human';
                $reasons[] = self::SHORT_VISIT_REASON;
                $detail[self::SHORT_VISIT_REASON] = [
                    'weight' => 0,
                    'why'    => 'The visit lasted ' . round($best / 1000, 1) . ' seconds, under the '
                        . (self::HUMAN_FLOOR_MS / 1000) . '-second floor for calling a visit human. '
                        . 'Nothing here says automation; there is simply not enough of it to be sure.',
                ];
            }
        }

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

        if (self::isBetterThanFloor($verdict) && !self::hadTestableEvidence($s)) {
            $verdict = self::UNTESTED_FLOOR;
            $reasons[] = self::UNTESTED_REASON;
            $detail[self::UNTESTED_REASON] = [
                'weight' => 0,
                'why'    => 'Nothing that could exculpate this session was observable: no beacon reported, '
                    . 'the log format captured no client hints to check the User-Agent against, and the '
                    . 'client never fetched a sub-resource or sent a conditional request. A verdict of '
                    . 'human is a positive claim and there is nothing here to base one on.',
            ];
        }

        if (!empty($ctx['no_transport'])) {
            $reasons[] = self::SINGLE_PLANE_REASON;
            $detail[self::SINGLE_PLANE_REASON] = [
                'weight' => 0,
                'why'    => 'This site has no access log in this installation, so the session was measured by '
                    . 'the beacon alone. The ' . count(self::TRANSPORT_CODES) . ' signals that read the request '
                    . 'log were not evaluated, and the evidence that remains comes from one plane, which is the '
                    . 'plane a determined client controls.',
            ];
        }

        $class = $this->classify($s, $reasons, $verdict);

        if ($reasons === []) {
            $reasons[] = self::CLEAN_REASON;
            $detail[self::CLEAN_REASON] = [
                'weight' => 0,
                'why'    => 'No bot signal fired on this session.',
            ];
        }

        if ($score > 0 && $detail === []) {
            throw new \LogicException('Rules: scored ' . $score . ' with no reasons. This is a bug.');
        }
        if ($verdict !== 'human' && $reasons === [self::CLEAN_REASON]) {
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
     * Did ANY plane of evidence actually say something about this session?
     *
     * The gate behind UNTESTED_FLOOR, and the whole question it answers is: could this session
     * have been caught if it had been a bot? If the answer is no, it may not be called a person.
     *
     * FOUR WAYS TO PASS, one per plane the product is built on, and each is a POSITIVE fact
     * rather than an absence — that is the discipline the rest of this file keeps about null and
     * the one that was missing from the ladder.
     *
     *  1. THE EXECUTION PLANE SPOKE. A beacon reported. That is the strongest evidence there is:
     *     scripts ran, the engine's feature set was probed against the version the User-Agent
     *     claims, automation properties were looked for, interactions were counted. A session
     *     with a beacon has been tested properly whatever else is true of it.
     *
     *  2. THE HEADER PLANE WAS TESTABLE. secChMismatch() or platformMismatch() returned a real
     *     boolean rather than null, which happens only when the log format actually captures the
     *     client hints AND the User-Agent claims a browser that must send them. A Chrome whose
     *     Sec-CH-UA agrees with its User-Agent has passed a check a spoofed header set fails, and
     *     that is genuine exculpating evidence from the log alone.
     *
     *  3. THE CLIENT DEMONSTRABLY RAN A RENDERER. It went back to the server for a stylesheet, a
     *     script, a font, an image or a favicon. Something parsed markup and followed what it
     *     referenced — an HTTP library fetching a URL does not. `own_assets` counts alongside
     *     `sub_resources` for the same reason ruleNoAssets() reads it: a visitor whose only
     *     sub-resource was Loghound's own `/b.js` did exactly what our script tag told their
     *     browser to do, and must not be punished for it.
     *
     *     NOT CONDITIONAL ON A 200. This is the precise correction to the three rules whose
     *     precondition created the hole: they need a successful HTML response because they
     *     accuse a client of not fetching the assets of a page it WAS given. This asks the
     *     opposite and weaker question — did anything render — and the answer survives any
     *     status code. A person who lands on a 404 or a 403 page whose own stylesheet loads has
     *     still demonstrated a browser.
     *
     *  4. AN HTTP CACHE SPOKE. The client received a 304, so it sent an If-None-Match or an
     *     If-Modified-Since and had a warm cache to validate. Scripted clients overwhelmingly do
     *     not, and this is a fact about the client that no status code on another request erases.
     *
     * WHAT FAILS ALL FOUR is a session consisting of request lines and nothing else: a
     * User-Agent string anyone can set, an address, a path and a count. The 403 on a deep
     * faceted search URL is that. So is a `/xmlrpc.php` sweep. So, for that matter, is a
     * returning visitor with a completely warm cache on a site that logs no client hints and has
     * no beacon — and calling that one `unknown` is the right answer too, because there is
     * genuinely nothing in the record that separates them.
     *
     * It reads only the signal map and never `$ctx`, deliberately: `beacon_deployed` and
     * `site_sends_304` describe what the INSTALLATION can do, and the question here is what this
     * SESSION showed. An installation with no beacon does not make a session untestable; it
     * makes every session on it rest on the remaining three.
     *
     * @param array<string,mixed> $s
     */
    private static function hadTestableEvidence(array $s): bool
    {
        if (!empty($s['beacon'])) {
            return true;
        }
        if (($s['secch_mismatch'] ?? null) !== null || ($s['platform_mismatch'] ?? null) !== null) {
            return true;
        }
        if ((int) ($s['sub_resources'] ?? 0) > 0 || (int) ($s['own_assets'] ?? 0) > 0) {
            return true;
        }
        if (!empty($s['got_304'])) {
            return true;
        }

        return false;
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
            /* A SELF-DECLARED CLIENT THAT PROBED IS NOT HONEST TRAFFIC. `declared_crawler` is
               labelled "said what it was and was telling the truth" everywhere in the panel and
               is presented as the group an operator does NOT need to act on, so a client that
               announced itself — sqlmap does, and so does every HTTP library on Enrich\Ua's
               table — and then asked for `/etc/passwd` must not land there. It declared a
               non-browser accurately and then behaved hostilely, which is `scripted`: we are
               confident it is not a person and cannot say what it is. */
            if (isset($fired['hostile_probe'])) {
                return 'scripted';
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
     * hostile_probe — the session asked for something no browser asks for by accident.
     *
     * WEIGHT 85, decisive alone, and it exists because the two halves of this product were not
     * speaking. Score\Attacks has named hostile request patterns at ingest since it was written,
     * Sessionizer folds the codes up onto the session as `hit_flags_ss`, and the RULESET never
     * read them — so a client whose entire visit was `/xmlrpc.php`, `/main/xmlrpc.php` and
     * `/new/xmlrpc.php` tripped nothing, scored 15 for `single_page_10s`, and was published in
     * the HUMAN population. The whole product claim is that it can tell a person from a scraper;
     * a WordPress exploit sweep filed under "humans" is that claim failing in public.
     *
     * IT READS Score\Attacks::DECISIVE AND NOT `severity: high`. Severity says how bad a match
     * would be if it worked; DECISIVE says whether a browser with a person behind it could have
     * produced it by accident, and the two are genuinely different sets — a downloads directory
     * serving `release-1.2.tar.gz` matches a medium-severity backup-file pattern, and a bundler's
     * source map matches a high-severity traversal one. Both are ordinary browsing. The selection
     * and the reason for every exclusion live in that constant's docblock, which is also where
     * the `over` paragraph for each pattern is written, so there is one place to argue with.
     *
     * Eighty-five rather than 100 for one reason worth stating: a code can be matched on a
     * request somebody else made THROUGH this session's client key. The key is a /24 plus a
     * User-Agent hash, so a corporate NAT can merge a scanner and a colleague into one session,
     * and at 100 the colleague would be unappealable. At 85 it still reaches `bot` alone, and a
     * single point of contrary evidence is still worth something.
     *
     * @param array<string,mixed> $s
     */
    private function ruleHostileProbe(array $s): ?string
    {
        $codes = (array) ($s['attack_decisive'] ?? []);
        if ($codes === []) {
            return null;
        }

        $labels = [];
        foreach ($codes as $code) {
            $labels[] = Attacks::describe((string) $code)['label'];
        }

        return 'This session requested ' . (count($labels) === 1 ? 'a pattern' : 'patterns')
            . ' with no innocent browser explanation: ' . implode(', ', $labels)
            . '. A person\'s browser does not ask for these by accident.';
    }

    /**
     * probe_sweep — everything it asked for was a probe, and the server gave it nothing.
     *
     * WEIGHT 50, designed to stack, and it is the rule that catches the case the decisive list
     * deliberately will not: `/xmlrpc.php`. That path is `atk_admin_probe`, which Score\Attacks
     * itself calls "the loudest and least alarming row in the table" because every one of your
     * own editors reaching `/wp-login.php` lands in it. A rule that fired on the code alone would
     * accuse your staff.
     *
     * SO THE RULE ASKS WHAT THE SERVER ANSWERED, which is this product's stated position on
     * hostile traffic everywhere else: a probe refused is noise and a probe answered is an
     * incident, and here the refusal is what makes the CLIENT suspicious rather than the request.
     * Three conditions, all required:
     *
     *  1. At least one named pattern matched, of any severity. Without one this is just a
     *     session that got a 404, which is a broken link.
     *  2. The server answered NOTHING with a body — no 2xx at all. An editor signing in gets the
     *     login form with a 200; a scanner enumerating paths that do not exist does not. This is
     *     also what keeps the rule off a real download, a real source map and a real search box,
     *     every one of which is a successful request.
     *  3. The client fetched no sub-resource whatsoever — not a stylesheet, script, font, image
     *     or favicon, and not Loghound's own beacon script either (`own_assets`, the same
     *     evidence ruleNoAssets() reads, for the same reason). A person whose browser lands on a
     *     404 still renders the error page and still goes back for its assets. Something that
     *     takes the status line and leaves did not render anything.
     *
     * Fifty, so it cannot reach `bot` alone but comfortably clears `unknown` — and on the sweep
     * that prompted it, stacked with `single_page_10s`, it reaches `likely_bot` and the session
     * leaves the human population, which is the whole point. The known over-report is a visitor
     * with a stale bookmark to an admin path whose 404 page carries no sub-resources at all; that
     * is a narrow population and it lands on `likely_bot`, not on `bot`.
     *
     * @param array<string,mixed> $s
     */
    private function ruleProbeSweep(array $s): ?string
    {
        $codes = (array) ($s['attack_codes'] ?? []);
        if ($codes === []) {
            return null;
        }
        if ((int) ($s['hits'] ?? 0) === 0) {
            return null;
        }
        if ((int) ($s['st2'] ?? 0) > 0) {
            return null;
        }
        if ((int) ($s['sub_resources'] ?? 0) > 0 || (int) ($s['own_assets'] ?? 0) > 0) {
            return null;
        }

        $labels = [];
        foreach ($codes as $code) {
            $labels[] = Attacks::describe((string) $code)['label'];
        }

        return 'Every request in this session matched a named probe pattern (' . implode(', ', $labels)
            . '), the server answered none of them with a body, and the client fetched no stylesheet, '
            . 'script, font, image or favicon afterwards. A person\'s browser renders the error page.';
    }

    /**
     * Refusal statuses that say more about the SITE than about the client.
     *
     * A 401 is "you need to be signed in", which is the correct answer to a person who followed
     * a link to a members-only page, and it is what every browser collects on the way to a login
     * prompt. A 407 is the same statement made by a proxy. A 429 is the operator's own rate
     * limiter firing, which is a fact about request volume and about how the limiter is
     * configured, not about whether a human is driving.
     *
     * A session refused only in these ways has not been shown to be anything, so it is carved
     * out of ruleNeverServed(). Everything else in the 4xx and 5xx classes counts: a 403, a 404,
     * a 410, a 400 and a 500 are all the site saying no to something that was asked for.
     *
     * @var array<int,int>
     */
    private const SOFT_REFUSALS = [401, 407, 429];

    /**
     * never_served — the site refused everything and served this client nothing at all.
     *
     * WEIGHT 80, decisive alone, and it is the answer to the largest structural hole in this
     * ruleset: A REFUSAL SILENCES THE RULES THAT WOULD HAVE CAUGHT THE CLIENT. `no_assets`,
     * `no_js_on_html` and `no_304_on_repeat` all require the site to have SERVED something
     * before they can speak, which is right on its own terms — you cannot hold a client to
     * account for not fetching the stylesheet of a page it never received. The consequence is
     * that the moment a site defends itself, the attacker goes quiet: a 403 from a captcha wall,
     * a 401 from an auth gate or a rate limiter removes precisely the evidence that would have
     * condemned the client, and on a defended site that is the majority case.
     *
     * Score\Rules::UNTESTED_FLOOR answers half of that by refusing to call such a session
     * HUMAN. This answers the other half: on a site's own owner's instruction, a client that was
     * served nothing whatsoever is not a person, and that is worth a verdict rather than a
     * shrug. `GET /de-at/opensolr-search?f_product_category_sm=…` answered 403, one request, no
     * assets, no validators, a deep faceted URL nothing links to — the session that prompted
     * this was published as a human with a score of 15.
     *
     * ------------------------------------------------------------------------------------
     * THE GUARDS, AND EACH IS THERE TO STOP A NAMED FALSE POSITIVE
     * ------------------------------------------------------------------------------------
     *  1. NOTHING WAS SERVED AND NOTHING WAS REDIRECTED. Not "a 4xx happened" — EVERY request in
     *     the session was refused. A session with twenty served pages and one 404 is a person
     *     who clicked a dead link, and calling that automation is the false positive that would
     *     discredit the product. It is also why `st3` has to be zero: a site that answers `http`
     *     with a 301 to `https` produces sessions whose only recorded request is that redirect,
     *     and a redirect is the server cooperating, not refusing.
     *
     *  2. THE REFUSALS WERE NOT ALL AUTHENTICATION OR RATE LIMITING. See SOFT_REFUSALS. A
     *     session consisting entirely of 401s may be credential stuffing and may equally be a
     *     person one click from signing in, and this rule reaches `bot` on its own, so it does
     *     not get to decide that case.
     *
     *  3. It is DEFERRED (see DEFERRED_CODES), so it never judges a session that is still
     *     running. "Every request so far was refused" is a statement about the future when the
     *     session has not ended, and the scorer can easily land between a 403 and the 200 that
     *     follows it.
     *
     * ------------------------------------------------------------------------------------
     * WHAT IT STILL GETS WRONG, STATED PLAINLY
     * ------------------------------------------------------------------------------------
     * A real person stopped by a captcha wall on their very first request, who then leaves
     * without their browser fetching a single sub-resource of the challenge page, looks
     * identical to a scraper and is scored `bot`. That population is narrow — a browser
     * rendering a challenge page almost always goes back for its script or its favicon, and
     * those requests are still counted into the session even though they are no longer indexed
     * — but it is not empty, and it is the price of the decisive form.
     *
     * @param array<string,mixed> $s
     */
    private function ruleNeverServed(array $s): ?string
    {
        $hits = (int) ($s['hits'] ?? 0);
        if ($hits === 0) {
            return null;
        }
        if ((int) ($s['st2'] ?? 0) > 0 || (int) ($s['st3'] ?? 0) > 0) {
            return null;
        }
        $refused = (int) ($s['refused'] ?? 0);
        if ($refused < $hits) {
            return null;
        }
        if ((int) ($s['soft_refusals'] ?? 0) >= $refused) {
            return null;
        }

        return 'The site refused every one of this client\'s ' . $hits . ' request'
            . ($hits === 1 ? '' : 's') . ' and served it nothing at all — no page, no redirect, not one '
            . 'byte of body. Somebody browsing a site gets something back.';
    }

    /**
     * mostly_refused — it opened with a refusal and almost everything after that was refused too.
     *
     * WEIGHT 45, designed to corroborate, and it is the middle of the range never_served leaves
     * open: a client enumerating paths until one of them works has a 2xx in it somewhere, so the
     * decisive rule correctly declines, and without this the session would be judged as though
     * the fifteen refusals had not happened.
     *
     * TWO CONDITIONS DO THE WORK, and the second is the one that makes the rule safe.
     *
     * The RATIO says most of what was asked for was refused. A threshold rather than a slope
     * because a rule an operator cannot check by hand is a rule they cannot disagree with, and
     * four fifths is a number somebody can hold against a session in the explorer.
     *
     * THE FIRST REQUEST HAVING BEEN REFUSED is what separates the two shapes a ratio alone
     * conflates. A person reads twenty pages, then follows a stale link and collects a 404: the
     * session OPENED with a 200 and this rule stays silent no matter what the tail looks like. A
     * scanner's first request is refused, because its first request is a guess. That single fact
     * removes the entire "human who found some dead links" population from the rule, which is
     * why the ratio can be as low as four fifths without being reckless.
     *
     * A floor of five requests keeps it away from the small numbers where a ratio means nothing:
     * one refusal out of one is 100% and is a single dead link.
     *
     * @param array<string,mixed> $s
     */
    private function ruleMostlyRefused(array $s): ?string
    {
        $hits = (int) ($s['hits'] ?? 0);
        if ($hits < 5) {
            return null;
        }
        $first = $s['first_status'] ?? null;
        if ($first === null || (int) $first < 400) {
            return null;
        }
        $refused = (int) ($s['refused'] ?? 0);
        if ($refused >= $hits) {
            return null;
        }
        if (($refused / $hits) < 0.8) {
            return null;
        }

        return 'This session opened with a refusal (' . (int) $first . ') and ' . $refused . ' of its '
            . $hits . ' requests were refused — ' . (int) round(($refused / $hits) * 100)
            . '% — with only occasional success. That is something trying paths until one works.';
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
     *   * A CLIENT THAT IS ACTUALLY A PHONE on a carrier network, per SPEC §7: a handset
     *     genuinely changes address repeatedly, and mobile CGNAT would otherwise flag real
     *     people.
     *
     *     THE EXEMPTION USED TO BE `as_type === 'mobile'` AND NOTHING ELSE, AND THAT WAS A HOLE
     *     THE SIZE OF A CATEGORY. It tested the NETWORK and was written about the DEVICE, so
     *     anything at all on a mobile ASN was excused — and the client it excused in the field
     *     was a User-Agent claiming a macOS DESKTOP, Chrome 148, on China Mobile AS56041, whose
     *     header fingerprint was shared by TEN distinct addresses in the window. Ten is twice
     *     the threshold; the rule is worth 80 on its own; the session was published as HUMAN.
     *     A desktop operating system on a cellular network is not the innocent case the
     *     exemption was written for — it is the opposite of it, and it is the shape a
     *     residential-proxy fleet sells.
     *
     *     So the exemption now requires the DEVICE to be a phone or a tablet as well.
     *     Enrich\Ua sets `device_s` on every hit where a User-Agent was logged, so this is a
     *     fact that is already on the document. An UNKNOWN device is not exempt, deliberately:
     *     the exemption has to be earned by evidence, exactly as the crawler exemption below
     *     is, and "we could not tell what this is" is not evidence that it is a handset. A real
     *     phone always says so in its User-Agent — that is how `device_s` was derived.
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
        if (self::isHandsetOnCarrier($s)) {
            return null;
        }
        if (!empty($s['ua_bot']) && ($s['rdns_ok'] ?? null) === true) {
            return null;
        }

        return 'This exact browser fingerprint was seen from ' . (int) $ips
            . ' distinct IP addresses in a 24-hour window around this session'
            . (isset($s['as_type']) && $s['as_type'] !== null ? ' (network type: ' . $s['as_type'] . ')' : '')
            . (($s['device'] ?? null) !== null ? ', on a ' . (string) $s['device'] . ' client' : '')
            . '. One browser cannot be on ' . (int) $ips
            . ' unrelated networks; this is a rotating-proxy fleet.';
    }

    /**
     * Device classes that make a client a HANDSET rather than merely a client on a carrier.
     *
     * Enrich\Ua::matchDevice() can answer desktop, mobile, tablet, bot or unknown. Only the
     * first two of those are a thing that legitimately moves between cell towers with a person
     * carrying it. A tablet is included because a cellular iPad is an ordinary subscriber; a
     * desktop is not, and `unknown` is not either — see isHandsetOnCarrier().
     *
     * @var array<int,string>
     */
    private const HANDSET_DEVICES = ['mobile', 'tablet'];

    /**
     * Is this client the innocent case the mobile exemption was written about?
     *
     * BOTH HALVES, and that is the entire point of the method existing rather than the network
     * test being written inline as it was. The exemption's justification is a HANDSET moving
     * between towers on carrier-grade NAT; testing only the network excused every client that
     * happened to arrive over a cellular ASN, which is where a residential-proxy fleet's mobile
     * exits live. A separate method makes the pairing hard to take apart again and gives the
     * next reader one place to argue with.
     *
     * An absent device is NOT a handset. That direction is deliberate and is the same discipline
     * the rest of this file keeps about null: an exemption is a decision to IGNORE evidence, so
     * it has to be earned by a positive fact, never granted by a missing one. The cost of
     * getting that backwards is a fleet going unscored; the cost of getting it right is that a
     * phone whose User-Agent we failed to parse loses its exemption, and a phone always names
     * itself — `device_s` is derived from the User-Agent that is sitting on the document.
     *
     * @param array<string,mixed> $s
     */
    private static function isHandsetOnCarrier(array $s): bool
    {
        if (($s['as_type'] ?? null) !== 'mobile') {
            return false;
        }
        $device = strtolower((string) ($s['device'] ?? ''));

        return in_array($device, self::HANDSET_DEVICES, true);
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
     * desktop_on_mobile_asn — a desktop operating system on a cellular network.
     *
     * WEIGHT 40, AND IT IS DELIBERATELY NOT DECISIVE. This is the same shape as
     * hosting_asn_browser_ua one category over: a client whose CLAIMED device contradicts the
     * kind of network it arrived on. Cellular address space is sold to handsets; a machine
     * announcing macOS or Windows on it is announcing something a carrier does not usually
     * carry, and mobile exits are exactly what a residential-proxy operator advertises as the
     * hardest addresses to block.
     *
     * THE FALSE-POSITIVE STORY IS REAL AND IT IS WHY THIS IS 40. Tethering is ordinary: a laptop
     * on a phone's hotspot presents a desktop User-Agent from a mobile ASN and is a person. So
     * does a cellular USB modem, a 4G office failover link, and a fixed-wireless home connection
     * whose operator's AS name reads as a carrier. Those populations are large enough that a
     * decisive weight here would accuse real people daily, which is the failure this whole
     * ruleset is built to avoid. Forty cannot reach any verdict past `unknown` on its own and is
     * meant to corroborate — and the session that prompted it had a ten-address fingerprint
     * cluster to corroborate with.
     *
     * IT DOES NOT DOUBLE-COUNT THE EXEMPTION IT SITS BESIDE. isHandsetOnCarrier() decides
     * whether fp_cluster_proxy_fleet is silenced; this decides whether the same contradiction is
     * worth points of its own. They read the same two facts and answer different questions, and
     * a session can legitimately trip this one while tripping nothing else.
     *
     * A declared crawler is excluded for the same reason it is excluded from
     * hosting_asn_browser_ua: a client that never claimed to be a desktop browser is not
     * contradicting itself, and a crawler on a carrier ASN is just a crawler with an odd exit.
     *
     * @param array<string,mixed> $s
     */
    private function ruleDesktopOnMobileAsn(array $s): ?string
    {
        if (($s['as_type'] ?? null) !== 'mobile') {
            return null;
        }
        if (!empty($s['ua_bot'])) {
            return null;
        }
        if (strtolower((string) ($s['device'] ?? '')) !== 'desktop') {
            return null;
        }

        return 'A User-Agent claiming a desktop operating system'
            . (($s['os'] ?? null) !== null ? ' (' . (string) $s['os'] . ')' : '')
            . ' arriving from cellular address space'
            . (isset($s['asn']) && $s['asn'] !== null ? ' (AS' . (int) $s['asn'] . ')' : '')
            . '. Carriers sell those addresses to handsets. Weak alone — a tethered laptop looks '
            . 'identical — and meaningful alongside another signal.';
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
     * LOGHOUND'S OWN BEACON SCRIPT SILENCES THE RULE, and this is the deliberate counterweight
     * to excluding it from `sub_resources`. Sessionizer stopped counting `/b.js` as site traffic,
     * which is correct — it is not the measured site's asset — but a visitor whose only
     * sub-resource WAS `/b.js` would then present as "took the markup and left" and newly collect
     * 25 bot points, on the strength of having done exactly what Loghound's own script tag told
     * their browser to do. That is a false positive manufactured by the measurement, which is the
     * worst kind. `own_assets` is the evidence that the renderer did go back to a server for
     * something the markup referenced, so the rule has nothing to say and says nothing. It is the
     * conservative direction: the rule can only fail to fire, never fire wrongly.
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
        if ((int) ($s['own_assets'] ?? 0) > 0) {
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
