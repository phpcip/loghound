<?php
/**
 * Loghound — how a dimension's stored values are spoken.
 *
 * WHAT THIS FIXES. Several fields in the schema hold internal identifiers: a verdict is
 * `likely_human`, a bot class is `declared_crawler`, a network type is `hosting`, a referrer
 * type is `ai`, a fired signal is `fp_cluster_proxy_fleet`. Those are the right things to
 * STORE — they are stable, they are what a filter carries in the URL, they are what an
 * operator greps for, and they are what the documentation names — and they were also what the
 * panel PRINTED, in every facet, table, dialog and chart label. Somebody who has never read
 * `src/Score/Rules.php` cannot tell from a list of slugs which one means "this is a declared
 * crawler" and which means "this looks like hidden automation".
 *
 * So every such dimension gets a label and, where there is something worth saying, a sentence.
 * Three rules hold this together:
 *
 *  1. **The slug stays.** It is the filter value, so filtering, multi-select and the three
 *     boolean operators keep working on it unchanged. Only the presentation is new, and the
 *     slug stays visible beside the label rather than being hidden behind it.
 *  2. **An unknown value renders as itself.** A value from an index written by a newer
 *     Loghound, a rule an operator added, a class this version has not heard of: it comes out
 *     as the slug, never as a wrong-but-plausible label and never as blank.
 *  3. **One source per vocabulary.** The signal wording lives with the rules that produce it
 *     (\Loghound\Score\Rules::REASONS) and is read from there, not copied. Nothing else keeps
 *     a second table of it.
 *
 * Fields that already hold words a person uses — a browser name, an operating system, a city,
 * an AS organisation, a netname, a virtual host, a path, a TLS version — are deliberately
 * absent. There is nothing to translate, and a half-populated map over real-world values
 * would mean some rows got a label and some did not.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Score\Rules;

final class Vocabulary
{
    /**
     * The five verdicts.
     *
     * `unknown` is given a sentence because it is the one an operator misreads: it does not
     * mean the scorer failed, it means the evidence did not reach a conclusion in either
     * direction, and that is a finding rather than a gap.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const VERDICTS = [
        'human'        => ['label' => 'Human', 'why' => 'Scored low enough that we believe a person drove this session.'],
        'likely_human' => ['label' => 'Likely human', 'why' => 'Some weak automation signals, not enough to call it a bot.'],
        'unknown'      => ['label' => 'Unknown', 'why' => 'Scored, and the evidence did not reach a verdict either way. Not a failure to measure.'],
        'likely_bot'   => ['label' => 'Likely bot', 'why' => 'Enough signals to suspect automation, short of the bot threshold.'],
        'bot'          => ['label' => 'Bot', 'why' => 'Automation, honest or not. Look at the class to tell which.'],
    ];

    /**
     * The bot classes, which are what separates honest automation from evasive automation.
     *
     * SPEC §7 is explicit that conflating the two is what makes existing tools useless, and a
     * reader can only act on that distinction if the class says which side it is on. `none` is
     * every session that was not classed as automation at all, and it is labelled rather than
     * left as a word that reads like a missing value.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const BOT_CLASSES = [
        'declared_crawler' => ['label' => 'Declared crawler', 'why' => 'Said what it was in the User-Agent and was telling the truth. Honest traffic.'],
        'ai_crawler'       => ['label' => 'AI crawler', 'why' => 'A declared crawler collecting for model training or inference.'],
        'monitor'          => ['label' => 'Monitor', 'why' => 'A declared uptime or availability checker.'],
        'spoofed_ua'       => ['label' => 'Spoofed User-Agent', 'why' => 'The headers contradict each other, or a crawler claim failed reverse DNS.'],
        'proxy_fleet'      => ['label' => 'Proxy fleet', 'why' => 'One browser fingerprint arriving from many unrelated networks.'],
        'headless'         => ['label' => 'Headless browser', 'why' => 'A driven or screenless browser: an automation marker, a software rasteriser, or a failed engine claim.'],
        'scripted'         => ['label' => 'Scripted client', 'why' => 'Scored as automation without falling into any of the named classes.'],
        'none'             => ['label' => 'Not automation', 'why' => 'Not classed as a bot of any kind.'],
    ];

    /**
     * Network types, as classified from the AS organisation name (\Loghound\Enrich\Asn).
     *
     * `hosting` is spelled out as a datacentre because that is the inference an operator draws
     * from it, and it is the one that matters: a consumer browser User-Agent arriving from
     * hosting address space is the `hosting_asn_browser_ua` signal.
     *
     * THIS LIST IS EXACTLY WHAT THE CLASSIFIER CAN PRODUCE, and it has to stay that way. The
     * value browser offers every entry here as a filter, so a value the classifier cannot emit
     * is a filter that returns nothing on every index, for ever, with no way for the operator
     * to tell that from "no such traffic this week". There was one: `business`, which no branch
     * of Asn::classifyOrg() can return — it answers with a key of TYPE_KEYWORDS, a value of
     * TYPE_OVERRIDES, or `unknown`. It is gone rather than added to the classifier, because
     * inventing a new network class changes what `hosting_asn_browser_ua` and the
     * `fp_cluster_proxy_fleet` mobile exclusion see, and nobody asked for a scoring change.
     * A test asserts the two sets are identical.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const AS_TYPES = [
        'hosting'  => ['label' => 'Hosting / datacentre', 'why' => 'Cloud, colocation, VPS or CDN address space. People do not browse from servers.'],
        'isp'      => ['label' => 'Consumer ISP', 'why' => 'Residential or business broadband.'],
        'mobile'   => ['label' => 'Mobile carrier', 'why' => 'Cellular address space, where many subscribers share few addresses.'],
        'vpn'      => ['label' => 'VPN / anonymiser', 'why' => 'A commercial VPN, a private relay or a Tor exit.'],
        'edu'      => ['label' => 'Education', 'why' => 'A university, school or research network.'],
        'gov'      => ['label' => 'Government', 'why' => 'A public-sector or military network.'],
        'unknown'  => ['label' => 'Unclassified', 'why' => 'The AS organisation name did not match any known pattern.'],
    ];

    /**
     * Referrer types, as derived in \Loghound\Parser::refererType().
     *
     * `ad` and `ai` are two-letter codes on the document and are the two nobody guesses. `link`
     * is the fallback — some other site linked here — and reads as nothing at all until it is
     * named.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const REFERER_TYPES = [
        'direct'   => ['label' => 'Direct', 'why' => 'No referrer was sent: a bookmark, a typed address, or a client that strips it.'],
        'internal' => ['label' => 'Same site', 'why' => 'Referred from this site, or from a host configured as internal.'],
        'ad'       => ['label' => 'Paid ad', 'why' => 'Carried an ad-network click id or a paid utm_medium. Tested before search, so a paid Google click is never counted as organic.'],
        'ai'       => ['label' => 'AI assistant', 'why' => 'Referred from an AI assistant or chat product.'],
        'search'   => ['label' => 'Search engine', 'why' => 'Organic: referred from a search engine with no paid click id.'],
        'social'   => ['label' => 'Social network', 'why' => 'Referred from a social platform.'],
        'link'     => ['label' => 'Another site', 'why' => 'Referred from a site that is none of the above.'],
    ];

    /**
     * Declared bot categories, from the User-Agent table in \Loghound\Enrich\Ua.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const BOT_CATEGORIES = [
        'search'  => ['label' => 'Search crawler', 'why' => 'Indexes pages for a search engine.'],
        'ai'      => ['label' => 'AI crawler', 'why' => 'Collects pages for model training or for answering in an assistant.'],
        'seo'     => ['label' => 'SEO tool', 'why' => 'A commercial backlink or audit crawler.'],
        'social'  => ['label' => 'Social preview', 'why' => 'Fetches a page to build a link preview.'],
        'monitor' => ['label' => 'Uptime monitor', 'why' => 'Checks that the site is answering.'],
        'other'   => ['label' => 'Other declared bot', 'why' => 'Declared itself a bot and does not fall into the named categories.'],
    ];

    /**
     * Which transport planes a session was seen on.
     *
     * Three stored values, and the interesting one is the absence. `planes_s` has NO schema
     * default, so every session indexed before the field existed carries none of these — and that
     * absence means "this installation had not started recording which planes it had", not
     * "log only". It is the same trap as `provisional_b`: the honest way to ask for sessions that
     * have a transport plane is to EXCLUDE `beacon_only`, which keeps all of that history, and the
     * "None of" operator is what spells it. Asking for `log_only` instead would silently drop
     * every older session, and the count would look like a fact.
     *
     * The remainder is offered as its own row by Facets::withAbsentValue(), labelled "Not
     * reported" and filtering as exactly that exclusion — so the reader can both see how much
     * history predates the field and select it, rather than having it quietly folded into one of
     * the three.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const PLANES = [
        'log_only'    => ['label' => 'Server log only', 'why' => 'Seen in the webserver log and never by the beacon: no script ran, or the visitor left before it reported.'],
        'log_beacon'  => ['label' => 'Log and beacon', 'why' => 'Seen on both planes, so the log counts and the measured timings describe the same visit.'],
        'beacon_only' => ['label' => 'Beacon only', 'why' => 'Reported by the beacon with no matching log line — the request never reached the measured webserver, or its log has not been read yet.'],
    ];

    /**
     * The boolean dimension, whose two stored values are the words `true` and `false`.
     *
     * A boolean facet printing "true" is the clearest case of a stored value leaking into the
     * interface. The THIRD state — the field absent, because the measured site never said
     * either — is not in here: it is not a value, it cannot be a bucket, and it is expressed
     * with the "None of" operator over both values instead.
     *
     * @var array<string,array{label:string,why:string}>
     */
    private const SIGNED_IN = [
        'true'  => ['label' => 'Signed in', 'why' => 'The measured site reported an authenticated visitor.'],
        'false' => ['label' => 'Anonymous', 'why' => 'The measured site reported an unauthenticated visitor.'],
    ];

    /**
     * Every dimension that has a vocabulary at all.
     *
     * Checked before a lookup so a caller can ask "does this field need translating" without
     * translating a value first, which is what lets a table decide between one column and two.
     */
    public static function has(string $field): bool
    {
        return in_array($field, [
            'bot_verdict_s',
            'bot_class_s',
            'as_type_s',
            'referer_type_s',
            'ua_bot_cat_s',
            'bot_reasons_ss',
            'signed_in_b',
            'planes_s',
        ], true);
    }

    /**
     * The label and explanation for one value of one dimension.
     *
     * Returns the raw value as the label when there is nothing to say about it, so a caller can
     * always render `label` and be correct. `why` is an empty string rather than a guess when
     * the value is not in the vocabulary — an invented explanation is worse than none.
     *
     * @return array{label:string,why:string,severity:string}
     */
    public static function value(string $field, string $value): array
    {
        if ($field === 'bot_reasons_ss') {
            $reason = Rules::reason($value);
            return [
                'label'    => $reason['label'],
                'why'      => $reason['why'],
                'severity' => $reason['severity'],
            ];
        }

        $table = match ($field) {
            'bot_verdict_s'  => self::VERDICTS,
            'bot_class_s'    => self::BOT_CLASSES,
            'as_type_s'      => self::AS_TYPES,
            'referer_type_s' => self::REFERER_TYPES,
            'ua_bot_cat_s'   => self::BOT_CATEGORIES,
            'signed_in_b'    => self::SIGNED_IN,
            'planes_s'       => self::PLANES,
            default          => [],
        };

        $entry = $table[$value] ?? null;
        if ($entry === null) {
            return ['label' => $value, 'why' => '', 'severity' => ''];
        }
        return ['label' => $entry['label'], 'why' => $entry['why'], 'severity' => ''];
    }

    /** Just the label, for a caller that has no room for a sentence. */
    public static function label(string $field, string $value): string
    {
        return self::value($field, $value)['label'];
    }

    /**
     * Every vocabulary, for the boot payload.
     *
     * ONE TABLE, SERVED ONCE, exactly as the country names are. Every surface in the panel shows
     * a verdict, a bot class, a network type, a referrer type and a fired signal in words, and a
     * table cell rendered by the front end needs those words without asking the server per row.
     * Shipping it here rather than keeping a second copy inside a JS module is what stops the two
     * drifting — and this side is the authority for the value SET and the WORDS. The MARK in
     * front of a value is a separate concern and lives in assets/js/icons.js, which is the
     * authority for nothing but the drawing and falls back to a generic shape for a value it
     * does not recognise.
     *
     * Small: six closed vocabularies and twenty reason codes — the seventeen weighted rules plus
     * `provisional_session`, `beacon_only_session` and `no_bot_signals`, which are worth no
     * points and are emitted anyway so a verdict can explain itself. A few kilobytes, on a page
     * that is behind authentication and never cached.
     *
     * @return array<string,array<string,array{label:string,why:string}>>
     */
    public static function all(): array
    {
        $out = [];
        foreach (['bot_verdict_s', 'bot_class_s', 'as_type_s', 'referer_type_s', 'ua_bot_cat_s', 'signed_in_b', 'planes_s', 'bot_reasons_ss'] as $field) {
            foreach (self::knownValues($field) as $value) {
                $spoken = self::value($field, $value);
                $out[$field][$value] = ['label' => $spoken['label'], 'why' => $spoken['why']];
            }
        }
        return $out;
    }

    /**
     * Every value of a dimension that has a closed vocabulary, in display order.
     *
     * Used by the value browser to offer a value that is in the schema but has no traffic in
     * the selected range, which is a legitimate thing to want on a small site: "show me the
     * sessions with a forged beacon" should be answerable as a filter even when the answer is
     * none, rather than the option being absent because the answer is none.
     *
     * Empty for an open vocabulary — a country, a path, an AS organisation — where the set of
     * values is whatever the traffic contained.
     *
     * @return array<int,string>
     */
    public static function knownValues(string $field): array
    {
        return match ($field) {
            'bot_verdict_s'  => array_keys(self::VERDICTS),
            'bot_class_s'    => array_keys(self::BOT_CLASSES),
            'as_type_s'      => array_keys(self::AS_TYPES),
            'referer_type_s' => array_keys(self::REFERER_TYPES),
            'ua_bot_cat_s'   => array_keys(self::BOT_CATEGORIES),
            'bot_reasons_ss' => Rules::reasonCodes(),
            'signed_in_b'    => array_keys(self::SIGNED_IN),
            'planes_s'       => array_keys(self::PLANES),
            default          => [],
        };
    }
}
