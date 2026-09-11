<?php
/**
 * Loghound — the mark in front of a value must match the value set behind it.
 *
 * `public/assets/js/icons.js` draws a small mark for every value of every closed dimension.
 * It is a second table of value names, in a second language, next to the PHP that produces
 * them — which is exactly the shape that drifts, and it had:
 *
 *   - `as_type_s: business`, which Enrich\Asn cannot return, offering a category the product
 *     does not have; and no `unknown`, which is the commonest answer it does return, so an
 *     unclassified network was drawn with the dimension's fallback — a datacentre rack.
 *   - `device_s: tv`, which Enrich\Ua cannot return; and no `bot` or `unknown`, both of which
 *     it does, with a fallback that was byte-identical to the desktop shape.
 *   - `bot_class_s`: three values Score\Rules::classify() cannot return, and six of the eight
 *     it can missing — `none` among them, so "not automation" was drawn as a robot.
 *   - `bot_verdict_s: evasive`, which is a population key and not a verdict.
 *   - `ua_bot_cat_s: archive` and `os_s: iPadOS`, neither of which the parser emits.
 *
 * These tests read the PRODUCERS — the real PHP that decides each value — and compare. They do
 * not hold a list of their own, because a third copy of the value set would be a third thing
 * to keep in step.
 *
 * A mark for an impossible value and a missing mark for a real one are the same defect from
 * opposite sides, and the second is the one that reaches a person.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Panel\Layout;
use Loghound\Panel\Vocabulary;

/** The icons module as source. */
function lh_icons_src(): string
{
    $path = dirname(__DIR__) . '/public/assets/js/icons.js';
    if (!is_file($path)) {
        lh_fail('public/assets/js/icons.js is missing');
    }
    return (string) file_get_contents($path);
}

/**
 * The keys icons.js declares for one dimension, in source order.
 *
 * Parses the object literal between `<dimension>: {` and its closing brace, taking the key at
 * the start of each line. Quoted keys are accepted because a value with a space in it — the
 * `Windows Phone` OS family — has to be written that way.
 *
 * @return string[]
 */
function lh_icon_keys(string $dimension): array
{
    $src = lh_icons_src();
    $start = strpos($src, "\n    " . $dimension . ': {');
    if ($start === false) {
        lh_fail('icons.js declares no table for ' . $dimension);
    }
    $end = strpos($src, "\n    },", $start);
    if ($end === false) {
        lh_fail('icons.js table for ' . $dimension . ' is not closed');
    }
    $block = substr($src, $start, $end - $start);

    preg_match_all("/^\s{8}'?([A-Za-z0-9_ ]+)'?:\s*\[/m", $block, $m);
    return array_values(array_filter($m[1], static fn (string $k): bool => $k !== '_'));
}

/** Does icons.js declare a fallback for this dimension? */
function lh_icon_has_fallback(string $dimension): bool
{
    $src = lh_icons_src();
    $start = strpos($src, "\n    " . $dimension . ': {');
    $end   = $start === false ? false : strpos($src, "\n    },", $start);
    if ($start === false || $end === false) {
        return false;
    }
    return (bool) preg_match("/^\s{8}_:\s*\[/m", substr($src, $start, $end - $start));
}

/**
 * The path list icons.js gives one key, as a normalised string, for comparing two entries.
 *
 * Used to prove a value is not merely PRESENT but drawn differently from the dimension's
 * fallback — which is the half of the defect that actually reaches a reader: `device_s`'s
 * fallback was the desktop shape, so "unknown" and "bot" were both a person at a computer.
 */
function lh_icon_paths(string $dimension, string $key): string
{
    $src = lh_icons_src();
    $start = strpos($src, "\n    " . $dimension . ': {');
    $end   = $start === false ? false : strpos($src, "\n    },", $start);
    if ($start === false || $end === false) {
        lh_fail('icons.js has no table for ' . $dimension);
    }
    $block = substr($src, $start, $end - $start);
    $quoted = preg_quote($key, '/');
    if (!preg_match("/^\s{8}'?" . $quoted . "'?:\s*(\[[^\]]*\])/m", $block, $m)) {
        lh_fail('icons.js has no entry for ' . $dimension . '/' . $key);
    }
    return (string) preg_replace('/\s+/', '', $m[1]);
}

/**
 * Every bot class Score\Rules::classify() can return, read out of its own source.
 *
 * @return string[]
 */
function lh_producer_bot_classes(): array
{
    $path = dirname(__DIR__) . '/src/Score/Rules.php';
    $src  = (string) file_get_contents($path);
    $from = strpos($src, 'public function classify(');
    if ($from === false) {
        lh_fail('Score\\Rules::classify() has moved');
    }
    $body = substr($src, $from, 3000);
    $body = substr($body, 0, strpos($body, "\n    }") ?: null);

    preg_match_all("/return '([a-z_]+)';/", $body, $m);
    $out = array_values(array_unique($m[1]));
    sort($out);
    return $out;
}

/**
 * Every device class Enrich\Ua::matchDevice() can return.
 *
 * @return string[]
 */
function lh_producer_devices(): array
{
    $src  = (string) file_get_contents(dirname(__DIR__) . '/src/Enrich/Ua.php');
    $from = strpos($src, 'matchDevice(string');
    if ($from === false) {
        lh_fail('Enrich\\Ua::matchDevice() has moved');
    }
    $body = substr($src, $from, 2000);
    $body = substr($body, 0, strpos($body, "\n    }") ?: null);

    preg_match_all("/return '([a-z]+)';/", $body, $m);
    $out = array_values(array_unique($m[1]));

    // A declared bot is given its device class outside matchDevice(), by the branch that
    // recognises the crawler in the first place. It is a value the field really holds.
    if (str_contains($src, "'device_s'      = 'bot'") || str_contains($src, "['device_s']      = 'bot'")) {
        $out[] = 'bot';
    }
    $out = array_values(array_unique($out));
    sort($out);
    return $out;
}

/**
 * Every referrer class Parser::refererType() can return.
 *
 * @return string[]
 */
function lh_producer_referer_types(): array
{
    $src  = (string) file_get_contents(dirname(__DIR__) . '/src/Parser.php');
    $from = strpos($src, 'private function refererType(');
    if ($from === false) {
        lh_fail('Parser::refererType() has moved');
    }
    $body = substr($src, $from, 3000);
    $body = substr($body, 0, strpos($body, "\n    }") ?: null);

    preg_match_all("/return '([a-z]+)';/", $body, $m);
    $out = array_values(array_unique($m[1]));
    sort($out);
    return $out;
}

return [
    'every mark icons.js draws is for a value its producer can actually emit' =>
        function (): void {
            // The vocabulary is the authority for the four dimensions that have one, and it is
            // itself held to the producers by tests/test_facets.php.
            foreach (['bot_verdict_s', 'bot_class_s', 'as_type_s', 'ua_bot_cat_s', 'referer_type_s'] as $field) {
                $real = Vocabulary::knownValues($field);
                foreach (lh_icon_keys($field) as $key) {
                    lh_true(
                        in_array($key, $real, true),
                        'icons.js draws ' . $field . '/' . $key . ', which nothing can produce — '
                        . 'an icon for an impossible value implies a category the product does not have. '
                        . 'Real values: ' . implode(', ', $real)
                    );
                }
            }

            foreach (lh_icon_keys('device_s') as $key) {
                lh_true(
                    in_array($key, lh_producer_devices(), true),
                    'icons.js draws device_s/' . $key . ', which Enrich\\Ua cannot return'
                );
            }
        },

    'every value of a closed dimension has a mark of its own, not the fallback' =>
        function (): void {
            // THE HALF THAT REACHES A READER. A value with no entry takes the dimension's
            // generic shape — and where that shape is another value's, the mark states
            // something untrue. `device_s`'s fallback WAS the desktop shape, and `as_type_s`'s
            // was the datacentre rack, so "unknown" was drawn as a fact on both.
            $checks = [
                'bot_verdict_s' => Vocabulary::knownValues('bot_verdict_s'),
                'bot_class_s'   => Vocabulary::knownValues('bot_class_s'),
                'as_type_s'     => Vocabulary::knownValues('as_type_s'),
                'ua_bot_cat_s'  => Vocabulary::knownValues('ua_bot_cat_s'),
                'referer_type_s' => Vocabulary::knownValues('referer_type_s'),
                'device_s'      => lh_producer_devices(),
            ];

            foreach ($checks as $field => $values) {
                $keys = lh_icon_keys($field);
                foreach ($values as $value) {
                    // `other` and `link` are the honest generic of their own dimension — a
                    // category whose whole meaning is "none of the above" is correctly drawn
                    // with the fallback and is the one exemption this test allows.
                    if (in_array($value, ['other', 'link'], true) && in_array($value, $keys, true) === false) {
                        continue;
                    }
                    lh_true(
                        in_array($value, $keys, true),
                        $field . '/' . $value . ' is a value the product produces and icons.js has no mark '
                        . 'for it, so it silently takes the dimension fallback'
                    );
                }
            }
        },

    'a value that means "unplaceable" is never drawn as something placed' =>
        function (): void {
            // The exact defect measured: `device_s: unknown` fell through to a fallback that was
            // byte-identical to `desktop`, and `as_type_s: unknown` to one identical to
            // `hosting`. An absence must not be drawn as a finding.
            // An explicit `unknown` and the dimension's fallback are the SAME neutral mark, so a
            // value nobody has added an entry for lands on the honest shape rather than on
            // whichever concrete value the fallback was copied from.
            foreach (['device_s', 'as_type_s'] as $field) {
                lh_same(
                    lh_icon_paths($field, 'unknown'),
                    lh_icon_paths($field, '_'),
                    $field . ': the fallback must be the same neutral mark as `unknown`'
                );
            }

            foreach ([['device_s', 'unknown', 'desktop'], ['as_type_s', 'unknown', 'hosting']] as [$field, $absent, $concrete]) {
                lh_true(
                    lh_icon_paths($field, $absent) !== lh_icon_paths($field, $concrete),
                    $field . '/' . $absent . ' must not be drawn with ' . $concrete . "'s mark"
                );
            }

            lh_true(
                lh_icon_paths('bot_class_s', 'none') !== lh_icon_paths('bot_class_s', '_'),
                'bot_class_s/none means NOT automation and must not take the robot fallback'
            );
        },

    'the accent is only ever applied to a value that exists' =>
        function (): void {
            $src = lh_icons_src();
            if (!preg_match('/const LOUD = \{(.*?)\};/s', $src, $m)) {
                lh_fail('icons.js no longer declares LOUD');
            }
            preg_match_all("/([a-z_]+):\s*\[([^\]]*)\]/", $m[1], $groups, PREG_SET_ORDER);
            lh_true($groups !== [], 'LOUD should name at least one dimension');

            foreach ($groups as $group) {
                $field = $group[1];
                preg_match_all("/'([a-z_]+)'/", $group[2], $values);
                $real = $field === 'device_s' ? lh_producer_devices() : Vocabulary::knownValues($field);
                foreach ($values[1] as $value) {
                    lh_true(
                        in_array($value, $real, true),
                        'LOUD accents ' . $field . '/' . $value . ', which nothing produces — so the accent '
                        . 'this product spends once is spent on nothing at all'
                    );
                }
            }
        },

    'the navigation rail has a mark for every view and none for a view that does not exist' =>
        function (): void {
            $slugs = array_column(Layout::nav(), 'slug');
            $keys  = lh_icon_keys('view');

            foreach ($slugs as $slug) {
                lh_true(
                    in_array($slug, $keys, true),
                    'the rail collapses to icons alone, so view "' . $slug . '" needs one of its own'
                );
            }
            foreach ($keys as $key) {
                lh_true(in_array($key, $slugs, true), 'icons.js draws a rail mark for "' . $key . '", which is not a view');
            }
        },

    'every dimension icons.js knows about still has a fallback to fall back to' =>
        function (): void {
            foreach (['bot_verdict_s', 'browser_s', 'os_s', 'device_s', 'as_type_s',
                      'ua_bot_cat_s', 'bot_class_s', 'view', 'theme', 'referer_type_s'] as $field) {
                lh_true(
                    lh_icon_has_fallback($field),
                    $field . ' needs a `_` entry: an unrecognised value must get the dimension mark, never nothing'
                );
            }
        },

    'no mark carries a colour of its own' =>
        function (): void {
            // The editorial system: currentColor for every stroke, so a mark follows both
            // themes with no second palette. A hex in this file is a mark that would be wrong
            // in one of them.
            $src = (string) preg_replace('#/\*.*?\*/#s', '', lh_icons_src());
            lh_same([], (function () use ($src): array {
                preg_match_all('/#[0-9a-fA-F]{3,8}\b/', $src, $m);
                return $m[0];
            })(), 'icons.js must carry no colour literal');
        },
];
