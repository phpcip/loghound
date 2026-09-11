<?php
/**
 * Loghound — query-shape normalisation.
 *
 * THE PROBLEM. A request log grouped by exact query string tells you nothing. A search box
 * produces a different string for every visitor, so the top of a "most frequent queries"
 * table is a list of one-hit wonders and the expensive pattern underneath it is invisible.
 * What an operator actually needs to know is which SHAPE of query runs, how often, how
 * slowly, and — the one nobody surfaces — which shapes return nothing at all.
 *
 * THE IDEA. `q=title:"foo"` and `q=title:"bar"` are the same query with different literals,
 * and they must land in the same bucket. `q=title:"foo"` and `q=body:"foo"` are different
 * queries and must not. So the literals are stripped and the structure is kept: field
 * names, boolean operators, parentheses, ranges, local params, boosts, the parameter set
 * itself. What survives is the part the application wrote; what is removed is the part the
 * visitor typed.
 *
 * WHY THE RESULT IS STILL HOSTILE. Everything here is derived from `full_request`, which is
 * chosen by whoever queried the index — including the field names that survive
 * normalisation. A shape is data, not markup, and every caller renders it with
 * Security::esc() or textContent. This class does not sanitise for display and must not be
 * relied on to.
 *
 * COST. Every input is length-capped before any pattern runs, every pattern is linear with
 * a bounded repetition count, and the token count is capped. A request log is attacker-
 * influenced, so a normaliser that can be made to backtrack is a denial of service on the
 * panel that reads it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class OpensolrShape
{
    /** Longest `full_request` considered. Beyond this the tail cannot change the shape. */
    public const MAX_INPUT = 8192;

    /** Longest single parameter value skeletonised. */
    private const MAX_VALUE = 2048;

    /** Most parameters read out of one request. */
    private const MAX_PARAMS = 120;

    /** Most tokens kept in one skeletonised value. */
    private const MAX_TOKENS = 200;

    /**
     * Parameters that say nothing about the shape of a query.
     *
     * Response format, pretty-printing and cache-busters change the bytes on the wire and
     * nothing about what Solr does, so leaving them in would split one shape into several.
     *
     * @var array<int,string>
     */
    private const NOISE = [
        'wt', 'json.wrf', 'indent', 'omitheader', 'echoparams', 'version',
        '_', 'ts', 'cb', 'nocache', 'cachebust',
    ];

    /**
     * Parameters whose value IS structure and is kept verbatim.
     *
     * A field list, a query-fields string or a sort clause names fields and weights the
     * application chose. Skeletonising them would erase the very thing that distinguishes
     * one shape from another.
     *
     * @var array<int,string>
     */
    private const FIELDISH = [
        'fl', 'qf', 'pf', 'pf2', 'pf3', 'df', 'sort', 'group.field', 'group.sort',
        'facet.field', 'facet.pivot', 'facet.range', 'facet.interval', 'stats.field',
        'hl.fl', 'mlt.fl', 'collapse.field', 'terms.fl',
    ];

    /**
     * Parameters carrying query syntax, always skeletonised however simple they look.
     *
     * `q=hello` must not be kept verbatim just because it happens to be one word, or every
     * single-word search becomes its own shape and the grouping is worthless.
     *
     * @var array<int,string>
     */
    private const QUERYISH = [
        'q', 'q.alt', 'fq', 'bq', 'bf', 'boost', 'rqq', 'hl.q',
        'facet.query', 'spellcheck.q', 'group.query', 'mlt.q',
    ];

    /**
     * Derive the shape of one request-log document.
     *
     * @param array<string,mixed> $doc A document from the Opensolr request log.
     * @return array{hash:string,handler:string,label:string,params:array<int,array{0:string,1:string}>}
     */
    public static function of(array $doc): array
    {
        return self::normalise(
            (string) ($doc['full_request'] ?? ''),
            (string) ($doc['path'] ?? ''),
            (string) ($doc['q'] ?? '')
        );
    }

    /**
     * Normalise a request into a shape: a handler, a canonical parameter set and a hash.
     *
     * The handler comes from the log's own `path` field when it has one, because that is
     * the platform's parsed answer and is more reliable than re-deriving it from a URL that
     * may be truncated. `full_request` is the source for parameters; when it is absent the
     * already-normalised `q` field is used on its own, which yields a coarser but still
     * honest shape rather than dropping the request from the analysis.
     *
     * @return array{hash:string,handler:string,label:string,params:array<int,array{0:string,1:string}>}
     */
    public static function normalise(string $fullRequest, string $path = '', string $q = ''): array
    {
        $handler = self::handler($path, $fullRequest);
        $pairs   = self::readParams($fullRequest);

        if ($pairs === [] && $q !== '') {
            $pairs = [['q', $q]];
        }

        $shaped = [];
        foreach ($pairs as [$key, $value]) {
            $lower = strtolower($key);
            if (in_array($lower, self::NOISE, true)) {
                continue;
            }
            $shaped[] = $lower . '=' . self::valueOf($lower, $value);
        }

        sort($shaped, SORT_STRING);
        $canonical = $handler . "\n" . implode("\n", $shaped);

        return [
            'hash'    => sha1($canonical),
            'handler' => $handler,
            'label'   => self::readable($handler, $shaped),
            'params'  => array_map(
                static function (string $entry): array {
                    $at = strpos($entry, '=');
                    return $at === false ? [$entry, ''] : [substr($entry, 0, $at), substr($entry, $at + 1)];
                },
                $shaped
            ),
        ];
    }

    /**
     * Normalise one parameter value according to what kind of parameter it is.
     */
    private static function valueOf(string $key, string $value): string
    {
        $value = trim(substr($value, 0, self::MAX_VALUE));

        if (in_array($key, self::QUERYISH, true) || str_ends_with($key, '.facet.query')) {
            return self::skeleton($value);
        }
        if (in_array($key, self::FIELDISH, true) || str_ends_with($key, '.facet.field')) {
            return (string) preg_replace('/\s+/', ' ', $value);
        }
        if ($value === '') {
            return '';
        }
        if (preg_match('/^-?[0-9]+(?:\.[0-9]+)?$/D', $value)) {
            return '#';
        }
        if (preg_match('/^[A-Za-z0-9_.\-]{1,40}$/D', $value)) {
            return $value;
        }
        return self::skeleton($value);
    }

    /**
     * Strip the literals out of a query value while keeping everything structural.
     *
     * Order matters. Local parameters are folded first so their internal spaces cannot
     * confuse the tokeniser; quoted phrases next, so a phrase containing "TO" or a bracket
     * cannot be mistaken for a range; ranges after that; then boosts and fuzziness, which
     * are numeric suffixes on terms that have not been replaced yet.
     *
     * The folded local-parameter block is padded with spaces on both sides, because
     * `{!knn f=v topK=5}[0.1,0.2]` has no space after the brace and would otherwise arrive
     * at the tokeniser as one token — recognised as a local param and returned verbatim,
     * carrying the vector literal into the shape with it.
     */
    public static function skeleton(string $value): string
    {
        $v = substr($value, 0, self::MAX_VALUE);
        $v = (string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $v);
        $v = self::foldLocalParams($v);
        $v = (string) preg_replace('/"(?:[^"\\\\]|\\\\.){0,400}"/', '"?"', $v);
        $v = self::foldRanges($v);
        $v = (string) preg_replace('/\^[0-9]+(?:\.[0-9]+)?/', '^#', $v);
        $v = (string) preg_replace('/~[0-9]*(?:\.[0-9]+)?/', '~#', $v);
        $v = (string) preg_replace('/([()])/', ' $1 ', $v);

        $tokens = preg_split('/\s+/', trim($v), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if (count($tokens) > self::MAX_TOKENS) {
            $tokens = array_slice($tokens, 0, self::MAX_TOKENS);
        }

        $out = [];
        foreach ($tokens as $token) {
            $prefix = '';
            while ($token !== '' && ($token[0] === '+' || $token[0] === '-' || $token[0] === '!')) {
                $prefix .= $token[0];
                $token = substr($token, 1);
            }
            $term = $prefix . self::term($token);
            if ($term === '') {
                continue;
            }
            if ($out !== [] && $out[count($out) - 1] === $term && ($term === '?' || $term === '#')) {
                continue;
            }
            $out[] = $term;
        }

        return implode(' ', $out);
    }

    /**
     * Classify one whitespace-delimited token.
     *
     * Anything the token is not recognised as becomes `?`, which is the safe direction: a
     * literal that slips through unrecognised would split one shape into thousands.
     */
    private static function term(string $token): string
    {
        if ($token === '') {
            return '';
        }
        if ($token === '(' || $token === ')' || $token === '*' || $token === '*:*') {
            return $token;
        }
        if ($token === 'AND' || $token === 'OR' || $token === 'NOT' || $token === 'TO'
            || $token === '&&' || $token === '||') {
            return $token;
        }
        if ($token === '"?"' || str_starts_with($token, '$')) {
            return $token;
        }
        if (str_starts_with($token, '{!')) {
            return $token;
        }
        if ($token[0] === '[' || $token[0] === '{') {
            return preg_match('/^[\[{][#*]TO[#*][\]}]$/D', $token) === 1 ? $token : '[?]';
        }
        if (preg_match('/^-?[0-9]+(?:\.[0-9]+)?$/D', $token)) {
            return '#';
        }

        $colon = strpos($token, ':');
        if ($colon !== false && $colon > 0) {
            $field = substr($token, 0, $colon);
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$/D', $field)) {
                return $field . ':' . self::term(substr($token, $colon + 1));
            }
            return '?';
        }

        return '?';
    }

    /**
     * Fold a `{!parser key=value ...}` block into one space-free token.
     *
     * Local parameters change which parser runs and against which fields, so they are
     * structure and must survive. Their values are normalised with the same rules as
     * ordinary parameters, their keys are sorted, and the whole block is joined with `|`
     * so the tokeniser sees a single token. The pipe is turned back into a space for
     * display in readable().
     */
    private static function foldLocalParams(string $value): string
    {
        return (string) preg_replace_callback(
            '/\{![^}]{0,400}\}/',
            static function (array $m): string {
                $inner = trim(substr($m[0], 2, -1));
                $parts = preg_split('/\s+/', $inner, -1, PREG_SPLIT_NO_EMPTY) ?: [];
                $parser = '';
                $pairs = [];
                foreach ($parts as $part) {
                    $at = strpos($part, '=');
                    if ($at === false) {
                        if ($parser === '' && preg_match('/^[A-Za-z0-9_.\-]{1,40}$/D', $part)) {
                            $parser = $part;
                        }
                        continue;
                    }
                    $key = substr($part, 0, $at);
                    $val = substr($part, $at + 1);
                    if (!preg_match('/^[A-Za-z0-9_.\-]{1,40}$/D', $key)) {
                        continue;
                    }
                    if (str_starts_with($val, '$')) {
                        $pairs[] = $key . '=' . $val;
                    } elseif (preg_match('/^-?[0-9]+(?:\.[0-9]+)?$/D', $val)) {
                        $pairs[] = $key . '=#';
                    } elseif (preg_match('/^[A-Za-z0-9_.\-^]{1,60}$/D', $val)) {
                        $pairs[] = $key . '=' . $val;
                    } else {
                        $pairs[] = $key . '=?';
                    }
                }
                sort($pairs, SORT_STRING);
                $body = array_merge($parser === '' ? [] : [$parser], $pairs);
                return ' {!' . implode('|', $body) . '} ';
            },
            $value
        );
    }

    /**
     * Replace the endpoints of every `[a TO b]` / `{a TO b}` range with placeholders.
     *
     * `*` is kept because an open end is structural — `[* TO NOW]` and `[NOW-1DAY TO NOW]`
     * are genuinely different queries — while a concrete bound is a literal like any other.
     * The result carries no spaces so the tokeniser treats it as one token.
     */
    private static function foldRanges(string $value): string
    {
        return (string) preg_replace_callback(
            '/([\[{])([^\[\]{}]{0,200}?)\s+TO\s+([^\[\]{}]{0,200}?)([\]}])/i',
            static function (array $m): string {
                $end = static fn (string $side): string => trim($side) === '*' ? '*' : '#';
                return $m[1] . $end($m[2]) . 'TO' . $end($m[3]) . $m[4];
            },
            $value
        );
    }

    /**
     * Read the query string of a request into ordered key/value pairs.
     *
     * Split by hand rather than with parse_str(), which collapses repeated parameters and
     * would silently merge `fq=a&fq=b` — the difference between one filter and two is
     * exactly the kind of structure this class exists to keep.
     *
     * @return array<int,array{0:string,1:string}>
     */
    private static function readParams(string $fullRequest): array
    {
        $request = substr($fullRequest, 0, self::MAX_INPUT);
        $at = strpos($request, '?');
        if ($at === false) {
            return [];
        }

        $pairs = [];
        foreach (explode('&', substr($request, $at + 1)) as $chunk) {
            if ($chunk === '' || count($pairs) >= self::MAX_PARAMS) {
                continue;
            }
            $eq = strpos($chunk, '=');
            $key = $eq === false ? $chunk : substr($chunk, 0, $eq);
            $value = $eq === false ? '' : substr($chunk, $eq + 1);
            $key = urldecode($key);
            if ($key === '' || !preg_match('/^[A-Za-z0-9_.\[\]\-]{1,64}$/D', $key)) {
                continue;
            }
            $pairs[] = [$key, urldecode($value)];
        }

        return $pairs;
    }

    /**
     * The handler a request hit.
     *
     * The log's own `path` field wins when it is present; otherwise the last path segment
     * of the request URL is used, which is where the handler sits in `/solr/<core>/select`.
     * Anything unrecognisable becomes "other" rather than being echoed back as a label.
     */
    private static function handler(string $path, string $fullRequest): string
    {
        $candidate = trim($path, "/ \t");
        if ($candidate === '') {
            $request = substr($fullRequest, 0, self::MAX_INPUT);
            $at = strpos($request, '?');
            $urlPath = (string) parse_url($at === false ? $request : substr($request, 0, $at), PHP_URL_PATH);
            $segments = array_values(array_filter(explode('/', $urlPath), static fn ($s): bool => $s !== ''));
            $candidate = $segments === [] ? '' : (string) end($segments);
        }

        return preg_match('/^[A-Za-z0-9_.\-]{1,40}$/D', $candidate) === 1 ? $candidate : 'other';
    }

    /**
     * Render a shape as one line a human can read.
     *
     * Still attacker-influenced — the field names in it came off the wire — so it is
     * escaped at every render site. This only decides what the line says, never that it is
     * safe.
     *
     * @param array<int,string> $shaped
     */
    private static function readable(string $handler, array $shaped): string
    {
        $line = $handler . ($shaped === [] ? '' : '  ' . implode('  ', $shaped));
        $line = str_replace(['[#TO#]', '[*TO#]', '[#TO*]', '[*TO*]', '{#TO#}'], ['[# TO #]', '[* TO #]', '[# TO *]', '[* TO *]', '{# TO #}'], $line);
        $line = str_replace('|', ' ', $line);
        return mb_substr($line, 0, 400);
    }
}
