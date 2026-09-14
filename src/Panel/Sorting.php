<?php
/**
 * Loghound — the order a table is read in, decided by Solr and remembered like a filter.
 *
 * A header press or the phone's sort selects used to reorder only the rows already on screen, so
 * a paged table sorted its current page and nothing else, and the choice was gone on the next
 * request. The order is now a request parameter, `o[<card id>]=<column>:<asc|desc>`, that the
 * card's own action turns into a Solr sort, and Panel\Scope keeps it in the session beside the
 * filters.
 *
 * NOTHING FROM THE REQUEST REACHES SOLR AS TEXT. The column is a key into a map the action
 * declares, the direction is one of two words, and the card id and the column key are checked
 * against fixed patterns before they are stored or read. The Solr expression always comes from
 * the map.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

use Loghound\Security;

final class Sorting
{
    /** The query parameter holding every card's order. */
    public const NS = 'o';

    /** A card id, as Controller::cardOpen() spells one. */
    private const CARD = '/^[a-z][a-z0-9-]{0,47}$/D';

    /** A column key, as an action's order map spells one. */
    private const COLUMN = '/^[a-z][a-z0-9_]{0,31}$/D';

    /** Most card orders one session keeps. */
    private const MAX_CARDS = 80;

    /**
     * The order a card is asked for, resolved against the columns it can sort by.
     *
     * `asked` says whether the request named a column the map knows, so an action that also
     * honours an older parameter can tell a stated order from the default.
     *
     * @param string               $card       The card id the order belongs to.
     * @param array<string,string> $map        Column key => Solr sort expression, without direction.
     * @param string               $defaultKey Column used when the request names none the map knows.
     * @param string               $defaultDir Direction used with the default column.
     * @return array{key:string,dir:string,sort:string,asked:bool}
     */
    public static function pick(string $card, array $map, string $defaultKey, string $defaultDir = 'desc'): array
    {
        [$key, $dir] = self::requested($card);
        $asked = $key !== '' && isset($map[$key]);
        if (!$asked) {
            $key = $defaultKey;
            $dir = $defaultDir === 'asc' ? 'asc' : 'desc';
        }

        return ['key' => $key, 'dir' => $dir, 'sort' => $map[$key] . ' ' . $dir, 'asked' => $asked];
    }

    /**
     * The column and direction the request names for one card, or two empty strings.
     *
     * @return array{0:string,1:string}
     */
    public static function requested(string $card): array
    {
        $all = $_GET[self::NS] ?? null;
        if (!is_array($all) || preg_match(self::CARD, $card) !== 1) {
            return ['', ''];
        }
        $raw = $all[$card] ?? null;
        if (is_array($raw)) {
            $raw = reset($raw);
        }

        return (is_string($raw) ? self::parse($raw) : null) ?? ['', ''];
    }

    /**
     * Split `column:direction`, or null when either half is not one this class accepts.
     *
     * @return array{0:string,1:string}|null
     */
    public static function parse(string $value): ?array
    {
        $parts = explode(':', $value, 2);
        if (count($parts) !== 2 || preg_match(self::COLUMN, $parts[0]) !== 1
            || ($parts[1] !== 'asc' && $parts[1] !== 'desc')) {
            return null;
        }

        return [$parts[0], $parts[1]];
    }

    /**
     * Every card order in a raw parameter, reduced to what may be kept, for Panel\Scope.
     *
     * @param array<mixed> $raw
     * @return array<string,string>
     */
    public static function clean(array $raw): array
    {
        $out = [];
        foreach ($raw as $card => $value) {
            if (count($out) >= self::MAX_CARDS) {
                break;
            }
            if (is_array($value)) {
                $value = reset($value);
            }
            if (!is_string($card) || preg_match(self::CARD, $card) !== 1
                || !is_string($value) || self::parse($value) === null) {
                continue;
            }
            $out[$card] = $value;
        }

        return $out;
    }

    /**
     * The attributes that tell assets/js/sorttable.js a table is ordered by Solr, and how it is now.
     *
     * @param string                       $card  The card id the table belongs to.
     * @param array{key:string,dir:string} $order What pick() resolved.
     * @param string                       $reset Comma-separated URL parameters a new order drops, such as an offset.
     */
    public static function tableAttrs(string $card, array $order, string $reset = ''): string
    {
        return ' data-order-card="' . Security::esc($card) . '"'
            . ' data-order-key="' . Security::esc($order['key']) . '"'
            . ' data-order-dir="' . Security::esc($order['dir']) . '"'
            . ($reset !== '' ? ' data-order-reset="' . Security::esc($reset) . '"' : '');
    }

    /**
     * The attributes that make one header cell order the card in Solr by a column of its map.
     *
     * @param string $column The column key.
     * @param string $first  The direction a first press asks for; empty lets the header decide.
     */
    public static function th(string $column, string $first = ''): string
    {
        return ' data-order="' . Security::esc($column) . '"'
            . ($first === 'asc' || $first === 'desc' ? ' data-order-first="' . $first . '"' : '');
    }
}
