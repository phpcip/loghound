<?php
/**
 * Loghound — CSV writing, and the two things a CSV of hostile data has to get right.
 *
 * ---------------------------------------------------------------------------------
 * 1. FORMULA INJECTION IS THE REAL RISK HERE, NOT QUOTING
 * ---------------------------------------------------------------------------------
 * Every value this product holds was chosen by whoever made the request: paths, query
 * strings, User-Agents, referers, AS organisation names, RIR netnames, search terms. Excel,
 * LibreOffice and Google Sheets all treat a cell whose text begins with `=`, `+`, `-`, `@`,
 * a TAB or a CR as a FORMULA and evaluate it on open — and the formula grammar reaches
 * outside the sheet (`=cmd|' /C calc'!A0`, `=WEBSERVICE(...)`, `=HYPERLINK(...)`). So an
 * export is the one place where this panel hands a file to a program that will execute part
 * of it, and a scraper picks the contents.
 *
 * Neutralisation is a leading apostrophe, which every one of those programs reads as "the
 * rest of this cell is literal text" and does not display. Two details make it hold:
 *
 *   - It is decided on the value with leading whitespace AND leading quote characters
 *     stripped, because ` =1+1` and `"=1+1` are the documented ways round a naive
 *     first-byte check: the spreadsheet trims the padding and evaluates what is left.
 *   - It is applied to TEXT fields only, and never to a number. A number reaches a cell
 *     through Csv::number(), which emits one numeric literal and nothing else — `-5` is the
 *     number minus five to every spreadsheet, while `-1+1` is a formula, and the difference
 *     is that `number()` cannot produce the second. Prefixing numbers instead would turn
 *     every negative figure in the file into text and break the arithmetic the export exists
 *     to enable.
 *
 * The neutralisation is not itself escapable: the apostrophe goes on the front of the whole
 * value, before any padding the attacker chose, so there is no position from which the value
 * can start a formula.
 *
 * ---------------------------------------------------------------------------------
 * 2. QUOTING, LINE ENDINGS, ENCODING
 * ---------------------------------------------------------------------------------
 * RFC 4180: fields containing a quote, a comma, a CR or an LF are wrapped in double quotes
 * and internal quotes are doubled; records end CRLF. A field with leading or trailing space
 * is quoted too — the RFC says the space is part of the field, and quoting is what makes a
 * reader that trims agree with one that does not.
 *
 * A UTF-8 BOM is written. It is the one concession to the programs this file is opened in:
 * without it Excel reads the bytes in the host's legacy codepage, and an AS organisation name
 * or a city outside ASCII arrives as mojibake — an export that silently corrupts half its own
 * text. Every other reader either skips the BOM or names the encoding that includes it
 * (`utf-8-sig`).
 *
 * ---------------------------------------------------------------------------------
 * 3. THE FILE SAYS WHAT IT IS
 * ---------------------------------------------------------------------------------
 * A CSV carries no metadata, so the provenance is written as ordinary two-column records
 * ahead of a blank line and the table's own header row: which view and table it came from,
 * the time range, the virtual host, every filter WITH ITS OPERATOR, the sort order, and what
 * the file covers when the table it came from is capped. That last line is the point of the
 * block. A file named "sessions" holding the first page of sessions is a lie somebody builds
 * a report on, and once the file has left the product nothing on screen can correct it.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound;

final class Csv
{
    /**
     * The hard ceiling on rows in any one export.
     *
     * Not a formatting concern: the export endpoint is a GET that makes Solr work, so the
     * total is clamped here as well as per dataset, and the file states the clamp. No
     * dataset may raise it.
     */
    public const MAX_ROWS = 10000;

    /** Record separator. RFC 4180 §2.1. */
    public const EOL = "\r\n";

    /**
     * The first characters a spreadsheet reads as the start of a formula.
     *
     * TAB and CR are in the list because both are accepted as leading whitespace inside a
     * cell and discarded, leaving whatever follows in the evaluated position.
     */
    private const FORMULA_LEADERS = ['=', '+', '-', '@', "\t", "\r"];

    /** Characters stripped before deciding whether a value starts a formula. */
    private const PADDING = " \t\n\r\0\x0B'\"`";

    /**
     * Make a text value inert in a spreadsheet.
     *
     * Returns the value unchanged when it cannot begin a formula, so the file stays readable:
     * only the values that would have been evaluated gain the apostrophe.
     */
    public static function neutralise(string $value): string
    {
        if ($value === '') {
            return '';
        }

        $first = $value[0];
        if (in_array($first, self::FORMULA_LEADERS, true)) {
            return "'" . $value;
        }

        $probe = ltrim($value, self::PADDING);
        if ($probe !== '' && in_array($probe[0], self::FORMULA_LEADERS, true)) {
            return "'" . $value;
        }

        return $value;
    }

    /**
     * Quote one field per RFC 4180.
     *
     * The value is already final: neutralisation, number formatting and date formatting all
     * happen before this, because quoting is about the file's grammar and has nothing to say
     * about what a spreadsheet does with the text inside a cell.
     */
    public static function field(string $value): string
    {
        $needsQuotes = strpbrk($value, ",\"\r\n") !== false
            || $value !== trim($value, " \t");

        if (!$needsQuotes) {
            return $value;
        }

        return '"' . str_replace('"', '""', $value) . '"';
    }

    /**
     * One record, CRLF-terminated.
     *
     * @param array<int,string> $fields Already formatted, in column order.
     */
    public static function row(array $fields): string
    {
        return implode(',', array_map([self::class, 'field'], $fields)) . self::EOL;
    }

    /**
     * A text cell: control characters removed, formula neutralised.
     *
     * NUL and the other C0 controls are dropped rather than escaped. They cannot appear in a
     * legitimate path or organisation name, they terminate the string for several readers,
     * and a CSV whose cells hold them is a file that parses differently in every tool. TAB is
     * kept as a space so the cell still reads as the value it was.
     */
    public static function text($value): string
    {
        if ($value === null || $value === false) {
            return '';
        }
        if (is_array($value)) {
            return self::text(implode('; ', array_map(static fn ($v): string => is_scalar($v) ? (string) $v : '', $value)));
        }
        if ($value === true) {
            return 'yes';
        }

        $out = (string) $value;
        $out = str_replace("\t", ' ', $out);
        $out = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $out);

        return self::neutralise($out);
    }

    /**
     * A numeric cell, unformatted.
     *
     * No thousands separator, no percent sign, no currency: the whole point is that a
     * spreadsheet reads the cell as a number and can do arithmetic on it. A null stays EMPTY
     * rather than becoming 0 — SPEC §1 forbids fabricating a measurement, and an absent
     * value averaged as zero is exactly that.
     *
     * The output is one numeric literal, which is what makes it safe to write without
     * neutralising: `-5` is a number to every spreadsheet, and this function cannot emit the
     * operator sequence that would make it a formula.
     */
    public static function number($value): string
    {
        if ($value === null || $value === '' || is_bool($value) || is_array($value)) {
            return '';
        }
        if (!is_numeric($value)) {
            return '';
        }

        $num = $value + 0;
        if (is_int($num)) {
            return (string) $num;
        }

        $out = rtrim(rtrim(number_format((float) $num, 6, '.', ''), '0'), '.');

        return $out === '' || $out === '-' ? '0' : $out;
    }

    /**
     * An instant, in the format the panel shows everywhere else.
     *
     * `mm/dd/yyyy hh:mm:ss`, rendered in the panel's display timezone rather than in UTC,
     * because the operator reading the file is the one who set that timezone and a column
     * that disagrees with the table it was exported from is a column nobody can reconcile.
     * The timezone is named in the file's own header block so the offset is never implied.
     */
    public static function moment($value, string $tz = 'UTC'): string
    {
        if (!is_string($value) || trim($value) === '') {
            return '';
        }

        /* AN ABSOLUTE INSTANT OR NOTHING. This handed the raw value to DateTimeImmutable,
           which accepts date MATH as readily as a date: `now`, `tomorrow`, `-1 year`,
           `yesterday 14:00` and `@0` all parse, and each one came out as a plausible,
           well-formatted timestamp computed from the moment of export. A cell whose value was
           not a date therefore did not read as absent — it read as a measurement, and a
           different one every time the file was taken. number() directly above refuses to turn
           an absent value into a 0 for exactly this reason and says so; this is the same rule,
           and a document read back from Solr is untrusted input like any other.

           The accepted shape is Solr's own date format, which is what a date field holds. */
        $text = trim($value);
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/D', $text) !== 1) {
            return '';
        }

        try {
            $when = new \DateTimeImmutable($text);
            $when = $when->setTimezone(new \DateTimeZone($tz));
        } catch (\Throwable $e) {
            return '';
        }

        return $when->format('m/d/Y H:i:s');
    }

    /**
     * A boolean cell.
     *
     * Three states, not two: a field the measured site never reported is absent on the
     * document, and "no" would be a claim nobody made.
     */
    public static function flag($value): string
    {
        if ($value === null) {
            return '';
        }
        /* A STRUCTURE IS NOT A THIRD BOOLEAN. An array reached `$value ? 'yes' : 'no'` and came
           out as a definite answer decided by whether it happened to be empty — "no" for `[]`
           and "yes" for anything in it. That is the same fabrication the null branch above
           exists to prevent, so it takes the same route: unknown stays unknown. */
        if (is_array($value) || is_object($value)) {
            return '';
        }
        if (is_string($value)) {
            $value = $value !== '' && $value !== 'false' && $value !== '0';
        }

        return $value ? 'yes' : 'no';
    }

    /**
     * A download filename that distinguishes three exports in one folder.
     *
     * The view, the table, the time range and the moment it was taken, all as slugs, so the
     * name is safe in a Content-Disposition header by construction rather than by escaping:
     * nothing outside `[a-z0-9-]` survives slug().
     */
    public static function filename(string $view, string $dataset, string $range, string $tz = 'UTC'): string
    {
        $stamp = self::moment(gmdate('c'), $tz);
        $stamp = str_replace(['/', ':', ' '], ['-', '', '-'], $stamp);

        return implode('-', array_filter([
            'loghound',
            self::slug($view),
            self::slug($dataset),
            self::slug($range),
            self::slug($stamp),
        ])) . '.csv';
    }

    /** Reduce a string to `[a-z0-9-]`, for a filename or a query key. */
    public static function slug(string $value): string
    {
        $out = strtolower($value);
        $out = (string) preg_replace('/[^a-z0-9]+/', '-', $out);

        return trim($out, '-');
    }

    /**
     * Send the response headers for a CSV download.
     *
     * The filename is already reduced to `[a-z0-9.-]` by filename(), so there is no CRLF and no
     * quote that could break out of the Content-Disposition header — it is safe by construction
     * rather than by escaping, which is the only way to be sure of a header built from a value.
     *
     * A no-op once output has begun. That is the CLI case — the test runner has already printed —
     * and it is also the honest answer in the streaming case: a second call after the first byte
     * could not change the response anyway, and warning about it would write PHP's own notice into
     * the middle of a CSV.
     */
    public static function headers(string $filename): void
    {
        if (headers_sent()) {
            return;
        }

        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-store, private');
        header('X-Content-Type-Options: nosniff');
    }

    /**
     * Drop every output buffer between here and the socket, so the response streams.
     *
     * The buffers matter as much as the headers: a paged export writes as it reads so its memory
     * footprint is one page, and an output buffer left on would accumulate the whole file behind
     * it and undo that.
     *
     * A NO-OP ON THE COMMAND LINE, and that is a real distinction rather than a test hook: with no
     * client socket there is nothing to stream to, and tearing down buffers there would destroy
     * whatever the calling process had put in place to capture the output — which is exactly what
     * the export tests do.
     */
    public static function unbuffer(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        while (ob_get_level() > 0) {
            ob_end_flush();
        }
    }

    /** The UTF-8 byte-order mark, written once before anything else. */
    public static function bom(): string
    {
        return "\xEF\xBB\xBF";
    }

    /** Write one already-built chunk and push it towards the client. */
    public static function put(string $chunk): void
    {
        echo $chunk;
        if (PHP_SAPI !== 'cli') {
            flush();
        }
    }
}
