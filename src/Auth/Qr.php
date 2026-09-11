<?php
/**
 * Loghound — QR encoder, enough of ISO/IEC 18004 to carry an otpauth URI.
 *
 * WHY THIS EXISTS AT ALL. Two-factor enrollment needs a QR code on the page, and every
 * convenient way of getting one is a way of handing the shared secret to somebody else: a
 * chart-server URL puts the secret in a third party's access log, and a CDN'd JavaScript
 * encoder puts it behind a script this panel's Content-Security-Policy correctly refuses to
 * load. There is no Composer here either. So it is written out, and it runs on the same
 * machine as the secret it draws.
 *
 * WHAT IS IMPLEMENTED, AND WHAT IS NOT. Byte mode, error-correction level M, versions 1
 * through 10 — a symbol up to 57×57 modules holding up to 213 bytes. An otpauth URI for a
 * 160-bit secret is around 120 bytes, so version 10 leaves room for a long site name and a
 * long account name and nothing has to degrade. Numeric, alphanumeric and Kanji modes,
 * structured append, ECI, and versions 11 to 40 are NOT implemented: they would be dead code
 * with no caller, and dead code in a security path is a liability. encode() refuses anything
 * it cannot represent rather than producing a symbol that does not decode.
 *
 * WHAT IS IMPLEMENTED IS IMPLEMENTED FULLY. All eight data masks are generated and the one
 * with the lowest penalty under the standard's four rules is chosen; Reed-Solomon is real
 * GF(256) arithmetic over the standard primitive polynomial; codewords are interleaved across
 * blocks the way the standard requires for versions 4 and up; format information carries its
 * BCH(15,5) check bits and version information its BCH(18,6) ones. Skipping any of those
 * produces a symbol that looks plausible in a browser and fails in a phone camera at an
 * angle, which is the worst possible failure mode for an enrollment screen.
 *
 * HOW IT IS KNOWN TO WORK. tests/test_qr.php pins the complete module matrix for a fixed
 * payload, so a regression cannot silently change the output, and asserts the structural
 * invariants a decoder depends on — finder patterns, timing patterns, the dark module, and
 * that the chosen mask really is the lowest-scoring one. The matrices were verified by
 * decoding rendered symbols with an independent reader (zbarimg) during development.
 *
 * COLOUR IS NOT A STYLE CHOICE HERE. svg() always draws dark modules on an explicit light
 * background, whatever theme the panel is in. A reader measures reflectance; an inverted QR
 * code is refused outright by some and read by others, and an enrollment screen that works
 * on one operator's phone and not another's is not acceptable.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

final class Qr
{
    /** Byte-mode indicator, four bits. */
    private const MODE_BYTE = 0b0100;

    /** Error-correction level M, as it appears in the format information. */
    private const EC_LEVEL_M = 0b00;

    /** Highest version this encoder builds. */
    public const MAX_VERSION = 10;

    /**
     * Block structure for error-correction level M, by version.
     *
     * [ec codewords per block, group 1 block count, group 1 data codewords,
     *  group 2 block count, group 2 data codewords]
     *
     * Taken from ISO/IEC 18004 table 9. The byte-mode capacity that follows from each row is
     * asserted in tests/test_qr.php against the published figures (14, 26, 42, 62, 84, 106,
     * 122, 152, 180, 213 bytes), which is what catches a transcription error in this table.
     *
     * @var array<int,array{0:int,1:int,2:int,3:int,4:int}>
     */
    private const BLOCKS = [
        1  => [10, 1, 16, 0, 0],
        2  => [16, 1, 28, 0, 0],
        3  => [26, 1, 44, 0, 0],
        4  => [18, 2, 32, 0, 0],
        5  => [24, 2, 43, 0, 0],
        6  => [16, 4, 27, 0, 0],
        7  => [18, 4, 31, 0, 0],
        8  => [22, 2, 38, 2, 39],
        9  => [22, 3, 36, 2, 37],
        10 => [26, 4, 43, 1, 44],
    ];

    /**
     * Alignment-pattern centre coordinates by version, ISO/IEC 18004 table E.1.
     *
     * Every pairing of these values is a centre, except the three that would sit on top of a
     * finder pattern.
     *
     * @var array<int,int[]>
     */
    private const ALIGNMENT = [
        1  => [],
        2  => [6, 18],
        3  => [6, 22],
        4  => [6, 26],
        5  => [6, 30],
        6  => [6, 34],
        7  => [6, 22, 38],
        8  => [6, 24, 42],
        9  => [6, 26, 46],
        10 => [6, 28, 50],
    ];

    /**
     * Encode text and return the module matrix.
     *
     * @return array<int,array<int,bool>>|null Null when the text does not fit in version 10.
     */
    public static function encode(string $text): ?array
    {
        $version = self::chooseVersion(strlen($text));
        if ($version === null) {
            return null;
        }

        $codewords = self::codewords($text, $version);
        $size = self::size($version);

        $function = self::functionMap($version, $size);
        $base = self::skeleton($version, $size, $function);
        $base = self::placeData($base, $function, $size, $codewords);

        $best = null;
        $bestScore = PHP_INT_MAX;
        for ($mask = 0; $mask < 8; $mask++) {
            $candidate = self::applyMask($base, $function, $size, $mask);
            $candidate = self::placeFormat($candidate, $size, $mask);
            $score = self::penalty($candidate, $size);
            if ($score < $bestScore) {
                $bestScore = $score;
                $best = $candidate;
            }
        }

        return $best;
    }

    /**
     * Render text as an inline SVG QR code.
     *
     * One <path> rather than a rect per module: a version 10 symbol is 3249 modules and a
     * rect for each of them is a hundred kilobytes of markup for no benefit. Horizontal runs
     * within a row are merged into one subpath, which is both smaller and renders faster.
     *
     * The quiet zone is four modules, which the standard requires and which readers really
     * do rely on; it is drawn as part of the light background rather than left to whatever
     * the surrounding page happens to be.
     *
     * @param string $title Accessible name for the graphic; it is escaped, never a secret.
     * @return string|null Null when the payload does not fit.
     */
    public static function svg(string $text, int $moduleSize = 6, int $quiet = 4, string $title = 'QR code'): ?string
    {
        $matrix = self::encode($text);
        if ($matrix === null) {
            return null;
        }

        $moduleSize = max(1, min(40, $moduleSize));
        $quiet = max(0, min(8, $quiet));
        $size = count($matrix);
        $span = ($size + 2 * $quiet) * $moduleSize;

        $path = '';
        for ($row = 0; $row < $size; $row++) {
            $col = 0;
            while ($col < $size) {
                if (!$matrix[$row][$col]) {
                    $col++;
                    continue;
                }
                $run = 0;
                while ($col + $run < $size && $matrix[$row][$col + $run]) {
                    $run++;
                }
                $x = ($col + $quiet) * $moduleSize;
                $y = ($row + $quiet) * $moduleSize;
                $path .= 'M' . $x . ' ' . $y . 'h' . ($run * $moduleSize)
                    . 'v' . $moduleSize . 'h-' . ($run * $moduleSize) . 'z';
                $col += $run;
            }
        }

        $label = htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return '<svg xmlns="http://www.w3.org/2000/svg" width="' . $span . '" height="' . $span . '" '
            . 'viewBox="0 0 ' . $span . ' ' . $span . '" role="img" aria-label="' . $label . '" '
            . 'class="qr">'
            . '<rect width="' . $span . '" height="' . $span . '" fill="#ffffff"/>'
            . '<path d="' . $path . '" fill="#000000"/>'
            . '</svg>';
    }

    /**
     * Render a matrix as text, one character per module.
     *
     * For tests and for a terminal. '#' and '.' rather than '1' and '0' so a pinned matrix in
     * a test file is readable as a picture, and so that a long row of it cannot be mistaken
     * for a hex string by tests/scan-secrets.php.
     *
     * @param array<int,array<int,bool>> $matrix
     */
    public static function toText(array $matrix): string
    {
        $lines = [];
        foreach ($matrix as $row) {
            $line = '';
            foreach ($row as $dark) {
                $line .= $dark ? '#' : '.';
            }
            $lines[] = $line;
        }
        return implode("\n", $lines);
    }

    /** Modules per side for a version. */
    public static function size(int $version): int
    {
        return 17 + 4 * $version;
    }

    /**
     * How many bytes byte-mode holds at level M in a version.
     *
     * Derived from the block table rather than tabled separately, so the two can never
     * disagree: total data bits, less the four-bit mode indicator and the character count
     * field, which widens from 8 to 16 bits at version 10.
     */
    public static function capacity(int $version): int
    {
        if (!isset(self::BLOCKS[$version])) {
            return 0;
        }
        [, $g1, $d1, $g2, $d2] = self::BLOCKS[$version];
        $dataBits = ($g1 * $d1 + $g2 * $d2) * 8;
        return intdiv($dataBits - 4 - self::countBits($version), 8);
    }

    /** The smallest version that holds this many bytes, or null when none does. */
    public static function chooseVersion(int $bytes): ?int
    {
        for ($version = 1; $version <= self::MAX_VERSION; $version++) {
            if ($bytes <= self::capacity($version)) {
                return $version;
            }
        }
        return null;
    }

    /** Width of the byte-mode character count field: 8 bits to version 9, 16 from version 10. */
    private static function countBits(int $version): int
    {
        return $version >= 10 ? 16 : 8;
    }

    /**
     * Build the final interleaved codeword stream for a payload.
     *
     * Three stages, in the order the standard fixes them: the bit stream (mode, length, data,
     * terminator, padding), the split into blocks with Reed-Solomon parity for each, and the
     * interleave. The interleave is what makes a burst of damage land across several blocks
     * instead of destroying one, so it is not an optional tidiness step.
     *
     * @return int[] Codewords, 0-255.
     */
    private static function codewords(string $text, int $version): array
    {
        [$ecPerBlock, $g1, $d1, $g2, $d2] = self::BLOCKS[$version];
        $dataTotal = $g1 * $d1 + $g2 * $d2;

        $bits = self::bitString($text, $version, $dataTotal);

        $data = [];
        for ($i = 0; $i < $dataTotal; $i++) {
            $data[] = (int) bindec(substr($bits, $i * 8, 8));
        }

        $blocks = [];
        $parity = [];
        $offset = 0;
        foreach ([[$g1, $d1], [$g2, $d2]] as [$count, $length]) {
            for ($b = 0; $b < $count; $b++) {
                $block = array_slice($data, $offset, $length);
                $offset += $length;
                $blocks[] = $block;
                $parity[] = ReedSolomon::parity($block, $ecPerBlock);
            }
        }

        $out = [];
        $longest = max(array_map('count', $blocks));
        for ($i = 0; $i < $longest; $i++) {
            foreach ($blocks as $block) {
                if (isset($block[$i])) {
                    $out[] = $block[$i];
                }
            }
        }
        for ($i = 0; $i < $ecPerBlock; $i++) {
            foreach ($parity as $block) {
                $out[] = $block[$i];
            }
        }

        return $out;
    }

    /**
     * The data bit stream, padded to exactly the version's data capacity.
     *
     * The terminator is up to four zero bits and is truncated when the stream is already
     * nearly full, then the stream is padded to a byte boundary, then the pad codewords
     * 0xEC and 0x11 alternate to the end. Those two values are fixed by the standard; they
     * are not arbitrary filler and a decoder does not treat them as data.
     */
    private static function bitString(string $text, int $version, int $dataTotal): string
    {
        $capacityBits = $dataTotal * 8;

        $bits = str_pad(decbin(self::MODE_BYTE), 4, '0', STR_PAD_LEFT);
        $bits .= str_pad(decbin(strlen($text)), self::countBits($version), '0', STR_PAD_LEFT);
        for ($i = 0, $n = strlen($text); $i < $n; $i++) {
            $bits .= str_pad(decbin(ord($text[$i])), 8, '0', STR_PAD_LEFT);
        }

        $bits .= str_repeat('0', min(4, max(0, $capacityBits - strlen($bits))));
        if (strlen($bits) % 8 !== 0) {
            $bits .= str_repeat('0', 8 - (strlen($bits) % 8));
        }

        $pad = ['11101100', '00010001'];
        $i = 0;
        while (strlen($bits) < $capacityBits) {
            $bits .= $pad[$i % 2];
            $i++;
        }

        return $bits;
    }

    /**
     * Map every module that is NOT available for data.
     *
     * Finders and their separators, both timing patterns, the alignment patterns, the format
     * information areas, the dark module, and the version information areas on version 7 and
     * above. Data placement and masking both consult this, which is why it is built once and
     * passed around rather than re-derived: the two must agree exactly or the symbol is
     * unreadable.
     *
     * @return array<int,array<int,bool>>
     */
    private static function functionMap(int $version, int $size): array
    {
        $map = array_fill(0, $size, array_fill(0, $size, false));

        foreach ([[0, 0], [0, $size - 7], [$size - 7, 0]] as [$r, $c]) {
            for ($i = -1; $i <= 7; $i++) {
                for ($j = -1; $j <= 7; $j++) {
                    $rr = $r + $i;
                    $cc = $c + $j;
                    if ($rr >= 0 && $rr < $size && $cc >= 0 && $cc < $size) {
                        $map[$rr][$cc] = true;
                    }
                }
            }
        }

        for ($i = 0; $i < $size; $i++) {
            $map[6][$i] = true;
            $map[$i][6] = true;
        }

        foreach (self::alignmentCentres($version, $size) as [$r, $c]) {
            for ($i = -2; $i <= 2; $i++) {
                for ($j = -2; $j <= 2; $j++) {
                    $map[$r + $i][$c + $j] = true;
                }
            }
        }

        for ($i = 0; $i < 9; $i++) {
            $map[8][$i] = true;
            $map[$i][8] = true;
        }
        for ($i = 0; $i < 8; $i++) {
            $map[8][$size - 1 - $i] = true;
            $map[$size - 1 - $i][8] = true;
        }

        if ($version >= 7) {
            for ($i = 0; $i < 6; $i++) {
                for ($j = 0; $j < 3; $j++) {
                    $map[$size - 11 + $j][$i] = true;
                    $map[$i][$size - 11 + $j] = true;
                }
            }
        }

        return $map;
    }

    /**
     * Every alignment-pattern centre, with the three that collide with a finder removed.
     *
     * @return array<int,array{0:int,1:int}>
     */
    private static function alignmentCentres(int $version, int $size): array
    {
        $coords = self::ALIGNMENT[$version] ?? [];
        $out = [];
        foreach ($coords as $r) {
            foreach ($coords as $c) {
                $onFinder = ($r <= 8 && $c <= 8)
                    || ($r <= 8 && $c >= $size - 9)
                    || ($r >= $size - 9 && $c <= 8);
                if (!$onFinder) {
                    $out[] = [$r, $c];
                }
            }
        }
        return $out;
    }

    /**
     * Draw every function pattern whose colour does not depend on the mask.
     *
     * Format and version information are written later — format because it encodes which mask
     * was chosen, version because it is constant but belongs with it.
     *
     * @param array<int,array<int,bool>> $function
     * @return array<int,array<int,bool>>
     */
    private static function skeleton(int $version, int $size, array $function): array
    {
        $m = array_fill(0, $size, array_fill(0, $size, false));

        foreach ([[0, 0], [0, $size - 7], [$size - 7, 0]] as [$r, $c]) {
            for ($i = 0; $i < 7; $i++) {
                for ($j = 0; $j < 7; $j++) {
                    $edge = ($i === 0 || $i === 6 || $j === 0 || $j === 6);
                    $core = ($i >= 2 && $i <= 4 && $j >= 2 && $j <= 4);
                    $m[$r + $i][$c + $j] = $edge || $core;
                }
            }
        }

        for ($i = 8; $i < $size - 8; $i++) {
            $dark = ($i % 2 === 0);
            $m[6][$i] = $dark;
            $m[$i][6] = $dark;
        }

        foreach (self::alignmentCentres($version, $size) as [$r, $c]) {
            for ($i = -2; $i <= 2; $i++) {
                for ($j = -2; $j <= 2; $j++) {
                    $ring = (max(abs($i), abs($j)) !== 1);
                    $m[$r + $i][$c + $j] = $ring;
                }
            }
        }

        $m[$size - 8][8] = true;

        if ($version >= 7) {
            $bits = self::versionBits($version);
            for ($i = 0; $i < 18; $i++) {
                $bit = (($bits >> $i) & 1) === 1;
                $m[$size - 11 + ($i % 3)][intdiv($i, 3)] = $bit;
                $m[intdiv($i, 3)][$size - 11 + ($i % 3)] = $bit;
            }
        }

        return $m;
    }

    /**
     * Lay the codeword bits into the data region.
     *
     * Two-module-wide columns from the right edge leftwards, alternating upwards and
     * downwards, skipping column 6 because the vertical timing pattern occupies it. Any
     * module left over after the codewords run out stays light, which is exactly what the
     * standard's "remainder bits" are.
     *
     * @param array<int,array<int,bool>> $m
     * @param array<int,array<int,bool>> $function
     * @param int[]                      $codewords
     * @return array<int,array<int,bool>>
     */
    private static function placeData(array $m, array $function, int $size, array $codewords): array
    {
        $bits = '';
        foreach ($codewords as $byte) {
            $bits .= str_pad(decbin($byte), 8, '0', STR_PAD_LEFT);
        }

        $index = 0;
        $total = strlen($bits);
        $upward = true;

        for ($col = $size - 1; $col > 0; $col -= 2) {
            if ($col === 6) {
                $col = 5;
            }
            for ($i = 0; $i < $size; $i++) {
                $row = $upward ? ($size - 1 - $i) : $i;
                foreach ([$col, $col - 1] as $c) {
                    if ($function[$row][$c]) {
                        continue;
                    }
                    $m[$row][$c] = ($index < $total) && $bits[$index] === '1';
                    $index++;
                }
            }
            $upward = !$upward;
        }

        return $m;
    }

    /**
     * XOR one of the eight mask patterns over the data modules only.
     *
     * @param array<int,array<int,bool>> $m
     * @param array<int,array<int,bool>> $function
     * @return array<int,array<int,bool>>
     */
    private static function applyMask(array $m, array $function, int $size, int $mask): array
    {
        for ($i = 0; $i < $size; $i++) {
            for ($j = 0; $j < $size; $j++) {
                if ($function[$i][$j]) {
                    continue;
                }
                if (self::maskBit($mask, $i, $j)) {
                    $m[$i][$j] = !$m[$i][$j];
                }
            }
        }
        return $m;
    }

    /** The eight mask conditions of ISO/IEC 18004 table 10. */
    private static function maskBit(int $mask, int $i, int $j): bool
    {
        switch ($mask) {
            case 0:
                return ($i + $j) % 2 === 0;
            case 1:
                return $i % 2 === 0;
            case 2:
                return $j % 3 === 0;
            case 3:
                return ($i + $j) % 3 === 0;
            case 4:
                return (intdiv($i, 2) + intdiv($j, 3)) % 2 === 0;
            case 5:
                return (($i * $j) % 2) + (($i * $j) % 3) === 0;
            case 6:
                return ((($i * $j) % 2) + (($i * $j) % 3)) % 2 === 0;
            default:
                return ((($i + $j) % 2) + (($i * $j) % 3)) % 2 === 0;
        }
    }

    /**
     * Write both copies of the format information for a chosen mask.
     *
     * Two copies, because the format information is the one thing a decoder cannot recover
     * without: if the top-left copy is damaged it reads the one split across the other two
     * corners.
     *
     * @param array<int,array<int,bool>> $m
     * @return array<int,array<int,bool>>
     */
    private static function placeFormat(array $m, int $size, int $mask): array
    {
        $bits = self::formatBits($mask);

        $first = [
            [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
            [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0],
        ];
        $second = [
            [8, $size - 1], [8, $size - 2], [8, $size - 3], [8, $size - 4],
            [8, $size - 5], [8, $size - 6], [8, $size - 7], [8, $size - 8],
            [$size - 7, 8], [$size - 6, 8], [$size - 5, 8], [$size - 4, 8],
            [$size - 3, 8], [$size - 2, 8], [$size - 1, 8],
        ];

        for ($i = 0; $i < 15; $i++) {
            $bit = (($bits >> $i) & 1) === 1;
            [$r1, $c1] = $first[$i];
            [$r2, $c2] = $second[$i];
            $m[$r1][$c1] = $bit;
            $m[$r2][$c2] = $bit;
        }

        return $m;
    }

    /**
     * The 15-bit format information: five data bits plus BCH(15,5) check bits, masked.
     *
     * The final XOR with 0x5412 exists so that an all-zero format — level M, mask 0 — is not
     * an all-light region, which a decoder would be unable to locate.
     */
    public static function formatBits(int $mask, int $ecLevel = self::EC_LEVEL_M): int
    {
        $data = (($ecLevel & 0b11) << 3) | ($mask & 0b111);

        $value = $data << 10;
        for ($i = 14; $i >= 10; $i--) {
            if ((($value >> $i) & 1) === 1) {
                $value ^= 0b10100110111 << ($i - 10);
            }
        }

        return (($data << 10) | $value) ^ 0b101010000010010;
    }

    /**
     * The 18-bit version information: six data bits plus BCH(18,6) check bits.
     *
     * Only versions 7 and above carry it. There is no final XOR on this one.
     */
    public static function versionBits(int $version): int
    {
        $value = $version << 12;
        for ($i = 17; $i >= 12; $i--) {
            if ((($value >> $i) & 1) === 1) {
                $value ^= 0b1111100100101 << ($i - 12);
            }
        }
        return ($version << 12) | $value;
    }

    /**
     * Score a masked symbol under the standard's four penalty rules; lower is better.
     *
     * The rules exist to avoid patterns a reader would misinterpret: long same-colour runs
     * look like timing patterns, 2×2 blocks defeat the sampling grid, the 1:1:3:1:1 sequence
     * imitates a finder pattern, and a symbol that is mostly one colour has less contrast to
     * work with. Choosing the lowest score is what makes the difference between a code that
     * scans from across a desk and one that has to be lined up carefully.
     *
     * @param array<int,array<int,bool>> $m
     */
    public static function penalty(array $m, int $size): int
    {
        $score = 0;

        for ($i = 0; $i < $size; $i++) {
            $score += self::runPenalty(self::row($m, $i, $size));
            $score += self::runPenalty(self::column($m, $i, $size));
        }

        for ($i = 0; $i < $size - 1; $i++) {
            for ($j = 0; $j < $size - 1; $j++) {
                $v = $m[$i][$j];
                if ($v === $m[$i][$j + 1] && $v === $m[$i + 1][$j] && $v === $m[$i + 1][$j + 1]) {
                    $score += 3;
                }
            }
        }

        for ($i = 0; $i < $size; $i++) {
            $score += 40 * self::finderLikeCount(self::row($m, $i, $size));
            $score += 40 * self::finderLikeCount(self::column($m, $i, $size));
        }

        $dark = 0;
        foreach ($m as $row) {
            foreach ($row as $cell) {
                $dark += $cell ? 1 : 0;
            }
        }
        $percent = ($dark * 100) / ($size * $size);
        $score += intdiv((int) floor(abs($percent - 50)), 5) * 10;

        return $score;
    }

    /**
     * Rule 1: five or more same-colour modules in a line.
     *
     * @param bool[] $line
     */
    private static function runPenalty(array $line): int
    {
        $score = 0;
        $run = 1;
        $count = count($line);
        for ($i = 1; $i < $count; $i++) {
            if ($line[$i] === $line[$i - 1]) {
                $run++;
                continue;
            }
            if ($run >= 5) {
                $score += 3 + ($run - 5);
            }
            $run = 1;
        }
        if ($run >= 5) {
            $score += 3 + ($run - 5);
        }
        return $score;
    }

    /**
     * Rule 3: occurrences of the 1:1:3:1:1 finder-like sequence with four light modules beside it.
     *
     * @param bool[] $line
     */
    private static function finderLikeCount(array $line): int
    {
        $bits = '';
        foreach ($line as $cell) {
            $bits .= $cell ? '1' : '0';
        }

        $count = 0;
        foreach (['10111010000', '00001011101'] as $needle) {
            $offset = 0;
            while (($at = strpos($bits, $needle, $offset)) !== false) {
                $count++;
                $offset = $at + 1;
            }
        }
        return $count;
    }

    /**
     * @param array<int,array<int,bool>> $m
     * @return bool[]
     */
    private static function row(array $m, int $index, int $size): array
    {
        $out = [];
        for ($j = 0; $j < $size; $j++) {
            $out[] = $m[$index][$j];
        }
        return $out;
    }

    /**
     * @param array<int,array<int,bool>> $m
     * @return bool[]
     */
    private static function column(array $m, int $index, int $size): array
    {
        $out = [];
        for ($i = 0; $i < $size; $i++) {
            $out[] = $m[$i][$index];
        }
        return $out;
    }
}
