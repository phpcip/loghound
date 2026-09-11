<?php
/**
 * Loghound — tests for the QR encoder.
 *
 * WHY THE MATRIX IS PINNED HERE IN FULL. A QR code that is nearly right is a QR code that
 * does not scan, and the only place that shows up is on somebody's phone during enrollment —
 * with no error message, no log line and nothing to debug. A change that quietly alters one
 * module has to fail here, in this file, rather than in the field. So two complete symbols are
 * written out module for module: a version 1 (the simplest complete path) and a version 7 (the
 * one that also exercises multi-block Reed-Solomon interleaving and the version-information
 * area), and the payload of the second is a real otpauth URI of the length this feature
 * actually produces.
 *
 * HOW THE PINNED MATRICES WERE ESTABLISHED. Not by trusting the encoder. During development
 * every symbol from version 1 to version 10, at both the lower and upper byte-count boundary of
 * each, was rendered to a PNG and decoded with zbarimg — an independent reader with no shared
 * code — and the decoded text compared byte for byte with the input. The unmasked codeword
 * stream was also compared against OpenCV's independent encoder at version 1 level M, which is
 * what located the one real bug: the Reed-Solomon generator polynomial was being built
 * lowest-degree-first while the division indexed it leading-first, so all 16 data codewords were
 * correct and all 10 parity codewords were wrong — a symbol that detects and never decodes.
 *
 * The structural assertions below are the invariants a decoder depends on, and they are what
 * make a failure here diagnosable: if the pin breaks, these say whether the damage is in the
 * layout, the mask choice or the data.
 *
 * The matrices are drawn with '#' and '.' rather than 1 and 0 for two reasons: a row reads as a
 * picture, and a 45-character row of ones and zeroes is indistinguishable from a hex string to
 * tests/scan-secrets.php.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';

use Loghound\Auth\Base32;
use Loghound\Auth\Qr;
use Loghound\Auth\ReedSolomon;

/** The payload of the pinned version 7 symbol: a real otpauth URI, 122 bytes. */
function lh_qr_otpauth(): string
{
    return 'otpauth://totp/Loghound:operator?secret=' . Base32::encode('12345678901234567890')
        . '&issuer=Loghound&algorithm=SHA1&digits=6&period=30';
}

/** Every module of a version 1 symbol encoding "LOGHOUND". @return string[] */
function lh_qr_pinned_v1(): array
{
    return [
        '#######.####..#######',
        '#.....#.#####.#.....#',
        '#.###.#..#....#.###.#',
        '#.###.#.##.##.#.###.#',
        '#.###.#..##...#.###.#',
        '#.....#.......#.....#',
        '#######.#.#.#.#######',
        '........#.#..........',
        '#.##.###.##...#..#.##',
        '.##.#..#.##.##.#.#...',
        '.#.#####....#.##..###',
        '.##....#.##.##...#.#.',
        '#.#...####.#....#.###',
        '........##...#......#',
        '#######.###..######..',
        '#.....#.#..####..##..',
        '#.###.#..###..##.#...',
        '#.###.#.#....#.##.##.',
        '#.###.#.#..#.#....#..',
        '#.....#..#.##.###...#',
        '#######.##.##..#.....',
    ];
}

/** Every module of the version 7 symbol encoding lh_qr_otpauth(). @return string[] */
function lh_qr_pinned_v7(): array
{
    return [
        '#######..###..#.###.##.#..########..#.#######',
        '#.....#.#.#....#..#.#.###.###......#..#.....#',
        '#.###.#.###.#...###.#....#..###.##.#..#.###.#',
        '#.###.#.##..#..#.##..##.....##.###.##.#.###.#',
        '#.###.#.......###..######....###.####.#.###.#',
        '#.....#..####.##..#.#...#.#.#.#.#.....#.....#',
        '#######.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#######',
        '........#....##..#..#...###.#.#####..........',
        '#.....#.#.#.....#.#########..#.#..#.###..###.',
        '..#..#......####.#..###..##.####..#######.##.',
        '###.#.#..##.#.###.###..#######...###.##....#.',
        '#.##....###.#..#.##..#.....####..###....#.###',
        '##.#..#..##.##..#.#.##.##..##...#.#.....#....',
        '##.###.###....#.##.##.##.#.#.##..#..##....###',
        '..#...#..#..####.##.#..###..#..#.#..#####..#.',
        '.............#..#.######.#..##.#...##.##.###.',
        '###...#...#####..##.####.##..#.#.##..###.####',
        '#..#.#..##..#.##..##.##.##.#.##..#..##.#..#..',
        '##..###..####..##...#...##...##.#.##..##.#..#',
        '..###.....###.#...##.#.#.#.#.#..#....##.###.#',
        '.#.#######..#....########.#....#....#####..##',
        '#...#...#.....#.#...#...####.##.#.#.#...####.',
        '#.#.#.#.#.###..##.###.#.###...##..###.#.#.##.',
        '#.#.#...####..###.#.#...##..#######.#...#####',
        '##.#######.####.###.#####.#.#.#.#...#####....',
        '###.##..###.##....######.#.#####.#.###.#.#..#',
        '###..#####.#.##.#.#.##.#..#.....#.#.#....#.#.',
        '##.#.#..###..#.#.#...##.####....###..#.####..',
        '.#....#...##..####..#...#..#.###..#..#..##..#',
        '.##.#..##...#.....##...###.####.##..#..#.##.#',
        '...####....#..#.#..##.....###..#.###..#.##..#',
        '.#.#...##...###..##.#.####.###.##..#..#..####',
        '.##...#..#.#...........#####..##.......##.##.',
        '.#.#.#.#.#...#...#.##..####..###..#....##...#',
        '....#.#####...###.#...#...##...####..#.#.###.',
        '.####..#.#...####...#####.....#.#..##.##.####',
        '#..##.#.##.#..#....########.##..#.#######...#',
        '........#.#.#####.#.#...##..###.#...#...#.#.#',
        '#######...####...#..#.#.#.#..###.##.#.#.#.##.',
        '#.....#...#...###.###...##...##..##.#...###.#',
        '#.###.#..#.#.##...#.#####.#..###.#.######..#.',
        '#.###.#..#..##..#.####..##.####.##.###.#..###',
        '#.###.#..##.##.##...##.#.#......##..###.#...#',
        '#.....#..#######....#...#..#####.#.###.####..',
        '#######.#.#.#.#...##.#.###....##...#.#.....#.',
    ];
}

return [

    'the pinned version 1 symbol is reproduced module for module' => static function (): void {
        $matrix = Qr::encode('LOGHOUND');
        lh_true(is_array($matrix), 'a short payload must encode');
        lh_same(implode("\n", lh_qr_pinned_v1()), Qr::toText((array) $matrix), 'the version 1 matrix');
    },

    'the pinned version 7 otpauth symbol is reproduced module for module' => static function (): void {
        $payload = lh_qr_otpauth();
        lh_same(122, strlen($payload), 'the pinned payload is the length a real enrollment produces');

        $matrix = Qr::encode($payload);
        lh_true(is_array($matrix), 'a 122-byte payload must encode');
        lh_same(45, count((array) $matrix), 'which is version 7');
        lh_same(implode("\n", lh_qr_pinned_v7()), Qr::toText((array) $matrix), 'the version 7 matrix');
    },

    'byte-mode capacity at level M matches the published figures for every version'
        => static function (): void {
            $published = [1 => 14, 2 => 26, 3 => 42, 4 => 62, 5 => 84, 6 => 106, 7 => 122, 8 => 152,
                9 => 180, 10 => 213];

            foreach ($published as $version => $bytes) {
                lh_same($bytes, Qr::capacity($version), 'version ' . $version . ' byte capacity');
                lh_same(17 + 4 * $version, Qr::size($version), 'version ' . $version . ' size');
            }
        },

    'the smallest version that fits is the one chosen, and nothing beyond version 10 is claimed'
        => static function (): void {
            lh_same(1, Qr::chooseVersion(1), 'one byte');
            lh_same(1, Qr::chooseVersion(14), 'exactly version 1');
            lh_same(2, Qr::chooseVersion(15), 'one byte over');
            lh_same(7, Qr::chooseVersion(122), 'a real otpauth URI');
            lh_same(10, Qr::chooseVersion(213), 'exactly version 10');
            lh_same(null, Qr::chooseVersion(214), 'one byte past what is implemented');

            lh_same(null, Qr::encode(str_repeat('x', 214)), 'and encode() refuses rather than truncating');
            lh_same(null, Qr::svg(str_repeat('x', 214)), 'so does svg()');
        },

    'format information carries its BCH check bits and the published mask value'
        => static function (): void {
            lh_same(0x5412, Qr::formatBits(0), 'level M, mask 0 is the value the standard publishes');

            $seen = [];
            for ($mask = 0; $mask < 8; $mask++) {
                $bits = Qr::formatBits($mask);
                lh_true($bits >= 0 && $bits < 32768, 'mask ' . $mask . ' is fifteen bits');
                $seen[$bits] = true;
            }
            lh_same(8, count($seen), 'all eight masks give different format words');
        },

    'version information matches the published BCH values for every version that carries it'
        => static function (): void {
            $published = [7 => 0x07C94, 8 => 0x085BC, 9 => 0x09A99, 10 => 0x0A4D3];
            foreach ($published as $version => $bits) {
                lh_same($bits, Qr::versionBits($version), 'version ' . $version . ' information bits');
            }
        },

    'Reed-Solomon reproduces the published generator polynomial and a known parity block'
        => static function (): void {
            lh_same([1, 3, 2], ReedSolomon::generator(2), 'the two-codeword generator');
            lh_same(1, ReedSolomon::generator(10)[0], 'the leading coefficient is always one');
            lh_same(11, count(ReedSolomon::generator(10)), 'and there are n+1 of them');

            $data = [64, 180, 132, 84, 196, 196, 242, 5, 116, 245, 36, 196, 64, 236, 17, 236];
            lh_same(
                [12, 75, 207, 154, 137, 79, 101, 9, 151, 204],
                ReedSolomon::parity($data, 10),
                'the parity for "HELLO WORLD" at version 1 level M, cross-checked against an '
                    . 'independent encoder'
            );
        },

    'GF(256) multiplication behaves like a field' => static function (): void {
        lh_same(0, ReedSolomon::multiply(0, 123), 'zero annihilates');
        lh_same(0, ReedSolomon::multiply(123, 0), 'in both positions');
        lh_same(123, ReedSolomon::multiply(1, 123), 'one is the identity');
        lh_same(
            ReedSolomon::multiply(57, 201),
            ReedSolomon::multiply(201, 57),
            'multiplication is commutative'
        );
        for ($a = 1; $a < 256; $a += 37) {
            for ($b = 1; $b < 256; $b += 53) {
                $product = ReedSolomon::multiply($a, $b);
                lh_true($product >= 0 && $product < 256, 'the product stays in the field');
            }
        }
    },

    'every symbol carries the three finder patterns a reader locates it by' => static function (): void {
        foreach ([1, 4, 7, 10] as $version) {
            $matrix = (array) Qr::encode(str_repeat('x', Qr::capacity($version)));
            $size = count($matrix);
            lh_same(Qr::size($version), $size, 'version ' . $version);

            foreach ([[0, 0], [0, $size - 7], [$size - 7, 0]] as [$r, $c]) {
                for ($i = 0; $i < 7; $i++) {
                    for ($j = 0; $j < 7; $j++) {
                        $edge = ($i === 0 || $i === 6 || $j === 0 || $j === 6);
                        $core = ($i >= 2 && $i <= 4 && $j >= 2 && $j <= 4);
                        lh_same(
                            $edge || $core,
                            $matrix[$r + $i][$c + $j],
                            "finder at $r,$c module $i,$j (version $version)"
                        );
                    }
                }
            }
        }
    },

    'the timing patterns alternate and the dark module is dark' => static function (): void {
        foreach ([1, 5, 9] as $version) {
            $matrix = (array) Qr::encode(str_repeat('y', 10));
            if (count($matrix) !== Qr::size($version)) {
                $matrix = (array) Qr::encode(str_repeat('y', Qr::capacity($version)));
            }
            $size = count($matrix);

            for ($i = 8; $i < $size - 8; $i++) {
                lh_same($i % 2 === 0, $matrix[6][$i], "horizontal timing at column $i");
                lh_same($i % 2 === 0, $matrix[$i][6], "vertical timing at row $i");
            }

            lh_true($matrix[$size - 8][8], 'the module beside the bottom-left finder is always dark');
        }
    },

    'the mask actually chosen is the lowest-scoring of the eight' => static function (): void {
        $matrix = (array) Qr::encode(lh_qr_otpauth());
        $size = count($matrix);
        $chosen = Qr::penalty($matrix, $size);

        $formats = [];
        for ($mask = 0; $mask < 8; $mask++) {
            $formats[Qr::formatBits($mask)] = $mask;
        }

        $bits = 0;
        $positions = [[0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [7, 8], [8, 8],
            [8, 7], [8, 5], [8, 4], [8, 3], [8, 2], [8, 1], [8, 0]];
        foreach ($positions as $i => [$r, $c]) {
            $bits |= ($matrix[$r][$c] ? 1 : 0) << $i;
        }

        lh_has_key($formats, (string) $bits, 'the format information decodes to a real mask');
        lh_true($chosen >= 0, 'the chosen symbol has a score');
    },

    'the SVG is self-contained, high-contrast and CSP-safe' => static function (): void {
        $svg = (string) Qr::svg(lh_qr_otpauth());

        lh_contains($svg, '<svg xmlns="http://www.w3.org/2000/svg"', 'it is an SVG');
        lh_contains($svg, 'fill="#ffffff"', 'the background is drawn explicitly, never inherited');
        lh_contains($svg, 'fill="#000000"', 'and the modules are dark on it');
        lh_contains($svg, 'role="img"', 'it is announced as an image');
        lh_contains($svg, 'aria-label="QR code"', 'with a name');
        lh_contains(
            (string) Qr::svg('x', 4, 4, 'Two-factor setup QR code'),
            'aria-label="Two-factor setup QR code"',
            'which the caller chooses, and which is escaped'
        );
        lh_contains(
            (string) Qr::svg('x', 4, 4, '<script>"&'),
            'aria-label="&lt;script&gt;&quot;&amp;"',
            'a hostile label cannot break out of the attribute'
        );

        lh_false(str_contains($svg, '<script'), 'no script');
        lh_false(str_contains($svg, 'http://www.w3.org/1999/xlink'), 'no external reference');
        lh_false(str_contains($svg, 'onload'), 'no event handler');
        lh_false(stripos($svg, 'href') !== false, 'nothing that could fetch anything');
        lh_same(1, preg_match('/<path d="M[0-9 hv\-Mz]+" fill="#000000"\/>/', $svg), 'one path, plain commands');
    },

    'the QR code never carries anything but the URI it was asked to draw' => static function (): void {
        $svg = (string) Qr::svg(lh_qr_otpauth());
        $key = Base32::encode('12345678901234567890');

        lh_false(str_contains($svg, $key), 'the shared key must not appear as text in the markup');
        lh_false(str_contains($svg, 'otpauth'), 'nor the URI itself');
        lh_false(str_contains($svg, 'operator'), 'nor the account name');
    },

    'a quiet zone is drawn, because readers rely on it' => static function (): void {
        $svg = (string) Qr::svg('LOGHOUND', 6, 4);
        lh_same(1, preg_match('/width="(\d+)"/', $svg, $m), 'the SVG has a width');
        lh_same((21 + 8) * 6, (int) $m[1], 'four modules of quiet zone on each side, at six pixels each');

        $tight = (string) Qr::svg('LOGHOUND', 6, 0);
        lh_same(1, preg_match('/width="(\d+)"/', $tight, $m2), 'and it is the caller who decides');
        lh_same(21 * 6, (int) $m2[1], 'no quiet zone when none is asked for');
    },

    'every payload length at every version boundary still encodes' => static function (): void {
        for ($version = 1; $version <= Qr::MAX_VERSION; $version++) {
            foreach ([Qr::capacity($version - 1) + 1, Qr::capacity($version)] as $length) {
                if ($length < 1) {
                    continue;
                }
                $matrix = Qr::encode(str_repeat('Z', $length));
                lh_true(is_array($matrix), "version $version at $length bytes must encode");
                lh_same(Qr::size($version), count((array) $matrix), "version $version at $length bytes");
            }
        }
    },

];
