<?php
/**
 * Loghound — Reed-Solomon parity over GF(256), for the QR encoder.
 *
 * Split out of Qr because it is a self-contained piece of arithmetic with nothing to do with
 * QR layout, and because it is the part most worth testing on its own: the published
 * generator polynomials for each parity length are a fixed, checkable answer.
 *
 * THE FIELD. GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D), with 2 as the generator, which
 * is what ISO/IEC 18004 specifies. Logarithm and antilogarithm tables are built once per
 * process, so multiplication is two lookups and an addition.
 *
 * WHAT PARITY BUYS. Level M corrects roughly 15% of the codewords in a block. That is why an
 * otpauth QR code still scans with a thumb over one corner of the screen, and it is the reason
 * the encoder interleaves blocks: damage spread across several blocks is inside each block's
 * budget, where the same damage concentrated in one is not.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Auth;

final class ReedSolomon
{
    /** The primitive polynomial ISO/IEC 18004 fixes for the field. */
    private const PRIMITIVE = 0x11D;

    /** @var int[]|null Antilogarithms: EXP[i] = 2^i in the field. */
    private static ?array $exp = null;

    /** @var int[]|null Logarithms: LOG[v] = i such that EXP[i] = v. */
    private static ?array $log = null;

    /**
     * The parity codewords for a block of data codewords.
     *
     * Polynomial long division of the data (shifted up by the parity length) by the generator
     * polynomial; the remainder IS the parity. Written as the usual in-place shift register
     * rather than with polynomial objects, because it is the form that is easy to check
     * against the standard.
     *
     * @param int[] $data Codewords, 0-255.
     * @return int[] Exactly $count parity codewords.
     */
    public static function parity(array $data, int $count): array
    {
        self::tables();

        $generator = self::generator($count);
        $remainder = array_fill(0, $count, 0);

        foreach ($data as $byte) {
            $factor = ((int) $byte) ^ $remainder[0];
            array_shift($remainder);
            $remainder[] = 0;
            if ($factor !== 0) {
                for ($i = 0; $i < $count; $i++) {
                    $remainder[$i] ^= self::multiply($generator[$i + 1], $factor);
                }
            }
        }

        return $remainder;
    }

    /**
     * The generator polynomial for a given parity length: (x - 2^0)(x - 2^1)…(x - 2^(n-1)).
     *
     * Returned lowest-degree-last, so index 0 is the leading coefficient and is always 1.
     *
     * @return int[] $count + 1 coefficients.
     */
    public static function generator(int $count): array
    {
        self::tables();

        $poly = [1];
        for ($i = 0; $i < $count; $i++) {
            $next = array_fill(0, count($poly) + 1, 0);
            foreach ($poly as $index => $coefficient) {
                $next[$index] ^= $coefficient;
                $next[$index + 1] ^= self::multiply($coefficient, self::$exp[$i]);
            }
            $poly = $next;
        }

        return $poly;
    }

    /**
     * Multiply two field elements.
     *
     * Zero is handled before the logarithm lookup, because log(0) does not exist and a table
     * that pretended otherwise would return a wrong answer instead of an error.
     */
    public static function multiply(int $a, int $b): int
    {
        if ($a === 0 || $b === 0) {
            return 0;
        }
        self::tables();
        return self::$exp[(self::$log[$a] + self::$log[$b]) % 255];
    }

    /**
     * Build the logarithm tables once.
     *
     * The doubling is a left shift with a conditional XOR by the primitive polynomial when it
     * overflows eight bits, which is multiplication by x in this field.
     */
    private static function tables(): void
    {
        if (self::$exp !== null) {
            return;
        }

        $exp = array_fill(0, 256, 0);
        $log = array_fill(0, 256, 0);

        $value = 1;
        for ($i = 0; $i < 255; $i++) {
            $exp[$i] = $value;
            $log[$value] = $i;
            $value <<= 1;
            if ($value >= 256) {
                $value ^= self::PRIMITIVE;
            }
        }
        $exp[255] = $exp[0];

        self::$exp = $exp;
        self::$log = $log;
    }
}
