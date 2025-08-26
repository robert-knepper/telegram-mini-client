<?php

namespace App\Encryption\Tools;

class PQFactor
{
    public static function factorPQByte(string $pq): array
    {
        dd(strlen($pq));
        $n = gmp_import($pq, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        $p = self::pollardRho($n);
        $q = gmp_div_q($n, $p);

        $pBytes = self::gmpToBytes($p);
        $qBytes = self::gmpToBytes($q);

        if (strcmp($pBytes, $qBytes) > 0) {
            [$pBytes, $qBytes] = [$qBytes, $pBytes];
        }

        return [$pBytes, $qBytes];
    }

    public static function factorPQInt(string $pq): array
    {
        $n = gmp_import($pq, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        $p = self::pollardRho($n);
        $q = gmp_div_q($n, $p);

        $pBytes = self::gmpToBytes($p);
        $qBytes = self::gmpToBytes($q);

        if (strcmp($pBytes, $qBytes) > 0) {
            [$pBytes, $qBytes] = [$qBytes, $pBytes];
        }

        return [$pBytes, $qBytes];
    }

    private static function pollardRho(\GMP $n): \GMP
    {
        if (gmp_prob_prime($n) > 0) return $n;
        while (true) {
            $x = gmp_random_range(2, gmp_sub($n, 1));
            $y = $x;
            $c = gmp_random_range(1, gmp_sub($n, 1));
            $d = gmp_init(1);
            while (gmp_cmp($d, 1) == 0) {
                $x = gmp_mod(gmp_add(gmp_pow($x, 2), $c), $n);
                $y = gmp_mod(gmp_add(gmp_pow($y, 2), $c), $n);
                $y = gmp_mod(gmp_add(gmp_pow($y, 2), $c), $n);
                $d = gmp_gcd(gmp_abs(gmp_sub($x, $y)), $n);
                if (gmp_cmp($d, $n) == 0) break;
            }
            if (gmp_cmp($d, 1) > 0 && gmp_cmp($d, $n) < 0) return $d;
        }
    }

    private static function gmpToBytes(\GMP $x, int $padLen = 8): string
    {
        $b = gmp_export($x, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        if ($b === false) {
            $b = "\x00";
        }
        if (strlen($b) < $padLen) {
            $b = str_repeat("\x00", $padLen - strlen($b)) . $b;
        }
        return $b;
    }
}