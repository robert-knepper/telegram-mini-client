<?php

namespace App;

use danog\PrimeModule;

class FactorPQ
{

    private static function logger($str)
    {
        dump($str);
    }
    public static function factor($pq)
    {
        foreach ([
                     'native_single_cpp',
                     'python_single_alt',
                     'python_single',
                     'native_single',
                 ] as $method) {
            dump('$method',$method);
            self::logger("Factorizing with $method (please wait, might take a while)");
            if ($method !== 'native_single_cpp') {
                self::logger('Install https://prime.madelineproto.xyz and the FFI extension to speed this up!');
            }

            $p = 0;
            $q = 0;
            try {
                $p = PrimeModule::$method($pq);
            } catch (\Throwable $e) {
                self::logger("While factorizing with $method: $e");
            }

            if ($p) {
                $q = $pq / $p;
                if ($p > $q) {
                    [$p, $q] = [$q, $p];
                }
                if ($pq === $p*$q) {
                    $ok = true;
                    break;
                }
            }
        }
        if (!$ok) {
            throw new \Exception("Couldn't compute p and q, install prime.madelineproto.xyz to fix. Original pq: {$pq}, computed p: {$p}, computed q: {$q}, computed pq: ".$p*$q);
        }

        return [
            'p' => $p,
            'q' => $q,
        ];
    }
}