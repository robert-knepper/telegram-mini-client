<?php

namespace App\Encryption;

class DiffieHellmanEncryptionBig extends DiffieHellmanEncryptionSmall
{

    public function __construct(private int $bigPrimeNumberP)
    {
    }

    function generatePublicKeyFromPrivateKey(int $privateKey, int $baseNumberG): int
    {
        return $this->modPow($baseNumberG, $privateKey, $this->bigPrimeNumberP);
    }

    function generateSharedKey(int $privateKey, int $oppositePublicKey): int
    {
        return $this->generatePublicKeyFromPrivateKey($privateKey, $oppositePublicKey);
    }

    /**
     * prevent overflow in pow big number
     * Square-and-Multiply
     */
    private function modPow(int $base, int $exp, int $mod): int
    {
        $result = 1;
        $base = $base % $mod;

        while ($exp > 0) {
            if ($exp & 1) {
                $result = ($result * $base) % $mod;
            }
            $base = ($base * $base) % $mod;
            $exp >>= 1;
        }

        return $result;
    }
}