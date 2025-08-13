<?php

namespace App\Encryption;

class DiffieHellmanEncryptionSmall
{

    public function __construct(private int $bigPrimeNumberP)
    {
    }

    function generatePublicKeyFromPrivateKey(int $privateKey, int $baseNumberG): int
    {
        return pow($baseNumberG, $privateKey) % $this->bigPrimeNumberP;
    }

    function generateSharedKey(int $privateKey, int $oppositePublicKey): int
    {
        return $this->generatePublicKeyFromPrivateKey($privateKey, $oppositePublicKey);
    }
}