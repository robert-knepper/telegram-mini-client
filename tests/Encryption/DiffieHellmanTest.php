<?php

namespace Encryption;

use PHPUnit\Framework\TestCase;

class DiffieHellmanTest extends TestCase
{
    public function test_big_encryption()
    {
        $primNumP = 23;
        $baseNumG = 5;
        $diffieHellman = new \App\Encryption\DiffieHellmanEncryptionBig($primNumP);

        $privateKeyA = 15;
        $privateKeyB = 6;

        $publicKeyA = $diffieHellman->generatePublicKeyFromPrivateKey($privateKeyA, $baseNumG);
        $publicKeyB = $diffieHellman->generatePublicKeyFromPrivateKey($privateKeyB, $baseNumG);

        $sharedKeyA = $diffieHellman->generateSharedKey($privateKeyA,$publicKeyB);
        $sharedKeyB = $diffieHellman->generateSharedKey($privateKeyB,$publicKeyA);

        $this->assertTrue($sharedKeyB === $sharedKeyA);
    }

    public function test_small_encryption()
    {
        $primNumP = 23;
        $baseNumG = 5;
        $diffieHellman = new \App\Encryption\DiffieHellmanEncryptionSmall($primNumP);

        $privateKeyA = 15;
        $privateKeyB = 6;

        $publicKeyA = $diffieHellman->generatePublicKeyFromPrivateKey($privateKeyA, $baseNumG);
        $publicKeyB = $diffieHellman->generatePublicKeyFromPrivateKey($privateKeyB, $baseNumG);

        $sharedKeyA = $diffieHellman->generateSharedKey($privateKeyA,$publicKeyB);
        $sharedKeyB = $diffieHellman->generateSharedKey($privateKeyB,$publicKeyA);

        $this->assertTrue($sharedKeyB === $sharedKeyA);
    }




}