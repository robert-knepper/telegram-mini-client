<?php

namespace Encryption;

use App\Encryption\RSAEncryption;
use PHPUnit\Framework\TestCase;

class RSAEncryptionTest extends TestCase
{
    function test_base_encryption()
    {
        $keys = RSAEncryption::generateKeys();
        $privateKey = $keys['private_key'];
        $publicKey = $keys['public_key'];
        $fingerprint = $keys['fingerprint'];

        $mainData = 'foo';
        $encryptData = RSAEncryption::encrypt($mainData, $publicKey);
        $dataDecrypted = RSAEncryption::decrypt($encryptData, $privateKey);
        $this->assertTrue($dataDecrypted === $mainData);
        $this->assertTrue(RSAEncryption::fingerprintFromPublicKey($publicKey) === $fingerprint);
    }
}