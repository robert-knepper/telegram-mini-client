<?php

namespace App\Encryption;

class RSAEncryption
{
    public static function generateKeys($bits = 2048): array
    {
        $config = [
            "private_key_bits" => $bits,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privKey);
        $details = openssl_pkey_get_details($res);
        $pubKey = $details['key'];

        $fingerprint = self::calculateFingerprint($details);

        return [
            'private_key' => $privKey,
            'public_key' => $pubKey,
            'fingerprint' => $fingerprint
        ];
    }

    public function generateKeysInFile(string $dirPath, array $keys): void
    {
        if (!is_dir($dirPath)) mkdir($dirPath);
        file_put_contents($dirPath . '/server_rsa_priv.pem', $keys['private_key']);
        file_put_contents($dirPath . '/server_rsa_pub.pem', $keys['public_key']);
        file_put_contents($dirPath . '/server_rsa_fingerprint.txt', $keys['fingerprint']);
    }

    private static function calculateFingerprint(array $details): string
    {
        $modulus = $details['rsa']['n'];
        $exponent = $details['rsa']['e'];

        $der = self::encodeDER($modulus, $exponent);

        $sha1 = sha1($der, true);
        $last8 = substr($sha1, -8);
        return '0x' . bin2hex(strrev($last8));
    }

    private static function encodeDER(string $modulus, string $exponent): string
    {
        return self::asn1Sequence(
            self::asn1Integer($modulus) .
            self::asn1Integer($exponent)
        );
    }

    private static function asn1Sequence(string $data): string
    {
        return "\x30" . self::asn1Length(strlen($data)) . $data;
    }

    private static function asn1Integer(string $data): string
    {
        if (ord($data[0]) > 0x7F) {
            $data = "\x00" . $data;
        }
        return "\x02" . self::asn1Length(strlen($data)) . $data;
    }

    private static function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }
        $lenBytes = ltrim(pack("N", $length), "\x00");
        return chr(0x80 | strlen($lenBytes)) . $lenBytes;
    }

    public static function encrypt($data, $pubKey)
    {
        openssl_public_encrypt($data, $out, $pubKey, OPENSSL_PKCS1_PADDING);
        return $out;
    }

    public static function decrypt($data, $privKey)
    {
        openssl_private_decrypt($data, $out, $privKey, OPENSSL_PKCS1_PADDING);
        return $out;
    }

    public static function fingerprintFromPublicKey(string $pubKey): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($pubKey));
        return self::calculateFingerprint($details);
    }
}