<?php

namespace App\Encryption\Resource;

use App\Encryption\Resource\PublicKeyEntity\BasePublicKeyEntity;
use App\Encryption\Resource\PublicKeyEntity\ServerRsaPublicKeyEntity;
use App\Encryption\Resource\PublicKeyEntity\TestRsaPublicKeyEntity;

class TelegramRSAPublicKey
{
    /**
     * @var BasePublicKeyEntity[]|string[]
     */
    private static array $publicKeyEntities = [
        ServerRsaPublicKeyEntity::class,
        TestRsaPublicKeyEntity::class
    ];
    public static function findPK(array $fingerPrints): BasePublicKeyEntity|string|null
    {
        foreach (self::$publicKeyEntities as $publicKeyEntity) {
            if (in_array($publicKeyEntity::getFingerPrint(), $fingerPrints)) {
                return $publicKeyEntity;
            }
        }
        return null;
    }


    /**
     * MTProto RSA_PAD encryptor for step 4.1 (https://core.telegram.org/mtproto/auth_key)
     * - data must be TL-serialized p_q_inner_data(_temp_dc) (<= 144 bytes)
     * - public key is Telegram RSA public key in PEM
     *
     * Returns:
     * [
     *   'encrypted_data'      => (binary 256 bytes),
     *   'encrypted_hex'       => (hex string),
     *   'public_key_fingerprint_long' => (signed int64 as string),
     *   'public_key_fingerprint_hex'  => (16-hex uppercase),
     * ]
     */
    public static function mtprotoRsaPadEncrypt(string $pubKeyPem, string $data): array
    {
        if (strlen($data) > 144) {
            throw new InvalidArgumentException("data length must be <= 144 bytes per spec (will be padded to 192).");
        }

        // ---- Parse RSA public key: get modulus n and exponent e (binary, big-endian)
        $key = openssl_pkey_get_public($pubKeyPem);
        if ($key === false) {
            throw new RuntimeException("Invalid RSA public key (PEM).");
        }
        $details = openssl_pkey_get_details($key);
        if (!$details || empty($details['rsa']['n']) || empty($details['rsa']['e'])) {
            throw new RuntimeException("Failed to extract RSA modulus/exponent.");
        }
        $n_bin = $details['rsa']['n']; // big-endian
        $e_bin = $details['rsa']['e']; // big-endian

        // ---- Compute Telegram-style RSA fingerprint (lower 64 bits of SHA1 of TL-serialized RSAPublicKey)
        $fingerprintBytes = self::rsa_fingerprint_bytes($n_bin, $e_bin); // last 8 bytes of SHA1
        $fingerprintHex = strtoupper(bin2hex($fingerprintBytes));  // e.g. 85FD64DE851D9DD0
        // TL 'long' on the wire is little-endian; keep signed int64 as string for PHP safety
        $fingerprintLongLE = self::bytes_le_to_int64_string($fingerprintBytes);

        // ---- Build RSA_PAD(data, key) as per 4.1
        $encrypted = self::rsa_pad_encrypt_block($data, $n_bin, $e_bin);

        return [
            'encrypted_data' => $encrypted,
            'encrypted_hex'  => bin2hex($encrypted),
            'public_key_fingerprint_long' => $fingerprintLongLE,
            'public_key_fingerprint_hex'  => $fingerprintHex,
        ];
    }

    /** 4.1 RSA_PAD implementation */
    private static function rsa_pad_encrypt_block(string $data, string $n_bin, string $e_bin): string
    {
        // data_with_padding: data + random -> total = 192 bytes
        $padLen = 192 - strlen($data);
        if ($padLen < 0) {
            throw new InvalidArgumentException("data too long for RSA_PAD.");
        }
        $data_with_padding = $data . random_bytes($padLen);

        // reverse bytes
        $data_pad_reversed = strrev($data_with_padding);

        // temp_key (32 bytes)
        // retry loop if key_aes_encrypted >= modulus
        for ($attempt = 0; $attempt < 50; $attempt++) {
            $temp_key = random_bytes(32);

            // data_with_hash = data_pad_reversed + SHA256(temp_key || data_with_padding)  -> 224 bytes
            $h = hash('sha256', $temp_key . $data_with_padding, true);
            $data_with_hash = $data_pad_reversed . $h; // 192 + 32 = 224

            // AES-256-IGE with zero IV (32 bytes of zero)
            $aes_encrypted = self::aes256_ige_encrypt($data_with_hash, $temp_key, str_repeat("\x00", 32)); // 224 bytes

            // temp_key_xor = temp_key XOR SHA256(aes_encrypted)
            $h2 = hash('sha256', $aes_encrypted, true);
            $temp_key_xor = $temp_key ^ $h2;

            // key_aes_encrypted = temp_key_xor || aes_encrypted -> 32 + 224 = 256 bytes
            $key_aes_encrypted = $temp_key_xor . $aes_encrypted;

            // compare big-endian integer with modulus n; if >= n, retry
            $m = gmp_import($key_aes_encrypted, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            $n = gmp_import($n_bin, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            if (gmp_cmp($m, $n) >= 0) {
                continue; // regenerate temp_key
            }

            // RSA raw: c = m^e mod n, big-endian, exactly 256 bytes
            $e = gmp_import($e_bin, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            $c = gmp_powm($m, $e, $n);
            $out = gmp_export($c, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
            // left pad to 256 bytes
            if (strlen($out) < 256) {
                $out = str_repeat("\x00", 256 - strlen($out)) . $out;
            }
            return $out;
        }

        throw new RuntimeException("RSA_PAD failed to produce value < modulus after several attempts.");
    }

    /** Compute Telegram RSA fingerprint: lower 64 bits of SHA1( TL-serialized rsa_public_key{ n:string, e:string } ) */
    private static function rsa_fingerprint_bytes(string $n_bin, string $e_bin): string
    {
        $payload = self::tl_string($n_bin) . self::tl_string($e_bin);
        $sha1 = sha1($payload, true);           // 20 bytes
        return substr($sha1, -8);               // lower 64 bits = last 8 bytes (no byte reordering)
    }

    /** TL string serialization (Binary Data Serialization rules) */
    private static function tl_string(string $s): string
    {
        $len = strlen($s);
        if ($len < 254) {
            $out = chr($len) . $s;
            // pad to 4-byte boundary
            $pad = (4 - (($len + 1) % 4)) % 4;
            return $out . str_repeat("\x00", $pad);
        } else {
            // 254 + 3-byte little-endian length
            $lenLe = pack('V', $len); // 4-byte LE; we will use only first 3 bytes
            $out = "\xFE" . substr($lenLe, 0, 3) . $s;
            $pad = (4 - (($len + 4) % 4)) % 4;
            return $out . str_repeat("\x00", $pad);
        }
    }

    /** Convert 8 bytes (big-endian from SHA1 tail) to signed int64 string in little-endian for TL 'long' */
    private static function bytes_le_to_int64_string(string $last8FromSha1): string
    {
        // The spec says: take final 8 bytes of SHA1(s) as 64-bit integer; small numbers are little-endian normally.
        // For wire (long) you send little-endian. We'll interpret the 8 bytes as big-endian number, then output signed decimal.
        // But to be safest across PHP, just pack as little-endian and unpack as signed 64.
        $le = strrev($last8FromSha1); // convert to little-endian
        $arr = unpack('q', $le);      // signed 64-bit
        // On 32-bit PHP, 'q' may not be supported; fallback to unsigned and manual sign handling:
        if ($arr === false) {
            $u = unpack('P', $le); // little-endian unsigned 64
            $u = $u[1];
            // Convert to signed decimal string
            if (PHP_INT_SIZE >= 8) {
                $signed = ($u & (1<<63)) ? ($u - (1<<64)) : $u;
                return (string)$signed;
            }
            // 32-bit PHP fallback using BCMath/GMP:
            $g = gmp_init('0', 10);
            for ($i = 0; $i < 8; $i++) {
                $g = gmp_add(gmp_mul($g, 256), ord($le[$i]));
            }
            if (gmp_cmp($g, gmp_init('9223372036854775807')) > 0) { // > INT64_MAX
                $g = gmp_sub($g, gmp_pow(2, 64));
            }
            return gmp_strval($g);
        }
        return (string)$arr[1];
    }

    /**
     * AES-256-IGE encrypt (no padding), single-shot, iv = 32 bytes.
     * Uses OpenSSL 'aes-256-ige' if available; otherwise a small pure-PHP IGE built over AES-ECB.
     */
    private static function aes256_ige_encrypt(string $plaintext, string $key, string $iv): string
    {
        if (strlen($key) !== 32) throw new InvalidArgumentException("IGE key must be 32 bytes.");
        if (strlen($iv)  !== 32) throw new InvalidArgumentException("IGE IV must be 32 bytes.");
        if ((strlen($plaintext) % 16) !== 0) {
            throw new InvalidArgumentException("IGE plaintext length must be multiple of 16 (got ".strlen($plaintext).").");
        }

        // Try OpenSSL's native aes-256-ige if present
        $methods = openssl_get_cipher_methods(true);
        if (in_array('aes-256-ige', $methods, true)) {
            $out = openssl_encrypt($plaintext, 'aes-256-ige', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $iv);
            if ($out === false) {
                throw new RuntimeException("OpenSSL aes-256-ige failed.");
            }
            return $out;
        }

        // Fallback pure-PHP IGE (built over AES-256-ECB, no padding)
        $blockEnc = function (string $block) use ($key): string {
            $r = openssl_encrypt($block, 'aes-256-ecb', $key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
            if ($r === false) throw new RuntimeException("OpenSSL AES-ECB failed.");
            return $r;
        };

        $ciphertext = '';
        $prevC = substr($iv, 16, 16);
        $prevP = substr($iv, 0, 16);

        $len = strlen($plaintext);
        for ($off = 0; $off < $len; $off += 16) {
            $p = substr($plaintext, $off, 16);
            $x = $p ^ $prevC;
            $y = $blockEnc($x);
            $c = $y ^ $prevP;
            $ciphertext .= $c;
            $prevP = $p;
            $prevC = $c;
        }
        return $ciphertext;
    }


}