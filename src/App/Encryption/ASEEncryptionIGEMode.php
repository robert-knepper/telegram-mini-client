<?php
namespace App\Encryption;
class ASEEncryptionIGEMode
{
    public function __construct(private int $blockSizeByByte = 16)
    {
    }

    private function ecb_encrypt(string $plaintext, string $key): string
    {
        $aes = new \phpseclib3\Crypt\AES('ecb');
        $aes->disablePadding();
        $aes->setKey($key);
        return $aes->encrypt($plaintext);
    }

    private function ecb_decrypt(string $ciphertext, string $key): string
    {
        $aes = new \phpseclib3\Crypt\AES('ecb');
        $aes->disablePadding();
        $aes->setKey($key);
        return $aes->decrypt($ciphertext);
    }

    function ige_encrypt(string $plaintext, string $key, string $iv1, string $iv2): string
    {
        $pad_len = $this->blockSizeByByte - (strlen($plaintext) % $this->blockSizeByByte);
        $plaintext .= str_repeat(chr($pad_len), $pad_len);

        $blocks = str_split($plaintext, $this->blockSizeByByte);
        $ciphertext = '';

        $c_prev = $iv1;
        $p_prev = $iv2;

        foreach ($blocks as $p) {
            $xored_in = $p ^ $c_prev;
            $encrypted = $this->ecb_encrypt($xored_in, $key);
            $c = $encrypted ^ $p_prev;

            $ciphertext .= $c;

            $c_prev = $c;
            $p_prev = $p;
        }

        return $ciphertext;
    }

    function ige_decrypt(string $ciphertext, string $key, string $iv1, string $iv2): string
    {
        $blocks = str_split($ciphertext, $this->blockSizeByByte);
        $plaintext = '';

        $c_prev = $iv1;
        $p_prev = $iv2;

        foreach ($blocks as $c) {
            $xored_in = $c ^ $p_prev;
            $decrypted = $this->ecb_decrypt($xored_in, $key);
            $p = $decrypted ^ $c_prev;

            $plaintext .= $p;

            $c_prev = $c;
            $p_prev = $p;
        }

        // remove Padding
        $pad_len = ord(substr($plaintext, -1));
        return substr($plaintext, 0, -$pad_len);
    }

}

/*
$key = random_bytes(16);
$iv1 = random_bytes(16);
$iv2 = random_bytes(16);

$plaintext = "message for IGE and ECB!";
$encryption = new \App\Encryption\ASEEncryptionIGEMode(16);
$ciphertext = $encryption->ige_encrypt($plaintext, $key, $iv1, $iv2);
$decrypted = $encryption->ige_decrypt($ciphertext, $key, $iv1, $iv2);

echo "main : $plaintext\n";
echo "(base64) encrypted: " . base64_encode($ciphertext) . "\n";
echo "decrypted : $decrypted\n";

if ($plaintext === $decrypted) {
    echo "OK!\n";
} else {
    echo "Error.\n";
}

*/