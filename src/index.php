<?php
require_once __DIR__ . '/../vendor/autoload.php';

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



//$gen = new \App\MTProtoAuthKeyGenerator();
//$gen->run();