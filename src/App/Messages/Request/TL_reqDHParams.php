<?php

namespace App\Messages\Request;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\TLObject;

class TL_reqDHParams extends TLObject
{

    private string $authKeyId;
    private int $messageId;


    public function __construct(
        private $nonce,
        private $serverNonce,
        private string $p,
        private string $q,
        private string $publicKeyFingerPrint,
        private $encryptData,
    )
    {
        $this->authKeyId = str_repeat("\0", 8);
        $this->messageId = $this->generateRandomMessageID();
    }


    public static function getConstructor(): int
    {
        return 0xd712e4be;
    }

    public function serialize(OutputSerializedData $out): void
    {
        $out->writeInt64((int)$this->authKeyId);
        $out->writeInt64($this->messageId);


        $body = new OutputSerializedData();
        $body->writeInt32(self::getConstructor());
        $body->writeRaw($this->nonce);
        $body->writeRaw($this->serverNonce);
        $body->writeP_Or_Q($this->p);
        $body->writeP_Or_Q($this->q);
        $body->writeRaw(hex2bin($this->publicKeyFingerPrint));
        $body->writeString($this->encryptData);
        $bodyLen = strlen($body->data);
        $out->writeInt32($bodyLen);
        $out->writeRaw($body->data);
    }

    public static function unserialize(InputSerializedData $in): TLObject
    {
        throw new \Exception('not implemented');
    }
}