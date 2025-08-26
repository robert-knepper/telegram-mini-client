<?php

namespace App\Messages\Request;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\TLObject;

class TL_reqPqMulti extends TLObject
{

    private string $authKeyId;
    private int $messageId;


    public function __construct(private string $nonce)
    {
        $this->authKeyId = str_repeat("\0", 8);
        $this->messageId = $this->generateRandomMessageID();
    }


    public static function getConstructor(): int
    {
        return 0xbe7e8ef1;
    }

    public function serialize(OutputSerializedData $out): void
    {


        $out->writeInt64((int)$this->authKeyId);
        $out->writeInt64($this->messageId);

        $body = new OutputSerializedData();
        $body->writeInt32(self::getConstructor());
        $body->writeRaw($this->nonce);
        $bodyLen = strlen($body->data);

        $out->writeInt32($bodyLen);
        $out->writeRaw($body->data);
    }

    public static function unserialize(InputSerializedData $in): TLObject
    {
        throw new \Exception('not implemented');
    }
}