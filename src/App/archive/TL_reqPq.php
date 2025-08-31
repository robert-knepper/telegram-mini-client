<?php

namespace App\archive;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\BaseTLReqObject;

class BaseTL_Req_resPq extends BaseTLReqObject
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
        return 0xbe7e8ef1; // constructor واقعی resPQ
    }

    public function serialize(OutputSerializedData $out): void
    {
        $body = new OutputSerializedData();
        $body->writeInt32(self::getConstructor());
        $body->writeRaw($this->nonce);
        $bodyLen = strlen($body->data);

        $out->writeInt64((int)$this->authKeyId);
        $out->writeInt64($this->messageId);
        $out->writeInt32($bodyLen);
        $out->writeRaw($body->data);
    }

    public static function response(InputSerializedData $in): BaseTLReqObject
    {
        throw new \Exception('not implemented');
    }
}