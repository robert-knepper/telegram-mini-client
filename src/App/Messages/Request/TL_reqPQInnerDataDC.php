<?php

namespace App\Messages\Request;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\TLObject;

class TL_reqPQInnerDataDC extends TLObject
{

    public function __construct(
        private string $pq,
        private int $p,
        private int $q,
        private $nonce,
        private $serverNonce,
        private $newNonce,
        private int $dc,
    )
    {

    }


    public static function getConstructor(): int
    {
        return 0xa9f55f95;
    }

    public function serialize(OutputSerializedData $out): void
    {
        $body = new OutputSerializedData();
        $body->writeInt32(self::getConstructor());
        $body->writeString($this->pq);
        $body->writeP_Or_Q($this->p);
        $body->writeP_Or_Q($this->q);
        $body->writeRaw($this->nonce);
        $body->writeRaw($this->serverNonce);
        $body->writeRaw($this->newNonce);
        $body->writeInt32($this->dc);
        $bodyLen = strlen($body->data);
        $out->writeRaw($body->data);
    }

    public static function unserialize(InputSerializedData $in): TLObject
    {
        throw new \Exception('not implemented');
    }
}