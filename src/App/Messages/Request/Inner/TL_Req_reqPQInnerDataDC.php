<?php

namespace App\Messages\Request\Inner;

use App\Encryption\Hex;
use App\MTProto\BaseTLResObject;
use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\BaseTLReqObject;

class TL_Req_reqPQInnerDataDC extends BaseTLReqObject
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
        $out->write(self::getConstructor(),'#');
        $out->write($this->pq,'string');
        $out->write(Hex::decode(gmp_strval($this->p, 16)),'string');
        $out->write(Hex::decode(gmp_strval($this->q, 16)),'string');
        $out->write($this->nonce,'int128');
        $out->write(base64_decode($this->serverNonce),'int128');
        $out->write($this->newNonce,'int256');
        $out->write($this->dc,'int');
    }


    public static function getResponseClass(): string
    {
        throw new \Exception('not implemented');
    }
}