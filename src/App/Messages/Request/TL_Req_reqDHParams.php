<?php

namespace App\Messages\Request;

use App\Encryption\Hex;
use App\MTProto\BaseTLResObject;
use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\BaseTLReqObject;

class TL_Req_reqDHParams extends BaseTLReqObject
{

    public function __construct(
        private $nonce,
        private $serverNonce,
        private $p,
        private $q,
        private $publicKeyFingerPrint,
        private $encryptData,
    )
    {
    }


    public static function getConstructor(): int
    {
        return 0xd712e4be;
    }

    public function serialize(OutputSerializedData $out): void
    {
//        $out->write(random_bytes(20), 'int128');
        $out->write($this->nonce, 'int128');
        $out->write($this->serverNonce, 'int128');
        $out->write($this->p, 'string');
        $out->write($this->q, 'string');
        $out->write($this->publicKeyFingerPrint, 'raw');
        $out->write($this->encryptData, 'string');
    }

    public static function response(InputSerializedData $in): BaseTLResObject
    {
        throw new \Exception('not implemented');
    }

    public static function getResponseClass(): string
    {
        throw new \Exception('not implemented');
    }
}