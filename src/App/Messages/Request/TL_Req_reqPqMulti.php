<?php

namespace App\Messages\Request;

use App\Messages\Response\TL_Res_resPQ;
use App\MTProto\OutputSerializedData;
use App\MTProto\BaseTLReqObject;

class TL_Req_reqPqMulti extends BaseTLReqObject
{

    public function __construct(private string $nonce)
    {
    }


    public static function getConstructor(): int
    {
        return 0xbe7e8ef1;
    }

    public static function getResponseClass(): string
    {
        return TL_Res_resPQ::class;
    }

    public function serialize(OutputSerializedData $out): void
    {
        $out->write($this->nonce, 'int128');
    }

}