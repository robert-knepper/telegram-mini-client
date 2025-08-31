<?php

namespace App\MTProto;

abstract class BaseTLReqObject extends BaseTLObject
{
    /**
     * @return string|BaseTLResObject
     */
    abstract public static function getResponseClass(): string;

    abstract public function serialize(OutputSerializedData $out): void;

}