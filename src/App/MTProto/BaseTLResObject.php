<?php

namespace App\MTProto;

abstract class BaseTLResObject extends BaseTLObject
{
    abstract public static function unserialize(InputSerializedData $data) : self;


    protected function __construct()
    {
    }


}