<?php

namespace App\MTProto;

abstract class BaseTLObject
{
    abstract public static function getConstructor(): int;
}