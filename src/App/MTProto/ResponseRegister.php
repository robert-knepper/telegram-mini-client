<?php

namespace App\MTProto;

class ResponseRegister
{
    public function __construct()
    {
    }

    private static $classByConstructor = [];

    /**
     * @param string|BaseTLResObject $class
     * @return void
     */
    public static function addTLObjRes(string $class): void
    {
        self::$classByConstructor[$class::getConstructor()] = $class;
    }

    /**
     * @param int $constructor
     * @return string|BaseTLResObject
     */
    public static function getTLObj(int $constructor): string
    {
        return self::$classByConstructor[$constructor];
    }
}