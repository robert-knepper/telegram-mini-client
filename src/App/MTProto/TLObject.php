<?php

namespace App\MTProto;

abstract class TLObject
{
    abstract public static function getConstructor(): int;

    abstract public function serialize(OutputSerializedData $out): void;

    abstract public static function unserialize(InputSerializedData $in): self;

    private static $counterMessageId = 0;
    protected static array $map = [];

    public static function register(int $constructor, string $class): void
    {
        self::$map[$constructor] = $class;
    }

    public static function createFromConstructor(int $constructor, InputSerializedData $in): self
    {
        if (!isset(self::$map[$constructor])) {
            throw new \RuntimeException("Unknown constructor: " . dechex($constructor));
        }
        return self::$map[$constructor]::unserialize($in);
    }


    protected function generateRandomMessageID()
    {
        return (self::$counterMessageId++ * 4) + (time() << 32);
    }
}