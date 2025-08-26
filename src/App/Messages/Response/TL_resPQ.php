<?php

namespace App\Messages\Response;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\TLObject;

class TL_resPQ extends TLObject
{
    public string $authKeyId;
    public int $messageId;
    public string $nonce;
    public string $server_nonce;
    public string $pq;        // big-endian bytes
    public array $fingerprints = []; // vector<long>

    public static function getConstructor(): int
    {
        return 0x05162463;
    }

    public function serialize(OutputSerializedData $out): void
    {
    }

    public static function unserialize(InputSerializedData $in): self
    {
        $obj = new self();
        $obj->authKeyId = $in->readInt64();
        $obj->messageId = $in->readInt64();
        $bodyLen = $in->readInt32();

        $constructor = $in->readInt32();
        if ($constructor !== self::getConstructor())
            throw new \Exception('constructor not match');
        $obj->nonce = $in->readRaw(16);
        $obj->server_nonce = $in->readRaw(16);

        $obj->pq = $in->readString();
        $obj->fingerprints = $in->readLongVector(function (InputSerializedData $stream) {
            return dechex($stream->readInt64());
        });

        return $obj;
    }
}