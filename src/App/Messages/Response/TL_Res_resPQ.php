<?php

namespace App\Messages\Response;

use App\MTProto\BaseTLResObject;
use App\MTProto\InputSerializedData;

class TL_Res_resPQ extends BaseTLResObject
{
    public $nonce;
    public $server_nonce;
    public $pq;        // big-endian bytes
    public array $fingerprints = []; // vector<long>

    public static function getConstructor(): int
    {
        return 0x05162463;
    }

    public static function unserialize(InputSerializedData $in): BaseTLResObject
    {
        $obj = new self();
        $obj->nonce = $in->read('int128');
        $obj->server_nonce = $in->read('int128');
        $obj->pq = $in->read('string');
//        $obj->pq = unpack('q', strrev($in->read('string')))[1];
        $obj->fingerprints = $in->read('Vector<long>');

        return $obj;
    }
}