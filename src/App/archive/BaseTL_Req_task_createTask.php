<?php

namespace App\archive;

use App\MTProto\InputSerializedData;
use App\MTProto\OutputSerializedData;
use App\MTProto\BaseTLReqObject;

class BaseTL_Req_task_createTask extends BaseTLReqObject
{
    public string $title;
    public string $description;

    public static function getConstructor(): int
    {
        return 0x11111111;
    }

    public function serialize(OutputSerializedData $out): void
    {
        $out->writeInt32(self::getConstructor());
        $out->writeString($this->title);
        $out->writeString($this->description);
    }

    public static function response(InputSerializedData $in): self
    {
        $obj = new self();
        $obj->title = $in->readString();
        $obj->description = $in->readString();
        return $obj;
    }
}