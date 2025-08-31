<?php

namespace App\MTProto;

class OutputSerializedData
{
    public string $data;

    public function __construct()
    {
        $this->newData();
    }

    public function newData(): void
    {
        $this->data = '';
    }

    public function getData(): string
    {
        return $this->data;
    }

    public function write(mixed $val, string $type)
    {
        $isVector = (
            is_array($val)
            && strlen($type) > 7
            && substr($type, 0, 6) == 'Vector'
        );
        switch ($type) {
            case '#':
                $this->writeConstructor($val);
                break;
            case 'string':
                $this->writeString($val);
                break;
            case 'int':
                $this->writeInt32($val);
                break;
            case 'long':
                $this->writeInt64($val);
                break;
            case 'int128':
            case 'int256':
            case 'int512':
                $this->writeRaw($val);
                break;
            default:
                if ($isVector){
                    $this->writeVector($val,function (){
                    });
                }
                throw new \Exception("Unsupported type");

        }
    }


    public function writeConstructor(int $val): void
    {
        $this->writeInt32($val);
    }

    public function writeInt32(int $val): void
    {
        $this->data .= pack('V', $val);
    }

    public function writeInt64($val): void
    {
        $this->data .= pack('P', $val);
    }

    public function writeFloat(float $val): void
    {
        $this->data .= pack('g', $val);
    }

    public function writeDouble(float $val): void
    {
        $this->data .= pack('e', $val);
    }

    public function writeBool(bool $val): void
    {
        $this->writeInt32($val ? 0x997275b5 : 0xbc799737);
    }

    public function writeString(string $val): void
    {
        $len = strlen($val);
        if ($len < 254) {
            // length as 1 byte
            $this->data .= chr($len);
            $this->data .= $val;
            // padding to make total length multiple of 4
            $padLen = (4 - (($len + 1) % 4)) % 4;
            $this->data .= str_repeat("\x00", $padLen);
        } else {
            // length as 0xFE + 3 bytes length
            $this->data .= chr(254);
            $this->data .= pack('V', $len); // actually 3 bytes used, pack returns 4
            // TL uses only 3 bytes, but pack returns 4, so use only first 3 bytes
            $this->data = substr($this->data, 0, -1); // remove last byte
            $this->data .= $val;
            $padLen = (4 - ($len % 4)) % 4;
            $this->data .= str_repeat("\x00", $padLen);
        }
    }

    public function writeVector(array $items, callable $serializeItem): void
    {
        $this->writeInt32(0x1cb5c415);
        $this->writeInt32(count($items));
        foreach ($items as $item) {
            $serializeItem($this, $item);
        }
    }

    public function writeRaw(string $val): void
    {
        $this->data .= $val;
    }

    public function writeP_Or_Q($val): void
    {
        $this->data .= chr(strlen(pack('V', $val))) . pack('V', $val) . str_repeat("\0", 3);
    }
}