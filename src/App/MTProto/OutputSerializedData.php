<?php

namespace App\MTProto;

use danog\MadelineProto\Lang;

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
            case 'long_f':
                $this->writeInt64($val);
                break;
            case 'int128':
            case 'int256':
            case 'int512':
                $this->writeRaw($val);
                break;
            case 'raw':
                $this->writeRaw($val);
                break;
            default:
                if ($isVector) {
                    $this->writeVector($val, function () {
                    });
                }
                throw new \Exception("Unsupported type");

        }
    }


    private function writeConstructor(int $val): void
    {
        if ($val > 4294967295) {
            throw new \Exception('value_bigger_than_4294967296');
        }
        if ($val < 0) {
            throw new \Exception('value_smaller_than_0');
        }
        $this->data .= pack('V', $val);
    }

    private function writeInt32(int $val): void
    {
        if ($val > 2147483647) {
            throw new \Exception('value_bigger_than_2147483647');
        }
        if ($val < -2147483648) {
            throw new \Exception('value_smaller_than_2147483648');
        }
        $res = pack('l', $val);
        $this->data .= $res;
    }

    private function writeInt64($val): void
    {
//         $this->data .= pack('P', $val);
        $this->data .= pack('q', $val);
    }

    private function writeFloat(float $val): void
    {
        $this->data .= pack('g', $val);
    }

    private function writeDouble(float $val): void
    {
        $this->data .= pack('e', $val);
    }

    private function writeBool(bool $val): void
    {
        $this->writeInt32($val ? 0x997275b5 : 0xbc799737);
    }

    private static function posmod(int $a, int $b): int
    {
        $resto = $a % $b;
        return $resto < 0 ? $resto + abs($b) : $resto;
    }

    private function writeString(string $val): void
    {

        $l = \strlen($val);
        $concat = '';
        if ($l <= 253) {
            $concat .= \chr($l);
            $concat .= $val;
            $concat .= pack('@' . self::posmod(-$l - 1, 4));
        } else {
            $concat .= \chr(254);
            $concat .= substr(pack('l', $l), 0, 3);
            $concat .= $val;
            $concat .= pack('@' . self::posmod(-$l, 4));
        }

        $this->write($concat, 'raw');

        /* $len = strlen($val);
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
             $this->data .= str_repeat("\x00", $padLen);*/
    }

    private function writeVector(array $items, callable $serializeItem): void
    {
        $this->writeInt32(0x1cb5c415);
        $this->writeInt32(count($items));
        foreach ($items as $item) {
            $serializeItem($this, $item);
        }
    }

    private function writeRaw(string $val): void
    {
        $this->data .= $val;
    }

    private function writeP_Or_Q($val): void
    {
        $this->data .= chr(strlen(pack('V', $val))) . pack('V', $val) . str_repeat("\0", 3);
    }
}