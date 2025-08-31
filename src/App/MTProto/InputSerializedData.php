<?php

namespace App\MTProto;

class InputSerializedData
{
    public string $data;
    public int $offset = 0;

    public function __construct()
    {
    }

    public function setData(string $binary): void
    {
        $this->data = $binary;
        $this->offset = 0;
    }

    public function read(string $type): mixed
    {
        $isVector = substr($type, 0, 6) === 'Vector';
        switch ($type) {
            case '#':
                return $this->readConstructor();
            case 'string':
            case 'strLong':
                return $this->readString();
            case 'int':
                return $this->readInt32();
            case 'long':
                return $this->readInt64();
            case 'int128':
                return $this->readInt128();
            default:
                if ($isVector) {
                    $itemType = substr($type, 7, strlen($type) - 8);
                    return $this->readVector(function (InputSerializedData $stream) use ($itemType) {
                        return $stream->read($itemType);
                    });
                }

                throw new \Exception("Unsupported type");
        }
    }

    private function readInt32(): int
    {
        $val = unpack('V', substr($this->data, $this->offset, 4))[1];
        $this->offset += 4;
        return $val;
    }

    private function readInt64(): int
    {
        $val = unpack('P', substr($this->data, $this->offset, 8))[1];
        $this->offset += 8;
        return $val;
    }

    private function readInt128(): string
    {
        return base64_encode($this->readRaw(16));
    }

    private function readFloat(): float
    {
        $val = unpack('g', substr($this->data, $this->offset, 4))[1];
        $this->offset += 4;
        return $val;
    }

    private function readDouble(): float
    {
        $val = unpack('e', substr($this->data, $this->offset, 8))[1];
        $this->offset += 8;
        return $val;
    }

    private function readBool(): bool
    {
        $val = $this->readInt32();
        if ($val === 0x997275b5) return true;
        if ($val === 0xbc799737) return false;
        throw new \Exception("Invalid bool value: 0x" . dechex($val));
    }

    private function readString(): string
    {
        $len = ord($this->data[$this->offset]);
        $this->offset += 1;

        if ($len === 254) {
            // TL long string length: 3 bytes
            $lenBytes = substr($this->data, $this->offset, 3);
            $len = ord($lenBytes[0]) | (ord($lenBytes[1]) << 8) | (ord($lenBytes[2]) << 16);
            $this->offset += 3;
        }

        $val = substr($this->data, $this->offset, $len);
        $this->offset += $len;

        // padding to 4 bytes
        $padLen = (4 - (($len + ($len < 254 ? 1 : 4)) % 4)) % 4;

        $this->offset += $padLen;
        return $val;
    }

    private function readVector(callable $deserializeItem): array
    {
        $constructor = $this->readInt32();
        if ($constructor !== 0x1cb5c415) {
            throw new \Exception("Invalid vector constructor: 0x" . dechex($constructor));
        }
        $count = $this->readInt32();

        $result = [];
        for ($i = 0; $i < $count; $i++) {
            $result[] = $deserializeItem($this);
        }
        return $result;
    }

    private function readLongVector(callable $deserializeItem): array
    {
        $constructor = $this->readConstructor();
        if ($constructor != '0x15c4b51c') {
            throw new \Exception("Invalid vector constructor: " . $constructor);
        }
        $count = $this->readInt32();
        $result = [];
        for ($i = 0; $i < $count; $i++) {
            $result[] = $deserializeItem($this);
        }
        return $result;
    }

    private function readRaw(int $length): string
    {
        $val = substr($this->data, $this->offset, $length);
        $this->offset += $length;
        return $val;
    }

    private function readConstructor(): int
    {
        $bin = $this->readRaw(4);
        return unpack('V', $bin)[1];
    }
}