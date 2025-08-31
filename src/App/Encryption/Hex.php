<?php

namespace App\Encryption;
class Hex
{
    public static function encode($bin_string)
    {
        $hex = '';
        $len = self::safeStrlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $chunk = \unpack('C', self::safeSubstr($bin_string, $i, 2));
            $c = $chunk[1] & 0xf;
            $b = $chunk[1] >> 4;
            $hex .= pack('CC', (87 + $b + ((($b - 10) >> 8) & ~38)), (87 + $c + ((($c - 10) >> 8) & ~38)));
        }
        return $hex;
    }

    public static function decode($hex_string)
    {
        $hex_pos = 0;
        $bin = '';
        $c_acc = 0;
        $hex_len = self::safeStrlen($hex_string);
        $state = 0;
        if (($hex_len & 1) !== 0) {
            throw new \RangeException(
                'Expected an even number of hexadecimal characters'
            );
        }

        $chunk = \unpack('C*', $hex_string);
        while ($hex_pos < $hex_len) {
            ++$hex_pos;
            $c = $chunk[$hex_pos];
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                throw new \RangeException(
                    'hexEncode() only expects hexadecimal characters'
                );
            }
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= \pack('C', $c_acc | $c_val);
            }
            $state ^= 1;
        }
        return $bin;
    }

    public static function safeStrlen($str)
    {
        if (\function_exists('mb_strlen')) {
            return (int)\mb_strlen($str, '8bit');
        } else {
            return (int)\strlen($str);
        }
    }

    public static function safeSubstr($str, $start = 0, $length = \null)
    {
        if (\function_exists('mb_substr')) {
            // mb_substr($str, 0, null, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (\is_null($length)) {
                if ($start >= 0) {
                    $length = self::safeStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }
            // $length calculation above might result in a 0-length string
            if ($length === 0) {
                return '';
            }
            return \mb_substr($str, $start, $length, '8bit');
        }
        if ($length === 0) {
            return '';
        }
        // Unlike mb_substr(), substr() doesn't accept null for length
        if (!is_null($length)) {
            return \substr($str, $start, $length);
        } else {
            return \substr($str, $start);
        }
    }
}