<?php

/**
 * Define BaseCrypto.php
 *
 * PHP version 8
 *
 * @author   Endy <endy@evit.net.cn>
 * @link     https://github.com/Endy-c
 * @license  MIT License
 *
 *  Copyright (c) 2022 Endy
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

namespace Evit\PhpGmCrypto\Encryption;

use Exception;

class BaseCrypto
{
    /**
     * [buffer2Str 将strBuffer转化为字符串]
     * @param  array  $buffer   [输入数组]
     * @return string           [输出字符串]
     */
    protected function buffer2Str(array $buffer): string
    {
        return pack('C*', ...$buffer);
    }

    protected function buffer2Uint32($buffer)
    {
        return pack('N*', ...$buffer);
    }

    /**
     * [int32 PHP位运算后溢出，需要处理为32位数值]
     * @param  uint32 $input    [64位未溢出]
     * @return int32            [为溢出数据添加符号位]
     */
    protected function int32($input)
    {
        /**
         * @todo 对比此方法和unpack(pack)方法效率
         */
        if ($input > 0x7FFFFFFF) {
            $input--;
            $input = ~$input;
            $input &= 0x7FFFFFFF;
            $input = -$input;
        }

        // $input = unpack('i', pack('i', $input))[1];
        return $input;
    }

    /**
     * [buffer2int 把4字节buffer转成int32]
     * @param  array $bytes [description]
     * @return int32        [description]
     */
    protected function buffer2Int($bytes)
    {
        $int32 = pack('C*', ...$bytes);
        $int32 = (unpack('l', $int32))[1];
        return $this->int32($int32);
    }

    /**
     * [leftCircularRotation 向左回环位移]
     * <<< i left circular rotation by i bits
     * 回环变位：如果字符串s中的字符循环移动任意位置之后能够得到另一个字符串 t，那么 s 称为 t 的回环变位(Circular Rotation)。例如，”ACTGACG” 就是 “TGACGAC” 的一个回环变位。
     * @param  uint32 $u32Buffer    [32位buffer]
     * @param  int    $bits         [位移长度]
     * @return uint32               [回环变位后的32位buffer]
     */
    protected function leftCircularRotation($u32Buffer, int $bits)
    {
        $bits = $bits % 32;
        return (($u32Buffer << $bits) & 0xFFFFFFFF) | $this->uRightShift($u32Buffer, 32 - $bits);
    }

    /**
     * [linearTransform L函数和L'函数，实现加密和密码扩展的线性变换]
     * @param  uint32   $input  [输入的32位数据]
     * @param  int      $type   [description]
     * @return uint32           [线性变换后的结果]
     */
    protected function linearTransform($input, $type)
    {
        if (!$type) {
            $input = $this->int32($input);
        }
        switch ($type) {
            // L'：key expand
            case 0:
            default:
                return $this->int32($input ^ $this->leftCircularRotation($input, 13)
                 ^ $this->leftCircularRotation($input, 23));
                // L：encrypt
            case 1:
                return $input ^ $this->leftCircularRotation($input, 2) ^ $this->leftCircularRotation($input, 10)
                 ^ $this->leftCircularRotation($input, 18) ^ $this->leftCircularRotation($input, 24);
        }
    }

    /**
     * [removePadding 逆向去除padding数据]
     * @param  array    $padded [填充后的块数组，长度为16倍数]
     * @return array            [去除填充后的原数组]
     */
    protected function removePadding($padded, $mode = 'PKCS7')
    {
        if (!($padded && is_array($padded))) {
            throw new Exception('必须传入pkcs7填充后数组');
        }

        if (!$mode == 'PKCS7') {
            /**
             * @todo 其他padding算法
             */
            return;
        }

        // padding长度一定是PKCS7数组的最后一个元素
        $paddingLen = end($padded);
        $result = array_slice($padded, 0, -$paddingLen);

        return $result;
    }

    /**
     * [str2Buffer 将字符串转化为strBuffer数组]
     * @param  string $str      [输入字符串]
     * @return array            [输出的数组]
     */
    protected function str2Buffer(string $str): array
    {
        // 由于unpack返回的数组下标从1开始，取values重置数组index方便后续计算
        return array_values(unpack('C*', $str));
    }

    /**
     * [u8ToU32 每16组u8数组pack进1组长度为4的u32数组]
     * @param  array $u8Array   [u8数组]
     * @param  array $baseIndex [基准偏移量]
     * @return array            [长度为4的u32数组]
     */
    protected function u8ToU32($u8Array, $baseIndex = 0)
    {
        if (!isset($u8Array[$baseIndex + 15])) {
            throw new Exception('数组长度[' . (count($u8Array) - $baseIndex) . ']不符合转换要求[16]');
        }

        $u32Array = [];
        for ($i = 0; $i < 4; $i++) {
            $u32Array[$i] = $u8Array[$baseIndex + $i * 4] << 24 | $u8Array[$baseIndex + $i * 4 + 1] << 16
             | $u8Array[$baseIndex + $i * 4 + 2] << 8 | $u8Array[$baseIndex + $i * 4 + 3];
        }
        return $u32Array;
    }

    /**
     * [uRightShift 实现无符号右移（JS里的>>>）]
     * @param  int32    $i32Buffer  [32位buffer]
     * @param  int      $bits       [位移长度]
     * @return uinit32              [无符号右移后的结果]
     */
    protected function uRightShift($i32Buffer, int $bits)
    {
        if (!$bits) {
            return $this->int32($i32Buffer);
        }
        return $this->int32((0x7FFFFFFF >> ($bits - 1)) & ($i32Buffer >> $bits));
    }

    /**
     * [hexArray 辅助函数，打印十六进制数组和论文示例值进行对比]
     * @param  array $array [数值型数组]
     * @return array        [元素为十六进制字符串的数组]
     */
    protected function hexArray($array)
    {
        $hex = array_map([$this, 'hexVal'], $array);
        return $hex;
    }

    /**
     * [hexVal 数值转换为16进制]
     * @param  int $value [整型数值]
     * @return string     [十六进制字符串]
     */
    protected function hexVal($value)
    {
        $hex = sprintf('%08x', $value);
        return $hex;
    }
}
