<?php

/**
 * Define SM3Encription.php
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

/**
 * SM3国密算法实现：http://www.sca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
 */
class SM3Encryption extends BaseCrypto
{
    // 初始值，用于确定压缩函数寄存器的初态
    private const SM3_IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ];

    // 常量，随j的变化取不同的值
    private const TJ_LT_16 = 0x79CC4519;
    private const TJ_GTE_16 = 0x7A879D8A;

    private $useOpenssl = false;

    public function __construct()
    {
        $this->checkOpenssl();
    }

    /**
     * [checkOpenssl 检查openssl库是否支持国密3]
     * @return
     */
    protected function checkOpenssl()
    {
        $ciphers = openssl_get_md_methods();
        if (in_array('sm3', $ciphers)) {
            $this->useOpenssl = true;
        }
    }

    /**
     * [isOpenssl 获取openssl是否支持国密3状态]
     * @return boolean
     */
    public function isOpenssl()
    {
        return false;
        return $this->useOpenssl;
    }

    public function hexArray($array)
    {
        $hex = array_map(function ($value) {
            $hex = sprintf('%08x', $value);
            return substr(implode('', array_reverse(str_split($hex, 2))), 0, 8);
        }, $array);
        return $hex;
    }

    public function sm3($input)
    {
        // 使用openssl的国密3算法加密返回
        if ($this->isOpenssl()) {
            return openssl_digest($input, 'sm3');
        }
        /*
         *  使用自实现算法
         */

        // 获取填充后的buffer数组
        $padded = $this->sm3Padding($input);
        // 获取分组后的结果m′
        $groupped = $this->group($padded);

        // 对m′按下列方式迭代：
        // FOR i=0 TO n-1
        // V(i+1) = CF(V(i), B(i))
        // ENDFOR

        // 初始矩阵
        $vector = self::SM3_IV;
        $groupLength = count($groupped);
        for ($i = 0; $i < $groupLength; $i++) {
            $vector = $this->sm3Compress($vector, $groupped[$i]);
        }

        dd($vector);
    }

    /**
     * [expandMessage 5.3.2 消息扩展]
     * @param  [type] $message  [B(i)，直接传入]
     * @return [type]           [description]
     */
    protected function expandMessage($message)
    {
        // a)将消息分组B(i)划分为16个字W0, W1, · · · , W15。
        // 64个字节，按4字节分成16组得到W数组
        $wGroup = array_chunk($message, 4);
        $wGroup = array_map(function ($value) {
            return $this->buffer2Int($value);
        }, $wGroup);
        // b)FOR j=16 TO 67
        // Wj ← P1(Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)) ⊕ (Wj−13 ≪ 7) ⊕ Wj−6
        // ENDFOR
        for ($j = 16; $j < 68; $j++) {
            $intValue = $this->sm3P1(
                $wGroup[$j - 16] ^ $wGroup[$j - 9] ^ $this->leftCircularRotation(
                    $wGroup[$j - 3],
                    15
                ) ^ $this->leftCircularRotation($wGroup[$j - 13], 7)
                 ^ $wGroup[$j - 6]
            );
            // 得到的int可能溢出，转为int32
            $wGroup[$j] = $this->int32($intValue);
        }
        $wDashedGroup = [];
        // c)FOR j=0 TO 63
        // W′j = Wj ⊕ Wj+4
        // ENDFOR
        for ($j = 0; $j < 64; $j++) {
            $wDashedGroup[$j] = $this->int32($wGroup[$j] ^ $wGroup[$j + 4]);
        }
        return ['prime' => $this->hexArray($wGroup), 'dash' => $this->hexArray($wDashedGroup)];
    }

    /**
     * [sm3Compress description]
     * @param  [type] $vector   [description]
     * @param  [type] $groupped [description]
     * @return [type]           [description]
     */
    protected function sm3Compress($vector, $groupped)
    {
        // 先记录Vi到一个新数组，防止后面的矩阵变换将Vi改变
        $vectorI = array_merge([], $vector);
        // 令A,B,C,D,E,F,G,H为字寄存器，均为4字节，初始赋值为IV
        // ABCDEFGH ← V(i), 对应为
        // A = $vector[0]
        // B = $vector[1]
        // C = $vector[2]
        // D = $vector[3]
        // E = $vector[4]
        // F = $vector[5]
        // G = $vector[6]
        // H = $vector[7]

        $expandedMsg = $this->expandMessage($groupped);
        dd('扩展后的消息：', $expandedMsg);
        for ($j = 0; $j < 63; $j++) {
            // SS1 ← ((A ≪ 12) + E + (Tj ≪ j)) ≪ 7
            $ss1 = $this->leftCircularRotation(
                $this->leftCircularRotation(
                    $vector[0],
                    12
                ) + $vector[4] + ($this->leftCircularRotation($this->getTJ($j), $j)),
                7
            );
            // SS2 ← SS1 ⊕ (A ≪ 12)
            $ss2 = $ss1 ^ $this->leftCircularRotation($vector[0], 12);
            // TT1 ← FFj (A, B, C) + D + SS2 + W′j
            $tt1 = $this->sm3FF($j, $vector[0], $vector[1], $vector[2])
             + $vector[3] + $ss2 + $expandedMsg['dash'][$j];
            // TT2 ← GGj (E, F, G) + H + SS1 + Wj
            $tt2 = $this->sm3GG($j, $vector[4], $vector[5], $vector[6])
             + $vector[7] + $ss1 + $expandedMsg['prime'][$j];
            // 变换矩阵
            // D ← C
            // C ← B ≪ 9
            // B ← A
            // A ← T T1
            // H ← G
            // G ← F ≪ 19
            // F ← E
            // E ← P0(T T2)
            $vector[3] = $vector[2];
            $vector[2] = $this->leftCircularRotation($vector[1], 9);
            $vector[1] = $vector[0];
            $vector[0] = $tt1;
            $vector[7] = $vector[6];
            $vector[6] = $this->leftCircularRotation($vector[5], 19);
            $vector[5] = $vector[4];
            $vector[4] = $this->sm3P0($tt2);
        }

        // V(i+1) ← ABCDEF GH ⊕ V(i)
        $nextVector = [];
        for ($i = 0; $i < 8; $i++) {
            $nextVector[$i] = $vector[$i] ^ $vectorI[$i];
        }

        return $nextVector;
    }

    protected function getTJ($index)
    {
        if ($index >= 0 && $index <= 15) {
            return self::TJ_LT_16;
        }
        if ($index >= 16 && $index <= 63) {
            return self::TJ_GTE_16;
        }
        throw new Exception('j must between 0 and 63');
    }

    /**
     * [group 将填充后的消息m′按512比特进行分组：m′ = B(0)B(1) · · · B(n−1)]
     * @param  [type] $input [description]
     * @return [type]        [description]
     */
    protected function group($input)
    {
        // buffer是字节数组，所以把512bit转换为字节长度进行分组
        $groupLength = 512 / 8;
        $output = array_chunk($input, $groupLength);
        return $output;
    }

    /**
     * [sm3Padding 假设消息m 的长度为l 比特。首先将比特“1”添加到消息的末尾，再添加k 个“0”，k是满
        足l + 1 + k ≡ 448mod512 的最小的非负整数。然后再添加一个64位比特串，该比特串是长度l的二进
        制表示。填充后的消息m′ 的比特长度为512的倍数。]
     * @author: 上面这段话转化为byte来描述：将消息按照64字节分组，其中最后一组长度restLength为byteLength % 64，
     *          将最后一组（如果正好是64字节整倍数，则添加一组64字节作为最后一组）按照以下方式填充：
     *          先填充1字节0x80，再填充55-restLength字节0x00,最后填充8字节bitLength
     * @param  [type] $data [description]
     * @return [type]       [description]
     */
    protected function sm3Padding($data)
    {
        // 转换字符串为字节数组
        $buffer = $this->str2Buffer($data);

        // 字节长度
        $byteLength = count($buffer);

        // 记录位长度
        $bitLength = $byteLength * 8;

        // 首先将比特“1”添加到消息的末尾
        $buffer [] = 0x80;

        // 再添加k 个“0”，k是满足l + 1 + k ≡ 448mod512 的最小的非负整数
        // 64[512bit] - 1[已填充的0x80] - ($byteLength % 64)[按64字节分组后剩余的字节数] - 8[最后要留8字节放长度]
        $paddingLength = 64 - 1 - ($byteLength % 64) - 8;

        // 按计算出的填充长度填充0
        $buffer = array_pad($buffer, $byteLength + $paddingLength + 1, 0x00);

        // 然后再添加一个64位比特串，该比特串是长度l的二进制表示
        $buffer = array_merge($buffer, $this->str2Buffer(pack("J", $bitLength)));

        return $buffer;
    }

    /**
     * [sm3FF 布尔函数FFj(X,Y,Z)]
     * @param  [type] $index  [description]
     * @param  [type] $inputX [description]
     * @param  [type] $inputY [description]
     * @param  [type] $inputZ [description]
     * @return [type]         [description]
     */
    protected function sm3FF($index, $inputX, $inputY, $inputZ)
    {
        if ($index >= 0 && $index <= 15) {
            return $inputX ^ $inputY ^ $inputZ;
        }
        return ($inputX & $inputY) | ($inputX & $inputZ) | ($inputY & $inputZ);
    }

    /**
     * [sm3GG 布尔函数GGj(X,Y,Z)]
     * @param  [type] $index  [description]
     * @param  [type] $inputX [description]
     * @param  [type] $inputY [description]
     * @param  [type] $inputZ [description]
     * @return [type]         [description]
     */
    protected function sm3GG($index, $inputX, $inputY, $inputZ)
    {
        if ($index >= 0 && $index <= 15) {
            return $inputX ^ $inputY ^ $inputZ;
        }
        return ($inputX & $inputY) | (~$inputX & $inputZ);
    }

    protected function sm3P0($input)
    {
        return $input ^ $this->leftCircularRotation($input, 9) ^ $this->leftCircularRotation($input, 17);
    }

    protected function sm3P1($input)
    {
        return $input ^ $this->leftCircularRotation($input, 15) ^ $this->leftCircularRotation($input, 23);
    }
}
