<?php

/**
 * Define EvitSM4Encryption.php
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

class EvitSM4Encryption extends BaseCrypto
{
    /**
     * @todo 算法文档里FK，CK，SBOX这几个常量都是写死的，弄清楚为什么
     * http://sca.hainan.gov.cn/xxgk/bzhgf/201804/W020180409400793061524.pdf
     */
    protected const SM4_FK = [
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    ];

    protected const SM4_CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ];

    protected const SM4_SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ];

    // 块长度，固定为16
    protected const SM4_BLOCK_SIZE = 16;

    private $key;
    private $hexIv = null;
    private $mode = 'cbc';
    private $encryptRoundKey = [];

    /**
     * [__construct 初始化加密算法]
     * @param array $config 数组，格式如下：
     * [
     *     'key'    => '密码，长度不足16将自动填充NULL，超过将自动截断',
     *     'mode'   => 'cbc或ecb，默认cbc',
     *     'iv'     => '偏移向量，长度固定为16，否则抛出异常',
     *     'type'   => '传入无效，固定为base64，使用text类型可能会造成字符串截断无法输出正确密文'
     * ]
     */
    public function __construct($config = null)
    {
        if (!is_array($config)) {
            throw new Exception("初始化参数只接受数组['key', 'mode', 'iv', 'type']");
        }
        // 处理密钥
        $keyBuffer = $this->str2Buffer($config['key'] ?? '');
        $this->key = $this->ensureKeyLength($keyBuffer);

        // 处理模式
        $mode = strtolower($config['mode'] ?? '');
        if (in_array($mode, ['cbc', 'ecb'])) {
            $this->mode = $mode;
        }

        // 处理偏移向量iv
        if ($this->mode == 'cbc') {
            $ivBuffer = [];
            $ivBuffer = $this->str2Buffer($config['iv'] ?? '');
            $this->checkIvLength($ivBuffer);
            $this->hexIv = $ivBuffer;
        }
        // 生成轮次密钥
        $this->spawnRoundKeys();
    }

    /**
     * [checkIvLength 检查iv长度，不是16位直接抛出异常]
     * @param  array $ivBuffer      [传入的iv转化为字节数组]
     * @return
     */
    private function checkIvLength(array $ivBuffer)
    {
        $length = count($ivBuffer);
        if ($length != 16) {
            throw new Exception('iv长度必须为16字节');
        }
    }

    /**
     * [ensureKeyLength 确保密码长度，传入长度不足16将自动填充NULL，超过将自动截断]
     * @param  array  $keyBuffer    [传入的key转化为字节数组]
     * @return array                [固定长度为16的字节数组]
     */
    private function ensureKeyLength(array $keyBuffer): array
    {
        $length = count($keyBuffer);
        if ($length == 16) {
            return $keyBuffer;
        }

        return $length > 16 ? array_slice($keyBuffer, 0, 16) : array_pad($keyBuffer, 16, 0);
    }

    /**
     * [getEncryptRoundKey 获取加密用轮密码]
     * @return [type] [解密用轮密码，为加密轮密码的反转数组]
     */
    private function getEncryptRoundKey()
    {
        return $this->encryptRoundKey;
    }

    /**
     * [getDecryptRoundKey 获取解密用轮密码]
     * @return array [解密用轮密码，为加密轮密码的反转数组]
     */
    private function getDecryptRoundKey()
    {
        return array_reverse($this->encryptRoundKey);
    }

    /**
     * [spawnRoundKeys 从输入的key生成32轮的轮次key]
     * The round keys are represented as (rk0, rk1, … , rk31), where rki(i = 0, … ,31) are 32-bit words.
     * The round keys are generated from the cipher key via key expansion algorithm.
     * The system parameter is FK = (FK0, FK1, FK2, FK3),
     * and the fixed parameter is CK = (CK0, CK1, … , CK31),
     * where the FKi(i = 0,1,2,3) and CKi(i = 0, … ,31) are 32-bit words used in the key expansion algorithm
     * @return
     */
    private function spawnRoundKeys()
    {
        /**
         * The 128-bit cipher key is represented as MK = (MK0, MK2, MK3, MK4), where MKi =
         * (i = 0,1,2,3) are 32-bit words.
         * 中间密码MK
         * @var middleK
         */
        $middleK = [];
        // 32轮次迭代数组roundK，会有36长度
        $roundK = [];
        $middleK = $this->u8ToU32($this->key, 0);

        for ($i = 0; $i < 4; $i++) {
            $roundK[$i] = $middleK[$i] ^ self::SM4_FK[$i];
        }

        for ($roundLoop = 0; $roundLoop < 32; $roundLoop++) {
            $roundK[$roundLoop + 4] = $this->roundFunction($roundK, $roundLoop);
            // 获得轮密码
            $this->encryptRoundKey[$roundLoop] = $roundK[$roundLoop + 4];
        }
    }

    /**
     * 轮函数F。
     *
     * 6 Round Function 𝑭
     * 6.1 Round Function Structure
     * Suppose the input to round function is (𝑋0 ,𝑋1 ,𝑋2 ,𝑋3 ) ∈ (𝑍43)C and the round key is
     * 𝑟𝑘 ∈ 𝑍43, then 𝐹 can be represented as: 3
     * 𝐹 𝑋0,𝑋1,𝑋2,𝑋3,𝑟𝑘   = 𝑋0 ⊕ 𝑇(𝑋1 ⊕ 𝑋2 ⊕ 𝑋3 ⊕ 𝑟𝑘).
     * @param $roundK       迭代数组
     * @param $roundLoop    迭代到第几轮
     * @param $type         0-密码轮函数，1-加密轮函数
     * @return 返回值赋值给$roundK[$roundLoop + 4]
     */
    private function roundFunction($roundK, $roundLoop, $type = 0, $isDecrypt = 0)
    {
        if ($type) {
            $rKeys = $isDecrypt ? $this->getDecryptRoundKey() : $this->getEncryptRoundKey();
            return $roundK[$roundLoop] ^ $this->tTransformFunction($roundK[$roundLoop + 1]
             ^ $roundK[$roundLoop + 2] ^ $roundK[$roundLoop + 3] ^ $rKeys[$roundLoop], 1);
        }

        return $this->int32($roundK[$roundLoop] ^ $this->tTransformFunction($roundK[$roundLoop + 1]
         ^ $roundK[$roundLoop + 2] ^ $roundK[$roundLoop + 3] ^ self::SM4_CK[$roundLoop]));
    }

    /**
     * 组合T。
     * 包括：
     * （1）非线性变换𝝉(tau)
     * （2）线性变换L。
     *
     * 6.2 Permutation 𝑻
     * 𝑇: 𝑍43 → 𝑍43 is an invertible transformation, composed of a nonlinear transformation 𝜏 33
     * and a linear transformation 𝐿. That is, 𝑇 ∙ = 𝐿(𝜏(∙)).
     *
     * (1) Nonlinear transformation 𝝉
     * 𝜏 is composed of 4 S-boxes in parallel. Suppose 𝐴 = (𝑎 ,𝑎 ,𝑎 ,𝑎 ) ∈ (𝑍M)C is input to 0234 3
     * 𝜏, and 𝐵 = (𝑏 ,𝑏 ,𝑏 ,𝑏 ) ∈ (𝑍M)C is the corresponding output, then 0234 3
     * 𝑏0,𝑏2,𝑏3,𝑏4 = 𝜏 𝐴 = (𝑆𝑏𝑜𝑥 𝑎0 ,𝑆𝑏𝑜𝑥 𝑎2 ,𝑆𝑏𝑜𝑥 𝑎3 ,𝑆𝑏𝑜𝑥 𝑎4 ).
     * The S-box is as follows:
     * @see self::SM4_SBOX
     *
     * (2) Linear transformation 𝑳
     * The output from the nonlinear transformation 𝜏 is the input to the linear
     * transformation 𝐿. Suppose the input to 𝐿 is 𝐵 ∈ 𝑍43, and the corresponding output is 3
     * 𝐶 ∈ 𝑍43, then 3
     * 𝐶=𝐿 𝐵 =𝐵⊕(𝐵<<<2)⊕(𝐵<<<10)⊕(𝐵<<<18)⊕(𝐵<<<24).
     *
     * @param   uint32  $input  组合变换输入项
     * @param   int     $type   0-密码扩展线性变换，1-加密线性变换
     * @return
     */
    private function tTransformFunction($input, $type = 0)
    {
        if (!$type) {
            $input = $this->int32($input);
        }
        $firstStage = $this->tauTransform($input, $type);
        $finalStage = $this->linearTransform($firstStage, $type);
        if ($type) {
            return $finalStage;
        }
        return $this->int32($finalStage);
    }

    /**
     * [tauTransform 使用SBOX进行𝜏变换]
     * @param  uint32 $input [输入的32位数据]
     * @return uint32        [𝜏变换结果]
     */
    private function tauTransform($input, $type)
    {
        if (!$type) {
            $input = $this->int32($input);
            return $this->int32(self::SM4_SBOX[$this->uRightShift($input, 24) & 0xFF] << 24
             | self::SM4_SBOX[$this->uRightShift($input, 16) & 0xFF] << 16
             | self::SM4_SBOX[$this->uRightShift($input, 8) & 0xFF] << 8
             | self::SM4_SBOX[$input & 0xFF]);
        }
        return self::SM4_SBOX[$this->uRightShift($input, 24) & 0xFF] << 24
         | self::SM4_SBOX[$this->uRightShift($input, 16) & 0xFF] << 16
         | self::SM4_SBOX[$this->uRightShift($input, 8) & 0xFF] << 8
         | self::SM4_SBOX[$input & 0xFF];
    }

    /**
     * [arrayPadding 需要将数组填充为块长度的整倍数]
     * SM4要求PKCS7Padding，假设数据长度需要填充n(n>0)个字节才对齐，那么填充n个字节，
     * 每个字节都是n;如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小。
     * @param  array $origin    [初始数组]
     * @return array            [填充后的块，16倍数]
     */
    private function arrayPadding($origin, $mode = 'PKCS7')
    {
        if (!$mode == 'PKCS7') {
            /**
             * @todo 其他padding算法
             */
            return;
        }

        if (!($origin && is_array($origin))) {
            return [];
        }

        $originalSize = count($origin);
        $blockSize = self::SM4_BLOCK_SIZE;
        // 需要填充的长度
        $paddingLen = $blockSize - $originalSize % $blockSize;
        return array_pad($origin, $originalSize + $paddingLen, $paddingLen);
    }

    public function decrypt($encrypted)
    {
        // 将密文转换为数组进行处理
        $u8Array = $this->str2Buffer($encrypted);
        // 解密块数量
        $numOfBlocks = count($u8Array) / self::SM4_BLOCK_SIZE;
        // 解密结果数组
        $result = $this->mode == 'cbc' ? $this->cbcMode($u8Array, $numOfBlocks, 1)
         : $this->ecbMode($u8Array, $numOfBlocks, 1);

        $ret = $this->removePadding($result);

        return $this->buffer2Str($ret);
    }

    public function encrypt($plainText)
    {
        // 将明文转换为数组进行处理
        $u8Array = $this->str2Buffer($plainText);
        // PKCS7填充
        $padded = $this->arrayPadding($u8Array);
        // 加密块数量
        $numOfBlocks = count($padded) / self::SM4_BLOCK_SIZE;
        ;
        // 加密结果数组
        $result = $this->mode == 'cbc' ? $this->cbcMode($padded, $numOfBlocks) : $this->ecbMode($padded, $numOfBlocks);

        return $this->buffer2Str($result);
    }

    private function doCrypt(&$chainBlock, $block, $isDecrypt)
    {
        // 加密先做异或运算
        if (!$isDecrypt) {
            for ($j = 0; $j < 4; $j++) {
                $chainBlock[$j] = $chainBlock[$j] ^ $block[$j];
            }
        }

        $cipherBlock = $this->cryptAlgrithm($isDecrypt ? $block : $chainBlock, $isDecrypt);
        // 解密后做异或
        if ($isDecrypt) {
            for ($j = 0; $j < 4; $j++) {
                $cipherBlock[$j] = $chainBlock[$j] ^ $cipherBlock[$j];
            }
        }
        return $cipherBlock;
    }

    private function cbcMode($padded, $numOfBlocks, $isDecrypt = 0)
    {
        // 块链
        $chainBlock = $this->u8ToU32($this->hexIv);
        $result = [];

        for ($i = 0; $i < $numOfBlocks; $i++) {
            // 本轮偏移量
            $roundIndex = $i * self::SM4_BLOCK_SIZE;
            // 本轮加密块
            $block = $this->u8ToU32($padded, $roundIndex);

            $cipherBlock = $this->doCrypt($chainBlock, $block, $isDecrypt);
            // 链密置换
            $chainBlock = $isDecrypt ? $block : $cipherBlock;

            // 最终结果
            for ($k = 0; $k < self::SM4_BLOCK_SIZE; $k++) {
                $bits = (3 - $k) % 4 * 8;
                $bits = $bits < 0 ? $bits + 32 : $bits;
                $result[$roundIndex + $k] = $cipherBlock[intval($k / 4)] >> $bits & 0xFF;
            }
        }

        return $result;
    }

    private function ecbMode($padded, $numOfBlocks, $isDecrypt = 0)
    {
        $result = [];
        for ($i = 0; $i < $numOfBlocks; $i++) {
            $roundIndex = $i * self::SM4_BLOCK_SIZE;
            $block = $this->u8ToU32($padded, $roundIndex);
            $cipherBlock = $this->cryptAlgrithm($block, $isDecrypt);
            for ($k = 0; $k < self::SM4_BLOCK_SIZE; $k++) {
                $bits = (3 - $k) % 4 * 8;
                $bits = $bits < 0 ? $bits + 32 : $bits;
                $result[$roundIndex + $k] = $cipherBlock[intval($k / 4)] >> $bits & 0xFF;
            }
        }
        return $result;
    }

    private function cryptAlgrithm($chainBlock, $isDecrypt)
    {
        // 异或运算块数组
        $xOrBlock = array_pad($chainBlock, 36, 0);
        // 32轮加密
        for ($i = 0; $i < 32; $i++) {
            $xOrBlock[$i + 4] = $this->roundFunction($xOrBlock, $i, 1, $isDecrypt);
        }

        // 取最后4位逆转数组作为最终加密块的值
        return array_reverse(array_slice($xOrBlock, -4));
    }
}
