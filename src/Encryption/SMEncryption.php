<?php

/**
 * Define SMEncryption.php
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

class SMEncryption extends EvitEncryption
{
    private $useOpenssl = false;
    private $key;
    private $hexIv;
    private $cryptor;
    private $mode = 'cbc';

    public function __construct($config = null)
    {
        $this->checkOpenssl();
        $this->key = $config['key'] ?? 'evit';
        $this->hexIv = $config['iv'] ?? 'evit';

        $mode = strtolower($config['mode'] ?? '');
        if (in_array($mode, ['cbc', 'ecb'])) {
            $this->mode = $mode;
        }

        list($this->hexIv, $this->key) = $this->getIvAndKey();
        if ($this->isOpenssl()) {
            return;
        }

        // 采用自实现加密算法
        $class = get_parent_class();
        $this->cryptor = new $class(['key' => $this->key, 'iv' => $this->hexIv, 'mode' => $mode]);
    }

    /**
     * [checkOpenssl 检查openssl库是否支持国密4]
     * @return
     */
    private function checkOpenssl()
    {
        $ciphers = openssl_get_cipher_methods();
        if (in_array('sm4-cbc', $ciphers)) {
            $this->useOpenssl = true;
        }
    }

    /**
     * [isOpenssl 获取openssl是否支持国密4状态]
     * @return boolean
     */
    public function isOpenssl()
    {
        return $this->useOpenssl;
    }

    /**
     * [sm4encrypt 国密4加密]
     * @param  string $input [明文]
     * @return string        [加密后密文]
     */
    public function sm4encrypt(string $input): string
    {
        // 使用openssl库进行国密4加密
        if ($this->isOpenssl()) {
            switch ($this->mode) {
                case 'cbc':
                default:
                    $encrypted = openssl_encrypt(
                        $input,
                        'sm4-cbc',
                        $this->key,
                        OPENSSL_RAW_DATA,
                        $this->hexIv
                    );
                    return (base64_encode($encrypted));
                case 'ecb':
                    $encrypted = openssl_encrypt(
                        $input,
                        'sm4-ecb',
                        $this->key,
                        OPENSSL_RAW_DATA
                    );
                    return (base64_encode($encrypted));
            }
        }
        // 自研库进行国密4加密
        $result = $this->cryptor->encrypt($input);
        return base64_encode($result);
    }

    /**
     * [getIvAndKey 将key和iv做md5散列后取16位，对应前端算法为md5(key).substr(0, 16)]
     * @return list         [iv, key]
     */
    private function getIvAndKey()
    {
        // 获取IV长度
        $ivLength = $this->isOpenssl() ? openssl_cipher_iv_length('sm4-cbc') : 16;
        // key长度固定为16
        $keyLength = 16;

        $hexIv = substr(
            md5($this->hexIv),
            0,
            $ivLength
        );

        $key = substr(
            md5($this->key),
            0,
            $keyLength
        );
        
        return [$hexIv, $key];
    }

    /**
     * [sm4decrypt 国密4解密]
     * @param  string $input [base64加密后的字符串]
     * @return string        [解密明文]
     */
    public function sm4decrypt(string $input): string
    {
        // 使用openssl库进行国密4解密
        if ($this->isOpenssl()) {
            switch ($this->mode) {
                case 'cbc':
                default:
                    $decrypted = openssl_decrypt(
                        base64_decode($input),
                        'sm4-cbc',
                        $this->key,
                        OPENSSL_RAW_DATA,
                        $this->hexIv
                    );
                    return $decrypted;
                case 'ecb':
                    $decrypted = openssl_decrypt(
                        base64_decode($input),
                        'sm4-ecb',
                        $this->key,
                        OPENSSL_RAW_DATA
                    );
                    return $decrypted;
            }
        }

        return $this->cryptor->decrypt(base64_decode($input));
    }
}
