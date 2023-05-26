<?php

/**
 * Define test.php
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

require_once __DIR__ . "/../../../../vendor/autoload.php";

use Evit\PhpGmCrypto\Encryption\SM4Encryption;

$config = [
    // mode string 'cbc' or 'ecb' is supported, default is 'cbc'.
    'mode'  => 'cbc',
    // password, will be processed by substr(md5($key), 0, 16)
    'key'   => '{replace-your-key-here}',
    // the iv used by 'cbc' mode, will be will be processed by substr(md5($iv), 0, 16)
    'iv'    => '{replace-your-iv-here}'
];

$sm4 = new SM4Encryption();

// Encrypt
$start = microtime(true);
$encypted = $sm4->sm4encrypt('{replace-your-plaintext-here}');
$end = microtime(true);
var_dump('Encrypt time elapsed: ' . number_format($end - $start, 8) . ' s');
var_dump("Cipher text: {$encypted}");

// Decrypt
$decStart = microtime(true);
$decrypted = $sm4->sm4decrypt($encypted);
$end = microtime(true);
var_dump('Decrypt time elapsed: ' . number_format($end - $decStart, 8) . ' s');
var_dump("Plain text: {$decrypted}");

// Determine whether openssl library is used
$algorithm = $sm4->isOpenssl() ? 'openssl' : 'php-gm-crypto';
var_dump("Algrithm: {$algorithm}");
var_dump('Total time elapsed: ' . number_format($end - $start, 8) . ' s');
