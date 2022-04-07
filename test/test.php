<?php

require_once __DIR__ . "/../vendor/autoload.php";

use Evit\PhpGmCrypto\Encryption\SMEncryption;

$start = microtime(true);

$config = [
    // 模式，支持cbc,ecb
    'mode'  => 'cbc',
    // 密码，将做md5散列后使用
    'key'   => '{replace-your-key-here}',
    // 初始偏移量，将做md5散列后使用
    'iv'    => '{replace-your-iv-here}'
];
$sm4 = new SMEncryption();
$encypted = $sm4->sm4encrypt('{replace-your-plaintext-here}');
var_dump("Cipher text:{$encypted}");
$decrypted = $sm4->sm4decrypt($encypted);
var_dump("Plain text:{$decrypted}");

$end = microtime(true);

$algorithm = $sm4->isOpenssl() ? 'openssl' : 'php-gm-crypto';

var_dump("Algrithm is:{$algorithm}");
var_dump('Time elapsed:' . number_format($end - $start, 8) . ' s');
