# 国密SM4对称加密算法

- PHP后端：```composer require evit/php-gm-crypto```
- 对应前端：```npm install evit-gm-crypt```

# php-gm-crypto

[![PHP Style Guide](https://img.shields.io/badge/Language-PHP-brightgreen.svg)](https://www.php-fig.org/psr/)[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 

基于`PHP`的国密加密算法实现。

Implement of Chinese encrypt algorithm in PHP.

完全兼容openssl的sm4-cbc和sm4-ecb国密SM算法，openssl >= 1.1.1支持国密算法时直接调用openssl进行SM4加解密，否则调用自定义算法。

Fully compatible with the sm4-cbc and sm4-ecb state secret SM algorithms of openssl. When openssl >= 1.1.1 supports the state secret algorithm, directly call openssl for SM4 encryption and decryption, otherwise call the custom algorithm.

新增SM3实现，openssl >= 1.1.1支持国密算法时直接调用openssl进行SM3杂凑，否则调用自定义算法。

与[`openssl_encrypt`](https://www.php.net/manual/en/function.openssl-encrypt.php)和[`openssl_decrypt`](https://www.php.net/manual/en/function.openssl-decrypt.php)保持一致性，当密码长度小于16时，静默填充NUL；当密码长度大于16时，静默截断。

Consistent with openssl_encrypt and openssl_decrypt, `NUL` is silently filled when the password length is less than 16; When the password length is greater than 16, it is truncated silently.

要使用openssl国密算法，openssl库需 >= 1.1.1。

To use openssl state secret algorithm, openssl library needs > = 1.1.1.

## Roadmap

- [x] SM4
- [x] SM3
- [ ] SM2

## Documentation

### Install

```bash
composer require evit/php-gm-crypto
```

### SM4

#### Init

```php
<?php
// If you are using a framework that does not support psr-4 autoloader, you need to explicitly import package from the vendor directory.
require_once __DIR__ . "/vendor/autoload.php";

use Evit\PhpGmCrypto\Encryption\EvitSM4Encryption;

$config = [
    // mode string 'cbc' or 'ecb' is supported, default is 'cbc'.
    'mode'  => 'cbc',
    // password, will be processed by substr(md5($key), 0, 16) if $config['hash']
    'key'   => '{replace-your-key-here}',
    // the iv used by 'cbc' mode, will be will be processed by substr(md5($iv), 0, 16) if $config['hash']
    'iv'    => '{replace-your-iv-here}',
    // weather do md5 to key and iv or not
    'hash'  => false
];

$sm4 = new EvitSM4Encryption($config);
```

#### Encrypt

```php
// Encrypt
$start = microtime(true);
$encypted = $sm4->sm4encrypt('{replace-your-plaintext-here}');
$end = microtime(true);
var_dump('Encrypt time elapsed:' . number_format($end - $start, 8) . ' s');
var_dump("Cipher text:{$encypted}");
```

#### Decrypt

```php
// Decrypt
$decStart = microtime(true);
$decrypted = $sm4->sm4decrypt($encypted);
$end = microtime(true);
var_dump('Decrypt time elapsed:' . number_format($end - $decStart, 8) . ' s');
var_dump("Plain text:{$decrypted}");
```

#### Algorithm
```php
// Determine whether openssl library is used
$algorithm = $sm4->isOpenssl() ? 'openssl' : 'php-gm-crypto';
var_dump("Algrithm is:{$algorithm}");
var_dump('Total time elapsed:' . number_format($end - $start, 8) . ' s');
```

### SM3

``` php
// If you are using a framework that does not support psr-4 autoloader, you need to explicitly import package from the vendor directory.
require_once __DIR__ . "/vendor/autoload.php";

use Evit\PhpGmCrypto\Encryption\EvitSM3Encryption;

$sm3 = new EvitSM3Encryption();
$input = 'abc';

$output = $sm3->sm3($input);
var_dump("SM3 hash result of '{$input}' is '{$output}'");
```

# 对应的前端安装

```
npm install evit-gm-crypt
```

传送门：[evit-gm-crypt](https://github.com/Endy-c/gm-crypt)

## License

[MIT](LICENSE)
