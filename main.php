<?php

namespace Crypter;

class Crypter {
    private $key;

    private $cipher;
    public $ivLen;

    public function __construct () 
    {
        $config = json_decode(file_get_contents(__DIR__.'/config.json'));
        $this->key = $this->getKey($config->key);

        $this->cipher = 'AES-128-CBC';
        $this->ivLen  = openssl_cipher_iv_length($this->cipher);
    }

    public function encrypt ($_plainText, $key = '') : string
    {
        if ($key == '') {
            $key = $this->key;
        }

        $iv            = openssl_random_pseudo_bytes($this->ivLen);
        $cipherTextRaw = openssl_encrypt($_plainText, $this->cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        $hmac          = hash_hmac('sha256', $cipherTextRaw, $key, $asBinary=true);
        $cipherText    = base64_encode( $iv.$hmac.$cipherTextRaw );

        return $cipherText;
    }

    public function decrypt ($_cipherText, $key = '') : string
    {        
        if ($key == '') {
            $key = $this->key;
        }

        $c                 = base64_decode($_cipherText);
        $iv                = substr($c, 0, $this->ivLen);
        $hmac              = substr($c, $this->ivLen, $sha2len=32);
        $cipherTextRaw     = substr($c, $this->ivLen+$sha2len);
        $originalPlainText = openssl_decrypt($cipherTextRaw, $this->cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        $calcMac           = hash_hmac('sha256', $cipherTextRaw, $key, $asBinary=true);

        return hash_equals($hmac, $calcMac) ? $originalPlainText : '';
    }

    public function createKey ($_len) : string 
    {
        $secret = '';
        $rnd = openssl_random_pseudo_bytes($_len, $cryptoStrong);
        
        if ($rnd !== false) {
            $secret = base64_encode($rnd);
        }

        $config = json_decode(file_get_contents(__DIR__.'/config.json'));
        $config->last_key = $config->key;
        $config->key = substr($secret, 0, strlen($secret) - 2);

        file_put_contents(__DIR__.'/config.json', json_encode($config, JSON_PRETTY_PRINT));

        $this->key = $rnd;
        
        return $secret;
    }

    public function getKey (string $secret) : string 
    {    
        $secret .= '==';
        $key = base64_decode($secret);        
        return $key;
    }
}

?>
