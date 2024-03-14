<?php

namespace App\Service;

class Aes
{
    public static $cipher = 'aes-256-cbc';

    /**
     * Generate a random string of specified length.
     *
     * @param int $length Length of the string to generate.
     * @return string The generated random string.
     * @throws \Exception
     */
    public static function generateRandomStr($length = 16)
    {
        $string = '';
        while (($len = strlen($string)) < $length) {
            $size = $length - $len;
            $bytes = random_bytes($size);
            $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
        }
        return $string;
    }

    /**
     * Encrypt the given plaintext.
     *
     * @param string $plaintext The plaintext to encrypt.
     * @param string|null $key The encryption key.
     * @return array An array containing the key, encrypted data, and IV.
     * @throws \Exception
     */
    public static function encrypt($plaintext, $key = null)
    {
        if ($key === null) {
            $key = self::generateRandomStr(32);
        }

        // Generate a random IV for each encryption
        $iv = random_bytes(openssl_cipher_iv_length(self::$cipher));
        $encryptedBase64 = base64_encode(openssl_encrypt($plaintext, self::$cipher, $key, OPENSSL_RAW_DATA, $iv));

        // Return the key, encrypted data, and IV in base64 format
        return [
            'key' => $key,
            'data' => $encryptedBase64,
            'iv' => base64_encode($iv) // Include IV for decryption
        ];
    }

    /**
     * Decrypt the given encrypted text.
     *
     * @param string $encryptedTextBase64 The encrypted text in base64 format.
     * @param string $key The encryption key.
     * @param string $ivBase64 The base64-encoded IV used for encryption.
     * @return false|string The decrypted text, or false on failure.
     */
    public static function decrypt($encryptedTextBase64, $key, $ivBase64)
    {
        $encryptedData = base64_decode($encryptedTextBase64);
        $iv = base64_decode($ivBase64); // Decode the IV from base64

        return openssl_decrypt($encryptedData, self::$cipher, $key, OPENSSL_RAW_DATA, $iv);
    }
}
