<?php

namespace App\Service;

class Rsa
{
    /**
     * Load a RSA key from file.
     *
     * @param string $name Name of the key file without extension.
     * @param string $type Type of the key: 'private' or 'public'.
     * @return string The key content.
     * @throws \Exception If the key file cannot be read.
     */
    public static function loadKey($name, $type)
    {
        $dir = ROOT . '/key/';
        $file = $dir . $name . ($type === 'private' ? '.key' : '.pem');

        if (!file_exists($file) || !is_readable($file)) {
            throw new \Exception("Unable to read the $type key: $name");
        }

        return file_get_contents($file);
    }

    /**
     * Encrypt data using a public key.
     *
     * @param string $plaintext The plain text to encrypt.
     * @param string $publicKey The public key.
     * @return string The encrypted data, base64 encoded.
     * @throws \Exception If encryption fails or the key is invalid.
     */
    public static function encryptData($plaintext, $publicKey)
    {
        $publicKeyResource = openssl_get_publickey($publicKey);
        if (!$publicKeyResource) {
            throw new \Exception('Invalid public key.');
        }

        if (!openssl_public_encrypt($plaintext, $encrypted, $publicKeyResource, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new \Exception('Public key encryption failed.');
        }

        return base64_encode($encrypted);
    }

    /**
     * Decrypt data using a private key.
     *
     * @param string $encryptedDataB64 The encrypted data, base64 encoded.
     * @param string $privateKey The private key.
     * @return string The decrypted plain text.
     * @throws \Exception If decryption fails or the key is invalid.
     */
    public static function decryptData($encryptedDataB64, $privateKey)
    {
        $privateKeyResource = openssl_get_privatekey($privateKey);
        if (!$privateKeyResource) {
            throw new \Exception('Invalid private key.');
        }

        if (!openssl_private_decrypt(base64_decode($encryptedDataB64), $plaintext, $privateKeyResource, OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new \Exception('Private key decryption failed.');
        }

        return $plaintext;
    }
}
