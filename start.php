<?php

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/app/service/Curl.php';
require_once __DIR__ . '/app/service/Rsa.php';
require_once __DIR__ . '/app/service/Aes.php';

use App\Service\Curl;
use App\Service\Rsa;
use App\Service\Aes;
use Workerman\Worker;
use Workerman\Protocols\Http\Response;

// 创建一个HTTP服务器
$http_worker = new Worker("http://0.0.0.0:19880");

// 同时处理的进程数
$http_worker->count = 4;

define("ROOT", __DIR__);

// 加载密钥
$privateKey = Rsa::loadKey('rsa', 'private');

$http_worker->onMessage = function ($connection, $request) use ($privateKey) {
    $method = $request->method();
    $uri = $request->uri();
    $body = $request->rawBody();
    $headers = $request->header();

    // 初始化Curl实例
    $curl = new Curl();

    foreach ($headers as $header => $value) {
        $curl->setHeader($header, $value);
    }

    try {
        $response = null;
        $aesdecryData = null;
        $sign = null;

        if (in_array($method, ['POST', 'PUT'])) {
            // 使用RSA解密header中的api-sign
            if (isset($headers['api-sign'])) {
                $sign = Rsa::decryptData($headers['api-sign'], $privateKey);
            }

            $jsonOb = json_decode($body, true);

            // 解密过程需要检查是否存在必要的数据
            if (isset($jsonOb['key']) && isset($jsonOb['data'])) {
                // 使用RSA解密AES密钥
                $decryptedKey = Rsa::decryptData($jsonOb['key'], $privateKey);
                // 使用AES解密数据
                $signHeader=json_decode($sign, true);
                $iv = $signHeader['iv']; // 假设IV通过header传递
                $aesdecryData = Aes::decrypt($jsonOb['data'], $decryptedKey, $iv);

                // 构造请求数据
                $curl->setRawPostData($aesdecryData);
            }
        }

        // 根据需要执行Curl请求，这里省略实际的Curl请求发送逻辑
        // $response = ...

        // 示例响应，展示请求的加密解密信息
        $connection->send(new Response(200, [], json_encode([
            'method' => $method,
            'uri' => $uri,
            'headers' => $headers,
            'sign' => $signHeader,
            'data' => json_decode($aesdecryData, true),
        ])));

    } catch (\Exception $e) {
        $connection->send(new Response(500, [], "Server Error: " . $e->getMessage()));
    }
};

Worker::runAll();
