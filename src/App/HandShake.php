<?php

namespace App;

use App\Crypto\Crypt;
use App\Encryption\Resource\PublicKeyEntity\TestRsaPublicKeyEntity;
use App\Encryption\Resource\TelegramRSAPublicKey;
use App\Encryption\Tools\PQFactor;
use App\Messages\Request\Inner\TL_Req_reqPQInnerDataDC;
use App\Messages\Request\TL_Req_reqDHParams;
use App\Messages\Request\TL_Req_reqPqMulti;
use App\Messages\Response\TL_Res_resPQ;
use App\MTProto\InputSerializedData;
use App\MTProto\MessageContainer;
use App\MTProto\OutputSerializedData;
use App\MTProto\ResponseRegister;
use danog\MadelineProto\RSA;
use danog\MadelineProto\SecurityException;
use danog\MadelineProto\Tools;
use ParagonIE\ConstantTime\Hex;
use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;

class HandShake
{
    public function __construct()
    {
        ResponseRegister::addTLObjRes(TL_Res_resPQ::class);
    }

    public function handle()
    {
        // Req_1
        $nonce = Random::string(16);
//        $nonce = hex2bin('c5d1e36e999628b7b1989de3126f24bc');
        $mcReqPqMulti = new MessageContainer(new TL_Req_reqPqMulti($nonce));

        $res = $this->sendRequest($mcReqPqMulti);
        // Res_1
        $mcResPQ = MessageContainer::make($res);
        /**
         * @var TL_Res_resPQ $resPQ
         */
        $resPQ = $mcResPQ->getMessage();


        if ($resPQ->nonce != $nonce)
            throw new \Exception('Invalid nonce');
        $pq = unpack('q', strrev($resPQ->pq))[1];
        $resultFactorPQ = FactorPQ::factor($pq);
        $p = $resultFactorPQ['p'];
        $q = $resultFactorPQ['q'];

        if ($p * $q !== $pq)
            throw new \Exception('Invalid factor pq');
        $p_bytes = strrev(pack('V', $p));
        $q_bytes = strrev(pack('V', $q));

        // Req_2
        $newNonce = Random::string(32);
        $req = new TL_Req_reqPQInnerDataDC($resPQ->pq, $p_bytes, $q_bytes, $nonce, $resPQ->server_nonce, $newNonce, 2);
        $outputData = new OutputSerializedData();
        $req->serialize($outputData);
        $data_with_padding = $outputData->data . Random::string(192 - \strlen($outputData->data));
        $data_pad_reversed = strrev($data_with_padding);

        // -------------------------- find rsa key

        $fingersByByte = [];

        foreach ($resPQ->fingerprints as $item) {
            $fingersByByte[] = pack('P', $item);
        }
        $fps = $fingersByByte;

        $rsaKey = unserialize(base64_decode('czo0MjU6Ii0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUlCQ2dLQ0FRRUE2THN6QmNDMUxHenlyOTkyTnpFMGllWStCU2FPVzYyMkFhOUJkNFpITGwrVHVGUTRsbzRnCjVuS2FNQndLL0JJYjl4VWZnMFEyOS8ybWdJUjZacjlrck03SGp1SWNDekZ2RHRyK0wwR1FqYWU5SDBwUkIyT08KNjJjRUNzNUhLaFQ1RFo5OEszM3ZtV2lMb3djNjIxZFF1d0tXU1FLaldmNTBYWUZ3NDJoMjFQMktYVUd5cDJ5LworYUV5Wit1VmdMTFFiUkExZEVqU0RaMmlHUnkxMk1rNWdwWWMzOTdhWXA0Mzhmc0pvSElnSjJsZ012NWg3V1k5CnQ2Ti9ieVk5Tnc5cDIxT2czQW9YU0wycS8ySUoxV1JVaGViZ0FkR1ZNbFYxZmt1T1FvRXpSN0VkcHF0UUQ5Q3MKNStiZm8zTmhtY3l2azVmdEIwV2tKOXo2Yk5aN3l4clA4d0lEQVFBQgotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0tIjs='));
        $n = unserialize(base64_decode('TzoyNjoicGhwc2VjbGliM1xNYXRoXEJpZ0ludGVnZXIiOjE6e3M6MzE6IgBwaHBzZWNsaWIzXE1hdGhcQmlnSW50ZWdlcgBoZXgiO3M6NTE0OiIwMGU4YmIzMzA1YzBiNTJjNmNmMmFmZGY3NjM3MzEzNDg5ZTYzZTA1MjY4ZTViYWRiNjAxYWY0MTc3ODY0NzJlNWY5M2I4NTQzODk2OGUyMGU2NzI5YTMwMWMwYWZjMTIxYmY3MTUxZjgzNDQzNmY3ZmRhNjgwODQ3YTY2YmY2NGFjY2VjNzhlZTIxYzBiMzE2ZjBlZGFmZTJmNDE5MDhkYTdiZDFmNGE1MTA3NjM4ZWViNjcwNDBhY2U0NzJhMTRmOTBkOWY3YzJiN2RlZjk5Njg4YmEzMDczYWRiNTc1MGJiMDI5NjQ5MDJhMzU5ZmU3NDVkODE3MGUzNjg3NmQ0ZmQ4YTVkNDFiMmE3NmNiZmY5YTEzMjY3ZWI5NTgwYjJkMDZkMTAzNTc0NDhkMjBkOWRhMjE5MWNiNWQ4YzkzOTgyOTYxY2RmZGVkYTYyOWUzN2YxZmIwOWEwNzIyMDI3Njk2MDMyZmU2MWVkNjYzZGI3YTM3ZjZmMjYzZDM3MGY2OWRiNTNhMGRjMGExNzQ4YmRhYWZmNjIwOWQ1NjQ1NDg1ZTZlMDAxZDE5NTMyNTU3NTdlNGI4ZTQyODEzMzQ3YjExZGE2YWI1MDBmZDBhY2U3ZTZkZmEzNzM2MTk5Y2NhZjkzOTdlZDA3NDVhNDI3ZGNmYTZjZDY3YmNiMWFjZmYzIjt9'));
        $e = unserialize(base64_decode('TzoyNjoicGhwc2VjbGliM1xNYXRoXEJpZ0ludGVnZXIiOjE6e3M6MzE6IgBwaHBzZWNsaWIzXE1hdGhcQmlnSW50ZWdlcgBoZXgiO3M6NjoiMDEwMDAxIjt9'));
        $fp = unserialize(base64_decode('czo4OiKF/WTehR2d0CI7'));
        $rsa = \App\Encryption\RSA::load($rsaKey,$n,$e,$fp);
        $selectedRsa = null;
        foreach ([$rsa] as $curkey) {
            if (\in_array($curkey->fp, $fps, true)) {
                $selectedRsa = $curkey;
            }
        }
        /**
         * @var \App\Encryption\RSA $selectedRsa
         */
        if (is_null($selectedRsa))
            throw new \Exception('rsa fp not found');

        do {
            $temp_key = Random::string(32);
            $data_with_hash = $data_pad_reversed.hash('sha256', $temp_key.$data_with_padding, true);
            $aes_encrypted = Crypt::igeEncrypt($data_with_hash, $temp_key, str_repeat("\0", 32));
            $temp_key_xor = $temp_key ^ hash('sha256', $aes_encrypted, true);
            $key_aes_encrypted_bigint = new BigInteger($temp_key_xor.$aes_encrypted, 256);
        } while ($key_aes_encrypted_bigint->compare($selectedRsa->n) >= 0);
        $encrypted_data = $selectedRsa->encrypt($key_aes_encrypted_bigint);

        // --------------
        $mcReqDHParam = new MessageContainer(new TL_Req_reqDHParams($nonce, $resPQ->server_nonce, $p_bytes, $q_bytes, $selectedRsa->fp, $encrypted_data));
        $foo = [
            'tl' => $mcReqDHParam->serialize(),
            'nonce' => $nonce,
            'server_nonce' => $resPQ->server_nonce,
            'p_bytes' => $p_bytes,
            'q_bytes' => $q_bytes,
            'encrypted_data' => $encrypted_data,
        ];
//        dd(base64_encode(serialize($foo)));
        $newRes = $this->sendRequest($mcReqDHParam);
        dd($newRes);
        dd($mcReqDHParam->serialize(),strlen($mcReqDHParam->serialize()));
//        dump('dwdw', $mcReqDHParam);
        dd($newRes);
        dd($outputData, 'sdwdw', $pkAndFingerPrint);
        dd();
        dd((int)$q, $p);
        dd($resPQ->nonce);
        dd($reqPq);


//        TL_resPq::unserialize(Out)
        dd($res, strlen($res));
        dd($nonce, strlen($nonce));
    }

    private function sendRequest(MessageContainer $payload, string $dc = 'https://venus.web.telegram.org/apiw1'): string
    { // https://venus.web.telegram.org/apiw1
//        return self::send($payload);
        $ch = curl_init($dc);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload->serialize(),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/octet-stream',
                'Connection: keep-alive',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_TIMEOUT => 5
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            throw new \RuntimeException('HTTP send error: ' . curl_error($ch));
        }
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($code < 200 || $code >= 300) {
            dump($resp);
            throw new \RuntimeException("HTTP status $code from DC");
        }
        return $resp;
    }


    private static function send($content)
    {
        $ch = curl_init('https://venus.web.telegram.org/apiw1');
//        $ch = curl_init('https://149.154.167.40');
//        $ch = curl_init('149.154.167.40');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_PORT, 443);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $content);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 10000);
        //curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Referer: https://web.telegram.org/',
            'Accept: */*',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
            'Origin: https://web.telegram.org',
            'Connection: keep-alive'
        ));
        //curl_setopt($ch, CURLOPT_PROXY, '127.0.0.1:9666');
//curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxyauth);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $return = curl_exec($ch);
        $error = curl_getinfo($ch);
        if ($error['http_code'] == 200) {
            return $return;
        } else {
            die('error curl!' . $error['http_code']);
        }
    }
}