<?php

namespace App;

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
use ParagonIE\ConstantTime\Hex;

class HandShake
{
    public function __construct()
    {
        ResponseRegister::addTLObjRes(TL_Res_resPQ::class);
    }

    public function handle()
    {
        // Req_1
        $nonce = random_bytes(16);
//        $nonce = hex2bin('c5d1e36e999628b7b1989de3126f24bc');
        $mcReqPqMulti = new MessageContainer(new TL_Req_reqPqMulti($nonce));
        $res = $this->sendRequest($mcReqPqMulti);

        // Res_1
        $mcResPQ = MessageContainer::make($res);
        /**
         * @var TL_Res_resPQ $resPQ
         */
        $resPQ = $mcResPQ->getMessage();


        if ($resPQ->nonce != base64_encode($nonce))
            throw new \Exception('Invalid nonce');
        [$pBytes, $qBytes] = PQFactor::factorPQInt($resPQ->pq);

        $p = gmp_import($pBytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $q = gmp_import($qBytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
        $pq = gmp_import($resPQ->pq, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        if (gmp_cmp(gmp_mul($p, $q), $pq) !== 0) {
            throw new \Exception('p q Factor not match');
        }

        // Req_2
        $newNonce = random_bytes(32);
        $req = new TL_Req_reqPQInnerDataDC($resPQ->pq, gmp_intval($p), gmp_intval($q), $nonce, $resPQ->server_nonce, $newNonce, 10000);
        $outputData = new OutputSerializedData();
        $req->serialize($outputData);


        // encrypt inner data
        $pkAndFingerPrint = TelegramRSAPublicKey::findPK($resPQ->fingerprints);
        if (is_null($pkAndFingerPrint))
            throw new \Exception('fingerprints not found');
        $encryptedInnerData = TelegramRSAPublicKey::encrypt($pkAndFingerPrint, $outputData->data);

        // --------------
        $mcReqDHParam = new MessageContainer(new TL_Req_reqDHParams($nonce, $resPQ->server_nonce, (int)$p,(int) $q, $pkAndFingerPrint['fp'], $encryptedInnerData));
        $newRes = $this->sendRequest($mcReqDHParam);
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