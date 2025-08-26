<?php
require_once __DIR__ . '/../bin/entry_point.php';

//\Swoole\Coroutine\run(function () {

$handShake = new \App\HandShake();
$handShake->handle();

dd("end");

//$handShake = new \App\MTProtoHandshake();
//$result = $handShake->createAuthKey();
//dd($result,'end');
//});

//$gen = new \App\MTProtoAuthKeyGenerator();
//$gen->run();