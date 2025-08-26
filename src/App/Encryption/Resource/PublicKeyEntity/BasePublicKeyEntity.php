<?php

namespace App\Encryption\Resource\PublicKeyEntity;

abstract class BasePublicKeyEntity
{
    abstract static public function getFingerPrint(): string;

    abstract static public function getPublicKey(): string;
}