<?php

namespace App\MTProto;

use App\Messages\Response\TL_Res_resPQ;

class MessageContainer
{
    private static $counterMessageId = 0;


    /**
     * @param BaseTLObject|BaseTLResObject|BaseTLReqObject $message
     * @param string $authKeyId
     * @param $messageId
     */
    public function __construct(
        private BaseTLObject $message,
        private string $authKeyId = "\0\0\0\0\0\0\0\0",
        private $messageId = null
    )
    {
        $this->messageId = $messageId ?? $this->generateRandomMessageID();
    }

    public static function make(string $streamData): MessageContainer
    {
        $in = new InputSerializedData();
        $in->setData($streamData);
        $authKeyId = $in->read('long');
        $messageId = $in->read('long');
        $bodyLen = $in->read('int');
        $constructor = $in->read('#');
        $responseClass = ResponseRegister::getTLObj($constructor);
        $obj = $responseClass::unserialize($in);
        $self = new self($obj, $authKeyId, $messageId);
        return $self;
    }

    public function serialize(): string
    {
        // bind header
        $out = new OutputSerializedData();
        $out->writeInt64((int)$this->authKeyId);
        $out->writeInt64($this->messageId);

        // get body
        $body = $this->serializeBody();
        $bodyLen = strlen($body);

        // bind body to message
        $out->writeInt32($bodyLen);
        $out->writeRaw($body);

        return $out->data;
    }

    /**
     * @return BaseTLObject|BaseTLResObject|BaseTLReqObject
     */
    public function getMessage() : BaseTLObject
    {
        return $this->message;
    }

    private function serializeBody(): string
    {
        $body = new OutputSerializedData();
        $body->writeInt32($this->message::getConstructor());
        $this->message->serialize($body);
        return $body->data;
    }

    protected function generateRandomMessageID()
    {
        return (self::$counterMessageId++ * 4) + (time() << 32);
    }

}