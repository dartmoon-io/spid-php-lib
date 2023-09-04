<?php

namespace Italia\Spid\Saml\In;

use Italia\Spid\Saml\Contracts\ResponseInterface;
use Italia\Spid\Saml\Session;
use Italia\Spid\Saml\Contracts\SpInterface;

abstract class AbstractAuthnResponse implements ResponseInterface
{
    protected $sp;

    public function __construct(SpInterface $sp)
    {
        $this->sp = $sp;
    }

    abstract public function validate($xml, $hasAssertion): bool;

    protected function validateDate($date)
    {
        if (preg_match('/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/', $date, $parts) == true) {
            $time = gmmktime($parts[4], $parts[5], $parts[6], $parts[2], $parts[3], $parts[1]);

            $input_time = strtotime($date);
            if ($input_time === false) {
                return false;
            }

            return $input_time == $time;
        } else {
            return false;
        }
    }

    protected function spidSession(\DOMDocument $xml)
    {
        $session = new Session();

        $attributes = [];
        $attributeStatements = $xml->getElementsByTagName('AttributeStatement');

        if ($attributeStatements->length > 0) {
            foreach ($attributeStatements->item(0)->childNodes as $attr) {
                if ($attr->hasAttributes()) {
                    $attributes[$attr->attributes->getNamedItem('Name')->value] = trim($attr->nodeValue);
                }
            }
        }

        $session->sessionID = $_SESSION['RequestID'];
        $session->idp = $_SESSION['idpName'];
        $session->idpEntityID = $xml->getElementsByTagName('Issuer')->item(0)->nodeValue;
        $session->attributes = $attributes;
        $session->level = substr($xml->getElementsByTagName('AuthnContextClassRef')->item(0)->nodeValue, -1);
        return $session;
    }
}
