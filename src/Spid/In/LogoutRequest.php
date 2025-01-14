<?php

namespace Italia\Spid\Spid\In;

use Italia\Spid\Saml\In\AbstractLogoutRequest;

class LogoutRequest extends AbstractLogoutRequest
{
    public function validate($xml, $hasAssertion) : bool
    {
        $root = $xml->getElementsByTagName('LogoutRequest')->item(0);

        if ($xml->getElementsByTagName('Issuer')->length == 0) {
            throw new \Exception("Invalid Response. Missing Issuer element");
        }
        if ($xml->getElementsByTagName('NameID')->length == 0) {
            throw new \Exception("Invalid Response. Missing NameID element");
        }
        if ($xml->getElementsByTagName('SessionIndex')->length == 0) {
            throw new \Exception("Invalid Response. Missing SessionIndex element");
        }

        $issuer = $xml->getElementsByTagName('Issuer')->item(0);
        $nameId = $xml->getElementsByTagName('NameID')->item(0);
        $sessionIndex = $xml->getElementsByTagName('SessionIndex')->item(0);

        if ($issuer->getAttribute('Destination') == "") {
            throw new \Exception("Missing Destination attribute");
        } elseif ($issuer->getAttribute('Destination') != $this->sp->settings['sp_entityid']) {
            throw new \Exception("Invalid ForDestinationmat attribute");
        }

        if ($issuer->getAttribute('Format') == "") {
            throw new \Exception("Missing Format attribute");
        } elseif ($issuer->getAttribute('Format') != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") {
            throw new \Exception("Invalid Format attribute");
        }
        if ($issuer->getAttribute('NameQualifier') == "") {
            throw new \Exception("Missing NameQualifier attribute");
        } elseif ($issuer->getAttribute('NameQualifier') != $_SESSION['spidSession']->idpEntityID) {
            throw new \Exception("Invalid NameQualifier attribute");
        }

        if ($nameId->getAttribute('Format') == "") {
            throw new \Exception("Missing NameID Format attribute");
        } elseif ($nameId->getAttribute('Format') != "“urn:oasis:names:tc:SAML:2.0:nameidformat:transient") {
            throw new \Exception("Invalid NameID Format attribute");
        }
        if ($nameId->getAttribute('NameQualifier') == "") {
            throw new \Exception("Missing NameID NameQualifier attribute");
        } elseif ($nameId->getAttribute('NameQualifier') != $_SESSION['spidSession']->idpEntityID) {
            throw new \Exception("Invalid NameID NameQualifier attribute");
        }
        
        if ($sessionIndex->nodeValue != $_SESSION['spidSession']->sessionID) {
            throw new \Exception("Invalid SessionID, expected " . $_SESSION['spidSession']->sessionID .
                " but received " . $sessionIndex->nodeValue);
        }
        $_SESSION['inResponseTo'] = $root->getAttribute('ID');
        return true;
    }
}
