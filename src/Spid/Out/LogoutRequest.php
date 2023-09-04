<?php

namespace Italia\Spid\Spid\Out;

use Italia\Spid\Saml\Out\AbstractLogoutRequest;

class LogoutRequest extends AbstractLogoutRequest
{
    public function generateXml($location)
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->sp->settings['sp_entityid'];
        $idpEntityId = $this->idp->metadata['idpEntityId'];
        $index = $this->idp->session->sessionID;
        $xml = <<<XML
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
ID="$id" IssueInstant="$issueInstant" Version="2.0" Destination="$idpEntityId">
    <saml:Issuer
        NameQualifier="$entityId"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</saml:Issuer>
    <saml:NameID
        NameQualifier="$idpEntityId"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">$idpEntityId</saml:NameID>
    <samlp:SessionIndex>$index</samlp:SessionIndex>
</samlp:LogoutRequest>
XML;
        $this->xml = $xml;
    }
}
