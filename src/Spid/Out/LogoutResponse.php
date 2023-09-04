<?php

namespace Italia\Spid\Spid\Out;

use Italia\Spid\Saml\Out\AbstractLogoutResponse;

class LogoutResponse extends AbstractLogoutResponse
{
    public function generateXml($location)
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $inResponseTo = $_SESSION['inResponseTo'];
        $spEntityId = $this->sp->settings['sp_entityid'];

        $xml = <<<XML
<samlp:LogoutResponse Destination="https://sp.example.com/slo"
    ID="$id" InResponseTo="$inResponseTo"
    IssueInstant="$issueInstant" Version="2.0" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" NameQualifier="something"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">$spEntityId</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>
XML;

        $this->xml = $xml;
    }
}
