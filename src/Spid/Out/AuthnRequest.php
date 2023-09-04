<?php

namespace Italia\Spid\Spid\Out;

use Italia\Spid\Saml\Out\AbstractAuthnRequest;

class AuthnRequest extends AbstractAuthnRequest
{
    public function generateXml($destination)
    {
        $id = $this->generateID();
        $issueInstant = $this->generateIssueInstant();
        $entityId = $this->sp->settings['sp_entityid'];

        // $idpEntityId = $this->idp->metadata['idpEntityId'];
        $assertID = $this->idp->assertID;
        $attrID = $this->idp->attrID;
        $level = $this->idp->level;
        if (isset($this->sp->settings['sp_comparison'])) {
            $comparison = $this->sp->settings['sp_comparison'];
        } else {
            $comparison = "exact";
        }
        $force = ($level > 1 || $comparison == "minimum") ? "true" : "false";
        
        $authnRequestXml = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id" 
    Version="2.0"
    IssueInstant="$issueInstant"
    Destination="$destination"
    ForceAuthn="$force"
    AssertionConsumerServiceIndex="$assertID">
    <saml:Issuer
        NameQualifier="$entityId"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">$entityId</saml:Issuer>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" />
    <samlp:RequestedAuthnContext Comparison="$comparison">
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL$level</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
XML;

        $xml = new \SimpleXMLElement($authnRequestXml);

        if (!is_null($attrID)) {
            $xml->addAttribute('AttributeConsumingServiceIndex', $attrID);
        }
        $this->xml = $xml->asXML();
    }
}
