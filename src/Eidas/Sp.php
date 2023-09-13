<?php

namespace Italia\Spid\Eidas;

use Italia\Spid\Saml\SignatureUtils;
use Italia\Spid\Saml\AbstractSp;
use Italia\Spid\Saml\Binding;
use Italia\Spid\Saml\Validator;

class Sp extends AbstractSp
{
    protected $settingsDefinition = [
        'sp_entityid' => Validator::REQUIRED,
        'sp_key_file' => Validator::REQUIRED,
        'sp_cert_file' => Validator::REQUIRED,
        'sp_comparison' => Validator::NOT_REQUIRED,
        'sp_assertionconsumerservice' => Validator::REQUIRED,
        'sp_singlelogoutservice' => Validator::REQUIRED,
        'sp_attributeconsumingservice' => Validator::NOT_REQUIRED,
        'sp_org_name' => Validator::NOT_REQUIRED,
        'sp_org_display_name' => Validator::NOT_REQUIRED,
        'sp_contact' => [
            Validator::REQUIRED => [
                'ipa_code' => Validator::REQUIRED,
                'fiscal_code' => Validator::NOT_REQUIRED,
                'email' => Validator::REQUIRED,
                'phone' => Validator::NOT_REQUIRED,
            ]
        ],
        'sp_key_cert_values' => [
            Validator::NOT_REQUIRED => [
                'countryName' => Validator::REQUIRED,
                'stateOrProvinceName' => Validator::REQUIRED,
                'localityName' => Validator::REQUIRED,
                'commonName' => Validator::REQUIRED,
                'emailAddress' => Validator::REQUIRED
            ]
        ],
        'idp_metadata_folder' => Validator::REQUIRED,
        'accepted_clock_skew_seconds' => Validator::NOT_REQUIRED
    ];

    protected $validAttributeFields = [
        "gender",
        "companyName",
        "registeredOffice",
        "fiscalNumber",
        "ivaCode",
        "idCard",
        "spidCode",
        "name",
        "familyName",
        "placeOfBirth",
        "countyOfBirth",
        "dateOfBirth",
        "mobilePhone",
        "email",
        "address",
        "expirationDate",
        "digitalAddress"
    ];

    // Response classes
    protected $requestClasses = [
        'AuthnRequest' => Out\AuthnRequest::class,
        'LogoutRequest' => Out\LogoutRequest::class,
        'LogoutResponse' => Out\LogoutResponse::class,
    ];

    // Request classes
    protected $responseClasses = [
        'AuthnResponse' => In\AuthnResponse::class,
        'LogoutRequest' => In\LogoutRequest::class,
        'LogoutResponse' => In\LogoutResponse::class,
    ];

    public function getMetadata(): string
    {
        if (!is_readable($this->settings['sp_cert_file'])) {
            return <<<XML
            <error>Your SP certificate file is not readable. Please check file permissions.</error>
XML;
        }
        
        $entityID = htmlspecialchars($this->settings['sp_entityid'], ENT_XML1);
        $id = preg_replace('/[^a-z0-9_-]/', '_', $entityID);
        $cert = SignatureUtils::cleanOpenSsl($this->settings['sp_cert_file']);

        $sloLocationArray = $this->settings['sp_singlelogoutservice'] ?? [];
        $assertcsArray = $this->settings['sp_assertionconsumerservice'] ?? [];
        $attrcsArray = $this->settings['sp_attributeconsumingservice'] ?? [];

        $xml = <<<XML
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="$entityID" ID="$id">
    <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        AuthnRequestsSigned="true" WantAssertionsSigned="true">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data><ds:X509Certificate>$cert</ds:X509Certificate></ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
XML;
        foreach ($sloLocationArray as $slo) {
            $location = htmlspecialchars($slo[0], ENT_XML1);
            $binding = $slo[1];
            if (strcasecmp($binding, "POST") === 0 || strcasecmp($binding, "") === 0) {
                $binding = Binding::BINDING_POST;
            } else {
                $binding = Binding::BINDING_REDIRECT;
            }
            $xml .= <<<XML

            <md:SingleLogoutService Binding="$binding" Location="$location"/>
XML;
        }
        $xml .= <<<XML
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
XML;
        for ($i = 0; $i < count($assertcsArray); $i++) {
            $location = htmlspecialchars($assertcsArray[$i], ENT_XML1);
            $xml .= <<<XML

        <md:AssertionConsumerService index="$i"
            isDefault="true"
            Location="$location" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
XML;
        }

        $xml .= <<<XML
        <md:AttributeConsumingService index="99">
            <md:ServiceName xml:lang="it">eIDAS Natural Person Minimum Attribute Set</md:ServiceName>       
XML;
        foreach ($attrcsArray[0] as $attr) {
            $xml .= <<<XML

        <md:RequestedAttribute Name="$attr"/>
XML;
        }
        $xml .= '</md:AttributeConsumingService>';
        $xml .= <<<XML
        <md:AttributeConsumingService index="100">
            <md:ServiceName xml:lang="it">eIDAS Natural Person Full Attribute Set</md:ServiceName>       
XML;
        foreach ($attrcsArray[1] as $attr) {
            $xml .= <<<XML

        <md:RequestedAttribute Name="$attr"/>
XML;
        }
        $xml .= '</md:AttributeConsumingService>';
        $xml .= '</md:SPSSODescriptor>';


        if (array_key_exists('sp_org_name', $this->settings)) {
            $orgName = $this->settings['sp_org_name'];
            $orgDisplayName = $this->settings['sp_org_display_name'];
            $xml .= <<<XML
<md:Organization>
    <md:OrganizationName xml:lang="it">$orgName</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="it">$orgDisplayName</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="it">$entityID</md:OrganizationURL>
</md:Organization>
XML;
        }

        $spContactIpaCode = $this->settings['sp_contact']['ipa_code'];
        $spContactEmail = $this->settings['sp_contact']['email'];

        $spContactPhone = $this->settings['sp_contact']['phone'] ?? false;
        $spContactFiscalCode = $this->settings['sp_contact']['fiscal_code'] ?? false;
        
        $xml .= <<<XML
<md:ContactPerson contactType="other">
    <md:Extensions>
        <spid:IPACode>$spContactIpaCode</spid:IPACode>
        <spid:Public/>
        <spid:FiscalCode>$spContactFiscalCode</spid:FiscalCode>
    </md:Extensions>
    <md:EmailAddress>$spContactEmail</md:EmailAddress>
    <md:TelephoneNumber>$spContactPhone</md:TelephoneNumber>
</md:ContactPerson>
XML;

        $xml .= '</md:EntityDescriptor>';

        return SignatureUtils::signXml($xml, $this->settings);
    }
}
