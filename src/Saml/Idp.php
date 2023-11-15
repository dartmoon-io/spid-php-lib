<?php

namespace Italia\Spid\Saml;

use Italia\Spid\Saml\Contracts\IdpInterface;

class Idp implements IdpInterface
{
    public $idpFileName;
    public $metadata;
    public $assertID;
    public $attrID;
    public $level = 1;
    public $session;

    protected $metadataFolder;

    public function __construct($metadataFolder)
    {
        $this->metadataFolder = $metadataFolder;
    }

    public function loadFromXml($name)
    {
        $fileName = $this->metadataFolder . $name . ".xml";
        if (!file_exists($fileName)) {
            throw new \Exception("Metadata file $fileName not found", 1);
        }
        if (!is_readable($fileName)) {
            throw new \Exception("Metadata file $fileName is not readable. Please check file permissions.", 1);
        }
        $xml = simplexml_load_file($fileName);

        $xml->registerXPathNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xml->registerXPathNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $metadata = [];
        $idpSSO = [];
        foreach ($xml->xpath('//md:SingleSignOnService') as $index => $item) {
            $idpSSO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSSO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $idpSLO = [];
        foreach ($xml->xpath('//md:SingleLogoutService') as $index => $item) {
            $idpSLO[$index]['location'] = $item->attributes()->Location->__toString();
            $idpSLO[$index]['binding'] = $item->attributes()->Binding->__toString();
        }

        $metadata['idpEntityId'] = $xml->attributes()->entityID->__toString();
        $metadata['idpSSO'] = $idpSSO;
        $metadata['idpSLO'] = $idpSLO;
        $metadata['idpCertValue'] = $this->formatCert($xml->xpath('//md:KeyDescriptor[@use=\'signing\']//ds:X509Certificate')[0]->__toString());

        $this->idpFileName = $name;
        $this->metadata = $metadata;
        return $this;
    }

    protected function formatCert($cert, $heads = true)
    {
        //$cert = str_replace(" ", "\n", $cert);
        $x509cert = str_replace(array("\x0D", "\r", "\n"), "", $cert);
        if (!empty($x509cert)) {
            $x509cert = str_replace('-----BEGIN CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace('-----END CERTIFICATE-----', "", $x509cert);
            $x509cert = str_replace(' ', '', $x509cert);

            if ($heads) {
                $x509cert = "-----BEGIN CERTIFICATE-----\n" .
                    chunk_split($x509cert, 64, "\n") .
                    "-----END CERTIFICATE-----\n";
            }
        }
        return $x509cert;
    }
}
