<?php

namespace Italia\Spid\Saml;

use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

class SignatureUtils
{
    public static function signXml($xml, $settings) : string
    {
        if (!is_readable($settings['sp_key_file'])) {
            throw new \Exception('Your SP key file is not readable. Please check file permissions.');
        }
        if (!is_readable($settings['sp_cert_file'])) {
            throw new \Exception('Your SP certificate file is not readable. Please check file permissions.');
        }
        $key = file_get_contents($settings['sp_key_file']);
        $key = openssl_get_privatekey($key, "");
        $cert = file_get_contents($settings['sp_cert_file']);
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
    
        $objKey = new XMLSecurityKey('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', array('type' => 'private'));
        $objKey->loadKey($key, false);

        $rootNode = $dom->firstChild;
        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $objXMLSecDSig->addReferenceList(
            array($rootNode),
            'http://www.w3.org/2001/04/xmlenc#sha256',
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID', 'overwrite' => false)
        );
        $objXMLSecDSig->sign($objKey);
        $objXMLSecDSig->add509Cert($cert, true);

        $insertBefore = $rootNode->firstChild;
        $messageTypes = array('AuthnRequest', 'Response', 'LogoutRequest', 'LogoutResponse');
        if (in_array($rootNode->localName, $messageTypes)) {
            $issuerNodes = self::query($dom, '/' . $rootNode->tagName . '/saml:Issuer');
            if ($issuerNodes->length == 1) {
                $insertBefore = $issuerNodes->item(0)->nextSibling;
            }
        }
        $objXMLSecDSig->insertSignature($rootNode, $insertBefore);

        return $dom->saveXML();
    }

    public static function signUrl($samlRequest, $relayState, $signatureAlgo, $keyFile)
    {
        if (!is_readable($keyFile)) {
            throw new \Exception('Your SP key file is not readable. Please check file permissions.');
        }
        $key = file_get_contents($keyFile);
        $key = openssl_get_privatekey($key, "");

        $msg = http_build_query([
            'SAMLRequest' => $samlRequest,
            'RelayState' => $relayState,
            'SigAlg' => $signatureAlgo,
        ]);

        openssl_sign($msg, $signature, $key, "SHA256");
        return base64_encode($signature);
    }

    public static function validateXmlSignature($xml, $cert) : bool
    {
        if (is_null($xml)) {
            return true;
        }
        $dom = clone $xml->ownerDocument;

        $certFingerprint = self::cleanOpenSsl($cert, true);
        $signCertFingerprint = self::cleanOpenSsl(
            $dom->getElementsByTagName('X509Certificate')->item(0)->nodeValue,
            true
        );

        // Trim spaces
        $certFingerprint = str_replace(' ', '', $certFingerprint);
        $signCertFingerprint = str_replace(' ', '', $signCertFingerprint);

        if ($signCertFingerprint != $certFingerprint) {
            return false;
        }

        $objXMLSecDSig = new XMLSecurityDSig();
        $objXMLSecDSig->idKeys = array('ID');

        $objDSig = $objXMLSecDSig->locateSignature($dom);
        $objKey = $objXMLSecDSig->locateKey();

        $objXMLSecDSig->canonicalizeSignedInfo();

        try {
            $retVal = $objXMLSecDSig->validateReference();
        } catch (\Exception $e) {
            throw $e;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        
        $objKey->loadKey($cert, false, true);
        if ($objXMLSecDSig->verify($objKey) === 1) {
            return true;
        }
        return false;
    }

    public static function certDNEquals($cert, $settings)
    {
        $parsed = openssl_x509_parse($cert, false);
        $dn = $parsed['subject'];

        $newDN = [
            "organizationName" => $settings['sp_org_name'],
            "commonName" => $settings['sp_key_cert_values']['commonName'],
            "undefined" => $settings['sp_entityid'], // Undefined beacause this is the key returned by openssl_x509_parse
            "organizationIdentifier" => "PA:IT-" . $settings['sp_contact']['ipa_code'],
            "countryName" => $settings['sp_key_cert_values']['countryName'],
            "localityName" => $settings['sp_key_cert_values']['localityName'],
            "stateOrProvinceName" => $settings['sp_key_cert_values']['stateOrProvinceName'],
            "organizationalUnitName" => $settings['sp_org_display_name'],
            "emailAddress" => $settings['sp_key_cert_values']['emailAddress'],
        ];

        asort($dn);
        asort($newDN);

        if (array_values($dn) == array_values($newDN)) {
            return true;
        }
        return false;
    }

    public static function generateKeyCert($settings) : array
    {
        $numberofdays = 3652 * 2;
        $privkey = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ));
        $dn = array(
            "organizationName" => $settings['sp_org_name'],
            "commonName" => $settings['sp_key_cert_values']['commonName'],
            "uri" => $settings['sp_entityid'],
            "organizationIdentifier" => "PA:IT-" . $settings['sp_contact']['ipa_code'],
            "countryName" => $settings['sp_key_cert_values']['countryName'],
            "localityName" => $settings['sp_key_cert_values']['localityName'],
            "stateOrProvinceName" => $settings['sp_key_cert_values']['stateOrProvinceName'],
            "organizationalUnitName" => $settings['sp_org_display_name'],
            "emailAddress" => $settings['sp_key_cert_values']['emailAddress'],
        );
        $csr = openssl_csr_new($dn, $privkey, array('digest_alg' => 'sha256', 'config' => __DIR__ . '/../../openssl.cnf' ));
        // Try until the serial is a positive number
        $myserial = -1;
        while ($myserial < 0) {
            $myserial = (int) hexdec(bin2hex(openssl_random_pseudo_bytes(8)));
        }
        $configArgs = array(
            'digest_alg' => 'sha256',
            'config' => __DIR__ . '/../../openssl.cnf'
        );
        $sscert = openssl_csr_sign($csr, null, $privkey, $numberofdays, $configArgs, $myserial);
        openssl_x509_export($sscert, $publickey);
        openssl_pkey_export($privkey, $privatekey);
        return [
            'key' => $privatekey,
            'cert' => $publickey
        ];
    }

    protected static function query(\DOMDocument $dom, $query, \DOMElement $context = null)
    {
        $xpath = new \DOMXPath($dom);

        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $xpath->registerNamespace('xs', 'http://www.w3.org/2001/XMLSchema');
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');

        if (isset($context)) {
            $res = $xpath->query($query, $context);
        } else {
            $res = $xpath->query($query);
        }
        return $res;
    }

    public static function cleanOpenSsl($file, $isCert = false)
    {
        if ($isCert) {
            $k = $file;
        } else {
            if (!is_readable($file)) {
                throw new \Exception('File '.$file.' is not readable. Please check file permissions.');
            }
            $k = file_get_contents($file);
        }
        $ck = '';
        foreach (preg_split("/((\r?\n)|(\r\n?))/", $k) as $l) {
            if (strpos($l, '-----') === false) {
                $ck .= $l;
            }
        }
        return $ck;
    }
}
