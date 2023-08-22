<?php

namespace Italia\Spid\Saml;

use Italia\Spid\Saml\Idp;
use Italia\Spid\Saml\In\BaseResponse;
use Italia\Spid\Saml\Settings;
use Italia\Spid\Saml\SignatureUtils;
use Italia\Spid\Contracts\Saml\SAMLInterface;
use Italia\Spid\Session;

abstract class AbstractSaml implements SAMLInterface
{
    public $settings;
    protected $idps = []; // contains filename -> Idp object array
    protected $session; // Session object

    abstract public function getSPMetadata(): string;

    public function __construct(array $settings, $autoconfigure = true)
    {
        Settings::validateSettings($settings);
        $this->settings = $settings;

        // Do not attemp autoconfiguration if key and cert values have not been set
        if (!array_key_exists('sp_key_cert_values', $this->settings)) {
            $autoconfigure = false;
        }
        if ($autoconfigure && !$this->isConfigured()) {
            $this->configure();
        }
    }

    public function loadIdpFromFile(string $filename)
    {
        if (empty($filename)) {
            return null;
        }
        if (array_key_exists($filename, $this->idps)) {
            return $this->idps[$filename];
        }
        $idp = new Idp($this);
        $this->idps[$filename] = $idp->loadFromXml($filename);
        return $idp;
    }

    public function getIdpList() : array
    {
        $files = glob($this->settings['idp_metadata_folder'] . "*.xml");

        if (is_array($files)) {
            $mapping = array();
            foreach ($files as $filename) {
                $idp = $this->loadIdpFromFile($filename);
                
                $mapping[basename($filename, ".xml")] = $idp->metadata['idpEntityId'];
            }
            return $mapping;
        }
        return array();
    }

    public function getIdp(string $filename)
    {
        return $this->loadIdpFromFile($filename);
    }

    public function login(
        string $idpName,
        int $assertId,
        int $attrId,
        $level = 1,
        string $redirectTo = null,
        $shouldRedirect = true
    ) {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_REDIRECT, ...$args);
    }

    public function loginPost(
        string $idpName,
        int $assertId,
        int $attrId,
        $level = 1,
        string $redirectTo = null,
        $shouldRedirect = true
    ) {
        $args = func_get_args();
        return $this->baseLogin(Settings::BINDING_POST, ...$args);
    }

    protected function baseLogin(
        $binding,
        $idpName,
        $assertId,
        $attrId,
        $level = 1,
        $redirectTo = null,
        $shouldRedirect = true
    ) {
        if ($this->isAuthenticated()) {
            return false;
        }
        if (!array_key_exists($assertId, $this->settings['sp_assertionconsumerservice'])) {
            throw new \Exception("Invalid Assertion Consumer Service ID");
        }
        if (isset($this->settings['sp_attributeconsumingservice'])) {
            if (!isset($this->settings['sp_attributeconsumingservice'][$attrId])) {
                throw new \Exception("Invalid Attribute Consuming Service ID");
            }
        } else {
            $attrId = null;
        }

        $idp = $this->loadIdpFromFile($idpName);
        return $idp->authnRequest($assertId, $attrId, $binding, $level, $redirectTo, $shouldRedirect);
    }

    public function isAuthenticated() : bool
    {
        $selectedIdp = $_SESSION['idpName'] ?? $_SESSION['spidSession']['idp'] ?? null;
        if (is_null($selectedIdp)) {
            return false;
        }
        $idp = $this->loadIdpFromFile($selectedIdp);
        $response = new BaseResponse($this);
        if (!empty($idp) && !$response->validate($idp->metadata['idpCertValue'])) {
            return false;
        }
        if (isset($_SESSION) && isset($_SESSION['inResponseTo'])) {
            $idp->logoutResponse();
            return false;
        }
        if (isset($_SESSION) && isset($_SESSION['spidSession'])) {
            $session = new Session($_SESSION['spidSession']);
            if ($session->isValid()) {
                $this->session = $session;
                return true;
            }
        }
        return false;
    }

    public function logout(int $slo, string $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_REDIRECT, ...$args);
    }

    public function logoutPost(int $slo, string $redirectTo = null, $shouldRedirect = true)
    {
        $args = func_get_args();
        return $this->baseLogout(Settings::BINDING_POST, ...$args);
    }

    protected function baseLogout($binding, $slo, $redirectTo = null, $shouldRedirect = true)
    {
        if (!$this->isAuthenticated()) {
            return false;
        }
        $idp = $this->loadIdpFromFile($this->session->idp);
        return $idp->logoutRequest($this->session, $slo, $binding, $redirectTo, $shouldRedirect);
    }

    public function getAttributes() : array
    {
        if ($this->isAuthenticated() === false) {
            return array();
        }
        return isset($this->session->attributes) && is_array($this->session->attributes) ? $this->session->attributes :
            array();
    }
    
    // returns true if the SP certificates are found where the settings says they are, and they are valid
    // (i.e. the library has been configured correctly
    protected function isConfigured() : bool
    {
        if (!is_readable($this->settings['sp_key_file'])) {
            return false;
        }
        if (!is_readable($this->settings['sp_cert_file'])) {
            return false;
        }
        $key = file_get_contents($this->settings['sp_key_file']);
        if (!openssl_get_privatekey($key)) {
            return false;
        }
        $cert = file_get_contents($this->settings['sp_cert_file']);
        if (!openssl_get_publickey($cert)) {
            return false;
        }
        if (!SignatureUtils::certDNEquals($cert, $this->settings)) {
            return false;
        }
        return true;
    }

    // Generates with openssl the SP certificates where the settings says they should be
    // this function should be used with care because it requires write access to the filesystem,
    // and invalidates the metadata
    protected function configure()
    {
        $keyCert = SignatureUtils::generateKeyCert($this->settings);
        $dir = dirname($this->settings['sp_key_file']);
        if (!is_dir($dir)) {
            throw new \InvalidArgumentException('The directory you selected for sp_key_file does not exist. ' .
                'Please create ' . $dir);
        }
        $dir = dirname($this->settings['sp_cert_file']);
        if (!is_dir($dir)) {
            throw new \InvalidArgumentException('The directory you selected for sp_cert_file does not exist.' .
                'Please create ' . $dir);
        }
        file_put_contents($this->settings['sp_key_file'], $keyCert['key']);
        file_put_contents($this->settings['sp_cert_file'], $keyCert['cert']);
    }
}
