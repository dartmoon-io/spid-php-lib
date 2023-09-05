<?php

namespace Italia\Spid\Saml;

use Italia\Spid\Saml\Idp;
use Italia\Spid\Saml\SignatureUtils;
use Italia\Spid\Saml\Contracts\SpInterface;
use Italia\Spid\Saml\In\ResponseWrapper;
use Italia\Spid\Saml\Session;

abstract class AbstractSp implements SpInterface
{
    public $settings;
    protected $idps = []; // contains filename -> Idp object array
    protected $session; // Session object

    // Settings definition
    protected $settingsDefinition = [];
    protected $validAttributeFields = [];

    // Response classes
    protected $requestClasses = [
        // 'AuthnRequest' => Out\AuthnRequest::class,
        // 'LogoutRequest' => Out\LogoutRequest::class,
        // 'LogoutResponse' => Out\LogoutResponse::class,
    ];

    // Request classes
    protected $responseClasses = [
        // 'AuthnResponse' => In\AuthnResponse::class,
        // 'LogoutRequest' => In\LogoutRequest::class,
        // 'LogoutResponse' => In\LogoutResponse::class,
    ];

    abstract public function getMetadata(): string;

    public function __construct(array $settings, $autoconfigure = true)
    {
        Validator::validateSettings($settings, $this->settingsDefinition, $this->validAttributeFields);
        $this->settings = $settings;

        // Let's start the session
        session_start();

        // Do not attemp autoconfiguration if key and cert values have not been set
        if (!array_key_exists('sp_key_cert_values', $this->settings)) {
            $autoconfigure = false;
        }
        if ($autoconfigure && !$this->isConfigured()) {
            $this->configure();
        }
    }

    public function getIdp(string $filename)
    {
        if (empty($filename)) {
            return null;
        }
        if (array_key_exists($filename, $this->idps)) {
            return $this->idps[$filename];
        }
        $idp = new Idp($this->settings['idp_metadata_folder']);
        $this->idps[$filename] = $idp->loadFromXml($filename);
        return $idp;
    }

    public function getIdpList() : array
    {
        $files = glob($this->settings['idp_metadata_folder'] . "*.xml");
        if (is_array($files)) {
            $mapping = [];
            foreach ($files as $filename) {
                $idp = $this->getIdp($filename);
                $mapping[basename($filename, ".xml")] = $idp->metadata['idpEntityId'];
            }

            return $mapping;
        }

        return [];
    }

    public function login(string $idpName, int $assertId, int $attrId, $level = 1, string $redirectTo = null, $shouldRedirect = true, $isPost = false)
    {
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

        $idp = $this->getIdp($idpName);
        $authn = new $this->requestClasses['AuthnRequest']($this, $idp, $assertId, $attrId, $level);
        $url = $isPost ? $authn->httpPost($redirectTo) : $authn->redirectUrl($redirectTo); 

        // Setup the session
        $_SESSION['RequestID'] = $authn->id;
        $_SESSION['idpName'] = $idp->idpFileName;
        $_SESSION['idpEntityId'] = $idp->metadata['idpEntityId'];
        $_SESSION['acsUrl'] = $this->settings['sp_assertionconsumerservice'][$assertId];

        if (!$shouldRedirect || $isPost) {
            return $url;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    public function isAuthenticated() : bool
    {
        $selectedIdp = $_SESSION['idpName'] ?? $_SESSION['spidSession']['idp'] ?? null;
        if (is_null($selectedIdp)) {
            return false;
        }

        $idp = $this->getIdp($selectedIdp);
        $response = $this->getResponse();
        if (!empty($idp) && !$response->validate($idp->metadata['idpCertValue'])) {
            return false;
        }

        if (isset($_SESSION) && isset($_SESSION['inResponseTo'])) {
            $this->sendLogoutResponse($idp);
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

    public function logout(int $slo, string $redirectTo = null, $shouldRedirect = true, $isPost = false)
    {
        if (!$this->isAuthenticated()) {
            return false;
        }

        $idp = $this->getIdp($this->session->idp);
        $logoutRequest = new $this->requestClasses['LogoutRequest']($this, $idp);
        $url = $isPost ? $logoutRequest->httpPost($redirectTo) : $logoutRequest->redirectUrl($redirectTo);

        // Setup the session
        $_SESSION['RequestID'] = $logoutRequest->id;
        $_SESSION['idpName'] = $idp->idpFileName;
        $_SESSION['idpEntityId'] = $idp->metadata['idpEntityId'];
        $_SESSION['sloUrl'] = reset($this->settings['sp_singlelogoutservice'][$slo]);

        if (!$shouldRedirect || $isPost) {
            return $url;
            exit;
        }

        header('Pragma: no-cache');
        header('Cache-Control: no-cache, must-revalidate');
        header('Location: ' . $url);
        exit("");
    }

    public function getAttributes() : array
    {
        if ($this->isAuthenticated() === false) {
            return [];
        }
        return isset($this->session->attributes) && is_array($this->session->attributes) 
            ? $this->session->attributes 
            : [];
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

    public function sendLogoutResponse(IDP $idp) : string
    {
        $redirectTo = $this->settings['sp_entityid'];

        $logoutResponse = new $this->responseClasses['LogoutResponse']($this, $idp);
        $url = $logoutResponse->httpPost($redirectTo);
        unset($_SESSION);

        return $url;
        exit;
    }

    protected function getResponse()
    {
        return new ResponseWrapper(
            $this,
            $this->responseClasses,
        );
    }
}
