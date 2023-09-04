<?php

namespace Italia\Spid\Saml\Out;

use Italia\Spid\Saml\Binding;
use Italia\Spid\Saml\SignatureUtils;

abstract class AbstractLogoutResponse extends AbstractRequest
{
    abstract public function generateXml($location);

    public function redirectUrl($redirectTo = null) : string
    {
        $location = parent::getBindingLocation(Binding::BINDING_REDIRECT, 'SLO');
        if (is_null($this->xml)) {
            $this->generateXml($location);
        }
        return parent::redirect($location, $redirectTo);
    }

    public function httpPost($redirectTo = null) : string
    {
        $location = parent::getBindingLocation(Binding::BINDING_POST, 'SLO');
        if (is_null($this->xml)) {
            $this->generateXml($location);
        }
        $this->xml = SignatureUtils::signXml($this->xml, $this->sp->settings);
        return parent::postForm($location, $redirectTo);
    }
}
