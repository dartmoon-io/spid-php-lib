<?php

namespace Italia\Spid\Saml\In;

use Italia\Spid\Saml\Contracts\ResponseInterface;

abstract class AbstractLogoutResponse implements ResponseInterface
{
    abstract public function validate($xml, $hasAssertion) : bool;
}
