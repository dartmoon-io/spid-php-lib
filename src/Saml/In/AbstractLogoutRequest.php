<?php

namespace Italia\Spid\Saml\In;

use Italia\Spid\Saml\Contracts\ResponseInterface;
use Italia\Spid\Saml\Contracts\SpInterface;

abstract class AbstractLogoutRequest implements ResponseInterface
{
    protected $sp;

    public function __construct(SpInterface $sp)
    {
        $this->sp = $sp;
    }

    abstract public function validate($xml, $hasAssertion) : bool;
}
