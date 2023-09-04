<?php

namespace Italia\Spid\Saml\Contracts;

interface IdpInterface
{
    // Loads an IDP metadata from its XML file
    // $xmlFile: only the name of the file.
    // The path is provided during Sp initialization via settings with the field 'idp_metadata_folder'
    public function loadFromXml($xmlFile);
}
