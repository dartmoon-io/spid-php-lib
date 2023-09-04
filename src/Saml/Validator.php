<?php

namespace Italia\Spid\Saml;

class Validator
{
    const REQUIRED = 1;
    const NOT_REQUIRED = 0;

    public static function validateSettings(array $settings, array $settingsDefinition, array $validAttributeFields)
    {
        $missingSettings = [];
        $msg = 'Missing settings fields: ';
        array_walk($settingsDefinition, function ($v, $k) use (&$missingSettings, &$settings, $settingsDefinition) {
            $settingRequired = $settingsDefinition[$k];
            $childSettings = [];
            if (is_array($v) && isset($v[self::REQUIRED])) {
                $settingRequired = self::REQUIRED;
                $childSettings[$k] = $v[self::REQUIRED];
            }
            if ($settingRequired == self::REQUIRED && !array_key_exists($k, $settings)) {
                $missingSettings[$k] = 1;
            } else {
                foreach ($childSettings as $key => $value) {
                    if ($value == self::REQUIRED && !array_key_exists($key, $settings[$k])) {
                        $missingSettings[$key] = 1;
                    }
                }
            }
        });
        foreach ($missingSettings as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($missingSettings) > 0) {
            throw new \Exception($msg);
        }

        $invalidFields = array_diff_key($settings, $settingsDefinition);
        // Check for settings that have child values
        array_walk($settingsDefinition, function ($v, $k) use (&$invalidFields) {
            // Child values found, check if settings array is set for that key
            if (is_array($v) && isset($settings[$k])) {
                // $v has at most 2 keys, self::REQUIRED and self::NOT_REQUIRED
                // do array_dif_key for both sub arrays
                $invalidFields = array_merge($invalidFields, array_diff_key($settings[$k], reset($v)));
                $invalidFields = array_merge($invalidFields, array_diff_key($settings[$k], end($v)));
            }
        });
        $msg = 'Invalid settings fields: ';
        foreach ($invalidFields as $k => $v) {
            $msg .= $k . ', ';
        }
        if (count($invalidFields) > 0) {
            throw new \Exception($msg);
        }

        self::checkSettingsValues($settings, $validAttributeFields);
    }

    protected static function checkSettingsValues($settings, $validAttributeFields)
    {
        if (filter_var($settings['sp_entityid'], FILTER_VALIDATE_URL) === false) {
            throw new \InvalidArgumentException('Invalid SP Entity ID provided');
        }
        // Save entity id host url for other checks
        $host = parse_url($settings['sp_entityid'], PHP_URL_HOST);

        if (!is_readable($settings['idp_metadata_folder'])) {
            throw new \InvalidArgumentException('Idp metadata folder does not exist or is not readable.');
        }
        if (isset($settings['sp_attributeconsumingservice'])) {
            if (!is_array($settings['sp_attributeconsumingservice'])) {
                throw new \InvalidArgumentException('sp_attributeconsumingservice should be an array');
            }
            array_walk($settings['sp_attributeconsumingservice'], function ($acs) use ($validAttributeFields) {
                if (!is_array($acs)) {
                    throw new \InvalidArgumentException('sp_attributeconsumingservice elements should be an arrays');
                }
                if (count($acs) == 0) {
                    throw new \InvalidArgumentException(
                        'sp_attributeconsumingservice elements should contain at least one element'
                    );
                }
                array_walk($acs, function ($field) use ($validAttributeFields) {
                    if (!in_array($field, $validAttributeFields)) {
                        throw new \InvalidArgumentException('Invalid Attribute field '. $field .' requested');
                    }
                });
            });
        }

        if (!is_array($settings['sp_assertionconsumerservice'])) {
            throw new \InvalidArgumentException('sp_assertionconsumerservice should be an array');
        }
        if (count($settings['sp_assertionconsumerservice']) == 0) {
            throw new \InvalidArgumentException('sp_assertionconsumerservice should contain at least one element');
        }
        array_walk($settings['sp_assertionconsumerservice'], function ($acs) use ($host) {
            if (strpos($acs, $host) === false) {
                throw new \InvalidArgumentException(
                    'sp_assertionconsumerservice elements Location domain should be ' . $host . ', got ' .
                    parse_url($acs, PHP_URL_HOST) . ' instead'
                );
            }
        });

        if (!is_array($settings['sp_singlelogoutservice'])) {
            throw new \InvalidArgumentException('sp_singlelogoutservice should be an array');
        }
        if (count($settings['sp_singlelogoutservice']) == 0) {
            throw new \InvalidArgumentException('sp_singlelogoutservice should contain at least one element');
        }
        array_walk($settings['sp_singlelogoutservice'], function ($slo) use ($host) {
            if (!is_array($slo)) {
                throw new \InvalidArgumentException('sp_singlelogoutservice elements should be arrays');
            }
            if (count($slo) != 2) {
                throw new \InvalidArgumentException(
                    'sp_singlelogoutservice array elements should contain exactly 2 elements, in order SLO Location ' .
                    'and Binding'
                );
            }
            if (!is_string($slo[0]) || !is_string($slo[1])) {
                throw new \InvalidArgumentException(
                    'sp_singlelogoutservice array elements should contain 2 string values, in order SLO Location ' .
                    'and Binding'
                );
            }
            if (strcasecmp($slo[1], "POST") != 0 &&
                strcasecmp($slo[1], "REDIRECT") != 0 &&
                strcasecmp($slo[1], "") != 0) {
                throw new \InvalidArgumentException('sp_singlelogoutservice elements Binding value should be one of '.
                    '"POST", "REDIRECT", or "" (empty string, defaults to POST)');
            }
            if (strpos($slo[0], $host) === false) {
                throw new \InvalidArgumentException(
                    'sp_singlelogoutservice elements Location domain should be ' . $host .
                    ', got ' .  parse_url($slo[0], PHP_URL_HOST) . 'instead'
                );
            }
        });
        if (isset($settings['sp_key_cert_values'])) {
            if (!is_array($settings['sp_key_cert_values'])) {
                throw new \Exception('sp_key_cert_values should be an array');
            }
            if (count($settings['sp_key_cert_values']) != 5) {
                throw new \Exception(
                    'sp_key_cert_values should contain 5 values: countryName, stateOrProvinceName, localityName, ' .
                    'commonName, emailAddress'
                );
            }
            foreach ($settings['sp_key_cert_values'] as $key => $value) {
                if (!is_string($value)) {
                    throw new \Exception(
                        'sp_key_cert_values values should be strings. Valued provided for key ' . $key .
                        ' is not a string'
                    );
                }
            }
            if (strlen($settings['sp_key_cert_values']['countryName']) != 2) {
                throw new \Exception('sp_key_cert_values countryName should be a 2 characters country code');
            }
        }
        if (isset($settings['accepted_clock_skew_seconds'])) {
            if (!is_numeric($settings['accepted_clock_skew_seconds'])) {
                throw new \InvalidArgumentException('accepted_clock_skew_seconds should be a number');
            }
            if ($settings['accepted_clock_skew_seconds'] < 0) {
                throw new \InvalidArgumentException('accepted_clock_skew_seconds should be at least 0 seconds');
            }
            if ($settings['accepted_clock_skew_seconds'] > 300) {
                throw new \InvalidArgumentException('accepted_clock_skew_seconds should be at most 300 seconds');
            }
        }
        if (isset($settings['sp_comparison'])) {
            if (strcasecmp($settings['sp_comparison'], "exact") != 0 &&
                strcasecmp($settings['sp_comparison'], "minimum") != 0 &&
                strcasecmp($settings['sp_comparison'], "better") != 0 &&
                strcasecmp($settings['sp_comparison'], "maximum") != 0) {
                throw new \InvalidArgumentException('sp_comparison value should be one of:' .
                    '"exact", "minimum", "better" or "maximum"');
            }
        }
    }
}
