<?php

/**
 * A filter for limiting which attributes are passed on.
 *
 * @author Brook Schofield, GÉANT
 * @package simpleSAMLphp
 * @version $Id$
 */
class sspmod_core_Auth_Process_AttributeReleasePolicy extends SimpleSAML_Auth_ProcessingFilter {

	/**
	 * List of attributes which this filter will allow through.
	 */
	private $allowedAttributes = array();


	/**
	 * Whether the 'attributes' option in the metadata takes precedence.
	 *
	 * @var bool
	 */
	private $isDefault = FALSE;

	/**
	 * Whether to read 'filter' rules from Configuration File.
	 */
	private $filterConfig = FALSE;

	/**
	 * Initialize this filter.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use
	 */
	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		foreach($config as $index => $value) {
			if ($index === 'default') {
				$this->isDefault = (bool)$value;
			} elseif ($index === 'config') {
				$this->filterConfig = (bool)$value;
			} elseif (is_int($index)) {
				if(!is_string($value)) {
					throw new SimpleSAML_Error_Exception('AttributeReleasePolicy: Invalid attribute name: ' . var_export($value, TRUE));
				}
				$this->allowedAttributes[] = $value;
			} else {
				throw new SimpleSAML_Error_Exception('AttributeReleasePolicy: Invalid option: ' . var_export($index, TRUE));
			}
		}
	}

	/**
	 * Get the configuration from a file and process in relation to this SP/IdP interaction.
	 *
	 * @param array &$request  The current request.
	 * @return array|NULL  Array with attribute names, or NULL if no limit is placed.
	 */
	private static function getFilterAllowed(array &$request) {

		$attributes = array();
		$config = SimpleSAML_Configuration::getConfig('config-attributereleasepolicy.php');
		$filterConfig = $config->getArray('filters');
		$filterOptions = array('entityID','RegistrationAuthority','EntityCategory','attributes');

		ksort($filterConfig); // Enuser that the filter is ordered - otherwise we don't need a priority index
		foreach($filterConfig as $index => $filter) {

			// Check that the filter is an array
			if (!is_array($filter)) {
				SimpleSAML_Logger::warning("Malformed filter rule: #".$index." ignoring: ".json_encode($filter));
				continue;
			}

			// Lazy match on an non-empty array being returned
			if (array_diff(array_keys($filterConfig[$index]), $filterOptions)) {
				SimpleSAML_Logger::warning("Malformed filter rule: #".$index." ignoring: ".json_encode($filter));
				continue;
			}

			// Check the entityID rule of the filter.
			//  - there is always an entityID in $request['Destination']
			//  - skip rule if array test (entityID matches) XNOR (contains %not) 
			//    (i.e. same result, both true or both false).
			//  - or skip rule if string test doesn't match
			if (array_key_exists('entityID',$filter) && (
				(is_array($filter['entityID']) && 
					in_array($request['Destination']['entityID'], $filter['entityID'], TRUE) 
					=== in_array('%not', $filter['entityID'], TRUE))
				|| 
				(is_string($filter['entityID']) && 
					$request['Destination']['entityID'] !== $filter['entityID'])
			)) {
				continue;
			}

			// Check the RegistrationAuthority rule of the filter.
			//	- skip if no RegistrationAuthority exists in $request['Destination']
			//  - skip rule if array test (RegistrationAuthority matches) XNOR (contains %not)
			//    (i.e. same result, both true or both false).
			//  - or skip rule if string test doesn't match
			if	(array_key_exists('RegistrationAuthority',$filter) && (
					!array_key_exists('RegistrationAuthority',$request['Destination']) 
					||
					(
					is_array($filter['RegistrationAuthority']) && 
					in_array($request['Destination']['RegistrationAuthority'], $filter['RegistrationAuthority'], TRUE) 
					=== in_array('%not', $filter['RegistrationAuthority'], TRUE)
					)
					||
					(
					is_string($filter['RegistrationAuthority']) &&
						$request['Destination']['RegistrationAuthority'] !== $filter['RegistrationAuthority']
					)
			)) {
				continue;
			}

			// Check the EntityCategory rule of the filter.
			//	- skip if no EntityCategory exists in $request['Destination']
			if (array_key_exists('EntityCategory',$filter)) {
				if (array_key_exists('EntityAttributes',$request['Destination']) &&
				  is_array($request['Destination']['EntityAttributes']) &&
				  array_key_exists('http://macedir.org/entity-category',$request['Destination']['EntityAttributes'])
				) {
					// Cast to an array
					if (is_string($filter['EntityCategory'])) {
						$filter['EntityCategory'] = (array)$filter['EntityCategory'];
					}
					if (!is_array($filter['EntityCategory'])) {
						SimpleSAML_Logger::warning("Malformed filter rule: #".$index." ignoring: ".json_encode($filter));
						continue;
					}
					$unmatched = array_diff($filter['EntityCategory'],
							$request['Destination']['EntityAttributes']['http://macedir.org/entity-category']);
					if (!(count($unmatched) === 0 || 
						(in_array('%or', $unmatched, TRUE) && count($unmatched) < count($filter['EntityCategory'])))
					   ) {
						continue;
					}
				} else {
					continue;
				}
			} 

			// Matched Rule
			SimpleSAML_Logger::debug("Matched AttributeReleasePolicy filter rule: #".$index);

			// Compile attributes
			if (array_key_exists('attributes',$filter)) {
				if (is_string($filter['attributes'])) {
					$filter['attributes'] = (array)$filter['attributes'];
				}

				if (in_array('%all', $filter['attributes'], TRUE)) {
					return NULL;
				} elseif (in_array('%required', $filter['attributes'], TRUE)) {
					if (array_key_exists('attributes.required',$request['Destination'])) {
						foreach($request['Destination']['attributes.required'] as $attr => $value) {
							$attributes[] = $value;
						}
					}
				} elseif (in_array('%requested', $filter['attributes'], TRUE)) {
					if (array_key_exists('attributes',$request['Destination'])) {
						foreach($request['Destination']['attributes'] as $attr => $value) {
							$attributes[] = $value;
						}
					}
				} else {
					foreach($filter['attributes'] as $attr => $value) {
						$attributes[] = $value;
					}
				}
			}
		}

		if (empty($attributes)) {
			return NULL;
		}

		return $attributes;
	}

	/**
	 * Get list of allowed from the SP/IdP config.
	 *
	 * @param array &$request  The current request.
	 * @return array|NULL  Array with attribute names, or NULL if no limit is placed.
	 */
	private static function getSPIdPAllowed(array &$request) {

		if (array_key_exists('Attributes', $request['Destination'])) {
			/* SP Config. */
			return $request['Destination']['Attributes'];
		}
		if (array_key_exists('Attributes', $request['Source'])) {
			/* IdP Config. */
			return $request['Source']['Attributes'];
		}
		return NULL;
	}


	/**
	 * Apply filter to remove attributes.
	 *
	 * Removes all attributes which aren't one of the allowed attributes.
	 *
	 * @param array &$request  The current request
	 */
	public function process(&$request) {
		assert('is_array($request)');
		assert('array_key_exists("Attributes", $request)');

		if ($this->filterConfig) {
			$allowedAttributes = self::getFilterAllowed($request);
			if ($allowedAttributes === NULL) {
				return;
			}
		} elseif ($this->isDefault) {
			$allowedAttributes = self::getSPIdPAllowed($request);
			if ($allowedAttributes === NULL) {
				$allowedAttributes = $this->allowedAttributes;
			}
		} elseif (!empty($this->allowedAttributes)) {
			$allowedAttributes = $this->allowedAttributes;
		} else {
			$allowedAttributes = self::getSPIdPAllowed($request);
			if ($allowedAttributes === NULL) {
				return; /* No limit on attributes. */
			}
		}

		$attributes =& $request['Attributes'];

		foreach($attributes as $name => $values) {
			if(!in_array($name, $allowedAttributes, TRUE)) {
				unset($attributes[$name]);
			}
		}

	}

}

?>
