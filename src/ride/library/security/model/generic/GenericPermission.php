<?php

namespace ride\library\security\model\generic;

use ride\library\security\model\Permission;

/**
 * Permission of the SecurityModel
 */
class GenericPermission implements Permission {

    /**
     * The code of this permission
     * @var string
     */
    protected $code;

    /**
     * The description of this permission
     * @var string
     */
    protected $description;

    /**
     * Constructs a new permission
     * @param string $code Code of the permission
     * @param string $description Description of the permission
     * @return null
     */
    public function __construct($code, $description = null) {
        if ($description === null) {
            $description = $code;
        }

        $this->setCode($code);
        $this->setDescription($description);
    }

    /**
     * Gets a string representation of this permission
     * @return string
     */
    public function __toString() {
        return $this->code;
    }

    /**
     * Sets the code of this permission
     * @param string $code
     * @return null
     */
    public function setCode($code) {
        $this->code = $code;
    }

    /**
     * Gets the code of this permission
     * @return string
     */
    public function getCode() {
        return $this->code;
    }

    /**
     * Sets the description of this permission
     * @param string $description
     * @return null
     */
    public function setDescription($description) {
        $this->description = $description;
    }

    /**
     * Gets the description of this permission
     * @return string
     */
    public function getDescription() {
        return $this->description;
    }

    /**
     * Creates a new permission by the state of the properties
     * @param array $properties
     * @return PermissionData
     * @see var_export
     */
    public static function __set_state($properties) {
        $permission = new self($properties['code']);

        foreach ($properties as $key => $value) {
            $permission->$key = $value;
        }

        return $permission;
    }

}