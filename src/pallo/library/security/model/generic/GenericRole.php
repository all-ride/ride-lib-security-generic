<?php

namespace pallo\library\security\model\generic;

use pallo\library\security\exception\SecurityException;
use pallo\library\security\model\Role;

/**
 * Role of the SecurityModel
 */
class GenericRole implements Role {

    /**
     * The id of the role
     * @var string
     */
    protected $id;

    /**
     * The name of the role
     * @var string
     */
    protected $name;

    /**
     * The allowed paths of the role
     * @var array
     */
    protected $paths;

    /**
     * The permissions of the role
     * @var array
     */
    protected $permissions;

    /**
     * Constructs a new role
     * @param integer $id
     * @param string $name
     * @return null
     */
    public function __construct() {
        $this->id = null;
        $this->name = null;
        $this->paths = array();
        $this->permissions = array();
    }

    /**
     * Gets a string representation of this role
     * @return string
     */
    public function __toString() {
        return $this->name;
    }

    /**
     * Sets the id of the role
     * @param string $id
     * @return null
     */
    public function setId($id) {
        if ($this->id !== null && $this->id != $id) {
            throw new SecurityException('Could not set the id of the role: already set');
        }

        $this->id = $id;
    }

    /**
     * Gets the id of this role
     * @return string
     */
    public function getId() {
        return $this->id;
    }

    /**
     * Sets the name of this role
     * @param string $name
     * @return null
     */
    public function setName($name) {
        $this->name = $name;
    }

    /**
     * Gets the name of this role
     * @return string
     */
    public function getName() {
        return $this->name;
    }

    /**
     * Sets the allowed paths to this role
     * @param array $paths
     * @return null
     */
    public function setPaths(array $paths) {
        $this->paths = $paths;
    }

    /**
     * Gets the allowed paths of this role
     * @return array Array with a path regular expression per element
     */
    public function getPaths() {
        return $this->paths;
    }

    /**
     * Sets the permissions of this role
     * @param array $permissions
     * @return null
     */
    public function setPermissions(array $permissions) {
        $this->permissions = $permissions;
    }

    /**
     * Gets the permissions of this role
     * @return array Array with Permission objects
     */
    public function getPermissions() {
        return $this->permissions;
    }

    /**
     * Check whether this role grants the provided permission
     * @param string $code the permission code to check
     * @return boolean true if the permission is granted, false if the
     * permission is denied
     */
    public function isPermissionGranted($code) {
        if (!$this->permissions) {
            return false;
        }

        foreach ($this->permissions as $permission) {
            if ($permission->getPermissionCode() == $code) {
                return true;
            }
        }

        return false;
    }

}