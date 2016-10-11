<?php

namespace ride\library\security\model\generic\io;

/**
 * Interface for a data source for a security model
 */
interface SecurityModelIO {

    /**
     * Pings the data source to see if it can be used
     * @return boolean
     */
    public function ping();

    /**
     * Writes the users to the data source
     * @param array $users
     * @return null
     */
    public function setUsers(array $users);

    /**
     * Reads the users from the data source
     * @return array
     */
    public function getUsers();

    /**
     * Writes the roles to the data source
     * @param array $roles
     * @return null
     */
    public function setRoles(array $roles);

    /**
     * Reads the roles from the data source
     * @return array
     */
    public function getRoles();

    /**
     * Writes the permissions to the data source
     * @param array $permissions
     * @return null
     */
    public function setPermissions(array $permissions);

    /**
     * Reads the permissions from the data source
     * @return array
     */
    public function getPermissions();

    /**
     * Writes the globally secured paths to the data source
     * @param array $paths
     * @return null
     */
    public function setSecuredPaths(array $paths);

    /**
     * Reads the globally secured paths from the data source
     * @return array
     */
    public function getSecuredPaths();

}
