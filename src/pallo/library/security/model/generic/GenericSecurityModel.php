<?php

namespace pallo\library\security\model\generic;

use pallo\library\encryption\hash\Hash;
use pallo\library\event\EventManager;
use pallo\library\security\model\generic\io\SecurityModelIO;
use pallo\library\security\model\Permission;
use pallo\library\security\model\Role;
use pallo\library\security\model\ChainableSecurityModel;
use pallo\library\security\model\User;
use pallo\library\security\SecurityManager;

/**
 * Model of the security data
 */
class GenericSecurityModel implements ChainableSecurityModel {

    /**
     * Instance of the event manager
     * @var pallo\library\event\EventManager
     */
    private $eventManager;

    /**
     * Instance of the hash algorithm
     * @var pallo\library\encryption\hash\Hash
     */
    private $hashAlgorithm;

    /**
     * The input/output implementation for this model
     * @var pallo\security\generic\io\SecurityModelIO
     */
    private $io;

    /**
     * The loaded users
     * @var array
     */
    private $users;

    /**
     * The loaded roles
     * @var array
     */
    private $roles;

    /**
     * The loaded permissions
     * @var array
     */
    private $permissions;

    /**
     * The loaded paths
     * @var array
     */
    private $paths;

    /**
     * Constructs a new security model
     * @param pallo\security\xml\io\SecurityModelIO $io
     * @param pallo\library\event\EventManager $eventManager
     * @param pallo\library\encryption\hash\Hash $hashAlgorithm
     * @return null
     */
    public function __construct(SecurityModelIO $io, EventManager $eventManager, Hash $hashAlgorithm) {
        $this->io = $io;
        $this->eventManager = $eventManager;
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * Gets a string representation of this security model
     * @return string
     */
    public function __toString() {
        return get_class($this) . '(' . get_class($this->io) . ')';
    }

    /**
     * Checks if this model owns the provided user instance
     * @param User $user
     * @return boolean
     */
    public function ownsUser(User $user) {
        return $user instanceof GenericUser;
    }

    /**
     * Checks if this model owns the provided role instance
     * @param Role $role
     * @return boolean
    */
    public function ownsRole(Role $role) {
        return $role instanceof GenericRole;
    }

    /**
     * Checks if this model owns the provided permission instance
     * @param Permission $permission
     * @return boolean
    */
    public function ownsPermission(Permission $permission) {
        return $permission instanceof GenericPermission;
    }

    /**
     * Checks if the security model is ready to work
     * @return boolean True if the model is ready, false otherwise
     */
    public function ping() {
        return $this->io->ping();
    }

    /**
     * Gets the paths which are secured for anonymous users
     * @return array Array with a path regular expression per element
     */
    public function getSecuredPaths() {
        if (!isset($this->paths)) {
            $this->paths = $this->io->getSecuredPaths();
        }

        return $this->paths;
    }

    /**
     * Sets the paths which are secured for anonymous users
     * @param array $routes Array with a path regular expression per element
     * @return null
     */
    public function setSecuredPaths(array $paths) {
        $this->paths = $paths;

        $this->io->setSecuredPaths($paths);
    }

    /**
     * Creates a new user
     * @return pallo\library\security\model\User
     */
    public function createUser() {
        return new GenericUser();
    }

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return pallo\library\security\model\User|null User object if found, null
     * otherwise
     */
    public function getUserByUsername($username) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        foreach ($this->users as $user) {
            if (strtoupper($user->getUserName()) == strtoupper($username)) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return pallo\library\security\model\User|null User object if found, null
     * otherwise
     */
    public function getUserByEmail($email) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        foreach ($this->users as $user) {
            if (strtoupper($user->getEmail()) == strtoupper($email)) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Find the users which match the provided part of a username
     * @param string $query Part of a username to match
     * @return array Array with the usernames which match the provided query
     */
    public function findUsersByUsername($query) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $users = array();

        foreach ($this->users as $user) {
            $username = $user->getUserName();

            if (!$query || stripos($username, $query) !== false) {
                $users[$user->getId()] = $username;
            }
        }

        return $users;
    }

    /**
     * Find the users which match the provided part of a email address
     * @param string $query Part of a email address
     * @return array Array with the usernames of the users which match the provided query
     */
    public function findUsersByEmail($query) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $users = array();

        foreach ($this->users as $user) {
            $username = $user->getUserName();
            $email = $user->getEmail();

            if (!$query || stripos($email, $query) !== false) {
                $users[$user->getUserId()] = $username;
            }
        }

        return $users;
    }

    /**
     * Saves a user
     * @param pallo\library\security\model\User $user The user to save
     * @return null
     */
    public function saveUser(User $user) {
        if ($user->isPasswordChanged()) {
            $password = $user->getPassword();

            $this->eventManager->triggerEvent(SecurityManager::EVENT_PASSWORD_UPDATE, array('user' => $user, 'password' => $password));

            if ($this->hashAlgorithm) {
                $user->setPassword($this->hashAlgorithm->hash($password));
            } else {
                $user->setPassword($password);
            }
        }

        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $this->users[$user->getId()] = $user;

        $this->users = $this->io->setUsers($this->users);
    }

    /**
     * Saves the provided roles for the provided user
     * @param pallo\library\security\model\User $user The user to update
     * @param array $roles The roles to set to the user
     * @return null
     */
    public function setRolesToUser(User $user, array $roles) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $this->users[$user->getId()]->setRoles($roles);

        $this->users = $this->io->setUsers($this->users);
    }

    /**
     * Deletes the provided user
     * @param pallo\library\security\model\User $user The user to delete
     * @return null
     */
    public function deleteUser(User $user) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $id = $user->getId();

        if (!isset($this->users[$id])) {
            return;
        }

        unset($this->users[$id]);

        $this->users = $this->io->setUsers($this->users);
    }

    /**
     * Creates a new role
     * @return pallo\library\security\model\Role
     */
    public function createRole() {
        return new GenericRole();
    }

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return pallo\library\security\model\Role|null The role if found or null
     * otherwise
     */
    public function getRoleByName($name) {
        if (!isset($this->roles)) {
            $this->roles = $this->io->getRoles();
        }

        foreach ($this->roles as $role) {
            if (strtoupper($role->getName()) == strtoupper($name)) {
                return $role;
            }
        }

        return null;
    }

    /**
     * Find the roles which match the provided part of a name
     * @param string $query Part of a name to match
     * @return array Array with the role name which match the provided query
     */
    public function findRolesByName($query) {
        if ($this->roles === null) {
            $this->roles = $this->io->getRoles();
        }

        $roles = array();

        foreach ($this->roles as $role) {
            $name = $role->getName();

            if (!$query || stripos($name, $query) !== false) {
                $roles[$role->getId()] = $role;
            }
        }

        return $roles;
    }

    /**
     * Saves a role
     * @param pallo\library\security\model\Role $role Role to save
     * @return null
     */
    public function saveRole(Role $role) {
        if ($this->roles === null) {
            $this->roles = $this->io->getRoles();
        }

        $this->roles[$role->getId()] = $role;

        $this->roles = $this->io->setRoles($this->roles);
    }

    /**
     * Sets the granted permissions to a role
     * @param Role $role Role to set the permissions to
     * @param array $permissionCodes Array with a permission code per element
     * @return null
     */
    public function setGrantedPermissionsToRole(Role $role, array $permissionCodes) {
        if ($this->roles === null) {
            $this->roles  = $this->io->getRoles();
        }

        $permissions = array();

        $this->getPermissions();
        foreach ($this->permissions as $permission) {
            if (in_array($permission->getCode(), $permissionCodes)) {
                $permissions[] = $permission;
            }
        }

        $roleId = $role->getId();

        $this->roles[$roleId]->setPermissions($permissions);

        $this->roles = $this->io->setRoles($this->roles);
    }

    /**
     * Sets the allowed paths to a role
     * @param pallo\library\security\model\Role $role Role to set the routes to
     * @param array $paths Array with a path regular expression per element
     * @return null
     */
    public function setAllowedPathsToRole(Role $role, array $paths) {
        if ($this->roles === null) {
            $this->roles  = $this->io->getRoles();
        }

        $roleId = $role->getId();

        $this->roles[$roleId]->setPaths($paths);

        $this->roles = $this->io->setRoles($this->roles);
    }

    /**
     * Deletes the provided role
     * @param pallo\library\security\model\Role $role Role to delete
     * @return null
     */
    public function deleteRole(Role $role) {
        if ($this->roles === null) {
            $this->roles = $this->io->getRoles();
        }

        $id = $role->getId();

        if (!isset($this->roles[$id])) {
            return;
        }

        unset($this->roles[$id]);

        $this->roles = $this->io->setRoles($this->roles);
    }

    /**
     * Gets all the permissions
     * @return array Array with Permission objects
     */
    public function getPermissions() {
        if ($this->permissions === null) {
            $this->permissions = $this->io->getPermissions();
        }

        return $this->permissions;
    }

    /**
     * Checks whether a given permission is available
     * @param string $code Code of the permission to check
     * @return boolean
     */
    public function hasPermission($code) {
        if ($this->permissions === null) {
            $this->permissions = $this->io->getPermissions();
        }

        return isset($this->permissions[$code]);
    }

    /**
     * Registers a new permission to the model
     * @param string $code Code of the permission
     * @return null
     */
    public function registerPermission($code) {
        if ($this->permissions === null) {
            $this->permissions = $this->io->getPermissions();
        }

        $this->permissions[$code] = new GenericPermission($code);

        $this->io->setPermissions($this->permissions);
    }

    /**
     * Unregisters an existing permission from the model
     * @param string $code Code of the permission
     * @return null
     */
    public function unregisterPermission($code) {
        if ($this->permissions === null) {
            $this->permissions = $this->io->getPermissions();
        }

        if (isset($this->permissions[$code])) {
            unset($this->permissions[$code]);
            $this->io->setPermissions($this->permissions);
        }
    }

}