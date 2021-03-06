<?php

namespace ride\library\security\model\generic;

use ride\library\encryption\hash\Hash;
use ride\library\event\EventManager;
use ride\library\security\exception\EmailExistsException;
use ride\library\security\exception\UsernameExistsException;
use ride\library\security\model\generic\io\SecurityModelIO;
use ride\library\security\model\Permission;
use ride\library\security\model\Role;
use ride\library\security\model\ChainableSecurityModel;
use ride\library\security\model\User;
use ride\library\security\SecurityManager;

/**
 * Model of the security data
 */
class GenericSecurityModel implements ChainableSecurityModel {

    /**
     * Instance of the event manager
     * @var \ride\library\event\EventManager
     */
    private $eventManager;

    /**
     * Instance of the hash algorithm
     * @var \ride\library\encryption\hash\Hash
     */
    private $hashAlgorithm;

    /**
     * The input/output implementation for this model
     * @var \ride\library\security\model\generic\io\SecurityModelIO
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
     * @param \ride\library\security\model\generic\io\SecurityModelIO $io
     * @param \ride\library\event\EventManager $eventManager
     * @param \ride\library\encryption\hash\Hash $hashAlgorithm
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
     * Sets the allowed paths to a role
     * @param \ride\library\security\model\Role $role Role to set the routes to
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
     * Saves the provided roles for the provided user
     * @param \ride\library\security\model\User $user The user to update
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
     * Gets a user by it's id
     * @param string $id Id of the user
     * @return User|null User object if found, null otherwise
     */
    public function getUserById($id) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $id = strtoupper($id);

        foreach ($this->users as $user) {
            if (strtoupper($user->getId()) == $id) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets a user by it's username
     * @param string $username Username of the user
     * @return \ride\library\security\model\User|null User object if found, null
     * otherwise
     */
    public function getUserByUsername($username) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $username = strtoupper($username);

        foreach ($this->users as $user) {
            if (strtoupper($user->getUserName()) == $username) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets a user by it's email address
     * @param string $email Email address of the user
     * @return \ride\library\security\model\User|null User object if found, null
     * otherwise
     */
    public function getUserByEmail($email) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $email = strtoupper($email);

        foreach ($this->users as $user) {
            if (strtoupper($user->getEmail()) == $email) {
                return $user;
            }
        }

        return null;
    }

    /**
     * Gets the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getUsers(array $options = null) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        if (!$options) {
            return $this->users;
        }

        $users = array();

        $query = isset($options['query']) ? $options['query'] : null;
        $queryName = isset($options['name']) ? $options['name'] : null;
        $queryUsername = isset($options['username']) ? $options['username'] : null;
        $queryEmail = isset($options['email']) ? $options['email'] : null;

        foreach ($this->users as $user) {
            $username = $user->getUserName();
            $name = $user->getDisplayName();
            $email = $user->getEmail();

            if ($query && stripos($username, $query) === false && stripos($name, $query) === false && stripos($email, $query) === false) {
                continue;
            }
            if ($queryName && stripos($name, $queryName) === false) {
                continue;
            }
            if ($queryUsername && stripos($username, $queryUsername) === false) {
                continue;
            }
            if ($queryEmail && stripos($email, $queryEmail) === false) {
                continue;
            }

            $users[$user->getId()] = $user;
        }

        if (isset($options['limit'])) {
            $page = isset($options['page']) ? $options['page'] : 1;
            $offset = ($page - 1) * $options['limit'];

            $users = array_slice($users, $offset, $options['limit'], true);
        }

        return $users;
    }

    /**
     * Counts the users
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>username</li>
     *     <li>email</li>
     * </ul>
     * @return integer
     */
    public function countUsers(array $options = null) {
        if (isset($options['limit'])) {
            unset($options['limit']);
        }

        return count($this->getUsers($options));
    }

    /**
     * Creates a new user
     * @return \ride\library\security\model\User
     */
    public function createUser() {
        return new GenericUser();
    }

    /**
     * Saves a user
     * @param \ride\library\security\model\User $user The user to save
     * @return null
     */
    public function saveUser(User $user) {
        if ($this->users === null) {
            $this->users = $this->io->getUsers();
        }

        $id = $user->getId();
        $username = $user->getUserName();
        $email = $user->getEmail();
        foreach ($this->users as $modelUser) {
            if ($modelUser->getUserName() == $username && $modelUser->getId() != $id) {
                throw new UsernameExistsException();
            }

            if ($email && $modelUser->getEmail() == $email && $modelUser->getId() != $id) {
                throw new EmailExistsException();
            }
        }

        if ($user->isPasswordChanged()) {
            $password = $user->getPassword();

            $this->eventManager->triggerEvent(SecurityManager::EVENT_PASSWORD_UPDATE, array('user' => $user, 'password' => $password));

            $user->setPassword($this->hashAlgorithm->hash($password));
        }

        $this->users[$user->getId()] = $user;

        $this->users = $this->io->setUsers($this->users);
    }

    /**
     * Deletes the provided user
     * @param \ride\library\security\model\User $user The user to delete
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
     * Gets a role by it's id
     * @param string $id Id of the role
     * @return Role|null Role object if found, null otherwise
     */
    public function getRoleById($id) {
        if (!isset($this->roles)) {
            $this->roles = $this->io->getRoles();
        }

        if (!isset($this->roles[$id])) {
            return null;
        }

        return $this->roles[$id];
    }

    /**
     * Gets a role by it's name
     * @param string $name Name of the role
     * @return \ride\library\security\model\Role|null The role if found or null
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
     * Gets all the roles
     * @param array $options Options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     *     <li>page</li>
     *     <li>limit</li>
     * </ul>
     * @return array
     */
    public function getRoles(array $options = null) {
        if (!isset($this->roles)) {
            $this->roles = $this->io->getRoles();
        }

        $roles = array();

        $query = isset($options['query']) ? $options['query'] : null;
        $queryName = isset($options['name']) ? $options['name'] : null;

        foreach ($this->roles as $role) {
            $name = $role->getName();

            if ($query && stripos($name, $query) === false) {
                continue;
            }
            if ($queryName && stripos($name, $queryName) === false) {
                continue;
            }

            $roles[$role->getId()] = $role;
        }

        if (isset($options['limit'])) {
            $page = isset($options['page']) ? $options['page'] : 1;
            $offset = ($page - 1) * $options['limit'];

            $roles = array_slice($roles, $offset, $options['limit'], true);
        }

        return $roles;
    }

    /**
     * Counts the roles
     * @param array $options Extra options for the query
     * <ul>
     *     <li>query</li>
     *     <li>name</li>
     * </ul>
     * @return integer
     */
    public function countRoles(array $options = null) {
        if (isset($options['limit'])) {
            unset($options['limit']);
        }

        return count($this->getRoles($options));
    }

    /**
     * Creates a new role
     * @return \ride\library\security\model\Role
     */
    public function createRole() {
        return new GenericRole();
    }

    /**
     * Saves a role
     * @param \ride\library\security\model\Role $role Role to save
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
     * Deletes the provided role
     * @param \ride\library\security\model\Role $role Role to delete
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
    public function addPermission($code) {
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
    public function deletePermission($code) {
        if ($this->permissions === null) {
            $this->permissions = $this->io->getPermissions();
        }

        if (isset($this->permissions[$code])) {
            unset($this->permissions[$code]);
            $this->io->setPermissions($this->permissions);
        }
    }

}
