<?php

namespace ride\library\security\model\generic;

use ride\library\security\matcher\PathMatcher;
use ride\library\security\model\User;

/**
 * User of the SecurityModel
 */
class GenericUser implements User {

    /**
     * Id of this user
     * @var string
     */
    protected $id;

    /**
     * Username to authenticate
     * @var string
     */
    protected $username;

    /**
     * Password
     * @var string
     */
    protected $password;

    /**
     * Display name
     * @var string
     */
    protected $displayName;

    /**
     * Email address of the user
     * @var string
     */
    protected $email;

    /**
     * Image of the user
     * @var string
     */
    protected $image;

    /**
     * Flag to see if the user's email address has been confirmed
     * @var boolean
     */
    protected $isEmailConfirmed;

    /**
     * Flag to see if the user is active
     * @var boolean
     */
    protected $isActive;

    /**
     * Flag to see if the user is a super user
     * @var boolean
     */
    protected $isSuperUser;

    /**
     * The roles of this user
     * @var array
     */
    protected $roles;

    /**
     * The preferences of the user
     * @var array
     */
    protected $preferences;

    /**
     * Flag to see if the password changed
     * @var boolean
     */
    protected $isPasswordChanged;

    /**
     * Constructs a new user
     * @param string $username = null
     * @return null
     */
    public function __construct($username = null, $password = null) {
        $this->id = null;
        $this->password = $password;
        $this->displayName = null;
        $this->email = null;
        $this->isEmailConfirmed = false;
        $this->isActive = false;
        $this->isSuperUser = false;
        $this->roles = array();
        $this->preferences = array();
        $this->isPasswordChanged = false;

        $this->setUserName($username);
    }

    /**
     * Sets the user id
     * @param integer $id
     * @return null
     */
    public function setId($id) {
        if ($this->id !== null && $this->id != $id) {
            throw new SecurityException('Could not set the id of the role: already set');
        }

        $this->id = $id;
    }

    /**
     * Gets the unique id of this user
     * @return string
     */
    public function getId() {
        return $this->id;
    }

    /**
     * Sets the display name of this user
     * @param string $name
     * @return
     */
    public function setDisplayName($displayName) {
        $this->displayName = $displayName;
    }

    /**
     * Gets the display name of this user
     * @return string
     */
    public function getDisplayName() {
        if (!$this->displayName) {
            return $this->username;
        }

        return $this->displayName;
    }

    /**
     * Sets the name to identify this user
     * @param string $username The username to identify the user
     * @return null
     */
    public function setUserName($username) {
        $this->username = $username;
    }

    /**
     * Gets the name to identify this user
     * @return string
     */
    public function getUserName() {
        return $this->username;
    }

    /**
     * Sets a new password for this user
     *
     * This method will run the security.password.update event before setting the password. This event
     * has the User object and the new plain password as arguments.
     * @param string $password Plain text password
     * @return null
     * @see SecurityModel
     */
    public function setPassword($password) {
        $this->password = $password;
        $this->isPasswordChanged = true;
    }

    /**
     * Checks if the user password has been changed
     * @return boolean
     */
    public function isPasswordChanged() {
        return $this->isPasswordChanged;
    }

    /**
     * Gets the password of this user
     * @return string Encrypted password
     */
    public function getPassword() {
        return $this->password;
    }

    /**
     * Sets the email address of this user
     * @param string $email
     * @return
     */
    public function setEmail($email) {
        $this->email = $email;

        $this->setIsEmailConfirmed(false);
    }

    /**
     * Gets the email address of this user
     * @return string
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * Sets whether this user's email address has been confirmed
     * @param boolean $flag
     * @return null
     */
    public function setIsEmailConfirmed($flag) {
        if (!$this->email) {
            $this->isEmailConfirmed = false;
        } else {
            $this->isEmailConfirmed = $flag;
        }
    }

    /**
     * Gets whether this user's email address has been confirmed
     * @return boolean
     */
    public function isEmailConfirmed() {
        return $this->isEmailConfirmed;
    }

    /**
     * Sets the image of this user
     * @param string $image Path to the image
     * @return
     */
    public function setImage($image) {
        $this->image = $image;
    }

    /**
     * Gets the path to the image of this user
     * @return string
     */
    public function getImage() {
        return $this->image;
    }

    /**
     * Sets whether this user is active
     * @param boolean $flag
     * @return null
     */
    public function setIsActive($flag) {
        $this->isActive = $flag;
    }

    /**
     * Gets whether this user is active
     * @return boolean
     */
    public function isActive() {
        return $this->isActive;
    }

    /**
     * Sets whether this user is a super user
     * @param boolean $flag
     * @return null
     */
    public function setIsSuperUser($flag) {
        $this->isSuperUser = $flag;
    }

    /**
     * Checks whether this user is a super user and thus can perform everything
     * @return @boolean True if this user is a super user, false otherwise
     */
    public function isSuperUser() {
        return $this->isSuperUser;
    }

    /**
     * Sets the roles of this user
     * @param array $roles
     * @return null
     */
    public function setRoles(array $roles) {
        $this->roles = $roles;
    }

    /**
     * Gets the roles of this user
     * @return array Array of Role objects
     */
    public function getRoles() {
        return $this->roles;
    }

    /**
     * Gets the highest weight of the user's roles
     * @return integer
     */
    public function getRoleWeight() {
        if ($this->isSuperUser) {
            return 2147483647;
        }

        $weight = 0;

        foreach ($this->roles as $role) {
            $roleWeight = $role->getWeight();
            if ($roleWeight > $weight) {
                $weight = $roleWeight;
            }
        }

        return $weight;
    }

    /**
     * Checks whether a permission is granted for this user
     * @param string $code Code of the permission to check
     * @return boolean True if permission is granted, false otherwise
     */
    public function isPermissionGranted($code) {
        if (!isset($this->permissions)) {
            $this->preparePermissions();
        }

        if (isset($this->permissions[$code])) {
            return true;
        }

        return false;
    }

    /**
     * Prepares the permissions for a quicker permission check
     * @return null
     */
    public function preparePermissions() {
        $this->permissions = array();

        foreach ($this->roles as $role) {
            $permissions = $role->getPermissions();

            foreach ($permissions as $permission) {
                $this->permissions[$permission->getCode()] = true;
            }
        }
    }

    /**
     * Checks whether a path is allowed for this user
     * @param string $path Path to check
     * @param string $method Request method to check
     * @param \ride\library\security\matcher\PathMatcher $pathMatcher To match
     * path regular expression on the route
     * @return boolean True if the path is allowed, false otherwise
     */
    public function isPathAllowed($path, $method, PathMatcher $pathMatcher) {
        if (!isset($this->paths)) {
            $this->preparePaths();
        }

        if ($pathMatcher->matchPath($path, $method, $this->paths)) {
            return true;
        }

        return false;
    }

    /**
     * Prepares the paths for a quicker path check
     * @return null
     */
    public function preparePaths() {
        $this->paths = array();

        foreach ($this->roles as $role) {
            $paths = $role->getPaths();

            foreach ($paths as $path) {
                $this->paths[$path] = true;
            }
        }

        $this->paths = array_keys($this->paths);
    }

    /**
     * Gets all the preferences of this user
     * @return array Array with the name of the setting as key and the setting as value
     */
    public function getPreferences() {
        return $this->preferences;
    }

    /**
     * Gets a preference of this user
     * @param string $name Name of the preference
     * @param mixed $default Default value for when the preference is not set
     * @return mixed The value of the preference or the provided default value if the preference is not set
     */
    public function getPreference($name, $default = null) {
        if (!isset($this->preferences[$name])) {
            return $default;
        }

        return $this->preferences[$name];
    }

    /**
     * Sets a preference for this user
     * @param string $name Name of the preference
     * @param mixed $value Value for the preference
     * @return null
     */
    public function setPreference($name, $value) {
        if ($value !== null) {
            $this->preferences[$name] = $value;
        } elseif (isset($this->preferences[$name])) {
            unset($this->preferences[$name]);
        }
    }

}
