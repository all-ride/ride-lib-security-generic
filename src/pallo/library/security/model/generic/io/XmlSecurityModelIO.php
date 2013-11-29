<?php

namespace pallo\library\security\model\generic\io;

use pallo\library\reflection\Boolean;
use pallo\library\system\file\File;

use pallo\library\security\model\generic\GenericPermission;
use pallo\library\security\model\generic\GenericRole;
use pallo\library\security\model\generic\GenericRoute;
use pallo\library\security\model\generic\GenericUser;

use \DOMDocument;
use \DOMElement;

class XmlSecurityModelIO implements SecurityModelIO {

    const TAG_ROOT = 'security';

    const TAG_USER = 'user';

    const TAG_ROLE = 'role';

    const TAG_PERMISSION = 'permission';

    const TAG_PREFERENCE = 'preference';

    const TAG_PATH = 'path';

    const ATTRIBUTE_ID = 'id';

    const ATTRIBUTE_USERNAME = 'username';

    const ATTRIBUTE_PASSWORD = 'password';

    const ATTRIBUTE_NAME = 'name';

    const ATTRIBUTE_EMAIL = 'email';

    const ATTRIBUTE_IMAGE = 'image';

    const ATTRIBUTE_ACTIVE = 'active';

    const ATTRIBUTE_SUPER = 'super';

    const ATTRIBUTE_CODE = 'code';

    const ATTRIBUTE_DESCRIPTION = 'description';

    const ATTRIBUTE_KEY = 'key';

    const ATTRIBUTE_VALUE = 'value';

    private $file;

    private $users;

    private $roles;

    private $permissions;

    private $paths;

    private $newId;

    public function __construct(File $file) {
        $this->file = $file;

        $this->users = null;
        $this->roles = null;
        $this->permissions = null;
        $this->paths = null;

        $this->newId = array(
            'user' => 1,
            'role' => 1,
        );
    }

    public function ping() {
        return true;
    }

    public function setUsers(array $users) {
        if ($this->roles === null) {
            $this->read();
        }

        $this->users = $users;
        foreach ($this->users as $index => $user) {
            if ($user->getId()) {
                continue;
            }

            $user->setId($this->newId['user']);
            $this->newId['user']++;

            unset($this->users[$index]);
            $this->users[$user->getId()] = $user;
        }

        $this->write();

        return $this->users;
    }

    public function getUsers() {
        if ($this->roles === null) {
            $this->read();
        }

        return $this->users;
    }

    public function setRoles(array $roles) {
        if ($this->users === null) {
            $this->read();
        }

        $this->roles = $roles;
        foreach ($this->roles as $index => $role) {
            if ($role->getId()) {
                continue;
            }

            $role->setId($this->newId['role']);
            $this->newId['role']++;

            unset($this->roles[$index]);
            $this->roles[$role->getId()] = $role;
        }

        $this->write();

        return $this->roles;
    }

    public function getRoles() {
        if ($this->roles === null) {
            $this->read();
        }

        return $this->roles;
    }

    public function setPermissions(array $permissions) {
        if ($this->users === null) {
            $this->read();
        }

        $this->permissions = $permissions;

        $this->write();
    }

    public function getPermissions() {
        if ($this->users === null) {
            $this->read();
        }

        return $this->permissions;
    }

    public function setSecuredPaths(array $paths) {
        if ($this->users === null) {
            $this->read();
        }

        $this->paths = $paths;

        $this->write();
    }

    public function getSecuredPaths() {
        if ($this->users === null) {
            $this->read();
        }

        return $this->paths;
    }

    protected function read() {
        $this->users = array();
        $this->roles = array();
        $this->permissions = array();
        $this->paths = array();

        if (!$this->file->exists()) {
            return;
        }

        $dom = new DOMDocument();
        $dom->load($this->file);

        foreach ($dom->documentElement->childNodes as $element) {
            switch ($element->nodeName) {
                case self::TAG_USER:
                    $this->readUser($element);
                    break;
                case self::TAG_ROLE:
                    $this->readRole($element);
                    break;
                case self::TAG_PERMISSION:
                    $this->readPermission($element);
                    break;
                case self::TAG_PATH:
                    $this->readPath($element);
                    break;
            }
        }

        foreach ($this->roles as $role) {
            $permissions = $role->getPermissions();
            foreach ($permissions as $code => $permission) {
                $permissions[$code] = $this->permissions[$code];
            }

            $role->setPermissions($permissions);
        }

        foreach ($this->users as $user) {
            $roles = $user->getRoles();
            foreach ($roles as $id => $role) {
                $roles[$id] = $this->roles[$id];
            }

            $user->setRoles($roles);
        }
    }

    protected function readUser(DOMElement $element) {
        $id = $element->getAttribute(self::ATTRIBUTE_ID);
        $username = $element->getAttribute(self::ATTRIBUTE_USERNAME);
        $displayName = $element->getAttribute(self::ATTRIBUTE_NAME);
        $password = $element->getAttribute(self::ATTRIBUTE_PASSWORD);
        $email = $element->getAttribute(self::ATTRIBUTE_EMAIL);
        $image = $element->getAttribute(self::ATTRIBUTE_IMAGE);
        $isActive = $element->getAttribute(self::ATTRIBUTE_ACTIVE);
        $isSuperUser = $element->getAttribute(self::ATTRIBUTE_SUPER);
        $roles = array();
        $preferences = array();

        if ($isActive != '') {
            $isActive = Boolean::getBoolean($isActive);
        }

        if ($isSuperUser != '') {
            $isSuperUser = Boolean::getBoolean($isSuperUser);
        }

        foreach ($element->childNodes as $child) {
            if ($child->nodeName == self::TAG_ROLE) {
                $roles[$child->nodeValue] = $child->nodeValue;
            } elseif ($child->nodeName == self::TAG_PREFERENCE) {
                $preferences[$child->getAttribute(self::ATTRIBUTE_KEY)] = unserialize($child->nodeValue);
            }
        }

        $user = new GenericUser($username, $password);
        $user->setId($id);
        if ($displayName) {
            $user->setDisplayName($displayName);
        }
        if ($email) {
            $user->setEmail($email);
        }
        if ($image) {
            $user->setImage($image);
        }
        $user->setIsActive($isActive);
        $user->setIsSuperUser($isSuperUser);
        $user->setRoles($roles);

        foreach ($preferences as $key => $value) {
            $user->setPreference($key, $value);
        }

        $this->users[$id] = $user;

        if ($id >= $this->newId['user']) {
             $this->newId['user'] = $id + 1;
        }
    }

    protected function readRole(DOMElement $element) {
        $id = $element->getAttribute(self::ATTRIBUTE_ID);
        $name = $element->getAttribute(self::ATTRIBUTE_NAME);
        $paths = array();
        $permissions = array();

        foreach ($element->childNodes as $child) {
            if ($child->nodeName == self::TAG_PATH) {
                $paths[$child->nodeValue] = $child->nodeValue;
            } elseif ($child->nodeName == self::TAG_PERMISSION) {
                $permissions[$child->nodeValue] = $child->nodeValue;
            }
        }

        $role = new GenericRole();
        $role->setId($id);
        $role->setName($name);
        $role->setPaths($paths);
        $role->setPermissions($permissions);

        $this->roles[$id] = $role;

        if ($id >= $this->newId['role']) {
            $this->newId['role'] = $id + 1;
        }
    }

    protected function readPermission(DOMElement $element) {
        $code = $element->getAttribute(self::ATTRIBUTE_CODE);
        $description = $element->getAttribute(self::ATTRIBUTE_DESCRIPTION);

        $permission = new GenericPermission($code, $description);

        $this->permissions[$code] = $permission;
    }

    protected function readPath(DOMElement $element) {
        $this->paths[] = $element->nodeValue;
    }

    protected function write() {
        $dom = new DOMDocument('1.0', 'utf-8');
        $dom->formatOutput = true;

        $securityElement = $dom->createElement(self::TAG_ROOT);
        $dom->appendChild($securityElement);

        foreach ($this->users as $user) {
            $email = $user->getEmail();
            $displayName = $user->getDisplayName();
            $image = $user->getImage();
            $isActive = $user->isActive();
            $isSuperUser = $user->isSuperUser();

            $userElement = $dom->createElement(self::TAG_USER);
            $userElement->setAttribute(self::ATTRIBUTE_ID, $user->getId());
            if ($displayName) {
                $userElement->setAttribute(self::ATTRIBUTE_NAME, $displayName);
            }
            if ($email) {
                $userElement->setAttribute(self::ATTRIBUTE_EMAIL, $email);
            }
            $userElement->setAttribute(self::ATTRIBUTE_USERNAME, $user->getUserName());
            $userElement->setAttribute(self::ATTRIBUTE_PASSWORD, $user->getPassword());
            $userElement->setAttribute(self::ATTRIBUTE_ACTIVE, $isActive ? '1' : '0');
            $userElement->setAttribute(self::ATTRIBUTE_SUPER, $isSuperUser ? '1' : '0');
            if ($image) {
                $userElement->setAttribute(self::ATTRIBUTE_IMAGE, $image);
            }

            $roles = $user->getRoles();
            foreach ($roles as $role) {
                $roleElement = $dom->createElement(self::TAG_ROLE, $role->getId());

                $importedRoleElement = $dom->importNode($roleElement, true);
                $userElement->appendChild($importedRoleElement);
            }

            $preferences = $user->getPreferences();
            foreach ($preferences as $key => $value) {
                $preferenceElement = $dom->createElement(self::TAG_PREFERENCE, serialize($value));
                $preferenceElement->setAttribute(self::ATTRIBUTE_KEY, $key);

                $importedPreferenceElement = $dom->importNode($preferenceElement, true);
                $userElement->appendChild($importedPreferenceElement);
            }

            $importedUserElement = $dom->importNode($userElement, true);
            $securityElement->appendChild($importedUserElement);
        }

        foreach ($this->roles as $role) {
            $roleElement = $dom->createElement(self::TAG_ROLE);
            $roleElement->setAttribute(self::ATTRIBUTE_ID, $role->getId());
            $roleElement->setAttribute(self::ATTRIBUTE_NAME, $role->getName());

            $paths = $role->getRolePaths();
            foreach ($paths as $path) {
                $pathElement = $dom->createElement(self::TAG_PATH, $path);

                $importedPathElement = $dom->importNode($pathElement, true);
                $roleElement->appendChild($importedPathElement);
            }

            $permissions = $role->getRolePermissions();
            foreach ($permissions as $permission) {
                $permissionElement = $dom->createElement(self::TAG_PERMISSION, $permission->getCode());

                $importedPermissionElement = $dom->importNode($permissionElement, true);
                $roleElement->appendChild($importedPermissionElement);
            }

            $importedRoleElement = $dom->importNode($roleElement, true);
            $securityElement->appendChild($importedRoleElement);
        }

        foreach ($this->permissions as $permission) {
            $permissionElement = $dom->createElement(self::TAG_PERMISSION);
            $permissionElement->setAttribute(self::ATTRIBUTE_CODE, $permission->getCode());
            $permissionElement->setAttribute(self::ATTRIBUTE_DESCRIPTION, $permission->getDescription());

            $importedPermissionElement = $dom->importNode($permissionElement, true);
            $securityElement->appendChild($importedPermissionElement);
        }

        foreach ($this->paths as $path) {
            $pathElement = $dom->createElement(self::TAG_PATH, $path);

            $importedPathElement = $dom->importNode($pathElement, true);
            $securityElement->appendChild($importedPathElement);
        }

        $parent = $this->file->getParent();
        $parent->create();

        $dom->save($this->file);
    }

}