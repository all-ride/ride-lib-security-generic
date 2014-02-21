<?php

namespace ride\library\security\model\generic\io;

interface SecurityModelIO {

    public function ping();

    public function setUsers(array $users);

    public function getUsers();

    public function setRoles(array $roles);

    public function getRoles();

    public function setPermissions(array $permissions);

    public function getPermissions();

    public function setSecuredPaths(array $paths);

    public function getSecuredPaths();

}