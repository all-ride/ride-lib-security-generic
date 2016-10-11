# Ride: Generic Security Model

Generic security model for the security library of the PHP Ride framework.

This security model is file based and usefull for a small user base or as a backup for other security models.

## What's In This Library

### SecurityModelIO

The _SecurityModelIO_ interface is used by the _GenericSecurityModel_ as a data source.

An implementation is provided for the XML format by the _XmlSecurityModelIO_ class.

### GenericSecurityModel

The _GenericSecurityModel_ class offers a generic implementation of the _SecurityModel_ interface from the [ride/lib-security](https://github.com/all-ride/ride-lib-security) module.
This class also implements the _GenericUser_, _GenericRole_ and _GenericPermission_ classes. 

## Code Sample

Check this code sample to see how to initialize this library:

```php
use ride\library\encryption\hash\Hash;
use ride\library\event\EventManager;
use ride\library\security\model\generic\io\XmlSecurityModelIO;
use ride\library\security\model\generic\GenericSecurityModel;
use ride\library\system\System;

function createSGenericSecurityModel(System $system, EventManager $eventManager, Hash $hashAlgorithm) {
    $file = $system->getFileSystem()->getFile('/path/to/security.xml');
    $securityModelIO = new XmlSecurityModelIO($file);
    
    $securityModel = new GenericSecurityModel($securityModelIO, $eventManager, $hashAlgorithm);
    
    return $securityModel;
}
```

### Implementations

You can check the related implementations of this library:
- [ride/cli-security](https://github.com/all-ride/ride-cli-security)
- [ride/lib-security](https://github.com/all-ride/ride-lib-security)
- [ride/lib-security-oauth](https://github.com/all-ride/ride-lib-security-oauth)
- [ride/web-security-generic](https://github.com/all-ride/ride-web-security-generic)

## Installation

You can use [Composer](http://getcomposer.org) to install this library.

```
composer require ride/lib-security-generic
```
