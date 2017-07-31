# **YesAuthority**
-------------------
YesAuthority is flexible authorization system for Laravel, It check the `route` permission to access a certain portion of the site or application. To add Permissions `User-based`, `Role-based`, `Virtual Conditions`. There is one middleware name as 'authority checkpost' which is use for filter permission of login user, Under this middleware handle every activity permission of user, role etc.  


## **Installation**
Require this package in your `composer.json` or install it by running:

```bash
    composer require livelyworks/yesauthority
```

After that add the service provider to `config/app.php`

```bash
    LivelyWorks\YesAuthority\YesAuthorityServiceProvider::class
```

This will place a copy of the configuration file at `config/yes-authority.php` and middleware at `Middleware/YesAuthorityCheckpostMiddleware.php`. The config file includes an 'default' configuration, which is a great place to setup your route permissions, So make this happen need to be run this command.

```bash
    php artisan vendor:publish  --tag="yesauthority"
```

Now, Open `app/Http/Kernel.php` file and add this middleware into `$routeMiddleware` array as:

```php
    protected $routeMiddleware = [
        'authority.checkpost'  => \App\Http\Middleware\YesAuthorityCheckpostMiddleware::class
    ];
```

After that provide protection to the application routes, You need to use `authority.checkpost` middleware in routes file. 


```php  
    Route::group(['middleware' => 'authority.checkpost'], function () {
        // define all those routes here, Which will be accessible after login.
    });
```

Congratulations, done installation.

##  **Configuration**

Below structure use for to define the abilities of user, More details you can read the [documentations](https://livelyworks.github.io/YesAuthority/Sample_Structure)` to add authorization rules.

```php

    [
        'allow' => ['temp1'], // Allowed permission to user. Priority is less than deny.
        'deny'  => ['*'], // Deny permission to user. Priority is higher than allow.
    ]

    canAccess('temp1');
    // true 
```



## **Usage - Helpers**

* **<h5>canAccess($accessId = null);</h5>**
Check the access, By default it check current route and return response in **boolean** value.
```php
    canAccess('temp1');
    // true or false
```

* **<h5>canPublicAccess($accessId = null);</h5>**
Check the public access, By default it check current route and return response in **boolean** value.

```php
    canPublicAccess();
    // true or false
```

## **Usage - Facade**

* **<h5>YesAuthority::check($accessId = null, $requestForUserId = null)</h5>**
Check the access of `$accessId`, By default it check current route and return response in **boolean** value, And it can check access of perticular user by passing user id `($requestForUserId)` parameter.
```php
    YesAuthority::check('temp1');
    // true or false
```


* **<h5>YesAuthority::isPublicAccess($accessId = null)</h5>**
Check the access of `$accessId`, By default it check current route and return response in **boolean** value.
```php
    YesAuthority::isPublicAccess('temp1');
    // true or false
```


## **Usage - Directives**

* **<h5>@canAccess($accessId = null);</h5>**
Check the access, By default it check current route and return response in **boolean** value.
```php
    @canAccess()
       // your logic here.
    @endAccess;
```


* **<h5>@canPublicAccess($accessId = null);</h5>**
Check the public access, By default it check current route and return response in **boolean** value.
```php
    @canPublicAccess()
       // your logic here.
    @endAccess;
```