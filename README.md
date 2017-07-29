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

## **Configuration Steps**

Open `app/Http/Kernel.php` file and add this middleware into `$routeMiddleware` array as:

```php
    protected $routeMiddleware = [
        
        'authority.checkpost'  => \App\Http\Middleware\YesAuthorityCheckpostMiddleware::class

    ];
```

After that provide protection to the application routes, You need to use `authority.checkpost` middleware in routes file. 

```php

    Route::get('/page', [ 'middleware' => 'authority.checkpost']);

```


> OR


define all those routes here, Which will be accessible after login.

```php  


Route::group(['middleware' => 'authority.checkpost'], function () {

});


```

> OR

```php
    // Other ways to use middleware.
```

After that use of `authority.checkpost` middleware only allowed routes can access the logged in user. If route not allowed and the user tries to access this route, So it will be return response `unauthorized` user.


##  **Other**
Yoooo..!! Done Installation & Configuration now you can use YesAuthority facade in your application with his chaining functions, Please see [documentations](https://livelyworks.github.io/YesAuthority).