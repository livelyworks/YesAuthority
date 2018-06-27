<?php

namespace LivelyWorks\YesAuthority;

/*
 * Service Provider for YesAuthority
 *-------------------------------------------------------- */

use Illuminate\Support\ServiceProvider;
use Blade;

class YesAuthorityServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/yes-authority.php' => config_path('yes-authority.php'),
            __DIR__.'/YesAuthorityCheckpostMiddleware.php' => app_path('Http/Middleware/YesAuthorityCheckpostMiddleware.php'),
            __DIR__.'/YesAuthorityPreCheckpostMiddleware.php' => app_path('Http/Middleware/YesAuthorityPreCheckpostMiddleware.php'),
        ], 'yesauthority');

        // required YesAuthority helpers & directives
        require __DIR__.'/support/helpers.php';
        require __DIR__.'/support/directives.php';
    }

    /**
     * Register any application services.
     */
    public function register()
    {
        // Register 'yesauthority' instance container to our YesAuthority object
        $this->app->singleton('yesauthority', function ($app) {
               return new \LivelyWorks\YesAuthority\YesAuthority();
        });

        // Register Alias
        $this->app->booting(function () {
            $loader = \Illuminate\Foundation\AliasLoader::getInstance();
            $loader->alias('YesAuthority',
                \LivelyWorks\YesAuthority\YesAuthorityFacade::class);
        });
    }
}
