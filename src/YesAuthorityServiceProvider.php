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
        ]);

        // Add @__can
        Blade::directive('__canAccess', function($expression)
        {
            return "<?php if(__canAccess($expression) === true): ?>";
        });

        // Add @__canPublicAccess
        Blade::directive('__canPublicAccess', function($expression)
        {
            return "<?php if(__canPublicAccess($expression) === true): ?>";
        });

        // Add @__canEnd
        Blade::directive('__endAccess', function($expression)
        {
            return '<?php endif; ?>';
        });
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
