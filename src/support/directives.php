<?php
    /**
     * YesAuthority directives.
     *
     *-------------------------------------------------------- */
    // Add @canAccess
    Blade::directive('canAccess', function($expression)
    {
        return "<?php if(canAccess($expression) === true): ?>";
    });

    // Add @canAccessEntity
    Blade::directive('canAccessEntity', function($expression)
    {
        return "<?php if(canAccessEntity($expression) === true): ?>";
    });    

    // Add @canPublicAccess
    Blade::directive('canPublicAccess', function($expression)
    {
        return "<?php if(canPublicAccess($expression) === true): ?>";
    });

    // Add @canEnd
    Blade::directive('endAccess', function($expression)
    {
        return '<?php endif; ?>';
    });