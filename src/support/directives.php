<?php
    /**
     * YesAuthority directives.
     *
     *-------------------------------------------------------- */
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