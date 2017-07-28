<?php
    /**
     * YesAuthority Helpers.
     * 
     * Common helper functions for YesAuthority applications
     *
     *-------------------------------------------------------- */
/*
    * Check if access available
    *
    * @param string $accessId
    * 
    * @return bool.
    *-------------------------------------------------------- */

    if (!function_exists('__canAccess')) {
        function __canAccess($accessId = null)
        {

            if(YesAuthority::check($accessId) === true 
                or YesAuthority::isPublicAccess($accessId)) {

                return true;
            }

            return false;
        }
    }

    /*
    * Check if access available
    *
    * @param string $accessId
    * 
    * @return bool.
    *-------------------------------------------------------- */
    if (!function_exists('__canPublicAccess')) {
        function __canPublicAccess($accessId = null)
        {
            return YesAuthority::isPublicAccess($accessId);
        }
    }