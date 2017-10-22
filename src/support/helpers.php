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

    if (!function_exists('canAccess')) {
        function canAccess($accessId = null)
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
    if (!function_exists('canPublicAccess')) {
        function canPublicAccess($accessId = null)
        {
            return YesAuthority::isPublicAccess($accessId);
        }
    }

    /*
    * Check for entity access
    *
    * @param string $accessId
    * 
    * @return bool.
    *-------------------------------------------------------- */

    if (!function_exists('canAccessEntity')) {
        function canAccessEntity($entityKey, $entityId, $accessId = null)
        {
            // check for entity permissions  
            if(YesAuthority::checkEntity($entityKey, $entityId)->check($accessId) === true 
                or YesAuthority::isPublicAccess($accessId)) {

                return true;
            }

            return false;
        }
    }