<?php

namespace LivelyWorks\YesAuthority;

/*
 * Facade for YesAuthority
 *-------------------------------------------------------- */

use Illuminate\Support\Facades\Facade;

/**
 * YesAuthority.
 *-------------------------------------------------------------------------- */
class YesAuthorityFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'yesauthority';
    }
}
