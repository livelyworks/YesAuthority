<?php

namespace LivelyWorks\YesAuthority;

/*
 * YesAuthorityResultDetails
 * 
 * Authorization system
 *
 *--------------------------------------------------------------------------- */

use Exception;

/**
 * This YesAuthority class.
 *---------------------------------------------------------------- */
class YesAuthorityResult
{
    /**
     * Custom Permissions holder
     *
     * @var array
     */
    protected $originalResult = [];

    /**
     * Custom Permissions holder
     *
     * @var array
     */
    protected $options = [];   

    /**
     * Custom Permissions holder
     *
     * @var array
     */
    protected $checkLevels = [];      

    /**
      * Constructor
      *
      *
      * @return void
      *-----------------------------------------------------------------------*/

    function __construct($originalResult, $options)
    {
        $this->originalResult = $originalResult;
        $this->options = $options;

        $this->checkLevels = $this->options['check_levels'];
    }

    /**
      * Constructor
      *
      *
      * @return void
      *-----------------------------------------------------------------------*/

    public function toArray()
    {
        return $this->originalResult;
    }

    function __call($func, $params){
        $getItem = snake_case($func);        
        if(array_key_exists(snake_case($getItem), $this->originalResult)){
            return $this->originalResult[$getItem];
        }

        throw new Exception("Undefined method - ". $func, 2);        
    }

        /**
      * Constructor
      *
      *
      * @return void
      *-----------------------------------------------------------------------*/

    public function isResultBy($resultExprected)
    {
        if(! array_key_exists($resultExprected, $this->checkLevels)) {
            throw new Exception("YesAuthority - $resultExprected is invalid level . ". implode(', ', array_keys($this->checkLevels)) . ' are valid levels');            
        }

        return $this->resultBy() == $resultExprected;
    }
}