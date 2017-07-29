<?php

namespace LivelyWorks\YesAuthority;

/*
 * YesAuthority 
 * 
 * Laravel Route Authorization system
 *
 *--------------------------------------------------------------------------- */

use Auth;
use Route;
use Exception;

/**
 * This YesAuthority class.
 *---------------------------------------------------------------- */
class YesAuthority
{
    /*
        Store public routes
    */
    protected $publicRoutes = [];
    /*
        Permission Container
    */
    protected $permissions = [];   

    /**
     * Custom Permissions holder
     *
     * @var array
     */
    protected $customPermissions = false;

    /**
     * Middleware name
     *
     * @var array
     */
    protected $middlewareName = "authority.checkpost";    

    /**
     * Authority Configurations
     *
     * @var array
     */
    protected $yesConfig = null;  
    protected $configColRole = null;  
    protected $configColUserId = null;
    protected $configColRoleId = null;    
    protected $dependentsAccessIds = null;
    protected $userIdentified;
    protected $roleIdentified;    
    protected $userRoleId;
    protected $userId;         
    protected $configColPermissions = [];     
    protected $configColRolePermissions = []; 
    protected $dynamicAccessZones = [];   
    protected $currentRouteAccessId;       
    protected $dynamicPermissionStorage = [];     
    protected $userPermissions = [];   
    protected $userRolePermissions = [];     
    protected $checkLevels = [];
    protected $checkLevel = 99;  
    protected $accessStages = [];     
    protected $allowedVia = null;      
    protected $accessDetailsRequested = false;
    protected $accessScope = [];  
    protected $isDirectChecked = true;   
    protected $filterTypes     = 'all';       
    protected $levelsModified = false;      
    protected $roleLevels = [
        1 => 'CONFIG_ROLE',
        3 => 'DB_ROLE'
    ];    

    /**
      * Constructor
      *
      *
      * @return void
      *-----------------------------------------------------------------------*/

    function __construct()
    {
        $this->initialize();

        // get permission info from config
        $this->permissions    = config('yes-authority');
    }

    /**
      * configure
      *
      *
      * @return void
      *-----------------------------------------------------------------------*/
    protected function configure($requestForUserId = null, $options = [])
    {
        if(__isEmpty($this->permissions) and is_array($this->permissions) === false) {
           throw new Exception("YesAuthority - permissions empty");
        }

        if($requestForUserId) {
            $this->userIdentified = true;
        } else {
            $this->userIdentified = Auth::check() ?: false;
        }

        $this->currentRouteAccessId = Route::currentRouteName();

        $this->yesConfig          = array_get($this->permissions, 'config');
        $this->configColRole      = array_get($this->yesConfig, 'col_role');
        $this->configColUserId    = array_get($this->yesConfig, 'col_user_id');
        $this->configColRoleId    = array_get($this->yesConfig, 'col_role_id') ?: $this->configColUserId;
        $this->dependentsAccessIds      = array_get($this->permissions, 'dependents');
        $userModelString          = array_get($this->yesConfig, 'user_model');
        $roleModelString          = array_get($this->yesConfig, 'role_model');

        if(__isEmpty($this->yesConfig) or __isEmpty($this->configColRole) or __isEmpty($this->configColUserId)) {
            throw new Exception("YesAuthority - config item should contain col_role, col_user_id");
        }

        $this->middlewareName = array_get($this->yesConfig, 'middleware_name') ?: $this->middlewareName;

        if($requestForUserId and ($this->accessScope === 'user')) {

            if(! is_string($userModelString)) {
                throw new Exception("YesAuthority - Please set key for user_model in config");
            }

            if(!class_exists($userModelString)) {
                throw new Exception("YesAuthority - User model does not exist.");
            }

            $userModel = new $userModelString;
            $userFound = $userModel->findOrFail($requestForUserId);
            $this->userIdentified   = $userFound->toArray();
        }

        if($this->userIdentified) {

            $this->configColPermissions = array_get($this->yesConfig, 'col_user_permissions');
            $this->configColRolePermissions = array_get($this->yesConfig, 'col_role_permissions') ?: $this->configColPermissions;

            if($this->accessScope !== 'role') {
                if(! $requestForUserId) {
                   $this->userIdentified  = Auth::user()->toArray();
                }

                $this->userRoleId     = array_get($this->userIdentified, $this->configColRole);
                $this->userId         = array_get($this->userIdentified, $this->configColUserId);

                if($this->configColPermissions and __isEmpty(array_get($this->userIdentified, $this->configColPermissions)) === false) {
                
                    $rawUserPermissions = array_get($this->userIdentified, $this->configColPermissions);

                    if(is_array($rawUserPermissions) === false) {
                        $this->userPermissions = array_merge($this->userPermissions, collect(json_decode($rawUserPermissions))->toArray());
                    } else {
                        $this->userPermissions = array_merge($this->userPermissions, $rawUserPermissions);
                    }
                }
            } 

            if($this->accessScope === 'role') {

                if($remaingLevels = array_except($this->checkLevels, $this->roleLevels) and ($this->levelsModified === true)) {
                    throw new Exception(implode(array_keys($remaingLevels), ', '). " not allowed for role based check");
                } elseif($remaingLevels and ($this->levelsModified === 'upto')) {
                    throw new Exception("Using YesAuthority::checkUpto() with YesAuthority::viaRole() is not permitted");
                }

                $this->userRoleId = $requestForUserId;
            }

            if($roleModelString and is_string($roleModelString)) {
                $roleModel = new $roleModelString;
                $roleFound = $roleModel->findOrFail($this->userRoleId);
                $this->roleIdentified   = $roleFound->toArray();

                if($this->configColRolePermissions and __isEmpty(array_get($this->roleIdentified, $this->configColRolePermissions)) === false) {
            
                    $rawUserRolePermissions = array_get($this->roleIdentified, $this->configColRolePermissions);

                    if(is_array($rawUserRolePermissions) === false) {
                        $this->userRolePermissions = array_merge($this->userRolePermissions, collect(json_decode($rawUserRolePermissions))->toArray());
                    } else {
                        $this->userRolePermissions = array_merge($this->userRolePermissions, $rawUserRolePermissions);
                    }
                }
            }

            $this->dynamicAccessZones = array_get($this->permissions, 'dynamic_access_zones');
        }    
    }

    /**
      * Get the permission details of checks
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function withDetails()
    {
        $this->accessDetailsRequested = true;
        return $this;
    }  

    /**
      * Set the requested filter types for routes/keys/zones
      *
      * @return this
      *-----------------------------------------------------------------------*/
    private function setFilterTypes( $type = 'all')
    {
        $this->filterTypes = array_merge($this->filterTypes, [$type]);

        if(in_array('all', $this->filterTypes)) {
            $this->filterTypes = array_where($this->filterTypes, function ($value, $key) {
                return $value !== 'all';
            });
        }
        return $this;
    }      

    /**
      * Restrict result to denied only
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function takeDenied()
    {
       return $this->setFilterTypes('denied');
    }

    /**
      * Restrict result to public routes take
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function takePublic()
    {
        return $this->setFilterTypes('public');
    }                 

    /**
      * Restrict result to available take
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function takeAllowed()
    {
         return $this->setFilterTypes('allowed');
    }       

    /**
      * Choose items to checks from available $this->checkLevels
      *
      * @param array/string $levels
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function checkOnly($levels)
    {
        if(! is_array($levels)) {
            $levels = [$levels];
        }

        $this->checkLevels = array_only($this->checkLevels, $levels);
        $this->levelsModified = true;

        if(empty($this->checkLevels)) {
            throw new Exception("YesAuthority::checkOnly() invalid array parameter");
        }

        return $this;
    }

    /**
      * Check the permissions except give level keys from $this->checkLevels
      *
      * @param array/string  - $levels - level key
      *
      * @return this
      *-----------------------------------------------------------------------*/

    public function checkExcept($levels)
    {
        if(! is_array($levels)) {
            $levels = [$levels];
        }

        if(empty(array_only($this->checkLevels, $levels))) {
            throw new Exception("YesAuthority::checkExcept() invalid array parameter");
        }

        $this->checkLevels = array_except($this->checkLevels, $levels);
        $this->levelsModified = true;

        return $this;
    }    

    /**
      * Check the permissions till the given level
      *
      * @param string  - $level - level key
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function checkUpto($level)
    {
        if(! is_string($level)) {
            throw new Exception("YesAuthority::checkUpto() argument should be string");            
        }

        $this->checkLevel = $this->checkLevels[$level];
        $this->levelsModified = 'upto';

        return $this;
    } 

    /**
      * Check the permissions based on Role Id instead of user id
      *
      * @return this
      *-----------------------------------------------------------------------*/
    public function viaRole()
    {
        $this->accessScope = 'role';

        return $this;
    }      

    /**
     * This method use to check permissions
     *
     * @param string $accessIdKey
     * @param bool $configure
     * @param int/string $requestForUserId
     * @param array $options []
     *      
     * @return mixed
     *---------------------------------------------------------------- */
    public function check($accessIdKey = null, $configure = true, $requestForUserId = null, $options = [])
    {  
        $options = array_merge([
            'internal_details' => $this->accessDetailsRequested
            ], $options);

        $isAccess   = false;

        $accessDetailsRequired = $options['internal_details'];

        if($configure === null or $configure === true) {
            $this->configure($requestForUserId, $options);
        }

        // check if user is logged in
        if (($this->userIdentified === false)) {

            if($accessDetailsRequired === true) {

                $result = $this->detailsFormat(false, $accessIdKey, [
                        'response_code' => 511,
                        'message' => 'Authentication Required'
                    ]);

                if($this->isDirectChecked === true) {
                    $this->initialize();
                }

                return $result;
            }

            return false;

            /*return [
                'reaction_code' => 9,
                'message'       => __("Not Authenticated")
            ];*/
        }

        // if accessKeyId not set then route name will be used as access id key
        if(!$accessIdKey) {
            $accessIdKey = $this->currentRouteAccessId;
        }
        
       if(__isEmpty($this->permissions) and is_array($this->permissions) === false) {

            if($this->isDirectChecked === true) {
                $this->initialize();
            }

            return true;
        }
        /*
            If contains * then you may like to reverse test 
        */
        if(($this->isDirectChecked === true) and (str_contains($accessIdKey, '*'))) {

            $wildCardResult = $this->checkWildCard($accessIdKey, $configure, $requestForUserId, $options);

            if($accessDetailsRequired === true) {

                $result = $this->detailsFormat($wildCardResult, $accessIdKey);

                return $result;
            }

            return $wildCardResult;
        }

        if(!isset($this->accessStages[$accessIdKey])) {
            $this->accessStages[$accessIdKey] = [];
        }

        if($this->performLevelChecks(1)) {
            // check for permissions using roles
            $isAccess = $this->performChecks($isAccess, $accessIdKey, 
                array_get($this->permissions, 'rules.roles.'.$this->userRoleId.'.allow'), 
                array_get($this->permissions, 'rules.roles.'.$this->userRoleId.'.deny'),
                [
                    'check_level' => 'CONFIG_ROLE'
                ]
            );
        }


        if($this->performLevelChecks(2)) {
            // check for permissions using user permissions
            $isAccess = $this->performChecks($isAccess, $accessIdKey, 
                array_get($this->permissions, 'rules.users.'.$this->userId.'.allow'), 
                array_get($this->permissions, 'rules.users.'.$this->userId.'.deny'),
                [
                    'check_level' => 'CONFIG_USER'
                ]
            );
        }

        // Process Dynamic Permissions - 07 JUL 2017 - proposed for removal
       // $this->processDynamicPermissions($accessIdKey);  

       if($this->performLevelChecks(3)) {
            if($this->userRolePermissions and !empty($this->userRolePermissions)) {
                 // check for permissions using user custom permissions
                $isAccess = $this->performChecks($isAccess, $accessIdKey, 
                    array_get($this->userRolePermissions, 'allow'), 
                    array_get($this->userRolePermissions, 'deny'),
                    [
                        'check_level' => 'DB_ROLE'
                    ]
                );
            }
       }    

       if($this->performLevelChecks(4)) {
            if($this->userPermissions and !empty($this->userPermissions)) {
                 // check for permissions using user custom permissions
                $isAccess = $this->performChecks($isAccess, $accessIdKey, 
                    array_get($this->userPermissions, 'allow'), 
                    array_get($this->userPermissions, 'deny'),
                    [
                        'check_level' => 'DB_USER'
                    ]
                );
            }
       }  

        // if access is denied check if item has dependents which may allowed through
        if($isAccess === false and $this->dependentsAccessIds 
            and array_key_exists($accessIdKey, $this->dependentsAccessIds)) {

            $dependents = $this->dependentsAccessIds[$accessIdKey];

            if(__isEmpty($dependents) === false) {

                foreach ($dependents as $dependent) {
                    
                    if($this->performLevelChecks(1)) {                
                        // check for permissions using roles
                        $isAccess = $this->performChecks($isAccess, $dependent, 
                            array_get($this->permissions, 'rules.roles.'.$this->userRoleId.'.allow'), 
                            array_get($this->permissions, 'rules.roles.'.$this->userRoleId.'.deny'),
                            [
                                'check_level' => 'CONFIG_ROLE'
                            ]
                        );
                    }
                    
                    if($this->performLevelChecks(2)) {
                        // check for permissions using user permissions
                        $isAccess = $this->performChecks($isAccess, $dependent, 
                            array_get($this->permissions, 'rules.users.'.$this->userId.'.allow'), 
                            array_get($this->permissions, 'rules.users.'.$this->userId.'.deny'),
                            [
                                'check_level' => 'CONFIG_USER'
                            ]
                        );
                    }

                    if($this->performLevelChecks(3)) {
                        if($this->userRolePermissions and !empty($this->userRolePermissions)) {
                            // check for permissions using user permissions
                            $isAccess = $this->performChecks($isAccess, $dependent, 
                                array_get($this->userRolePermissions, 'allow'), 
                                array_get($this->userRolePermissions, 'deny'),
                                [
                                    'check_level' => 'DB_ROLE'
                                ]
                            );                        
                        }
                    }

                    if($this->performLevelChecks(4)) {
                        if($this->userPermissions and !empty($this->userPermissions)) {
                            // check for permissions using user permissions
                            $isAccess = $this->performChecks($isAccess, $dependent, 
                                array_get($this->userPermissions, 'allow'), 
                                array_get($this->userPermissions, 'deny'),
                                [
                                    'check_level' => 'DB_USER'
                                ]
                            );                        
                        }
                    }

                    // if access permitted not need to iterate further
                    if($isAccess === true) {
                        break;
                    }

                }
            }

        }

        if($this->performLevelChecks(5)) {
            // dynamic conditions if any 
            $conditionItems = array_get($this->permissions, 'rules.conditions');
            $index = 0;

            if(__isEmpty($conditionItems) === false and is_array($conditionItems)) {
                // check for declared conditionItems
                foreach ($conditionItems as $conditionItem) {
                    // get the access ids and condition
                    $conditionAccessIds = array_get($conditionItem, 'access_ids');
                    $condition          = array_get($conditionItem, 'condition') ?: null;
                    $uses               = array_get($conditionItem, 'uses') ?: $condition;
                    $name               = array_get($conditionItem, 'name') ?: 'condition_' . $index;

                    $index++;

                    // check if it exists
                    if((__isEmpty($conditionAccessIds) === false)) {

                        $isMatchFound = false;
                         // check of each access id
                        foreach ($conditionAccessIds as $conditionAccessId) {
                            // check for match
                            if(str_is($this->cleanIdKey($conditionAccessId), 
                                $accessIdKey)) {
                                $isMatchFound = true;
                                break;
                            }
                        } 
                        
                        $isConditionalAccess = $isAccess;     

                       // if match found
                       if(($isMatchFound === true) and $uses and is_string($uses)) {   

                            $uses = explode('@', $uses);
                            if(count($uses) !== 2) {
                                throw new Exception("YesAuthority invalid condition class configurations");                            
                            }

                            if(! class_exists($uses[0]) or ! method_exists($uses[0], $uses[1])) {
                                throw new Exception("YesAuthority invalid condition class or method configurations");
                            }

                            $executeCondition = new $uses[0]();
                            $isConditionalAccess = $executeCondition->$uses[1]($accessIdKey, $isAccess, $this->currentRouteAccessId);    
                       
                        } elseif(($isMatchFound === true) and is_callable($uses)) {                        
                            $isConditionalAccess = $uses($accessIdKey, $isAccess, $this->currentRouteAccessId);                           
                       } 

                        // expect boolean 
                        if(is_bool($isConditionalAccess) === true) {   

                            if(! isset($this->accessStages[$accessIdKey]['__conditions'])) {
                                $this->accessStages[$accessIdKey]['__conditions'] = [];
                            }

                            $this->accessStages[$accessIdKey]['__result'] = 'CONDITIONS';
                            $name = (array_key_exists($name, $this->accessStages[$accessIdKey]['__conditions'])) 
                                        ? $name.'_'.$index : $name;

                            $this->accessStages[$accessIdKey]['__conditions']['__result'] = $name;
                            $this->accessStages[$accessIdKey]['__conditions'][$name] = $isConditionalAccess;

                            $isAccess = $this->accessStages[$accessIdKey]['CONDITIONS'] = $isConditionalAccess;
                        }

                    }
                }
            }
        }

       if($isAccess === true) {

            if($accessDetailsRequired === true) {

                $result =  $this->detailsFormat(true, $accessIdKey);

                if($this->isDirectChecked === true) {
                    $this->initialize();
                }

                return $result;
            }

            if($this->isDirectChecked === true) {
                $this->initialize();
            }            

            return true;
        }

        $result = $this->detailsFormat(false, $accessIdKey);

        if(! $accessDetailsRequired) {
            return false;
        }

        if($this->isDirectChecked === true) {
            $this->initialize();
        }
        
        return $result;
    }

    /**
     * Check if route is allowed or not
     *
     * @param string $routeName
     * @param array $middleware     
     *
     * @return mixed
     *---------------------------------------------------------------- */
    protected function checkWildCard($accessIdKey = null, $configure = true, $requestForUserId = null, $options = [])
    {   
        $options = array_merge($options, [
                'ignore_details' => true,
                'internal_details' => true
            ]);

        $availableRoutes = $this->availableRoutes(false, $requestForUserId, $options);

        foreach ($availableRoutes as $route) {
            if(str_is($this->cleanIdKey($accessIdKey), $route) === true) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if route is allowed or not
     *
     * @param string $routeName
     * @param array $middleware     
     *
     * @return mixed
     *---------------------------------------------------------------- */
    protected function isRouteAvailable($routeName, $middleware, $configure = true, $requestForUserId = null, $options = [])
    {   
        $options = array_merge([
            'internal_details' => $this->accessDetailsRequested
            ], $options);

        if(in_array($this->middlewareName, $middleware)) {
            $getResult = $this->check($routeName, $configure, $requestForUserId, $options);

            if($options['internal_details'] === true) {
                return $getResult;
            }

            return  $getResult === true ?: false;
        }

        // set as public route
        $this->publicRoutes[] = $routeName;

        if($options['internal_details'] === true) {

            return $this->detailsFormat(true, $routeName, [
                    'is_public' => true,
                ]);
        }

        return true;        
    }

    /**
     * Get available available routes which consist of available & public routes
     *
     * @param bool $isUriRequired - if you required uri along with route names
     * @param string/int $requestForUserId - User other than logged in
     * @param array $options - []
     *
     * @return array
     *---------------------------------------------------------------- */
    public function availableRoutes($isUriRequired = false, $requestForUserId = null, $options = [])
    {
        return $this->takeAllowed()->takePublic()->getRoutes($isUriRequired, $requestForUserId, $options);
    }

    /**
     * Get routes
     *
     * @param bool $isUriRequired - if you required uri along with route names
     * @param string/int $requestForUserId - User other than logged in
     * @param array $options - []
     *
     * @return array
     *---------------------------------------------------------------- */
    public function getRoutes($isUriRequired = false, $requestForUserId = null, $options = [])
    {
        $options = array_merge([
                'ignore_details' => false,
                'internal_details' => true
            ], $options);

        // get all application routes.
        $routeCollection = Route::getRoutes();
        $routes = [];

        $this->isDirectChecked = false;

        $this->configure($requestForUserId, $options);

        // if routes found
        if (__isEmpty($routeCollection) === false) {
            // If routeName=>uri is required
            foreach ($routeCollection as $route) {
                $routeName = $route->getName();

                if($routeName) {

                    $getResult = $this->isRouteAvailable($routeName, $route->middleware(), false, $requestForUserId, $options);

                    if(($this->accessDetailsRequested === true) and ($options['ignore_details'] === false)) {

                        if(($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {
                            
                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                    'uri' => $route->uri()
                                ]);
                        } elseif(($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {
                            
                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                    'uri' => $route->uri()
                                ]);
                        } elseif(($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {
                            
                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                    'uri' => $route->uri()
                                ]);
                        } 

                    } else {

                        if(($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {
                                
                            if($isUriRequired) {
                                $routes[$routeName] = $route->uri();
                            } else {
                                $routes[] = $routeName;
                            }
                            
                        } elseif(($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {
                            
                            if($isUriRequired) {
                                $routes[$routeName] = $route->uri();
                            } else {
                                $routes[] = $routeName;
                            }
                            
                        } elseif(($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {
                            
                            if($isUriRequired) {
                                $routes[$routeName] = $route->uri();
                            } else {
                                $routes[] = $routeName;
                            }
                        }
                    }           
                } 
            }
        }

        unset($routeCollection);

        $this->initialize();

        return $routes;      
    }

    /**
     * Get all available zones
     * 
     * @param  $requestForUserId - user other than logged in 
     * @param  $options - []  
     *
     * @return array
     *---------------------------------------------------------------- */
    public function availableZones($requestForUserId = null, $options = [])
    {
        return $this->takeAllowed()->takePublic()->getZones($requestForUserId, $options);
    }

    /**
     * Get all zones
     * 
     * @param  $requestForUserId - user other than logged in 
     * @param  $options - []  
     *
     * @return array
     *---------------------------------------------------------------- */
    public function getZones($requestForUserId = null, $options = [])
    {
        $availableZones = [];

        $this->isDirectChecked = false;
        $options['internal_details'] = true;

        $this->configure($requestForUserId, $options);

        if(__isEmpty($this->dynamicAccessZones) === false) {            

            foreach ($this->dynamicAccessZones as $accessZone => $accessZoneContents) {                
                
                $getResult = $this->check($accessZone, false, $requestForUserId, $options);

                if($this->accessDetailsRequested === true) {

                        if(($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {
                            
                            $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                                'title' => $accessZoneContents['title'],
                                'is_zone' => true,
                            ]);

                        } elseif(($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {
                            
                            $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                                'title' => $accessZoneContents['title'],
                                'is_zone' => true,
                            ]);

                        } elseif(($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {
                            
                            $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                                'title' => $accessZoneContents['title'],
                                'is_zone' => true,
                            ]);
                        } 

                    } else {

                        if(($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {
                                
                            $availableZones[] = $accessZone;
                            
                        } elseif(($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {                         
                            $availableZones[] = $accessZone;
                            
                        } elseif(($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {            

                            $availableZones[] = $accessZone;
                        }
                    }  
            }
        }

        $this->initialize();

        return $availableZones;      
    }

    /**
     * Get all allowed/public routes
     *
     * @return array
     *---------------------------------------------------------------- */
    public function isPublicAccess($routeName = null, $requestForUserId = null)
    {

        if(!$routeName) {
            $routeName = Route::currentRouteName();
        }

        $this->availableRoutes($requestForUserId);

        return in_array($routeName, $this->publicRoutes);
    }

    /**
     * This method use for display breadCrumb.
     *
     * @param bool $initialAccess
     * @param string $accessIdKey
     * @param array $accessList
     * @param array $denyList               
     * 
     * @return mixed
     *---------------------------------------------------------------- */
    protected function performChecks($initialAccess, $accessIdKey, $accessList, $denyList = [], $options = [])
    {
        $isAccess = $initialAccess;
        $specific = null;
        $decisionStrength = [];

        if(!$accessList or !is_array($accessList)) {
            $accessList = [];
        }

        if(!$denyList or !is_array($denyList)) {
            $denyList = [];
        }

        if(__isEmpty($this->dynamicAccessZones) === false and (count($accessList) + count($denyList)) > 0) {

            $zoneAllowedAccessIds = [];
            $zoneDeniedAccessIds = [];

            $denyList = $denyList ?: [];

            foreach ($this->dynamicAccessZones as $accessZone => $accessZoneContents) {

                if(is_array($accessList) and in_array($accessZone, $accessList)) {
                    $zoneAllowedAccessIds = array_merge($zoneAllowedAccessIds, array_get($this->dynamicAccessZones[$accessZone], 'access_ids') ?: []);
                }

                if(is_array($denyList) and in_array($accessZone, $denyList)) {
                    $zoneDeniedAccessIds = array_merge($zoneDeniedAccessIds, array_get($this->dynamicAccessZones[$accessZone], 'access_ids') ?: []);
                }
            }

            $accessList = array_unique(array_merge($accessList, $zoneAllowedAccessIds));
            $denyList = array_unique(array_merge($denyList, array_diff($zoneDeniedAccessIds, $zoneAllowedAccessIds)));
        }

        // perform allowed check
        if(__isEmpty($accessList) === false and is_array($accessList)) {
            foreach ($accessList as $accessId) {

                // remove unnecessary wild-cards *
                $accessId = $this->cleanIdKey($accessId);

                if($accessId === $accessIdKey) {
                    $specific = 'allow';
                    break;
                }

                if(str_is($accessId, $accessIdKey) === true) {

                    $decisionStrength[strlen($accessId)] = $isAccess =  true;

                }
            }
        }

        //perform deny check
        if(__isEmpty($denyList) === false and is_array($denyList)) {
            foreach ($denyList as $denyId) {

                // remove unnecessary wild-cards *
                $denyId = $this->cleanIdKey($denyId);

                if($denyId === $accessIdKey) {
                    $specific = 'deny';
                    break;
                }

                if(str_is($denyId, $accessIdKey) === true) {

                    $decisionStrength[strlen($denyId)] = $isAccess =  false;

                }                
            }
        }

        if(is_array($this->dynamicAccessZones) and array_key_exists($accessIdKey, $this->dynamicAccessZones)) {
            $this->accessStages[$accessIdKey]['__data'] = [
                'is_zone' => true,
                'title' => $this->dynamicAccessZones[$accessIdKey]['title']
            ];
        }
        
        // if it specific item then its important
        if($specific) {
            $this->accessStages[$accessIdKey][$options['check_level']] =  ($specific === 'allow') ? true : false;
            $this->accessStages[$accessIdKey]['__result'] = $options['check_level'];
            return $this->accessStages[$accessIdKey][$options['check_level']];
        }

        if(empty($decisionStrength) === false) {
            $this->accessStages[$accessIdKey]['__result'] = $options['check_level'];
            return $this->accessStages[$accessIdKey][$options['check_level']] =  $decisionStrength[max(array_keys($decisionStrength))];
        }

        return $isAccess;
    }

    /**
     * Details format
     *
     * @param string $idKey
     * 
     * @return string
     *---------------------------------------------------------------- */
    protected function detailsFormat($isAccess, $accessIdKey, $options = []) {

        if(!empty($this->accessStages[$accessIdKey])) {
            $itemData = array_pull($this->accessStages[$accessIdKey], '__data');

            if(is_array($itemData) and !empty($itemData)) {
                $options = array_merge($options, $itemData);
            }
        }

        if($isAccess instanceof YesAuthorityResult) {

            foreach ($options as $key => $value) {
                $isAccess->{$key} = $value;
            }

            return $isAccess;
        }

        $options = array_merge([
            'response_code' => $isAccess ? 200 : 401,
            'message' => $isAccess ? 'OK' : 'Unauthorized',
        ], $options);

        $conditionsIfAny = [];
        $conditionResult = null;

        $resultBy = __ifIsset($this->accessStages[$accessIdKey], function() use (&$accessIdKey, &$conditionsIfAny, &$conditionResult) {
                        $conditionsIfAny = array_pull($this->accessStages[$accessIdKey], '__conditions');
                return array_pull($this->accessStages[$accessIdKey], '__result');
            }, null);

        if(! empty($conditionsIfAny)) {
            $conditionResult = array_pull($conditionsIfAny, '__result');
        }        
        
        $parentLevel = null;
        // find parent level item
        if($resultBy ) {
            foreach (array_reverse($this->accessStages[$accessIdKey]) as $key => $value) {
                $levelKeyId = $this->checkLevels[$key];
                $resultKeyId = $this->checkLevels[$resultBy];
                if(($levelKeyId < $resultKeyId) and !$parentLevel) {
                    $parentLevel = $key;
                    break;
                } 
            }
        }

        $result = new YesAuthorityResult([
            'response_code' => $options['response_code'],
            'message' => $options['message'],
            'is_access' => $isAccess,
            'result_by' => $resultBy,
            'upper_level' => $parentLevel,
            'condition_result_by' => $conditionResult,
            'conditions_checked' => $conditionsIfAny,
            'levels_checked' => __ifIsset($this->accessStages[$accessIdKey], true, []),
            'access_id_key' => $accessIdKey,
            'title' => __ifIsset($options['title'], true, null),
            'is_public' => isset($options['is_public']) ? $options['is_public'] : false,
            'is_zone' => __ifIsset($options['is_zone'], true),
        ], [
           'check_levels' => $this->checkLevels
        ]);


        unset($options, $accessIdKey, $isAccess, $this->accessStages, $resultBy, $parentLevel, $conditionsIfAny, $conditionResult);

        return $result;
        
    }

    /**
     * Reset basic settings
     *
     * @param string $idKey
     * 
     * @return string
     *---------------------------------------------------------------- */
    private function initialize() {

        $this->checkLevel = 99;
        $this->checkLevels = [
            'CONFIG_ROLE'   => 1, // Config Role
            'CONFIG_USER'   => 2, // Config User
            'DB_ROLE'       => 3, // DB Role
            'DB_USER'       => 4, // DB User
            'CONDITIONS'     => 5, // Conditions
        ];

        $this->customPermissions = false;
        $this->accessDetailsRequested = false;    
        $this->accessScope = 'user';    
        $this->isDirectChecked = true;
        $this->levelsModified = false;
        $this->filterTypes = ['all'];
    }

    /**
     * Remove extra * from string
     *
     * @param string $idKey
     * 
     * @return string
     *---------------------------------------------------------------- */
    protected function cleanIdKey($idKey) {
         // remove unnecessary wild-cards *
        return preg_replace('/\*+/', '*', $idKey);
    }

    /**
     * Check the levels
     *
     * @param int $idKey
     * 
     * @return bool
     *---------------------------------------------------------------- */
    protected function performLevelChecks($level = 99) {
        return ($this->checkLevel >= $level) and in_array($level, $this->checkLevels);
    }
}