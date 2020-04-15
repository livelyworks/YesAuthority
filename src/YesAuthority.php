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
        Store guest only routes process
    */
    protected $guestOnlyRoutes = [];
    protected $processPreCheckPost = false;

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
     * @var string
     */
    protected $middlewareName = "authority.checkpost";

    /**
     * Pre Checkpost Middleware name
     *
     * @var string
     */
    protected $preCheckpostMiddlewareName = "authority.pre.checkpost";

    /**
     * Authority Configurations
     *
     * @var mixed
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
    protected $isAccessIdsArray = false;
    protected $roleLevels = [
        0 => 'CONFIG_BASE',
        1 => 'CONFIG_ROLE',
        3 => 'DB_ROLE'
    ];

    protected $configEntity = null;
    protected $entityPermissions = [];
    protected $entityIdentified = [];
    protected $userRequestForEntity = null;
    protected $pseudoAccessIds = [];
    protected $requestCheckStringId = '';
    protected $accessResultContainer = [];

    protected $defaultAllowedAccessIds = [];
    protected $uniqueIdKeyString = null;

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
        // if file is stored somewhere else
        $customConfigPath = array_get($this->permissions, 'custom_config_path');
        if ($customConfigPath) {
            $this->permissions = require $customConfigPath;
        }

        $this->requestCheckStringId = '';
        $this->isAccessIdsArray = false;
        $this->userId = null;
        $this->accessResultContainer = [];
    }
    /**
     * configure
     *
     *
     * @return void
     *-----------------------------------------------------------------------*/
    protected function configure($requestForUserId = null, $options = [])
    {
        if (isEmpty($this->permissions) and is_array($this->permissions) === false) {
            throw new Exception('YesAuthority - permissions empty. Please check your YesAuthority configurations.');
        }

        if ($this->configEntity and !empty($this->configEntity) and $requestForUserId) {
            throw new Exception('YesAuthority - use requestForUserId via checkEntity method.');
        }

        if ($this->userRequestForEntity) {
            $requestForUserId = $this->userRequestForEntity;
        }

        if ($requestForUserId) {
            $this->userIdentified = true;
            $requestForUserId = is_numeric($requestForUserId) ? (int) $requestForUserId :  $requestForUserId;
        } else {
            $this->userIdentified = Auth::check() ?: false;
        }

        $this->currentRouteAccessId = Route::currentRouteName();
        // check of roles has permissions by extending another role
        $rules = array_get($this->permissions, 'rules.roles', []);
        if (!empty($rules)) {
            // loop for each role rule
            foreach ($rules as $ruleKey => $ruleValue) {
                // extend permissions by roles
                $this->extendRolePermissions($ruleKey);
            }
            // unset unnecessary
            unset($rules);
        }
        $this->userRolePermissions = [];
        $this->yesConfig          = array_get($this->permissions, 'config');
        $this->configColRole      = array_get($this->yesConfig, 'col_role');
        $this->configColUserId    = array_get($this->yesConfig, 'col_user_id');
        $this->configColRoleId    = array_get($this->yesConfig, 'col_role_id', $this->configColUserId);

        $this->dependentsAccessIds      = array_get($this->permissions, 'dependents');
        $userModelString          = array_get($this->yesConfig, 'user_model');
        $userModelWhereClouses          = array_get($this->yesConfig, 'user_model_where');
        $roleModelString          = array_get($this->yesConfig, 'role_model');
        $this->pseudoAccessIds    = array_get($this->yesConfig, 'pseudo_access_ids', []);
        $this->defaultAllowedAccessIds = array_get($this->yesConfig, 'default_allowed_access_ids', []);

        if (isEmpty($this->yesConfig) or isEmpty($this->configColRole) or isEmpty($this->configColUserId)) {
            throw new Exception('YesAuthority - config item should contain col_role, col_user_id');
        }

        $userModelWhereClousesContainer = [];
        if ($userModelWhereClouses and is_array($userModelWhereClouses)) {
            foreach ($userModelWhereClouses as $userModelWhereClouseKey => $userModelWhereClouseValue) {
                $userModelWhereClousesContainer[$userModelWhereClouseKey]
                    = is_callable($userModelWhereClouseValue) ? $userModelWhereClouseValue() : $userModelWhereClouseValue;
            }
        }

        $this->middlewareName = array_get($this->yesConfig, 'middleware_name')
            ?: $this->middlewareName;

        $this->preCheckpostMiddlewareName = array_get($this->yesConfig, 'pre_checkpost_middleware_name')
            ?: $this->preCheckpostMiddlewareName;

        if ($requestForUserId and ($this->accessScope === 'user')) {

            if (!is_string($userModelString)) {
                throw new Exception('YesAuthority - Please set key for user_model in config');
            }

            if (!class_exists($userModelString)) {
                throw new Exception('YesAuthority - User model does not exist.');
            }

            $userModel = new $userModelString;
            //$userFound = $userModel->findOrFail($requestForUserId);
            if (is_array($requestForUserId)) {
                $userFound = $userModel->where(array_merge(
                    $userModelWhereClousesContainer,
                    $requestForUserId
                ))->first();
            } else {
                $userFound = $userModel->where(array_merge(
                    [
                        $this->configColUserId => $requestForUserId
                    ],
                    $userModelWhereClousesContainer
                ))->first();
            }
            $this->userIdentified   = $userFound->toArray();
        }

        if ($this->userIdentified) {

            $this->configColPermissions = array_get($this->yesConfig, 'col_user_permissions');
            $this->configColRolePermissions = array_get($this->yesConfig, 'col_role_permissions') ?: $this->configColPermissions;

            if ($this->accessScope !== 'role') {
                if (!$requestForUserId) {
                    // consider custom user model even if user is logged in for permissions
                    if (is_string($userModelString)) {
                        if (!class_exists($userModelString)) {
                            throw new Exception('YesAuthority - User model does not exist.');
                        }
                        $userModel = new $userModelString;
                        $userFound = $userModel->where(
                            array_merge([
                                $this->configColUserId => Auth::id()
                            ], $userModelWhereClousesContainer)
                        )->first();
                        $this->userIdentified   = $userFound->toArray();
                    } else {
                        $this->userIdentified  = Auth::user()->toArray();
                    }
                }

                $this->userRoleId     = array_get($this->userIdentified, $this->configColRole);
                $this->userId         = array_get($this->userIdentified, $this->configColUserId);

                if ($this->configColPermissions and isEmpty(array_get($this->userIdentified, $this->configColPermissions)) === false) {

                    $rawUserPermissions = array_get($this->userIdentified, $this->configColPermissions);

                    if (is_array($rawUserPermissions) === false) {
                        $this->userPermissions = array_merge($this->userPermissions, json_decode($rawUserPermissions, true)->toArray());
                    } else {
                        $this->userPermissions = array_merge($this->userPermissions, $rawUserPermissions);
                    }
                }
            }

            if ($this->accessScope === 'role') {

                if ($remaingLevels = array_except($this->checkLevels, $this->roleLevels) and ($this->levelsModified === true)) {
                    throw new Exception(implode(', ', array_keys($remaingLevels)) . ' not allowed for role based check');
                } elseif ($remaingLevels and ($this->levelsModified === 'upto')) {
                    throw new Exception('Using YesAuthority::checkUpto() with YesAuthority::viaRole() is not permitted');
                }


                $this->userRoleId = $requestForUserId;
            }

            if ($roleModelString and is_string($roleModelString)) {
                $roleModel = new $roleModelString;
                $roleFound = $roleModel->findOrFail($this->userRoleId);
                $this->roleIdentified   = $roleFound->toArray();

                if ($this->configColRolePermissions and isEmpty(array_get($this->roleIdentified, $this->configColRolePermissions)) === false) {

                    $rawUserRolePermissions = array_get($this->roleIdentified, $this->configColRolePermissions);

                    if (is_array($rawUserRolePermissions) === false) {
                        $this->userRolePermissions = array_merge($this->userRolePermissions, json_decode($rawUserRolePermissions, true));
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
        $this->requestCheckStringId .= '_wd';
        $this->accessDetailsRequested = true;
        return $this;
    }

    /**
     * Set the requested filter types for routes/keys/zones
     *
     * @return this
     *-----------------------------------------------------------------------*/
    private function setFilterTypes($type = 'all')
    {
        $this->filterTypes = array_merge($this->filterTypes, [$type]);

        if (in_array('all', $this->filterTypes)) {
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
    protected function processPreCheckpostIds()
    {
        $this->processPreCheckPost = true;
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
        if (!is_array($levels)) {
            $levels = [$levels];
        }

        array_unshift($levels, 'CONFIG_BASE');

        $this->checkLevels = array_only($this->checkLevels, $levels);
        $this->levelsModified = true;

        if (empty($this->checkLevels)) {
            throw new Exception('YesAuthority::checkOnly() invalid array parameter'
                . implode(', ', array_keys($this->checkLevels)) . ' are accepted');
        }

        $this->requestCheckStringId .= '_co_' . implode('_level_', $levels);

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
        if (!is_array($levels)) {
            $levels = [$levels];
        }

        array_unshift($levels, 'CONFIG_BASE');

        if (empty(array_only($this->checkLevels, $levels))) {
            throw new Exception('YesAuthority::checkExcept() Invalid array parameter, '
                . implode(', ', array_keys($this->checkLevels)) . ' are accepted');
        }

        $this->checkLevels = array_except($this->checkLevels, $levels);
        $this->levelsModified = true;

        $this->requestCheckStringId .= '_ce_' . implode('_level_', $levels);

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
        if (!is_string($level)) {
            throw new Exception("YesAuthority::checkUpto() - $level - argument should be string");
        }

        if (!array_key_exists($level, $this->checkLevels)) {
            throw new Exception(
                "YesAuthority::checkUpto() - Invalid key $level, Only "
                    . implode(', ', array_keys($this->checkLevels)) . ' are accepted'
            );
        }

        $this->checkLevel = $this->checkLevels[$level];
        $this->levelsModified = 'upto';

        $this->requestCheckStringId .= '_cu_level_' . $level;

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

        $this->requestCheckStringId .= '_vr';

        return $this;
    }

    /**
     * This method use to check permissions
     *
     * @param string $accessIdKey
     * @param int/string $requestForUserId
     * @param array $options []
     *      
     * @return mixed
     *---------------------------------------------------------------- */
    public function check($accessIdKey = null, $requestForUserId = null, array $options = [])
    {
        $this->isAccessIdsArray = false;
        $options = array_merge([
            'internal_details' => $this->accessDetailsRequested,
            'configure' => true,
            'isAccessIdsArray' => false
        ], $options);

        $isAccess   = false;

        $accessDetailsRequired = $options['internal_details'];

        if ($options['configure'] === null or $options['configure'] === true) {
            $this->configure($requestForUserId, $options);
        }
        // if multiple access id/keys
        if (is_array($accessIdKey)) {

            $accessResultArray = [];
            // remove duplicates
            $accessIdKey = array_unique($accessIdKey);
            // no need to reconfigure it
            $options['configure'] = false;
            $this->isAccessIdsArray = true;
            $options['isAccessIdsArray'] = true;
            // check each key for the access
            foreach ($accessIdKey as $accessIdKeyItem) {
                $accessResultArray[$accessIdKeyItem] = $this->check(
                    $accessIdKeyItem,
                    $requestForUserId,
                    $options
                );
            }
            $this->isAccessIdsArray = false;
            // reset identification
            $this->requestCheckStringId = '';
            $this->initialize();
            return $accessResultArray;
        }

        $this->uniqueIdKeyString = $this->generateUniqueIdKeyString($accessIdKey, $requestForUserId, $options);

        // try to retrieve already checked item 
        $existingUniqueIdItem = array_get(
            $this->accessResultContainer,
            $this->uniqueIdKeyString,
            null
        );
        // if found return that same
        if ($existingUniqueIdItem) {
            return $existingUniqueIdItem['result'];
        }

        // check if user is logged in
        if (($this->userIdentified === false)) {

            if ($accessDetailsRequired === true) {

                $result = $this->detailsFormat(false, $accessIdKey, [
                    'response_code' => 403,
                    'message' => 'Forbidden - Authentication Required'
                ]);

                if ($this->isDirectChecked === true) {
                    $this->initialize();
                }

                return $this->processResult($accessIdKey, $requestForUserId, $result, $options);
            }

            return $this->processResult($accessIdKey, $requestForUserId, false, $options);
        }

        // if accessKeyId not set then route name will be used as access id key
        if (!$accessIdKey) {
            $accessIdKey = $this->currentRouteAccessId;
        }
        // accessIdKey should be there
        if (!$accessIdKey) {
            throw new Exception('YesAuthority - AccessIdKey/RouteName is missing');
        }

        if (isEmpty($this->permissions) and is_array($this->permissions) === false) {

            if ($this->isDirectChecked === true) {
                $this->initialize();
            }

            return $this->processResult($accessIdKey, $requestForUserId, true, $options);
        }

        if (!is_string($accessIdKey)) {
            throw new Exception('YesAuthority - Invalid AccessIdKey parameter for check');
        }

        // allow if the access id allowed default
        if (in_array($accessIdKey, $this->defaultAllowedAccessIds) === true) {

            if ($accessDetailsRequired === true) {
                $result = $this->detailsFormat(true, $accessIdKey, [
                    'override_result_by' => 'DEFAULT_ALLOWED'
                ]);
                return $this->processResult($accessIdKey, $requestForUserId, $result, $options);
            }
            return $this->processResult($accessIdKey, $requestForUserId, true, $options);
        }

        /*
            If contains * then you may like to reverse test
        */
        if (($this->isDirectChecked === true) and (str_contains($accessIdKey, '*'))) {

            $wildCardResult = $this->checkWildCard($accessIdKey, $requestForUserId, $options);

            if ($accessDetailsRequired === true) {

                $result = $this->detailsFormat($wildCardResult, $accessIdKey);

                return $this->processResult($accessIdKey, $requestForUserId, $result, $options);
            }

            return $this->processResult($accessIdKey, $requestForUserId, $wildCardResult, $options);
        }

        if (!isset($this->accessStages[$this->uniqueIdKeyString])) {
            $this->accessStages[$this->uniqueIdKeyString] = [];
        }

        if (array_get($this->permissions, 'rules.base')) {
            $isAccess = $this->performChecks(
                $isAccess,
                $accessIdKey,
                array_get($this->permissions, 'rules.base.allow'),
                array_get($this->permissions, 'rules.base.deny'),
                [
                    'check_level' => 'CONFIG_BASE'
                ]
            );
        }

        if ($this->performLevelChecks(1)) {
            // check for permissions using roles
            $isAccess = $this->performChecks(
                $isAccess,
                $accessIdKey,
                array_get($this->permissions, 'rules.roles.' . $this->userRoleId . '.allow'),
                array_get($this->permissions, 'rules.roles.' . $this->userRoleId . '.deny'),
                [
                    'check_level' => 'CONFIG_ROLE'
                ]
            );
        }


        if ($this->performLevelChecks(2)) {
            // check for permissions using user permissions
            $isAccess = $this->performChecks(
                $isAccess,
                $accessIdKey,
                array_get($this->permissions, 'rules.users.' . $this->userId . '.allow'),
                array_get($this->permissions, 'rules.users.' . $this->userId . '.deny'),
                [
                    'check_level' => 'CONFIG_USER'
                ]
            );
        }

        // Process Dynamic Permissions - 07 JUL 2017 - proposed for removal
        // $this->processDynamicPermissions($accessIdKey);

        if ($this->performLevelChecks(3)) {
            if ($this->userRolePermissions and !empty($this->userRolePermissions)) {
                // check for permissions using user custom permissions
                $isAccess = $this->performChecks(
                    $isAccess,
                    $accessIdKey,
                    array_get($this->userRolePermissions, 'allow'),
                    array_get($this->userRolePermissions, 'deny'),
                    [
                        'check_level' => 'DB_ROLE'
                    ]
                );
            }
        }

        if ($this->performLevelChecks(4)) {
            if ($this->userPermissions and !empty($this->userPermissions)) {
                // check for permissions using user custom permissions
                $isAccess = $this->performChecks(
                    $isAccess,
                    $accessIdKey,
                    array_get($this->userPermissions, 'allow'),
                    array_get($this->userPermissions, 'deny'),
                    [
                        'check_level' => 'DB_USER'
                    ]
                );
            }
        }

        // if access is denied check if item has dependents which may allowed through
        if (
            $isAccess === false and $this->dependentsAccessIds
            and array_key_exists($accessIdKey, $this->dependentsAccessIds)
        ) {

            $dependents = $this->dependentsAccessIds[$accessIdKey];

            if (isEmpty($dependents) === false) {

                foreach ($dependents as $dependent) {

                    if ($this->performLevelChecks(1)) {
                        // check for permissions using roles
                        $isAccess = $this->performChecks(
                            $isAccess,
                            $dependent,
                            array_get($this->permissions, 'rules.roles.' . $this->userRoleId . '.allow'),
                            array_get($this->permissions, 'rules.roles.' . $this->userRoleId . '.deny'),
                            [
                                'check_level' => 'CONFIG_ROLE'
                            ]
                        );
                    }

                    if ($this->performLevelChecks(2)) {
                        // check for permissions using user permissions
                        $isAccess = $this->performChecks(
                            $isAccess,
                            $dependent,
                            array_get($this->permissions, 'rules.users.' . $this->userId . '.allow'),
                            array_get($this->permissions, 'rules.users.' . $this->userId . '.deny'),
                            [
                                'check_level' => 'CONFIG_USER'
                            ]
                        );
                    }

                    if ($this->performLevelChecks(3)) {
                        if ($this->userRolePermissions and !empty($this->userRolePermissions)) {
                            // check for permissions using user permissions
                            $isAccess = $this->performChecks(
                                $isAccess,
                                $dependent,
                                array_get($this->userRolePermissions, 'allow'),
                                array_get($this->userRolePermissions, 'deny'),
                                [
                                    'check_level' => 'DB_ROLE'
                                ]
                            );
                        }
                    }

                    if ($this->performLevelChecks(4)) {
                        if ($this->userPermissions and !empty($this->userPermissions)) {
                            // check for permissions using user permissions
                            $isAccess = $this->performChecks(
                                $isAccess,
                                $dependent,
                                array_get($this->userPermissions, 'allow'),
                                array_get($this->userPermissions, 'deny'),
                                [
                                    'check_level' => 'DB_USER'
                                ]
                            );
                        }
                    }

                    // if access permitted not need to iterate further
                    if ($isAccess === true) {
                        break;
                    }
                }
            }
        }

        if ($this->performLevelChecks(5)) {
            if ($this->configEntity) {
                if ($this->entityPermissions and !empty($this->entityPermissions)) {
                    // check for permissions using custom entities permissions
                    $isAccess = $this->performChecks(
                        $isAccess,
                        $accessIdKey,
                        array_get($this->entityPermissions, 'allow'),
                        array_get($this->entityPermissions, 'deny'),
                        [
                            'check_level' => 'DB_ENTITY'
                        ]
                    );
                }

                $entityCondition = array_get($this->configEntity, 'condition');
                if ($this->performLevelChecks(6) and $entityCondition and is_callable($entityCondition)) {
                    $entityConditionIsAccess = $entityCondition(
                        $accessIdKey,
                        $isAccess,
                        $this->currentRouteAccessId,
                        $this->entityIdentified,
                        $this->userIdentified
                    );

                    if ((is_bool($entityConditionIsAccess) === true)) {
                        $this->accessStages[$this->uniqueIdKeyString]['__result'] = 'ENTITY_CONDITION';
                        $isAccess = $this->accessStages[$this->uniqueIdKeyString]['ENTITY_CONDITION'] = $entityConditionIsAccess;
                    }
                }
            }
        }

        if ($this->performLevelChecks(7)) {
            // dynamic conditions if any
            $conditionItems = array_get($this->permissions, 'rules.conditions');
            $index = 0;

            if (isEmpty($conditionItems) === false and is_array($conditionItems)) {
                // check for declared conditionItems
                foreach ($conditionItems as $conditionItem) {
                    // get the access ids and condition
                    $conditionAccessIds = array_get($conditionItem, 'access_ids');
                    $condition          = array_get($conditionItem, 'condition') ?: null;
                    $uses               = array_get($conditionItem, 'uses') ?: $condition;
                    $name               = array_get($conditionItem, 'name') ?: 'condition_' . $index;

                    $index++;

                    // check if it exists
                    if ((isEmpty($conditionAccessIds) === false)) {

                        $isMatchFound = false;
                        // check of each access id
                        foreach ($conditionAccessIds as $conditionAccessId) {
                            // check for match
                            if (str_is(
                                $this->cleanIdKey($conditionAccessId),
                                $accessIdKey
                            )) {
                                $isMatchFound = true;
                                break;
                            }
                        }

                        $isConditionalAccess = $isAccess;

                        // if match found
                        if (($isMatchFound === true) and $uses and is_string($uses)) {

                            $uses = explode('@', $uses);
                            if (count($uses) !== 2) {
                                throw new Exception('YesAuthority invalid condition class configurations');
                            }

                            if (!class_exists($uses[0]) or !method_exists($uses[0], $uses[1])) {
                                throw new Exception('YesAuthority invalid condition class or method configurations');
                            }

                            $executeCondition = new $uses[0]();
                            $isConditionalAccess = $executeCondition->$uses[1]($accessIdKey, $isAccess, $this->currentRouteAccessId);
                        } elseif (($isMatchFound === true) and $uses and is_callable($uses)) {
                            $isConditionalAccess = $uses($accessIdKey, $isAccess, $this->currentRouteAccessId);
                        }

                        // expect boolean
                        if (($isMatchFound === true) and $uses and (is_bool($isConditionalAccess) === true)) {

                            if (!isset($this->accessStages[$this->uniqueIdKeyString]['__conditions'])) {
                                $this->accessStages[$this->uniqueIdKeyString]['__conditions'] = [];
                            }

                            $this->accessStages[$this->uniqueIdKeyString]['__result'] = 'CONDITIONS';
                            $name = (array_key_exists($name, $this->accessStages[$this->uniqueIdKeyString]['__conditions']))
                                ? $name . '_' . $index : $name;

                            $this->accessStages[$this->uniqueIdKeyString]['__conditions']['__result'] = $name;
                            $this->accessStages[$this->uniqueIdKeyString]['__conditions'][$name] = $isConditionalAccess;

                            $isAccess = $this->accessStages[$this->uniqueIdKeyString]['CONDITIONS'] = $isConditionalAccess;
                        }
                    }
                }
            }
        }

        if ($isAccess === true) {

            if ($accessDetailsRequired === true) {

                $result =  $this->detailsFormat(true, $accessIdKey);

                if ($this->isDirectChecked === true) {
                    $this->initialize();
                }

                return $this->processResult($accessIdKey, $requestForUserId, $result, $options);
            }

            if ($this->isDirectChecked === true) {
                $this->initialize();
            }

            return $this->processResult($accessIdKey, $requestForUserId, true, $options);
        }

        $result = $this->detailsFormat(false, $accessIdKey);

        if (!$accessDetailsRequired) {
            return $this->processResult($accessIdKey, $requestForUserId, false, $options);
        }

        if ($this->isDirectChecked === true) {
            $this->initialize();
        }

        return $this->processResult($accessIdKey, $requestForUserId, $result, $options);
    }

    /**
     * Process the result item
     *
     * @param string $accessIdKey  
     * @param string|int $requestForUserId  
     * @param mixed  $accessIdKeyResult 
     *
     * @return mixed
     *---------------------------------------------------------------- */
    protected function processResult($accessIdKey, $requestForUserId, $accessIdKeyResult, $options = [])
    {
        // store the result for later use.
        if (is_string($accessIdKey)) {

            $this->accessResultContainer[$this->uniqueIdKeyString] = [
                'access_id_key' => $accessIdKey,
                'result' => $accessIdKeyResult,
            ];
        }
        if ($options['isAccessIdsArray'] == false) {
            // reset the requestCheckStringId
            $this->requestCheckStringId = '';
        }
        // let return the actual result
        return $accessIdKeyResult;
    }

    /**
     * Create unique key 
     *
     * @param string $accessIdKey  
     * @param string|int $requestForUserId  
     *
     * @return mixed
     *---------------------------------------------------------------- */
    protected function generateUniqueIdKeyString($accessIdKey, $requestForUserId, $options = [])
    {
        return strtolower(str_replace('.', '_', $accessIdKey)
            . '_'
            . (($options['internal_details']) ? '_ird_' : '')
            . ($requestForUserId ?: $this->userId)
            . $this->requestCheckStringId);
    }

    /**
     * Get Access Result log result
     *
     * @return mixed
     *---------------------------------------------------------------- */
    public function accessResultLog()
    {
        return $this->accessResultContainer;
    }

    /**
     * Check if route is allowed or not
     *
     * @param string $routeName
     * @param array $middleware     
     *
     * @return mixed
     *---------------------------------------------------------------- */
    protected function checkWildCard($accessIdKey = null, $requestForUserId = null, array $options = [])
    {
        $options = array_merge($options, [
            'ignore_details' => true,
            'internal_details' => true,
            'configure' => true
        ]);

        $availableRoutes = $this->availableRoutes(false, $requestForUserId, $options);

        foreach ($availableRoutes as $route) {
            if (str_is($this->cleanIdKey($accessIdKey), $route) === true) {
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
    protected function isRouteAvailable($routeName, $middleware, $requestForUserId = null, array $options = [])
    {
        $options = array_merge([
            'internal_details' => $this->accessDetailsRequested,
            'configure' => true
        ], $options);

        if (in_array($this->middlewareName, $middleware)) {
            $getResult = $this->check($routeName, $requestForUserId, $options);

            if ($options['internal_details'] === true) {
                return $getResult;
            }

            return  $getResult === true ?: false;
        }
        // Filter guest only routes
        if (in_array($this->preCheckpostMiddlewareName, $middleware)) {

            if ($this->userIdentified) {

                $this->guestOnlyRoutes[] = $routeName;

                if ($options['internal_details'] === true) {

                    return $this->detailsFormat(false, $routeName, [
                        'is_public' => true,
                    ]);
                }

                return false;
            } else {

                if ($options['internal_details'] === true) {

                    return $this->detailsFormat(true, $routeName, [
                        'is_public' => true,
                    ]);
                }

                return true;
            }
        }

        // set as public route
        $this->publicRoutes[] = $routeName;

        if ($options['internal_details'] === true) {

            return $this->detailsFormat(true, $routeName, [
                'is_public' => true,
            ]);
        }

        return true;
    }

    /**
     * Merge the allowed pseudo routes/accessIds 
     *
     * @param array $routes - routes array
     * @param string/int $requestForUserId - User other than logged in
     * @param array $options - []
     *     
     * @return array
     *---------------------------------------------------------------- */
    protected function mergePseudoAllowedAccessIds($routes, $requestForUserId = null, array $options = [])
    {
        $options = array_merge([
            'ignore_details' => false,
            'internal_details' => false,
            'configure' => false
        ], $options);

        $allowedPseudoAccessIds = [];
        foreach ($this->pseudoAccessIds as $pseudoAccessId) {
            if ($this->check($pseudoAccessId, $requestForUserId, $options) === true) {
                $allowedPseudoAccessIds[] = $pseudoAccessId;
            }
        }

        return array_merge($allowedPseudoAccessIds, $routes);
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
    public function availableRoutes($isUriRequired = false, $requestForUserId = null, array $options = [])
    {
        $routes =  $this->processPreCheckpostIds()->takeAllowed()->takePublic()->getRoutes($isUriRequired, $requestForUserId, $options);

        return $this->mergePseudoAllowedAccessIds($routes, $requestForUserId, $options);
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
    public function getRoutes($isUriRequired = false, $requestForUserId = null, array $options = [])
    {
        $options = array_merge([
            'ignore_details' => false,
            'internal_details' => true,
            'configure' => false
        ], $options);

        // get all application routes.
        $routeCollection = Route::getRoutes();
        $routes = [];

        $this->isDirectChecked = false;

        $this->configure($requestForUserId, $options);

        // if routes found
        if (isEmpty($routeCollection) === false) {
            // If routeName=>uri is required
            foreach ($routeCollection as $route) {
                $routeName = $route->getName();

                if ($routeName) {

                    $getResult = $this->isRouteAvailable($routeName, $route->middleware(), $requestForUserId, $options);

                    if (($this->accessDetailsRequested === true) and ($options['ignore_details'] === false)) {

                        if (($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {

                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                'uri' => $route->uri()
                            ]);
                        } elseif (($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {

                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                'uri' => $route->uri()
                            ]);
                        } elseif (($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {

                            $routes[] = $this->detailsFormat($getResult, $routeName, [
                                'uri' => $route->uri()
                            ]);
                        }
                    } else {

                        if (($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {

                            if ($isUriRequired) {
                                $routes[$routeName] = $route->uri();
                            } else {
                                $routes[] = $routeName;
                            }
                        } elseif (($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {

                            if ($isUriRequired) {
                                $routes[$routeName] = $route->uri();
                            } else {
                                $routes[] = $routeName;
                            }
                        } elseif (($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {

                            if ($isUriRequired) {
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

        // check if pre check post needed or not
        if ($this->processPreCheckPost === true) {
            if ($isUriRequired) {
                return array_diff_key($routes, array_flip($this->guestOnlyRoutes));
            } else {
                return array_diff($routes, $this->guestOnlyRoutes);
            }
        }

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
        $options = array_merge([
            'internal_details' => true,
            'configure' => false
        ], $options);

        $availableZones = [];

        $this->isDirectChecked = false;

        $this->configure($requestForUserId, $options);

        if (isEmpty($this->dynamicAccessZones) === false) {

            foreach ($this->dynamicAccessZones as $accessZone => $accessZoneContents) {

                $getResult = $this->check($accessZone, $requestForUserId, $options);

                if ($this->accessDetailsRequested === true) {

                    if (($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {

                        $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                            'title' => array_get($accessZoneContents, 'title'),
                            'is_zone' => true,
                            'dependencies' => array_get($accessZoneContents, 'dependencies'),
                            'parent' => array_get($accessZoneContents, 'parent'),
                            'description' => array_get($accessZoneContents, 'description'),
                        ]);
                    } elseif (($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {

                        $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                            'title' => array_get($accessZoneContents, 'title'),
                            'is_zone' => true,
                            'dependencies' => array_get($accessZoneContents, 'dependencies'),
                            'parent' => array_get($accessZoneContents, 'parent'),
                            'description' => array_get($accessZoneContents, 'description'),
                        ]);
                    } elseif (($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {

                        $availableZones[] = $this->detailsFormat($getResult, $accessZone, [
                            'title' => array_get($accessZoneContents, 'title'),
                            'is_zone' => true,
                            'dependencies' => array_get($accessZoneContents, 'dependencies'),
                            'parent' => array_get($accessZoneContents, 'parent'),
                            'description' => array_get($accessZoneContents, 'description'),
                        ]);
                    }
                } else {

                    if (($getResult->isAccess() === true) and ($getResult->isPublic() === false) and (array_intersect($this->filterTypes, ['all', 'allowed']))) {

                        $availableZones[] = $accessZone;
                    } elseif (($getResult->isAccess() === true) and ($getResult->isPublic() === true) and (array_intersect($this->filterTypes, ['all', 'public']))) {
                        $availableZones[] = $accessZone;
                    } elseif (($getResult->isAccess() === false) and (array_intersect($this->filterTypes, ['all', 'denied']))) {

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
    public function isPublicAccess($routeName = null)
    {
        // run get routes & collect public routes
        $this->takePublic()->getRoutes();

        if (is_array($routeName)) {
            $confirmedPublicRoutes = [];

            foreach ($routeName as $routeItem) {
                if (in_array($routeName, $this->publicRoutes)) {
                    $confirmedPublicRoutes[$routeItem] = true;
                }
            }

            return $confirmedPublicRoutes;
        }

        if (!$routeName) {
            $routeName = Route::currentRouteName();
        }

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

        if (!$accessList or !is_array($accessList)) {
            $accessList = [];
        }

        if (!$denyList or !is_array($denyList)) {
            $denyList = [];
        }

        if (isEmpty($this->dynamicAccessZones) === false and (count($accessList) + count($denyList)) > 0) {

            $zoneAllowedAccessIds = [];
            $zoneDeniedAccessIds = [];

            $denyList = $denyList ?: [];
            // Zone Parent child collection
            foreach ($this->dynamicAccessZones as $accessZone => $accessZoneContents) {
                // update list of permissions based on Parent Zones
                $accessList = $this->collectParentZones($accessZone, $accessList, $accessZone);
                $denyList = $this->collectParentZones($accessZone, $denyList, $accessZone);

                if (is_array($accessList) and in_array($accessZone, $accessList)) {
                    $zoneAllowedAccessIds = array_merge($zoneAllowedAccessIds, array_get($this->dynamicAccessZones[$accessZone], 'access_ids', []));
                }

                if (is_array($denyList) and in_array($accessZone, $denyList)) {
                    $zoneDeniedAccessIds = array_merge($zoneDeniedAccessIds, array_get($this->dynamicAccessZones[$accessZone], 'access_ids', []));
                }
            }

            $accessList = array_unique(array_merge($accessList, $zoneAllowedAccessIds));
            $denyList = array_unique(array_merge($denyList, array_diff($zoneDeniedAccessIds, $zoneAllowedAccessIds)));
        }

        // perform allowed check
        if (isEmpty($accessList) === false and is_array($accessList)) {
            foreach ($accessList as $accessId) {

                // remove unnecessary wild-cards *
                $accessId = $this->cleanIdKey($accessId);

                if ($accessId === $accessIdKey) {
                    $specific = 'allow';
                    break;
                }

                if (str_is($accessId, $accessIdKey) === true) {

                    $decisionStrength[strlen($accessId)] = $isAccess =  true;
                }
            }
        }

        //perform deny check
        if (isEmpty($denyList) === false and is_array($denyList)) {
            foreach ($denyList as $denyId) {

                // remove unnecessary wild-cards *
                $denyId = $this->cleanIdKey($denyId);

                if ($denyId === $accessIdKey) {
                    $specific = 'deny';
                    break;
                }

                if (str_is($denyId, $accessIdKey) === true) {

                    $decisionStrength[strlen($denyId)] = $isAccess =  false;
                }
            }
        }

        if (is_array($this->dynamicAccessZones) and array_key_exists($accessIdKey, $this->dynamicAccessZones)) {
            $this->accessStages[$this->uniqueIdKeyString]['__data'] = [
                'is_zone' => true,
                'title' => array_get($this->dynamicAccessZones[$accessIdKey], 'title'),
                'dependencies' => array_get($this->dynamicAccessZones[$accessIdKey], 'dependencies'),
                'parent' => array_get($this->dynamicAccessZones[$accessIdKey], 'parent'),
                'description' => array_get($this->dynamicAccessZones[$accessIdKey], 'description'),
            ];
        }

        // if it specific item then its important
        if ($specific) {
            $this->accessStages[$this->uniqueIdKeyString][$options['check_level']] =  ($specific === 'allow') ? true : false;
            $this->accessStages[$this->uniqueIdKeyString]['__result'] = $options['check_level'];
            return $this->accessStages[$this->uniqueIdKeyString][$options['check_level']];
        }

        if (empty($decisionStrength) === false) {
            $this->accessStages[$this->uniqueIdKeyString]['__result'] = $options['check_level'];
            return $this->accessStages[$this->uniqueIdKeyString][$options['check_level']] =  $decisionStrength[max(array_keys($decisionStrength))];
        }

        return $isAccess;
    }

    /**
     * Collect the Parent and child zones & return permissions based on
     *
     * @param string $accessZone
     * @param array  $allowDenyList
     * @param string $intialAccessZone
     * 
     * @return array
     *---------------------------------------------------------------- */
    protected function collectParentZones($accessZone, $allowDenyList, $intialAccessZone)
    {
        // get access zone details
        $accessZoneContents = array_get($this->dynamicAccessZones, $accessZone);
        // name of the parent zone
        $parentZoneName = array_get($accessZoneContents, 'parent');
        // check if the Parent & Self zone are same
        if ($parentZoneName == $accessZone) {
            throw new Exception("YesAuthority - Zone's Self Parent Relation - $accessZone");
        }
        // if parent is there
        if ($parentZoneName) {
            // grab the same for nested parents
            $allowDenyList = $this->collectParentZones($parentZoneName, $allowDenyList, $intialAccessZone);
            // *** SEQUENCE is IMPORTANT - DO NOT CHANGE ***
            // add item to access/deny list
            if (is_array($allowDenyList) and in_array($parentZoneName, $allowDenyList)) {
                $allowDenyList[] = $accessZone;
            }
        }
        // get access list back
        return array_unique($allowDenyList);
    }

    /**
     * Details format
     *
     * @param string $idKey
     * 
     * @return string
     *---------------------------------------------------------------- */
    protected function detailsFormat($isAccess, $accessIdKey, $options = [])
    {

        if (!empty($this->accessStages[$this->uniqueIdKeyString])) {
            $itemData = array_pull($this->accessStages[$this->uniqueIdKeyString], '__data');

            if (is_array($itemData) and !empty($itemData)) {
                $options = array_merge($options, $itemData);
            }
        }

        if ($isAccess instanceof YesAuthorityResult) {

            foreach ($options as $key => $value) {
                $isAccess->{$key} = $value;
            }

            return $isAccess;
        }

        $options = array_merge([
            'response_code' => $isAccess ? 200 : 401,
            'message' => $isAccess ? 'OK' : 'Unauthorized',
            'override_result_by' => false
        ], $options);

        $conditionsIfAny = [];
        $conditionResult = null;

        $resultBy = ifIsset($this->accessStages[$this->uniqueIdKeyString], function () use (&$accessIdKey, &$conditionsIfAny, &$conditionResult) {
            $conditionsIfAny = array_pull($this->accessStages[$this->uniqueIdKeyString], '__conditions');
            return array_pull($this->accessStages[$this->uniqueIdKeyString], '__result');
        }, null);

        if (!empty($conditionsIfAny)) {
            $conditionResult = array_pull($conditionsIfAny, '__result');
        }

        $parentLevel = null;
        // find parent level item
        if ($resultBy) {
            foreach (array_reverse($this->accessStages[$this->uniqueIdKeyString]) as $key => $value) {
                $levelKeyId = $this->checkLevels[$key];
                $resultKeyId = $this->checkLevels[$resultBy];
                if (($levelKeyId < $resultKeyId) and !$parentLevel) {
                    $parentLevel = $key;
                    break;
                }
            }
        }

        if ($options['override_result_by']) {
            $resultBy = $options['override_result_by'];
        }

        $result = new YesAuthorityResult([
            'response_code' => $options['response_code'],
            'message' => $options['message'],
            'is_access' => $isAccess,
            'result_by' => $resultBy,
            'upper_level' => $parentLevel,
            'condition_result_by' => $conditionResult,
            'conditions_checked' => $conditionsIfAny,
            'levels_checked' => ifIsset($this->accessStages[$this->uniqueIdKeyString], true, []),
            'access_id_key' => $accessIdKey,
            'title' => ifIsset($options['title'], true, null),
            'is_public' => isset($options['is_public']) ? $options['is_public'] : false,
            'is_zone' => ifIsset($options['is_zone'], true),
            'dependencies' => ifIsset($options['dependencies'], true, null),
            'parent' => ifIsset($options['parent'], true, null),
            'description' => ifIsset($options['description'], true, null),
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
    private function initialize()
    {

        if ($this->isAccessIdsArray == true) {
            return false;
        }

        $this->checkLevel = 99;
        $this->checkLevels = [
            'CONFIG_BASE'   => 0,
            'CONFIG_ROLE'   => 1, // Config Role
            'CONFIG_USER'   => 2, // Config User
            'DB_ROLE'       => 3, // DB Role
            'DB_USER'       => 4, // DB User
            'DB_ENTITY'     => 5,
            'ENTITY_CONDITION' => 6,
            'CONDITIONS'    => 7, // Conditions            
        ];

        $this->customPermissions = false;
        $this->accessDetailsRequested = false;
        $this->accessScope = 'user';
        $this->isDirectChecked = true;
        $this->levelsModified = false;
        $this->filterTypes = ['all'];
        // $this->configEntity = null;
        $this->entityIdentified = [];
        $this->isAccessIdsArray = false;
        $this->currentRouteAccessId = null;
        // $this->roleIdentified = null;
        // $this->userIdentified = null;
        $this->userPermissions = [];
    }

    /**
     * Check custom entities permission
     *
     * @param string $entityKey
     * @param int/string/array $entityId
     * @param int/string $requestForUserId          
     *
     * @return this
     *---------------------------------------------------------------- */
    public function checkEntity($entityKey, $entityId, $requestForUserId = null)
    {
        $entities = array_get($this->permissions, 'entities');

        if (!$entities or isEmpty($entities)) {
            throw new Exception('YesAuthority - entities empty. Please check your YesAuthority entities.');
        }

        $this->configEntity = array_get($entities, $entityKey);
        $this->userRequestForEntity = $requestForUserId ? $requestForUserId : Auth::id();

        if (!$this->configEntity or isEmpty($this->configEntity)) {
            throw new Exception('YesAuthority - ' . $entityKey . ' entity not found. Please check your YesAuthority entities.');
        }

        $entityModelString  = array_get($this->configEntity, 'model');
        $entityIdColumn     = array_get($this->configEntity, 'id_column');
        $permissionColumn   = array_get($this->configEntity, 'permission_column');
        $userIdColumn       = array_get($this->configEntity, 'user_id_column');
        $whereClouses       = array_get($this->configEntity, 'where', []);

        if (
            !$entityModelString
            // or !$entityIdColumn 
            or !$permissionColumn
            or !$userIdColumn
        ) {
            throw new Exception('YesAuthority - entity config should contain model, permission_column and user_id_column');
        }

        if (!is_string($entityModelString)) {
            throw new Exception('YesAuthority - Please set key for model in entity config');
        }

        if (!class_exists($entityModelString)) {
            throw new Exception('YesAuthority - Entity model does not exist.');
        }

        $this->entityPermissions = [];

        // check if entity available as array
        if (is_array($entityId)) {
            $this->entityIdentified   = $entityId;
        } else {
            $entityModel = new $entityModelString;
            $entityIdColumn = $entityIdColumn ? $entityIdColumn : $entityModel->getKeyName();
            $entityFound = $entityModel->where(array_merge([
                $entityIdColumn => $entityId,
                $userIdColumn => $this->userRequestForEntity,
            ], $whereClouses))->first();

            if (isEmpty($entityFound)) {
                return $this;
            }
            // if entity model found
            $this->entityIdentified   = $entityFound->toArray();
        }

        if (empty($this->entityIdentified)) {
            return $this;
        }

        $this->requestCheckStringId .= '_cee_' . $entityKey . '_' . $this->entityIdentified[$entityIdColumn] . '_' . $requestForUserId;

        // get the permissions out of it
        $rawEntityPermissions = array_get($this->entityIdentified, $permissionColumn);

        // if permissions found
        if (isEmpty($rawEntityPermissions) === false) {
            // if not an array, make it
            if (is_array($rawEntityPermissions) === false) {
                $this->entityPermissions = json_decode($rawEntityPermissions, true);
            } else {
                $this->entityPermissions = $rawEntityPermissions;
            }
        }

        return $this;
    }

    /**
     * Remove extra * from string
     *
     * @param string $idKey
     * 
     * @return string
     *---------------------------------------------------------------- */
    protected function cleanIdKey($idKey)
    {
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
    protected function performLevelChecks($level = 99)
    {
        return ($this->checkLevel >= $level) and in_array($level, $this->checkLevels);
    }

    /**
     * Extend the permissions from one role to another
     *
     * @param int/string $requestedRoleId      
     * @param int/string $ruleKey        
     *
     * @return void
     *-----------------------------------------------------------------------*/
    protected function extendRolePermissions($requestedRoleId, $ruleKey = null)
    {
        // avoid recursive loop
        if ($requestedRoleId == $ruleKey) {
            throw new Exception($ruleKey . " - invalid extended role id");
        }
        // get available roles info
        $availalbleRoleItems = array_get($this->permissions, 'rules.roles');
        // Get original role item for which permissions are extending
        $originalRoleItem = array_get($availalbleRoleItems, $requestedRoleId);
        // if its not internal query then it may original
        if (!$ruleKey) {
            $ruleKey = $requestedRoleId;
            $ruleValue = &$originalRoleItem;
        } else {
            // get the information for internal request item
            $ruleValue = array_get($availalbleRoleItems, $ruleKey);
        }
        // check if it is extended by other role
        if (array_has($ruleValue, 'extends') and !empty($ruleValue['extends'])) {
            // if found handle each permissions.
            foreach ($ruleValue['extends'] as $extendedBy) {
                try {
                    // access by variable
                    list($roleId, $permissionType) = explode('.', $extendedBy);
                    // avoid recursive loop
                    if ($ruleKey == $roleId) {
                        throw new Exception('invalid:same');
                    }
                } catch (Exception $e) {
                    throw new Exception(
                        $e->getMessage() == 'invalid:same' ?
                            $roleId . " - invalid extended role id"
                            : $extendedBy . " - is invalid extended permissions, it should be like 1.allow"
                    );
                }
                // check if valid attribute for permissions
                if (!in_array($permissionType, ['allow', 'deny'])) {
                    throw new Exception($extendedBy . " - only allow & deny are accepted for permissions (Spell check again). eg. 1.allow");
                }
                // existing permission
                $extendedPermissionContainer = array_get($originalRoleItem, $permissionType, []);
                // extended role permission item
                $extendRoleItem = array_get($availalbleRoleItems, $roleId, null);
                // if requested role is not found
                if (!$extendRoleItem) {
                    throw new Exception($roleId . " - requested role is not available");
                }
                // grab main sudo ids
                $requestedItemPseudoAccessIds = array_intersect(
                    array_get($originalRoleItem, $permissionType, []),
                    $this->pseudoAccessIds
                );
                // merge permissions & filter the container for unique access ids
                $extendedPermissionContainer = array_unique(array_merge_recursive(
                    $extendedPermissionContainer,
                    array_get($extendRoleItem, $permissionType, [])
                ));
                // remove the pseudo access ids
                $extendedPermissionContainer = array_diff(
                    $extendedPermissionContainer,
                    array_diff($this->pseudoAccessIds, $requestedItemPseudoAccessIds)
                );
                // set the refined permitted access ids on to the container
                array_set(
                    $this->permissions,
                    'rules.roles.' . $requestedRoleId . '.' . $permissionType,
                    $extendedPermissionContainer
                );
                // check if the internal extends is there
                if (array_has($extendRoleItem, 'extends') and !empty($extendRoleItem['extends'])) {
                    // if so repeat the flow
                    $this->extendRolePermissions($requestedRoleId, $roleId);
                }
                // remove unnecessary items
                unset($extendedPermissionContainer, $extendRoleItem, $roleId, $permissionType);
            }
        }
        // remove unnecessary items
        unset($availalbleRoleItems, $originalRoleItem, $ruleKey, $ruleValue, $requestedRoleId);
        // all done
        return true;
    }
}
