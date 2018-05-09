<?php 
/* 
 *  YesAuthority Configurations
 *
 *  This configuration file is part of YesAuthority
 *
 *------------------------------------------------------------------------------------------------*/
return [
    /* authority configurations
     *--------------------------------------------------------------------------------------------*/
    'config' => [
        /*
         *   @optional - define here your pseudo access ids
         *   psudo_access_ids
        */         
        'pseudo_access_ids'       => [
            // 'admin',
            // 'customer'
        ],          
        /*
         *   @required - if you want use name other than 'authority.checkpost'
         *   middleware_name - YesAuthority Middleware name
        */    
        'middleware_name'           => 'authority.checkpost',
        /*
         *   @required
         *   col_user_id - ID column name for users table
        */        
        'col_user_id'           => 'id',

        /*
         *   @required
         *   col_role - Your Role ID column name for users table
        */        
        'col_role'              => 'user_roles_id',

        /*
         *   @optional - if you want to use dynamic permissions
         *   col_user_permissions - Dynamic Permissions(json) column on users table 
         *   This column should contain json encoded array containing 'allow' & 'deny' arrays
        */
    //    'col_user_permissions'  => '__permissions',

        /*
         *   @required
         *   user_model - User Model
        */        
        'user_model'            => 'App\User',
        /*
         *   @optional
         *   role_model - Role Model
        */        
      //  'role_model'            => 'App\UserRoleModel',
        /*
         *   @optional
         *   col_role_id - ID column name for role table
        */
    //    'col_role_id'           => 'id',        

        /*
         *   @optional
         *   ccol_role_permissions - Dynamic Permissions(json) column on role table, 
         *   This column should contain json encoded array containing 'allow' & 'deny' arrays
        */
    //    'col_role_permissions'  => '__permissions'
    ],
    /* 
     *  Authority rules
     *
     *  Rules item needs to have 2 arrays with keys allow & deny value of it will be array
     *  containing access ids as required.
     *  wildcard entries are accepted using *
     *  for each section level deny will be more powerful than allow
     *  also key length also matters more is length more
     *--------------------------------------------------------------------------------------------*/     
    'rules' => [
        /*  
         *  Role Based rules
         *  First level of defense 
         *----------------------------------------------------------------------------------------*/    
        'roles' => [
            /*  
             *  Rules for the Roles for using id (key will be id)
             *------------------------------------------------------------------------------------*/
            // @example given for role id of 1
           /* 1 => [ // this may be admin user role id
                'allow' => ['*'],
                'deny'  => [],
            ],
            // Team Member role permissions
            2 => [ // this may normal user role id
                'allow' => [
                    'view_only_blog_post', // zone id can be used
                    '*' // all the routes/idKeys are allowed
                ],
                'deny'  => [
                    "manage.*"
                ],
            ],*/
        ],
        /* 
         *  User based rules
         *  2nd level of defense
         *  Will override the rules of above 1st level(roles) if matched
         *----------------------------------------------------------------------------------------*/                
        'users' => [
             /*  
             *  Rules for the Users for using id (key will be id)
             *------------------------------------------------------------------------------------*/
            // @example given for user id of 1
            /* 1 => [ // this may be admin user id
                'allow' => ['*'],
                'deny'  => [],
            ],
            // Team Member permissions
            2 => [ // this may normal user  id
                'allow' => [
                    'view_only_blog_post', // zone id can be used
                    '*' // all the routes/idKeys are allowed
                ],
                'deny'  => [
                    "manage.*"
                ],
            ],*/
        ],
        /*  
         *  DB Role Based rules
         *  3rd level of defense 
         *  Will override the rules of above 2nd level(user) if matched
         *  As it will be database based you don't need to do anything here
         *----------------------------------------------------------------------------------------*/

        /*  
         *  DB User Based rules 
         *  4th level of defense 
         *  Will override the rules of above 3rd level(db roles) if matched
         *  As it will be database based you don't need to do anything here
         *----------------------------------------------------------------------------------------*/        

        /*  Dynamic permissions based on conditions
         *  Will override the rules of above 4th level(db user) if matched
         *  5th level of defense     
         * each condition will be array with following options available:
         *  @key - string - name
         *      @value - string - it will be condition identifier (alpha-numeric-dash)  
         *  @key - string - access_ids
         *      @value - array - of ids (alpha-numeric-dash)
         *  @key - string - uses
         *      @value - string - of of classNamespace@method
         *          OR
         *      @value - anonymous function -            
         *  @note - both the function/method receive following 3 parameters so you can 
         *          run your own magic of logic using it.
         *  $accessIdKey            - string - requested id key
         *  $isAccess               - bool - what is the access received from the above level/condition 
         *  $currentRouteAccessId   - current route/accessIds being checked.
         *----------------------------------------------------------------------------------------*/
        'conditions' => [
            // Example conditions
            //  It should return boolean values, true for access allow & false for deny
            /*[
                'name' => 'xyz',
                'access_ids' => ['demo_authority','delete_blog_post','*'],
                'uses' => 'App\Yantrana\XyzCondition@abc'
            ],
            [
                'name' => 'xyz2',
                'access_ids' => ['demo_authority','delete_blog_post','*'],
                'uses' => function ()
                {
                    return true;
                }
            ]*/
        ]
    ],

    /* 
     *  Dynamic access zones
     *
     *  Zones can be created for various reasons, when using dynamic permission system
     *  its bad to store direct access ids into database in that case we can create dynamic access
     *  zones which is the group of access ids & these can be handled with one single key id.
     *----------------------------------------------------------------------------------------*/   
    'dynamic_access_zones' => [
        // @example given for role id of one
        /*'view_only_blog_post' => [
            'title' => 'View Only Blog Post',
            'access_ids' => [
                'manage.blog.read.*'
            ],
            'dependencies' => [
                'view_only_blog_comments'
            ],
            'parent' => 'blog'
        ],*/
    ],
    'entities' => [
        /*'project' => [
            'model' => 'App\Yantrana\Components\User\Models\UserAuthorityModel',
            'id_column' => '_id',
            'permission_column' => '__permissions',
            'user_id_column' => 'users__id'
        ]*/
    ]
];