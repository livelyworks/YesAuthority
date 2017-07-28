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
         *   @required - if you want use name other than 'authority.checkpost'
         *   middleware_name - YesAuthority Middleware name
        */    
    //    'middleware_name'           => 'authority.checkpost',

        /*
         *   @required
         *   col_user_id - ID column name for users table
        */
        'col_user_id'           => 'id',

        /*
         *   @required
         *   col_role - Your Role ID column name for users table
        */
        'col_role'              => 'user_roles__id',

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
    //    'role_model'            => 'App\Yantrana\Components\User\Models\UserRole',

        /*
         *   @optional
         *   col_role_id - ID column name for role table
        */
    //    'col_role_id'           => '_id',

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
     *  Rules item needs to have 2 key arrays called allow & deny
     *  wildcard entries are accepted using *
     *  for each section deny will be more powerful than allow
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
            // @example given for role id of one
            /*1 => [
                'allow' => [
                        'view_only_blog_post', // zone id can be used
                        '*' // all the routes/idKeys are allowed
                    ],
                'deny'  => [
                        'manage.*', // all the routes/idKeys are allowed except manage.*
                    ],
                ]
            ],*/
        ],

        /* 
         *  User based rules
         *  2nd level of defense
         *  Will override the rules of above roles if matched
         *----------------------------------------------------------------------------------------*/
        'users' => [
            /*  
             *  Rules for the Users for using id (key will be id)
             *------------------------------------------------------------------------------------*/
            // @example given for role id of one
            /*1 => [
                'allow' => [
                        'view_only_blog_post', // zone id can be used
                        '*' // all the routes/idKeys are allowed
                    ],
                'deny'  => [
                        'manage.*', // all the routes/idKeys are allowed except manage.*
                    ],
                ]
            ],*/
        ],

        /*  
         *  DB Role Based rules
         *  3rd level of defense 
         *----------------------------------------------------------------------------------------*/

        /*  
         *  DB User Based rules 
         *  4th level of defense 
         *----------------------------------------------------------------------------------------*/        

        /*  Dynamic permissions based on conditions
         *  5th level of defense         
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
     *  zones which is the group of access ids which can be handled with one single key id.
     *----------------------------------------------------------------------------------------*/
    'dynamic_access_zones' => [
        // @example given for role id of one
        /*'view_only_blog_post' => [
            'title' => 'View Only Blog Post',
            'access_ids' => [
                'manage.blog.read.*'
            ]
        ],*/
    ]
];