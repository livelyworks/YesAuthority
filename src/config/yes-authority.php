<?php 
return [
    // authority configurations
    'config' => [
        'col_user_id'           => '_id',
        'col_role'              => 'user_roles__id',
        'col_user_permissions'  => '__permissions',
        'user_model'            => 'App\Yantrana\Components\User\Models\User',
        //'col_role_id'           => '_id',
        'role_model'            => 'App\Yantrana\Components\User\Models\UserRole',
       // 'col_role_permissions'  => '__permissions'
    ],
 	'rules' => [
        'roles' => [
            // admin user role permissions
            1 => [
                'allow' => ['*'],
                'deny'  => [],
            ],
            // Team Member role permissions
            2 => [
                'allow' => [
                    '*',
                    'delete_blog_post',
                    'view_only_blog_post'
                ],
                'deny'  => [
                    'manage.configuration.*',
                    'manage.users.*',
                    'manage.user.*',
                    'manage.pages.*',
                    'manage.faq.*',
                    'manage.product.*',
                    'manage.support_department.*',
                    'manage.support_ticket.*',
                    'manage.blog.post.comment.*',
                    'manage.blog.post.comment.read.list',
                    'manage-blog.post.comment.read.list.dialog',
                    'file_manager', 
                    'file_manager.*',
                    'add_edit_blog_post'
                ],
            ],
            // Customer role permissions
            3 => [
                'allow' => ['*'],
                'deny'  => [
                    'manage.*',
                    'file_manager', 
                    'file_manager.*',
                    'delete_blog_post',
                    'add_edit_blog_post'
                ],
            ]
        ],
        'users' => [
            // id of user 1 permissions
            1 => [
                'allow' => [],
                'deny'  => [],
            ],
            // id of user 2 permissions
            2 => [
                'allow' => [],
                'deny'  => [],
            ]
        ],
        // dynamic permissions based on conditions
        'conditions' => [
            // condition to check if user logged in or not
            // DEMO MODE CHECK
            [
                'name' => 'xyz',
                'access_ids' => ['demo_authority','delete_blog_post','*'],
                'uses' => 'App\Yantrana\XyzCondition@abc'
            ],
            [
                'name' => 'xyz',
                'access_ids' => ['demo_authority'],
                'uses' => 'App\Yantrana\XyzCondition@test'
            ]
        ]
    ],

    /*
      Dynamic Access Items
    ------------------------------------------------------------------ */   
    'dynamic_access_zones' => [
        // Only view blog post
        'view_only_blog_post' => [
            'title' => 'View Only Blog Post',
            'access_ids' => [
                'manage.blog.read.*'
            ],
            'dependencies' => [
            ]
        ],

        // Add or Edit Blog Post
        'add_edit_blog_post' => [
            'title' => 'Add or Edit Blog Post',
            'access_ids' => [
                'manage.blog.write.*'
            ],
            'dependencies' => [
                'view_only_blog_post'
            ]
        ],

        // Delete Blog Post
        'delete_blog_post' => [
            'title' => 'Delete Blog Post',
            'access_ids' => [
                'manage.blog.write.delete'
            ],
            'dependencies' => [
                'view_only_blog_post'
            ]
        ]
    ]
];