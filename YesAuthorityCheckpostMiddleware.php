<?php

namespace App\Http\Middleware;

use Auth;
use Closure;
use Illuminate\Contracts\Auth\Guard;

use YesAuthority;

class YesAuthorityCheckpostMiddleware
{
    /**
     * The Guard implementation.
     *
     * @var Guard
     */
    protected $auth;


    /**
     * Create a new filter instance.
     *
     * @param Guard $auth
     * @param ItemCommentRepository     $itemCommentRepository  - ItemComment Repository
     * @param BlogRepository    $blogRepository     - Blog Repository
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        // if user guest
        if ($this->auth->guest()) {
            if ($request->ajax()) {
                Session::put('intendedUrl', URL::previous());

                return __apiResponse([
                        'message' => __('Please login to complete request.'),
                        'auth_info' => getUserAuthInfo(9),
                    ], 9);
            }

            Session::put('intendedUrl', URL::current());

            return redirect()->route('user.login')
                             ->with([
                                'error' => true,
                                'message' => __('Please login to complete request.'),
                            ]);
        }

        $authority = YesAuthority::check();

        if (is_array($authority)) {
            if (($authority['reaction_code'] === 11) || (Auth::user()->status !== 1)) {
                if ($request->ajax()) {
                    return __apiResponse([
                                    'message' => __('Unauthorized.'),
                                    'auth_info' => getUserAuthInfo(11),
                                ], 11);
                }

                return redirect()->route('public.app')
                             ->with([
                                'error' => true,
                                'message' => __('Unauthorized.'),
                            ]);
            }
        }

        return $next($request);
    }
}
