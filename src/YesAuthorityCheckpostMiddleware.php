<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;

use YesAuthority;

class YesAuthorityCheckpostMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        if (! Auth::guard($guard)->check() or YesAuthority::check() === false) {
            return redirect('/');
        }

        return $next($request);

        /*
        // Detailed handling
        if (Auth::guard($guard)->check()) {            
             $authority  = YesAuthority::withDetails()->check();

            if($authority->isAccess() === true) {
                return $next($request);
             }
        }        
        return redirect('/home');
        */

    }
}