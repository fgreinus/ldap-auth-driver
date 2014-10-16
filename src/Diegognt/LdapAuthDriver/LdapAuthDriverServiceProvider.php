<?php
namespace Diegognt\LdapAuthDriver;

use Illuminate\Auth\Guard;
use Illuminate\Support\ServiceProvider;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Diego Navarro (diego.nava07@gmail.com)
 *
 */

class LdapAuthDriverServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var  boolean
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->package('diegognt/ldap-auth-driver');

        $this->app['auth']->extend('ldap', function ($app) {
            return new Guard(
                new LdapAuthDriverUserProvider($app['db']->connection()),
                $app->make('session.store')
            );
        });
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {

    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return array('ldap');
    }
}
