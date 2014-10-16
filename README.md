# l4 OpenLDAP Auth Driver

An OpenLDAP authentication driver for Laravel 4.

## Installation

Add the following to your `composer.json` file.

```
require {
	"diegognt/ldap-auth-driver": "dev-master"
}
```

Run `composer update`.

Open `app/config/app.php` and add:

`Diegognt\LdapAuthDriver\LdapAuthDriverServiceProvider`

Open `app/config/auth.php` and change the authentication driver to `ldap`.

## Configuration

Run `php artisan config:publish diegognt/ldap-auth-driver` and adjust the config file for your LDAP settings.

It can be found in `app/config/packages/diegognt/ldap-auth-driver`.

Thanks to [yuri-moens](https://github.com/yuri-moens)
