<?php
namespace fgreinus\LdapAuthDriver;

use Config;
use Exception;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\UserInterface;
use Illuminate\Auth\UserProviderInterface;
use Illuminate\Database\Connection;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Florian Greinus (florian.greinus@gmail.com)
 *
 */
class LdapAuthDriverUserProvider implements UserProviderInterface
{
    /**
     * The Eloquent user model.
     *
     * @var  string
     */
    protected $model;

    /**
     * The LDAP connection.
     *
     * @var ldap link
     */
    protected $conn;

    /**
     * The active database connection.
     *
     * @param  \Illuminate\Database\Connection
     */
    protected $db_conn;

    /**
     * Create a new LDAP user provider.
     *
     * @param
     */
    public function __construct( Connection $db_conn )
    {
        $this->db_conn = $db_conn;

        if (!extension_loaded( 'ldap' )) {
            throw new Exception( "PHP LDAP extension not loaded." );
        }

        if (!$this->conn = ldap_connect( "ldap://" . Config::get( 'ldap-auth-driver::host' ) )) {
            throw new Exception( "Could not connect to LDAP host " . Config::get( 'ldap-auth-driver::host' ) . ": " . ldap_error( $this->conn ) );
        }

        ldap_set_option( $this->conn, LDAP_OPT_PROTOCOL_VERSION, Config::get( 'ldap-auth-driver::version' ) );
        ldap_set_option( $this->conn, LDAP_OPT_REFERRALS, 0 );

        if (Config::get( 'ldap-auth-driver::username' ) && Config::get( 'ldap-auth-driver::password' ) && Config::get( 'ldap-auth-driver::rdn' )) {
            if (!@ldap_bind( $this->conn,
                'cn=' . Config::get( 'ldap-auth-driver::username' ) . ',' . Config::get( 'ldap-auth-driver::rdn' ),
                Config::get( 'ldap-auth-driver::password' ) )
            ) {
                throw new Exception( 'Could not bind to AD: ' . ldap_error( $this->conn ) );
            }
        } else {
            if (!@ldap_bind( $this->conn )) {
                throw new Exception( 'Could not bind to AD: ' . ldap_error( $this->conn ) );
            }
        }
    }

    /**
     * Clean up the LDAP connection.
     */
    public function __destruct()
    {
        if (!is_null( $this->conn )) {
            ldap_unbind( $this->conn );
        }
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     *
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveById( $identifier )
    {
        if (Config::get( 'ldap-auth-driver::eloquent' ) == true) {
            $identifier = \User::find( $identifier )->username;
        }

        if ($entries = $this->searchLdap( $identifier )) {
            if (Config::get( 'ldap-auth-driver::use_db' )) {
                $ldap_value = $entries[0][Config::get( 'ldap-auth-driver::ldap_field' )][0];
                $user       = $this->db_conn->table( Config::get( 'ldap-auth-driver::db_table' ) )->where( Config::get( 'ldap-auth-driver::db_field' ),
                    '=', $ldap_value )->first();

                if (Config::get( 'ldap-auth-driver::eloquent' )) {
                    return \User::find( $user->id );
                } else {
                    return new GenericUser( get_object_vars( $user ) );
                }
            } else {
                return $this->createGenericUserFromLdap( $entries[0] );
            }
        } else {
            return null;
        }
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed $identifier
     * @param  string $token
     *
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveByToken( $identifier, $token )
    {
        if (Config::get( 'ldap-auth-driver::eloquent' ) == true) {
            $identifier = \User::find( $identifier )->username;
        }

        if ($entries = $this->searchLdap( $identifier )) {
            $ldap_value = $entries[0][Config::get( 'ldap-auth-driver::ldap_field' )][0];
            $user       = $this->db_conn->table( Config::get( 'ldap-auth-driver::db_table' ) )->where( Config::get( 'ldap-auth-driver::db_field' ),
                '=', $ldap_value )->first();

            $model = $this->createModel();

            return $model->newQuery()
                         ->where( 'id', $user->id )
                         ->where( $model->getRememberTokenName(), $token )
                         ->first();
        } else {
            return null;
        }
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Auth\UserInterface $user
     * @param  string $token
     *
     * @return void
     */
    public function updateRememberToken( UserInterface $user, $token )
    {
        if (!$user instanceof GenericUser) {
            $user->setAttribute( $user->getRememberTokenName(), $token );

            $user->save();
        }
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     *
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveByCredentials( array $credentials )
    {
        $result = @ldap_search(
            $this->conn,
            Config::get( 'ldap-auth-driver::basedn' ),
            "(" . Config::get( 'ldap-auth-driver::login_attribute' ) . "=" . $credentials['username'] . ")",
            array(), 0, 0, 0, LDAP_DEREF_ALWAYS
        );
        if ($result == false) {
            return null;
        }

        $entries = ldap_get_entries( $this->conn, $result );

        if ($entries['count'] == 0 || $entries['count'] > 1) {
            return null;
        }

        if (Config::get( 'ldap-auth-driver::eloquent' ) == true) {
            $user = \User::where( 'username', $entries[0]['uid'][0] )->first();
            if ($user) {
                $this->model = $user;
            } else {
                $this->model = $this->createEloquentUserFromLdap( $entries[0] );
            }
        } else {
            $this->model = $this->createGenericUserFromLdap( $entries[0] );
        }

        return $this->model;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Auth\UserInterface $user
     * @param  array
     *
     * @return boolean
     */
    public function validateCredentials( UserInterface $user, array $credentials )
    {
        return ldap_bind( $this->conn, $user['ldapdn'], $credentials['password'] );
    }

    /**
     * Search the LDAP server for entries that match the specified identifier.
     *
     * @param  mixed $identifier
     *
     * @return array|null
     */
    private function searchLdap( $identifier )
    {
        $filter = Config::get( 'ldap-auth-driver::filter' );
        if (strpos( $filter, '&' )) {
            $filter = substr_replace( $filter,
                '(' . Config::get( 'ldap-auth-driver::user_id_attribute' ) . '=' . $identifier . ')',
                strpos( $filter, '&' ) + 1, 0 );
        } else {
            $filter = '(&(' . Config::get( 'ldap-auth-driver::user_id_attribute' ) . '=' . $identifier . ')' . $filter . ')';
        }

        $result = @ldap_search( $this->conn, Config::get( 'ldap-auth-driver::basedn' ), $filter );

        if ($result == false) {
            return null;
        }

        $entries = ldap_get_entries( $this->conn, $result );
        if ($entries['count'] == 0 || $entries['count'] > 1) {
            return null;
        }

        return $entries;
    }

    /**
     * Create a GenericUser from the specified LDAP entry.
     *
     * @param  array $entry
     *
     * @return \Illuminate\Auth\GenericUser
     */
    private function createGenericUserFromLdap( $entry )
    {
        $parameters = array(
            'id' => $entry[Config::get( 'ldap-auth-driver::user_id_attribute' )][0]
        );

        foreach (Config::get( 'ldap-auth-driver::user_attributes' ) as $key => $value) {
            $parameters[$value] = $entry[$key][0];
        }

        return new GenericUser( $parameters );
    }

    /**
     * Create a GenericUser from the specified LDAP entry.
     *
     * @param  array $entry
     *
     * @return \Illuminate\Auth\GenericUser
     */
    private function createEloquentUserFromLdap( $entry )
    {
        $parameters = array();

        $parameters['ldapdn'] = $entry['dn'];

        foreach (Config::get( 'ldap-auth-driver::user_attributes' ) as $key => $value) {
            $parameters[$value] = $entry[$key][0];
        }

        return \User::create( $parameters );
    }
}
