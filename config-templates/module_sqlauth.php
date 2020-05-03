<?php

/**
 * This is the configuration file for the SQL authentication module.
 */

$config = [
    /**
     * The algorithm to use for generating and validating password hashes
     * Possibilities may vary per PHP-version. See https://www.php.net/manual/en/password.constants.php
     */
    'algorithm' => PASSWORD_ARGON2I,

    /**
     * The authentication source to be used by the password reset functionality.
     */
    'authsource' => 'DB-WIFI',

    /**
     * The authentication source can write the last logon back to the database at the cost of an extra query.
     */
    'update_last_logon' => true,

    /**
     * The identifier that's being used as the identifier in the database.
     */
    'userIdentifier' => 'urn:mace:dir:attribute-def:eduPersonPrincipalName',
];
