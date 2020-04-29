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
     * The authentication source to be used by the password reset functionality. Set to `null` to
     * show a minimalistic email form without authentication.
     */
    'authsource' => null,
];
