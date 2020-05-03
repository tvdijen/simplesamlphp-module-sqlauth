<?php

declare(strict_types=1);

namespace SimpleSAML\Module\SqlAuth\Auth\Source;

use Exception;
use PDO;
use PDOException;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error;
use SimpleSAML\Logger;

/**
 * Simple SQL authentication source
 *
 * This class is an example authentication source which authenticates an user
 * against a SQL database.
 *
 * @package SimpleSAMLphp
 */

class SQL extends \SimpleSAML\Module\core\Auth\UserPassBase
{
    /**
     * The name of the table used for user accounts.
     */
    private $tablename;

    /**
     * The module configuration.
     */
    private $moduleConfig;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Make sure that all required parameters are present.
        if (!array_key_exists('tablename', $config)) {
            throw new Exception(
                'Missing required configuration \'tablename\' for authentication source ' . $this->authId
            );
        }

        if (!is_string($config['tablename'])) {
            throw new Exception('Expected parameter \'tablename\' for authentication source ' . $this->authId .
                ' to be a string. Instead it was: ' . var_export($config['tablename'], true));
        }

        $this->moduleConfig = Configuration::getOptionalConfig('module_sqlauth.php');
        $this->tablename = $config['tablename'];
    }


    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login(string $username, string $password): array
    {
        $db = Database::getInstance();

        $stmt = $db->read(
            'SELECT * FROM `' . $this->tablename . '` WHERE uid = :username',
            ['username' => $username]
        );
        $data = $stmt->fetchAll();

        Logger::debug('sqlauth:' . $this->authId . ': Got ' . count($data) . ' rows from database');

        if (count($data) !== 1) {
            // No rows returned (or multiple users?) - invalid username
            Logger::error('sqlauth:' . $this->authId . ': Wrong username given.');
            throw new Error\Error('WRONGUSERPASS');
        } elseif (!array_key_exists('password', $data[0]) || $data[0]['password'] === null) {
            // No password available or set to NULL
            Logger::error('sqlauth:' . $this->authId . ': No password.');
            throw new Error\Error('WRONGUSERPASS');
        } elseif (password_verify($password, $data[0]['password']) === false) {
            // Incorrect password
            Logger::error('sqlauth:' . $this->authId . ': Incorrect password.');
            throw new Error\Error('WRONGUSERPASS');
        }

        if ($this->moduleConfig->getBoolean('update_last_logon', true)) {
            $stmt = $db->write(
                'UPDATE `' . $this->tablename . '` SET last_logon=NOW() WHERE uid = :username',
                ['username' => $username]
            );

            if ($stmt === false) {
                throw new Exception('Updating the last_logon failed.');
            }
        }

        return ['userPrincipalName' => [$data[0]['uid']]];
    }


    /**
     * Attempt to retrieve the user's details from the database.
     *
     * On a successful attempt, this function should return the users attributes. On failure,
     * it should throw an exception.
     *
     * @param string $uid  The user's identifier.
     * @return array  Associative array with the users attributes.
     */
    public function getAttributes(string $uid): array
    {
        $db = Database::getInstance();;

        $stmt = $db->read(
            'SELECT * FROM `' . $this->tablename . '` WHERE uid = :username',
            ['username' => $uid])
        ;
        $data = $stmt->fetchAll();

        Logger::debug('sqlauth:' . $this->authId . ': Got ' . count($data) . ' rows from database');

        if (count($data) !== 1) {
            // No rows returned (or multiple users?) - invalid username
            Logger::error('sqlauth:' . $this->authId . ': Wrong username given.');
        }

        return $data;
    }
}
