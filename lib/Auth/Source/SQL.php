<?php

namespace SimpleSAML\Module\SqlAuth\Auth\Source;

use Exception;
use PDO;
use PDOException;
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
     * The DSN we should connect to.
     */
    private $dsn;

    /**
     * The username we should connect to the database with.
     */
    private $username;

    /**
     * The password we should connect to the database with.
     */
    private $password;

    /**
     * The options that we should connect to the database with.
     */
    private $options;

    /**
     * The query we should use to retrieve the attributes for the user.
     *
     * The username will be available as :username.
     */
    private $query;

    /**
     * The query we should use to update the last_logon attribute for the user.
     *
     * The username and table name will be available as :username and :tablename.
     */
    private $update_query;

    /**
     * The name of the table used for user accounts.
     */
    private $tablename;


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
        foreach (['dsn', 'username', 'password', 'table_query', 'query', 'update_query'] as $param) {
            if (!array_key_exists($param, $config)) {
                throw new Exception('Missing required configuration \'' . $param .
                    '\' for authentication source ' . $this->authId);
            }

            if (!is_string($config[$param]) || (!is_null($config[$param]) && ($param === 'update_query'))) {
                throw new Exception('Expected parameter \'' . $param .
                    '\' for authentication source ' . $this->authId .
                    ' to be a string. Instead it was: ' .
                    var_export($config[$param], true));
            }
        }

        $this->dsn = $config['dsn'];
        $this->username = $config['username'];
        $this->password = $config['password'];
        $this->tablename = $config['tablename'];
        $this->query = $config['query'];
        $this->update_query = $config['update_query'];
        if (isset($config['options'])) {
            $this->options = $config['options'];
        }
    }


    /**
     * Create a database connection.
     *
     * @return \PDO  The database connection.
     */
    private function connect(): PDO
    {
        try {
            $db = new PDO($this->dsn, $this->username, $this->password, $this->options);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
                $this->dsn . '\': ' . $e->getMessage());
        }

        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $driver = explode(':', $this->dsn, 2);
        $driver = strtolower($driver[0]);

        // Driver specific initialization
        switch ($driver) {
            case 'mysql':
                // Use UTF-8
                $db->exec("SET NAMES 'utf8mb4'");
                break;
            case 'pgsql':
                // Use UTF-8
                $db->exec("SET NAMES 'UTF8'");
                break;
        }

        return $db;
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
        $db = $this->connect();

        try {
            $sth = $db->prepare($this->query);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to prepare query: ' . $e->getMessage());
        }

        try {
            $sth->execute(['username' => $username, 'tablename' => $this->tablename]);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to execute query: ' . $e->getMessage());
        }

        try {
            $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to fetch result set: ' . $e->getMessage());
        }

        Logger::debug('sqlauth:' . $this->authId . ': Got ' . count($data) . ' rows from database');

        if (count($data) !== 1) {
            // No rows returned (or multiple users?) - invalid username
            Logger::error('sqlauth:' . $this->authId . ': Wrong username given.');
            throw new Error\Error('WRONGUSERPASS');
        } elseif (!isset($data['password']) || $data['password'] === null) {
            // No password available or set to NULL
            Logger::error('sqlauth:' . $this->authId . ': No password.');
            throw new Error\Error('WRONGUSERPASS');
        } elseif (password_verify($password, $data['password'])) {
            // Incorrect password
            Logger::error('sqlauth:' . $this->authId . ': Incorrect password.');
            throw new Error\Error('WRONGUSERPASS');
        }

        try {
            $sth = $db->prepare($this->update_query);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to prepare query: ' . $e->getMessage());
        }

        try {
            $update = $sth->execute(['username' => $username, 'tablename' => $this->tablename]);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:' . $this->authId . ': - Failed to execute query: ' . $e->getMessage());
        }

        if ($sth->rowCount() !== 1) {
            throw new Exception('Updating the last_logon failed.');
        }

        return [];
    }
}
