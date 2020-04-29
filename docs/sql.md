`SqlAuth:SQL`
=============

This is a authentication module for authenticating a user against a SQL database.


Options
-------

`dsn`
:   The DSN which should be used to connect to the database server.
    Check the various database drivers in the [PHP documentation](http://php.net/manual/en/pdo.drivers.php) for a description of the various DSN formats.

`username`
:   The username which should be used when connecting to the database server.


`password`
:   The password which should be used when connecting to the database server.

`tablename`
:   The name of the table to be used by this module.

`query`
:   The SQL query which should be used to retrieve the user.
    The parameters :username, :password and :tablename are available.
    If the username/password is incorrect, the query should return no rows.

`update_query`
:   The SQL query which should be used to update the user's last_logon timestamp.
    The parameters :username and :tablename are available.
    Set to NULL to not update this value at all.

Examples
--------

Database layout used in some of the examples:

    CREATE TABLE users (
      uid VARCHAR(256) NOT NULL PRIMARY KEY,
      password VARCHAR(256),
      password_last_set TIMESTAMP,
      last_logon TIMESTAMP
    );

Example query:

    SELECT * FROM :tablename
    WHERE uid = :username

Security considerations
-----------------------

Please never store passwords in plaintext in a database. You should always hash your passwords with a secure one-way
function like the ones in the ARGON2 family.
	
One way hashing algorithms like MD5 or SHA1 are considered insecure and should therefore be avoided.
