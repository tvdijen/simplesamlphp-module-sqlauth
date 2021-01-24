<?php

declare(strict_types=1);

namespace SimpleSAML\Module\SqlAuth\Controller;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\SqlAuth\Auth\Source\SQL;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Controller class for the SqlAuth module.
 *
 * This class serves the configuration views available in the module.
 *
 * @package SimpleSAML\Module\SqlAuth
 */
class PasswordResetController
{
    /** @var \SimpleSAML\Configuration */
    private $config;

    /** @var \SimpleSAML\Session */
    private $session;

    /** @var \SimpleSAML\Module\SqlAuth\Auth\Source\SQL */
    private $authsource;

    /** @var string */
    private $tablename;

    /** @var mixed|int */
    private $algorithm;

    /** @var string */
    private $userIdentifier;

    /** @var string */
    private $subject;

    /** @var string */
    private const DEFAULT_IDP_AUTHSOURCE = 'DB-WIFI';

    /** @var string */
    private const DEFAULT_SP_AUTHSOURCE = 'default-sp';


    /**
     * PasswordResetController constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->session = $session;

        $moduleConfig = Configuration::getOptionalConfig('module_sqlauth.php');
        $authId = $moduleConfig->getString('authsource', self::DEFAULT_IDP_AUTHSOURCE);
        $this->userIdentifier = $moduleConfig->getString(
            'userIdentifier',
            'urn:mace:dir:attribute-def:eduPersonPrincipalName'
        );
        $this->algorithm = $moduleConfig->getString('algorithm', PASSWORD_ARGON2I);
        $this->subject = $moduleConfig->getString('mail.subject', ['en' => 'Your GovRoam passcode']);

        $authsourcesConfig = Configuration::getConfig('authsources.php');
        $authsource = $authsourcesConfig->getArray($authId);

        $this->tablename = $authsource['tablename'];
        $this->authsource = new SQL(['AuthId' => $authId], $authsource);
    }


    /**
     * Display the user details and reset button.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function main(Request $request): Template
    {
        // Require authentication
        $authsource = new Auth\Simple(self::DEFAULT_SP_AUTHSOURCE);
        $this->requireAuth($authsource);

        // Pull UID attributes from database
        $idp_attrs = $this->session->getData('user', 'idp_attributes');
        $db_attrs = $this->authsource->getAttributes(array_pop($idp_attrs[$this->userIdentifier]))[0];

        $t = new Template($this->config, 'SqlAuth:overview.twig');
        $t->data = [
            'uid' => $db_attrs['uid'],
            'last_logon' => $db_attrs['last_logon'],
            'password_last_set' => $db_attrs['password_last_set'],
            'mail' => $db_attrs['mail'],
            'reseturl' => Module::getModuleURL('SqlAuth/reset', []),
            'logouturl' => Module::getModuleURL('SqlAuth/logout', []),
        ];

        return $t;
    }


    /**
     * Reset the user's password.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function reset(Request $request): Template
    {
        // Require authentication
        $authsource = new Auth\Simple(self::DEFAULT_SP_AUTHSOURCE);
        $this->requireAuth($authsource);

        $passcode = $this->generatePasscode();

        $idp_attrs = $this->session->getData('user', 'idp_attributes');
        $db_attrs = $this->authsource->getAttributes(array_pop($idp_attrs[$this->userIdentifier]))[0];

        $this->writePasscode($db_attrs['uid'], $passcode);
        $this->emailPasscode($db_attrs['mail'], $passcode);

        $t = new Template($this->config, 'SqlAuth:passwordReset.twig');
        $t->data = [
            'overviewurl' => Module::getModuleURL('SqlAuth/', []),
            'logouturl' => Module::getModuleURL('SqlAuth/logout', []),
            'passcode' => $passcode,
        ];

        return $t;
    }


    /**
     * Log the user off.
     *
     * @return void
     */
    public function logout(): void
    {
        $authsource = new Auth\Simple(self::DEFAULT_SP_AUTHSOURCE);
        $authsource->logout(Module::getModuleURL('SqlAuth/logoutFinished', []));
    }


    /**
     * Say goodbye to the user.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function logoutFinished(): Template
    {
        $t = new Template($this->config, 'SqlAuth:logoutFinished.twig');
        $t->data = [];

        return $t;
    }


    /**
     * Generate a new passcode.
     *
     * @return string
     */
    private function generatePasscode(): string
    {
        $passcode = '';

        for ($i = 0; $i < 6; $i++) {
            $passcode .= strval(random_int(0, 9));
        }

        return $passcode;
    }


    /**
     * Write the user's passcode to the database.
     *
     * @param string $username
     * @param string $passcode
     */
    private function writePasscode(string $username, string $passcode): void
    {
        $db = Database::getInstance();

        $stmt = $db->write(
            'UPDATE `' . $this->tablename . '` SET password_last_set=NOW(), password = :password WHERE uid = :username',
            ['password' => password_hash($passcode, $this->algorithm), 'username' => $username]
        );

        if ($stmt === false) {
            throw new Exception('Updating the last_logon failed.');
        }
    }


    /**
     * Email the user's passcode.
     *
     * @param string $to  The recipient for the mail
     * @param string $passcode  The newly generated passcode
     */
    private function emailPasscode(string $to, string $passcode): void
    {
        $translator = new Translate($this->config);
        $mail = new Utils\EMail($translator->getPreferredTranslation($this->subject), 'tvdijen@hotmail.com', $to);
        $mail->setData(['passcode' => $passcode]);
//        $mail->generateBody('mail_passcode.twig');

//        try {
            $mail->send();
//        } catch (\PHPMailer\PHPMailer\Exception $e) {
//            Logger::warning("Unable to send passcode");
//        }
    }


    /**
     * @param \SimpleSAML\Auth\Simple $authsource
     * @return void
     */
    private function requireAuth(Auth\Simple $authsource): void
    {
        if (!$authsource->isAuthenticated()) {
            $url = Module::getModuleURL('SqlAuth/', []);
            $params = [
                'ErrorURL' => $url,
                'ReturnTo' => $url,
            ];
            $authsource->login($params);
        }

        // Get Authn attributes
        $idp_attrs = $authsource->getAttributes();

        // Require UID
        Assert::keyExists($idp_attrs, $this->userIdentifier);

        $this->session->setData('user', 'idp_attributes', $idp_attrs);
        $this->session->save();
    }
}
