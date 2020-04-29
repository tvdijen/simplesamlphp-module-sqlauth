<?php

declare(strict_types=1);

namespace SimpleSAML\Module\SqlAuth\Controller;

use SimpleSAML\Auth;
use SimpleSAML\Configuration;
//use SimpleSAML\HTTP\RunnableResponse;
//use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Webmozart\Assert\Assert;

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
    protected $config;

    /** @var \SimpleSAML\Session */
    protected $session;


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
    }


    /**
     * Display the user details and reset button.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \SimpleSAML\XHTML\Template
     */
    public function main(Request $request): Template
    {
        $authsource = new Auth\Simple('default-sp');
        if (!is_null($request->query->get('logout'))) {
            $authsource->logout($this->config->getBasePath() . 'logout.php');
        } elseif (!is_null($request->query->get(Auth\State::EXCEPTION_PARAM))) {
            // This is just a simple example of an error
            /** @var array $state */
            $state = Auth\State::loadExceptionState();
            Assert::keyExists($state, Auth\State::EXCEPTION_DATA);
            throw $state[Auth\State::EXCEPTION_DATA];
        }

        if (!$authsource->isAuthenticated()) {
            $url = Module::getModuleURL('SqlAuth/', []);
            $params = [
                'ErrorURL' => $url,
                'ReturnTo' => $url,
            ];
            $authsource->login($params);
        }

        $attributes = $authsource->getAttributes();
        $authData = [];
        $t = new Template($this->config, 'SqlAuth:PasswordReset.twig', 'attributes');

        $t->data = [
            'attributes' => $attributes,
            'attributesHtml' => '<h1>Dit zijn je attributen</h1>',
            'authData' => $authData,
            'nameid' => ['Format' => 'transient', 'NameQualifier' => 'test', 'SPNameQualifier' => 'test', 'SPProvidedID' => 'sp', 'value' => 'test'],
            'logouturl' => Utils\HTTP::getSelfURLNoQuery() . '?logout',
        ];

        return $t;
    }
}
