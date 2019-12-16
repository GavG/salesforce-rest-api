<?php
namespace Gmo\Salesforce\Authentication;

use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Gmo\Salesforce\Exception;
use GuzzleHttp;

class PasswordAuthentication implements AuthenticationInterface, LoggerAwareInterface
{
    /** @var LoggerInterface */
    protected $log;
    /** @var string */
    protected $clientId;
    /** @var string */
    protected $clientSecret;
    /** @var string */
    protected $username;
    /** @var string */
    protected $password;
    /** @var string */
    protected $securityToken;
    /** @var string */
    protected $accessToken;

    public function __construct(
        $clientId,
        $clientSecret,
        $username,
        $password,
        $securityToken,
        LoggerInterface $log = null,
        $loginApiUrl = "https://login.salesforce.com/services/oauth2/token"
    ) {
        $this->log = $log ?: new NullLogger();
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->username = $username;
        $this->password = $password;
        $this->securityToken = $securityToken;

        $this->guzzle = new GuzzleHttp\Client();
    }

    /**
     * @inheritdoc
     */
    public function getAccessToken()
    {
        if ($this->accessToken) {
            return $this->accessToken;
        }

        $postFields = array(
            'grant_type' => 'password',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'username' => $this->username,
            'password' => $this->password . $this->securityToken,
        );
        $request = $this->guzzle->post('oauth2/token', null, $postFields);
        $request->setAuth('user', 'pass');
        $response = $request->send();
        $responseBody = $response->getBody();
        $jsonResponse = json_decode($responseBody, true);

        if ($response->getStatusCode() !== 200) {
            $message = $responseBody;
            if (isset($jsonResponse['error_description'])) {
                $message = $jsonResponse['error_description'];
            }
            $this->log->error($message, array('response' => $responseBody));
            throw new Exception\SalesforceAuthentication($message);
        }

        if (!isset($jsonResponse['access_token']) || empty($jsonResponse['access_token'])) {
            $message = 'Access token not found';
            $this->log->error($message, array('response' => $responseBody));
            throw new Exception\SalesforceAuthentication($message);
        }

        $this->accessToken = $jsonResponse['access_token'];

        return $this->accessToken;
    }

    public function invalidateAccessToken()
    {
        $this->accessToken = null;
    }

    /**
     * @inheritdoc
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->log = $logger;
    }

}
