<?php

namespace Ekapusta\OAuth2Esia;

use Ekapusta\OAuth2Esia\Interfaces\EsiaServiceInterface;
use Ekapusta\OAuth2Esia\Interfaces\Provider\ProviderInterface;
use League\OAuth2\Client\Token\AccessToken;
use UnexpectedValueException;

class EsiaService implements EsiaServiceInterface
{
    private $provider;

    public function __construct(ProviderInterface $provider)
    {
        $this->provider = $provider;
    }

    /**
     * @return string
     */
    public function generateState()
    {
        return $this->provider->generateState();
    }

    /**
     * @param string $generatedState
     *
     * @return string
     */
    public function getAuthorizationUrl($generatedState)
    {
        return $this->provider->getAuthorizationUrl(['state' => $generatedState]);
    }

    /**
     * @param string $generatedState
     * @param string $passedState
     * @param string $passedCode
     *
     * @throws UnexpectedValueException
     *
     * @return array
     */
    public function getResourceOwner($generatedState, $passedState, $passedCode)
    {
        if ($generatedState != $passedState) {
            throw new UnexpectedValueException("Generated and passed states must be same: $generatedState != $passedState");
        }

        $accessToken = $this->provider->getAccessToken('authorization_code', ['code' => $passedCode]);
        $resourceOwner = $this->provider->getResourceOwner($accessToken);

        return $resourceOwner->toArray();
    }

    /**
     * @param string $generatedState
     * @param string $passedState
     * @param string $passedCode
     *
     * @throws UnexpectedValueException
     *
     * @return array
     */
    public function getResourceOwnerOrg($generatedState, $passedState, $passedCode)
    {
        if ($generatedState != $passedState) {
            throw new UnexpectedValueException("Ошибка авторизации! Попробуйте авторизоваться снова. Генерируемые и передаваемые состояния должны быть одинаковыми:  $generatedState != $passedState");
        }

        $accessToken = $this->provider->getAccessToken('authorization_code', ['code' => $passedCode]);
        $resourceOwner = $this->provider->getResourceOwnerOrg($accessToken, $_GET['orgoid']);
        $row = $accessToken->getValues();
        $row['access_token'] = $accessToken->getToken();
        $row['refresh_token'] = $accessToken->getRefreshToken();
        $row['expires'] = $accessToken->getExpires();
        $row['resource_owner_id'] = $accessToken->getResourceOwnerId();
        $row['id_token'] = !isset($row['id_token']) ?  '-1_'. $row['resource_owner_id'] : $row['id_token'];
        $_SESSION['oauth_esia_token_state'] = $row['state'];
        setcookie('oauth_esia_token_state', $row['state'], time() + ONE_DAY, '/');

        return $resourceOwner->toArray();
    }

    public function getResourceOwnerOrgByToken(AccessToken $accessToken, $oid)
    {
        if (isset($accessToken)) {
            $resourceOwner = $this->provider->getResourceOwnerOrg($accessToken, $oid);
            return $resourceOwner->toArray();
        } else {
            throw new \Exception('Ошибка доступа!');
        }
    }
}
