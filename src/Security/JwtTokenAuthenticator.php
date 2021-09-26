<?php
/**
 * jwt-auth - JwtTokenAuthenticator.php
 *
 * Date: 2/23/18
 * Time: 11:58 PM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */

namespace Lamsa\JwtDecoder\Security;

use Lamsa\JwtDecoder\Entity\User;
use Lamsa\JwtDecoder\Exception\ExpiredTokenException;
use Lamsa\JwtDecoder\Exception\InvalidTokenException;
use Lamsa\JwtDecoder\Exception\MissingTokenException;
use Lamsa\JwtDecoder\Exception\UnverifiedTokenException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Class JwtTokenAuthenticator
 * @package AppBundle\Security
 */
class JwtTokenAuthenticator extends AbstractAuthenticator
{
    /**
     * @var CustomJWTEncoder
     */
    private $encoder;

    /**
     * JwtTokenAuthenticator constructor.
     *
     * @param CustomJWTEncoder $encoder
     */
    public function __construct(CustomJWTEncoder $encoder)
    {
        $this->encoder = $encoder;
    }

    /**
     * @param Request $request
     *
     * @return bool|false|null|string|\string[]
     */
    public function getCredentials(Request $request)
    {
        $extractor = new AuthorizationHeaderTokenExtractor('Bearer', 'Authorization');
        $token     = $extractor->extract($request);

        if (!$token) {
            throw new MissingTokenException();
        }

        return $token;
    }

    /**
     * @param mixed $credentials
     *
     * @return User
     */
    public function getUser($credentials)
    {
        $data = [];
        try {
            $data = $this->encoder->decode($credentials);
        } catch (JWTDecodeFailureException $e) {
            switch (true) {
                case JWTDecodeFailureException::EXPIRED_TOKEN === $e->getReason():
                    throw new ExpiredTokenException();
                case JWTDecodeFailureException::INVALID_TOKEN === $e->getReason():
                    throw new InvalidTokenException();
                case JWTDecodeFailureException::UNVERIFIED_TOKEN === $e->getReason():
                    throw new UnverifiedTokenException();
            }
        }
        $roles  = $data['roles'];
        $userId = $data['user_id'];

        $user = new User();
        $user->setRoles($roles);
        $user->setUserId($userId);

        return $user;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $exception
     *
     * @return Response|null
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        switch (true) {
            case $exception instanceof ExpiredTokenException:
                $data = array('code' => $exception->getStatusCode(), 'message' => $exception->getMessageKey());
                break;
            case $exception instanceof InvalidTokenException:
                $data = array('code' => $exception->getStatusCode(), 'message' => $exception->getMessageKey());
                break;
            case $exception instanceof UnverifiedTokenException:
                $data = array('code' => $exception->getStatusCode(), 'message' => $exception->getMessageKey());
                break;
            case $exception instanceof MissingTokenException:
                $data = array('code' => $exception->getStatusCode(), 'message' => $exception->getMessageKey());
                break;
            default:
                $data = array('code' => 401, 'message' => $exception->getMessage());
        }

        return new JsonResponse($data, $data['code']);
    }

    /**
     * @param Request        $request
     * @param TokenInterface $token
     * @param string         $firewallName
     *
     * @return Response|null
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    /**
     * @param Request $request
     *
     * @return PassportInterface
     */
    public function authenticate(Request $request): PassportInterface
    {
        $apiToken = $this->getCredentials($request);
        if (null === $apiToken || false === $apiToken) {
            throw new MissingTokenException();
        }

        return new SelfValidatingPassport(new UserBadge($apiToken, function($userIdentifier) {
            return $this->getUser($userIdentifier);
        }));
    }

    /**
     * @param Request $request
     *
     * @return bool|null
     */
    public function supports(Request $request): ?bool
    {
        return true;
    }
}