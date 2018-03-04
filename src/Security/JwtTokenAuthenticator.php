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
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * Class JwtTokenAuthenticator
 * @package AppBundle\Security
 */
class JwtTokenAuthenticator extends AbstractGuardAuthenticator
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var JWTEncoderInterface
     */
    private $encoder;

    /**
     * JwtTokenAuthenticator constructor.
     *
     * @param LoggerInterface $logger
     * @param JWTEncoderInterface $encoder
     */
    public function __construct(LoggerInterface $logger,JWTEncoderInterface $encoder)
    {
        $this->encoder = $encoder;
        $this->logger = $logger;
    }

    /**
     * @param Request $request
     *
     * @return bool|false|null|string|\string[]
     */
    public function getCredentials(Request $request)
    {
        $isLoginOrSignupSubmit = ($request->getPathInfo() == '/users/login' || $request->getPathInfo() == '/users/signup') && $request->isMethod('POST');
        if($isLoginOrSignupSubmit){
            return null;
        }

        $extractor = new AuthorizationHeaderTokenExtractor('Bearer','Authorization');
        $token = $extractor->extract($request);

        if(!$token){
            throw new MissingTokenException();
        }
        return $token;
    }

    /**
     * @param mixed $credentials
     * @param UserProviderInterface $userProvider
     *
     * @return User
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $data = [];
        try {
            $data = $this->encoder->decode($credentials);
        } catch (JWTDecodeFailureException $e) {
            switch (true){
                case 'expired_token' === $e->getReason():
                    throw new ExpiredTokenException();
                case 'invalid_token' === $e->getReason():
                    throw new InvalidTokenException();
                case 'unverified_token' === $e->getReason():
                    throw new UnverifiedTokenException();
            }
        }
        $username = $data['username'];

        $roles = $data['roles'];

        $this->logger->info($username.' '."roles",[$roles]);

        $user = new User();
        $user->setRoles(['ROLE_USER']);

        return $user;
    }

    /**
     * @param mixed $credentials
     * @param UserInterface $user
     *
     * @return bool
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     * @param Request $request
     * @param AuthenticationException $exception
     *
     * @return JsonResponse
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [];

        switch (true) {
            case $exception instanceof UsernameNotFoundException:
                return;
            case $exception instanceof ExpiredTokenException:
                $data = array('code' => $exception->getStatusCode(),'message' => $exception->getMessageKey());
                break;
            case $exception instanceof InvalidTokenException:
                $data = array('code' => $exception->getStatusCode(),'message' => $exception->getMessageKey());
                break;
            case $exception instanceof UnverifiedTokenException:
                $data = array('code' => $exception->getStatusCode(),'message' => $exception->getMessageKey());
                break;
            case $exception instanceof MissingTokenException:
                $data = array('code' => $exception->getStatusCode(),'message' => $exception->getMessageKey());
                break;
        }
        return new JsonResponse($data, $exception->getStatusCode());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
    }

    /**
     * @return bool
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * @param Request $request
     * @param AuthenticationException|null $authException
     *
     * @return JsonResponse
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $message = $authException ? $authException->getMessageKey() : 'missing creds';
        return new JsonResponse([
            'error' =>$message],
            401);

    }
}