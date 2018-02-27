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

use Lamsa\JwtDecoder\Exception\UnverifiedTokenException;
use Lamsa\JwtDecoder\Entity\User;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\ExpiredTokenException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\InvalidTokenException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\MissingTokenException;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
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
        $isLoginSubmit = $request->getPathInfo() == '/login' && $request->isMethod('POST');
        if($isLoginSubmit){
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
        try {
            $data = $this->encoder->decode($credentials);
        } catch (JWTDecodeFailureException $e) {
            $this->logger->error("Exception message ",[$e->getMessage(),$e->getCode()]);
            $this->logger->error("Exception reason ",[$e->getReason(),$e->getCode()]);

            switch (true){
                case 'expired_token' === $e->getReason():
                    throw new ExpiredTokenException();
                case 'invalid_token' === $e->getReason():
                    throw new InvalidTokenException();
                case 'unverified_token' === $e->getReason():
                    throw new UnverifiedTokenException();
            }
        }
        $this->logger->error("Token Data Here ",$data);
        $username = $data['username'];

        $roles = $data['roles'];
        if($roles !== 'admin'){
//            throw new UnauthorizedException();
        }

        $this->logger->info("roles",[$roles]);

        $identity = new User();
        $identity->setRoles(['ROLE_USER']);
        $this->logger->info('role',$identity->getRoles());
        return $identity;
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
        if($exception instanceof UsernameNotFoundException){
            return;
        }
        $data = array(
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())
        );

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
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