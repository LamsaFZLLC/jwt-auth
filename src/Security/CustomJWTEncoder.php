<?php
/**
 * jwt-auth - CustomJWTEncoder.php
 *
 * Date: 2/23/18
 * Time: 11:58 PM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */
namespace Lamsa\JwtDecoder\Security;
use JWT\Authentication\JWT;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTEncodeFailureException;
use Psr\Log\LoggerInterface;

/**
 * Class CustomJWTEncoder
 *
 * @package Lamsa\JwtDecoder\Security
 */
class CustomJWTEncoder implements JWTEncoderInterface
{
    const ALGORITHM = 'HS256';

    /**
     * @var int
     */
    private $ttl;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var string
     */
    protected $passPhrase;

    /**
     * @param string $passPhrase
     * @param $ttl
     * @param LoggerInterface $logger
     */
    public function __construct($passPhrase,$ttl,LoggerInterface $logger)
    {
        $this->passPhrase = $passPhrase;
        $this->logger = $logger;
        $this->ttl = $ttl;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(array $data)
    {
        try {
            $data['iat'] = time();
            if (null !== $this->ttl) {
                $data['exp'] = time() + $this->ttl;
            }
            return \Firebase\JWT\JWT::encode($data, $this->passPhrase,self::ALGORITHM);
        }
        catch (\Exception $e) {
            $this->logger->info('exception '.$e->getMessage());
            throw new JWTEncodeFailureException(JWTEncodeFailureException::INVALID_CONFIG, 'An error occurred while trying to encode the JWT token.', $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decode($token)
    {
        try {
            $payload =  (array) \Firebase\JWT\JWT::decode($token, $this->passPhrase);
            $this->checkIssuedAt($payload);
            $this->checkExpiration($payload);
        } catch (\Exception $e) {
            $this->logger->info('exception  '.$e->getMessage());

            switch (true){
                case 'Expired JWT Token' === $e->getMessage():
                    throw new JWTDecodeFailureException(JWTDecodeFailureException::EXPIRED_TOKEN, 'Expired Token', $e);
                case 'Signature verification failed' === $e->getMessage():
                    throw new JWTDecodeFailureException(JWTDecodeFailureException::UNVERIFIED_TOKEN, 'Unverified Token', $e);
            }
            throw new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, 'Invalid Token', $e);
        }
        return $payload;
    }

    /**
     * Ensures that the signature is not expired.
     * @param array $payload
     * @throws JWTDecodeFailureException
     */
    private function checkExpiration(array $payload)
    {

        if (!isset($payload['exp']) || !is_numeric($payload['exp'])) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token');
        }

        if (0 <= (new \DateTime())->format('U') - $payload['exp']) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::EXPIRED_TOKEN, 'Expired JWT Token');
        }
    }

    /**
     * Ensures that the iat claim is not in the future.
     * @param array $payload
     * @throws JWTDecodeFailureException
     */
    private function checkIssuedAt(array $payload)
    {
        if (isset($payload['iat']) && (int) $payload['iat'] > time()) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token');
        }
    }

}