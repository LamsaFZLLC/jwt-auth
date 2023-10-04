<?php
/**
 * content-service - ExpiredTokenException.php
 *
 * Date: 2/24/18
 * Time: 6:24 PM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */

namespace Lamsa\JwtDecoder\Exception;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Class ExpiredTokenException
 * @package AppBundle\Exception
 */
class ExpiredTokenException extends AuthenticationException
{
    /**
     * @return string
     */
    public function getMessageKey(): string
    {
        return 'expired token';
    }

    /**
     * Returns the status code.
     *
     * @return int An HTTP response status code
     */
    public function getStatusCode(): int
    {
        return Response::HTTP_UNAUTHORIZED;
    }
}