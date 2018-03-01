<?php
/**
 * content-service - InvalidTokenException.php
 *
 * Date: 2/24/18
 * Time: 6:26 PM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */

namespace AppBundle\Exception;


use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Class InvalidTokenException
 * @package AppBundle\Exception
 */
class InvalidTokenException extends AuthenticationException
{
    /**
     * @return string
     */
    public function getMessageKey()
    {
        return 'Invalid token';
    }

    /**
     * Returns the status code.
     *
     * @return int An HTTP response status code
     */
    public function getStatusCode()
    {
        return Response::HTTP_UNAUTHORIZED;
    }

}