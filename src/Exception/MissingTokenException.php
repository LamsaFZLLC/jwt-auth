<?php
/**
 * content-service - MissingTokenException.php
 *
 * Date: 2/24/18
 * Time: 7:10 PM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */

namespace Lamsa\JwtDecoder\Exception;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Class MissingTokenException
 * @package AppBundle\Exception
 */
class MissingTokenException  extends AuthenticationException
{
    /**
     * @return string
     */
    public function getMessageKey()
    {
        return 'missing token';
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