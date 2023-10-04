<?php
/**
 * jwt-auth - UnverifiedTokenException.php
 *
 * Date: 2/27/18
 * Time: 11:54 AM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */
namespace Lamsa\JwtDecoder\Exception;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Class UnverifiedTokenException
 * @package Lamsa\JwtDecoder\Exception
 */
class UnverifiedTokenException extends AuthenticationException
{
    public function getMessageKey(): string
    {
        return 'unverified token';
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