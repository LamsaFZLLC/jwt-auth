<?php

namespace Lamsa\JwtDecoder\Exception;


use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * jwt-auth - UnverifiedTokenException.php
 *
 * Date: 2/27/18
 * Time: 11:54 AM
 * @author    Abdelhameed Alasbahi <abdkwa92@gmail.com>
 * @copyright Copyright (c) 2017 LamsaWorld (http://www.lamsaworld.com/)
 */
class UnverifiedTokenException extends AuthenticationException
{
    public function getMessageKey()
    {
        return 'unverified token';
    }
}