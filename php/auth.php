<?php

Base::useLib('config');

interface iAuthenticater {
    public function validate($login, $password);
}

final class AuthTest implements iAuthenticater {
    public function validate($login, $password) {
	return $login === 'luke' && $password == 'ifeeltheforce';
    }
}

final class RadiusException extends Exception {
    public function __construct($text) {
	parent::__construct('RADIUS authentication error: ' . $text . '.');
    }
}

final class Radius implements iAuthenticater {
    const TIMEOUT = 5, TRIES = 3;
    private $server, $port, $secret;

    public function __construct() {
	$config = Config::get();
	$this->server = $config->getRadiusServer();
	$this->port = $config->getRadiusPort();
	$this->secret = $config->getRadiusSecret();
    }

    public function validate($login, $password) {
	$radius = radius_auth_open();

	if (!radius_add_server($radius, $this->server, $this->port,
			       $this->secret, self::TIMEOUT, self::TRIES) ||
	    !radius_create_request($radius, RADIUS_ACCESS_REQUEST) ||
	    !radius_put_attr($radius, RADIUS_USER_NAME,     $login) ||
	    !radius_put_attr($radius, RADIUS_USER_PASSWORD, $password) ||
	    ($result = radius_send_request($radius)) === FALSE)
	    throw new RadiusException(radius_strerror($radius));
	radius_close($radius);

	switch ($result) {
	case RADIUS_ACCESS_ACCEPT:
	    return TRUE;

	case RADIUS_ACCESS_REJECT:
	    return FALSE;

	case RADIUS_ACCESS_CHALLENGE:
	    throw new RadiusException('unhandled challenge request');
	}

	throw new RadiusException('unknown response');
    }
}

?>
