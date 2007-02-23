<?php

final class UnknownProtocolException extends Exception {
    public function __construct($protocol) {
	parent::__construct((string)$protocol . ': unknown protocol');
    }
}

final class Protocol {
    private $family, $name, $class, $record;
    private static $protocols;

    private function __construct($family, $name, $class, $record = FALSE) {
	$this->family = $family;
	$this->name = $name;
	$this->class = $class . 'Address';
	$this->record = $record;
	self::$protocols[$family] = $this;
    }

    public function getFamily() {
	return $this->family;
    }

    public function getName() {
	return $this->name;
    }

    public function getClass() {
	return $this->class;
    }

    public function getDnsRecord() {
	return $this->record;
    }

    private static function buildProtocols() {
	if (!isset(self::$protocols)) {
	    self::$protocols = array();
	    new self('inet6',      'IPv6',     'Ipv6', 'AAAA');
	    new self('inet',       'IPv4',     'Ipv4', 'A');
	    new self('link/ether', 'Ethernet', 'Ethernet');
	}
    }

    public static function ipv6() {
	self::buildProtocols();
	return self::$protocols['inet6'];
    }

    public static function ipv4() {
	self::buildProtocols();
	return self::$protocols['inet'];
    }

    public static function ethernet() {
	self::buildProtocols();
	return self::$protocols['link/ether'];
    }

    public static function getAll() {
	self::buildProtocols();
	return self::$protocols;
    }

    public static function fromFamily($family) {
	self::buildProtocols();
	$family = (string)$family;

	return isset(self::$protocols[$family])
	     ? self::$protocols[$family] : FALSE;
    }

    public function __toString() {
	return $this->name;
    }
}

?>
