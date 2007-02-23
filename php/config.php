<?php

final class EmptyConfigVariableException extends Exception {
    public function __construct($name) {
	parent::__construct($name . ': configuration variable not set and ' .
			    'no suitable default value found.');
    }
}

final class Config {
    private static $config;
    private $vars = array(), $cache = array();

    private function __construct() {
	@include dirname(__FILE__) . '/dirs.php';
	if (isset($CONFDIR))
	    $this->vars['CONFDIR'] = $CONFDIR;

	@include $this->getConfigDir() . '/config.php';
	if (isset($CONFDIR))
	    $this->vars['CONFDIR'] = $CONFDIR;

	while (isset($CONFDIR) && isset($this->vars['CONFDIR']) &&
	       $CONFDIR !== $this->vars['CONFDIR']) {
	    $this->vars['CONFDIR'] = $CONFDIR;
	    @include $this->getConfigDir() . '/config.php';
	}

	$this->vars = get_defined_vars();
    }

    private function getCache($name) {
	if (isset($this->cache[$name]))
	    return $this->cache[$name];
	return NULL;
    }

    private function setCache($name, $value) {
	$this->cache[$name] = $value;
	return $value;
    }

    private function getValue($name, $default) {
	if (isset($this->vars[$name]))
	    return $this->vars[$name];
	return $default;
    }

    private function getValueArray($name, $default = array()) {
	if (($value = $this->getValue($name, NULL)) === NULL)
	    return $default;
	return array($value);
    }

    private function getDirectory($name, $default = array(), $create = FALSE) {
	if (($value = $this->getCache($name)) !== NULL)
	    return $value;
	$values = array_merge($this->getValueArray($name), $default);

	foreach ($values as $dir)
	    if (is_dir($dir))
		return $this->setCache($name, (string)$dir);

	if ($create)
	    foreach ($values as $dir)
		if (@mkdir($dir))
		    return $this->setCache($name, (string)$dir);

	throw new EmptyConfigVariableException($name);
    }

    public function getLibDir() {
	static $default = array('/usr/lib/cwp', '/usr/local/lib/cwp');
	return self::getDirectory('LIBDIR', $default);
    }

    public function getDataDir() {
	if (($value = $this->getCache('DATADIR')) !== NULL)
	    return $value;

	$default = array(dirname(dirname(__FILE__)),
			 '/usr/share/cwp', '/usr/local/share/cwp');
	return $this->getDirectory('DATADIR', $default);
    }

    public function getConfigDir() {
	static $default = array('/etc/cwp', '/etc/local/cwp',
				'/usr/local/etc/cwp');
	return $this->getDirectory('CONFDIR', $default);
    }

    public function getPhpDir() {
	return $this->getDataDir() . '/php';
    }

    public function getHtmlDir() {
	return $this->getDataDir() . '/htdocs';
    }

    public function getStateDir() {
	static $default = array('/var/lib/cwp', '/var/local/var/lib/cwp',
				'/usr/local/var/lib/cwp',
				'/var/local/var/cwp', '/usr/local/var/cwp');
	return $this->getDirectory('STATEDIR', $default, TRUE);
    }

    public function getFirewall() {
	return (string)$this->getValue('FIREWALL', 'Iptables');
    }

    public function getAuth() {
	return (string)$this->getValue('AUTH', 'AuthTest');
    }

    public function getAuthDelay() {
	return (int)$this->getValue('AUTH_DELAY', 60);
    }

    public function getRadiusServer() {
	return (string)$this->getValue('RADIUS_SERVER', 'localhost');
    }

    public function getRadiusPort() {
	return (int)$this->getValue('RADIUS_PORT', 0);
    }

    public function getRadiusSecret() {
	return (string)$this->getValue('RADIUS_SECRET', '');
    }

    private function getValidInterface($var, $test_ifaces) {
	if (($value = $this->getCache($var)) !== NULL)
	    return $value;

	if (($interfaces = $this->getValue($var, NULL)) === NULL)
	    $interfaces = $test_ifaces;
	else
	    $interfaces = array($interfaces);

	Base::useLib('interface');
	foreach ($interfaces as $name)
	    try {
		return $this->setCache($var, new NetworkInterface($name));
	    } catch (NonexistentInterfaceException $exception) {}

	throw new EmptyConfigVariableException($var);
    }

    public function getInternalInterface() {
	//TODO: faire propre !!!
	static $test_ifaces = array('wlan0', 'ath0', 'eth1', 'eth0');
	return $this->getValidInterface('INT_INTERFACE', $test_ifaces);
    }

    public function getInterface() {
	$test_ifaces = array('br0', $this->getInternalInterface()->getName());
	return $this->getValidInterface('INTERFACE', $test_ifaces);
    }

    public function isInterfaceBridge() {
	return preg_match('/^br[0-9]+$/', $this->getInterface()->getName());
    }

    public function getUseNat() {
	return (boolean)$this->getValue('USE_NAT', TRUE);
    }

    public function getUseMac() {
	return (boolean)$this->getValue('USE_MAC', TRUE);
    }

    public function getAutoAddress(Protocol $protocol) {
	return (boolean)$this->getValue('AUTO_' .
					strtoupper($protocol->getName()),
					TRUE);
    }

    public function getBridge(Protocol $protocol) {
	return (boolean)$this->getValue('BRIDGE_' .
					strtoupper($protocol->getName()),
					$this->isInterfaceBridge());
    }

    public function getService($service, $default = TRUE) {
	$service = (gettype($service) === 'object' &&
		    $service instanceof Service)
		 ? get_class($service) : (string)$service;
	return $this->getValue(strtoupper($service), $default);
    }

    public static function get() {
	if (!isset(self::$config))
	    self::$config = new self;
	return self::$config;
    }
}

?>
