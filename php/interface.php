<?php

Base::useLib('protocol', 'address');

final class NonexistentInterfaceException extends Exception {
    public function __construct($name) {
	parent::__construct($name . ': interface doesn\'t exist.');
    }
}

final class NetworkInterface {
    private $name, $addresses = array();
    private static $all;

    public function __construct($name) {
	$name = (string)$name;
	$this->name = $name;

	$pipe = popen('/sbin/ip addr show dev ' . $name, 'r');
	while (!feof($pipe)) {
	    $line = fgets($pipe);
	    if ($line{0} === ' ') {
		$line = preg_split('/\s+/', trim($line));
		if (count($line) >= 2)
		    try {
			if (($protocol = Protocol::fromFamily($line[0]))
			    !== FALSE) {
			    $class = $protocol->getClass();
			    $this->addresses[] = new $class($line[1]);
			}
		    } catch (AddressFormatException $exception) {}
	    }
	}

	if (pclose($pipe) !== 0)
	    throw new NonexistentInterfaceException($name);
    }

    public function getName() {
	return $this->name;
    }

    public function getAddresses(Protocol $protocol = NULL, $scope = 0) {
	if ($protocol === NULL && $scope === 0) {
	    $addresses = $this->addresses;
	} else {
	    $addresses = array();
	    foreach ($this->addresses as $address) {
		if (($protocol === NULL ||
		     $address->getProtocol() === $protocol) &&
		    ($scope === 0 || ($address->getScope() & $scope) !== 0))
		    $addresses[] = $address;
	    }
	}

	return $addresses;
    }

    public static function getAll() {
	if (!isset(self::$all)) {
	    self::$all = array();

	    $file = fopen('/proc/net/dev', 'r');
	    while (!feof($file)) {
		$line = fgets($file);
		if (($pos = strpos($line, ':')) !== FALSE) {
		    $name = trim(substr($line, 0, $pos));
		    self::$all[$name] = new self($name);
		}
	    }
	    fclose($file);
	}

	return self::$all;
    }

    public static function getDefaultRoute() {
	$pipe = popen('/sbin/ip -4 route show to exact 0/0', 'r');
	while (!feof($pipe)) {
	    $line = trim(fgets($pipe));
	    if (strncmp($line, 'default ', 8) === 0)
		try {
		    $name = preg_replace('/^.*?dev (\S+).*$/', '\1', $line);
		    $interface = new NetworkInterface($name);
		    break;
		} catch (NonexistentInterfaceException $exception) {}
	}
	pclose($pipe);

	if (isset($interface))
	    return $interface;
	throw new NonexistentInterfaceException('Default route');
    }

    public function addAddress(Address $address) {
	if ($address->getProtocol() === Protocol::ethernet())
	    throw new InternalErrorException('try to assign an ethernet ' .
					     'address to an interface');

	$broadcast = $address->getProtocol() === Protocol::ipv4()
		   ? ' broadcast +' : '';
	exec('/sbin/ip -f ' . $address->getProtocol()->getFamily() .
	     ' addr add ' . $address->getAddress() . '/' .
	     $address->getNetmask() . $broadcast . ' dev ' . $this->name,
	     $lines, $retval);
	if ($retval === 0)
	    $this->addresses[] = $address;
	else
	    echo "RETVAL: $retval\n";
    }

    public function addAutoAddresses($protocols = NULL) {
	Base::useLib('config');

	if ($protocols === NULL) {
	    $protocols = Protocol::getAll();
	    while (($key = array_search(Protocol::ethernet(), $protocols, TRUE))
		   !== FALSE)
		unset($protocols[$key]);
	} else if (gettype($protocols) !== 'array')
	    $protocols = array($protocols);

	$bridge = Config::get()->isInterfaceBridge();

	foreach ($protocols as $protocol) {
	    if (gettype($protocol) !== 'object' ||
		!($protocol instanceof Protocol) ||
		!Config::get()->getAutoAddress($protocol))
		continue;

	    if (!$bridge)
		$reach = 1;
	    else if (Config::get()->getBridge($protocol))
		$reach = 0;
	    else
		$reach = 2;

	    $addresses = $this->getAddresses($protocol, Address::SCOPE_GLOBAL |
							Address::SCOPE_SITE);
	    if (count($addresses) < $reach)
		$this->addAddress(eval('return ' . $protocol->getClass() .
				       '::makeAuto($this);'));
	}
    }

    public function up() {
	exec('/sbin/ip link set ' . $this->name . ' up');
    }

    public function down() {
	exec('/sbin/ip link set ' . $this->name . ' down');
    }

    public static function getHostname() {
	try {
	    $default = self::getDefaultRoute();
	    foreach (array(Address::SCOPE_GLOBAL, Address::SCOPE_SITE)
		     as $scope)
		foreach ($default->getAddresses(NULL, $scope) as $address)
		    if ($address->getProtocol() !== Protocol::ethernet()) {
			$address = $address->getAddress();
			if (($host = gethostbyaddr($address)) !== $address)
			    return $host;
		    }
	} catch (NonexistentInterfaceException $exception) {}

	return 'localhost';
    }

    public static function getDomain() {
	$file = fopen('/etc/resolv.conf', 'r');
	while (!feof($file)) {
	    $words = preg_split('/\s+/', trim(fgets($file)), 3);
	    if (count($words) >= 2) {
		if ($words[0] === 'domain') {
		    $domain = $words[1];
		    break;
		} else if (!isset($search) && $words[0] === 'search')
		    $search = $words[1];
	    }
	}
	fclose($file);

	if (isset($domain))
	    return $domain;
	if (isset($search))
	    return $search;

	$fqdn = self::getHostname();
	if (($pos = strpos($fqdn, '.')) !== FALSE)
	    return substr($fqdn, $pos + 1);
	return NULL;
    }

    public function __toString() {
	return $this->name;
    }
}

?>
