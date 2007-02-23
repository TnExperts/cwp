<?php

Base::useLib('protocol');

final class AddressFormatException extends Exception {
    public function __construct($address, Protocol $protocol = NULL) {
	parent::__construct((string)$address . ': wrong ' .
			    ($protocol === NULL ?
			     '' : $protocol->getName() . ' ') .
			    'address format');
    }
}

abstract class Address {
    const SCOPE_UNKNOWN = 1, SCOPE_HOST = 2, SCOPE_LINK = 4,
	  SCOPE_SITE = 8, SCOPE_GLOBAL = 16;

    private $protocol, $scope;
    protected $address = FALSE, $subnet = FALSE, $netmask = FALSE;

    private static $local;

    protected function __construct(Protocol $protocol, $regex, $address) {
	$address = (string)$address;
	if (!preg_match((string)$regex, $address))
	    throw new AddressFormatException($address, $protocol);

	$this->protocol = $protocol;
    }

    final public function getProtocol() {
	return $this->protocol;
    }

    final public function getAddress() {
	return $this->address;
    }

    final public function getSubnet() {
	return $this->subnet;
    }

    final public function getNetmask() {
	return $this->netmask;
    }

    final public function getScope() {
	if (!isset($this->scope))
	    $this->scope = $this->getAddressScope();
	return $this->scope;
    }

    abstract public static function getLocalhost();

    final public static function getClient() {
	return self::fromString($_SERVER['REMOTE_ADDR']);
    }

    final public static function getLocalAddresses(Protocol $protocol = NULL) {
	if (!isset(self::$local)) {
	    self::$local = array();

	    Base::useLib('interface');
	    foreach (NetworkInterface::getAll() as $iface)
		self::$local = array_merge(self::$local,
					   $iface->getAddresses());
	}

	if ($protocol === NULL)
	    $res = self::$local;
	else {
	    $res = array();
	    foreach (self::$local as $address)
		if ($address->getProtocol() === $protocol)
		    $res[] = $address;
	}

	return $res;
    }

    final public static function getNameservers() {
	static $nameservers;

	if (!isset($nameservers)) {
	    $nameservers = array();

	    $file = fopen('/etc/resolv.conf', 'r');
	    while (!feof($file)) {
		$words = preg_split('/\s+/', trim(fgets($file)), 2);
		if (count($words) === 2 && $words[0] === 'nameserver')
		    try {
			$nameservers[] = self::fromString($words[1]);
		    } catch (AddressFormatException $exception) {}
	    }
	    fclose($file);
	}

	return $nameservers;
    }

    final public function isLocal() {
	foreach (self::getLocalAddresses($this->protocol) as $address) {
	    if ($address->address === $this->address)
		return TRUE;
	}
	return FALSE;
    }

    abstract protected function getAddressScope();

    final public static function fromEthernet(EthernetAddress $ethernet) {
	Base::useLib('service');
	return Service::getAllAddresses($ethernet);
    }

    public function toEthernet() {
	$pipe = popen('/sbin/ip -f ' . $this->protocol->getFamily() .
		      ' neigh show', 'r');

	while (!feof($pipe)) {
	    $neighbour = preg_split('/\s+/', trim(fgets($pipe)));

	    if ($neighbour[0] === $this->address) {
		pclose($pipe);

		if (($pos = array_search('lladdr', $neighbour, TRUE)) === FALSE)
		    continue;
		if (!isset($neighbour[$pos = (int)$pos + 1]))
		    continue;
		return new EthernetAddress($neighbour[$pos]);
	    }
	}

	pclose($pipe);
	throw new AddressFormatException('ethernet(' . $this->address . ')',
					 Protocol::ethernet());
    }

    public function makeDnsReverse() {
	return FALSE;
    }

    abstract public static function makeLocal(EthernetAddress $ethernet);
    abstract public static function makeAuto(NetworkInterface $interface);

    final public static function fromString($string) {
	static $protocols = array('Ipv6', 'Ipv4', 'Ethernet');
	$address = FALSE;

	foreach ($protocols as $protocol) {
	    $class = $protocol . 'Address';
	    try {
		return new $class($string);
	    } catch (AddressFormatException $exception) {}
	}

	throw new AddressFormatException($string);
    }

    final public function __toString() {
	return $this->address;
    }
}

final class Ipv6Address extends Address {
    public function __construct($address) {
	$regex = '%^(([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:)|'
	       . ':((:[0-9a-f]{1,4}){1,7}|:)|'
	       . '[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6}|:)|'
	       . '([0-9a-f]{1,4}:){2}((:[0-9a-f]{1,4}){1,5}|:)|'
	       . '([0-9a-f]{1,4}:){3}((:[0-9a-f]{1,4}){1,4}|:)|'
	       . '([0-9a-f]{1,4}:){4}((:[0-9a-f]{1,4}){1,3}|:)|'
	       . '([0-9a-f]{1,4}:){5}((:[0-9a-f]{1,4}){1,2}|:)|'
	       . '([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}?))'
	       . '(/([1-9]?[0-9]|1([01][0-9]|2[0-8])))?$%';
	parent::__construct(Protocol::ipv6(), $regex, $address);
	$address = self::collapse($address);

	if (strpos($address, '/') === FALSE) {
	    $this->subnet = $address;
	    $this->netmask = 128;
	} else {
	    list($address, $netmask) = explode('/', (string)$address);
	    $this->netmask = (int)$netmask;

	    $addr = self::expand($address);
	    $subnet = array();
	    $bits = $this->netmask;

	    foreach (explode(':', $addr) as $word) {
		if ($bits >= 16)
		    $mask = 0xFFFF;
		else if ($bits > 0)
		    $mask = (0x7FFF << (16 - $bits)) & 0xFFFF;
		else
		    $mask = 0x0000;
		$bits -= 16;

		$subnet[] = dechex(hexdec($word) & $mask);
	    }

	    $this->subnet = self::collapse(implode(':', $subnet));
	}

	$this->address = (string)$address;
    }

    public static function expand($address) {
	if (strpos($address, '::') !== FALSE) {
	    $replace = str_repeat(':0', 8 - substr_count($address, ':')) . ':';
	    $address = str_replace('::', $replace, $address);
	    if ($address{0} === ':')
		$address = '0' . $address;
	    if ($address{strlen($address) - 1} === ':')
		$address .= '0';
	}

	return $address;
    }

    public static function collapse($address) {
	for ($i = 7; $i >= 1; $i--) {
	    $collapsed = preg_replace('/(^|:)(0:){' . $i . '}0($|:)/',
				      '::', $address, 1, $count);
	    if ($count > 0)
		return $collapsed;
	}

	return $address;
    }

    public static function getLocalhost() {
	return new self('::1');
    }

    protected function getAddressScope() {
	if ($this->address === '::1')
	    return parent::SCOPE_HOST;
	$expanded = self::expand($this->address);
	if (strncmp($expanded, 'fe80:0:0:0:', 11) === 0)
	    return parent::SCOPE_LINK;
	if (strncmp($expanded, 'fec0:0:0:', 9) === 0 ||
	    strncmp($expanded, 'fd', 2) === 0)
	    return parent::SCOPE_SITE;
	if ((hexdec(substr($this->address, 0, strpos($this->address, ':')))
	     & 0xE000) === 0x2000)
	    return parent::SCOPE_GLOBAL;
	return parent::SCOPE_UNKNOWN;
    }

    public function makeDnsReverse() {
	$reverse = 'ip6.arpa';

	foreach(explode(':', self::expand($this->address)) as $word) {
	    $str = '';
	    $word = str_repeat('0', 4 - strlen($word)) . $word;
	    for ($i = 0; $i < 4; $i++)
		$reverse = $word{$i} . '.' . $reverse;
	}

	return $reverse;
    }

    public static function makeLocal(EthernetAddress $ethernet) {
	// Make a site-local (RFC 4193) address
	list($usec, $sec) = explode(' ', microtime());
	$sec = (int)$sec & 0xFFFF;
	$usec1 = (float)$usec * (float)(1 << 16);
	$usec2 = (int)round($usec1 * (float)(1 << 16)) & 0xFFFF;
	$usec1 = (int)$usec1 & 0xFFFF;
	$timestamp = sprintf('%08x%04x%04x', $sec, $usec1, $usec2);

	$string = $timestamp . $ethernet->makeEui64();
	if (strlen($string) !== 32)
	    throw new InternalErrorException('site prefix string: ' . $string);
	$string = 'fd' . substr(sha1($string), -10);

	$prefix = '';
	for ($i = 0; $i < 3; $i++)
	    $prefix .= dechex(hexdec(substr($string, $i * 4, 4))) . ':';
	$prefix .= dechex(rand(0x0000, 0xFFFF));

	return new self($prefix . ':' . $ethernet->makeIid() . '/64');
    }

    public static function makeAuto(NetworkInterface $interface) {
	Base::useLib('interface');

	$ethernet = $interface->getAddresses(Protocol::ethernet());
	if (empty($ethernet))
	    throw new InternalErrorException('interface without MAC' .
					     ' address');
	$ethernet = $ethernet[0];

	// Look for a 6to4 prefix
	try {
	    $if6to4 = NetworkInterface::getDefaultRoute();
	    $address = $if6to4->getAddresses(Protocol::ipv4(),
					     Address::SCOPE_GLOBAL);
	} catch (NonexistentInterfaceException $exception) {}

	if (!empty($address)) {
	    $bytes = explode('.', $address[0]->getAddress());
	    $address = '2002';
	    for ($i = 0; $i < 4; $i += 2)
		$address .= ':' . dechex(((int)$bytes[$i] << 8) |
					 (int)$bytes[$i + 1]);
	    $address .= ':' . dechex(rand(0x0000, 0xFFFF))
		      . ':' . $ethernet->makeIid() . '/64';
	    $address = new self($address);
	} else
	    // Finally make our own site-local subnet
	    $address = self::makeLocal($ethernet);

	return $address;
    }
}

final class Ipv4Address extends Address {
    public function __construct($address) {
	$regex = '%^(([1-9]?[0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))\.){3}'
	       . '([1-9]?[0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))'
	       . '(/([12]?[0-9]|3[0-2]|'
	       . '(([1-9]?[0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))\.){3}'
	       . '([1-9]?[0-9]|1[0-9]{2}|2([0-4][0-9]|5[0-5]))))?$%';
	parent::__construct(Protocol::ipv4(), $regex, $address);

	if (strpos($address, '/') === FALSE) {
	    $subnet = explode('.', $address);
	    $class = (int)$subnet[0];

	    if ($class < 192) {
		if ($class < 128) {
		    $this->subnet = $subnet[0] . '.0.0.0';
		    $this->netmask = 8;
		} else {
		    $this->subnet = $subnet[0] . '.' . $subnet[1] . '.0.0';
		    $this->netmask = 16;
		}
	    } else {
		if ($class < 224) {
		    $this->subnet = $subnet[0] . '.' . $subnet[1]
				  . '.' . $subnet[2] . '.0';
		    $this->netmask = 24;
		} else {
		    $this->subnet = (string)($class & 0xF0) . '.0.0.0';
		    $this->netmask = 4;
		}
	    }
	} else {
	    list($address, $netmask) = explode('/', $address);

	    if (strpos($netmask, '.') === FALSE) {
		$this->netmask = (int)$netmask;
		$netmask = self::cidrToMask($netmask);
	    } else
		$this->netmask = self::maskToCidr($netmask);

	    $subnet = explode('.', $address);
	    $netmask = explode('.', $netmask);
	    for ($i = 0; $i < count($subnet); $i++)
		$subnet[$i] = (string)((int)$subnet[$i] & (int)$netmask[$i]);
	    $this->subnet = implode('.', $subnet);
	}

	$this->address = $address;
    }

    public static function cidrToMask($netmask) {
	$netmask = (int)$netmask;
	$mask = '';

	for ($i = 0; $i < 4; $i++) {
	    if ($netmask >= 8)
		$mask .= '255.';
	    else if ($netmask > 0)
		$mask .= (string)((0x7F << (8 - $netmask)) & 0xFF) . '.';
	    else
		$mask .= '0.';
	    $netmask -= 8;
	}

	return substr($mask, 0, -1);
    }

    public static function maskToCidr($netmask) {
	$cidr = 0;

	foreach (explode('.', $netmask) as $byte) {
	    $byte = (int)$byte;
	    for ($i = 7; $i >= 0; $i--)
		if (($byte & (1 << $i)) !== 0)
		    $cidr++;
		else
		    break;
	}

	return $cidr;
    }

    public static function getLocalhost() {
	return new self('127.0.0.1');
    }

    protected function getAddressScope() {
	$bytes = explode('.', $this->address, 2);
	foreach ($bytes as &$byte)
	    $byte = (int)$byte;

	if ($bytes[0] === 127)
	    return parent::SCOPE_HOST;
	if ($bytes[0] === 169 && $bytes[1] === 254)
	    return parent::SCOPE_LINK;
	if ($bytes[0] === 10 ||
	    ($bytes[0] === 172 && ($bytes[1] & 0xF0) === 16) ||
	    ($bytes[0] === 192 && $bytes[1] === 168))
	    return parent::SCOPE_SITE;
	if ($bytes[0] < 224)
	    return parent::SCOPE_GLOBAL;
	return parent::SCOPE_UNKNOWN;
    }

    public function makeDnsReverse() {
	$reverse = 'in-addr.arpa';
	foreach(explode('.', $this->address) as $byte)
	    $reverse = $byte . '.' . $reverse;
	return $reverse;
    }

    public static function makeLocal(EthernetAddress $ethernet) {
	return new self('10.' . rand(0, 255) . '.' . rand(0, 255) . '.1/24');
    }

    public static function makeAuto(NetworkInterface $interface) {
	return self::makeLocal(EthernetAddress::getLocalhost());
    }
}

final class EthernetAddress extends Address {
    public function __construct($address) {
	$regex = '/^([0-9a-f]{2}\:){5}[0-9a-f]{2}$/';
	parent::__construct(Protocol::ethernet(), $regex, $address);
	$this->address = (string)$address;
    }

    public static function getLocalhost() {
	return new self('00:00:00:00:00:00');
    }

    protected function getAddressScope() {
	return parent::SCOPE_LINK;
    }

    public function toEthernet() {
	return $this;
    }

    public static function makeLocal(EthernetAddress $ethernet) {
	$address = '';
	for ($i = 0; $i < 6; $i++)
	    $address .= sprintf('%02x:', rand(0x00, 0xFF));
	return new self(substr($address, 0, -1));
    }

    public static function makeAuto(NetworkInterface $interface) {
	return self::makeLocal(self::getLocalhost());
    }

    public function makeEui64() {
	$mac = str_replace(':', '', $this->address);
	$eui64 = substr($mac, 0, 6) . 'fffe' . substr($mac, 6, 6);
	$eui64{1} = dechex((hexdec($eui64[1]) & 12) | 2);
	return $eui64;
    }

    public function makeIid() {
	$eui64 = $this->makeEui64();
	$iid = '';

	for ($i = 0; $i < 4; $i++)
	    $iid .= dechex(hexdec(substr($eui64, $i * 4, 4))) . ':';

	return substr($iid, 0, -1);
    }
}

?>
