<?php

Base::useLib('config', 'address', 'interface');

final class ServiceDisabledException extends Exception {
    public function __construct($name) {
	parent::__construct((string)$name . ': service disabled.');
    }
}

final class ServiceNotFoundException extends Exception {
    public function __construct($name) {
	parent::__construct((string)$name . ': service not found.');
    }
}

final class ServiceNotSupportedException extends Exception {
    public function __construct($name) {
	parent::__construct((string)$name . ': service not supported.');
    }
}

final class PermissionDeniedException extends Exception {
    public function __construct($name) {
	parent::__construct((string)$name . ': permission denied.');
    }
}

abstract class Service {
    protected static $apache = array('apache', 'httpd', 'http', 'www');

    private $users, $fallback, $simulate;
    protected $exe, $dir, $path, $umask = 0077;
    protected $pidfile, $uid, $gid, $uname, $gname;

    protected function __construct($exe, $users = 0, $fallback = TRUE) {
	if (($this->exe = (string)$exe) !== 'cwp') {
	    $path = '/usr/sbin:/sbin:/usr/bin:/bin:' . $_ENV['PATH']
		. ':/usr/local/sbin:/usr/local/bin';

	    foreach (explode(':', $path) as $dir) {
		$file = $dir . '/' . $this->exe;
		if (is_file($file) && is_executable($file)) {
		    $this->path = $file;
		    break;
		}
	    }
	} else
	    $this->path = '/';

	$this->dir = Config::get()->getStateDir() . '/' . $this->exe;
	$this->users = $users;
	$this->fallback = (boolean)$fallback;
	$this->pidfile = $this->dir . '/' . $this->exe . '.pid';
    }

    final private function setupService()
    {
	if (!Config::get()->getService($this))
	    throw new ServiceDisabledException($this->exe);
	if (!isset($this->path))
	    throw new ServiceNotFoundException($this->exe);
	if (($info = self::findUser($this->users, $this->fallback)) === FALSE)
	    throw new PermissionDeniedException($this->exe);

	$this->uid = $info['uid'];
	$this->gid = $info['gid'];
	$this->uname = $info['name'];
	$info = posix_getgrgid($this->gid);
	$this->gname = $info['name'];
    }

    final protected static function findUser($users, $fallback = FALSE,
					     $group = FALSE) {
	if ($group) {
	    $getid = 'posix_getgid';
	    $getugid = 'posix_getgrgid';
	    $getname = 'posix_getgrnam';
	    $idinfo = 'gid';
	} else {
	    $getid = 'posix_getuid';
	    $getugid = 'posix_getpwuid';
	    $getname = 'posix_getpwnam';
	    $idinfo = 'uid';
	}

	if (gettype($users) !== 'array')
	    $users = array($users);

	if (posix_geteuid() === 0) {
	    if ($fallback)
		$users = array_merge($users, array('nobody', 'guest', 65535,
						   $getid()));

	    foreach ($users as $user) {
		$info = gettype($user) === 'integer'
		      ? $getugid($user) : $getname($user);
		if ($info !== FALSE)
		    return $info;
	    }
	} else {
	    $user = $getugid($getid());
	    if ($fallback || in_array($user[$idinfo], $users, TRUE) ||
		in_array($user['name'], $users, TRUE))
		return $getugid($getid());
	}

	return FALSE;
    }

    final protected static function findGroup($groups, $fallback = FALSE) {
	return self::findUser($groups, $fallback, TRUE);
    }

    final protected function cleanup() {
	if ($this->simulate)
	    return TRUE;

	if (!is_dir($this->dir)) {
	    @unlink($this->dir);
	    mkdir($this->dir);
	}

	if (is_dir($this->dir)) {
	    chmod($this->dir, 0700);
	    chown($this->dir, $this->uid);
	    chgrp($this->dir, $this->gid);
	    return TRUE;
	}

	return FALSE;
    }

    final protected function makeFilename($type, $name = '') {
	if (empty($name))
	    $name = $this->exe;
	return $this->dir . '/' . $name . '.' . $type;
    }

    final protected function writeFile($contents, $type, $name = '',
				       $mode = 0400) {
	$file = $this->makeFilename($type, $name);

	if (!$this->simulate) {
	    if (($contents !== NULL || !is_file($file)) &&
		@file_get_contents($file) !== $contents) {
		if (file_put_contents($file, $contents) === FALSE)
		    return FALSE;
	    }

	    chmod($file, $mode);
	    chown($file, $this->uid);
	    chgrp($file, $this->gid);
	}

	return $file;
    }

    final protected function writeConfig($contents, $name = '') {
	return $this->writeFile($contents, 'conf', $name);
    }

    final protected function deleteFile($type, $name = '') {
	$file = $this->makeFilename($type, $name);
	if (!$this->simulate)
	    @unlink($file);
	return $file;
    }

    final private function getPid() {
	$pid = @file_get_contents($this->pidfile);
	if ($pid === FALSE || empty($pid) || ($ipid = (int)$pid) === 0)
	    return FALSE;
	return $ipid;
    }

    final protected function isRunning() {
	return $this->getPid() !== FALSE;
    }

    final protected function exec($args, $writepid = TRUE,
				  $changeuid = FALSE) {
	if (!$this->simulate) {
	    $pid = pcntl_fork();
	    if ($pid > 0)
		return array();
	    if ($pid === -1)
		return array($this->exe . ': fork failed.');

	    if ($writepid)
		$this->writeFile((string)posix_getpid(), 'pid', '', 0600);
	    else if (file_exists($this->pidfile))
		unlink($this->pidfile);

	    if ($changeuid && posix_geteuid() === 0 && $this->uid !== 0) {
		posix_setgid($this->gid);
		posix_setuid($this->uid);
	    }
	}

	if ($this->path !== '/') {
	    if (gettype($args) === 'string')
		$args = preg_split('/\s+/', trim($args));

	    if ($this->simulate)
		return array('cd ' . $this->dir,
			    $this->path . ' ' . implode(' ', $args));

	    if (chdir($this->dir)) {
		umask($this->umask);
		pcntl_exec($this->path, $args);
	    }

	    exit(-1);
	}

	if ($this->simulate)
	    return array('# start ' . $this->exe . ' processus');

	chdir($this->dir);
	umask($this->umask);
	return TRUE;
    }

    abstract protected function setup();
    abstract protected function launch();

    final public function start($simulate) {
	$this->simulate = $simulate;
	$this->setupService();

	if ($this->setup())
	    return $this->launch();
	return $this->simulate
	     ? array() : array($this->exe . ': setup failed.');
    }

    final public function stop($simulate) {
	$lines = array();

	if ($this->simulate) {
	    $lines[] = 'killall ' . $this->path;
	} else {
	    $lines = array();

	    if (file_exists($this->pidfile)) {
		if (($pid = $this->getPid()) !== FALSE &&
		    !@posix_kill($pid, 15 /* SIGTERM */))
		    $lines[] = 'kill ' . $this->path . '(' . $pid
			    . '): failed terminating service.';
		@unlink($this->pidfile);
	    }

	    return $lines;
	}

	return $lines;
    }

    public function getAddresses(EthernetAddress $ethernet) {
	return array();
    }

    final public static function getAll() {
	$all = array();
	foreach (get_declared_classes() as $class)
	    if (is_subclass_of($class, __CLASS__))
		$all[] = $class;
	return $all;
    }

    final public static function getAllAddresses(EthernetAddress $ethernet) {
	$addresses = array();

	// Get addresses provided by each service
	foreach (self::getAll() as $class) {
	    $service = new $class;
	    $addresses = array_merge($addresses,
				     $service->getAddresses($ethernet));
	}

	// Add IPv6 addresses derived from known prefixes if IPv6 is bridged
	if (Config::get()->getBridge(Protocol::ipv6())) {
	    $found = FALSE;
	    foreach ($addresses as $address)
		if ($address->getProtocol() === Protocol::ipv6()) {
		    $found = TRUE;
		    break;
		}

	    if (!$found) {
		$iid = $ethernet->makeIid();
		$iface = Config::get()->getInterface();
		$pref_addresses = $iface->getAddresses(Protocol::ipv6(),
						       Address::SCOPE_GLOBAL |
						       Address::SCOPE_SITE);

		foreach ($pref_addresses as $address) {
		    if (($netmask = $address->getNetmask()) > 64)
			continue;
		    $subnet = Ipv6Address::expand($address->getSubnet());
		    if (substr($subnet, -8) !== ':0:0:0:0')
			throw new InternalError('IPv6 address expand error');
		    $addresses[] = new Ipv6Address(substr($subnet, 0, -7) .
						   $iid . '/' . $netmask);
		}
	    }
	}

	// Add the current client if no connectivity has otherwise been found
	if (!empty($_SERVER['REMOTE_ADDR'])) {
	    $addr = Address::fromString($_SERVER['REMOTE_ADDR']);
	    $found = FALSE;

	    foreach ($addresses as $address)
		if ($address->getProtocol() === $addr->getProtocol()) {
		    $found = TRUE;
		    break;
		}

	    if (!$found)
		$addresses[] = $addr;
	}

	return $addresses;
    }
}

final class ClientsFile extends Service {
    public function __construct() {
	parent::__construct('cwp', parent::$apache, FALSE);
    }

    protected function setup() {
	$this->cleanup();
	chmod($this->dir, 0700);
	$this->deleteFile('lock', 'clients');
	return $this->writeFile(NULL, 'list', 'clients', 0600) !== FALSE;
    }

    protected function launch() {
	if (($ret = $this->exec(NULL, TRUE, TRUE)) !== TRUE)
	    return $ret;

	Base::useLib('portal');
	$portal = new Portal;
	$delay = Config::get()->getAuthDelay();

	while (TRUE) {
	    $portal->purgeAddresses();
	    sleep($delay);
	}
    }

    public function getAddresses(EthernetAddress $ethernet) {
	return array();
    }
}

final class Radvd extends Service {
    private $prefixes = array(), $iface, $if6to4;
    private $config, $log;

    public function __construct() {
	parent::__construct('radvd', 'radvd');

	// First try to use already assigned addresses
	$this->iface = Config::get()->getInterface();
	$addresses = $this->iface->getAddresses(Protocol::ipv6(),
						Address::SCOPE_GLOBAL |
						Address::SCOPE_SITE);
	if (Config::get()->isInterfaceBridge())
	    array_shift($addresses);
	foreach ($addresses as $address)
	    if (($netmask = $address->getNetmask()) <= 64)
		$this->prefixes[] = $address->getSubnet() . '/' . $netmask;
    }

    protected function setup() {
	if (Config::get()->getBridge(Protocol::ipv6()))
	    throw new ServiceDisabledException($this->exe);
	if (empty($this->prefixes))
	    throw new ServiceNotSupportedException($this->exe);

	$config = 'interface ' . $this->iface->getName() . " {\n"
		. "\tAdvSendAdvert on;\n";
	foreach ($this->prefixes as $number => $prefix) {
	    $config .= "\tprefix " . $prefix . " {\n"
		     . "\t\tAdvOnLink on;\n"
		     . "\t\tAdvAutonomous on;\n";
	    if ($number === 0 && isset($this->if6to4))
		$config .= "\t\tBase6to4Interface " . $this->if6to4->getName()
			 . ";\n";
	    $config .= "\t};\n";
	}
	$config .= "};\n";

	$this->cleanup();
	chmod($this->dir, 0700);

	$this->config = $this->writeConfig($config);
	$this->log = $this->writeFile(NULL, 'log', '', 0600);
	return $this->config !== FALSE && $this->log !== FALSE;
    }

    protected function launch() {
	return $this->exec(array('-C', $this->config, '-p', $this->pidfile,
				 '-m', 'logfile', '-l', $this->log,
				 '-u', $this->uname), FALSE);
    }

    public function getAddresses(EthernetAddress $ethernet) {
	if (!$this->isRunning())
	    return array();

	$iid = $ethernet->makeIid();
	$addresses = array();

	foreach ($this->prefixes as $prefix) {
	    list($subnet, $netmask) = explode('/', $prefix);
	    $subnet = Ipv6Address::expand($subnet);

	    if (substr($subnet, -8) !== ':0:0:0:0')
		throw new InternalError('invalid radvd prefix');
	    $addresses[] = new Ipv6Address(substr($subnet, 0, -7) . $iid .
					   '/' . $netmask);
	}

	return $addresses;
    }
}

final class Dhcpv4d extends Service {
    private $iface, $config, $leases;

    public function __construct() {
	parent::__construct('dhcpd', array('dhcp', 'dhcpd'));
    }

    protected function setup() {
	Base::useLib('portal');

	if (Config::get()->getBridge(Protocol::ipv4()))
	    throw new ServiceDisabledException($this->exe);

	$iface = Config::get()->getInterface();
	$address = $iface->getAddresses(Protocol::ipv4(),
					Address::SCOPE_GLOBAL |
					Address::SCOPE_SITE);

	$this->iface = $iface->getName();
	reset($address);
	if (Config::get()->isInterfaceBridge())
	    $address = next($address);
	else
	    $address = current($address);

	if (empty($address))
	    throw new ServiceNotSupportedException($this->exe);

	$addr = $address->getAddress();
	$subnet = $address->getSubnet();
	$netmask = Ipv4Address::cidrToMask($address->getNetmask());

	$config = "ddns-update-style interim;\n"
		. 'subnet ' . $subnet . ' netmask ' . $netmask . " {\n"
		. "\tauthoritative;\n";

	foreach (array('addr', 'subnet', 'netmask') as $var) {
	    $$var = explode('.', $$var);
	    foreach ($$var as &$byte)
		$byte = (int)$byte;
	    unset($byte);
	}

	$first = $subnet;
	$first[3]++;

	$broadcast = array();
	for ($i = 0; $i < count($subnet); $i++)
	    $broadcast[$i] = $subnet[$i] | (~$netmask[$i] & 255);

	$last = $broadcast;
	$last[3]--;

	$subnet = $address->getSubnet();
	$netmask = Ipv4Address::cidrToMask($address->getNetmask());
	foreach (array('first', 'last', 'broadcast') as $var)
	    $$var = implode('.', $$var);

	if ($address->getAddress() !== $first) {
	    $before = $addr;
	    for ($i = 3; $i >= 0; $i--) {
		if ($before[$i] > 0) {
		    $before[$i]--;
		    break;
		}
		$before[$i] = 255;
	    }
	    $before = implode('.', $before);

	    $config .= "\trange " . $first . ' ' . $before . ";\n";
	}

	if ($address->getAddress() !== $last) {
	    $after = $addr;
	    for ($i = 3; $i >= 0; $i--) {
		if ($after[$i] < 255) {
		    $after[$i]++;
		    break;
		}
		$after[$i] = 0;
	    }
	    $after = implode('.', $after);

	    $config .= "\trange " . $after . ' ' . $last . ";\n";
	}

	$addr = $address->getAddress();
	$config .= "\tdefault-lease-time 600;\n"
		 . "\tmax-lease-time 7200;\n"
		 . "\tserver-identifier " . $addr . ";\n"
		 . "\tserver-name \"" . Portal::HOSTNAME . "\";\n"
		 . "\toption subnet-mask " . $netmask . ";\n"
		 . "\toption broadcast-address " . $broadcast . ";\n"
		 . "\toption routers " . $addr . ";\n";

	if (Config::get()->getService('Dns'))
	    $nameservers = array($addr);
	else {
	    $nameservers = array();
	    foreach (Address::getNameservers() as $nameserver)
		if ($nameserver->getProtocol() === Protocol::ipv4())
		    $nameservers[] = $nameserver->getAddress();
	}

	if (count($nameservers) > 0)
	    $config .= "\toption domain-name-servers "
		     . implode(', ', $nameservers) . ";\n";

	$domain = NetworkInterface::getDomain();
	if (!empty($domain))
	    $config .= "\toption domain-name \"" . $domain . "\";\n";

	$config .= "}\n";

	$this->cleanup();
	$this->config = $this->writeConfig($config);
	$this->leases = $this->writeFile(NULL, 'leases');
	$this->writeFile(NULL, 'leases~');

	return $this->config !== FALSE;
    }

    protected function launch() {
	if (($group = self::findGroup(parent::$apache)) !== FALSE) {
	    $this->umask = 0037;
	    chgrp($this->dir, $group['gid']);
	    chmod($this->dir, 0710);
	    $group = $group['name'];
	} else {
	    $this->umask = 0033;
	    chmod($this->dir, 0711);
	    $group = $this->gname;
	}

	return $this->exec(array('-q', '-cf', $this->config,
				 '-pf', $this->pidfile, '-lf', $this->leases,
				 '-user', $this->uname, '-group', $group,
				 $this->iface));
    }

    public function getAddresses(EthernetAddress $ethernet) {
	if (!$this->isRunning())
	    return array();

	if (($leases = file_get_contents($this->makeFilename('leases')))
	    === FALSE)
	    return array();

	$leases = preg_replace("/#.*?\n/", '', $leases);
	$leases = preg_replace('/([{};])/', ' \1 ', $leases);
	$leases = preg_split('/\s+/', trim($leases));

	$nextcmd = TRUE;
	while (($token = array_shift($leases)) !== NULL) {
	    $newcmd = $nextcmd;
	    $nextcmd = FALSE;

	    switch ($token) {
	    case 'lease':
		if ($newcmd) {
		    unset($ip);
		    try {
			$ip = new Ipv4Address(current($leases));
			array_shift($leases);
		    } catch (AddressFormatException $exception) {}
		}
		break;

	    case 'hardware':
		if ($newcmd && current($leases) === 'ethernet') {
		    array_shift($leases);
		    if (($mac = current($leases)) === $ethernet->getAddress())
			return isset($ip) ? array($ip) : array();
		}
		break;

	    case '{':
	    case '}':
	    case ';':
		$nextcmd = TRUE;
	    }
	}

	return array();
    }
}

final class Dns extends Service {
    private $config;

    public function __construct() {
	parent::__construct('named', array('named', 'bind'));
    }

    protected function setup() {
	Base::useLib('portal');

	$serial = 0;
	$iface = Config::get()->getInterface();
	$scope = Address::SCOPE_GLOBAL | Address::SCOPE_SITE;

	$config = "options {\n"
		. "\tdirectory \"" . $this->dir . "\";\n"
		. "\tpid-file  \"" . $this->pidfile . "\";\n"
		. "\tversion   \"Undisclosed\";\n"
		. "\n"
		. "\tlisten-on {\n";

	$addresses = $iface->getAddresses(Protocol::ipv4(), $scope);
	if (empty($addresses))
	    $config .= "\t\tnone;\n";
	else
	    foreach ($addresses as $address)
		$config .= "\t\t" . $address->getAddress() . ";\n";
	$config .= "\t};\n"
		 . "\tlisten-on-v6 { ";

	if (count($iface->getAddresses(Protocol::ipv6(), $scope)) > 0)
	    $config .= "any";
	else
	    $config .= "none";

	$config .= "; };\n"
		 . "\n"
		 . "\tquery-source-v6 address * port 53;\n"
		 . "\tquery-source    address * port 53;\n"
		 . "\n"
		 . "\tforwarders {\n";

	foreach (Address::getNameservers() as $address)
	    $config .= "\t\t" . $address->getAddress() . ";\n";

	$config .= "\t};\n"
		 . "};\n"
		 . "\n"
		 . "logging {\n"
		 . "\tcategory lame-servers { null; };\n"
		 . "\tcategory config       { null; };\n"
		 . "\tcategory network      { null; };\n"
		 . "\tcategory general      { null; };\n"
		 . "\tcategory notify       { null; };\n"
		 . "};\n"
		 . "\n"
		 . "controls {};\n"
		 . "\n"
		 . "zone \"localhost\" IN {\n"
		 . "\ttype master;\n"
		 . "\tfile \"localhost.zone\";\n"
		 . "\tallow-update { none; };\n"
		 . "\tnotify no;\n"
		 . "\tforwarders {};\n"
		 . "};\n"
		 . "\n"
		 . 'zone "1' . str_repeat('.0', 31) . ".ip6.arpa\" IN {\n"
		 . "\ttype master;\n"
		 . "\tfile \"localhost-rev.zone\";\n"
		 . "\tallow-update { none; };\n"
		 . "\tnotify no;\n"
		 . "\tforwarders {};\n"
		 . "};\n"
		 . "\n"
		 . "zone \"1.0.0.127.in-addr.arpa\" IN {\n"
		 . "\ttype master;\n"
		 . "\tfile \"localhost-rev.zone\";\n"
		 . "\tallow-update { none; };\n"
		 . "\tnotify no;\n"
		 . "\tforwarders {};\n"
		 . "};\n"
		 . "\n"
		 . 'zone "' . Portal::HOSTNAME . "\" IN {\n"
		 . "\ttype master;\n"
		 . "\tfile \"portal.zone\";\n"
		 . "\tallow-update { none; };\n"
		 . "\tnotify no;\n"
		 . "\tforwarders {};\n"
		 . "};\n";

	$soa = "\$TTL 1W\n"
	     . "@\tIN\tSOA\t" . Portal::HOSTNAME . '. root.' .
		Portal::HOSTNAME . ". (\n"
	     . "\t\t\t\t" . $serial . "\t; Serial\n"
	     . "\t\t\t\t8H\t; Refresh\n"
	     . "\t\t\t\t2H\t; Retry\n"
	     . "\t\t\t\t1W\t; Expire\n"
	     . "\t\t\t\t1D )\t; Minimum\n"
	     . "\tIN\tNS\t" . Portal::HOSTNAME . ".\n";

	$zone_localhost = "\tIN\tAAAA\t::1\n\tIN\tA\t127.0.0.1\n";
	$rev_localhost  = "\tIN\tPTR\tlocalhost.\n";
	$rev_portal     = "\tIN\tPTR\t" . Portal::HOSTNAME . ".\n";

	$zone_portal = '';
	foreach ($iface->getAddresses(NULL, $scope)
		 as $address)
	    if (($record = $address->getProtocol()->getDnsRecord()) !== FALSE) {
		$zone_portal .= "\tIN\t" . $record . "\t"
			      . $address->getAddress() . "\n";
		$config .= "\nzone \"" . $address->makeDnsReverse()
			 . "\" IN {\n"
			 . "\ttype master;\n"
			 . "\tfile \"portal-rev.zone\";\n"
			 . "\tallow-update { none; };\n"
			 . "\tnotify no;\n"
			 . "\tforwarders {};\n"
			 . "};\n";
	    }

	$this->cleanup();
	$this->writeFile($soa . $zone_localhost, 'zone', 'localhost');
	$this->writeFile($soa . $zone_portal,    'zone', 'portal');
	$this->writeFile($soa . $rev_localhost,  'zone', 'localhost-rev');
	$this->writeFile($soa . $rev_portal,     'zone', 'portal-rev');
	$this->config = $this->writeConfig($config);

	return $this->config !== FALSE;
    }

    protected function launch() {
	@unlink($this->pidfile);
	return $this->exec(array('-c', $this->config, '-u', $this->uname),
			   FALSE);
    }

    public function getAddresses(EthernetAddress $ethernet) {
	return array();
    }
}

?>
