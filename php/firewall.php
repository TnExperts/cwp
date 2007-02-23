<?php

Base::useLib('config', 'protocol', 'address', 'interface');

interface iFirewall {
    public function __construct(NetworkInterface $iface = NULL);

    public function commit($simulate = FALSE);
    public function undo($simulate = FALSE);

    public function begin();
    public function addPing();
    public function addAutoConf();
    public function addAntiSpoof();
    public function addAuthorizedClients();
    public function addNat();
    public function addNameserver(Address $nameserver);
    public function addPortal();
    public function addBlockEverything();

    public function addClient(EthernetAddress $ethernet, $addresses);
}

final class Iptables implements iFirewall {
    const IPV6 = 1, IPV4 = 2, BOTH = 3, ETHERNET = 4;
    private static $cmd_reverse = array(
	'A' => 'D',
	'D' => 'D',
	'F' => 'F',
	'I' => 'D',
	'N' => 'X'
    );
    private static $ipt_exes = array(
	'ip6t_path' => 'ip6tables',
	'ip4t_path' => 'iptables',
	'ebt_path'  => 'ebtables'
    );

    private $commands = array();
    private $interface, $iface, $int_iface, $is_bridge;
    private $ip6t_path, $ip4t_path, $ebt_path;

    public function __construct() {
	$this->interface = Config::get()->getInterface();
	$this->iface = $this->interface->getName();
	$this->int_iface = Config::get()->getInternalInterface()->getName();
	$this->is_bridge = Config::get()->isInterfaceBridge();

	$this->bridge = 0;
	if (Config::get()->getBridge(Protocol::ipv6()))
	    $this->bridge |= self::IPV6;
	if (Config::get()->getBridge(Protocol::ipv4()))
	    $this->bridge |= self::IPV4;

	$path = array_merge(array(Config::get()->getLibDir(),
				  '/usr/sbin', '/sbin'),
			    explode(':', $_ENV['PATH']));

	foreach (self::$ipt_exes as $var => $exe)
	    foreach ($path as $dir) {
		$file = $dir . '/' . $exe;
		if (is_file($file) && is_executable($file)) {
		    $this->$var = $file;
		    break;
		}
	    }
    }

    public function __destruct() {
	$this->commit();
    }

    private function exec($rule, $protocol = self::BOTH, $verbatim = FALSE) {
	if ($protocol & self::IPV4 && isset($this->ip4t_path))
	    $this->commands[] = $this->ip4t_path . ' ' . $rule;
	if ($protocol & self::IPV6 && isset($this->ip6t_path))
	    $this->commands[] = $this->ip6t_path . ' ' . $rule;
	if ($protocol & self::ETHERNET && isset($this->ebt_path))
	    $this->commands[] = $this->ebt_path . ' ' . $rule;
    }

    public function commit($simulate = FALSE) {
	if (empty($this->commands))
	    $lines = array();
	else {
	    foreach ($this->commands as &$command)
		$command = escapeshellcmd($command);
	    unset($command);

	    if ($simulate)
		$lines = $this->commands;
	    else {
		$lines = array();
		foreach ($this->commands as $command) {
		    unset($clines);
		    exec($command, $clines, $retval);
		    if ($retval !== 0)
			$lines[] = 'Failed: ' . $command;
		    $lines = array_merge($lines, $clines);
		}
	    }

	    $this->commands = array();
	}

	return $lines;
    }

    public function undo($simulate = FALSE) {
	foreach ($this->commands as &$rule) {
	    $done = FALSE;
	    foreach (self::$cmd_reverse as $command => $reverse) {
		if (strpos($rule, ' -' . $command . ' ') !== FALSE) {
		    $rule = str_replace(' -' . $command . ' ',
					' -' . $reverse . ' ', $rule);
		    $done = TRUE;
		}
	    }

	    if (!$done)
		throw new InternalErrorException($rule .
						 ': unknown iptables ' .
						 'command reverse');
	}

	$this->commands = array_reverse($this->commands);
	return $this->commit($simulate);
    }

    public function begin() {
	if (!$this->is_bridge) {
	    $this->exec('-t mangle -A PREROUTING -i ' . $this->iface .
			' -j MARK --set-mark 1');
	    $this->exec('-t mangle -A PREROUTING -i ! ' . $this->iface .
			' -j MARK --set-mark 2');
	    $this->exec('-t mangle -A POSTROUTING -o ' . $this->iface .
			' -m mark --mark 4 -j DROP');
	    $this->exec('-t mangle -A POSTROUTING -o ! ' . $this->iface .
			' -m mark --mark 3 -j DROP');
	}

	$this->exec('-t nat -A PREROUTING -i ' . $this->int_iface .
		    ' -j mark --set-mark 1', self::ETHERNET);
	$this->exec('-t nat -A PREROUTING -i ! ' . $this->int_iface .
		    ' -j mark --set-mark 2', self::ETHERNET);
	$this->exec('-t nat -A POSTROUTING -o ' . $this->int_iface .
		    ' --mark 4 -j DROP', self::ETHERNET);
	$this->exec('-t nat -A POSTROUTING -o ! ' . $this->int_iface .
		    ' --mark 3 -j DROP', self::ETHERNET);
    }

    public function addPing() {
	foreach (array('request', 'reply') as $request) {
	    $this->exec('-A INPUT -i ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type echo-' . $request .
			' -m mark --mark 1 -j ACCEPT', self::IPV6);
	    $this->exec('-A INPUT -i ' . $this->iface .
			' -p icmp --icmp-type echo-' . $request .
			' -m mark --mark 1 -j ACCEPT', self::IPV4);

	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type echo-' . $request .
			' -j ACCEPT', self::IPV6);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type echo-' . $request .
			' -j MARK --set-mark 5', self::IPV6);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p icmp --icmp-type echo-' . $request .
			' -j ACCEPT', self::IPV4);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p icmp --icmp-type echo-' . $request .
			' -j MARK --set-mark 5', self::IPV4);
	}
    }

    public function addAutoConf() {
	// Neighbour solicitation/advertisement
	foreach (array('solicitation', 'advertisement') as $request) {
	    $this->exec('-A INPUT -i '  . $this->iface .
			' -p ipv6-icmp --icmpv6-type neighbour-' .
			$request . ' -j ACCEPT', self::IPV6);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type neighbour-' .
			$request . ' -j ACCEPT', self::IPV6);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type neighbour-' .
			$request . ' -j MARK --set-mark 5', self::IPV6);

	    if (($this->bridge & self::IPV6) !== 0) {
		$this->exec('-A FORWARD -i ' . $this->iface .
			    ' -o ' . $this->iface .
			    ' -p ipv6-icmp --icmpv6-type neighbour-' .
			    $request . ' -j ACCEPT', self::IPV6);
		$this->exec('-A FORWARD -i ' . $this->iface .
			    ' -o ' . $this->iface .
			    ' -p ipv6-icmp --icmpv6-type neighbour-' .
			    $request . ' -j ACCEPT', self::IPV6);
	    }
	}

	// Router solicitation/advertisement
	if (($this->bridge & self::IPV6) === 0) {
	    $this->exec('-A INPUT -i ' . $this->iface . ' -m mark --mark 1' .
			' -p ipv6-icmp --icmpv6-type router-solicitation ' .
			'-j ACCEPT', self::IPV6);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type router-advertisement ' .
			'-j ACCEPT', self::IPV6);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type router-advertisement ' .
			'-j MARK --set-mark 3', self::IPV6);
	} else {
	    $this->exec('-A INPUT -i ' . $this->iface . ' -m mark --mark 2' .
			' -p ipv6-icmp --icmpv6-type router-advertisement ' .
			'-j ACCEPT', self::IPV6);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type router-solicitation ' .
			'-j ACCEPT', self::IPV6);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type router-solicitation ' .
			'-j MARK --set-mark 4', self::IPV6);
	    $this->exec('-A FORWARD -i ' . $this->iface .
			' -o ' . $this->iface . ' -m mark --mark 1' .
			' -p ipv6-icmp --icmpv6-type router-solicitation ' .
			'-j ACCEPT', self::IPV6);
	    $this->exec('-A FORWARD -i ' . $this->iface .
			' -o ' . $this->iface . ' -m mark --mark 2' .
			' -p ipv6-icmp --icmpv6-type router-advertisement ' .
			'-j ACCEPT', self::IPV6);
	}

	// DHCP
	$this->exec('-A INPUT -i ' . $this->iface . ' -m mark --mark 1' .
		    ' -p udp --sport 68 --dport 67 -j ACCEPT',
		    (~$this->bridge) & self::BOTH);
	$this->exec('-A OUTPUT -o ' . $this->iface .
		    ' -p udp --sport 67 --dport 68 -j ACCEPT',
		    (~$this->bridge) & self::BOTH);
	$this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
		    ' -p udp --sport 67 --dport 68 -j MARK --set-mark 3',
		    (~$this->bridge) & self::BOTH);
	$this->exec('-A INPUT -i ' . $this->iface . ' -m mark --mark 2' .
		    ' -p udp --sport 67 --dport 68 -j ACCEPT',
		    $this->bridge);
	$this->exec('-A OUTPUT -o ' . $this->iface .
		    ' -p udp --sport 68 --dport 67 -j ACCEPT',
		    $this->bridge);
	$this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
		    ' -p udp --sport 68 --dport 67 -j MARK --set-mark 4',
		    $this->bridge);
	$this->exec('-A FORWARD -i '  . $this->iface .
		    ' -o ' . $this->iface . ' -m mark --mark 1' .
		    ' -p udp --sport 68 --dport 67 -j ACCEPT',
		    $this->bridge);
	$this->exec('-A FORWARD -i '  . $this->iface .
		    ' -o ' . $this->iface . ' -m mark --mark 2' .
		    ' -p udp --sport 67 --dport 68 -j ACCEPT',
		    $this->bridge);
    }

    public function addAntiSpoof() {
	$this->exec('-N antispoof');
	$this->exec('-F antispoof');

	foreach ($this->interface->getAddresses(NULL, Address::SCOPE_LINK |
						      Address::SCOPE_SITE |
						      Address::SCOPE_GLOBAL)
		 as $address) {
	    $protocol = $address->getProtocol();
	    if ($protocol === Protocol::ipv6())
		$protocol = self::IPV6;
	    else if ($protocol === Protocol::ipv4())
		$protocol = self::IPV4;
	    else
		continue;

	    $subnet = $address->getSubnet() . '/' . $address->getNetmask();

	    if (($this->bridge & $protocol) === 0) {
		$this->exec('-A FORWARD -i ' . $this->iface . ' -d ' .
			    $subnet . ' -m mark --mark 1 -j DROP', $protocol);
		$this->exec('-A FORWARD -o ' . $this->iface . ' -s ' .
			    $subnet . ' -m mark --mark 3 -j DROP', $protocol);
	    }
	    $this->exec('-A antispoof -i ' . $this->iface . ' -s ' .
			$subnet . ' -j RETURN', $protocol);
	    $this->exec('-A antispoof -o ' . $this->iface . ' -d ' .
			$subnet . ' -j RETURN', $protocol);
	}

	$this->exec('-A antispoof -j DROP');
	$this->exec('-A INPUT -i '   . $this->iface .
		    ' -m mark --mark 1 -j antispoof');
	$this->exec('-A OUTPUT -o '  . $this->iface .
		    ' -m mark --mark 3 -j antispoof');
	$this->exec('-A FORWARD -i ' . $this->iface .
		    ' -m mark --mark 1 -j antispoof');
	$this->exec('-A FORWARD -o ' . $this->iface .
		    ' -m mark --mark 3 -j antispoof');
    }

    public function addAuthorizedClients() {
	$this->exec('-N unauth');
	$this->exec('-F unauth');
	$this->exec('-A unauth -o ' . $this->iface . ' -m mark --mark 2' .
		    ' -m state --state ESTABLISHED,RELATED -j RETURN');
	$this->exec('-A FORWARD -i ' . $this->iface .
		    ' -m mark --mark 1 -j unauth');
	$this->exec('-A FORWARD -o ' . $this->iface .
		    ' -m mark --mark 2 -j unauth');

	$this->exec('-t nat -N unauth', self::IPV4);
	$this->exec('-t nat -F unauth', self::IPV4);
	$this->exec('-t nat -A PREROUTING -i ' . $this->iface .
		    ' -m mark --mark 1 -j unauth', self::IPV4);
    }

    public function addNat() {
	// ip6tables doesn't support NAT yet; IPv6 was designed to avoid using
	// NAT though, so that shouldn't actually be a problem ;-)
	if (Config::get()->getUseNat() && ($this->bridge & self::IPV4) === 0)
	    foreach ($this->interface->getAddresses(Protocol::ipv4(),
						    Address::SCOPE_SITE |
						    Address::SCOPE_GLOBAL)
		    as $address) {
		$subnet = $address->getSubnet() . '/' . $address->getNetmask();
		$this->exec('-t nat -A POSTROUTING -s ' . $subnet . ' -d ! ' .
			    $subnet . ' -j MASQUERADE', self::IPV4);
	    }
    }

    public function addNameserver(Address $nameserver) {
	$proto = $nameserver->getProtocol();
	if ($proto === Protocol::ipv6())
	    $protocol = self::IPV6;
	else if ($proto === Protocol::ipv4())
	    $protocol = self::IPV4;
	else
	    throw new UnknownProtocolException($nameserver);

	if ($nameserver->isLocal()) {
	    $this->exec('-A INPUT -i '  . $this->iface .
			' -m mark --mark 1 -p tcp --dport 53 -j ACCEPT',
			$protocol);
	    $this->exec('-A INPUT -i '  . $this->iface .
			' -m mark --mark 1 -p udp --dport 53 -j ACCEPT',
			$protocol);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p tcp --sport 53 -j ACCEPT', $protocol);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p udp --sport 53 -j ACCEPT', $protocol);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p tcp --sport 53 -j MARK --set-mark 5',
			$protocol);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p udp --sport 53 -j MARK --set-mark 5',
			$protocol);
	} else {
	    $this->exec('-A unauth -i ' . $this->iface . ' -d ' .
			$nameserver->getAddress() .
			' -p tcp --dport 53 -m mark --mark 1 -j ACCEPT',
			$protocol);
	    $this->exec('-A unauth -i ' . $this->iface . ' -d ' .
			$nameserver->getAddress() .
			' -p udp --dport 53 -m mark --mark 1 -j ACCEPT',
			$protocol);
	    $this->exec('-A unauth -o ' . $this->iface . ' -s ' .
			$nameserver->getAddress() .
			' -p tcp --sport 53 -m mark --mark 2 -j ACCEPT',
			$protocol);
	    $this->exec('-A unauth -o ' . $this->iface . ' -s ' .
			$nameserver->getAddress() .
			' -p udp --sport 53 -m mark --mark 1 -j ACCEPT',
			$protocol);
	}
    }

    public function addPortal() {
	foreach (array(80, 443) as $port) {
	    // Accept communication with web server
	    $this->exec('-A INPUT -i '   . $this->iface .
			' -p tcp --dport ' . $port .
			' -m mark --mark 1 -j ACCEPT');
	    $this->exec('-A OUTPUT -o '  . $this->iface .
			' -p tcp --sport ' . $port . ' -j ACCEPT');
	    $this->exec('-t mangle -A OUTPUT -o '  . $this->iface .
			' -p tcp --sport ' . $port . ' -j MARK --set-mark 5');

	    // ip6tables doesn't support NAT (yet), so reject connections with
	    // the hope that clients will use an alternative IPv4 address.
	    // If REJECT isn't supported, packets simply get dropped.
	    $this->exec('-A unauth -i ' . $this->iface .
			' -p tcp --dport ' . $port . ' -m mark --mark 1' .
			' -j REJECT --reject-with no-route', self::IPV6);
	    $this->exec('-A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type no-route -j ACCEPT',
			self::IPV6);
	    $this->exec('-t mangle -A OUTPUT -o ' . $this->iface .
			' -p ipv6-icmp --icmpv6-type no-route ' .
			'-j MARK --set-mark 3', self::IPV6);

	    // Do a redirection for IPv4
	    $this->exec('-t nat -A unauth -i ' . $this->iface .
			' -p tcp --dport ' . $port .
			' -m mark --mark 1 -j REDIRECT', self::IPV4);
	}
    }

    public function addBlockEverything() {
	$this->exec('-A INPUT -i ' . $this->iface .
		    ' -m mark --mark 1 -j DROP');
	$this->exec('-t mangle -I OUTPUT -o '  . $this->iface .
		    ' -j MARK --set-mark 4');
	$this->exec('-A unauth -j DROP');

	if ($this->is_bridge) {
	    foreach (array('0x0800', '0x0806', '0x86DD') as $protocol) {
		$this->exec('-A INPUT -i '   . $this->int_iface . ' -p ' .
			    $protocol . ' -j ACCEPT', self::ETHERNET);
		$this->exec('-A OUTPUT -o '  . $this->int_iface . ' -p ' .
			    $protocol . ' -j ACCEPT', self::ETHERNET);
		$this->exec('-A FORWARD -i ' . $this->int_iface . ' -p ' .
			    $protocol . ' -j ACCEPT', self::ETHERNET);
		$this->exec('-A FORWARD -o ' . $this->int_iface . ' -p ' .
			    $protocol . ' -j ACCEPT', self::ETHERNET);
	    }

	    $this->exec('-A INPUT -i '   . $this->int_iface . ' -j DROP',
			self::ETHERNET);
	    $this->exec('-A OUTPUT -o '  . $this->int_iface . ' -j DROP',
			self::ETHERNET);
	    $this->exec('-A FORWARD -i ' . $this->int_iface . ' -j DROP',
			self::ETHERNET);
	    $this->exec('-A FORWARD -o ' . $this->int_iface . ' -j DROP',
			self::ETHERNET);
	}
    }

    public function addClient(EthernetAddress $ethernet, $addresses) {
	if (Config::get()->getUseMac()) {
	    $macfilter = ' -m mac --mac-source ' . $ethernet->getAddress();

	    // Workaround: see below
	    $bugmac = $this->interface->getAddresses(Protocol::ethernet());
	    reset($bugmac);
	    $bugmac = current($bugmac)->getAddress();
	} else
	    $macfilter = '';

	if (empty($addresses)) {
	    // No address associated (yet) to this Ethernet address
	    if (!empty($macfilter)) {
		// Filter by MAC address only
		$this->exec('-I unauth -i ' . $this->iface .
			    ' -m mark --mark 1' . $macfilter . ' -j RETURN');
		$this->exec('-t nat -I unauth -i ' . $this->iface .
			    ' -m mark --mark 1' . $macfilter . ' -j RETURN');
	    }
	} else
	    foreach ($addresses as $address) {
		$protocol = $address->getProtocol();
		if ($protocol === Protocol::ipv6())
		    $proto = self::IPV6;
		else if ($protocol === Protocol::ipv4())
		    $proto = self::IPV4;
		else
		    throw new UnknownProtocolException($address);

		$this->exec('-I unauth -i ' . $this->iface . ' -s ' .
			    $address->getAddress() . ' -m mark --mark 1' .
			    $macfilter . ' -j RETURN', $proto);
		$this->exec('-t nat -I unauth -i ' . $this->iface . ' -s ' .
			    $address->getAddress() . ' -m mark --mark 1' .
			    $macfilter . ' -j RETURN', $proto & self::IPV4);
		$this->exec('-I unauth -o ' . $this->iface . ' -d ' .
			    $address->getAddress() .
			    ' -m mark --mark 2 -j RETURN', $proto);

		// Workaround for a bug where incoming remote packets get the
		// current machine MAC address; so allow incoming packets
		// presenting our own MAC address...
		if (isset($bugmac))
		    $this->exec('-I unauth -i ' . $this->iface . ' -s ' .
				$address->getAddress() .
				' -m mark --mark 1 -m mac --mac-source ' .
				$bugmac . ' -j ACCEPT', $proto);
	    }
    }
}

?>
