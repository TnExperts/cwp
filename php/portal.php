<?php
Base::useLib('address');

final class Portal {
    const HTTP = 80, HTTPS = 443;
    const TITLE = 'Captive Web Portal';
    const HOSTNAME = 'portal.cwp';

    private $firewall, $file, $lockfile;
    private $registered, $since;
    private $host;

    public function __construct() {
	$this->file = Config::get()->getStateDir() . '/cwp/clients.list';
	$this->lockfile = Config::get()->getStateDir() . '/cwp/clients.lock';

	try {
	    if (($target = $this->checkUrl()) !== FALSE)
		$this->display($target);
	} catch (Exception $exception) {
	    $trace = str_replace("\n", "<br/>\n  ",
				 $exception->getTraceAsString());
	    $contents = "<h2>What&#8217;s Going On?</h2>\n"
		      . '<p>The portal encountered an unattented error.  If '
		      . 'you keep getting this error, please contact the site '
		      . 'administrator and provide him the following '
		      . "information.</p>\n"
		      . "<h2>Error Information</h2>\n"
		      . "<h3>Message</h3>\n"
		      . '<p>' . self::encodeHtml($exception->getMessage())
		      . ($exception->getCode() === 0 ? '' :
			 (' (code ' . $exception->getCode() . ')'))
		      . "</p>\n"
		      . "<h3>Location</h3>\n"
		      . '<p>File <em>'
		      . self::encodeHtml(basename($exception->getFile()))
		      . '</em>, line <em>' . $exception->getLine()
		      . "</em>.</p>\n"
		      . "<h3>Backtrace</h3>\n"
		      . "<p>\n  " . $trace . "\n</p>\n";
	    self::makePage($contents, 'Internal Error');
	}
    }

    private function getFirewall() {
	if (!isset($this->firewall)) {
	    Base::useLib('config', 'firewall');
	    $firewall = Config::get()->getFirewall();
	    $this->firewall = new $firewall;
	}

	return $this->firewall;
    }

    private function build() {
	$this->getFirewall();

	$this->firewall->begin();
	$this->firewall->addPing();
	$this->firewall->addAutoConf();
	$this->firewall->addAntiSpoof();
	$this->firewall->addAuthorizedClients();
	$this->firewall->addNat();

	if (Config::get()->getService('Dhcpv4d') &&
	    Config::get()->getService('Dns')) {
	    $this->firewall->addNameserver(Ipv6Address::getLocalhost());
	    $this->firewall->addNameserver(Ipv4Address::getLocalhost());
	} else
	    foreach (Address::getNameservers() as $nameserver)
		$this->firewall->addNameserver($nameserver);

	$this->firewall->addPortal();
	$this->firewall->addBlockEverything();
    }

    public function start($simulate = FALSE) {
	$this->build();
	$this->addRegisteredClients();
	return $this->firewall->commit($simulate);
    }

    public function stop($simulate = FALSE) {
	$this->build();
	return $this->firewall->undo($simulate);
    }

    private function lock() {
	while (($file = @fopen($this->lockfile, 'x')) === FALSE)
	    usleep(10);
	fwrite($file, (string)getmypid() . "\n");
	fclose($file);
	chmod($this->lockfile, 0400);
    }

    private function unlock() {
	unlink($this->lockfile);
    }

    private function isRegistered() {
	if (isset($this->registered))
	    return $this->registered;
	$this->registered = FALSE;

	$ethernet = self::getEthernet();
	$this->lock();
	if (($file = @fopen($this->file, 'r')) !== FALSE) {
	    while (!feof($file)) {
		$line = trim(fgets($file));
		if (empty($line))
		    continue;

		list(, $since, $eth, $registered) = explode("\t", $line);

		if ($eth === $ethernet->getAddress()) {
		    //$registered = explode(' ', $registered);
		    $this->registered = /*in_array($_SERVER['REMOTE_ADDR'],
						 $registered)*/ TRUE;
		    $this->since = $since;
		    break;
		}
	    }

	    fclose($file);
	    $this->unlock();

	    if ($this->registered)
		$this->refreshAddresses($ethernet);
	}

	return $this->registered;
    }

    public function purgeAddresses() {
	$this->lock();
	if (($file = @fopen($this->file, 'r')) === FALSE) {
	    $this->unlock();
	    return;
	}

	$mintime = time() - Config::get()->getAuthDelay();
	$lines = array();

	while (!feof($file)) {
	    $line = trim(fgets($file));
	    if (empty($line))
		continue;

	    list($timestamp, , $eth, $registered) = explode("\t", $line);
	    if ((int)$timestamp < $mintime) {
		$registered = explode(' ', $registered);
		foreach ($registered as &$address)
		    $address = Address::fromString($address);
		unset($address);
		$this->addClientRules(new EthernetAddress($eth), $registered);
		$removed = TRUE;
	    } else
		$lines[] = $line;
	}

	fclose($file);

	if (isset($removed)) {
	    file_put_contents($this->file, $lines);
	    $this->firewall->undo();
	}

	$this->unlock();
    }

    private function addRegisteredClients() {
	$this->lock();
	if (($file = @fopen($this->file, 'r')) === FALSE) {
	    $this->unlock();
	    return;
	}

	while (!feof($file)) {
	    $line = trim(fgets($file));
	    if (empty($line))
		continue;

	    list(, , $eth, $registered) = explode("\t", $line);
	    $registered = explode(' ', $registered);
	    foreach ($registered as &$address)
		$address = Address::fromString($address);
	    unset($address);
	    $this->addClientRules(new EthernetAddress($eth), $registered);
	}

	fclose($file);
	$this->unlock();
    }

    private function registerAddresses(EthernetAddress $ethernet, $addresses) {
	$this->lock();
	$clients = @file($this->file);
	$this->unlock();

	if ($clients === FALSE)
	    return array();
	$new = array();

	foreach ($clients as $key => $client) {
	    list(, $since, $eth, $registered) = explode("\t", $client);
	    if ($eth === $ethernet->getAddress()) {
		$registered = explode(' ', rtrim($registered));
		unset($clients[$key]);
		break;
	    }
	    unset($since, $registered);
	}

	if ($addresses === NULL) {
	    if (!isset($registered))
		return array();

	    foreach ($registered as &$address)
		$address = Address::fromString($address);
	    unset($address);

	    $this->addClientRules($ethernet, $registered);
	    $this->firewall->undo();
	} else if (empty($addresses)) {
	    if (isset($registered))
		$new = $registered;
	} else {
	    $add = array();
	    $del = array();

	    if (isset($registered))
		foreach ($registered as $address) {
		    $addr = Address::fromString($address);
		    if (Config::get()->getBridge($addr->getProtocol()))
			$new[] = $address;
		    else
			$del[] = $addr;
		}

	    foreach ($addresses as $address)
		if (!in_array($address->getAddress(), $new)) {
		    $new[] = $address->getAddress();
		    $add[] = $address;
		}

	    $this->addClientRules($ethernet, $add);
	    $this->firewall->commit();
	    $this->addClientRules($ethernet, $del);
	    $this->firewall->undo();
	}

	if (!empty($new)) {
	    if (!isset($since))
		$since = time();
	    $clients[] = (string)time() . "\t" . $since . "\t"
		       . $ethernet->getAddress() . "\t"
		       . implode(' ', $new) . "\n";
	}
	$this->lock();
	file_put_contents($this->file, $clients);
	$this->unlock();

	return $new;
    }

    private function removeAddresses(EthernetAddress $ethernet) {
	return $this->registerAddresses($ethernet, NULL);
    }

    private function refreshAddresses(EthernetAddress $ethernet) {
	return $this->registerAddresses($ethernet, array());
    }

    private static function getEthernet() {
	static $ethernet;
	if (!isset($ethernet))
	    $ethernet = Address::getClient()->toEthernet();
	return $ethernet;
    }

    private function addClientRules(EthernetAddress $ethernet, $addresses) {
	$this->getFirewall();
	try {
	    $this->firewall->addClient($ethernet, $addresses);
	} catch (AddressFormatException $exception) {}
    }

    private function addClient() {
	$ethernet = self::getEthernet();
	$was_registered = $this->isRegistered();
	$this->registerAddresses($ethernet, Address::fromEthernet($ethernet));

	if ($was_registered)
	    return FALSE;
	$this->registered = TRUE;
	$this->since = time();
	return TRUE;
    }

    private function removeClient() {
	if ($this->isRegistered()) {
	    $this->removeAddresses(self::getEthernet());
	    $this->registered = FALSE;
	    return TRUE;
	}

	return FALSE;
    }

    private static function makeDate($time = NULL) {
	if ($time === NULL)
	    $time = time();

	// Make a RFC 1123 compliant date
	return gmdate('D, d M Y H:i:s') . ' GMT';
    }

    private static function isSslSupported() {
	return isset($_GET['ssl']) && (int)$_GET['ssl'];
    }

    private static function encodeHtml($text) {
	return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }

    private static function encodeAddress($address) {
	if (strpos($address, ':') !== FALSE)
	    $address = '[' . $address . ']';
	return $address;
    }

    private static function makeUrl($host, $port = self::HTTP, $uri = '/') {
	if ($uri{0} !== '/')
	    $uri = '/' . $uri;

	switch ((int)$port) {
	case self::HTTP:
	    $proto = 'http://';
	    $port = '';
	    break;

	case self::HTTPS:
	    $proto = 'https://';
	    $port = '';
	    break;

	default:
	    $proto = 'http://';
	    $port = ':' . $port;
	}

	return $proto . self::encodeAddress($host) . $port . $uri;
    }

    private static function encodeHost($host) {
	if (strpos($host, ':') !== FALSE)
	    return str_replace(':', '+', $host);
	return $host;
    }

    private static function decodeHost($host) {
	if (strpos($host, '+') !== FALSE)
	    return str_replace('+', ':', $host);
	return $host;
    }

    private static function encodeTarget($host, $port, $uri) {
	switch ($port) {
	case self::HTTP:
	    $port = 'http';
	    break;

	case self::HTTPS:
	    $port = 'https';
	}

	return '/' . $port . '/' . self::encodeHost($host) . $uri;
    }

    private static function decodeTarget($target) {
	if (!preg_match('%^/(https?|[0-9]{1,5})/[0-9A-Za-z.:+-]+/%', $target))
	    return FALSE;

	list(, $port, $host, $uri) = explode('/', $target, 4);

	switch ($port) {
	case 'http':
	    $port = self::HTTP;
	    break;

	case 'https':
	    $port = self::HTTPS;
	    break;

	default:
	    $port = (int)$port;
	}

	$host = self::decodeHost($host);
	$uri = '/' . $uri;
	return array($host, $port, $uri);
    }

    private static function makePage($contents, $title = self::TITLE,
				     $refresh = FALSE, $open = '') {
	if (!empty($_SERVER['HTTP_ACCEPT']) &&
	    strpos($_SERVER['HTTP_ACCEPT'], 'application/xhtml+xml') !== FALSE)
	    $type = 'application/xhtml+xml';
	else
	    $type = 'text/html';

	if ($refresh) {
	    $code = 'window.location.replace(window.location);';
	    $onload = 'setTimeout(\'' . $code . "', "
		    . (Config::get()->getAuthDelay() * 800) . ');';
	    if (!empty($open))
		$onload .= ' ';
	} else
	    $onload = '';

	if (!empty($open))
	    $onload .= 'window.open(\'' . $open . '\');';

	header('Content-Type: ' . $type . '; charset=US-ASCII');
	header('Content-Style-Type: text/css');
	header('Content-Script-Type: text/javascript');
	header('Content-Language: en');
	header('Cache-Control: no-cache, must-revalidate');
	header('Pragma: no-cache');
	header('Expires: ' . self::makeDate());
	header('Last-Modified: ' . self::makeDate());
	header('Vary: Accept');
	header('Vary: *', FALSE);
	header('Server: CWP');
	header('X-Powered-By: CWP');

	if ($contents{strlen($contents) - 1} === "\n")
	    $contents = substr($contents, 0, -1);

	echo '<' . '?xml version="1.0" encoding="US-ASCII"?' . ">\n"
	   . '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" '
	   . "\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
	   . "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\">\n"
	   . "  <head>\n"
	   . '    <title>' . $title . "</title>\n"
	   . '    <meta http-equiv="Content-Type" content="' . $type
	   . "; charset=US-ASCII\"/>\n"
	   . '    <meta http-equiv="Content-Style-Type" '
	   . "content=\"text/css\"/>\n"
	   . "    <meta http-equiv=\"Content-Language\" content=\"en\"/>\n"
	   . '    <style type="text/css" media="screen" '
	   . "title=\"Default Style\">\n"
	   . "      @import url(/cwp.css);\n"
	   . "    </style>\n"
	   . "  </head>\n"
	   . '  <body' . (empty($onload) ? '' : (' onload="' . $onload . '"')) .
	     ">\n"
	   . "    <div id=\"page\">\n"
	   . '      <h1>' . $title . "</h1>\n"
	   . "      <div id=\"contents\">\n"
	   . '        ' . str_replace("\n", "\n        ", $contents) . "\n"
	   . "      </div>\n"
	   . "    </div>\n"
	   . "  </body>\n"
	   . "</html>\n";
    }

    private static function redirect($url) {
	$contents = '<p>The document has moved <a href="'
		  . self::encodeHtml($url) . "\">here</a>.</p>\n";
	header('Location: ' . $url);
	header('Refresh: ' . $url);
	self::makePage($contents, 'Redirection');
    }

    private function redirectToPortal($uri = '/') {
	if ($uri{0} !== '/')
	    $uri = '/' . $uri;
	$ssl = self::isSslSupported() ? self::HTTPS : self::HTTP;

	switch ((int)$ssl) {
	case self::HTTP:
	    $port = 'http';
	    break;

	case self::HTTPS:
	    $port = 'https';
	}

	$url = self::makeUrl($this->host, $ssl, $uri);
	self::redirect($url);
    }

    private static function sendFile($file) {
	if ($file{0} !== '/' || $file{1} === '.')
	    return FALSE;
	$file = Config::get()->getHtmlDir() . $file;
	if (!is_file($file))
	    return FALSE;

	switch ($ext = substr(strrchr($file, '.'), 1)) {
	case 'css':
	    $type = 'text/css';
	    break;

	case 'png':
	    $type = 'image/png';
	    break;

	case 'gif':
	    $type = 'image/gif';
	    break;

	case 'svg':
	    $type = 'image/svg+xml';
	    break;

	default:
	    throw new InternalErrorException($ext . ': unknown file type.');
	}

	if (($time = filemtime($file)) !== FALSE)
	    header('Last-Modified: ', self::makeDate($time));
	if (($size = filesize($file)) !== FALSE)
	    header('Content-Length: ' . $size);
	header('Content-Type: ' . $type);
	header('Server: CWP');
	header('X-Powered-By: CWP');

	readfile($file);
	return TRUE;
    }

    private function checkUrl() {
	if (PHP_SAPI === 'cli')
	    return FALSE;

	if (Config::get()->getService('Dhcpv4d') &&
	    Config::get()->getService('Dns'))
	    $this->host = self::HOSTNAME;
	else
	    try {
		Address::fromString($_SERVER['SERVER_NAME']);
		$this->host = $_SERVER['SERVER_ADDR'];
	    } catch (AddressFormatException $exception) {
		$this->host = $_SERVER['SERVER_NAME'];
	    }

	$host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
	$addr = $this->host;

	if (!empty($host) && $host !== $_SERVER['SERVER_ADDR'] &&
	    $host !== self::encodeAddress($_SERVER['SERVER_ADDR']) &&
	    $host !== $addr && $host !== self::encodeAddress($addr)) {
	    $target = self::encodeTarget($host, $_SERVER['SERVER_PORT'],
					 $_SERVER['REQUEST_URI']);
	    $this->redirectToPortal($target);
	    return FALSE;
	}

	if (isset($_POST['target']))
	    $target = $_POST['target'];
	else if (isset($_GET['target']))
	    $target = $_GET['target'];
	else if (isset($_SERVER['REQUEST_URI']))
	    $target = $_SERVER['REQUEST_URI'];

	if (!isset($target) || $target === '/')
	    return '/';

	if (self::sendFile($target))
	    return FALSE;

	if (self::decodeTarget($target) === FALSE) {
	    $this->redirectToPortal();
	    return FALSE;
	}

	if (self::isSslSupported() &&
	    (int)$_SERVER['SERVER_PORT'] !== self::HTTPS) {
	    $this->redirectToPortal($target);
	    return FALSE;
	}

	return $target;
    }

    private function display($target = '/') {
	Base::useLib('config', 'interface');

	$address = $_SERVER['REMOTE_ADDR'];
	$server = empty($_SERVER['HTTP_HOST'])
		? $_SERVER['SERVER_ADDR'] : $_SERVER['HTTP_HOST'];
	$version = strpos($address, ':') !== FALSE ? 6 : 4;
	$address = self::encodeHtml($address);
	$cwp = self::encodeHtml(self::makeUrl($this->host,
					      $_SERVER['SERVER_PORT'],
					      $target));

	/*
	$alt = array();
	$scopes = Address::SCOPE_SITE | Address::SCOPE_GLOBAL;
	foreach (Config::get()->getInterface()->getAddresses(NULL, $scopes)
		 as $altaddr)
	    if ($altaddr->getProtocol() !== Protocol::ethernet() &&
		($addr = $altaddr->getAddress()) !== $server) {
		$url = self::makeUrl($addr, $_SERVER['SERVER_PORT'], $target);
		$url = self::encodeHtml($url);
		$alt[] = '<a href="' . $url . '">' . $addr . '</a>';
	    }
	*/

	$alt = empty($alt) ? ''
	     : '  Available alternate address'
	     . (count($alt) === 1 ? '' : 'es') . ': '
	     . implode(', ', $alt) . ".<br/>\n";

	$contents = '';
	$open = FALSE;

	try {
	    $registered = $this->isRegistered();

	    if (($login = !empty($_POST['login'])) ||
		!empty($_POST['logout'])) {
		if ($login) {
		    if (empty($_POST['username']) || empty($_POST['password']))
			$message = 'A login and a password are required';
		    else {
			Base::useLib('auth');
			$auth = Config::get()->getAuth();
			$auth = new $auth;

			if ($auth->validate($_POST['username'],
					    $_POST['password'])) {
			    if ($this->addClient()) {
				$message = 'Successfully logged in';
				$open = TRUE;
			    } else
				$message = 'You are already logged in';
			    $registered = TRUE;
			} else
			    $message = 'Login failed';
		    }
		} else if ($this->removeClient()) {
		    $message = 'Successfully logged out';
		    $registered = FALSE;
		} else
		    $message = 'You are not logged in';
		$contents .= '<p><em>' . $message . ".</em></p>\n";
	    } else if ($registered) {
		$length = (int)((time() - $this->since) / 60);
		$contents .= '<p>Session duration: '
			   . sprintf('%d:%02d', $length / 60, $length % 60)
			   . ".</p>\n";
	    }

	    $contents .= '<form name="auth" action="' . $cwp
		       . "\" method=\"post\">\n"
		       . "  <p>\n"
		       . ($registered
			  ? ('    <input name="logout" type="submit" ' .
			     "value=\"Logout\"/>\n")
			  : ("    <label for=\"username\">Login</label>\n" .
			     '    <input id="username" name="username" ' .
			     'type="text" value="' .
			     (isset($_POST['username']) ?
			      $_POST['username'] : '') .
			     "\"/><br/>\n" .
			     "    <label for=\"password\">Password</label>\n" .
			     '    <input id="password" name="password" ' .
			     "type=\"password\" value=\"\"/><br/>\n" .
			     '    <input name="login" type="submit" ' .
			     "value=\"Login\"/>\n" .
			     "    <input type=\"reset\" value=\"Reset\"/>\n"))
		       . "  </p>\n"
		       . "</form>\n";

	    if ($registered) {
		$contents .= "<p>\n"
			   . '  <strong>Warning: you must leave this '
			   . 'window/tab open to keep having access to the '
			   . "network.</strong>\n"
			   . "  <noscript>\n"
			   . '    <strong>Caution: your browser '
			   . 'does not support JavaScript or it is '
			   . 'disabled. Please enable it or click periodicaly '
			   . "on the following button.</strong>\n"
			   . "  </noscript>\n"
			   . "</p>\n";
	    }
	} catch (AddressFormatException $exception) {
	    $registered = FALSE;
	}

	if ($target !== '/') {
	    list($host, $port, $uri) = self::decodeTarget($target);
	    $targeturl = self::encodeHtml(self::makeUrl($host, $port, $uri));
	    $targetlink = '<a href="' . $targeturl . '" onclick="window.open(\''
			. $targeturl . '\'); return false;">' . $targeturl
			. '</a>';

	    $contents .= "<p>\n"
		       . '  The website you were trying to reach is '
		       . $targetlink . ".<br/>\n"
		       . '  Please click on the preceding link to '
		       . "visit the website once you get authenticated.\n"
		       . "</p>\n";
	} else
	    $targeturl = '';

	if (!empty($contents))
	$contents = "<h2>Authentication</h2>\n" . $contents;

	$contents .= "<h2>Your Connectivity</h2>\n"
		   . "<p>\n"
		   . '  Your current address is ' . $address . ".<br/>\n"
		   . '  Your are using the Internet Protocol version '
		   . $version . ".\n"
		   . "</p>\n"
		   . "<p>\n"
		   . '  The address you can use to connect to '
		   . 'this server is <a href="' . $cwp . '">'
		   . $this->host . "</a>.<br/>\n"
		   . $alt
		   . "</p>\n";

	self::makePage($contents, self::TITLE, $registered,
		       $open ? $targeturl : '');
    }
}

?>
