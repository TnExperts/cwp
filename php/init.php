<?php

Base::useLib('config', 'interface', 'portal', 'service');

final class InitScript {
    private $argc, $argv;

    public function __construct() {
	if (PHP_SAPI !== 'cli')
	    return;

	$this->argc = (int)$_SERVER['argc'];
	$this->argv = $_SERVER['argv'];

	if ($this->argc < 2 || $this->argc > 3)
	    $this->usage();
	if ($this->argc === 3) {
	    if ($this->argv[2] === 'simulate')
		$simulate = TRUE;
	    else
		$this->usage();
	} else
	    $simulate = FALSE;

	switch ($this->argv[1]) {
	case 'start':
	    $actions = array('start');
	    break;

	case 'stop':
	    $actions = array('stop');
	    break;

	case 'restart':
	    $actions = array('stop', 'start');
	    break;

	default:
	    $this->usage();
	}

	if (!$simulate) {
	    $iface = Config::get()->getInterface();
	    if ($this->argv[1] !== 'stop') {
		$iface->up();
		$iface->addAutoAddresses();
	    }
	}

	$objects = array();
	foreach (Service::getAll() as $service)
	    $objects[] = new $service;
	$objects[] = new Portal;
	$lines = array();

	foreach ($objects as $object)
	    foreach ($actions as $action)
		try {
		    $lines = array_merge($lines, $object->$action($simulate));
		} catch (ServiceDisabledException $exception) {
		} catch (ServiceNotFoundException $exception) {
		    echo 'Warning: ' . $exception->getMessage() . "\n";
		} catch (PermissionDeniedException $exception) {
		    echo 'Warning: ' . $exception->getMessage() . "\n";
		} catch (ServiceNotSupportedException $exception) {
		    echo 'Warning: ' . $exception->getMessage() . "\n";
		}

	if (count($lines) > 0)
	    echo implode("\n", $lines) . "\n";
	exit();
    }

    private function usage($exitcode = -1) {
	echo 'Usage: ' . $this->argv[0] . " <start|stop|restart> [simulate]\n";
	exit($exitcode);
    }
}

?>
