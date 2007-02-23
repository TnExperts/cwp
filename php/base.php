<?php

if ((int)substr(PHP_VERSION, 0, strpos(PHP_VERSION, '.')) < 5) {
    echo "PHP version 5 required!\n";
    exit(-1);
}

final class InternalErrorException extends Exception {
    public function __construct($reason = NULL) {
	parent::__construct('Internal error' .
		(empty($reason) ? '' : (': ' . $reason)) .
		'.  Please report.');
    }
}

final class NonexistentLibraryException extends Exception {
    public function __construct($name) {
	parent::__construct($name . ': nonexistent library.');
    }
}

final class Base {
    public static function bootstrap() {
	$libdir = dirname(__FILE__);
	@include_once $libdir . '/dirs.php';

	while (TRUE)
	    if (isset($DATADIR) && is_dir($newdir = $DATADIR . '/php')) {
		if ($newdir === $libdir)
		    break;
		$libdir = $newdir;
		@include_once $libdir . '/dirs.php';
	    }

	require_once $libdir . '/config.php';
    }

    public static function useLib() {
	static $block = array('base', 'dirs', 'config');
	$libdir = Config::get()->getPhpDir();

	foreach (func_get_args() as $name)
	    if (!in_array($name, $block))
		require_once $libdir . '/' . $name . '.php';
    }
}

Base::bootstrap();

?>
