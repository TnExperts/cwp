configdir = $(sysconfdir)/$(PACKAGE_TARNAME)
dist_config_DATA = config.php

phpdir = $(pkgdatadir)/php
php_DATA = dirs.php

dist_pkgdata_DATA = init.php
pkgdata_DATA = cwp.common cwp.vhost init.sh

EXTRA_DIST = cwp.common.in cwp.vhost.in dirs.php.in init.sh.in
CLEANFILES = cwp.common    cwp.vhost    dirs.php    init.sh

sedit = sed \
	-e 's|@pkglibdir[@]|$(pkglibdir)|g' \
	-e 's|@pkgdatadir[@]|$(pkgdatadir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@IP6TABLES_PATH[@]|$(IP6TABLES_PATH)|g' \
	-e 's|@IP4TABLES_PATH[@]|$(IP4TABLES_PATH)|g' \
        -e 's|@EBTABLES_PATH[@]|$(EBTABLES_PATH)|g' \
	-e 's|@PHP_PATH[@]|$(PHP_PATH)|g' \
	-e 's|@PACKAGE_TARNAME[@]|$(PACKAGE_TARNAME)|g'

cwp.common cwp.vhost dirs.php init.sh:
	$(sedit) "$<" >"$@"

cwp.common: $(srcdir)/cwp.common.in Makefile
cwp.vhost:  $(srcdir)/cwp.vhost.in  Makefile
dirs.php:   $(srcdir)/dirs.php.in   Makefile
init.sh:    $(srcdir)/init.sh.in    Makefile
