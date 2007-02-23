pkglib_PROGRAMS = ip6tables iptables ebtables
ip6tables_SOURCES = ip6tables.c iptwrapper.h
iptables_SOURCES = iptables.c iptwrapper.h
ebtables_SOURCES = ebtables.c iptwrapper.h

install-exec-hook:
	for group in apache httpd http www; do \
	    for exe in $(pkglib_PROGRAMS); do \
		chown root:$$group "$(DESTDIR)$(pkglibdir)"/$$exe && \
		chmod 4710         "$(DESTDIR)$(pkglibdir)"/$$exe; \
	    done && break; \
	done
