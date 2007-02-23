SUBDIRS = \
    etc \
    htdocs \
    php \
    wrapper

dist_pdf_DATA = doc-fr/rapport.pdf

EXTRA_DIST = \
    autogen.sh \
    doc-fr/Makefile \
    doc-fr/bglstyle.sty \
    doc-fr/images/cwp-1200dpi.png \
    doc-fr/images/cwp-text.eps \
    doc-fr/images/cwp-text.pdf \
    doc-fr/images/cwp.eps \
    doc-fr/images/cwp.png \
    doc-fr/images/screenshot.eps \
    doc-fr/images/screenshot.png \
    doc-fr/images/ulp.eps \
    doc-fr/images/ulp.pdf \
    doc-fr/rapport.tex \
    gentoo/cwp.ebuild \
    gentoo/cwp.init \
    gentoo/vhost.conf

statedir = $(localstatedir)/$(PACKAGE_TARNAME)
state_DATA = .keep
CLEANFILES = $(state_DATA)

.keep:
	touch "$@"

OVERLAY   = /usr/local/portage
EBUILDDIR = $(OVERLAY)/net-misc/$(PACKAGE_TARNAME)
EBUILD    = $(EBUILDDIR)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION).ebuild
DISTFILE  = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.bz2

.PHONY: ebuild
ebuild: dist-bzip2
	cp "$(srcdir)/gentoo/$(PACKAGE_TARNAME).ebuild" "$(EBUILD)"
	cp "$(DISTFILE)" /usr/portage/distfiles
	ebuild $(EBUILD) digest
