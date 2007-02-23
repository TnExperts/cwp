# Copyright 1999-2007 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit eutils

DESCRIPTION="Captive Web Portal"
HOMEPAGE="http://gxcore.free.fr/projets/m2ria/mrsf/"
SRC_URI="${HOMEPAGE}${P}.tar.bz2"

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~ppc ~x86"

IUSE="apache2 bridge dhcp dns ipv6 radius radv ssl"

DEPEND="ssl? ( dev-libs/openssl )"
RDEPEND="
	>=dev-lang/php-5
	apache2?  ( =net-www/apache-2* )
	!apache2? ( =net-www/apache-1* )
	sys-apps/iproute2
	net-firewall/iptables
	ipv6?   ( radv? ( net-misc/radvd ) )
	dhcp?   ( net-misc/dhcp )
	dns?    ( net-dns/bind )
	bridge? ( net-firewall/ebtables )
	radius? ( dev-php5/pecl-radius
		  || ( net-dialup/freeradius net-dialup/gnuradius ) )
	"

pkg_setup() {
	if use ssl && ! built_with_use net-www/apache ssl; then
		eerror "net-www/apache must be emerged with the"
		eerror "'ssl' USE flag."
		die
	fi

	local apache
	if use apache2; then
		apache="apache2"
	else
		apache="apache"
	fi

	if ! built_with_use dev-lang/php ${apache}; then
		eerror "dev-lang/php muse be emerged with the corresponding"
		eerror "apache ('apache2' or 'apache') USE flag."
		die
	fi

	if ! built_with_use dev-lang/php cli pcntl posix; then
		eerror "dev-lang/php must be emerged with the"
		eerror "'cli', 'pcntl' and 'posix' USE flags."
		die
	fi
}

src_compile() {
	econf LDFLAGS="${LDFLAGS:+${LFDLAFS} }-Wl,-z,now" || die "econf failed"
	emake || die "emake failed"
}

src_install() {
	make DESTDIR="${D}" install
	newinitd "gentoo/${PN}.init" "${PN}"
	insinto /etc/apache*/vhosts.d
	newins gentoo/vhost.conf "10-${PN}.conf"

	local apache
	if use apache2; then
		apache="apache2"
	else
		apache="apache"
	fi

	local ssldir="/etc/${apache}/ssl"
	dodir "${ssldir}"

	local sslbase="${D}${ssldir}/${PN}"
	openssl genrsa -out "${sslbase}.key" 1024
	cat <<EOF | openssl req -new -key "${sslbase}.key" -out "${sslbase}.csr"
FR
Bas-Rhin
Strasbourg
Captive Web Portal
Access Site
portal.cwp
root@portal.cwp


EOF
	openssl x509 -req -days 365 -in "${sslbase}.csr" \
		-signkey "${sslbase}.key" -out "${sslbase}.crt"
	rm -f "${sslbase}.csr"
	fperms 0400 "${ssldir}/${PN}.key" "${ssldir}/${PN}.crt"
}
