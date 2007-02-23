<?php

# Authentivation service to use.  Default is 'AuthTest' which is a fake one
# accepting only the "luke"/"ifeeltheforce" (without quotes) login/password
# pair.  It is of course strongly advised to use a better service.
# Possible values: "AuthTest", "Radius"
#$AUTH = 'AuthTest';

# Maximum delay a client remains authenticated without accessing the portal.
# This is expressed in seconds.  Default: 60.
#$AUTH_DELAY = 60;

# Parameters for the RADIUS authentication method.
#$RADIUS_SERVER = 'localhost';
#$RADIUS_PORT   = 0;
#$RADIUS_SECRET = '';

# The interface connected to the clients (should be your wireless card).
# If not specified, try br0, wlan0, ath0, eth1, eth0 (in that order).
#$INT_INTERFACE = 'wlan0';

# The interface we intercept trafic from.
# Should be a bridge interface or the same as $INT_INTERFACE above.
#$INTERFACE = $INT_INTERFACE;

# Wether to use NAT for connections coming from the managed network.
# This is enabled by default.
#$USE_NAT = TRUE;

# Wether to filter accesses by MAC address (enabled by default).
# Note: this requires the iptables MAC match module.
#$USE_MAC = TRUE;

# Wether to auto assign IP addresses to the interface.
# Enabled by default if not operating on a bridge.
#$AUTO_IPV6 = TRUE;
#$AUTO_IPV4 = TRUE;

# Wether to use a bridge for address assignment.
# Disabled by default unless operating on a bridge.
#$BRIDGE_IPV6 = FALSE;
#$BRIDGE_IPV4 = FALSE;

# Services: enable or disable a service explicitely.
# They are all enabled by default if available and needed.
#$RADVD   = TRUE; # IPv6 router advertisement
#$DHCPV4D = TRUE; # IPv4 DHCP
#$DNS     = TRUE; # DNS proxy (necessary for valid HTTPS)

# Firewall engine to use.  Only "Iptables" is possile until CWP gets ported
# to other architectures.  DON'T SET THIS VALUE!
#$FIREWALL = 'Iptables';

?>
