###############################################################################
# OpenVAS Vulnerability Test
# $Id: check_dns_tcp.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# DNS Server on UDP and TCP
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# This is not really a security check.
# See STD0013

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18356");
  script_version("$Revision: 9608 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("DNS Server on UDP and TCP");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("General");
  script_dependencies('external_svc_ident.nasl', 'dns_server.nasl');
  script_require_udp_ports("Services/udp/domain", 53);
  script_mandatory_keys("DNS/identified");

  script_tag(name:"summary", value:"A DNS server is running on this port but
  it only answers to UDP requests.
  This means that TCP requests are blocked by a firewall.

  This configuration is incorrect: TCP might be used by any
  request, it is not restricted to zone transfers.
  Read RFC1035 or STD0013 for more information.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include('misc_func.inc');

port = get_kb_item( 'Services/udp/domain' );
if( ! port ) exit( 0 );
if( ! get_udp_port_state( port ) ) exit( 0 ); # Only on TCP?

if( verify_service( port:port, ipproto:'tcp', proto:'domain' ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
} else {
  close( soc );
  if( get_port_state( port ) )
    register_service( port:port, proto:'domain');
}

exit( 99 );