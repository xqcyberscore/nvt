##############################################################################
# OpenVAS Vulnerability Test
# $Id: sip_detection.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# Detect SIP Compatible Hosts (UDP)
#
# Authors:
# Noam Rathaus
# Modified by Michael Meyer 2009-05-04
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11963");
  script_version("$Revision: 8236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detect SIP Compatible Hosts (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Service detection");
  script_dependencies("gb_open_udp_ports.nasl", "sip_detection_tcp.nasl");
  script_require_udp_ports("Services/udp/unknown", 5060, 5061, 5070);

  script_xref(name:"URL", value:"http://www.cs.columbia.edu/sip/");

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming traffic
  to this port.");

  script_tag(name:"summary", value:"A Voice Over IP service is listening on the remote port.

  The remote host is running SIP (Session Initiation Protocol), a protocol
  used for Internet conferencing and telephony.

  Make sure the use of this program is done in accordance with your corporate
  security policy.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("sip.inc");

proto = "udp";
port = get_unknown_port( default:5060, ipproto:proto );

req = construct_sip_options_req( port:port, proto:proto );
res = sip_send_recv( port:port, data:req, proto:proto );

if( "SIP/2.0" >!< res ) exit( 0 );

replace_kb_item( name:"sip/full_banner/" + proto + "/" + port, value:res );

if( "Server:" >< res ) {
  banner = egrep( pattern:'^Server:', string:res );
  banner = substr( banner, 8 );
} else if( "User-Agent" >< res ) {
  banner = egrep( pattern:'^User-Agent', string:res );
  banner = substr( banner, 12 );
}

if( banner ) {
  replace_kb_item( name:"sip/banner/" + proto + "/" + port, value:banner );
}

desc = 'Server/User-Agent: ' + banner;

if( egrep( pattern:"Allow:.*OPTIONS.*", string:res ) ) {
  OPTIONS = egrep( pattern:"Allow:.*OPTIONS.*", string:res );
  OPTIONS -= "Allow: ";
  OPTIONS = chomp( OPTIONS );
}

if( ! isnull( OPTIONS ) ) {
  desc += '\nSupported Options:\n' + OPTIONS + '\n';
}

desc += '\nFull banner output:\n\n' + res;

set_kb_item( name:"sip/detected", value:TRUE );
set_kb_item( name:"sip/port_and_proto", value:port + "#-#" + proto );

log_message( port:port, protocol:proto, data:desc );
register_service( port:port, ipproto:proto, proto:"sip", message:"A service supporting the SIP protocol was idendified." );

exit( 0 );
