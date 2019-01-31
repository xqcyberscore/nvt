###############################################################################
# OpenVAS Vulnerability Test
# $Id: telnetserver_detect_type_nd_version.nasl 13370 2019-01-30 16:34:48Z cfischer $
#
# Telnet Banner Reporting
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10281");
  script_version("$Revision: 13370 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-30 17:34:48 +0100 (Wed, 30 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Telnet Banner Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("telnet.nasl");
  script_require_ports("Services/telnet", 23);

  script_tag(name:"summary", value:"This scripts reports the received banner of a Telnet service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

port = get_telnet_port( default:23 );
soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

# nb: Don't use get_telnet_banner() as we want to use telnet_verify_banner()
# without the need to have dump.inc and misc_func.inc included in every VT
# using get_telnet_banner().
banner = telnet_negotiate( socket:soc );
if( ! telnet_verify_banner( data:banner ) ) {
  close( soc );
  exit( 0 );
}

telnet_close_socket( socket:soc, data:banner );
if( strlen( banner ) ) {

  if( "login:" >!< tolower( banner ) )
    set_kb_item( name:"telnet/" + port + "/no_login_banner", value:TRUE ); # for check_account()

  telnet_set_banner( port:port, banner:banner );
  set_kb_item( name:"telnet/banner/available", value:TRUE );

  # nb: Safeguard if telnet.nasl failed on fragile ports
  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:"telnet", message:"A Telnet server seems to be running on this port" );

  log_message( port:port, data:'Remote Telnet banner :\n' + banner );
}

exit( 0 );