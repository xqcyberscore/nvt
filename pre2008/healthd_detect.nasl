###############################################################################
# OpenVAS Vulnerability Test
# $Id: healthd_detect.nasl 4233 2016-10-07 10:53:48Z cfi $
#
# HealthD detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Should cover BID: 1107
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com> 
# Copyright (C) 2001 SecuriTeam
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
  script_oid("1.3.6.1.4.1.25623.1.0.10731");
  script_version("$Revision: 4233 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-07 12:53:48 +0200 (Fri, 07 Oct 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("HealthD detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/healthd", "Services/unknown", 1281);

  tag_summary = "The FreeBSD Health Daemon was detected.
  The HealthD provides remote administrators with information about the 
  current hardware temperature, fan speed, etc, allowing them to monitor
  the status of the server.";

  tag_impact = "Such information about the hardware's current state might be sensitive; 
  it is recommended that you do not allow access to this service from the network.";

  tag_solution = "Configure your firewall to block access to this port.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item( "Services/healthd" );
if( ! port ) port = get_unknown_port( default:1281 );

if( get_port_state( port ) ) {

  soc = open_sock_tcp(port);

  if( soc ) {
    data = string( "foobar" );
    resultsend = send( socket:soc, data:data );
    resultrecv = recv( socket:soc, length:8192 );

    if( "ERROR: Unsupported command" >< resultrecv ) {

      set_kb_item( name:"healthd/installed", value:TRUE );
      register_service( port:port, proto:"healthd");

      data = string("VER d");
      resultsend = send( socket:soc, data:data );
      resultrecv = recv( socket:soc, length:8192 );
      close( soc );

      if( "ERROR: Unsupported command" >< resultrecv ) {
        security_message( port:port );
      } else {
        data = string( "The HealthD version we found is: ", resultrecv, "\n" );
        security_message( port:port, data:data );
      }
      exit( 0 );
    }
    close( soc );
    exit( 99 );
  }
}

exit( 0 );