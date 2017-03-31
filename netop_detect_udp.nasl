###############################################################################
# OpenVAS Vulnerability Test
# $Id: netop_detect_udp.nasl 4822 2016-12-21 07:19:58Z cfi $
#
# NetOp products UDP detection
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)  
# Jakob Bohm of Danware (http://www.danware.dk)
#
# Copyright:
# Copyright (C) 2004 Corsaire Limited and Danware Data A/S
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
  script_oid("1.3.6.1.4.1.25623.1.0.15766");
  script_version("$Revision: 4822 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-21 08:19:58 +0100 (Wed, 21 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NetOp products UDP detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This NASL script is Copyright 2004 Corsaire Limited and Danware Data A/S.");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl", "gb_open_udp_ports.nasl");
  script_require_udp_ports("Services/udp/unknown", 6502, 1971); #TODO: We should do something similar to the TCP "Services/unknown" for UDP

  tag_summary = "This script detects if the remote system has a Danware NetOp
  program enabled and running on UDP. These programs are used
  for remote system administration, for telecommuting and for
  live online training and usually allow authenticated users to
  access the local system remotely.

  Specific information will be given depending on the program
  detected";

  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include('netop.inc');

function test( port ) {

  socket = open_sock_udp( port );
  
  if( socket ) {

    send( socket:socket, data:helo_pkt_udp );
  
    banner_pkt = recv( socket:socket, length:1500, timeout:3 );
  
    close(socket);

    netop_check_and_add_banner();
  }
}

addr = get_host_ip();
proto_nam = 'udp';

# test default ports
foreach port( make_list( 6502, 1971 ) ) {
  if( ! get_udp_port_state( port ) ) continue;
  test( port:port );
}

# retrieve and test unknown services
port = get_kb_item( "UDP/PORTS" );
if( isnull( port ) ) exit( 0 );

if( get_udp_port_state( port ) ) {
  test( port:port );
}

exit( 0 );
