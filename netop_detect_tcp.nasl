# OpenVAS Vulnerability Test
# $Id: netop_detect_tcp.nasl 4034 2016-09-12 12:12:26Z cfi $
# Description: NetOp products TCP detection
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
#

tag_summary = "This script detects if the remote system has a Danware NetOp
program enabled and running on TCP.  These programs are used
for remote system administration, for telecommuting and for
live online training and usually allow authenticated users to
access the local system remotely.

Specific information will be given depending on the program
detected";

# declare description
if(description)
{
  script_id(15765);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4034 $");
  script_tag(name:"last_modification", value:"$Date: 2016-09-12 14:12:26 +0200 (Mon, 12 Sep 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  name="NetOp products TCP detection";
  script_name(name);
  summary= "Determines if the remote host has any Danware NetOp program active on TCP";
  script_summary(summary);
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This NASL script is Copyright 2004 Corsaire Limited and Danware Data A/S.");
  script_family("Service detection");
  script_dependencies("find_service.nasl","find_service2.nasl");
  script_tag(name : "summary" , value : tag_summary);
  script_require_ports("Services/unknown", 6502, 1971);

  exit(0);
}



############## declarations ################

# includes
include('netop.inc');
include('global_settings.inc');

# declare function
function test(port)
{
	if ( ! get_port_state(port) ) return 0;

	# open connection
	socket=open_sock_tcp(port, transport:ENCAPS_IP);
	
	# check that connection succeeded
	if(socket)
	{
		########## packet one of two ##########
		
		# send packet
		send(socket:socket, data:helo_pkt_gen);
	
		# receive response
		banner_pkt = recv(socket:socket, length:1500, timeout: 3);
		
		# check response contains correct contents and
		#   log response accordingly.
		
		netop_check_and_add_banner();
		
		########## packet two of two ##########
		
		if (ord(netop_kb_val[39]) == 0xF8)
		{
			send(socket:socket,data:quit_pkt_stream);
		}
		close(socket);
	}
}


############## script ################

# initialise variables
local_var socket;
addr=get_host_ip();
proto_nam='tcp';

# test default ports
test(port:6502);
#test(port:1971); #Tested below

# retrieve and test unknown services
port = get_unknown_port( default:1971 );
test(port:port);
exit(0);

############## End of TCP-specific detection script ################

