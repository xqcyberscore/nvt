# OpenVAS Vulnerability Test
# $Id: directconnect_hub.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Direct Connect hub detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "A Direct Connect 'hub' (or server) is running on this port.  Direct
Connect is a protocol used for peer-to-peer file-sharing as well as
chat, and a hub routes communications among peers.  While any type of
file may be shared, Direct Connect hubs often handle movies, images,
music files, and games, which may not be suitable for use in a 
business environment.";

if(description)
{
  script_id(13751);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 
  script_name("Direct Connect hub detection");
  script_tag(name:"cvss_base", value:"0.0");
 
 
  summary = "Direct Connect hub detection";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
 
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  family = "Peer-To-Peer File Sharing";
  script_family(family);
  script_dependencies("find_service.nasl");
  script_require_ports("Services/DirectConnectHub", 411);

  script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Direct_connect_file-sharing_application");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}



port = get_kb_item("Services/DirectConnectHub");
if (!port) port = 411;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if(soc)
{
	r=recv_line(socket:soc, length:1024);
	if ( ! r ) exit(0);
	if (ereg(pattern:"^\$Lock .+",string:r))
	{
		# Disconnect nicely.
		str="$quit|";
		send(socket:soc,data:str);

		log_message(port);
	}
	close(soc);
}

