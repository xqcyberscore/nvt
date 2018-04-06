# OpenVAS Vulnerability Test
# $Id: http-rpc-epmap.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Detect the HTTP RPC endpoint mapper
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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

tag_summary = "This detects the http-rpc-epmap service by connecting
to the port 593 and processing the buffer received.

This endpoint mapper provides CIS (COM+ Internet Services)
parameters like port 135 (epmap) for RPC.";

tag_solution = "Deny incoming traffic from the Internet to TCP port 593
as it may become a security threat in the future, if a
vulnerability is discovered.

For more information about CIS:
http://msdn.microsoft.com/library/en-us/dndcom/html/cis.asp";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10763");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "Detect the HTTP RPC endpoint mapper";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Windows";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/http-rpc-epmap", 593);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

exit(0); # Broken at this time

port = get_kb_item("Services/http-rpc-epmap");
if (!port) port = 593;
key = string("http-rpc-epmap/banner/", port);
banner = get_kb_item(key);

if(!banner)
{
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
  {
  banner = recv(socket:soc, length:1000);
  close(soc);
  }
 }
}

if( "ncacn_http" >< banner)
{
 security_message(port:port);
}
