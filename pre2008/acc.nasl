# OpenVAS Vulnerability Test
# $Id: acc.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: The ACC router shows configuration without authentication
#
# Authors:
# Sebastian Andersson <sa@hogia.net>
# Changes by rd :
#	- script id
#	- cve id
#
# Copyright:
# Copyright (C) 2000 Sebastian Andersson
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

tag_summary = "The remote router is an ACC router.

Some software versions on this router will allow an attacker to run the SHOW 
command without first providing any authentication to see part of the router's 
configuration.";

tag_solution = "Upgrade the software.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10351");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(183);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-1999-0383");
 
 name = "The ACC router shows configuration without authentication";
 script_name(name);
 



 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2000 Sebastian Andersson");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/telnet", 23);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;

banner = get_telnet_banner(port:port);
if ( ! banner || "Login:" >< banner ) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  first_line = telnet_negotiate(socket:soc);
  if("Login:" >< first_line) {
   req = string("\x15SHOW\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   r = recv_line(socket:soc, length:1024);
   if(("SET" >< r) ||
      ("ADD" >< r) ||
      ("RESET" >< r)) {
    security_message(port);
    # cleanup the router...
    while(! ("RESET" >< r)) {
     if("Type 'Q' to quit" >< r) {
      send(socket:soc, data:"Q");
      close(soc);
      exit(0);
     }
     r = recv(socket:soc, length:1024);
    }
   }
  }
  close(soc);
 }
}
